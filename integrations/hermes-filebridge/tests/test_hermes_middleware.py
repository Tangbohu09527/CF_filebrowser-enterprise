"""Real pinned Hermes loader/middleware/model_tools + native HTTPS worker.

Explicit component integration test; supply --hermes-source and --worker.
The fixture host supplies synthetic bindings. No authenticated HTTP request or
Gateway binding exchange is exercised: authenticated_request_binding=false.
No Hermes core, PluginContext, registry, or tool dispatcher is mocked/patched.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
PLUGIN = HERE.parent / "plugin"
DOWNLOAD = "filebrowser_download_inbound"
PROCESS = "cf_inbound_test_process_workcopy"
DUMMY_AUTH = "Bearer public-isolated-test-capability-never-a-real-token"
_spec = importlib.util.spec_from_file_location("cf_hermes_probe_support", HERE / "hermes_probe_support.py")
support = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(support)
ENTRYPOINT_BLOBS = {
    "model_tools.py": "924cd94413b18c3a069228950939c4c43fa43b3b",
    "hermes_cli/middleware.py": "897e4afc07ba0d78ba928baf39a8573422b648be",
}
PRIVATE_ACL_SCRIPT = r"""
$p=$env:CF_INBOUND_TEST_DIR
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid); $acl.SetAccessRuleProtection($true,$false)
foreach($id in @($sid.Value,'S-1-5-18','S-1-5-32-544')) {
 $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
 [Security.Principal.SecurityIdentifier]::new($id),'FullControl',
 'ContainerInherit,ObjectInherit','None','Allow'))
}
[IO.Directory]::SetAccessControl($p,$acl)
"""


def verify_source(source, commit=support.DEFAULT_HERMES_COMMIT, archive=None):
    return support.verify_source(source, commit, archive)


def private_directory(path):
    path.mkdir(mode=0o700)
    if os.name != "nt":
        return
    # Only this newly created test directory receives a private protected DACL;
    # this is an ordinary-user test, with no administrator elevation/bypass.
    powershell = Path(os.environ["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command", PRIVATE_ACL_SCRIPT],
                   env={**os.environ, "CF_INBOUND_TEST_DIR": str(path)},
                   check=True, capture_output=True, timeout=15)


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, _request, _client_address):
        pass  # A cancelled TLS response is expected; never print request data.


def child_check(source, worker, commit=support.DEFAULT_HERMES_COMMIT):
    sandbox = Path(os.environ["HERMES_HOME"]).parent
    support.assert_isolated_environment(sandbox)
    support.bootstrap_system_metadata()

    def allowed_acl_helper(executable, command, environment):
        if os.name != "nt":
            return False
        powershell = Path(os.environ["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        expected = subprocess.list2cmdline([str(powershell), "-NoProfile", "-NonInteractive",
                                          "-Command", PRIVATE_ACL_SCRIPT])
        executable = Path(os.path.abspath(executable)) if executable is not None else None
        path = Path(os.path.abspath(environment.get("CF_INBOUND_TEST_DIR", "")))
        return executable in (None, powershell) and command == expected and sandbox in path.parents

    violations = support.install_audit_guard(sandbox, source, worker=worker, allow_network=True,
                                             allowed_subprocess=allowed_acl_helper)
    system_reads = violations.system_reads
    sys.path.insert(0, str(source))
    from hermes_cli.plugins import PluginContext, get_plugin_manager
    from tools.registry import registry
    from model_tools import handle_function_call

    manager = get_plugin_manager()
    checks = unittest.TestCase()
    manager.discover_and_load()
    try:
        loaded = manager._plugins.get("cf-filebridge")
        checks.assertIsNotNone(loaded)
        checks.assertTrue(loaded.enabled, loaded.error)
        checks.assertIsNone(loaded.error)
        checks.assertEqual(Path(loaded.module.__file__).resolve(),
                           Path(os.environ["HERMES_HOME"]) / "plugins/cf-filebridge/__init__.py")
        read_entry = registry.get_entry("filebrowser_files")
        contexts = [cell.cell_contents for cell in (read_entry.handler.__closure__ or ())
                    if isinstance(cell.cell_contents, PluginContext)]
        checks.assertEqual(len(contexts), 1)
        ctx = contexts[0]  # Actual context passed by official loader, never constructed here.
        inbound = loaded.module.inbound
        checks.assertEqual(set(registry.get_entry(DOWNLOAD).schema["parameters"]["properties"]),
                           {"attachment_id"})

        class MiddlewareTests(unittest.TestCase):
            def setUp(self):
                self.temp = tempfile.TemporaryDirectory(prefix="cf-hermes-middleware-case-", dir=sandbox / "temp")
                self.addCleanup(self.temp.cleanup)
                self.root = Path(self.temp.name).resolve()
                self.work = self.root / "task"
                private_directory(self.work)
                self.sentinel = self.work / "unknown-sentinel"
                self.sentinel.write_bytes(b"unrelated task file: must not be changed")
                self.body = (FIXTURES / "sample.pdf").read_bytes()
                self.calls = 0
                self.calls_lock = threading.Lock()
                self.mode = "ok"
                self.started = threading.Event()
                self.server_release = threading.Event()
                self.addCleanup(self.server_release.set)
                self.headers_correct = True
                owner = self

                class Handler(BaseHTTPRequestHandler):
                    def log_message(self, *_args):
                        pass

                    def do_GET(self):
                        with owner.calls_lock:
                            owner.calls += 1
                            count = owner.calls
                            owner.headers_correct &= self.headers.get("Authorization") == DUMMY_AUTH
                        owner.started.set()
                        if self.path != "/inbound-media/7/content":
                            self.send_error(404)
                            return
                        if owner.mode == "slow":
                            owner.server_release.wait(5)
                        if owner.mode == "503" or (owner.mode == "503_once" and count == 1):
                            self.send_response(503)
                            self.send_header("Retry-After", "1")
                            self.send_header("Content-Length", "0")
                            self.end_headers()
                            return
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(owner.body)))
                        self.end_headers()
                        try:
                            self.wfile.write(owner.body)
                        except (OSError, ssl.SSLError):
                            pass

                self.server = QuietServer(("127.0.0.1", 0), Handler)
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls.load_cert_chain(FIXTURES / "cert.pem", FIXTURES / "key.pem")
                self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
                threading.Thread(target=self.server.serve_forever, daemon=True).start()
                self.addCleanup(self.server.server_close)
                self.addCleanup(self.server.shutdown)
                self.bridge = inbound.HostBridge(str(worker), hashlib.sha256(worker.read_bytes()).hexdigest())
                self.addCleanup(self.bridge.close)
                self.bindings = {}
                self.middleware_calls = []
                self.middleware_lock = threading.Lock()
                self.processing_started = threading.Event()
                self.processing_release = threading.Event()
                self.addCleanup(self.processing_release.set)
                self.hold_processing = False
                self.processing_stream = None

                def middleware(tool_name, args, next_call, task_id, session_id, **_context):
                    if tool_name not in (DOWNLOAD, PROCESS):
                        return next_call(args)
                    with self.middleware_lock:
                        self.middleware_calls.append((tool_name, task_id, session_id))
                    # Explicit synthetic fixture authority. Production must
                    # authenticate a Gateway exchange; IDs alone authorize nothing.
                    dispatch_id = self.bindings.get((task_id, session_id))
                    if dispatch_id is None:
                        return json.dumps(inbound.failure("trusted_context_unavailable"))
                    try:
                        with self.bridge.activate(dispatch_id):
                            return next_call(args)
                    except inbound.BridgeError as error:
                        # Upstream skips a middleware that throws before next_call.
                        # Denial therefore MUST return, not raise an exception.
                        return json.dumps(inbound.failure(error.code))

                def process_workcopy(args, **_kwargs):
                    try:
                        with self.bridge.open_workcopy(args["handle"]) as stream:
                            data = stream.read()
                            self.processing_stream = stream
                            self.processing_started.set()
                            if self.hold_processing:
                                if not self.processing_release.wait(5):
                                    return json.dumps(inbound.failure("test_release_timeout"))
                            return json.dumps({"ok": True, "sha256": hashlib.sha256(data).hexdigest(),
                                               "bytes_read": len(data), "closed": stream.closed})
                    except inbound.BridgeError as error:
                        return json.dumps(inbound.failure(error.code))

                registration = ctx.register_middleware("tool_execution", middleware)
                self.addCleanup(registration.dispose)
                registration = ctx.register_tool(
                    name=PROCESS, toolset="cf_filebridge_inbound_test", handler=process_workcopy,
                    schema={"name": PROCESS, "description": "Isolated test consumer of a workcopy handle.",
                            "parameters": {"type": "object", "required": ["handle"],
                                           "additionalProperties": False,
                                           "properties": {"handle": {"type": "string"}}}})
                self.assertIsNotNone(registration)
                self.addCleanup(registration.dispose)

            def binding(self, suffix="one", work=None):
                expires = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
                origin = "https://127.0.0.1:%d" % self.server.server_port
                return {
                    "dispatch_id": "synthetic-dispatch-" + suffix,
                    "task_id": "synthetic-task-" + suffix, "thread_id": "synthetic-thread-" + suffix,
                    "enterprise_identity_id": "synthetic-identity-" + suffix, "work_dir": str(work or self.work),
                    "gateway_origin": origin, "expires_at": expires, "max_bytes": 1024 * 1024,
                    "ca_file": str(FIXTURES / "cert.pem"),
                    "ca_sha256": hashlib.sha256((FIXTURES / "cert.pem").read_bytes()).hexdigest(),
                    "attachments": [{"schema": "cf-inbound-read/v1", "message_id": 3, "attachment_id": 5,
                        "thread_id": "synthetic-thread-" + suffix, "enterprise_identity_id": "synthetic-identity-" + suffix,
                        "url": origin + "/inbound-media/7/content", "authorization": DUMMY_AUTH,
                        "expires_at": expires, "size": len(self.body), "sha256": hashlib.sha256(self.body).hexdigest(),
                        "mime_type": "application/pdf", "filename": "../../never-use-this-name.pdf",
                        "declared_quality": None, "original_comparison": "not_checked", "formal_archive": False,
                        "download_policy": {"max_attempts": 4, "total_timeout_seconds": 30,
                            "retryable_status_codes": [503], "retry_after_seconds": 1}}],
                }

            def start(self, binding):
                self.bridge.start_dispatch(binding)
                self.bindings[(binding["task_id"], binding["task_id"])] = binding["dispatch_id"]

            def assert_files(self, successful, work=None):
                directory = work or self.work
                files = list(directory.iterdir())
                published = [path for path in files if path.name.startswith("work-")]
                self.assertEqual(len(published), int(successful))
                for path in published:
                    self.assertEqual(path.read_bytes(), self.body)
                expected = set(published)
                if directory == self.work:
                    self.assertEqual(self.sentinel.read_bytes(), b"unrelated task file: must not be changed")
                    expected.add(self.sentinel)
                self.assertEqual(set(files), expected, "unpublished partial file left behind")

            def assert_ended(self, binding, handle):
                self.assertFalse(self.call(task=binding["task_id"])["ok"])
                self.assertFalse(self.call(PROCESS, {"handle": handle}, task=binding["task_id"])["ok"])
                with self.assertRaises(inbound.BridgeError):
                    self.bridge.resolve_workcopy(handle)
                with self.assertRaises(inbound.BridgeError):
                    with self.bridge.open_workcopy(handle):
                        self.fail("ended Dispatch supplied a stream")
                with self.assertRaises(inbound.BridgeError):
                    with self.bridge.activate(binding["dispatch_id"]):
                        self.fail("ended Dispatch was reactivated")

            def call(self, name=DOWNLOAD, args=None, task="synthetic-task-one"):
                answer = handle_function_call(name, args if args is not None else {"attachment_id": 5},
                                              task_id=task, session_id=task,
                                              tool_call_id="synthetic-tool-call", turn_id="synthetic-turn",
                                              user_task="Untrusted prompt cannot supply a binding")
                result = json.loads(answer)
                self.assertNotIn(DUMMY_AUTH, answer)
                self.assertNotIn(str(self.work), answer)
                # Registry dispatch bypasses execution middleware. Even on the
                # same worker thread, the activation must have been reset.
                direct = json.loads(registry.dispatch(DOWNLOAD, {"attachment_id": 5}, task_id=task, session_id=task))
                self.assertEqual(direct["error"]["code"], "trusted_context_unavailable")
                return result

            def test_missing_binding_is_denied_by_real_middleware(self):
                answer = self.call()
                self.assertFalse(answer["ok"])
                self.assertEqual(answer["error"]["code"], "trusted_context_unavailable")
                self.assertEqual(self.middleware_calls, [(DOWNLOAD, "synthetic-task-one", "synthetic-task-one")])
                self.assertEqual(self.calls, 0)

            def test_concurrent_repeat_reuses_budget_and_downstream_reads_bytes(self):
                self.mode = "503_once"
                binding = self.binding()
                self.start(binding)
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(self.call) for _ in range(2)]
                    results = [future.result(timeout=10) for future in futures]
                self.assertTrue(all(result["ok"] for result in results), results)
                self.assertEqual(results[0]["handle"], results[1]["handle"])
                self.assertEqual(self.call()["handle"], results[0]["handle"])
                processed = self.call(PROCESS, {"handle": results[0]["handle"]})
                self.assertTrue(processed["ok"], processed)
                self.assertEqual(processed["bytes_read"], len(self.body))
                self.assertEqual(processed["sha256"], hashlib.sha256(self.body).hexdigest())
                self.assertFalse(processed["closed"])
                self.assertTrue(self.processing_stream.closed)
                self.assertEqual(self.calls, 2)
                self.assertTrue(self.headers_correct)
                self.assertEqual(len(self.middleware_calls), 4)
                self.bridge.end_dispatch(binding["dispatch_id"])
                self.assert_ended(binding, results[0]["handle"])
                self.assert_files(successful=True)

            def test_exhausted_budget_stays_exhausted_across_model_calls(self):
                self.mode = "503"
                binding = self.binding()
                self.start(binding)
                self.assertFalse(self.call()["ok"])
                self.assertEqual(self.calls, 4)
                self.bridge.start_dispatch(binding)
                self.assertFalse(self.call()["ok"])
                self.assertEqual(self.calls, 4)
                self.assert_files(successful=False)

            def test_concurrent_dispatches_cannot_consume_each_others_handle(self):
                other_work = self.root / "other-task"
                private_directory(other_work)
                first, second = self.binding(), self.binding("two", other_work)
                self.start(first)
                self.start(second)
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(self.call, task=binding["task_id"]) for binding in (first, second)]
                    results = [future.result(timeout=10) for future in futures]
                self.assertTrue(all(result["ok"] for result in results), results)
                self.assertNotEqual(results[0]["handle"], results[1]["handle"])
                denied = self.call(PROCESS, {"handle": results[0]["handle"]}, task=second["task_id"])
                self.assertFalse(denied["ok"])
                self.assertEqual(denied["error"]["code"], "invalid_handle")
                self.assertTrue(self.call(PROCESS, {"handle": results[1]["handle"]}, task=second["task_id"])["ok"])
                self.assertEqual(self.calls, 2)
                self.bridge.end_dispatch(first["dispatch_id"])
                self.bridge.end_dispatch(second["dispatch_id"])
                self.assert_ended(first, results[0]["handle"])
                self.assert_ended(second, results[1]["handle"])
                self.assert_files(successful=True)
                self.assert_files(successful=True, work=other_work)

            def test_host_cancel_interrupts_inflight_tool_and_prevents_restart(self):
                self.mode = "slow"
                binding = self.binding()
                self.start(binding)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(self.call)
                    self.assertTrue(self.started.wait(3))
                    self.bridge.end_dispatch(binding["dispatch_id"])
                    result = future.result(timeout=4)
                self.assertFalse(result["ok"])
                self.assertFalse(self.call()["ok"])
                self.assert_files(successful=False)
                with self.assertRaises(inbound.BridgeError):
                    self.bridge.start_dispatch(binding)
                self.assertEqual(self.calls, 1)

            def test_host_end_closes_stream_inside_actual_downstream_tool(self):
                binding = self.binding()
                self.start(binding)
                downloaded = self.call()
                self.assertTrue(downloaded["ok"], downloaded)
                self.hold_processing = True
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(self.call, PROCESS, {"handle": downloaded["handle"]})
                    self.assertTrue(self.processing_started.wait(3))
                    self.assertFalse(self.processing_stream.closed)
                    self.bridge.end_dispatch(binding["dispatch_id"])
                    self.assertTrue(self.processing_stream.closed)
                    self.processing_release.set()
                    processed = future.result(timeout=4)
                self.assertTrue(processed["closed"])
                self.assert_ended(binding, downloaded["handle"])
                self.assert_files(successful=True)
                self.assertEqual(self.calls, 1)

        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MiddlewareTests))
        if not result.wasSuccessful():
            raise SystemExit(1)
        checks.assertEqual(violations, [], "unexpected external operation was attempted")
        print(json.dumps({"hermes_commit": commit, "tests": result.testsRun,
                          "entrypoint": "model_tools.handle_function_call", "real_loader": True,
                          "real_plugin_context": True, "real_tool_execution_middleware": True,
                          "real_https_native_worker": True, "synthetic_host_bindings": True,
                          "authenticated_request_binding": False, "live_enabled": False,
                          "isolation_audit_violations": len(violations),
                          "readonly_system_metadata": sorted(system_reads), "ok": True}))
    finally:
        manager.unload()


def run(source, worker, commit=support.DEFAULT_HERMES_COMMIT, archive=None):
    with tempfile.TemporaryDirectory(prefix="cf-hermes-middleware-") as temporary:
        root = Path(temporary).resolve()
        home = root / "profile"
        shutil.copytree(PLUGIN, home / "plugins/cf-filebridge",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        config = {"plugins": {"enabled": ["cf-filebridge"], "entries": {
            "cf-filebridge": {"settings": {"inbound_enabled": True}}}},
            "agent": {"environment_probe": False}, "security": {"allow_lazy_installs": False}}
        (home / "config.yaml").write_text(json.dumps(config), encoding="utf-8")
        env = support.isolated_environment(root)
        command = [sys.executable, "-I", "-X", "utf8", "-B", str(Path(__file__).resolve()),
                   "--hermes-source", str(source), "--hermes-commit", commit, "--worker", str(worker), "--child"]
        if archive is not None:
            command.extend(("--hermes-archive", str(archive)))
        completed = subprocess.run(command,
                                   cwd=root, env=env, capture_output=True, text=True, timeout=90)
        print(completed.stdout.replace(DUMMY_AUTH, "[REDACTED_SYNTHETIC_CREDENTIAL]"), end="")
        print(completed.stderr.replace(DUMMY_AUTH, "[REDACTED_SYNTHETIC_CREDENTIAL]"), end="", file=sys.stderr)
        if completed.returncode:
            raise SystemExit(completed.returncode)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-source", required=True, type=Path)
    parser.add_argument("--hermes-commit", choices=support.VERSIONS, default=support.DEFAULT_HERMES_COMMIT)
    parser.add_argument("--hermes-archive", type=Path)
    parser.add_argument("--worker", type=Path,
                        default=os.environ.get("CF_FILEBRIDGE_INBOUND_TEST_EXE"),
                        help="Explicit compiled isolated worker (or CF_FILEBRIDGE_INBOUND_TEST_EXE)")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    options = parser.parse_args()
    if not options.worker:
        parser.error("--worker or CF_FILEBRIDGE_INBOUND_TEST_EXE is required")
    source_path = options.hermes_source.absolute()
    worker_path = options.worker.resolve(strict=True)
    archive = options.hermes_archive.resolve(strict=True) if options.hermes_archive else None
    verify_source(source_path, options.hermes_commit, archive)
    if options.child:
        child_check(source_path, worker_path, options.hermes_commit)
    else:
        run(source_path, worker_path, options.hermes_commit, archive)
