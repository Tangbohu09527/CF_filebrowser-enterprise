"""Real HTTPS + compiled native worker; synthetic authenticated host lifecycle.

This proves repository plugin-to-worker wiring and actual disk bytes, NOT that
the installed Hermes has a trusted lifecycle bridge or that Gateway is deployed.
"""
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

PLUGIN_PATH = Path(__file__).resolve().parents[1] / "plugin" / "__init__.py"
spec = importlib.util.spec_from_file_location("cf_inbound_plugin_test", PLUGIN_PATH)
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
from cf_inbound_plugin_test import inbound

FIXTURES = Path(__file__).parent / "fixtures"
DUMMY_AUTH = "Bearer public-isolated-test-capability-never-a-real-token"


class Context:
    """Explicit host test double; real public-loader coverage is separate."""
    def __init__(self):
        self.tools = {}
        self.settings = {"inbound_enabled": True}

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_tool(self, **tool):
        self.tools[tool["name"]] = tool


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # Expected TLS/connection aborts; never print request data.


class PluginInboundTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = os.environ.get("CF_FILEBRIDGE_INBOUND_TEST_EXE", "")
        if not raw or not Path(raw).is_file():
            raise RuntimeError("Build cmd/filebridge-inbound and set CF_FILEBRIDGE_INBOUND_TEST_EXE; integration tests are mandatory")
        cls.executable = Path(raw).resolve()
        cls.binary_hash = hashlib.sha256(cls.executable.read_bytes()).hexdigest()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cf-inbound-plugin-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.work = self.root / "task"
        self.work.mkdir(mode=0o700)
        if os.name == "nt":
            # Set a real NTFS protected DACL on THIS fresh test directory. No
            # administrator elevation, chmod emulation or existing-user ACL edits.
            script = r"""
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
            subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                           env={**os.environ, "CF_INBOUND_TEST_DIR": str(self.work)}, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.body = (FIXTURES / "sample.pdf").read_bytes()
        self.calls = 0
        self.mode = "ok"
        self.started = threading.Event()
        self.headers_correct = True
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                owner.calls += 1
                owner.headers_correct &= self.headers.get("Authorization") == DUMMY_AUTH
                owner.started.set()
                if self.path != "/inbound-media/7/content":
                    self.send_error(404)
                    return
                if owner.mode == "slow":
                    time.sleep(2)
                if owner.mode == "503" or (owner.mode == "503_once" and owner.calls == 1):
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
        self.bridge = inbound.HostBridge(str(self.executable), self.binary_hash)
        self.addCleanup(self.bridge.close)
        self.ctx = Context()
        plugin.register(self.ctx)
        self.tool = self.ctx.tools["filebrowser_download_inbound"]["handler"]

    def binding(self):
        expires = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
        origin = "https://127.0.0.1:%d" % self.server.server_port
        return {
            "dispatch_id": "dispatch-test-1", "task_id": "task-test-1", "thread_id": "thread-test-1",
            "enterprise_identity_id": "identity-test-1", "work_dir": str(self.work),
            "gateway_origin": origin, "expires_at": expires, "max_bytes": 1024 * 1024,
            "ca_file": str((FIXTURES / "cert.pem").resolve()),
            "ca_sha256": hashlib.sha256((FIXTURES / "cert.pem").read_bytes()).hexdigest(),
            "attachments": [{"schema": "cf-inbound-read/v1", "message_id": 3, "attachment_id": 5,
                "thread_id": "thread-test-1", "enterprise_identity_id": "identity-test-1",
                "url": origin + "/inbound-media/7/content", "authorization": DUMMY_AUTH,
                "expires_at": expires, "size": len(self.body), "sha256": hashlib.sha256(self.body).hexdigest(),
                "mime_type": "application/pdf", "filename": "../../never-use-this-name.pdf",
                "declared_quality": None, "original_comparison": "not_checked", "formal_archive": False,
                "download_policy": {"max_attempts": 4, "total_timeout_seconds": 30,
                    "retryable_status_codes": [503], "retry_after_seconds": 1}}],
        }

    def call(self, **kwargs):
        with self.bridge.activate("dispatch-test-1"):
            return json.loads(self.tool({"attachment_id": 5}, **kwargs))

    def test_model_context_and_task_id_cannot_authorize(self):
        answer = json.loads(self.tool({"attachment_id": 5}, task_id="trusted-looking", session_id="thread-test-1"))
        self.assertEqual(answer["error"]["code"], "trusted_context_unavailable")
        for bad in ({"attachment_id": 5, "task_context": self.binding()}, {"attachment_id": True},
                    {"attachment_id": 5, "url": "https://elsewhere/"}, {"attachment_id": 5, "task_id": "new"}):
            self.assertEqual(json.loads(self.tool(bad))["error"]["code"], "invalid_tool_input")
        self.assertEqual(self.calls, 0)

    def test_actual_pdf_and_jpeg_disk_handle_and_no_secrets(self):
        for body in (self.body, (FIXTURES / "sample.jpg").read_bytes()):
            with self.subTest(body=body[:4]):
                self.body = body
                binding = self.binding()
                binding["dispatch_id"] += str(len(body))
                binding["task_id"] += str(len(body))
                binding["attachments"][0]["mime_type"] = "application/pdf" if body.startswith(b"%PDF") else "image/jpeg"
                quality = None if body.startswith(b"%PDF") else "standard"
                binding["attachments"][0]["declared_quality"] = quality
                self.bridge.start_dispatch(binding)
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(output), self.bridge.activate(binding["dispatch_id"]):
                    response = json.loads(self.tool({"attachment_id": 5}))
                    self.assertTrue(response["ok"], response)
                    self.assertTrue(response["verified"])
                    self.assertFalse(response["formal_archive"])
                    self.assertEqual(response["original_comparison"], "not_checked")
                    self.assertEqual(response["declared_quality"], quality)
                    resolved = self.bridge.resolve_workcopy(response["handle"])
                    local = Path(resolved["path"])
                    self.assertEqual(local.parent, self.work)
                    self.assertEqual(local.read_bytes(), body)
                    with self.bridge.open_workcopy(response["handle"]) as verified_file:
                        self.assertEqual(verified_file.read(), body)
                    self.assertEqual(response["bytes_written"], len(body))
                    self.assertEqual(response["sha256"], hashlib.sha256(body).hexdigest())
                    repeated = json.loads(self.tool({"attachment_id": 5}, task_id="model-tries-another-task"))
                    self.assertEqual(repeated["handle"], response["handle"])
                self.assertNotIn(DUMMY_AUTH, output.getvalue() + json.dumps(response))
                self.assertNotIn(str(self.work), json.dumps(response))
                self.bridge.end_dispatch(binding["dispatch_id"])
        self.assertEqual(self.calls, 2)
        self.assertTrue(self.headers_correct)

    def test_concurrent_repeat_503_shares_worker_and_budget(self):
        self.mode = "503_once"
        self.bridge.start_dispatch(self.binding())
        results = []
        threads = [threading.Thread(target=lambda: results.append(self.call(task_id="model-changed"))) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(results), 5)
        self.assertTrue(all(r["ok"] for r in results), results)
        self.assertEqual(len({r["handle"] for r in results}), 1)
        self.assertEqual(self.calls, 2)

    def test_cancel_interrupts_inflight_and_cannot_restart(self):
        self.mode = "slow"
        binding = self.binding()
        self.bridge.start_dispatch(binding)
        replies = []
        thread = threading.Thread(target=lambda: replies.append(self.call()))
        thread.start()
        self.assertTrue(self.started.wait(3))
        self.bridge.end_dispatch(binding["dispatch_id"])
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertFalse(replies[0]["ok"])
        self.assertEqual(list(self.work.iterdir()), [])
        with self.assertRaises(inbound.BridgeError):
            self.bridge.start_dispatch(binding)
        binding["dispatch_id"] = "changed-dispatch-same-task"
        with self.assertRaises(inbound.BridgeError):
            self.bridge.start_dispatch(binding)
        self.assertEqual(self.calls, 1)

    def test_integrity_failure_terminal_no_half_file(self):
        binding = self.binding()
        binding["attachments"][0]["sha256"] = "0" * 64
        self.bridge.start_dispatch(binding)
        first, second = self.call(), self.call(task_id="try-again")
        self.assertFalse(first["ok"])
        self.assertFalse(second["ok"])
        self.assertEqual(self.calls, 1)
        self.assertEqual(list(self.work.iterdir()), [])
        self.assertNotIn(DUMMY_AUTH, json.dumps(first))

    def test_idle_lease_expiry_closes_worker_and_downstream_stream(self):
        binding = self.binding()
        binding["expires_at"] = (datetime.now(timezone.utc) + timedelta(seconds=1.2)).isoformat()
        self.bridge.start_dispatch(binding)
        with self.bridge.activate(binding["dispatch_id"]):
            receipt = json.loads(self.tool({"attachment_id": 5}))
            self.assertTrue(receipt["ok"], receipt)
            with self.bridge.open_workcopy(receipt["handle"]) as stream:
                deadline = time.monotonic() + 4
                while not stream.closed and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(stream.closed, "idle expired Dispatch left downstream stream open")
            answer = json.loads(self.tool({"attachment_id": 5}, task_id="new"))
            self.assertFalse(answer["ok"])
        self.assertEqual(self.calls, 1)

    def test_end_between_wait_and_response_cannot_deliver_success(self):
        binding = self.binding()
        self.bridge.start_dispatch(binding)
        dispatch = self.bridge._dispatches[binding["dispatch_id"]]
        dispatch.stopped.set()
        dispatch.responses.put({"ok": True})
        with self.assertRaises(inbound.BridgeError):
            dispatch._wait(1)

    def test_tampered_pin_and_changed_context_cannot_spawn_again(self):
        bad = inbound.HostBridge(str(self.executable), "0" * 64)
        self.addCleanup(bad.close)
        with self.assertRaises(inbound.BridgeError):
            bad.start_dispatch(self.binding())
        binding = self.binding()
        self.bridge.start_dispatch(binding)
        binding["attachments"][0]["authorization"] = "Bearer changed"
        with self.assertRaises(inbound.BridgeError):
            self.bridge.start_dispatch(binding)
        self.assertEqual(self.calls, 0)

    def test_native_stderr_and_inherited_filebrowser_token_are_not_used(self):
        secret = "synthetic-filebrowser-runtime-token-never-use-for-gateway"
        keylog = self.root / "must-not-write-tls-secrets"
        with patch.dict(os.environ, {"FILEBROWSER_AGENT_TOKEN": secret,
                                   "HTTPS_PROXY": "http://127.0.0.1:1",
                                   "SSLKEYLOGFILE": str(keylog)}):
            self.bridge.start_dispatch(self.binding())
            response = self.call()
        self.assertTrue(response["ok"], response)
        self.assertTrue(self.headers_correct)
        self.assertNotIn(secret, json.dumps(response))
        self.assertFalse(keylog.exists())
        # Capture actual native stderr too: DEVNULL in the host is not evidence
        # that the standalone worker itself avoids raw-input diagnostics.
        invalid = json.dumps({"authorization": DUMMY_AUTH, "token": secret}).encode() + b"\n"
        direct = subprocess.run([str(self.executable)], input=invalid, capture_output=True,
                                timeout=3, shell=False)
        combined = direct.stdout + direct.stderr
        self.assertNotIn(DUMMY_AUTH.encode(), combined)
        self.assertNotIn(secret.encode(), combined)
        self.assertEqual(direct.stderr, b"")
        self.assertFalse(json.loads(direct.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
