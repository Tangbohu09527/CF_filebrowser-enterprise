"""Synthetic control-server component tests with real TLS/adapter/native worker.

These are not joint Gateway/Hermes acceptance tests. Framework identifiers and
Gateway responses are synthetic test inputs; production classes are unmodified.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

from test_hermes_middleware import private_directory


PLUGIN = Path(__file__).resolve().parents[1] / "plugin"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
spec = importlib.util.spec_from_file_location("cf_inbound_host_test", PLUGIN / "__init__.py")
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
inbound = __import__(spec.name + ".inbound", fromlist=["HostBridge"])
control = __import__(spec.name + ".inbound_control", fromlist=["ControlClient"])
host = __import__(spec.name + ".inbound_host", fromlist=["HostAdapter"])
SERVICE_ENV = "CF_FILEBRIDGE_HOST_SYNTHETIC_TEST"
SERVICE_SECRET = "synthetic-only-host-service-secret-never-a-live-credential"
READ_SECRET = "Bearer synthetic-only-attachment-grant-never-a-live-credential"
DOWNLOAD = "filebrowser_download_inbound"
CONSUMER = "test_process_inbound"
_WORKER_AUDIT = {"installed": False, "active": None}


def _observe_worker_launch(event, args):
    active = _WORKER_AUDIT["active"]
    if active is None or event != "subprocess.Popen":
        return
    _executable, command, _cwd, environment = args
    if active["worker"] not in str(command):
        return
    # Popen(env=None) inherits the environment and is valid. Inspect only this
    # test's named synthetic secret; never retain unrelated environment values.
    environment = os.environ if environment is None else environment
    active["launches"].append({
        "service_secret_in_environment": environment.get(SERVICE_ENV) == SERVICE_SECRET,
        "service_secret_in_command": SERVICE_SECRET in str(command),
    })


class Settings:
    """Explicit configuration fixture; does not impersonate PluginContext."""
    def __init__(self, raw):
        self.raw = raw

    def get_config(self, key, default=None):
        return self.raw if key == "inbound_host" else (True if key == "inbound_enabled" else default)


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, _request, _client_address):
        pass  # Revocation deliberately interrupts TLS responses.


class HostControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = os.environ.get("CF_FILEBRIDGE_INBOUND_TEST_EXE", "")
        if not raw or not Path(raw).is_file():
            raise RuntimeError("Set CF_FILEBRIDGE_INBOUND_TEST_EXE to the compiled isolated worker")
        cls.worker = Path(raw).resolve()
        cls.worker_hash = hashlib.sha256(cls.worker.read_bytes()).hexdigest()
        cls.worker_launches = []
        if not _WORKER_AUDIT["installed"]:
            sys.addaudithook(_observe_worker_launch)
            _WORKER_AUDIT["installed"] = True

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cf-inbound-host-component-")
        self.addCleanup(self.temp.cleanup)
        audit_scope = {"worker": str(self.worker), "launches": self.worker_launches}
        _WORKER_AUDIT["active"] = audit_scope

        def stop_observing():
            if _WORKER_AUDIT["active"] is audit_scope:
                _WORKER_AUDIT["active"] = None

        # Audit hooks cannot be removed. Deactivate after this test's resources
        # close so unrelated later test classes are never observed/interrupted.
        self.addCleanup(stop_observing)
        self.root = Path(self.temp.name).resolve()
        self.work_root = self.root / "private-tasks"
        private_directory(self.work_root)
        self.body = (FIXTURES / "sample.pdf").read_bytes()
        self.mime = "application/pdf"
        self.mode = "ok"
        self.lease_seconds = 20
        self.response_transform = None
        self.event_transform = None
        self.redirect_location = None
        self.redirect_status = 302
        self.resolve_calls = self.event_calls = self.closed_calls = self.download_calls = 0
        self.lock = threading.Lock()
        self.records = {}
        self.closed_observations = []
        self.processes = []
        self.processing_stream = None
        self.processing_entered = threading.Event()
        self.processing_release = threading.Event()
        self.processing_returned = threading.Event()
        self.events_entered = threading.Event()
        self.first_snapshot = threading.Event()
        self.first_snapshot.set()
        self.download_entered = threading.Event()
        self.partial_body_sent = threading.Event()
        self.download_release = threading.Event()
        self.closed_entered = threading.Event()
        self.stop_server = threading.Event()
        self.closed_failure = False
        self.control_headers_valid = True
        self.media_headers_valid = True
        self.launch_start = len(self.worker_launches)
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def send_json(self, body, status=200):
                data = json.dumps(body, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def authorized(self):
                ok = self.headers.get("Authorization") == "Bearer " + SERVICE_SECRET
                owner.control_headers_valid &= ok
                if not ok:
                    self.send_json({"detail": "unavailable"}, 403)
                return ok

            def do_POST(self):
                if not self.authorized():
                    return
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                if self.path == control.PREFIX + "/resolve":
                    with owner.lock:
                        owner.resolve_calls += 1
                        if owner.redirect_location:
                            self.send_response(owner.redirect_status)
                            self.send_header("Location", owner.redirect_location)
                            self.send_header("Cache-Control", "no-store")
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", "0")
                            self.end_headers()
                            return
                        record = owner.records.get(body["session_id"])
                        if record is None:
                            serial = len(owner.records) + 1
                            expiry = (datetime.now(timezone.utc) + timedelta(seconds=owner.lease_seconds)).isoformat()
                            record = {"owner": body, "binding_id": str(uuid.uuid4()), "epoch": str(uuid.uuid4()),
                                      "serial": serial, "lease": expiry, "sequence": 1, "state": "running",
                                      "reason": None, "disconnect": False, "sent": 0, "closed": False}
                            owner.records[body["session_id"]] = record
                        if record["owner"] != body or record["closed"]:
                            self.send_json({"detail": "unavailable"}, 403)
                            return
                        response = owner.resolve_response(record)
                    if owner.response_transform:
                        owner.response_transform(response)
                    self.send_json(response)
                    return
                if self.path.endswith("/closed"):
                    with owner.lock:
                        owner.closed_calls += 1
                        record = owner.records.get(body["session_id"])
                        valid = record is not None and body == {**record["owner"], "claim_epoch": record["epoch"]}
                        owner.control_headers_valid &= valid
                        if not valid:
                            self.send_json({"detail": "unavailable"}, 403)
                            return
                        record["closed"] = True
                        owner.closed_observations.append({
                            "workers_exited": all(process.poll() is not None for process in owner.processes),
                            "stream_closed": owner.processing_stream is None or owner.processing_stream.closed,
                            "callback_returned": not owner.processing_entered.is_set() or owner.processing_returned.is_set(),
                        })
                    owner.closed_entered.set()
                    self.send_json({"schema": control.SCHEMA, "binding_id": record["binding_id"], "state": "closed"},
                                   503 if owner.closed_failure else 200)
                    return
                self.send_json({"detail": "unavailable"}, 404)

            def do_GET(self):
                if self.path == "/inbound-media/7/content":
                    with owner.lock:
                        owner.download_calls += 1
                        count = owner.download_calls
                        owner.media_headers_valid &= self.headers.get("Authorization") == READ_SECRET
                    owner.download_entered.set()
                    if owner.mode == "slow":
                        owner.download_release.wait(5)
                    if owner.mode == "503_once" and count == 1:
                        self.send_response(503)
                        self.send_header("Retry-After", "1")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(owner.body)))
                    self.end_headers()
                    if owner.mode == "slow-body":
                        split = max(1, len(owner.body) // 2)
                        self.wfile.write(owner.body[:split])
                        self.wfile.flush()
                        owner.partial_body_sent.set()
                        owner.download_release.wait(10)
                        self.wfile.write(owner.body[split:])
                        return
                    self.wfile.write(owner.body)
                    return
                if not self.authorized():
                    return
                with owner.lock:
                    owner.event_calls += 1
                    record = owner.records.get(self.headers.get("X-CF-Session-Id"))
                    expected = {} if record is None else {
                        "X-CF-Session-Id": record["owner"]["session_id"], "X-CF-Task-Id": record["owner"]["task_id"],
                        "X-CF-Host-Instance-Id": record["owner"]["host_instance_id"],
                        "X-CF-Host-Nonce": record["owner"]["host_nonce"], "X-CF-Claim-Epoch": record["epoch"],
                        "Last-Event-ID": "1"}
                    valid = bool(expected) and all(self.headers.get(key) == value for key, value in expected.items())
                    owner.control_headers_valid &= valid
                if not valid:
                    self.send_json({"detail": "unavailable"}, 403)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                owner.events_entered.set()
                owner.first_snapshot.wait(5)
                while not owner.stop_server.is_set():
                    with owner.lock:
                        if record["disconnect"]:
                            return
                        snapshot = {"schema": control.SCHEMA, "binding_id": record["binding_id"],
                                    "claim_epoch": record["epoch"], "host_instance_id": record["owner"]["host_instance_id"],
                                    "host_nonce": record["owner"]["host_nonce"], "sequence": record["sequence"],
                                    "state": record["state"], "lease_valid_until": record["lease"], "reason": record["reason"]}
                        record["sent"] += 1
                    if owner.event_transform:
                        owner.event_transform(snapshot)
                    wire = f"id: {snapshot['sequence']}\nevent: binding\ndata: {json.dumps(snapshot)}\n\n".encode()
                    self.wfile.write(wire)
                    self.wfile.flush()
                    if snapshot["state"] != "running":
                        return
                    owner.stop_server.wait(0.05)

        self.server = QuietServer(("127.0.0.1", 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(FIXTURES / "cert.pem", FIXTURES / "key.pem")
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.stop_server.set)
        self.addCleanup(self.first_snapshot.set)
        self.addCleanup(self.download_release.set)
        self.addCleanup(self.processing_release.set)
        self.environment = patch.dict(os.environ, {SERVICE_ENV: SERVICE_SECRET})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.raw = {"gateway_origin": "https://127.0.0.1:%d" % self.server.server_port,
                    "service_token_env": SERVICE_ENV, "profile_reference": "synthetic-profile", "profile_revision": 1,
                    "work_root": str(self.work_root), "client_path": str(self.worker), "client_sha256": self.worker_hash,
                    "max_bytes": 1024 * 1024, "ca_file": str(FIXTURES / "cert.pem"),
                    "ca_sha256": hashlib.sha256((FIXTURES / "cert.pem").read_bytes()).hexdigest(),
                    "consumer_tools": [CONSUMER]}
        # The native HTTP request probe reuses only this explicitly synthetic
        # HTTPS service. Its adapter is loaded by the real Hermes plugin loader
        # in a separate process; this fixture must not start or bind one there.
        if not getattr(self, "make_adapter", True):
            return
        self.config = control.HostConfig.from_context(Settings(self.raw))
        self.client = control.ControlClient(self.config)
        self.bridge = inbound.HostBridge(str(self.worker), self.worker_hash)
        self.adapter = host.HostAdapter(self.client, self.bridge, downstream_tools=[CONSUMER])
        self.addCleanup(self.adapter.close)
        self.download_handler = inbound.handler_for(Settings(self.raw))

    def resolve_response(self, record):
        serial = record["serial"]
        thread_id = "00000000-0000-4000-8000-%012d" % serial
        identity_id = "10000000-0000-4000-8000-%012d" % serial
        return {**record["owner"], "binding_id": record["binding_id"], "dispatch_id": serial,
                "claim_epoch": record["epoch"], "message_id": serial, "thread_id": thread_id,
                "enterprise_identity_id": identity_id, "profile_reference": "synthetic-profile", "profile_revision": 1,
                "lease_valid_until": record["lease"], "state": "running", "budget_scope": f"message:{serial}:attachment:5",
                "event_sequence": 1, "attachments": [{"schema": "cf-inbound-read/v1", "message_id": serial,
                    "attachment_id": 5, "thread_id": thread_id, "enterprise_identity_id": identity_id,
                    "url": self.raw["gateway_origin"] + "/inbound-media/7/content", "authorization": READ_SECRET,
                    "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                    "download_policy": {"max_attempts": 4, "total_timeout_seconds": 30,
                                        "retryable_status_codes": [503], "retry_after_seconds": 1},
                    "size": len(self.body), "sha256": hashlib.sha256(self.body).hexdigest(), "mime_type": self.mime,
                    "filename": "../../never-select-a-local-path.pdf", "declared_quality": None,
                    "original_comparison": "not_checked", "formal_archive": False}]}

    def call(self, session="synthetic-session", name=DOWNLOAD, args=None, callback=None):
        text = self.adapter.middleware(tool_name=name, args=args or {"attachment_id": 5},
                                       next_call=callback or self.download_handler, session_id=session, task_id=session)
        self.assertNotIn(SERVICE_SECRET, text)
        self.assertNotIn(READ_SECRET, text)
        self.assertNotIn(str(self.work_root), text)
        return json.loads(text)

    def scope(self, session="synthetic-session"):
        return self.adapter._scopes[(session, session)]

    def remember_worker(self, session="synthetic-session"):
        dispatch = self.bridge._dispatches[self.scope(session).resolved.worker_binding["dispatch_id"]]
        self.processes.append(dispatch.process)

    def wait_until(self, condition, seconds=4):
        deadline = time.monotonic() + seconds
        while not condition() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(condition(), "timed out waiting for actual lifecycle condition")

    def test_config_rejects_unsafe_tls_origin_token_source_and_types(self):
        invalid = [{"gateway_origin": "http://127.0.0.1:1"}, {"gateway_origin": self.raw["gateway_origin"] + "/path"},
                   {"service_token_env": "FILEBROWSER_RUNTIME_TOKEN"}, {"profile_revision": True},
                   {"max_bytes": True}, {"work_root": "relative"}, {"ca_sha256": "0" * 64},
                   {"unknown": "ignored-must-not-be-accepted"}]
        for changed in invalid:
            with self.subTest(changed=list(changed)):
                with self.assertRaises(inbound.BridgeError):
                    control.HostConfig.from_context(Settings({**self.raw, **changed}))
        self.assertEqual(self.resolve_calls, 0)

    def test_untrusted_certificate_is_rejected_before_http(self):
        raw = {key: value for key, value in self.raw.items() if key not in ("ca_file", "ca_sha256")}
        client = control.ControlClient(control.HostConfig.from_context(Settings(raw)))
        with self.assertRaises(inbound.BridgeError):
            client.resolve("synthetic-session", "synthetic-session", "instance", "n" * 32)
        self.assertEqual(self.resolve_calls, 0)

    def test_trusted_certificate_with_wrong_hostname_sends_no_http(self):
        # The checked-in certificate's only SAN is IP:127.0.0.1. The CA is
        # explicitly trusted, so this exercises hostname validation separately.
        raw = {**self.raw, "gateway_origin": "https://localhost:%d" % self.server.server_port}
        client = control.ControlClient(control.HostConfig.from_context(Settings(raw)))
        with self.assertRaises(inbound.BridgeError):
            client.resolve("wrong-host", "wrong-host", "instance", "n" * 32)
        self.assertEqual(self.resolve_calls, 0)

    def test_control_redirect_never_forwards_service_authorization(self):
        target_calls = []

        class Target(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                target_calls.append(self.headers.get("Authorization") == "Bearer " + SERVICE_SECRET)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_POST = do_GET

        target = QuietServer(("127.0.0.1", 0), Target)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(FIXTURES / "cert.pem", FIXTURES / "key.pem")
        target.socket = tls.wrap_socket(target.socket, server_side=True)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        self.addCleanup(target.server_close)
        self.addCleanup(target.shutdown)
        self.redirect_location = "https://127.0.0.1:%d/control-target" % target.server_port
        # Both TLS servers are trusted by the same fixture CA. Failure cannot
        # be attributed to an untrusted redirect target certificate.
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                self.redirect_status = status
                with self.assertRaises(inbound.BridgeError):
                    self.client.resolve(f"redirect-{status}", f"redirect-{status}", "instance", "n" * 32)
        self.assertEqual(self.resolve_calls, 5)
        self.assertEqual(target_calls, [], "redirect target received an HTTP request")
        self.assertEqual((self.event_calls, self.download_calls), (0, 0))
        self.assertEqual(list(self.work_root.iterdir()), [])

    def test_resolve_rejects_wrong_owner_and_typed_fields_without_directory(self):
        cases = [("dispatch_id", True), ("profile_revision", "1"), ("event_sequence", True),
                 ("message_id", True), ("host_nonce", "wrong-owner"), ("session_id", "wrong-session"),
                 ("profile_reference", "different-profile"), ("budget_scope", "unrelated-budget")]
        for index, (field, value) in enumerate(cases):
            with self.subTest(field=field):
                self.response_transform = lambda response, k=field, v=value: response.update({k: v})
                with self.assertRaises(inbound.BridgeError):
                    self.client.resolve(f"case-{index}", f"case-{index}", "instance", "n" * 32)
                self.assertEqual(list(self.work_root.iterdir()), [])
        self.assertEqual(self.download_calls, 0)

    def test_attachment_projection_preserves_native_mime_and_bearer_contract(self):
        parent = self.resolve_response({"serial": 1, "owner": {}, "binding_id": str(uuid.uuid4()),
                                        "epoch": str(uuid.uuid4()),
                                        "lease": (datetime.now(timezone.utc) + timedelta(seconds=20)).isoformat()})
        item = parent["attachments"][0]
        for mime in ("application/pdf", "image/jpeg", "image/png", "application/octet-stream"):
            with self.subTest(mime=mime):
                candidate = {**item, "mime_type": mime}
                self.assertEqual(self.client._attachment(candidate, parent), candidate)
        for token in ("!", "".join(chr(code) for code in range(0x21, 0x7f)), "~" * 121):
            candidate = {**item, "authorization": "Bearer " + token}
            self.assertEqual(self.client._attachment(candidate, parent), candidate)
        for code in (*range(0x21), 0x7f):
            with self.subTest(rejected_code=code):
                with self.assertRaises(inbound.BridgeError):
                    self.client._attachment({**item, "authorization": "Bearer prefix" + chr(code) + "suffix"}, parent)
        for token in ("", "~" * 122, "nonascii-\u00e9"):
            with self.assertRaises(inbound.BridgeError):
                self.client._attachment({**item, "authorization": "Bearer " + token}, parent)
        self.assertEqual((self.resolve_calls, self.download_calls), (0, 0))
        self.assertEqual(list(self.work_root.iterdir()), [])

    def test_first_running_snapshot_gates_native_worker(self):
        self.first_snapshot.clear()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.call)
            self.assertTrue(self.events_entered.wait(3))
            self.assertEqual(len(self.worker_launches), self.launch_start)
            self.assertEqual(self.download_calls, 0)
            self.assertFalse(future.done())
            self.first_snapshot.set()
            response = future.result(timeout=5)
        self.assertTrue(response["ok"], response)
        self.assertEqual(self.event_calls, 1)

    def test_first_snapshot_checks_owner_state_and_exact_sequence_type(self):
        changes = [{"host_nonce": "forged-owner"}, {"sequence": True},
                   {"state": "revoked", "reason": "already_ended"},
                   {"lease_valid_until": (datetime.now(timezone.utc) + timedelta(seconds=25)).isoformat()}]
        for index, changed in enumerate(changes):
            with self.subTest(changed=list(changed)):
                self.event_transform = lambda snapshot, update=changed: snapshot.update(update)
                session = f"bad-first-snapshot-{index}"
                self.assertFalse(self.call(session=session)["ok"])
                self.assertTrue(self.scope(session).finished.wait(4))
        self.assertEqual(self.download_calls, 0)
        self.assertEqual(len(self.worker_launches), self.launch_start)

    def test_concurrent_repeat_uses_one_resolve_event_worker_and_budget(self):
        self.mode = "503_once"
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.call) for _ in range(2)]
            responses = [future.result(timeout=10) for future in futures]
        self.assertTrue(all(response["ok"] for response in responses), responses)
        self.assertEqual(responses[0]["handle"], responses[1]["handle"])
        self.assertEqual(self.call()["handle"], responses[0]["handle"])
        self.assertEqual((self.resolve_calls, self.event_calls, self.download_calls), (1, 1, 2))
        self.assertEqual(len(self.worker_launches) - self.launch_start, 1)

    def test_pdf_jpeg_and_secret_separation_with_actual_processing(self):
        output = io.StringIO()
        keylog = self.root / "must-not-write-tls-keys"
        with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog), "HTTPS_PROXY": "http://127.0.0.1:1"}), \
                redirect_stdout(output), redirect_stderr(output):
            for index, (body, mime) in enumerate(((self.body, "application/pdf"),
                                                ((FIXTURES / "sample.jpg").read_bytes(), "image/jpeg"))):
                self.body, self.mime = body, mime
                session = f"media-{index}"
                response = self.call(session=session)
                self.assertTrue(response["ok"], response)

                def consume(args):
                    with host.open_workcopy(args["handle"]) as stream:
                        actual = stream.read()
                    self.assertEqual(actual, body)
                    return json.dumps({"ok": True, "size": len(actual)})

                processed = self.call(session=session, name=CONSUMER, args={"handle": response["handle"]}, callback=consume)
                self.assertTrue(processed["ok"], processed)
                self.adapter.on_session_end(session_id=session, task_id=session)
        self.assertNotIn(SERVICE_SECRET, output.getvalue())
        self.assertNotIn(READ_SECRET, output.getvalue())
        self.assertFalse(keylog.exists())
        self.assertTrue(self.control_headers_valid)
        self.assertTrue(self.media_headers_valid)
        launches = self.worker_launches[self.launch_start:]
        self.assertEqual(len(launches), 2)
        self.assertTrue(all(not any(item.values()) for item in launches), "synthetic service secret reached native worker")

    def test_equal_sequence_keepalives_never_extend_fixed_lease(self):
        self.lease_seconds = 1.8
        response = self.call()
        self.assertTrue(response["ok"], response)
        self.remember_worker()
        scope = self.scope()
        deadline = scope.resolved.deadline_monotonic
        self.wait_until(lambda: self.records["synthetic-session"]["sent"] >= 3)
        self.assertEqual(scope.resolved.deadline_monotonic, deadline)
        self.assertTrue(scope.finished.wait(5))
        self.assertFalse(self.call()["ok"])
        self.assertEqual((self.resolve_calls, self.event_calls, self.download_calls), (1, 1, 1))
        self.assertTrue(self.closed_entered.is_set())
        self.assertTrue(all(item["workers_exited"] for item in self.closed_observations))

    def test_gap_and_disconnect_are_terminal_without_reconnect(self):
        for index, reason in enumerate(("gap", "disconnect")):
            with self.subTest(reason=reason):
                session = f"terminal-{index}"
                response = self.call(session=session)
                self.assertTrue(response["ok"], response)
                scope = self.scope(session)
                with self.lock:
                    record = self.records[session]
                    if reason == "gap":
                        record.update(sequence=3, state="revoked", reason="test_gap")
                    else:
                        record["disconnect"] = True
                self.assertTrue(scope.finished.wait(5))
                self.assertFalse(self.call(session=session)["ok"])
        self.assertEqual((self.resolve_calls, self.event_calls, self.download_calls, self.closed_calls), (2, 2, 2, 2))

    def test_closed_failure_occurs_after_worker_stream_and_callback_close(self):
        self.closed_failure = True
        downloaded = self.call()
        self.assertTrue(downloaded["ok"], downloaded)
        self.remember_worker()

        def consume(args):
            try:
                with host.open_workcopy(args["handle"]) as stream:
                    self.processing_stream = stream
                    self.processing_entered.set()
                    self.processing_release.wait(4)
                    return json.dumps({"ok": True})
            finally:
                self.processing_returned.set()

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.call, name=CONSUMER, args={"handle": downloaded["handle"]}, callback=consume)
            self.assertTrue(self.processing_entered.wait(3))
            with self.lock:
                self.records["synthetic-session"].update(sequence=2, state="revoked", reason="synthetic_cancel")
            self.wait_until(lambda: self.processing_stream.closed)
            self.assertFalse(self.closed_entered.is_set(), "ACK raced a running downstream callback")
            self.processing_release.set()
            self.assertFalse(future.result(timeout=5)["ok"])
        self.assertTrue(self.scope().finished.wait(5))
        self.assertEqual(self.closed_calls, 1)
        self.assertEqual(self.closed_observations, [{"workers_exited": True, "stream_closed": True, "callback_returned": True}])
        self.assertFalse(self.call()["ok"])
        self.assertEqual((self.resolve_calls, self.event_calls, self.download_calls), (1, 1, 1))

    def test_failed_resolve_is_tombstoned_and_end_before_start_never_resolves(self):
        self.response_transform = lambda response: response.update(host_nonce="wrong-owner")
        self.assertFalse(self.call()["ok"])
        self.assertFalse(self.call()["ok"])
        self.assertEqual(self.resolve_calls, 1)
        self.adapter.on_session_end(session_id="ended-before-start", task_id="ended-before-start")
        self.assertFalse(self.call(session="ended-before-start")["ok"])
        self.assertEqual(self.resolve_calls, 1)
        self.assertEqual(self.download_calls, 0)

    def test_ended_budget_cannot_reappear_under_new_session_and_binding(self):
        downloaded = self.call()
        self.assertTrue(downloaded["ok"], downloaded)
        self.adapter.on_session_end(session_id="synthetic-session", task_id="synthetic-session")
        self.assertTrue(self.scope().finished.wait(4))

        def reuse_budget(response):
            response["message_id"] = 1
            response["attachments"][0]["message_id"] = 1
            response["budget_scope"] = "message:1:attachment:5"

        self.response_transform = reuse_budget
        self.assertFalse(self.call(session="new-session-same-budget")["ok"])
        self.assertFalse(self.call(session="new-session-same-budget")["ok"])
        self.assertEqual((self.resolve_calls, self.event_calls, self.download_calls), (2, 1, 1))
        self.assertEqual(len(self.worker_launches) - self.launch_start, 1)

    def test_restarted_host_cannot_take_old_owner_or_refresh_budget(self):
        downloaded = self.call()
        self.assertTrue(downloaded["ok"], downloaded)
        original_instance = self.adapter.host_instance_id
        self.adapter.close()
        replacement = host.HostAdapter(self.client, inbound.HostBridge(str(self.worker), self.worker_hash))
        self.addCleanup(replacement.close)
        self.assertNotEqual(replacement.host_instance_id, original_instance)
        result = json.loads(replacement.middleware(tool_name=DOWNLOAD, args={"attachment_id": 5},
                                                  next_call=self.download_handler, session_id="synthetic-session",
                                                  task_id="synthetic-session"))
        self.assertFalse(result["ok"])
        self.assertEqual((self.resolve_calls, self.event_calls, self.download_calls), (2, 1, 1))
        self.assertEqual(len(self.worker_launches) - self.launch_start, 1)

    def test_model_context_and_unlisted_consumer_do_not_gain_activation(self):
        result = json.loads(self.download_handler({"attachment_id": 5}, task_id="synthetic-session", session_id="synthetic-session"))
        self.assertEqual(result["error"]["code"], "trusted_context_unavailable")
        with self.assertRaises(inbound.BridgeError):
            with host.open_workcopy("inbound:" + "a" * 48):
                self.fail("unbound downstream opened a workcopy")
        self.assertEqual(self.resolve_calls, 0)


if __name__ == "__main__":
    unittest.main()
