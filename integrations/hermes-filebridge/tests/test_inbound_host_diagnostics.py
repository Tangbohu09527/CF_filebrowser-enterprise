"""Fixed diagnostic contracts; synthetic objects, no worker/network or secrets."""
from contextlib import nullcontext
import importlib.util
import json
from pathlib import Path
import sys
import time
import types
import unittest
from unittest.mock import patch

PLUGIN = Path(__file__).resolve().parents[1] / "plugin"
spec = importlib.util.spec_from_file_location("cf_host_diagnostic_test", PLUGIN / "__init__.py")
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
host = __import__(spec.name + ".inbound_host", fromlist=["HostAdapter"])
control = __import__(spec.name + ".inbound_control", fromlist=["HostConfig"])
SECRET = "PRIVATE_SESSION_TOKEN_PATH_ARGUMENT_EXCEPTION"

class Timer:
    def __init__(self, *args, **kwargs): pass
    def start(self): pass
    def cancel(self): pass

class SnapshotThread:
    def __init__(self, *, target, args, **kwargs): self.scope = args[0]
    def start(self): self.scope.snapshot.set()
    def join(self, *args): pass
    def is_alive(self): return False

class MissingSnapshotThread(SnapshotThread):
    def start(self): self.scope.stopped.set(); self.scope.snapshot.set()

class HostDiagnosticTests(unittest.TestCase):
    def fixture(self):
        resolved = types.SimpleNamespace(budget_scope=SECRET, binding_id=SECRET,
            deadline_monotonic=time.monotonic()+20, dispatch_id=48,
            worker_binding={"dispatch_id": SECRET, "attachments": [{"attachment_id": 3}]})
        bridge = types.SimpleNamespace(start_dispatch=lambda value: None,
            end_dispatch=lambda value: True, close=lambda: None,
            activate=lambda value: nullcontext())
        ctl = types.SimpleNamespace(resolve=lambda *args: resolved,
            events=lambda value: types.SimpleNamespace(close=lambda: None), closed=lambda value: None)
        adapter = host.HostAdapter(ctl, bridge)
        self.addCleanup(adapter.close)
        scope = host._Scope(SECRET, SECRET)
        return adapter, scope, resolved

    def logs(self, callback):
        with self.assertLogs(host._LOGGER, level="INFO") as captured:
            result = callback()
        text = "\n".join(captured.output)
        self.assertNotIn(SECRET, text)
        return result, text

    def test_register_configuration_failure_keeps_none_and_redacts(self):
        ctx = types.SimpleNamespace(get_config=lambda key, default=None: True)
        with patch.object(control.HostConfig, "from_context", side_effect=ValueError(SECRET)):
            result, text = self.logs(lambda: host.register_host(ctx))
        self.assertIsNone(result)
        self.assertIn("stage=register_config", text)
        self.assertIn("reason=value_error", text)

    def test_register_client_failure_is_separate(self):
        config = types.SimpleNamespace(client_path=SECRET, client_sha256=SECRET, consumer_tools=())
        ctx = types.SimpleNamespace(get_config=lambda key, default=None: True)
        with patch.object(control.HostConfig, "from_context", return_value=config), \
             patch.object(control, "ControlClient", side_effect=OSError(SECRET)):
            result, text = self.logs(lambda: host.register_host(ctx))
        self.assertIsNone(result)
        self.assertIn("stage=register_client", text)
        self.assertIn("reason=os_error", text)

    def test_register_success_has_fixed_version_event(self):
        adapter, _, _ = self.fixture()
        handle = types.SimpleNamespace(dispose=lambda: None)
        ctx = types.SimpleNamespace(register_middleware=lambda *args: handle,
            register_hook=lambda *args: handle, on_unload=lambda *args: handle)
        result, text = self.logs(lambda: adapter.register(ctx))
        self.assertIs(result, adapter)
        self.assertIn("cf_filebridge_inbound_diagnostic_v1", text)
        self.assertIn("stage=register_success reason=ok", text)

    def test_registration_failure_retains_existing_fail_closed_contract(self):
        adapter, _, _ = self.fixture()
        ctx = types.SimpleNamespace(register_middleware=lambda *args: None,
            register_hook=lambda *args: None, on_unload=lambda *args: None)
        with self.assertLogs(host._LOGGER, level="INFO") as captured:
            with self.assertRaises(host.BridgeError) as caught: adapter.register(ctx)
        self.assertEqual(caught.exception.code, "trusted_context_unavailable")
        self.assertIn("stage=register_handles", "\n".join(captured.output))

    def test_scope_mismatch_logs_only_boolean_identifiers(self):
        adapter, _, _ = self.fixture()
        result, text = self.logs(lambda: adapter.middleware(host._DOWNLOAD,
            {"attachment_id": SECRET}, lambda args: "unexpected", session_id="private-session", task_id="private-task"))
        self.assertEqual(json.loads(result)["error"]["code"], "trusted_context_unavailable")
        self.assertIn("stage=scope", text)
        self.assertIn("identifiers_valid=True task_equals_session=False", text)
        self.assertNotIn("private-session", text)
        self.assertNotIn("private-task", text)

    def test_resolve_events_snapshot_and_worker_failures_are_distinct(self):
        for stage in ("resolve", "events", "snapshot", "worker"):
            with self.subTest(stage=stage):
                adapter, scope, _ = self.fixture()
                failed = lambda *args: (_ for _ in ()).throw(host.BridgeError("task_directory_unavailable"))
                if stage == "resolve": adapter.control.resolve = failed
                if stage == "events": adapter.control.events = failed
                if stage == "worker": adapter.bridge.start_dispatch = failed
                thread = MissingSnapshotThread if stage == "snapshot" else SnapshotThread
                with patch.object(host.threading, "Timer", Timer), patch.object(host.threading, "Thread", thread):
                    _, text = self.logs(lambda: adapter._initialize(scope))
                self.assertIn("stage=" + stage + " ", text)
                self.assertTrue(scope.stopped.is_set())
                self.assertEqual(scope.error, "task_cancelled")
                if stage == "resolve": self.assertIn("dispatch_id=None attachment_id=None", text)
                else: self.assertIn("dispatch_id=48 attachment_id=3", text)

    def test_callback_exception_is_separate_and_external_error_unchanged(self):
        adapter, scope, resolved = self.fixture()
        scope.resolved, scope.started = resolved, True
        scope.setup_finished.set()
        def failed(args): raise RuntimeError(SECRET)
        with patch.object(adapter, "_scope", return_value=scope):
            result, text = self.logs(lambda: adapter.middleware(host._DOWNLOAD, {"secret": SECRET}, failed,
                session_id="private-session", task_id="private-session"))
        self.assertEqual(json.loads(result)["error"]["code"], "trusted_context_unavailable")
        self.assertIn("stage=next_call reason=unexpected_error", text)

    def test_cleanup_failure_does_not_claim_ack_was_attempted(self):
        adapter, scope, resolved = self.fixture()
        scope.resolved = resolved
        scope.setup_finished.set()
        def failed(value): raise RuntimeError(SECRET)
        adapter.bridge.end_dispatch = failed
        _, text = self.logs(lambda: adapter._terminate(scope))
        self.assertIn("stage=cleanup reason=unexpected_error", text)
        self.assertNotIn("close_ack", text)
        self.assertTrue(scope.finished.is_set())

    def test_event_stream_error_is_safe(self):
        adapter, scope, resolved = self.fixture()
        scope.resolved = resolved
        scope.setup_finished.set()
        class Stream:
            def __iter__(self): raise ValueError(SECRET)
            def close(self): pass
        scope.stream = Stream()
        _, text = self.logs(lambda: adapter._events(scope))
        self.assertIn("stage=events_stream reason=value_error", text)

    def test_unknown_codes_and_invalid_numeric_values_never_leak(self):
        _, scope, resolved = self.fixture()
        scope.resolved = resolved
        resolved.dispatch_id = SECRET
        resolved.worker_binding["attachments"][0]["attachment_id"] = True
        _, text = self.logs(lambda: host._diagnostic("resolve", host.BridgeError(SECRET), scope=scope))
        self.assertIn("reason=unexpected_error", text)
        self.assertIn("dispatch_id=None attachment_id=None", text)

    def test_logging_exception_does_not_change_denial_or_success(self):
        adapter, _, _ = self.fixture()
        with patch.object(host._LOGGER, "warning", side_effect=RuntimeError(SECRET)):
            result = adapter.middleware(host._DOWNLOAD, {}, lambda args: "unexpected", session_id="one", task_id="two")
        self.assertEqual(json.loads(result)["error"]["code"], "trusted_context_unavailable")
        handle = types.SimpleNamespace(dispose=lambda: None)
        ctx = types.SimpleNamespace(register_middleware=lambda *args: handle,
            register_hook=lambda *args: handle, on_unload=lambda *args: handle)
        with patch.object(host._LOGGER, "info", side_effect=RuntimeError(SECRET)):
            self.assertIs(adapter.register(ctx), adapter)

if __name__ == "__main__": unittest.main()
