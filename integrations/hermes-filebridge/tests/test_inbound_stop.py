"""Failure-injection unit tests for bounded shutdown and truthful closed ACKs.

The child process and control client here are explicit test doubles. Actual
native worker/HTTPS and official request integration are separate test suites.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


PLUGIN = Path(__file__).resolve().parents[1] / "plugin" / "__init__.py"
spec = importlib.util.spec_from_file_location("cf_inbound_stop_test", PLUGIN)
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
from cf_inbound_stop_test import inbound, inbound_host


class Output:
    def __init__(self, initialized=True):
        self.initialized = initialized
        self.first = True
        self.reading = threading.Event()
        self.release = threading.Event()
        self.closed = False

    def readline(self, _limit):
        if self.first:
            self.first = False
            return json.dumps({"ok": self.initialized}).encode() + b"\n"
        self.reading.set()
        self.release.wait(10)
        return b""

    def close(self):
        self.closed = True


class Process:
    def __init__(self, *, initialized=True, exit_on_kill=False):
        self.stdin = io.BytesIO()
        self.stdout = Output(initialized)
        self.exited = False
        self.exit_on_kill = exit_on_kill
        self.waits = []
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_started = threading.Event()
        self.wait_gate = None

    def poll(self):
        return 0 if self.exited else None

    def wait(self, timeout=None):
        self.waits.append(timeout)
        self.wait_started.set()
        if self.wait_gate is not None:
            self.wait_gate.wait(2)
        if not self.exited:
            raise subprocess.TimeoutExpired("synthetic-child", timeout)
        return 0

    def terminate(self):
        self.terminate_calls += 1

    def kill(self):
        self.kill_calls += 1
        if self.exit_on_kill:
            self.exited = True


class StopTests(unittest.TestCase):
    def process(self, **kwargs):
        process = Process(**kwargs)
        def release():
            process.exited = True
            if process.wait_gate is not None:
                process.wait_gate.set()
            process.stdout.release.set()
        self.addCleanup(release)
        return process

    def bridge(self, process):
        bridge = inbound.HostBridge(str(PLUGIN), "0" * 64)
        binding = {"dispatch_id": "dispatch", "task_id": "task", "attachments": [{"attachment_id": 1}]}
        with patch.object(inbound, "_client", return_value=PLUGIN), patch.object(inbound.subprocess, "Popen", return_value=process):
            bridge.start_dispatch(binding)
        return bridge

    def test_unkillable_process_never_reports_closed_on_repeat(self):
        process = self.process()
        bridge = self.bridge(process)
        self.assertTrue(process.stdout.reading.wait(1))
        before = time.monotonic()
        self.assertFalse(bridge.end_dispatch("dispatch"))
        self.assertFalse(bridge.end_dispatch("dispatch"))
        self.assertLess(time.monotonic() - before, 1)
        self.assertEqual(process.waits, [2, 2, 2, 2, 2, 2])
        self.assertEqual(process.kill_calls, 2)
        self.assertFalse(process.stdout.closed, "cannot close stdout while reader is blocked")
        self.assertIsNotNone(bridge._dispatches["dispatch"], "must retain the unjoined child")

    def test_concurrent_end_does_not_ack_cleared_tombstone(self):
        process = self.process()
        process.wait_gate = threading.Event()
        bridge = self.bridge(process)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(bridge.end_dispatch, "dispatch")
            self.assertTrue(process.wait_started.wait(1))
            second = pool.submit(bridge.end_dispatch, "dispatch")
            self.assertFalse(second.done())
            process.wait_gate.set()
            self.assertFalse(first.result(timeout=2))
            self.assertFalse(second.result(timeout=2))
        self.assertEqual(process.waits, [2] * 6)

    def test_killed_child_reports_success_only_after_exit(self):
        process = self.process(exit_on_kill=True)
        bridge = self.bridge(process)
        self.assertTrue(bridge.end_dispatch("dispatch"))
        self.assertIsNotNone(process.poll())
        self.assertEqual(process.waits, [2, 2, 2])
        self.assertEqual(process.terminate_calls, 1)
        self.assertEqual(process.kill_calls, 1)
        self.assertTrue(bridge.end_dispatch("dispatch"))
        self.assertEqual(process.kill_calls, 1)

    def test_initialization_failure_retains_unjoined_child(self):
        process = self.process(initialized=False)
        bridge = inbound.HostBridge(str(PLUGIN), "0" * 64)
        binding = {"dispatch_id": "dispatch", "task_id": "task", "attachments": [{"attachment_id": 1}]}
        with patch.object(inbound, "_client", return_value=PLUGIN), patch.object(inbound.subprocess, "Popen", return_value=process):
            with self.assertRaises(inbound.BridgeError):
                bridge.start_dispatch(binding)
        self.assertIsNotNone(bridge._dispatches["dispatch"])
        self.assertFalse(bridge.end_dispatch("dispatch"))

    def test_blocked_processing_close_is_bounded_and_not_acknowledged(self):
        process = self.process(exit_on_kill=True)
        bridge = self.bridge(process)
        released = threading.Event()
        self.addCleanup(released.set)
        class Stream:
            closed = False
            def close(self):
                released.wait(10)
                self.closed = True
        stream = Stream()
        dispatch = bridge._dispatches["dispatch"]
        with dispatch.files_lock:
            dispatch.files.add(stream)
        before = time.monotonic()
        self.assertFalse(bridge.end_dispatch("dispatch"))
        self.assertLess(time.monotonic() - before, 3)
        self.assertFalse(stream.closed)
        released.set()
        self.assertTrue(dispatch._streams_closed.wait(1))
        self.assertTrue(bridge.end_dispatch("dispatch"))

    def test_host_service_environment_is_not_inherited_by_worker(self):
        process = self.process(exit_on_kill=True)
        with patch.dict(os.environ, {"CF_FILEBRIDGE_HOST_TEST_SECRET": "synthetic-never-a-credential"}), \
                patch.object(inbound.subprocess, "Popen", return_value=process) as popen:
            dispatch = inbound._Dispatch(PLUGIN, b"{}")
        self.assertFalse(any(key.upper().startswith("CF_FILEBRIDGE_HOST_") for key in popen.call_args.kwargs["env"]))
        self.assertTrue(dispatch.stop())


class AdapterAcknowledgmentTests(unittest.TestCase):
    def test_failed_local_join_does_not_send_closed(self):
        class Events:
            def __init__(self):
                self.initial = True
                self.stopped = threading.Event()
            def __iter__(self):
                return self
            def __next__(self):
                if self.initial:
                    self.initial = False
                    return "running"
                self.stopped.wait(3)
                raise StopIteration
            def close(self):
                self.stopped.set()
        class Control:
            def __init__(self):
                self.acks = []
                self.stream = Events()
            def resolve(self, session, task, instance, nonce):
                return SimpleNamespace(binding_id="binding", budget_scope="message:1:attachment:1",
                    deadline_monotonic=time.monotonic()+3, worker_binding={"dispatch_id": "dispatch"})
            def events(self, _resolved):
                return self.stream
            def closed(self, resolved):
                self.acks.append(resolved)
        class Bridge:
            def __init__(self):
                self.end_calls = 0
            def start_dispatch(self, _binding):
                pass
            @contextmanager
            def activate(self, _dispatch):
                yield
            def end_dispatch(self, _dispatch):
                self.end_calls += 1
                return False  # Explicit failure to join the simulated child.
            def close(self):
                return False
        control, bridge = Control(), Bridge()
        adapter = inbound_host.HostAdapter(control, bridge)
        self.addCleanup(adapter.close)
        result = adapter.middleware("filebrowser_download_inbound", {"attachment_id": 1},
                                    lambda _args: "called", task_id="session", session_id="session")
        self.assertEqual(result, "called")
        adapter.on_session_end(session_id="session")
        self.assertGreaterEqual(bridge.end_calls, 1)
        self.assertEqual(control.acks, [])
        result = json.loads(adapter.middleware("filebrowser_download_inbound", {"attachment_id": 1},
            lambda _args: self.fail("ended scope reached the handler"), task_id="session", session_id="session"))
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
