"""Test-only JSON IPC, including actual native Windows sharing conflicts.

This imports only the project's standard-library helper, never official Hermes.
POSIX open handles do not block reads or rename: those platforms assert the
corresponding immediate success instead of pretending to reproduce NT sharing.
"""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cf_joint_host_ipc_test", HERE / "hermes_joint_host.py")
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class HermesJointHostIPCTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cf-joint-ipc-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.status = self.root / "external-host-status.json"
        self.status.write_text('{"old": true}', encoding="utf-8")
        self.subject = host.ExternalHermesHost(Path("python"), self.root, self.root,
                                               Path("worker"), hermes_commit="test")

    def open_blocker(self, share, release_after=None):
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
            kernel.CreateFileW.restype = wintypes.HANDLE
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.CloseHandle.restype = wintypes.BOOL
            handle = kernel.CreateFileW(str(self.status), 0x80000000, share, None, 3, 0x80, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            self.handle = handle

            def close():
                if self.handle is not None:
                    self.assertTrue(kernel.CloseHandle(self.handle))
                    self.handle = None
        else:
            stream = self.status.open("rb")
            close = stream.close
        self.addCleanup(close)
        if release_after is not None:
            thread = threading.Thread(target=lambda: (time.sleep(release_after), close()))
            thread.start()
            self.addCleanup(thread.join)

    def test_snapshot_during_transient_open_handle(self):
        self.open_blocker(0, 0.15)
        start = time.monotonic()
        self.assertEqual(asyncio.run(self.subject.snapshot()), {"old": True})
        if os.name == "nt":
            self.assertGreaterEqual(time.monotonic() - start, 0.1)

    def test_persistent_read_conflict_is_bounded(self):
        self.open_blocker(0)
        start = time.monotonic()
        if os.name == "nt":
            with self.assertRaises(PermissionError):
                asyncio.run(self.subject.snapshot())
            self.assertGreaterEqual(time.monotonic() - start, 0.8)
        else:
            self.assertEqual(asyncio.run(self.subject.snapshot()), {"old": True})
        self.assertLess(time.monotonic() - start, 2)

    def test_atomic_publish_during_transient_open_handle(self):
        self.open_blocker(3, 0.15)  # READ | WRITE, deliberately no SHARE_DELETE.
        start = time.monotonic()
        host._write(self.status, {"new": True})
        if os.name == "nt":
            self.assertGreaterEqual(time.monotonic() - start, 0.1)
        self.assertEqual(json.loads(self.status.read_text()), {"new": True})
        self.assertFalse(self.status.with_suffix(".tmp").exists())

    def test_persistent_publish_conflict_preserves_previous_value(self):
        self.open_blocker(3)
        start = time.monotonic()
        if os.name == "nt":
            with self.assertRaises(PermissionError):
                host._write(self.status, {"new": True})
            self.assertGreaterEqual(time.monotonic() - start, 0.8)
            self.assertEqual(json.loads(self.status.read_text()), {"old": True})
        else:
            host._write(self.status, {"new": True})
            self.assertEqual(json.loads(self.status.read_text()), {"new": True})
        self.assertLess(time.monotonic() - start, 2)

    def test_bad_json_is_not_retried(self):
        self.status.write_text("{bad", encoding="utf-8")
        # Observe real file parsing and both retry layers. Windows event-loop
        # startup latency is unrelated to whether malformed JSON is retried.
        with patch.object(host, "_read_json", wraps=host._read_json) as read_json, \
             patch.object(Path, "read_text", autospec=True, side_effect=Path.read_text) as read_text, \
             patch.object(host.asyncio, "sleep", side_effect=AssertionError("Malformed JSON must not back off")) as sleep:
            with self.assertRaises(json.JSONDecodeError):
                asyncio.run(self.subject.snapshot())
            read_json.assert_awaited_once_with(self.status)
            read_text.assert_called_once_with(self.status, encoding="utf-8")
            sleep.assert_not_called()
            sleep.assert_not_awaited()

    def test_missing_snapshot_retains_five_second_timeout(self):
        self.status.unlink()
        start = time.monotonic()
        with self.assertRaises(TimeoutError):
            asyncio.run(self.subject.snapshot())
        self.assertGreaterEqual(time.monotonic() - start, 4.8)
        self.assertLess(time.monotonic() - start, 6)

    def test_unrelated_write_error_is_immediate(self):
        start = time.monotonic()
        with self.assertRaises(FileNotFoundError):
            host._write(self.root / "missing" / "file.json", {})
        self.assertLess(time.monotonic() - start, 0.5)


if __name__ == "__main__":
    unittest.main()
