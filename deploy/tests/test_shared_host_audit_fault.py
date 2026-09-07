#!/usr/bin/env python3
"""Fault-probe counterexamples only: no ptrace, service, network or VM runs."""
from __future__ import annotations

import base64
import copy
import contextlib
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("audit_fault_tests", ROOT / "scripts/tests/shared_host_audit_fault.py")
fault = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fault)


def snapshot():
    return {"container": "a" * 64, "image": "sha256:" + "b" * 64,
            "pid": 100, "starttime": 1234, "init_pid": 99, "restart_count": 0,
            "database": [1, 2], "fds": [3], "threads": {100: [1234, 200], 101: [1235, 200]}}


class TraceTests(unittest.TestCase):
    def test_only_selected_db_fds_all_threads_every_write_and_raw_arguments(self):
        command = fault.strace_command(100, [3, 7], True)
        self.assertIn("--trace-fds=3,7", command)
        self.assertIn("raw=all", command)
        self.assertIn("inject=pwrite64:error=EIO:when=1+", command)
        self.assertIn("-f", command)
        self.assertEqual(command[-2:], ["-p", "100"])
        self.assertNotIn("-P", command)
        self.assertNotIn("-o", command)
        self.assertNotIn("write=", " ".join(command))
        self.assertFalse(any("inject=" in item for item in fault.strace_command(100, [3], False)))

    def test_exec_children_detach_and_unverified_tid_cannot_count(self):
        self.assertIn("--detach-on=execve", fault.strace_command(100, [3], True))
        verifier = mock.Mock(side_effect=fault.FaultError("trace_thread_not_owned"))
        counts = fault.TraceCounts(100, [3], thread_check=verifier)
        with self.assertRaises(fault.FaultError):
            counts.feed(b"[pid 999] pwrite64(0x3, 0xc001000, 0x1000, 0x2000) = -1 EIO (Input/output error) (INJECTED)\n")
        verifier.assert_called_once_with(999)
        self.assertEqual(counts.summary()["writes"], 0)

    def test_live_thread_guard_requires_tgid_uid_starttime_tracer_and_db_inode(self):
        info = {"tgid": 100, "uid": [10001] * 4, "starttime": 1235, "tracer": 200}
        detaching = [False]
        guard = fault.trace_thread_guard(snapshot(), 200, detaching)
        with mock.patch.object(fault, "process_info", return_value=info), mock.patch.object(fault.os, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=2)):
            guard(101)
            for key, value in (("tgid", 999), ("uid", [0] * 4), ("starttime", 999), ("tracer", 0)):
                changed = dict(info, **{key: value})
                with mock.patch.object(fault, "process_info", return_value=changed), self.subTest(field=key), self.assertRaises(fault.FaultError):
                    guard(101)
            with mock.patch.object(fault.os, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=9)), self.assertRaises(fault.FaultError):
                guard(101)
            detaching[0] = True
            with mock.patch.object(fault, "process_info", return_value=dict(info, tracer=0)):
                guard(101)

    def test_raw_success_and_actual_injection_are_distinct_counts(self):
        counts = fault.TraceCounts(100, [3])
        counts.feed(b"[pid   101] pwrite64(0x3, 0xc001000, 0x1000, 0x2000) = 0x1000\n")
        counts.feed(b"[pid   102] pwrite64(0x3, 0xc002000, 0x1000, 0x3000) = -1 EIO (Input/output error) (INJECTED)\n")
        self.assertEqual(counts.finish(), {"writes": 2, "successful": 1, "injected_eio": 1})
        self.assertNotIn("0xc", json.dumps(counts.summary()))

    def test_interleaved_unfinished_write_requires_matching_completion(self):
        counts = fault.TraceCounts(100, [3])
        counts.feed(b"[pid 101] pwrite64(0x3, 0xabcd, 0x10, 0) <unfinished ...>\n")
        counts.feed(b"[pid 102] pwrite64(0x3, 0xabce, 0x10, 0) = 0x10\n")
        counts.feed(b"[pid 101] <... pwrite64 resumed>) = -1 EIO (Input/output error) (INJECTED)\n")
        self.assertEqual(counts.finish()["injected_eio"], 1)

    def test_uncertain_trace_never_passes_or_echoes_secrets(self):
        for raw in (b'pwrite64(3, "SECRET_PASSWORD", 4, 0) = 4\n',
                    b'pwrite64(0x4, 0xabc, 0x10, 0) = 0x10\n',
                    b'pwrite64(0x3, 0xabc, 0x10, 0) = -1 EIO (Input/output error)\n',
                    b'URL=https://secret.test Token=SECRET_TOKEN\n',
                    b'[pid 101] <... pwrite64 resumed>) = 0x10\n',
                    b'pwrite64(0x3, 0xabc, 0x10, 0) <unfinished ...>\n',
                    b'pwrite64(0x3, 0xabc, 0x10, 0) = 0x10', b'X' * 4097):
            with self.subTest(raw_length=len(raw)):
                counts = fault.TraceCounts(100, [3])
                with self.assertRaises(fault.FaultError) as raised:
                    counts.feed(raw)
                    counts.finish()
                self.assertNotIn("SECRET", str(raised.exception))
                self.assertNotIn("https", str(raised.exception))


class ContractTests(unittest.TestCase):
    def test_only_exact_actual_503_dto_with_server_request_id_passes(self):
        reply = fault.api.Reply(503, {"x-request-id": "a" * 32}, b'{"status":503,"message":"audit unavailable"}')
        self.assertEqual(fault.fault_reply(reply), "a" * 32)
        for status, data, request_id in ((500, {"status": 503, "message": "audit unavailable"}, "a" * 32),
                (503, {"status": 503, "message": "audit_unavailable"}, "a" * 32),
                (503, {"status": 503, "message": "audit unavailable", "token": "SECRET"}, "a" * 32),
                (503, {"status": 503, "message": "audit unavailable"}, "SECRET")):
            with self.subTest(status=status, request_id_length=len(request_id)):
                with self.assertRaises(fault.FaultError):
                    fault.fault_reply(fault.api.Reply(status, {"x-request-id": request_id}, json.dumps(data).encode()))

    def test_identity_or_thread_coverage_change_refuses(self):
        before = snapshot()
        fault.check_snapshot(before, snapshot(), 200)
        for field, value in (("container", "c" * 64), ("image", "sha256:" + "d" * 64),
                ("pid", 102), ("starttime", 1236), ("fds", [4]), ("database", [1, 3]),
                ("restart_count", 1), ("threads", {}), ("threads", {100: [1234, 0]})):
            after = copy.deepcopy(before)
            after[field] = value
            with self.subTest(field=field), self.assertRaises(fault.FaultError):
                fault.check_snapshot(before, after, 200)
        after = copy.deepcopy(before)
        after["threads"][102] = [1237, 200]
        fault.check_snapshot(before, after, 200)

    def test_same_tid_with_new_starttime_refuses(self):
        after = snapshot()
        after["threads"][101][0] += 1
        with self.assertRaises(fault.FaultError):
            fault.check_snapshot(snapshot(), after, 200)

    def test_json_roundtrip_does_not_hide_same_tid_replacement(self):
        after = snapshot()
        after["threads"][101][0] += 1
        with self.assertRaises(fault.FaultError):
            fault.check_snapshot(json.loads(json.dumps(snapshot())), after, 200)

    def test_successful_write_counts_cannot_pass_injection_window(self):
        for result in ({"writes": 0, "successful": 0, "injected_eio": 0},
                       {"writes": 2, "successful": 1, "injected_eio": 1}):
            with self.assertRaises(fault.FaultError):
                fault.check_counts(result, True)
        fault.check_counts({"writes": 2, "successful": 0, "injected_eio": 2}, True)
        fault.check_counts({"writes": 2, "successful": 2, "injected_eio": 0}, False)

    def test_watchdog_stops_on_dead_parent_or_deadline_not_only_ssh_timeout(self):
        self.assertFalse(fault.watchdog_due(True, 1.0, 5.0))
        self.assertTrue(fault.watchdog_due(False, 1.0, 5.0))
        self.assertTrue(fault.watchdog_due(True, 5.0, 5.0))

    def test_detach_escalation_uses_only_owned_pidfd_and_finite_waits(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("private", 2), 0]
        with mock.patch.object(fault, "pidfd_signal") as send, mock.patch.object(signal, "SIGKILL", 9, create=True):
            fault.detach(process, 55)
        self.assertEqual(send.call_args_list, [mock.call(55, signal.SIGINT), mock.call(55, 9)])
        self.assertEqual(process.wait.call_args_list, [mock.call(timeout=2), mock.call(timeout=2)])

    def test_failed_tracer_pidfd_setup_still_detaches_the_owned_child(self):
        args = SimpleNamespace(mode="observe", control_file="control", expected_container="a" * 64,
                               expected_image="sha256:" + "b" * 64, ready_file="ready", release_file="release")
        initial = snapshot()
        initial["healthy"] = True
        for value in initial["threads"].values():
            value[1] = 0
        target = {"sha256": "c" * 64, "temporary_count": 0}
        process = mock.Mock(pid=200)
        process.poll.return_value = None
        process.wait.return_value = 0
        control = {"version": 1, "root": "/cf-audit-fault-" + "a" * 12, "original_sha256": "c" * 64}
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(fault, "private_json", return_value=control))
            stack.enter_context(mock.patch.object(fault, "command", return_value=b"strace -- version 6.13\n"))
            stack.enter_context(mock.patch.object(fault, "identify", return_value=initial))
            stack.enter_context(mock.patch.object(fault, "target_snapshot", return_value=target))
            stack.enter_context(mock.patch.object(fault.api, "protected_path"))
            stack.enter_context(mock.patch.object(fault.subprocess, "Popen", return_value=process))
            stack.enter_context(mock.patch.object(fault.os, "pidfd_open", side_effect=[33, OSError("PRIVATE_ERROR")], create=True))
            stack.enter_context(mock.patch.object(fault.signal, "pidfd_send_signal", create=True))
            stack.enter_context(mock.patch.object(fault.os, "close"))
            stack.enter_context(mock.patch.object(fault.os, "read", return_value=b""))
            stack.enter_context(mock.patch.object(fault, "process_info", return_value={"starttime": 99, "ppid": fault.os.getpid()}))
            report = fault.server_window(args)
        process.send_signal.assert_called_once_with(signal.SIGINT)
        process.wait.assert_called_once_with(timeout=2)
        self.assertFalse(report["passed"])
        self.assertTrue(report["detached"])
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_unregistered_cleanup_refuses_wrong_parent_or_starttime(self):
        for current in ({"ppid": -1, "starttime": 99}, {"ppid": fault.os.getpid(), "starttime": 100}):
            process = mock.Mock(pid=200)
            process.poll.return_value = None
            with mock.patch.object(fault, "process_info", return_value=current), self.assertRaises(fault.FaultError):
                fault.detach_unregistered_child(process, 99)
            process.send_signal.assert_not_called()
            process.kill.assert_not_called()

    def test_detach_does_not_signal_an_already_exited_tracer(self):
        process = mock.Mock()
        process.poll.return_value = 0
        with mock.patch.object(fault, "pidfd_signal") as send:
            fault.detach(process, 55)
        send.assert_not_called()


def acceptance():
    result = fault.FaultAcceptance.__new__(fault.FaultAcceptance)
    result.checks = []
    result.admin = "PRIVATE_ADMIN_SESSION"
    result.args = SimpleNamespace(ready_file="ready", server_report="server", restart_report="restart")
    result.state = {"root": "/cf-audit-fault-" + "a" * 12, "users": {"fault": {
        "id": 2, "username": "PRIVATE_USER", "password": "PRIVATE_PASSWORD"}},
        "fault": {"session": "PRIVATE_SAVED_SESSION", "prepared": True,
                  "original": base64.b64encode(b"A" * 4096).decode(),
                  "attempted": base64.b64encode(b"B" * 4096).decode(), "control_sha256": "c" * 64}}
    result.checkpoint = mock.Mock()
    result.login_admin = mock.Mock()
    result.client = SimpleNamespace(request=mock.Mock())
    result.download = mock.Mock()
    return result


def terminal_event(test):
    path = test.state["root"] + "/target.bin"
    return {"requestId": "1" * 32, "username": "PRIVATE_USER", "userId": 2,
            "source": fault.api.SOURCE, "path": path, "canonicalPath": path,
            "action": "file.modify", "origin": "http", "authMethod": "session",
            "result": "success", "httpStatus": 200,
            "metadata": {"schemaVersion": 1, "method": "PUT", "overwrite": True}}


class ClientPhaseTests(unittest.TestCase):
    def test_control_fault_following_put_keep_identical_session_parameters_and_body(self):
        test = acceptance()
        test.ready = mock.Mock()
        test.terminal = mock.Mock()
        test.items = mock.Mock(return_value=[])
        test.client.request.side_effect = [
            fault.api.Reply(200, {"x-request-id": "1" * 32}, b""),
            fault.api.Reply(200, {"x-request-id": "2" * 32}, b""),
            fault.api.Reply(503, {"x-request-id": "3" * 32}, b'{"status":503,"message":"audit unavailable"}'),
            fault.api.Reply(200, {"x-request-id": "4" * 32}, b"")]
        test.download.side_effect = [fault.api.Reply(200, {}, body * 4096) for body in (b"B", b"A", b"A", b"B")]
        test.control()
        test.login_admin.reset_mock()
        test.fault()
        test.login_admin.assert_not_called()
        server = {"passed": True, "detached": True, "mode": "inject", "control_sha256": "c" * 64,
                  "counts": {"writes": 1, "successful": 0, "injected_eio": 1}, "identity": snapshot()}
        restart = {"passed": True, "phase": "restarted", "control_sha256": "c" * 64, "prior_identity": snapshot()}
        with mock.patch.object(fault, "private_json", side_effect=[server, restart]):
            test.verify()
        calls = test.client.request.call_args_list
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[0], calls[2])
        self.assertEqual(calls[0], calls[3])
        self.assertEqual(calls[0].kwargs["token"], "PRIVATE_SAVED_SESSION")
        self.assertEqual(calls[0].kwargs["query"], {"source": fault.api.SOURCE, "path": "/target.bin"})
        self.assertEqual(calls[0].kwargs["body"], b"B" * 4096)
        self.assertEqual(calls[1].kwargs["body"], b"A" * 4096)
        self.assertTrue(test.state["fault"]["verified"])
        self.assertNotIn("PRIVATE", json.dumps(test.checks))

    def test_not_ready_and_replayed_fault_never_issue_put(self):
        for ready in ({}, {"version": 1, "ready": False}, {"version": 1, "ready": True, "mode": "observe"}):
            test = acceptance()
            test.state["fault"]["control_complete"] = True
            with mock.patch.object(fault, "private_json", return_value=ready), self.assertRaises(fault.FaultError):
                test.fault()
            test.client.request.assert_not_called()
        test = acceptance()
        test.state["fault"].update(control_complete=True, attempted_fault=True)
        with self.assertRaises(fault.FaultError):
            test.fault()
        test.client.request.assert_not_called()

    def test_audit_filter_uses_handler_requestID_not_DTO_requestId(self):
        test = acceptance()
        test.request = mock.Mock(return_value=fault.api.Reply(200, {}, b'{"items":[],"hasMore":false}'))
        self.assertEqual(test.items("1" * 32), [])
        query = test.request.call_args.kwargs["query"]
        self.assertEqual(query["requestID"], "1" * 32)
        self.assertNotIn("requestId", query)
        self.assertEqual(query["actor"], "PRIVATE_USER")
        self.assertEqual(query["path"], test.state["root"] + "/target.bin")

    def test_terminal_requires_exact_identity_session_method_and_success(self):
        test = acceptance()
        original = terminal_event(test)
        test.items = mock.Mock(return_value=[original])
        test.terminal("1" * 32)
        for key, value in (("requestId", "2" * 32), ("userId", 9), ("authMethod", "token"),
                           ("tokenRef", "PRIVATE_TOKEN"), ("source", "other"), ("result", "unknown"),
                           ("httpStatus", 503), ("canonicalPath", "/other"),
                           ("metadata", {"schemaVersion": 1, "method": "POST", "overwrite": True})):
            event = copy.deepcopy(original)
            event[key] = value
            test.items.return_value = [event]
            with self.subTest(field=key), self.assertRaises(fault.FaultError):
                test.terminal("1" * 32)

    def test_verify_requires_detach_and_new_process_evidence_before_requests(self):
        test = acceptance()
        test.state["fault"].update(response_validated=True, request_id="3" * 32, control_ids=["1" * 32])
        for server in ({}, {"passed": True, "detached": False},
                       {"passed": True, "detached": True, "mode": "observe"}):
            with mock.patch.object(fault, "private_json", return_value=server), self.assertRaises(fault.FaultError):
                test.verify()
            test.login_admin.assert_not_called()
            test.client.request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
