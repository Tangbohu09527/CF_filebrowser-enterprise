#!/usr/bin/env python3
"""Pending acceptance counterexamples; no Docker, VM or production process runs."""
from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import http.client
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import ssl
import stat
import subprocess
import tempfile
import threading
import types
import unittest
import urllib.parse
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


api = load("pending_acceptance_tests", "scripts/tests/shared-host-api.py")
vm = load("pending_vm_tests", "scripts/tests/shared_host_vm.py")
ORIGINAL = b"A" * 4096
PREFIX = b"B" * api.PENDING_PREFIX_BYTES
IMAGE = "sha256:" + "1" * 64
CONTAINER = "2" * 64


def control():
    return {"version": 1, "root": "/cf-audit-pending-" + "a" * 12,
            "original_size": len(ORIGINAL), "original_sha256": hashlib.sha256(ORIGINAL).hexdigest(),
            "prefix_size": len(PREFIX), "prefix_sha256": hashlib.sha256(PREFIX).hexdigest()}


def acceptance():
    test = api.Acceptance.__new__(api.Acceptance)
    test.checks = []
    test.checkpoint = mock.Mock()
    test.login = mock.Mock(return_value="PRIVATE_SESSION_SENTINEL")
    test.login_admin = mock.Mock()
    test.state = {"root": control()["root"], "users": {"pending": {
        "id": 2, "username": "private-pending-user", "password": "PRIVATE_PASSWORD_SENTINEL"}},
        "pending": {"prepared": True, "original": base64.b64encode(ORIGINAL).decode(),
                    "prefix": base64.b64encode(PREFIX).decode()}}
    test.client = types.SimpleNamespace(host="files.cf.test", port=18443,
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), requests=0)
    return test


def event():
    return {"requestId": "3" * 32, "username": "private-pending-user", "userId": 2,
            "source": api.SOURCE, "path": control()["root"] + "/target.bin",
            "canonicalPath": control()["root"] + "/target.bin", "origin": "http",
            "action": "file.modify", "result": "unknown", "errorCode": "process_interrupted",
            "metadata": {"schemaVersion": 1, "method": "PUT", "overwrite": True}}


class PendingFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cf-pending-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / control()["root"].lstrip("/")
        self.directory.mkdir()
        self.target = self.directory / "target.bin"
        self.target.write_bytes(ORIGINAL)
        self.service_id = self.target.stat().st_uid
        self.assertEqual(self.service_id, self.target.stat().st_gid)

    def observe(self):
        # Actual disposable files; the observer's service ID is the local test
        # owner. Formal guest calls retain the fixed 10001 default.
        return api.audit_pending_filesystem(control(), files_root=self.root, service_id=self.service_id)

    def test_only_a_stable_complete_new_prefix_is_ready(self):
        original = self.observe()
        self.assertIsNone(original["temporary"])
        temporary = self.directory / ".filebrowser-write-1234"
        temporary.write_bytes(PREFIX[:1024])
        self.assertFalse(self.observe()["temporary"]["complete"])
        temporary.write_bytes(PREFIX)
        ready = self.observe()
        self.assertTrue(ready["temporary"]["complete"])
        self.assertEqual(ready["target"], original["target"])
        self.assertEqual(ready["directory"], original["directory"])
        self.assertEqual(self.target.read_bytes(), ORIGINAL)

    def test_target_overwrite_wrong_prefix_and_multiple_temps_refuse(self):
        self.target.write_bytes(b"C" * len(ORIGINAL))
        with self.assertRaises(api.AcceptanceError):
            self.observe()
        self.target.write_bytes(ORIGINAL)
        temporary = self.directory / ".filebrowser-write-1234"
        temporary.write_bytes(b"D" * len(PREFIX))
        with self.assertRaises(api.AcceptanceError):
            self.observe()
        temporary.write_bytes(PREFIX)
        (self.directory / ".filebrowser-write-5678").write_bytes(PREFIX)
        with self.assertRaises(api.AcceptanceError):
            self.observe()

    def test_extra_entry_and_bad_control_refuse(self):
        (self.directory / "unrelated.txt").write_bytes(b"unrelated")
        with self.assertRaises(api.AcceptanceError):
            self.observe()
        for field, value in (("root", "/../../secret"), ("prefix_size", 10**9),
                             ("original_sha256", "PRIVATE_SENTINEL")):
            changed = control()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(api.AcceptanceError) as caught:
                api.pending_control(changed)
            self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

    def test_hardlinked_or_symlink_metadata_refuse_without_read(self):
        original = self.target.lstat()
        for mode, links in ((original.st_mode, 2), (stat.S_IFLNK | 0o777, 1)):
            fields = list(original)
            fields[0], fields[3] = mode, links
            with self.subTest(mode=mode, links=links), mock.patch.object(Path, "lstat", return_value=os.stat_result(fields)), mock.patch.object(api.os, "open") as opened:
                with self.assertRaises(api.AcceptanceError):
                    api.pending_file_state(self.target, len(ORIGINAL), control()["original_sha256"], self.service_id)
                opened.assert_not_called()


class PendingClientTests(unittest.TestCase):
    def test_partial_upload_holds_same_strict_tls_connection_until_eof(self):
        test = acceptance()
        connection = mock.Mock()
        connection.getresponse.side_effect = http.client.RemoteDisconnected("PRIVATE_EXCEPTION_SENTINEL")
        before = (test.client.context.check_hostname, test.client.context.verify_mode)
        with mock.patch.object(api.http.client, "HTTPSConnection", return_value=connection) as factory:
            test.audit_pending_hold()
        factory.assert_called_once_with(test.client.host, test.client.port, context=test.client.context, timeout=30)
        connection.send.assert_called_once_with(PREFIX)
        connection.putheader.assert_any_call("Content-Length", str(api.PENDING_CONTENT_BYTES))
        self.assertGreater(api.PENDING_CONTENT_BYTES, len(PREFIX))
        connection.close.assert_called_once_with()
        self.assertTrue(test.state["pending"]["disconnected"])
        self.assertEqual(before, (test.client.context.check_hostname, test.client.context.verify_mode))
        self.assertNotIn("PRIVATE", json.dumps(test.checks))

    def test_response_or_deadline_is_not_success_and_always_closes(self):
        for failure in (None, TimeoutError("PRIVATE_EXCEPTION_SENTINEL")):
            test = acceptance()
            connection = mock.Mock()
            connection.getresponse.side_effect = failure
            with self.subTest(failure=type(failure).__name__), mock.patch.object(api.http.client, "HTTPSConnection", return_value=connection):
                with self.assertRaises(api.AcceptanceError) as caught:
                    test.audit_pending_hold()
            connection.close.assert_called_once_with()
            self.assertFalse(test.state["pending"].get("disconnected", False))
            self.assertNotIn("PRIVATE_EXCEPTION_SENTINEL", str(caught.exception))

    def verified(self, changed=None):
        test = acceptance()
        test.state["pending"].update(prefix_sent=True, disconnected=True)
        chosen = event() if changed is None else changed
        test.pending_audit_items = mock.Mock(side_effect=[[chosen], [chosen]])
        test.resource = mock.Mock()
        test.download = mock.Mock(side_effect=[api.Reply(200, {}, ORIGINAL), api.Reply(200, {}, b"N" * 4096)])
        return test

    def test_exact_query_uses_backend_parameter_through_real_client_request(self):
        test = acceptance()
        test.admin = "PRIVATE_SESSION_SENTINEL"
        test.client = api.Client.__new__(api.Client)
        test.client.host, test.client.port = "files.cf.test", 18443
        test.client.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        test.client.requests = 0
        response = mock.Mock(status=200)
        response.getheaders.return_value = [("Content-Type", "application/json")]
        response.read.return_value = json.dumps({"items": [event()], "hasMore": False}).encode()
        connection = mock.Mock()
        connection.getresponse.return_value = response
        query_source = (ROOT / "backend/http/audit_query.go").read_text(encoding="utf-8")
        supported_block = query_source.split("supported := map[string]struct{}{", 1)[1].split("\n\t}", 1)[0]
        supported = set(re.findall(r'"([A-Za-z]+)":', supported_block))
        with mock.patch.object(api.http.client, "HTTPSConnection", return_value=connection):
            self.assertEqual(test.pending_audit_items(request_id=event()["requestId"]), [event()])
        method, path = connection.request.call_args.args
        self.assertEqual(method, "GET")
        parsed = urllib.parse.urlsplit(path)
        self.assertEqual(parsed.path, "/api/audit")
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        self.assertTrue(set(query).issubset(supported))
        self.assertEqual(query, {"actor": [event()["username"]], "source": [api.SOURCE],
            "path": [event()["path"]], "action": ["file.modify"], "limit": ["100"],
            "requestID": [event()["requestId"]]})
        self.assertNotIn("PRIVATE_SESSION_SENTINEL", path)
        connection.close.assert_called_once_with()
        self.assertEqual(test.client.requests, 1)

    def test_recovered_event_requires_exact_query_and_keeps_identifier_private(self):
        test = self.verified()
        with mock.patch.object(api.secrets, "token_bytes", return_value=b"N" * 4096):
            test.audit_pending_verify()
        self.assertEqual(test.state["pending"]["request_id"], event()["requestId"])
        test.pending_audit_items.assert_has_calls([mock.call(), mock.call(request_id=event()["requestId"])])
        self.assertTrue(test.state["pending"]["verified"])
        serialized = json.dumps(test.checks)
        self.assertNotIn(event()["requestId"], serialized)
        self.assertNotIn(test.state["users"]["pending"]["username"], serialized)

    def test_wrong_terminal_identity_or_method_never_reaches_following_write(self):
        cases = [("result", "success"), ("errorCode", "other"), ("httpStatus", 200),
                 ("path", "/other"), ("canonicalPath", "/other"), ("source", "other"),
                 ("username", "other"), ("userId", 3), ("action", "file.upload"),
                 ("origin", "webdav"), ("requestId", "arbitrary"),
                 ("metadata", {"schemaVersion": 1, "method": "POST", "overwrite": True})]
        for key, value in cases:
            chosen = event()
            chosen[key] = value
            test = self.verified(chosen)
            with self.subTest(field=key), self.assertRaises(api.AcceptanceError):
                test.audit_pending_verify()
            test.resource.assert_not_called()

    def test_duplicate_recovery_events_or_original_changed_refuse(self):
        test = self.verified()
        test.pending_audit_items.side_effect = [[event(), event()]]
        with self.assertRaises(api.AcceptanceError):
            test.audit_pending_verify()
        test.resource.assert_not_called()
        test = self.verified()
        test.download.side_effect = [api.Reply(200, {}, b"changed")]
        with self.assertRaises(api.AcceptanceError):
            test.audit_pending_verify()
        test.resource.assert_not_called()


class PendingContainerTests(unittest.TestCase):
    def fixture(self):
        compose = yaml.safe_load((ROOT / "deploy/shared-host/compose.yaml").read_text(encoding="utf-8"))
        self.assertEqual(len(compose["services"]), 1)
        service = next(iter(compose["services"]))
        return {"Id": CONTAINER, "Image": IMAGE, "RestartCount": 0,
                "Config": {"Labels": {"com.docker.compose.project": "cf-filebrowser", "com.docker.compose.service": service}},
                "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
                "State": {"Running": True, "ExitCode": 0, "OOMKilled": False, "Health": {"Status": "healthy"}}}

    def execute_guest_script(self, *, info=None, ids=None, kill=True):
        before = self.fixture() if info is None else info
        after = copy.deepcopy(before)
        after["State"].update(Running=False, ExitCode=137)
        calls = []
        self.last_calls = calls
        def run(command, **kwargs):
            calls.append(command)
            self.assertEqual(command[:3], ["docker", "--host", "unix:///var/run/docker.sock"])
            self.assertTrue(kwargs["capture_output"])
            self.assertTrue(kwargs["check"])
            self.assertLessEqual(kwargs["timeout"], 15)
            operation = command[4]
            if operation == "ls":
                output = "\n".join([CONTAINER] if ids is None else ids).encode()
            elif operation == "kill":
                self.assertEqual(command[5:], ["--signal", "KILL", CONTAINER])
                output = b""
            else:
                self.assertEqual(operation, "inspect")
                killed = any(call[4] == "kill" for call in calls)
                output = json.dumps([after if killed else before]).encode()
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")
        script = vm.pending_container_script(IMAGE, CONTAINER, kill=kill)
        source = script.split("\n", 1)[1].rsplit("PENDING_CONTAINER\n", 1)[0]
        with mock.patch.object(subprocess, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            exec(compile(source, "<pending-guest-test>", "exec"), {})
        return calls

    def test_real_compose_service_is_accepted_before_any_kill(self):
        calls = self.execute_guest_script(kill=False)
        self.assertEqual([call[4] for call in calls], ["ls", "inspect"])

    def test_only_verified_service_is_killed_and_identity_rechecked(self):
        calls = self.execute_guest_script()
        self.assertEqual([call[4] for call in calls], ["ls", "inspect", "kill", "inspect"])

    def test_wrong_project_service_image_or_multiple_containers_refuse(self):
        for key, value in (("Image", "sha256:" + "9" * 64), ("Id", "9" * 64),
                           ("Config", {"Labels": {"com.docker.compose.project": "sentinel", "com.docker.compose.service": self.fixture()["Config"]["Labels"]["com.docker.compose.service"]}}),
                           ("Config", {"Labels": {"com.docker.compose.project": "cf-filebrowser", "com.docker.compose.service": "unrelated-service"}}),
                           ("HostConfig", {"RestartPolicy": {"Name": "always"}})):
            info = self.fixture()
            info[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.execute_guest_script(info=info)
            self.assertFalse(any(call[4] == "kill" for call in self.last_calls))
        with self.assertRaises(RuntimeError):
            self.execute_guest_script(ids=[CONTAINER, "4" * 64])
        with self.assertRaises(vm.VerificationError):
            vm.pending_container_script(IMAGE, kill=True)


class PendingFailureEvidenceTests(unittest.TestCase):
    def report(self):
        return {"version": 1, "phase": "audit-pending-prepare", "passed": False, "requests": 3,
                "checks": [{"check": "pending_create", "passed": False, "http_status": 503}],
                "failure": "PRIVATE_EXCEPTION_SENTINEL", "body": "PRIVATE_RESPONSE_SENTINEL"}

    def test_failed_check_survives_and_private_fields_are_discarded(self):
        report = self.report()
        safe = vm.pending_api_failure(report, report["phase"])
        self.assertEqual(safe["checks"], report["checks"])
        self.assertEqual(safe["requests"], 3)
        self.assertEqual(safe["failure"], "api_check_failed")
        self.assertFalse(safe["passed"])
        self.assertNotIn("PRIVATE", json.dumps(safe))
        self.assertNotIn("body", safe)

    def test_wrong_phase_or_unbounded_unknown_check_is_rejected(self):
        cases = [("phase", "verify-restored"), ("version", True), ("checks", [
            {"check": "PRIVATE_REQUEST_SENTINEL", "passed": False}]), ("checks", [
            {"check": "pending_create", "passed": False, "http_status": 999}]), ("checks", [
            {"check": "pending_create", "passed": False, "body": "PRIVATE_RESPONSE_SENTINEL"}]),
            ("checks", [{"check": "pending_create", "passed": True}] * 101)]
        for field, value in cases:
            report = self.report()
            report[field] = value
            with self.subTest(field=field):
                safe = vm.pending_api_failure(report, "audit-pending-prepare")
                self.assertEqual(safe["checks"], [])
                self.assertEqual(safe["failure"], "invalid_api_evidence")
                self.assertNotIn("PRIVATE", json.dumps(safe))
        with self.assertRaises(vm.VerificationError):
            vm.pending_api_failure(self.report(), "PRIVATE_PHASE_SENTINEL")


class PendingOrchestrationTests(unittest.TestCase):
    def run_probe(self, *, change_target=False, no_prefix=False, fail_phase=None):
        evidence, commands = {}, []
        release = threading.Event()
        original = {"target": {"inode": 1, "size": len(ORIGINAL), "complete": True},
                    "temporary": None, "directory": {"inode": 2}}
        ready = copy.deepcopy(original)
        ready["temporary"] = {"inode": 3, "size": len(PREFIX), "complete": True}
        server = types.SimpleNamespace(name="server", write_file=mock.Mock())
        client = types.SimpleNamespace(name="client", read_file=mock.Mock(return_value=json.dumps(control()).encode()))
        observations = 0
        def command(script, **kwargs):
            nonlocal observations
            commands.append(script)
            if "PENDING_FILES" in script:
                observations += 1
                observed = copy.deepcopy(original if observations == 1 or no_prefix else ready)
                if change_target and observations > 1:
                    observed["target"]["inode"] = 9
                output = json.dumps(observed).encode()
            elif "PENDING_CONTAINER" in script:
                killed = "kill=True\n" in script
                if killed:
                    release.set()
                output = json.dumps({"id": CONTAINER, "image": IMAGE, "running": not killed,
                                     "healthy": not killed, "restart_count": 0}).encode()
            else:
                self.assertIn("manage.sh start", script)
                output = b""
            return subprocess.CompletedProcess([], 0, stdout=output, stderr=b"")
        server.command_on_guest = command
        def phase(machine, name, evidence_name, **kwargs):
            self.assertIs(machine, client)
            self.assertEqual(kwargs["state_name"], "audit-pending-state.json")
            if name == "audit-pending-hold":
                self.assertEqual(kwargs["timeout"], 140)
                release.wait(timeout=0.05)
            if name == "audit-pending-" + str(fail_phase):
                label = {"prepare": "pending_create", "hold": "audit_pending_connection_interrupted",
                         "verify": "audit_pending_recovered_terminal"}[fail_phase]
                failure = vm.VerificationError("PRIVATE_EXCEPTION_SENTINEL")
                failure.api_evidence = {"version": 1, "phase": name, "passed": False, "requests": 3,
                    "checks": [{"check": label, "passed": False, "http_status": 503}],
                    "failure": "PRIVATE_EXCEPTION_SENTINEL", "body": "PRIVATE_RESPONSE_SENTINEL"}
                raise failure
            return {"passed": True, "checks": [{"check": label, "passed": True} for label in (
                "audit_pending_recovered_terminal", "audit_pending_exact_request_lookup",
                "audit_pending_original_not_overwritten", "audit_pending_following_write", "audit_pending_following_read")]}
        args = types.SimpleNamespace()
        self.evidence, self.commands = evidence, commands
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(vm, "api", side_effect=phase))
            stack.enter_context(mock.patch.object(vm, "healthy"))
            stack.enter_context(mock.patch.object(vm, "sentinel_state", return_value={"stable": True}))
            stack.enter_context(mock.patch.object(vm, "record_stage"))
            if no_prefix:
                stack.enter_context(mock.patch.object(vm.time, "monotonic", side_effect=[0, 1, 46]))
                stack.enter_context(mock.patch.object(vm.time, "sleep"))
            vm.audit_pending_interrupt(server, client, args, evidence, IMAGE,
                                       {"server": {"stable": True}, "client": {"stable": True}})
        return evidence, commands

    def test_only_complete_prefix_permits_kill_then_formal_same_image_start(self):
        evidence, commands = self.run_probe()
        self.assertEqual(sum("kill=True\n" in item for item in commands), 1)
        self.assertEqual(sum("manage.sh start" in item for item in commands), 1)
        self.assertTrue(evidence["audit_pending"]["passed"])
        self.assertTrue(all(set(check).issubset({"check", "passed", "count"}) for check in evidence["audit_pending"]["checks"]))
        self.assertNotIn(CONTAINER, json.dumps(evidence))
        self.assertNotIn(IMAGE, json.dumps(evidence))
        self.assertFalse(any(thread.name == "audit-pending-client" for thread in threading.enumerate()))

    def test_api_failures_retain_operation_and_check_without_private_exception(self):
        for phase, label in (("prepare", "pending_create"), ("hold", "audit_pending_connection_interrupted"),
                             ("verify", "audit_pending_recovered_terminal")):
            with self.subTest(phase=phase), self.assertRaises(vm.VerificationError) as caught:
                self.run_probe(fail_phase=phase)
            summary = self.evidence["audit_pending"]
            self.assertFalse(summary["passed"])
            self.assertEqual(summary["operation"], phase)
            self.assertEqual(summary["failed_api"]["phase"], "audit-pending-" + phase)
            self.assertEqual(summary["failed_api"]["checks"], [{"check": label, "passed": False, "http_status": 503}])
            self.assertNotIn("PRIVATE", json.dumps(self.evidence))
            self.assertNotIn("PRIVATE", str(caught.exception))
            self.assertEqual(sum("kill=True\n" in item for item in self.commands), 0 if phase == "prepare" else 1)
            self.assertEqual(sum("manage.sh start" in item for item in self.commands), 1 if phase == "verify" else 0)
            self.assertFalse(any(thread.name == "audit-pending-client" for thread in threading.enumerate()))

    def test_changed_target_refuses_before_kill_or_start_and_joins_holder(self):
        with self.assertRaises(vm.VerificationError):
            self.run_probe(change_target=True)
        self.assertFalse(any("kill=True\n" in item or "manage.sh start" in item for item in self.commands))
        self.assertFalse(self.evidence["audit_pending"]["passed"])
        self.assertFalse(any(thread.name == "audit-pending-client" for thread in threading.enumerate()))

    def test_prefix_deadline_refuses_before_kill_or_start_and_joins_holder(self):
        with self.assertRaises(vm.VerificationError):
            self.run_probe(no_prefix=True)
        self.assertFalse(any("kill=True\n" in item or "manage.sh start" in item for item in self.commands))
        self.assertFalse(self.evidence["audit_pending"]["passed"])
        self.assertFalse(any(thread.name == "audit-pending-client" for thread in threading.enumerate()))


if __name__ == "__main__":
    unittest.main()
