#!/usr/bin/env python3
"""Counterexamples for real protocol acceptance; no network or subprocess execution."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest
import urllib.parse
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("shared_host_acceptance", ROOT / "scripts/tests/shared-host-api.py")
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
FILENAME = "\u4e2d\u6587 \u7a7a\u683c.txt"
BRIDGE_FILENAME = "\u4e2d\u6587 \u6587\u4ef6.txt"


def acceptance():
    test = api.Acceptance.__new__(api.Acceptance)
    test.checks = []
    test.admin = "unused-session"
    test.admin_password = "private-admin-sentinel"
    test.state = {"root": "/test-scope", "users": {
        "bridge": {"id": 2, "username": "bridge-user", "password": "private-bridge-sentinel"},
        "dav": {"id": 3, "username": "dav-user", "password": "private-dav-sentinel"},
    }, "tokens": {}, "protocols": {}}
    test.checkpoint = mock.Mock()
    return test


def listing(entries):
    body = '<d:multistatus xmlns:d="DAV:">'
    for path, status in entries:
        href = urllib.parse.quote("/dav/" + api.SOURCE + path, safe="/")
        body += ('<d:response><d:href>' + href + '</d:href><d:propstat>'
                 '<d:prop><d:resourcetype/><d:getcontentlength>9</d:getcontentlength></d:prop>'
                 '<d:status>HTTP/1.1 ' + str(status) + ' Status</d:status></d:propstat></d:response>')
    return api.Reply(207, {}, (body + '</d:multistatus>').encode())


def event(role, action, method, path, result="success", status=200):
    return {"schemaVersion": 1, "requestId": role + "-" + method + "-" + result,
            "timestampUtc": "2026-09-07T12:34:56.123456789Z",
            "userId": 2 if role == "bridge" else 3, "username": role + "-user",
            "authMethod": "token", "origin": "http" if role == "bridge" else "webdav",
            "source": api.SOURCE, "path": "/test-scope" + path,
            "action": action, "result": result, "httpStatus": status,
            "metadata": {"schemaVersion": 1, "method": method}}


def audit_events():
    return {"bridge": [
        event("bridge", "file.upload", "POST", "/bridge/" + BRIDGE_FILENAME),
        event("bridge", "file.upload", "POST", "/bridge/token-denied.txt", "denied", 403),
    ], "dav": [
        event("dav", "webdav.read", "GET", "/webdav/" + FILENAME),
        event("dav", "webdav.write", "PUT", "/webdav/" + FILENAME, status=201),
        event("dav", "webdav.write", "PUT", "/webdav/token-denied.txt", "denied", 403),
    ]}


def use_audit(test, events):
    def request(*args, **kwargs):
        role = kwargs["query"]["actor"].removesuffix("-user")
        return api.Reply(200, {}, json.dumps({"items": events[role], "hasMore": False}).encode())
    test.request = request


class ProtocolAcceptanceTests(unittest.TestCase):
    def test_dav_rejects_multistatus_with_only_forbidden_properties(self):
        test = acceptance()
        test.dav = mock.Mock(return_value=listing([("/webdav/", 403)]))
        with self.assertRaises(api.AcceptanceError):
            test.dav_listing("listing", "/webdav/", "unused")

    def test_dav_requires_successful_expected_business_file(self):
        expected = "/webdav/" + FILENAME
        for entries in ([('/webdav/', 200)], [('/webdav/', 200), (expected, 403)]):
            with self.subTest(entries=entries):
                test = acceptance()
                test.dav = mock.Mock(return_value=listing(entries))
                with self.assertRaises(api.AcceptanceError):
                    test.dav_listing("listing", "/webdav/", "unused", expected_paths=(expected,))
        test = acceptance()
        test.dav = mock.Mock(return_value=listing([('/webdav/', 200), (expected, 200)]))
        hrefs = test.dav_listing("listing", "/webdav/", "unused", expected_paths=(expected,))
        self.assertIn('/dav/' + api.SOURCE + expected, hrefs)

    def test_dav_nested_property_href_does_not_count_as_file_entry(self):
        test = acceptance()
        expected = "/webdav/" + FILENAME
        reply = listing([("/webdav/", 200)])
        nested = ('<d:owner><d:href>' + urllib.parse.quote("/dav/" + api.SOURCE + expected, safe="/")
                  + '</d:href></d:owner>').encode()
        reply.body = reply.body.replace(b'</d:prop>', nested + b'</d:prop>')
        test.dav = mock.Mock(return_value=reply)
        with self.assertRaises(api.AcceptanceError):
            test.dav_listing("listing", "/webdav/", "unused", expected_paths=(expected,))

    def test_dav_retains_scope_denial(self):
        test = acceptance()
        test.dav = mock.Mock(return_value=api.Reply(207, {}, b'<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/outside/file</d:href></d:response></d:multistatus>'))
        with self.assertRaises(api.AcceptanceError):
            test.dav_listing("listing", "/webdav/", "unused")

    def test_filebridge_listing_requires_uploaded_file_metadata(self):
        valid = {"source": api.SOURCE, "path": "/bridge", "folders": [], "files": [
            {"source": api.SOURCE, "path": "/bridge/" + BRIDGE_FILENAME,
             "name": BRIDGE_FILENAME, "size": 19, "is_dir": False}]}
        variants = [dict(valid, files=[])]
        for field, value in (("source", "wrong"), ("path", "/bridge/wrong"),
                             ("name", "wrong"), ("size", 20), ("is_dir", True)):
            invalid = copy.deepcopy(valid)
            invalid["files"][0][field] = value
            variants.append(invalid)
        for invalid in variants:
            with self.subTest(invalid=invalid):
                with self.assertRaises(api.AcceptanceError):
                    acceptance().check_filebridge_listing("listing", invalid, "/bridge", BRIDGE_FILENAME, 19)
        acceptance().check_filebridge_listing("listing", valid, "/bridge", BRIDGE_FILENAME, 19)

    def test_protocol_audit_rejects_all_failed_events(self):
        events = audit_events()
        for items in events.values():
            for item in items:
                item.update(result="failed", httpStatus=500)
        test = acceptance()
        use_audit(test, events)
        with self.assertRaises(api.AcceptanceError):
            test.protocol_audit()

    def test_protocol_audit_rejects_pending_or_wrong_success_records(self):
        mutations = [
            {"result": "", "httpStatus": None, "timestampUtc": "0001-01-01T00:00:00Z"},
            {"httpStatus": 500}, {"timestampUtc": "0001-01-01T00:00:00Z"},
            {"timestampUtc": "not-a-timestamp"}, {"path": "/test-scope/unrelated.txt"},
            {"source": "outside"}, {"username": "unrelated-user"}, {"userId": 999},
            {"origin": "internal"}, {"schemaVersion": 99},
            {"metadata": {"schemaVersion": 1, "method": "DELETE"}},
        ]
        for role, index in (("bridge", 0), ("dav", 0), ("dav", 1)):
            for mutation in mutations:
                with self.subTest(role=role, index=index, mutation=mutation):
                    events = audit_events()
                    events[role][index].update(mutation)
                    test = acceptance()
                    use_audit(test, events)
                    with self.assertRaises(api.AcceptanceError):
                        test.protocol_audit()

    def test_protocol_audit_requires_denied_evidence_too(self):
        for role in ("bridge", "dav"):
            with self.subTest(role=role):
                events = audit_events()
                events[role] = [item for item in events[role] if item["result"] != "denied"]
                test = acceptance()
                use_audit(test, events)
                with self.assertRaises(api.AcceptanceError):
                    test.protocol_audit()

    def test_protocol_audit_accepts_terminal_success_and_preserves_ids(self):
        test = acceptance()
        events = audit_events()
        # Early HTTP permission denials have no resolved path/method metadata.
        for field in ("path", "source", "metadata"):
            events["bridge"][1].pop(field)
        use_audit(test, events)
        test.protocol_audit()
        previous = copy.deepcopy(test.state["protocols"]["audit_ids"])
        test.protocol_audit()
        self.assertEqual(test.state["protocols"]["audit_ids"], previous)
        self.assertTrue(all(check["passed"] for check in test.checks))

    def test_protocol_audit_retains_secret_redaction(self):
        test = acceptance()
        events = audit_events()
        events["bridge"][0]["extra"] = test.admin_password
        use_audit(test, events)
        with self.assertRaisesRegex(api.AcceptanceError, "redaction"):
            test.protocol_audit()


if __name__ == "__main__":
    unittest.main(verbosity=2)
