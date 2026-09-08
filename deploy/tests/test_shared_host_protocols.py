#!/usr/bin/env python3
"""Counterexamples for real protocol acceptance; no network or subprocess execution."""
from __future__ import annotations

import copy
import importlib.util
import json
import socket
import ssl
import traceback
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
    # Match backend/http/audit_query.go's auditQueryItem response DTO: the
    # database Event's top-level SchemaVersion is not exposed by this endpoint.
    return {"requestId": role + "-" + method + "-" + result,
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
    def transport_failure(self, error, stage="request"):
        client = api.Client.__new__(api.Client)
        client.host, client.port, client.requests = "files.test", 18443, 0
        client.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        before = (client.context.check_hostname, client.context.verify_mode, client.context.verify_flags)
        connection = mock.Mock()
        target = connection.getresponse.return_value.read if stage == "read" else getattr(connection, stage)
        target.side_effect = error
        with mock.patch.object(api.http.client, "HTTPSConnection", return_value=connection) as factory:
            with self.assertRaises(api.AcceptanceError) as caught:
                client.request("POST", "/api/auth/login", query={"username": "admin"},
                               token="PRIVATE_TOKEN_SENTINEL", body=b"PRIVATE_BODY_SENTINEL",
                               headers={"X-Password": "PRIVATE_HEADER_SENTINEL"})
        factory.assert_called_once_with("files.test", 18443, context=client.context, timeout=90)
        connection.close.assert_called_once_with()
        self.assertEqual(client.requests, 1)
        self.assertEqual((client.context.check_hostname, client.context.verify_mode, client.context.verify_flags), before)
        return caught.exception

    def test_transport_failure_categories_preserve_request_and_tls_behavior(self):
        secret = "https://private.invalid/PRIVATE_URL_SENTINEL Authorization: PRIVATE_HEADER_SENTINEL PRIVATE_BODY_SENTINEL"
        certificate = ssl.SSLCertVerificationError(1, secret)
        certificate.verify_code, certificate.verify_message = 92, secret
        cases = [
            (certificate, "tls_certificate_verify; errno=1; verify_code=92"),
            (socket.gaierror(-2, secret), "dns; errno=-2"),
            (TimeoutError(110, secret), "timeout; errno=110"),
            (ConnectionResetError(104, secret), "connection_reset; errno=104"),
            (ssl.SSLEOFError(8, secret), "eof; errno=8"),
            (api.http.client.RemoteDisconnected(secret), "eof"),
            (ssl.SSLError(1, secret), "tls; errno=1"),
            (api.http.client.BadStatusLine(secret), "http"),
            (OSError(5, secret), "os; errno=5"),
        ]
        for error, expected in cases:
            for stage in ("request", "getresponse", "read"):
                with self.subTest(category=expected, stage=stage):
                    caught = self.transport_failure(error, stage)
                    self.assertEqual(str(caught), "TLS or HTTP transport failed; category=" + expected)
                    self.assertTrue(all(value not in str(caught) for value in (secret, "PRIVATE_")))

    def test_transport_failure_never_formats_sensitive_exception_or_chain(self):
        class UnprintableTransportError(OSError):
            def __str__(self):
                raise AssertionError("transport exception must never be stringified")
        for error in (UnprintableTransportError(5, "PRIVATE_BODY_SENTINEL"),
                      type("PRIVATE_TYPE_SENTINEL", (api.http.client.HTTPException,), {})(
                          "https://private.invalid/PRIVATE_URL_SENTINEL Authorization: PRIVATE_HEADER_SENTINEL PRIVATE_BODY_SENTINEL")):
            with self.subTest(kind="protected-exception"):
                caught = self.transport_failure(error)
                rendered = "".join(traceback.format_exception(caught))
                self.assertTrue("PRIVATE_" not in rendered, "protected transport data leaked through the exception chain")
                self.assertIsNone(caught.__cause__)
                self.assertTrue(caught.__suppress_context__)

    def test_transport_failure_omits_noninteger_or_out_of_range_codes(self):
        for errno_value, verify_code in ((True, True), ("PRIVATE_HEADER_SENTINEL", "PRIVATE_BODY_SENTINEL"),
                                         (-32769, -1), (32768, 256), (10 ** 100, 10 ** 100)):
            with self.subTest(errno_type=type(errno_value).__name__):
                error = ssl.SSLCertVerificationError(1, "PRIVATE_URL_SENTINEL")
                error.errno, error.verify_code = errno_value, verify_code
                caught = self.transport_failure(error)
                self.assertEqual(str(caught), "TLS or HTTP transport failed; category=tls_certificate_verify")

    def test_permission_update_accepts_handler_no_content_contract(self):
        # backend/http/audit_user_actions_test.go's permission-update case asserts
        # the real userPutHandler returns 204, with no JSON response body.
        test = acceptance()
        granted = api.permissions(create=False)
        test.client = mock.Mock()
        test.client.request.return_value = api.Reply(204, {}, b"")
        test.set_permissions("bridge", granted)
        test.client.request.assert_called_once_with(
            "PUT", "/api/users", token=test.admin, query={"id": 2},
            data={"which": ["permissions"], "data": {"permissions": granted}},
            headers={"X-Password": urllib.parse.quote(test.admin_password, safe="")})
        self.assertEqual(test.state["users"]["bridge"]["permissions"], granted)
        test.checkpoint.assert_called_once_with()
        self.assertEqual(test.checks[-1]["http_status"], 204)

    def test_permission_update_rejects_other_statuses_without_persisting_grants(self):
        for status in (200, 201, 202, 401, 403, 500):
            with self.subTest(status=status):
                test = acceptance()
                test.state["users"]["bridge"]["permissions"] = api.permissions()
                before = copy.deepcopy(test.state)
                test.client = mock.Mock()
                test.client.request.return_value = api.Reply(status, {}, b"")
                with self.assertRaises(api.AcceptanceError):
                    test.set_permissions("bridge", api.permissions(create=False))
                self.assertEqual(test.state, before)
                test.checkpoint.assert_not_called()

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
                    acceptance().check_filebridge_listing("listing", invalid, "/bridge", BRIDGE_FILENAME, 19, logical_size=True)
        acceptance().check_filebridge_listing("listing", valid, "/bridge", BRIDGE_FILENAME, 19, logical_size=True)

    def test_filebridge_listing_uses_source_display_mode_for_controlled_files(self):
        for logical, byte_size, displayed in ((False, 0, 0), (False, 47, 4096), (False, 4096, 4096),
                                              (False, 4097, 8192), (True, 0, 0), (True, 47, 47),
                                              (True, 4096, 4096), (True, 4097, 4097)):
            with self.subTest(logical=logical, byte_size=byte_size):
                reply = {"source": api.SOURCE, "path": "/bridge", "files": [
                    {"source": api.SOURCE, "path": "/bridge/" + BRIDGE_FILENAME,
                     "name": BRIDGE_FILENAME, "size": displayed, "is_dir": False}]}
                test = acceptance()
                test.check_filebridge_listing("listing", reply, "/bridge", BRIDGE_FILENAME, byte_size, logical_size=logical)
                self.assertEqual(test.checks[-1]["expected_display_size"], displayed)
                self.assertEqual(test.checks[-1]["logical_bytes"], byte_size)
                for invalid_size in (displayed + 1, displayed - 1, True, str(displayed)):
                    invalid = copy.deepcopy(reply)
                    invalid["files"][0]["size"] = invalid_size
                    with self.assertRaises(api.AcceptanceError):
                        test.check_filebridge_listing("listing", invalid, "/bridge", BRIDGE_FILENAME, byte_size, logical_size=logical)
                with self.assertRaises(api.AcceptanceError):
                    test.check_filebridge_listing("listing", dict(reply, files=[]), "/bridge", BRIDGE_FILENAME, byte_size, logical_size=logical)

    def test_filebridge_listing_requires_explicit_unique_source_size_configuration(self):
        for logical in (True, False):
            test = acceptance()
            test.request = mock.Mock(return_value=api.Reply(200, {}, json.dumps([
                {"name": api.SOURCE, "config": {"useLogicalSize": logical}}]).encode()))
            self.assertIs(test.filebridge_listing_logical_size(), logical)
            self.assertEqual(test.request.call_args.kwargs['query'], {'property': 'sources'})
        for sources in ([], [{"name": "other", "config": {"useLogicalSize": False}}],
                        [{"name": api.SOURCE, "config": {}}],
                        [{"name": api.SOURCE, "config": {"useLogicalSize": "false"}}],
                        [{"name": api.SOURCE, "config": {"useLogicalSize": 0}}],
                        [{"name": api.SOURCE, "config": {"useLogicalSize": False}}] * 2):
            with self.subTest(sources=sources):
                test = acceptance()
                test.request = mock.Mock(return_value=api.Reply(200, {}, json.dumps(sources).encode()))
                with self.assertRaises(api.AcceptanceError):
                    test.filebridge_listing_logical_size()

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
            {"origin": "internal"}, {"metadata": {"schemaVersion": 99, "method": "POST"}},
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
