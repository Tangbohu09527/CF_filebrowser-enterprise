#!/usr/bin/env python3
"""QEMU launch and diagnostic regressions; no VM is booted by these tests."""
from __future__ import annotations

import importlib.util
import copy
import contextlib
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts/tests/shared_host_vm.py"
SPEC = importlib.util.spec_from_file_location("shared_host_vm_tests", MODULE_PATH)
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)


class CertificateTrustTests(unittest.TestCase):
    """Real disposable certificates/TLS; this does not boot a VM or application."""

    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl"):
            raise RuntimeError("OpenSSL is required for the strict certificate regression")
        cls.temporary = tempfile.TemporaryDirectory(prefix="cf-vm-strict-tls-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.tls = harness.certificates(Path(cls.temporary.name))

    def verify(self, leaf, name, *, ca="ca.crt", flag="-verify_hostname"):
        return subprocess.run(["openssl", "verify", "-x509_strict", "-purpose", "sslserver",
                               "-CAfile", str(self.tls / ca), flag, name, str(self.tls / leaf)],
                              capture_output=True, check=False, timeout=30)

    def test_generated_server_and_registry_certificates_pass_strict_verification(self):
        for leaf, name, flag in (("server.crt", harness.TLS_NAME, "-verify_hostname"),
                                 ("registry.crt", "localhost", "-verify_hostname"),
                                 ("registry.crt", "127.0.0.1", "-verify_ip")):
            with self.subTest(leaf=leaf, flag=flag):
                self.assertEqual(self.verify(leaf, name, flag=flag).returncode, 0,
                                 "generated certificate failed strict chain/name/purpose verification; private output suppressed")

    def test_strict_verification_rejects_wrong_name_and_untrusted_ca(self):
        self.assertNotEqual(self.verify("server.crt", "wrong.cf.test").returncode, 0)
        self.assertNotEqual(self.verify("server.crt", harness.TLS_NAME, ca="untrusted-ca.crt").returncode, 0)

    def test_strict_python_client_completes_real_tls_handshake(self):
        context = harness.ssl.create_default_context(cafile=str(self.tls / "ca.crt"))
        # Python 3.13 enables this flag by default; exercise that same policy
        # when the focused regression runs on an older Python installation.
        context.verify_flags |= harness.ssl.VERIFY_X509_STRICT
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, harness.ssl.CERT_REQUIRED)
        server_context = harness.ssl.SSLContext(harness.ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.tls / "server.crt", self.tls / "server.key")
        completed = []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            def serve():
                try:
                    with listener.accept()[0] as raw:
                        raw.settimeout(5)
                        with server_context.wrap_socket(raw, server_side=True) as secured:
                            secured.sendall(b"strict-test")
                            completed.append(True)
                except OSError:
                    completed.append(False)
            thread = threading.Thread(target=serve)
            thread.start()
            try:
                with socket.create_connection(listener.getsockname(), timeout=5) as raw:
                    with context.wrap_socket(raw, server_hostname=harness.TLS_NAME) as secured:
                        self.assertEqual(secured.recv(32), b"strict-test")
            finally:
                thread.join(timeout=6)
            self.assertFalse(thread.is_alive())
            self.assertEqual(completed, [True])


class UIRasterEvidenceTests(unittest.TestCase):
    def fixture(self):
        return {'schema': 1, 'rasters': [
            {'width': 640, 'height': 480, 'nonWhitePixels': 120, 'pixelSha256': 'a' * 64},
            {'width': 640, 'height': 480, 'nonWhitePixels': 180, 'pixelSha256': 'b' * 64}]}

    def case_log(self):
        return b''.join(json.dumps({'case': case, 'status': 'passed', 'retry': 0,
                                    'stage': 'delete' if case == 'crud' else 'xlsx_checks' if case == 'xlsx' else case}).encode() + b'\n'
                        for case in ('crud', 'png', 'jpg', 'xlsx', 'logout'))

    def test_case_summary_requires_every_fixed_case_final_success(self):
        report = harness.ui_case_evidence(self.case_log())
        self.assertTrue(report['passed'])
        self.assertEqual(set(report['final']), {'crud', 'png', 'jpg', 'xlsx', 'logout'})
        retry = self.case_log().replace(b'"passed"', b'"failed"', 1)
        retry += b'{"case":"crud","status":"passed","retry":1,"stage":"delete"}\n'
        self.assertTrue(harness.ui_case_evidence(retry)['passed'])
        partial = self.case_log().splitlines(keepends=True)[0]
        self.assertFalse(harness.ui_case_evidence(partial)['passed'])

    def test_case_summary_rejects_unknown_keys_statuses_cases_and_retry_bounds(self):
        bad = [b'', b'PRIVATE-TOKEN', self.case_log() * 4]
        for record in ({'case': 'unknown', 'status': 'passed', 'retry': 0},
                       {'case': 'crud', 'status': 'PRIVATE-STATUS', 'retry': 0},
                       {'case': 'crud', 'status': 'passed', 'retry': True},
                       {'case': 'crud', 'status': 'passed', 'retry': -1},
                       {'case': 'crud', 'status': 'passed', 'retry': 3},
                       {'case': 'crud', 'status': 'passed', 'retry': '0'},
                       {'case': 'crud', 'status': 'passed', 'retry': 0, 'title': 'PRIVATE-PASSWORD'}):
            record['stage'] = 'delete'
            bad.append(json.dumps(record).encode() + b'\n')
        bad.append(self.case_log() + self.case_log().splitlines(keepends=True)[0])
        bad.append(b'{"case":"crud","status":"passed","retry":2,"stage":"delete"}\n')
        for raw in bad:
            with self.subTest(raw=raw):
                with self.assertRaises(harness.VerificationError) as caught:
                    harness.ui_case_evidence(raw)
                self.assertNotIn('PRIVATE', str(caught.exception))

    def test_case_summary_retains_only_last_entered_operation(self):
        for case, stages in {'crud': ('login', 'listing', 'upload', 'edit', 'edit_open', 'edit_render', 'edit_focus', 'edit_replace', 'save_menu', 'save_response', 'save_navigation', 'rename', 'download', 'delete'),
                             'png': ('login', 'listing', 'png'), 'jpg': ('login', 'listing', 'jpg'),
                             'xlsx': ('login', 'listing', 'xlsx', 'xlsx1_request', 'xlsx1_response', 'xlsx1_status', 'xlsx1_viewer', 'xlsx1_decode',
                                      'xlsx2_request', 'xlsx2_response', 'xlsx2_status', 'xlsx2_viewer', 'xlsx2_decode', 'xlsx_evidence', 'xlsx_checks'), 'logout': ('login', 'listing', 'logout')}.items():
            for stage in stages:
                with self.subTest(case=case, stage=stage):
                    record = {'case': case, 'status': 'failed', 'retry': 0, 'stage': stage}
                    report = harness.ui_case_evidence(json.dumps(record).encode())
                    self.assertFalse(report['passed'])
                    self.assertEqual(report['attempts'], [record])

    def test_case_summary_rejects_invalid_and_cross_case_operations(self):
        for case, stage in (('crud', 'save'), ('crud', 'png'), ('png', 'edit'), ('xlsx', 'logout'), ('logout', 'xlsx'),
                            ('jpg', 'PRIVATE-URL-TOKEN'), ('crud', True), ('crud', 1), ('crud', [])):
            with self.subTest(case=case, stage=stage):
                record = {'case': case, 'status': 'failed', 'retry': 0, 'stage': stage}
                with self.assertRaises(harness.VerificationError) as caught:
                    harness.ui_case_evidence(json.dumps(record).encode())
                self.assertNotIn('PRIVATE', str(caught.exception))

    def test_passed_case_requires_known_final_operation(self):
        for case in ('crud', 'png', 'jpg', 'xlsx', 'logout'):
            for stage in (None, 'login', 'listing'):
                with self.subTest(case=case, stage=stage):
                    record = {'case': case, 'status': 'passed', 'retry': 0, 'stage': stage}
                    with self.assertRaises(harness.VerificationError):
                        harness.ui_case_evidence(json.dumps(record).encode())

    def test_intermediate_save_or_spreadsheet_step_cannot_be_reported_passed(self):
        stages = {'crud': ('edit_open', 'edit_render', 'edit_focus', 'edit_replace', 'save_menu', 'save_response', 'save_navigation'),
                  'xlsx': ('xlsx', 'xlsx1_request', 'xlsx1_response', 'xlsx1_status', 'xlsx1_viewer', 'xlsx1_decode',
                           'xlsx2_request', 'xlsx2_response', 'xlsx2_status', 'xlsx2_viewer', 'xlsx2_decode', 'xlsx_evidence')}
        for case, values in stages.items():
            for stage in values:
                with self.subTest(case=case, stage=stage), self.assertRaises(harness.VerificationError):
                    harness.ui_case_evidence(json.dumps({'case': case, 'status': 'passed', 'retry': 0, 'stage': stage}).encode())

    def test_failed_unknown_operation_is_retained_without_claiming_progress(self):
        for status in ('failed', 'timedOut', 'skipped', 'interrupted'):
            with self.subTest(status=status):
                record = {'case': 'crud', 'status': status, 'retry': 0, 'stage': None}
                report = harness.ui_case_evidence(json.dumps(record).encode())
                self.assertFalse(report['passed'])
                self.assertIsNone(report['attempts'][0]['stage'])

    def test_ui_failure_retains_before_each_case_failure_with_no_private_output(self):
        vm = mock.Mock()
        cases = self.case_log().replace(b'"passed"', b'"timedOut"', 1)
        vm.command_on_guest.return_value = subprocess.CompletedProcess([], 1, b'PRIVATE-STDOUT', b'PRIVATE-STDERR')
        vm.read_file.side_effect = lambda name: cases if name.endswith('.ndjson') else json.dumps(self.fixture()).encode()
        with self.assertRaises(harness.VerificationError) as caught:
            harness.real_ui(vm)
        evidence = caught.exception.ui_evidence
        self.assertFalse(evidence['passed'])
        self.assertEqual(evidence['cases']['final']['crud'], 'timedOut')
        self.assertFalse(evidence['cases']['passed'])
        self.assertNotIn('PRIVATE', json.dumps(evidence))

    def test_zero_exit_cannot_override_missing_case_or_blank_or_identical_rasters(self):
        vm = mock.Mock()
        vm.command_on_guest.return_value = subprocess.CompletedProcess([], 0, b'', b'')
        for kind in ('missing-case', 'blank', 'identical'):
            with self.subTest(kind=kind):
                raster = self.fixture()
                cases = self.case_log()
                if kind == 'missing-case':
                    cases = cases.splitlines(keepends=True)[0]
                elif kind == 'blank':
                    raster['rasters'][0]['nonWhitePixels'] = 0
                else:
                    raster['rasters'][1]['pixelSha256'] = raster['rasters'][0]['pixelSha256']
                vm.read_file.side_effect = lambda name: cases if name.endswith('.ndjson') else json.dumps(raster).encode()
                with self.assertRaises(harness.VerificationError) as caught:
                    harness.real_ui(vm)
                evidence = caught.exception.ui_evidence
                self.assertFalse(evidence['passed'])
                self.assertEqual(evidence['raster'], raster)
                if kind != 'missing-case':
                    self.assertFalse(evidence['raster_passed'])

    def test_accepts_only_two_distinct_nonblank_raster_summaries(self):
        value = self.fixture()
        safe = harness.ui_raster_evidence(value)
        self.assertEqual(safe, value)
        self.assertIsNot(safe, value)
        self.assertIsNot(safe['rasters'][0], value['rasters'][0])

    def test_rejects_wrong_schema_keys_blank_placeholder_and_invalid_numbers(self):
        variants = [None, [], {'schema': 1, 'rasters': []}]
        for schema in (True, False, '1', 1.0, 2):
            variants.append(dict(self.fixture(), schema=schema))
        variants.append(dict(self.fixture(), secret='PRIVATE-TOKEN'))
        variants.append(dict(self.fixture(), rasters=self.fixture()['rasters'][:1]))
        variants.append(dict(self.fixture(), rasters=self.fixture()['rasters'] * 2))
        same = self.fixture()
        same['rasters'][1]['pixelSha256'] = same['rasters'][0]['pixelSha256']
        variants.append(same)
        for field, invalid in (('width', 0), ('width', 1025), ('width', True), ('width', '640'),
                               ('height', 0), ('height', 1025), ('height', False), ('height', 480.0),
                               ('nonWhitePixels', 0), ('nonWhitePixels', 10), ('nonWhitePixels', 640 * 480 + 1),
                               ('nonWhitePixels', True), ('nonWhitePixels', '120'),
                               ('pixelSha256', 'a' * 63), ('pixelSha256', 'g' * 64), ('pixelSha256', True),
                               ('secret', 'PRIVATE-PASSWORD')):
            value = self.fixture()
            value['rasters'][0][field] = invalid
            variants.append(value)
        for value in variants:
            with self.subTest(value=value):
                with self.assertRaises(harness.VerificationError) as caught:
                    harness.ui_raster_evidence(value)
                self.assertNotIn('PRIVATE', str(caught.exception))

    def test_real_ui_reads_the_existing_private_output_and_returns_only_summary(self):
        vm = mock.Mock()
        vm.command_on_guest.return_value = subprocess.CompletedProcess([], 0, b'PRIVATE-STDOUT', b'PRIVATE-STDERR')
        vm.read_file.side_effect = lambda name: self.case_log() if name.endswith('.ndjson') else json.dumps(self.fixture()).encode()
        report = harness.real_ui(vm)
        self.assertTrue(report['passed'])
        self.assertEqual(report['raster'], self.fixture())
        self.assertTrue(report['cases']['passed'])
        vm.read_file.assert_any_call('/home/cf-manager/verification/playwright-output/xlsx-raster-evidence.json')
        vm.read_file.assert_any_call('/home/cf-manager/verification/playwright-output/ui-case-evidence.ndjson')
        self.assertFalse(vm.command_on_guest.call_args.kwargs['check'])

    def test_real_ui_failures_never_include_guest_output_or_invalid_json(self):
        vm = mock.Mock()
        for code, payload in ((1, json.dumps(self.fixture()).encode()), (0, b'PRIVATE-PASSWORD')):
            with self.subTest(code=code):
                vm.command_on_guest.return_value = subprocess.CompletedProcess([], code, b'PRIVATE-TOKEN', b'PRIVATE-STDERR')
                vm.read_file.return_value = payload
                with self.assertRaises(harness.VerificationError) as caught:
                    harness.real_ui(vm)
                self.assertNotIn('PRIVATE', str(caught.exception))
                self.assertTrue(caught.exception.__suppress_context__)


class LANBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tcp = mock.Mock()
        self.tcp.getsockname.return_value = (harness.DENIED_IP, 42000)
        self.tcp.getpeername.return_value = (harness.SERVER_IP, harness.TLS_PORT)
        self.tls = mock.Mock()
        self.tls.do_handshake.side_effect = harness.ssl.SSLEOFError(8, "closed before handshake")
        self.context = mock.Mock()
        self.context.wrap_socket.return_value = self.tls
        self.dial = mock.patch.object(harness.socket, "create_connection", return_value=self.tcp).start()
        self.trust = mock.patch.object(harness.ssl, "create_default_context", return_value=self.context).start()
        self.curl = mock.patch.object(harness.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 0, b'{"message":"ok"}\n200', b''),
            subprocess.CompletedProcess([], 0, b'<html></html>\n200', b''),
            subprocess.CompletedProcess([], 60, b'', b'private-certificate-diagnostic'),
            subprocess.CompletedProcess([], 0, b'{"message":"ok"}\n200', b''),
        ]).start()
        self.addCleanup(mock.patch.stopall)

    def probe(self):
        return harness.probe_lan_boundary('/protected/ca.crt', '/protected/wrong-ca.crt', '/protected/empty-trust')

    def test_report_retains_failed_substage_without_private_transport_output(self):
        self.curl.side_effect = [subprocess.CompletedProcess([], 22, b'PRIVATE-BODY\n503', b'PRIVATE-TOKEN')]
        report = harness.lan_probe_report('/protected/ca.crt', '/protected/wrong-ca.crt', '/protected/empty-trust')
        self.assertFalse(report['passed'])
        self.assertEqual(report['stage'], 'allowed-health-before')
        self.assertEqual(report['failure'], {'category': 'assertion'})
        self.assertEqual(report['observations']['allowed-health-before'], {'curl_exit_code': 22, 'http_status': 503, 'body_expected': False})
        self.assertNotIn('PRIVATE', json.dumps(report))
        self.assertNotIn('/protected', json.dumps(report))

    def test_report_retains_completed_controls_and_only_bounded_tls_error_codes(self):
        certificate_error = harness.ssl.SSLCertVerificationError(1, 'PRIVATE-PASSWORD')
        certificate_error.verify_code = 92
        self.context.wrap_socket.side_effect = certificate_error
        report = harness.lan_probe_report('/protected/ca.crt', '/protected/wrong-ca.crt', '/protected/empty-trust')
        self.assertFalse(report['passed'])
        self.assertEqual(report['stage'], 'denied-tls-handshake')
        self.assertEqual(report['failure'], {'category': 'tls-certificate', 'errno': 1, 'verify_code': 92})
        self.assertEqual(report['completed'], ['allowed-health-before', 'allowed-ui', 'trusted-context', 'denied-tcp-connect', 'denied-socket-identity'])
        self.assertNotIn('PRIVATE', json.dumps(report))
        self.tcp.close.assert_called_once_with()

    def test_diagnostic_codes_reject_bool_strings_and_out_of_range_values(self):
        for number in (True, '92', -32769, 32768):
            with self.subTest(number=number):
                self.assertNotIn('errno', harness.lan_safe_fields({'errno': number}))
        for number in (True, '92', -1, 256):
            with self.subTest(number=number):
                error = harness.ssl.SSLCertVerificationError(1, 'PRIVATE-TOKEN')
                error.verify_code = number
                self.assertEqual(harness.lan_error_fields(error), {'category': 'tls-certificate', 'errno': 1})
        for name, (minimum, maximum) in harness.LAN_INTEGER_FIELDS.items():
            self.assertEqual(harness.lan_safe_fields({name: minimum}), {name: minimum})
            self.assertEqual(harness.lan_safe_fields({name: maximum}), {name: maximum})
            for number in (True, str(minimum), minimum - 1, maximum + 1):
                self.assertNotIn(name, harness.lan_safe_fields({name: number}))

    def test_error_classification_never_formats_exception_text_or_class_names(self):
        class PrivateSecretError(OSError):
            def __str__(self):
                raise AssertionError('must not format private error')
        cases = [(PrivateSecretError(5, 'PRIVATE-TOKEN'), 'os'), (socket.gaierror(-2, 'PRIVATE-TOKEN'), 'dns'),
                 (TimeoutError('PRIVATE-TOKEN'), 'timeout'), (ConnectionResetError('PRIVATE-TOKEN'), 'connection'),
                 (harness.ssl.SSLEOFError(8, 'PRIVATE-TOKEN'), 'eof'), (harness.ssl.SSLError(1, 'PRIVATE-TOKEN'), 'tls'),
                 (RuntimeError('PRIVATE-TOKEN'), 'internal')]
        for error, category in cases:
            with self.subTest(category=category):
                report = harness.lan_error_fields(error)
                self.assertEqual(report['category'], category)
                self.assertNotIn('PRIVATE', json.dumps(report))
                self.assertNotIn('PrivateSecretError', json.dumps(report))

    def test_success_report_keeps_every_original_boundary_check(self):
        report = harness.lan_probe_report('/protected/ca.crt', '/protected/wrong-ca.crt', '/protected/empty-trust')
        self.assertTrue(report['passed'])
        self.assertEqual(report['stage'], 'complete')
        self.assertEqual(report['completed'], list(harness.LAN_PROBE_STAGES[1:-1]))
        self.assertEqual(report['observations']['denied-tcp-connect']['tcp_connected'], True)
        self.assertEqual(report['observations']['denied-socket-identity'], {'source_matches': True, 'peer_matches': True})
        self.assertEqual(report['observations']['denied-tls-handshake']['rejection'], 'tls-eof')
        self.assertEqual(report['observations']['wrong-ca']['curl_exit_code'], 60)
        self.assertEqual(report['observations']['allowed-health-after']['http_status'], 200)

    def test_success_report_requires_all_observed_boundaries_not_just_stage_names(self):
        report = harness.lan_probe_report('/protected/ca.crt', '/protected/wrong-ca.crt', '/protected/empty-trust')
        self.assertTrue(harness.sanitized_lan_report(report)['passed'])
        self.assertEqual(harness.sanitized_lan_report(report)['observations'], report['observations'])
        missing_all = copy.deepcopy(report)
        missing_all['observations'] = {}
        self.assertFalse(harness.sanitized_lan_report(missing_all)['passed'])
        for stage, observations in report['observations'].items():
            for name in observations:
                with self.subTest(stage=stage, name=name):
                    missing = copy.deepcopy(report)
                    missing['observations'][stage].pop(name)
                    self.assertFalse(harness.sanitized_lan_report(missing)['passed'])
        for stage, name, value in (('allowed-health-before', 'curl_exit_code', 7),
                                   ('allowed-ui', 'http_status', 403),
                                   ('denied-tcp-connect', 'tcp_connected', False),
                                   ('denied-socket-identity', 'source_matches', False),
                                   ('denied-tls-handshake', 'tls_handshake_completed', True),
                                   ('denied-tls-handshake', 'application_bytes_received', 1),
                                   ('denied-tls-handshake', 'elapsed_ms', 5000),
                                   ('wrong-ca', 'curl_exit_code', 35),
                                   ('allowed-health-after', 'body_expected', False)):
            with self.subTest(stage=stage, name=name):
                wrong = copy.deepcopy(report)
                wrong['observations'][stage][name] = value
                self.assertFalse(harness.sanitized_lan_report(wrong)['passed'])

    def test_report_preserves_the_original_just_under_five_second_boundary(self):
        with mock.patch.object(harness.time, 'monotonic', side_effect=[10.0, 14.9996]):
            report = harness.lan_probe_report('/protected/ca.crt', '/protected/wrong-ca.crt', '/protected/empty-trust')
        self.assertTrue(report['passed'])
        self.assertEqual(report['observations']['denied-tls-handshake']['elapsed_ms'], 4999)

    def test_report_rejects_exactly_five_seconds_without_marking_tls_complete(self):
        with mock.patch.object(harness.time, 'monotonic', side_effect=[10.0, 15.0]):
            report = harness.lan_probe_report('/protected/ca.crt', '/protected/wrong-ca.crt', '/protected/empty-trust')
        self.assertFalse(report['passed'])
        self.assertEqual(report['stage'], 'denied-tls-handshake')
        self.assertEqual(report['observations']['denied-tls-handshake']['elapsed_ms'], 5000)
        self.assertNotIn('denied-tls-handshake', report['completed'])

    def test_requires_connected_correct_socket_then_prompt_tls_eof(self):
        result = self.probe()
        self.assertEqual(result['denied_source']['socket_source'], harness.DENIED_IP)
        self.assertEqual(result['denied_source']['socket_peer'], harness.SERVER_IP)
        self.assertEqual(result['denied_source']['rejection'], 'tls-eof')
        self.assertFalse(result['denied_source']['tls_handshake_completed'])
        self.assertEqual(result['denied_source']['application_bytes_received'], 0)
        self.assertEqual(result['untrusted_ca_exit_code'], 60)
        self.assertEqual(result['allowed_before_status'], 200)
        self.assertEqual(result['allowed_after_status'], 200)
        self.dial.assert_called_once_with((harness.TLS_NAME, harness.TLS_PORT), timeout=5, source_address=(harness.DENIED_IP, 0))
        self.context.wrap_socket.assert_called_once_with(self.tcp, server_hostname=harness.TLS_NAME, do_handshake_on_connect=False)
        self.assertEqual(self.context.minimum_version, harness.ssl.TLSVersion.TLSv1_2)
        self.tcp.sendall.assert_not_called()
        self.tls.sendall.assert_not_called()
        self.tls.close.assert_called_once_with()
        final_curl = self.curl.call_args_list[-1].args[0]
        self.assertIn('X-Forwarded-For: ' + harness.DENIED_IP, final_curl)
        self.assertIn('X-Real-IP: ' + harness.DENIED_IP, final_curl)

    def test_prompt_reset_is_a_valid_pre_http_refusal(self):
        self.tls.do_handshake.side_effect = ConnectionResetError()
        self.assertEqual(self.probe()['denied_source']['rejection'], 'tcp-reset')

    def test_connection_failure_is_not_cidr_denial(self):
        self.dial.side_effect = ConnectionRefusedError()
        with self.assertRaises(harness.VerificationError):
            self.probe()
        self.context.wrap_socket.assert_not_called()

    def test_wrong_actual_source_or_peer_is_rejected(self):
        for method, address in ((self.tcp.getsockname, (harness.CLIENT_IP, 42000)),
                                (self.tcp.getpeername, ('192.0.2.13', harness.TLS_PORT))):
            with self.subTest(address=address):
                method.return_value = address
                self.curl.side_effect = [subprocess.CompletedProcess([], 0, b'{"message":"ok"}\n200', b''), subprocess.CompletedProcess([], 0, b'<html></html>\n200', b'')]
                with self.assertRaises(harness.VerificationError):
                    self.probe()
                self.tcp.getsockname.return_value = (harness.DENIED_IP, 42000)
                self.tcp.getpeername.return_value = (harness.SERVER_IP, harness.TLS_PORT)
        self.context.wrap_socket.assert_not_called()

    def test_tls_success_timeout_certificate_error_and_other_ssl_errors_fail(self):
        for error in (None, TimeoutError(), harness.ssl.SSLCertVerificationError(1, 'bad certificate'), harness.ssl.SSLError(1, 'protocol error')):
            with self.subTest(error=type(error).__name__):
                self.curl.side_effect = [subprocess.CompletedProcess([], 0, b'{"message":"ok"}\n200', b''), subprocess.CompletedProcess([], 0, b'<html></html>\n200', b'')]
                self.tls.do_handshake.side_effect = error
                with self.assertRaises(harness.VerificationError):
                    self.probe()

    def test_eof_after_the_deadline_is_not_prompt_listener_refusal(self):
        with mock.patch.object(harness.time, "monotonic", side_effect=[10.0, 15.0]):
            with self.assertRaises(harness.VerificationError):
                self.probe()

    def test_untrusted_ca_requires_exit_60_not_any_transport_failure(self):
        for code in (0, 7, 22, 28, 35, 56):
            with self.subTest(code=code):
                self.curl.side_effect = [subprocess.CompletedProcess([], 0, b'{"message":"ok"}\n200', b''), subprocess.CompletedProcess([], 0, b'<html></html>\n200', b''), subprocess.CompletedProcess([], code, b'', b'private-output')]
                with self.assertRaises(harness.VerificationError):
                    self.probe()

    def test_allowed_source_must_work_before_and_after_negative_probes(self):
        for failing in (0, 3):
            with self.subTest(failing=failing):
                results = [subprocess.CompletedProcess([], 0, b'{"message":"ok"}\n200', b''), subprocess.CompletedProcess([], 0, b'<html></html>\n200', b''), subprocess.CompletedProcess([], 60, b'', b''), subprocess.CompletedProcess([], 0, b'{"message":"ok"}\n200', b'')]
                results[failing] = subprocess.CompletedProcess([], 28, b'', b'private-output')
                self.curl.side_effect = results
                with self.assertRaises(harness.VerificationError):
                    self.probe()


class QemuLaunchTests(unittest.TestCase):
    def make_vm(self, directory):
        root = Path(directory)
        ssh_key = root / "client-key"
        ssh_key.with_suffix(".pub").write_text("ssh-ed25519 public-test-key\n")
        calls = []

        def setup_command(command, **kwargs):
            calls.append(command)
            if command[0] == "ssh-keygen":
                path = Path(command[command.index("-f") + 1])
                path.write_text("private-test-key\n")
                path.with_suffix(".pub").write_text("ssh-ed25519 public-test-key\n")
            if command[0] == "cloud-localds":
                Path(command[-3]).write_bytes(b"seed-test")
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with mock.patch.object(harness, "execute", side_effect=setup_command), mock.patch.object(harness, "port", return_value=22222):
            vm = harness.VM(1, root, root / "base.qcow2", ssh_key, 22223, "tcg")
        return vm, calls

    def test_disk_serial_is_a_device_property_and_disk_order_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            vm, _ = self.make_vm(directory)
            drives = [vm.command[index + 1] for index, value in enumerate(vm.command) if value == "-drive"]
            devices = [vm.command[index + 1] for index, value in enumerate(vm.command) if value == "-device" and vm.command[index + 1].startswith("virtio-blk-pci")]
            self.assertTrue(all("serial=" not in drive for drive in drives), "QEMU removed -drive serial= in 3.0")
            self.assertEqual(devices, ["virtio-blk-pci,drive=system", "virtio-blk-pci,drive=storage,serial=cf-test-data", "virtio-blk-pci,drive=seed"])
            self.assertTrue(all("if=none" in drive for drive in drives))
            self.assertIn("readonly=on", drives[2])

    def test_sparse_disks_stay_within_the_authorized_two_vm_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            _, calls = self.make_vm(directory)
            creates = [command for command in calls if command[:2] == ["qemu-img", "create"]]
            self.assertEqual([command[-1] for command in creates], ["24G", "11G"])
        budget = harness.resource_budget(3 * 1024 ** 3, 1024 ** 2)
        self.assertEqual(budget["system_disk_gib_per_vm"], int(creates[0][-1][:-1]))
        self.assertEqual(budget["test_disk_gib_per_vm"], int(creates[1][-1][:-1]))
        self.assertEqual(budget["total_virtual_disk_bytes"], 73 * 1024 ** 3 + 1024 ** 2)
        self.assertEqual(budget["maximum_virtual_disk_bytes"], 80_000_000_000)
        self.assertEqual(budget["maximum_memory_bytes"], 8_000_000_000)
        self.assertLessEqual(budget["total_virtual_disk_bytes"], 80_000_000_000)
        self.assertLessEqual(budget["configured_memory_bytes"], 8_000_000_000)
        with self.assertRaises(harness.VerificationError):
            harness.resource_budget(5 * 1024 ** 3)

    def test_previous_79_gib_disk_configuration_exceeds_decimal_authorization(self):
        # Actual aa1bb690 CI: two 24+14 GiB VMs, a 3 GiB base and 753664 seed bytes.
        old_total = 79 * 1024 ** 3 + 753664
        self.assertEqual(old_total, 84_826_357_760)
        self.assertGreater(old_total, 80_000_000_000)
        with mock.patch.object(harness, "TEST_DISK_GIB", 14):
            with self.assertRaises(harness.VerificationError):
                harness.resource_budget(3 * 1024 ** 3, 753664)

    def test_decimal_disk_limit_accepts_exact_bytes_and_rejects_base_or_seed_growth(self):
        base = 3 * 1024 ** 3
        vm_disks = 2 * (24 + 11) * 1024 ** 3
        seed_at_limit = 80_000_000_000 - vm_disks - base
        budget = harness.resource_budget(base, seed_at_limit)
        self.assertEqual(budget["total_virtual_disk_bytes"], 80_000_000_000)
        for base_bytes, seed_bytes in ((base + 1, seed_at_limit), (base, seed_at_limit + 1)):
            with self.subTest(base_bytes=base_bytes, seed_bytes=seed_bytes):
                with self.assertRaises(harness.VerificationError):
                    harness.resource_budget(base_bytes, seed_bytes)

    def test_eight_gib_memory_is_rejected_by_eight_decimal_gb_limit(self):
        with mock.patch.object(harness, "VM_MEMORY_MIB", 4096):
            with self.assertRaises(harness.VerificationError):
                harness.resource_budget(3 * 1024 ** 3)

    def test_qemu_error_is_retained_and_only_known_diagnostic_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            vm, _ = self.make_vm(directory)
            private_log = vm.directory / "qemu.private.stderr.log"
            private_log.write_text("qemu-system-x86_64: Block format 'qcow2' does not support the option 'serial'\nPRIVATE-KEY-MUST-NOT-LEAK\n")
            vm.process = mock.Mock()
            vm.process.poll.return_value = 1
            with self.assertRaises(harness.VerificationError) as error:
                vm.wait_ready()
            self.assertIn("unsupported-drive-serial", str(error.exception))
            self.assertIn("exit 1", str(error.exception))
            self.assertNotIn("PRIVATE-KEY", str(error.exception))
            self.assertNotIn(directory, str(error.exception))
            self.assertIn("PRIVATE-KEY", private_log.read_text())


class ImageIdentityTests(unittest.TestCase):
    def fixture(self):
        revision = "a" * 40
        manifest_digest = "sha256:" + "b" * 64
        config_digest = "sha256:" + "c" * 64
        config = {"architecture": "amd64", "os": "linux", "config": {"User": "10001:10001", "Labels": {"org.opencontainers.image.revision": revision}, "Env": ["PATH=/usr/bin"], "Entrypoint": ["/entrypoint.sh"]}, "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "d" * 64]}}
        expected = {"registry_reference": "localhost:5001/cf-filebrowser@" + manifest_digest, "registry_digest": manifest_digest, "manifest_digest": manifest_digest, "config_digest": config_digest, "config": config}
        info = {"Id": config_digest, "RepoDigests": [expected["registry_reference"]], "Config": copy.deepcopy(config["config"]), "Os": "linux", "Architecture": "amd64", "RootFS": {"Type": "layers", "Layers": config["rootfs"]["diff_ids"]}}
        return revision, expected, info

    def test_legacy_config_id_and_containerd_manifest_id_verify_same_content(self):
        revision, expected, info = self.fixture()
        harness.verify_image_identity(info, expected, revision)
        info["Id"] = expected["manifest_digest"]
        info["Descriptor"] = {"digest": expected["manifest_digest"], "mediaType": "application/vnd.oci.image.manifest.v1+json"}
        harness.verify_image_identity(info, expected, revision)
        record = harness.image_identity_record(info)
        self.assertEqual(record["image_id"], expected["manifest_digest"])
        self.assertEqual(record["descriptor"]["digest"], expected["manifest_digest"])
        self.assertNotIn("Env", json.dumps(record))

    def test_wrong_pin_id_configuration_layers_or_revision_are_rejected(self):
        revision, expected, info = self.fixture()
        mutations = [lambda x: x.update(RepoDigests=[]), lambda x: x.update(Id="sha256:" + "e" * 64), lambda x: x["Config"].update(User="0:0"), lambda x: x["Config"]["Labels"].update({"org.opencontainers.image.revision": "f" * 40}), lambda x: x["RootFS"].update(Layers=[]), lambda x: x.update(Descriptor={"digest": "sha256:" + "e" * 64})]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(info)
                mutate(changed)
                with self.assertRaises(harness.VerificationError):
                    harness.verify_image_identity(changed, expected, revision)

    def test_registry_blob_bytes_must_match_digest_before_json_is_trusted(self):
        payload = b'{"schemaVersion":2}'
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        self.assertEqual(harness.decode_registry_blob(payload, digest), {"schemaVersion": 2})
        with self.assertRaises(harness.VerificationError):
            harness.decode_registry_blob(payload + b" ", digest)


class FailureEvidenceTests(unittest.TestCase):
    def test_failed_api_retains_sanitized_checks_without_raw_output(self):
        vm = mock.Mock(name="guest")
        vm.name = "cf-verification-2"
        vm.command_on_guest.return_value = subprocess.CompletedProcess([], 1, b"TOKEN-MUST-NOT-LEAK", b"PASSWORD-MUST-NOT-LEAK")
        report = {"version": 1, "phase": "protocols", "passed": False, "checks": [{"name": "webdav_put_denied", "passed": False}], "failure": "unexpected status"}
        vm.read_file.return_value = json.dumps(report).encode()
        with self.assertRaises(harness.VerificationError) as caught:
            harness.api(vm, "protocols", "api-protocols.json")
        self.assertEqual(caught.exception.api_evidence, report)
        self.assertNotIn("TOKEN", str(caught.exception))
        self.assertNotIn("PASSWORD", str(caught.exception))
        self.assertFalse(vm.command_on_guest.call_args.kwargs["check"])

    def test_failed_lan_preserves_only_allowlisted_report_and_keeps_nonzero_failure(self):
        vm = mock.Mock(name='guest')
        vm.name = 'cf-verification-2'
        report = {'schema': 'cf-lan-boundary/v1', 'passed': False, 'stage': 'wrong-ca',
                  'completed': ['allowed-health-before', 'PRIVATE-TOKEN'],
                  'observations': {'wrong-ca': {'curl_exit_code': 35, 'body': 'PRIVATE-BODY', 'errno': True}, 'PRIVATE-STAGE': {}},
                  'failure': {'category': 'assertion', 'message': 'PRIVATE-PASSWORD', 'verify_code': '92'},
                  'unexpected': 'PRIVATE-KEY'}
        vm.command_on_guest.return_value = subprocess.CompletedProcess([], 1, json.dumps(report).encode(), b'PRIVATE-STDERR')
        with self.assertRaises(harness.VerificationError) as caught:
            harness.lan_boundary(vm)
        safe = caught.exception.lan_evidence
        self.assertEqual(safe['stage'], 'wrong-ca')
        self.assertEqual(safe['observations'], {'wrong-ca': {'curl_exit_code': 35}})
        self.assertEqual(safe['failure'], {'category': 'assertion'})
        self.assertEqual(safe['completed'], ['allowed-health-before'])
        self.assertNotIn('PRIVATE', json.dumps(safe) + str(caught.exception))
        self.assertFalse(vm.command_on_guest.call_args.kwargs['check'])

    def test_lan_missing_or_forged_success_report_cannot_mask_failure(self):
        vm = mock.Mock(name='guest')
        vm.name = 'cf-verification-2'
        for payload in (b'PRIVATE-TOKEN', b'{"schema":"cf-lan-boundary/v1","passed":true,"stage":"complete","completed":[]}'):
            with self.subTest(payload=payload):
                vm.command_on_guest.return_value = subprocess.CompletedProcess([], 0, payload, b'PRIVATE-PASSWORD')
                with self.assertRaises(harness.VerificationError) as caught:
                    harness.lan_boundary(vm)
                self.assertFalse(caught.exception.lan_evidence['passed'])
                self.assertNotIn('PRIVATE', str(caught.exception) + json.dumps(caught.exception.lan_evidence))

    def test_failed_lan_keeps_only_completed_prefix_before_current_stage(self):
        stages = list(harness.LAN_PROBE_STAGES[1:-1])
        cases = [('allowed-health-before', stages, []),
                 ('denied-tls-handshake', stages, stages[:5]),
                 ('wrong-ca', [stages[0], stages[0], *stages[1:]], stages[:1]),
                 ('wrong-ca', [stages[1], stages[0]], []),
                 ('wrong-ca', [stages[0], 'PRIVATE-STAGE', stages[1]], stages[:1]),
                 ('guest-dispatch', stages, [])]
        for current, claimed, expected in cases:
            with self.subTest(current=current, claimed=claimed):
                value = {'schema': 'cf-lan-boundary/v1', 'passed': False, 'stage': current,
                         'completed': claimed, 'observations': {stage: {'http_status': 200} for stage in stages},
                         'failure': {'category': 'assertion'}}
                report = harness.sanitized_lan_report(value)
                self.assertEqual(report['completed'], expected)
                allowed = set(expected + ([current] if current in stages else []))
                self.assertEqual(set(report['observations']), allowed)
                self.assertFalse(report['passed'])

    def test_api_configuration_failure_does_not_mask_original_exit(self):
        vm = mock.Mock(name="guest")
        vm.name = "cf-verification-2"
        vm.command_on_guest.return_value = subprocess.CompletedProcess([], 2, b"secret", b"secret")
        vm.read_file.side_effect = harness.VerificationError("missing")
        with self.assertRaises(harness.VerificationError) as caught:
            harness.api(vm, "exercise", "api-initial.json")
        self.assertIn("exit 2", str(caught.exception))
        self.assertFalse(caught.exception.api_evidence["passed"])


class RuntimeReadinessTests(unittest.TestCase):
    def fixture(self):
        return {"image_id": "sha256:" + "a" * 64, "health": "healthy", "running": True, "readonly_rootfs": True, "exec_uid": 10001, "exec_gid": 10001, "pid1_uid": [10001] * 4, "pid1_gid": [10001] * 4, "tools": {name: {"exit_code": 0, "version": "1.2.3"} for name in ("ffmpeg", "ffprobe", "exiftool", "curl", "filebrowser")}, "filebrowser_commit": "b" * 40, "writable": {name: True for name in ("files", "data", "cache")}, "denied_writes": {"root": True, "config": True}, "readable": {name: True for name in ("entrypoint", "config", "jwt", "totp", "storage_identity", "tls_certificate", "tls_key", "tls_ca")}, "entrypoint_executable": True, "entrypoint_syntax_valid": True, "readonly_bind_mounts": True, "bootstrap_absent": True}

    def test_runtime_contract_requires_real_numeric_identity_and_all_boundaries(self):
        record = self.fixture()
        harness.verify_runtime_readiness(record, record["image_id"], record["filebrowser_commit"])
        for key, bad in (("exec_uid", 0), ("exec_gid", 0), ("pid1_uid", [0] * 4), ("health", "unhealthy"), ("readonly_rootfs", False), ("readonly_bind_mounts", False), ("bootstrap_absent", False)):
            with self.subTest(key=key):
                changed = copy.deepcopy(record)
                changed[key] = bad
                with self.assertRaises(harness.VerificationError):
                    harness.verify_runtime_readiness(changed, record["image_id"], record["filebrowser_commit"])
        for section, key, bad in (("tools", "ffmpeg", {"exit_code": 1, "version": ""}), ("writable", "files", False), ("denied_writes", "config", False), ("readable", "jwt", False)):
            with self.subTest(section=section):
                changed = copy.deepcopy(record)
                changed[section][key] = bad
                with self.assertRaises(harness.VerificationError):
                    harness.verify_runtime_readiness(changed, record["image_id"], record["filebrowser_commit"])

    def test_runtime_script_uses_service_identity_and_only_temporary_writes(self):
        script = harness.runtime_readiness_script()
        self.assertNotIn('"--user"', script)
        self.assertNotIn('chown', script)
        self.assertNotIn('chmod', script)
        self.assertNotIn('database.db', script)
        self.assertIn('mktemp', script)
        self.assertIn('test -r', script)
        self.assertIn('exec 3>>', script)


class MissingStorageTests(unittest.TestCase):
    def fixture(self):
        return {"docker_active": True, "sentinel_id": "b" * 64, "sentinel_running": True, "service_ids": ["a" * 64], "service_id": "a" * 64, "service_running": False, "storage_mounted": False, "storage_directory_exists": True, "storage_device_is_root": True, "business_path_exists": False}

    def test_daemon_not_restored_yet_cannot_count_as_missing_disk_refusal(self):
        # This met the old SSH-boot-ID/nonrunning/no-project-path assertions.
        record = self.fixture()
        record.update(docker_active=False, sentinel_running=False)
        with self.assertRaises(harness.VerificationError):
            harness.verify_missing_storage_state(record, "a" * 64, "b" * 64)

    def test_exact_original_containers_and_no_system_disk_writes_are_required(self):
        record = self.fixture()
        harness.verify_missing_storage_state(record, "a" * 64, "b" * 64)
        for field, value in (("sentinel_id", "c" * 64), ("sentinel_running", False), ("service_id", "c" * 64), ("service_running", True), ("business_path_exists", True), ("storage_mounted", True), ("storage_device_is_root", False)):
            with self.subTest(field=field):
                changed = dict(record)
                changed[field] = value
                with self.assertRaises(harness.VerificationError):
                    harness.verify_missing_storage_state(changed, "a" * 64, "b" * 64)

    def test_wait_allows_delayed_autostart_without_starting_anything(self):
        ready = self.fixture()
        waiting = dict(ready, docker_active=False, sentinel_running=False)
        record = {}
        with mock.patch.object(harness, "missing_storage_state", side_effect=[waiting, ready]) as read, mock.patch.object(harness.time, "monotonic", return_value=0), mock.patch.object(harness.time, "sleep") as sleep:
            harness.wait_missing_storage_ready(mock.Mock(), "a" * 64, "b" * 64, record)
        self.assertEqual(read.call_count, 2)
        sleep.assert_called_once_with(2)
        self.assertEqual(record["before_explicit_start"], ready)
        self.assertEqual(record["readiness_observations"], 2)

    def test_wait_retries_a_snapshot_taken_during_daemon_transition(self):
        ready = self.fixture()
        transitional = dict(ready, service_id=None, service_ids=[], service_running=None)
        record = {}
        with mock.patch.object(harness, "missing_storage_state", side_effect=[transitional, ready]) as read, mock.patch.object(harness.time, "monotonic", return_value=0), mock.patch.object(harness.time, "sleep"):
            harness.wait_missing_storage_ready(mock.Mock(), "a" * 64, "b" * 64, record)
        self.assertEqual(read.call_count, 2)
        self.assertEqual(record["before_explicit_start"], ready)

    def test_inactive_daemon_probe_never_triggers_docker_socket_activation(self):
        vm = mock.Mock()
        vm.command_on_guest.return_value = subprocess.CompletedProcess([], 0, b"{}", b"")
        harness.missing_storage_state(vm, "a" * 64, "b" * 64)
        script = vm.command_on_guest.call_args.args[0]
        body = script.split("<<'CF_MISSING_STORAGE'\n", 1)[1].rsplit("\nCF_MISSING_STORAGE", 1)[0]
        with mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 3, "", "")) as commands, mock.patch("builtins.print"):
            exec(compile(body, "missing-storage-guest", "exec"), {})
        self.assertTrue(commands.called)
        self.assertTrue(all(call.args[0][0] != "docker" for call in commands.call_args_list))

    def test_wait_times_out_and_retains_last_state(self):
        waiting = dict(self.fixture(), docker_active=False, sentinel_running=False)
        record = {}
        with mock.patch.object(harness, "missing_storage_state", return_value=waiting), mock.patch.object(harness.time, "monotonic", side_effect=[0, 0, 0, 180]), mock.patch.object(harness.time, "sleep"):
            with self.assertRaisesRegex(harness.VerificationError, "180 seconds"):
                harness.wait_missing_storage_ready(mock.Mock(), "a" * 64, "b" * 64, record)
        self.assertEqual(record["before_explicit_start"], waiting)

    def test_wait_never_tolerates_a_system_disk_write_or_returned_mount(self):
        for field, value in (("business_path_exists", True), ("storage_mounted", True), ("service_running", True)):
            with self.subTest(field=field):
                unsafe = dict(self.fixture(), docker_active=False, sentinel_running=False)
                unsafe[field] = value
                record = {}
                with mock.patch.object(harness, "missing_storage_state", return_value=unsafe), mock.patch.object(harness.time, "monotonic", return_value=0), mock.patch.object(harness.time, "sleep") as sleep:
                    with self.assertRaises(harness.VerificationError):
                        harness.wait_missing_storage_ready(mock.Mock(), "a" * 64, "b" * 64, record)
                sleep.assert_not_called()
                self.assertEqual(record["before_explicit_start"], unsafe)

    def test_missing_storage_probe_uses_full_saved_container_ids(self):
        vm = mock.Mock()
        vm.command_on_guest.return_value = subprocess.CompletedProcess([], 0, json.dumps(self.fixture()).encode(), b"")
        harness.missing_storage_state(vm, "a" * 64, "b" * 64)
        script = vm.command_on_guest.call_args.args[0]
        self.assertIn("'--no-trunc'", script)
        self.assertIn("inspect('" + "a" * 64 + "')", script)
        with self.assertRaises(harness.VerificationError):
            harness.missing_storage_state(vm, "a" * 12, "b" * 64)

    def test_explicit_start_rejection_retains_only_known_error_category(self):
        report = harness.missing_storage_rejection(subprocess.CompletedProcess([], 1, b"SECRET", b"Error: bind source path does not exist: /private/path\nTOKEN"))
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["category"], "missing-bind-source")
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertNotIn("TOKEN", json.dumps(report))
        self.assertNotIn("/private/path", json.dumps(report))



class AuditStoreFaultTests(unittest.TestCase):
    IMAGE = "sha256:" + "b" * 64
    CONTAINER = "a" * 64

    def test_private_reports_only_export_fixed_whitelist_values(self):
        raw = {"version": 1, "phase": "server", "mode": "inject", "passed": True, "detached": True,
               "stage": "complete", "strace_version": "6.13", "coverage_samples": 4,
               "counts": {"writes": 3, "successful": 0, "injected_eio": 3},
               "identity": {"pid": 12, "container": self.CONTAINER, "token": "PRIVATE_TOKEN"},
               "request_id": "PRIVATE_ID", "nonce": "PRIVATE_NONCE", "trace": "PRIVATE_TRACE",
               "failure": None, "body": "PRIVATE_BODY"}
        safe = harness.fault_public_report(raw, "server", mode="inject")
        self.assertTrue(safe["passed"])
        self.assertEqual(safe["counts"], raw["counts"])
        encoded = json.dumps(safe)
        self.assertNotIn("PRIVATE", encoded)
        self.assertNotIn(self.CONTAINER, encoded)
        self.assertNotIn("identity", encoded)
        for key, value in (("phase", "verify"), ("passed", 1), ("stage", "PRIVATE_STAGE"),
                           ("coverage_samples", True), ("counts", {"writes": 0, "successful": 0, "injected_eio": 0})):
            bad = dict(raw, **{key: value})
            rejected = harness.fault_public_report(bad, "server", mode="inject")
            self.assertFalse(rejected["passed"])
            self.assertNotIn("PRIVATE", json.dumps(rejected))

    def test_ready_requires_exact_current_container_image_and_nonce_without_echo(self):
        worker = mock.Mock()
        worker.is_alive.return_value = True
        baseline = {"version": 1, "ready": True, "mode": "inject", "container": self.CONTAINER,
                    "image": self.IMAGE, "nonce": "c" * 32, "control_sha256": "d" * 64, "body": "PRIVATE_BODY"}
        server = mock.Mock()
        server.command_on_guest.return_value = subprocess.CompletedProcess([], 0, stdout=json.dumps(baseline).encode(), stderr=b"")
        safe = harness.fault_wait_ready(server, "inject", self.CONTAINER, self.IMAGE, worker)
        self.assertNotIn("PRIVATE", json.dumps(safe))
        for key, value in (("version", True), ("ready", 1), ("mode", "observe"), ("container", "f" * 64),
                           ("image", "sha256:" + "e" * 64), ("nonce", "PRIVATE_NONCE")):
            changed = dict(baseline, **{key: value})
            server.command_on_guest.return_value.stdout = json.dumps(changed).encode()
            with self.subTest(field=key), self.assertRaises(harness.VerificationError) as caught:
                harness.fault_wait_ready(server, "inject", self.CONTAINER, self.IMAGE, worker)
            self.assertNotIn("PRIVATE", str(caught.exception))

    def test_source_stage_uses_existing_sequence_and_only_guest_apt_dependency(self):
        import inspect
        source = inspect.getsource(harness.scenario)
        self.assertLess(source.index("audit_pending_interrupt("), source.index("audit_store_fault("))
        self.assertLess(source.index("audit_store_fault("), source.index('"initial-real-api-exercise"'))
        fake = mock.Mock()
        harness.prerequisites(fake, "a" * 40)
        script = fake.command_on_guest.call_args.args[0]
        self.assertIn("apt-get install --yes --no-install-recommends ca-certificates", script)
        self.assertIn("e2fsprogs strace", script)
        self.assertNotIn("ptrace_scope", script)
        self.assertNotIn("SYS_PTRACE", script)

    def run_probe(self, *, failed_client=None, missing_ready=False, detach_failure=False, release_failure=False):
        events, evidence = [], {}
        released = {mode: threading.Event() for mode in ("observe", "inject")}
        server = SimpleNamespace(name="cf-verification-1")
        client = SimpleNamespace(name="cf-verification-2")
        server.read_file = client.read_file = mock.Mock(return_value=b"PRIVATE_CONTROL")
        def write(path, data, mode="0600"):
            events.append(("write", path))
            if "release" in path:
                which = "observe" if "observe" in path else "inject"
                if release_failure:
                    released[which].set()
                    raise harness.VerificationError("PRIVATE_RELEASE_ERROR")
                self.assertEqual(json.loads(data), {"version": 1, "nonce": "c" * 32})
                released[which].set()
        server.write_file = client.write_file = write
        def command(script, **kwargs):
            events.append(("command", script))
            body = {"id": self.CONTAINER, "image": self.IMAGE, "running": True, "healthy": True}
            return subprocess.CompletedProcess([], 0, stdout=json.dumps(body).encode(), stderr=b"")
        server.command_on_guest = command
        def call(machine, phase, evidence_name, *arguments, **kwargs):
            mode = arguments[arguments.index("--mode") + 1] if "--mode" in arguments else None
            events.append((phase, mode))
            if phase == "server":
                self.assertIs(machine, server)
                self.assertIn(self.CONTAINER, arguments)
                self.assertIn(self.IMAGE, arguments)
                released[mode].wait(timeout=0.2)
                return {"version": 1, "phase": phase, "mode": mode, "passed": True, "detached": True,
                        "stage": "complete", "strace_version": "6.13", "coverage_samples": 4,
                        "counts": {"writes": 1, "successful": int(mode == "observe"), "injected_eio": int(mode == "inject")}}
            if phase == "detached":
                return {"version": 1, "phase": phase, "passed": not detach_failure, "detached": not detach_failure}
            if phase == failed_client:
                failure = harness.VerificationError("PRIVATE_CLIENT_ERROR")
                failure.fault_evidence = {"version": 1, "phase": phase, "passed": False,
                                          "failure": "PRIVATE_BODY", "request_id": "PRIVATE_ID", "trace": "PRIVATE_TRACE"}
                raise failure
            return {"version": 1, "phase": phase, "passed": True, "requests": 1, "check_count": 2}
        def ready(machine, mode, container, image, worker):
            self.assertEqual((container, image), (self.CONTAINER, self.IMAGE))
            if missing_ready:
                raise harness.VerificationError("PRIVATE_READY_ERROR")
            return {"version": 1, "ready": True, "mode": mode, "nonce": "c" * 32,
                    "container": self.CONTAINER, "image": self.IMAGE, "control_sha256": "d" * 64}
        self.events, self.evidence = events, evidence
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(harness, "fault_guest", side_effect=call))
            stack.enter_context(mock.patch.object(harness, "fault_wait_ready", side_effect=ready))
            stack.enter_context(mock.patch.object(harness, "record_stage"))
            stack.enter_context(mock.patch.object(harness, "sentinel_state", return_value={"stable": True}))
            stack.enter_context(mock.patch.object(harness, "healthy"))
            harness.audit_store_fault(server, client, SimpleNamespace(), evidence, self.IMAGE,
                                      {server.name: {"stable": True}, client.name: {"stable": True}})
        return events, evidence

    def test_real_probe_order_uses_two_windows_then_formal_restart_and_verify(self):
        events, evidence = self.run_probe()
        phases = [entry[0] for entry in events if entry[0] not in ("write", "command")]
        self.assertEqual(phases, ["prepare", "server", "control", "detached", "server", "fault", "detached", "restarted", "verify"])
        commands = [entry[1] for entry in events if entry[0] == "command"]
        formal = [item for item in commands if "manage.sh stop" in item]
        self.assertEqual(len(formal), 1)
        self.assertIn("manage.sh start", formal[0])
        self.assertTrue(evidence["audit_store_fault"]["passed"])
        self.assertNotIn("PRIVATE", json.dumps(evidence))
        self.assertNotIn(self.CONTAINER, json.dumps(evidence))
        self.assertFalse(any(thread.name.startswith("audit-store-") for thread in threading.enumerate()))

    def test_not_ready_sends_no_put_but_joins_and_verifies_detach(self):
        with self.assertRaises(harness.VerificationError):
            self.run_probe(missing_ready=True)
        phases = [entry[0] for entry in self.events]
        self.assertNotIn("control", phases)
        self.assertNotIn("fault", phases)
        self.assertIn("detached", phases)
        self.assertFalse(any("manage.sh start" in str(entry) for entry in self.events))
        self.assertNotIn("PRIVATE", json.dumps(self.evidence))

    def test_client_failure_releases_joins_verifies_detach_and_stops(self):
        with self.assertRaises(harness.VerificationError):
            self.run_probe(failed_client="fault")
        self.assertEqual(sum(entry == ("detached", None) for entry in self.events), 2)
        self.assertTrue(any(entry[0] == "write" and "inject-release" in entry[1] for entry in self.events))
        self.assertFalse(any("manage.sh start" in str(entry) for entry in self.events))
        self.assertNotIn("PRIVATE", json.dumps(self.evidence))
        self.assertFalse(any(thread.name.startswith("audit-store-") for thread in threading.enumerate()))

    def test_release_or_detach_failure_never_enters_next_window_or_restart(self):
        for option in ("detach_failure", "release_failure"):
            with self.subTest(option=option), self.assertRaises(harness.VerificationError):
                self.run_probe(**{option: True})
            self.assertNotIn(("server", "inject"), self.events)
            self.assertFalse(any("manage.sh start" in str(entry) for entry in self.events))
            self.assertFalse(self.evidence["audit_store_fault"]["passed"])
            self.assertNotIn("PRIVATE", json.dumps(self.evidence))


class InitialUIContinuationTests(unittest.TestCase):
    IMAGE = "sha256:" + "b" * 64
    CONTAINER = "a" * 64
    PINNED = "localhost:1234/cf-test@sha256:" + "c" * 64

    def failure(self):
        attempts = [{'case': case, 'status': 'failed' if case == 'crud' else 'passed', 'retry': 0,
                     'stage': 'edit' if case == 'crud' else 'xlsx_checks' if case == 'xlsx' else case}
                    for case in harness.UI_CASE_IDS]
        cases = harness.ui_case_evidence(b'\n'.join(json.dumps(item).encode() for item in attempts))
        error = harness.VerificationError('PRIVATE_ERROR')
        error.ui_evidence = {'passed': False, 'process_exit_code': 1, 'cases': cases, 'raster_passed': True,
                             'raster': UIRasterEvidenceTests().fixture()}
        return error

    def invoke(self, error=None, *, backup_failure=False, invalid_snapshot=False, ui_passed=False):
        events, evidence = [], {'result': 'failed', 'checks': []}
        server, client = SimpleNamespace(name='cf-verification-1'), SimpleNamespace(name='cf-verification-2')
        args = SimpleNamespace(source_sha='d' * 40)
        def command(script, **kwargs):
            if 'backup.sh create' in script:
                events.append('backup')
                self.assertIn('ui-failure-initial.tar', script)
                self.assertIn('--source-sha ' + args.source_sha, script)
                self.assertIn('--image-id ' + self.IMAGE, script)
                self.assertNotIn('PRIVATE', script)
                if backup_failure:
                    raise harness.VerificationError('private backup command failed')
                output = b''
            elif 'manage.sh start' in script:
                events.append('start')
                output = b''
            elif 'UI_FAILURE_SNAPSHOT' in script:
                events.append('snapshot')
                output = json.dumps({'version': 1, 'verified': not invalid_snapshot,
                                     'sha256': 'e' * 64, 'size': 10240}).encode()
            else:
                events.append('identity')
                output = json.dumps({'id': self.CONTAINER, 'image': self.IMAGE,
                                     'running': True, 'healthy': True}).encode()
            return subprocess.CompletedProcess([], 0, output, b'')
        server.command_on_guest = command
        self.events, self.evidence = events, evidence
        with contextlib.ExitStack() as stack:
            ui = stack.enter_context(mock.patch.object(harness, 'real_ui'))
            if ui_passed:
                ui.return_value = {'passed': True}
            else:
                ui.side_effect = error or self.failure()
            stack.enter_context(mock.patch.object(harness, 'record_stage'))
            stack.enter_context(mock.patch.object(harness, 'sentinel_state', return_value={'stable': True}))
            stack.enter_context(mock.patch.object(harness, 'healthy', side_effect=lambda vm: events.append('healthy')))
            harness.initial_ui_with_preservation(server, client, args, evidence, self.IMAGE, self.PINNED,
                                                 {server.name: {'stable': True}, client.name: {'stable': True}})
            events.append('subsequent-lifecycle')
            ui.assert_called_once_with(client)
        return evidence

    def test_real_ui_failure_snapshots_before_start_and_continues_without_passing(self):
        evidence = self.invoke()
        self.assertLess(self.events.index('backup'), self.events.index('snapshot'))
        self.assertLess(self.events.index('snapshot'), self.events.index('start'))
        self.assertLess(self.events.index('start'), self.events.index('subsequent-lifecycle'))
        self.assertEqual(evidence['result'], 'failed')
        self.assertEqual(evidence['ui_failures'], ['initial_ui'])
        self.assertFalse(evidence['initial_ui']['passed'])
        self.assertTrue(evidence['initial_ui_preservation']['passed'])
        self.assertFalse(evidence['initial_ui_preservation']['process_memory_preserved'])
        self.assertTrue(evidence['initial_ui_preservation']['private_ui_output_retained'])
        self.assertNotIn('PRIVATE', json.dumps(evidence))

    def test_invalid_or_incomplete_ui_evidence_never_starts_preservation_or_lifecycle(self):
        for variant in ('missing', 'exit-zero', 'exit-bool', 'partial', 'forged-final', 'all-passed', 'private-stage', 'missing-raster', 'skipped-case', 'transport'):
            error = self.failure()
            if variant == 'missing':
                del error.ui_evidence
            elif variant == 'exit-zero':
                error.ui_evidence['process_exit_code'] = 0
            elif variant == 'exit-bool':
                error.ui_evidence['process_exit_code'] = True
            elif variant == 'partial':
                error.ui_evidence['cases']['attempts'].pop()
            elif variant == 'forged-final':
                error.ui_evidence['cases']['final']['crud'] = 'passed'
            elif variant == 'all-passed':
                error.ui_evidence['cases']['attempts'][0].update(status='passed', stage='delete')
                error.ui_evidence['cases'] = harness.ui_case_evidence(b'\n'.join(
                    json.dumps(item).encode() for item in error.ui_evidence['cases']['attempts']))
            elif variant == 'private-stage':
                error.ui_evidence['cases']['attempts'][0]['stage'] = 'PRIVATE_STAGE'
            elif variant == 'missing-raster':
                del error.ui_evidence['raster']
                error.ui_evidence['raster_passed'] = False
            elif variant == 'skipped-case':
                error.ui_evidence['cases']['attempts'][1]['status'] = 'skipped'
                error.ui_evidence['cases']['final']['png'] = 'skipped'
            else:
                error = OSError('PRIVATE_TRANSPORT')
            with self.subTest(variant=variant), self.assertRaises((harness.VerificationError, OSError)):
                self.invoke(error)
            self.assertNotIn('backup', self.events)
            self.assertNotIn('start', self.events)
            self.assertNotIn('subsequent-lifecycle', self.events)

    def test_unknown_case_stage_never_authorizes_continuation(self):
        for all_unknown in (False, True):
            error = self.failure()
            attempts = error.ui_evidence['cases']['attempts']
            for item in (attempts if all_unknown else attempts[:1]):
                item.update(status='failed', stage=None)
            # Generic diagnostics must still retain unknown stages. Only the
            # continuation gate rejects possible browser/page fixture failures.
            error.ui_evidence['cases'] = harness.ui_case_evidence(b'\n'.join(json.dumps(item).encode() for item in attempts))
            if all_unknown:
                error.ui_evidence['raster_passed'] = False
                del error.ui_evidence['raster']
            with self.subTest(all_unknown=all_unknown):
                with self.assertRaises(harness.VerificationError):
                    self.invoke(error)
                self.assertNotIn('backup', self.events)
                self.assertNotIn('start', self.events)
                self.assertNotIn('subsequent-lifecycle', self.events)
                self.assertIsNone(error.ui_evidence['cases']['attempts'][0]['stage'])

    def test_failed_spreadsheet_case_can_preserve_absent_raster_without_claiming_decode(self):
        error = self.failure()
        error.ui_evidence['cases']['attempts'][3].update(status='failed', stage='xlsx1_response')
        error.ui_evidence['cases']['final']['xlsx'] = 'failed'
        error.ui_evidence['raster_passed'] = False
        del error.ui_evidence['raster']
        evidence = self.invoke(error)
        self.assertEqual(evidence['initial_ui']['cases']['final']['xlsx'], 'failed')
        self.assertFalse(evidence['initial_ui']['raster_passed'])
        self.assertNotIn('raster', evidence['initial_ui'])
        self.assertIn('subsequent-lifecycle', self.events)

    def test_backup_or_snapshot_refusal_preserves_failure_and_never_restarts(self):
        for flag in ('backup_failure', 'invalid_snapshot'):
            with self.subTest(flag=flag), self.assertRaises(harness.VerificationError):
                self.invoke(**{flag: True})
            self.assertIn('backup', self.events)
            self.assertNotIn('start', self.events)
            self.assertNotIn('subsequent-lifecycle', self.events)
            self.assertFalse(self.evidence['initial_ui_preservation']['passed'])
            self.assertEqual(self.evidence['ui_failures'], ['initial_ui'])

    def test_initial_success_does_not_make_a_failure_backup_or_mark_sticky_failure(self):
        evidence = self.invoke(ui_passed=True)
        self.assertNotIn('backup', self.events)
        self.assertNotIn('start', self.events)
        self.assertTrue(evidence['initial_ui']['passed'])
        self.assertNotIn('ui_failures', evidence)

    def test_completion_cannot_overwrite_initial_failure_after_restored_ui_passes(self):
        evidence = self.invoke()
        evidence['restored_ui'] = {'passed': True}
        with mock.patch.object(harness, 'record_stage'), self.assertRaises(harness.VerificationError):
            harness.complete_scenario(SimpleNamespace(), evidence)
        self.assertEqual(evidence['result'], 'failed')
        self.assertTrue(evidence['restored_ui']['passed'])
        self.assertFalse(evidence['initial_ui']['passed'])

    def test_completion_passes_when_both_actual_ui_phases_passed(self):
        evidence = {'result': 'failed', 'initial_ui': {'passed': True}, 'restored_ui': {'passed': True}}
        with mock.patch.object(harness, 'record_stage'):
            harness.complete_scenario(SimpleNamespace(), evidence)
        self.assertEqual(evidence['result'], 'passed')

    def test_main_returns_one_after_independent_stages_finish_with_sticky_failure(self):
        import io
        with tempfile.TemporaryDirectory(prefix='cf-ui-sticky-result-') as directory:
            root = Path(directory)
            output = root / 'evidence'
            def scenario(args, work, evidence):
                evidence.update(initial_ui={'passed': False}, restored_ui={'passed': True}, ui_failures=['initial_ui'])
                harness.complete_scenario(args, evidence)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(harness.sys, 'platform', 'linux'))
                stack.enter_context(mock.patch.dict(harness.os.environ, {'GITHUB_ACTIONS': 'true'}))
                stack.enter_context(mock.patch.object(harness.shutil, 'which', return_value='available'))
                stack.enter_context(mock.patch.object(harness.tempfile, 'mkdtemp', return_value=str(root / 'private')))
                stack.enter_context(mock.patch.object(harness, 'scenario', side_effect=scenario))
                stack.enter_context(mock.patch.object(harness.sys, 'argv', ['shared_host_vm.py', '--source-sha', 'a' * 40,
                    '--image-ref', self.PINNED, '--evidence', str(output), '--accelerator', 'tcg']))
                stdout, stderr = io.StringIO(), io.StringIO()
                stack.enter_context(contextlib.redirect_stdout(stdout))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                self.assertEqual(harness.main(), 1)
            stored = json.loads((output / 'vm-result.json').read_bytes())
            self.assertEqual(stored['result'], 'failed')
            self.assertFalse(stored['initial_ui']['passed'])
            self.assertTrue(stored['restored_ui']['passed'])
            self.assertNotIn('verification passed', stdout.getvalue())

    def test_scenario_preserves_full_remaining_sequence_and_uses_sticky_completion(self):
        import inspect
        source = inspect.getsource(harness.scenario)
        full_call = '        storage_lifecycle(args, evidence, server, client, image_id, baseline)'
        self.assertEqual(source.count(full_call + '\n'), 1)
        self.assertLess(source.index('"real-host-reboot-and-api"'), source.index(full_call + '\n'))
        self.assertLess(source.index(full_call + '\n'), source.index('"formal-controlled-stop-backup"'))
        source += inspect.getsource(harness.storage_lifecycle)
        self.assertLess(source.index('initial_ui_with_preservation('), source.index('"formal-stop-start-and-container-restart"'))
        for phase in ('"docker-daemon-restart-and-api"', '"real-host-reboot-and-api"',
                      '"missing-business-mount-real-reboot"', '"container-recreation-and-persistence"',
                      '"formal-controlled-stop-backup"', '"blank-target-backup-rejection-tests-and-formal-restore"',
                      '"restored-real-api-verification"', '"restored-existing-playwright-ui"'):
            self.assertIn(phase, source)
        self.assertIn('evidence["restored_ui"] = real_ui(server)', source)
        self.assertIn('complete_scenario(args, evidence)', source)
        self.assertNotIn('evidence["result"] = "passed"', source)


class StorageLifecycleTests(unittest.TestCase):
    def test_data_config_root_and_disk_changes_fail_closed(self):
        before = {name: {"tree_sha256": "a" * 64, "entry_count": 1} for name in ("disk", "config", "data", "root_underlay")}
        before["root_underlay"]["business_path_exists"] = False
        harness.verify_lifecycle_snapshot(before, copy.deepcopy(before), include_data=True)
        for name in before:
            after = copy.deepcopy(before); after[name]["tree_sha256"] = "b" * 64
            with self.subTest(name=name), self.assertRaises(harness.VerificationError):
                harness.verify_lifecycle_snapshot(before, after, include_data=True)
        after = copy.deepcopy(before); after['root_underlay']['business_path_exists'] = True
        with self.assertRaises(harness.VerificationError):
            harness.verify_lifecycle_snapshot(after, after, include_data=False)

    def test_lifecycle_route_keeps_full_defaults_and_excludes_other_suites(self):
        import inspect
        source = inspect.getsource(harness.scenario)
        route = source.split('if args.scope == "lifecycle":', 1)[1].split('if args.scope == "reboot":', 1)[0]
        self.assertIn('"lifecycle-seed"', route)
        self.assertIn('verify_phase="lifecycle-verify"', route)
        self.assertIn('return', route)
        for call in ('real_ui(', 'audit_pending_interrupt(', 'audit_store_fault(', 'backup.sh', 'storage_control('):
            self.assertNotIn(call, route)
        self.assertIn('default="full"', inspect.getsource(harness.main))

    def test_only_lifecycle_api_omits_preview_and_full_verifier_retains_it(self):
        import inspect
        spec = importlib.util.spec_from_file_location('lifecycle_api', MODULE_PATH.with_name('shared-host-api.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.assertIn('self.verify_persistence()', inspect.getsource(module.Acceptance.lifecycle_verify))
        full = inspect.getsource(module.Acceptance.verify_restored)
        self.assertIn('self.verify_persistence()', full)
        self.assertIn('restored_actual_preview', full)
        self.assertIn('restored_preview_has_bytes', full)
        seed = inspect.getsource(module.Acceptance.lifecycle_seed)
        for call in ('self.token_tests(', 'self.share_tests(', 'self.check_audit('):
            self.assertIn(call, seed)
        self.assertNotIn('fixtures()', seed)


class RebootDiagnosticTests(unittest.TestCase):
    def test_timeout_names_exact_operation_and_keeps_raw_output_private(self):
        args = SimpleNamespace()
        evidence = {'source_sha': 'a' * 40, 'result': 'failed'}
        vm = SimpleNamespace(name='cf-verification-1')
        failure = subprocess.TimeoutExpired(['ssh', 'PRIVATE-ARG'], 210,
                                            output=b'PRIVATE-TOKEN', stderr=b'PRIVATE-SECRET')
        with mock.patch.object(harness, 'record_stage'), mock.patch.object(harness, 'reboot_observation', return_value={'docker': 'active'}):
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                harness.reboot_operation(args, evidence, vm, 'container-health', mock.Mock(side_effect=failure))
        self.assertIs(raised.exception, failure)
        record = evidence['reboot_operations'][0]
        self.assertEqual(record['operation'], 'container-health')
        self.assertEqual(record['vm'], 'cf-verification-1')
        self.assertEqual(record['classification'], 'subprocess-timeout')
        self.assertEqual(record['timeout_seconds'], 210)
        self.assertGreaterEqual(record['elapsed_seconds'], 0)
        self.assertNotIn('PRIVATE', json.dumps(evidence))
        self.assertEqual(evidence['result'], 'failed')

    def test_diagnostic_failure_cannot_replace_original_exception(self):
        evidence = {}
        original = ValueError('PRIVATE-JSON')
        with mock.patch.object(harness, 'record_stage'), mock.patch.object(harness, 'reboot_observation', side_effect=OSError('PRIVATE-PATH')):
            with self.assertRaises(ValueError) as raised:
                harness.reboot_operation(SimpleNamespace(), evidence, SimpleNamespace(name='cf-verification-1'), 'container-health', mock.Mock(side_effect=original))
        self.assertIs(raised.exception, original)
        self.assertEqual(evidence['reboot_failure_state'], {'available': False, 'classification': 'os-error'})
        self.assertNotIn('PRIVATE', json.dumps(evidence))

    def test_success_records_result_and_elapsed_without_failure_probe(self):
        evidence = {}
        with mock.patch.object(harness, 'record_stage'), mock.patch.object(harness, 'reboot_observation') as diagnostic:
            value = harness.reboot_operation(SimpleNamespace(), evidence, SimpleNamespace(name='cf-verification-2'), 'https-lan', lambda: {'passed': True})
        self.assertEqual(value, {'passed': True})
        self.assertEqual(evidence['reboot_operations'][0]['result'], 'passed')
        diagnostic.assert_not_called()

    def test_guest_failure_exit_code_is_retained_without_error_text(self):
        failure = harness.VerificationError('PRIVATE-DETAIL')
        failure.guest_exit_code = 255
        evidence = {}
        with mock.patch.object(harness, 'record_stage'), mock.patch.object(harness, 'reboot_observation', return_value={}):
            with self.assertRaises(harness.VerificationError):
                harness.reboot_operation(SimpleNamespace(), evidence, SimpleNamespace(name='cf-verification-1'), 'boot-id-change', mock.Mock(side_effect=failure))
        self.assertEqual(evidence['reboot_operations'][0]['exit_code'], 255)
        self.assertNotIn('PRIVATE', json.dumps(evidence))

    def test_observation_rejects_unknown_keys_and_raw_data(self):
        vm = mock.Mock()
        for raw in (b'{"password":"PRIVATE"}', b'PRIVATE', b'x' * 65537):
            vm.command_on_guest.return_value = subprocess.CompletedProcess([], 0, raw, b'PRIVATE-STDERR')
            with self.subTest(size=len(raw)), self.assertRaises(harness.VerificationError) as error:
                harness.reboot_observation(vm)
            self.assertNotIn('PRIVATE', str(error.exception))
        self.assertEqual(vm.command_on_guest.call_args.kwargs['timeout'], 45)

    def test_health_budget_and_existing_checks_are_unchanged(self):
        import inspect
        self.assertIn('timeout=210', inspect.getsource(harness.healthy))
        self.assertIn('seq 1 90', inspect.getsource(harness.healthy))
        source = inspect.getsource(harness.scenario)
        for operation in ('boot-id-change', 'container-health', 'https-lan', 'file-api'):
            self.assertIn(operation, source)
        self.assertIn('lan_boundary(client)', source)
        self.assertIn('api(client, "verify-restored", "api-host-restart.json")', source)


class TargetedRebootTests(unittest.TestCase):
    IMAGE = 'sha256:' + 'a' * 64

    def state(self):
        return {'available': True, 'docker': 'active', 'storage_mounted': True, 'storage_on_root_device': False,
                'storage_uuid': '12345678-1234-1234-1234-123456789abc', 'storage_identity_matches': True,
                'bootstrap_absent': True, 'container_count': 1, 'container_id': 'b' * 64, 'image_id': self.IMAGE,
                'running': True, 'status': 'running', 'health': 'healthy', 'exit_code': 0, 'restart_count': 0,
                'config_sha256': 'c' * 64, 'container_error': 'none'}

    def test_positive_observation_and_strict_sanitized_values(self):
        vm = mock.Mock()
        vm.command_on_guest.return_value = subprocess.CompletedProcess([], 0, json.dumps(self.state()).encode(), b'PRIVATE')
        self.assertEqual(harness.reboot_observation(vm), self.state())
        for key, value in (('docker', 'PRIVATE'), ('exit_code', 'PRIVATE'), ('config_sha256', 'PRIVATE'), ('running', 1)):
            invalid = self.state(); invalid[key] = value
            vm.command_on_guest.return_value.stdout = json.dumps(invalid).encode()
            with self.subTest(key=key), self.assertRaises(harness.VerificationError):
                harness.reboot_observation(vm)

    def test_mounted_wrong_device_identity_bootstrap_and_unhealthy_are_rejected(self):
        harness.verify_reboot_state(self.state(), self.IMAGE)
        for key, value in (('storage_mounted', False), ('storage_on_root_device', True), ('storage_identity_matches', False),
                           ('bootstrap_absent', False), ('health', 'unhealthy'), ('image_id', 'sha256:' + 'd' * 64),
                           ('storage_uuid', None), ('config_sha256', None), ('container_count', 2)):
            invalid = self.state(); invalid[key] = value
            with self.subTest(key=key), self.assertRaises(harness.VerificationError):
                harness.verify_reboot_state(invalid, self.IMAGE)

    def invoke(self, *, health_error=None, after=None):
        evidence = {'result': 'failed'}
        self.server = mock.Mock(name='server'); self.server.name = 'cf-verification-1'
        self.client = mock.Mock(name='client'); self.client.name = 'cf-verification-2'
        self.server.reboot.return_value = {'before': 'old-boot', 'after': 'new-boot'}
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(harness, 'record_stage'))
            observe = stack.enter_context(mock.patch.object(harness, 'reboot_observation', side_effect=[self.state(), after or self.state()]))
            stack.enter_context(mock.patch.object(harness, 'storage_evidence', return_value={}))
            stack.enter_context(mock.patch.object(harness, 'verify_storage_evidence'))
            evidence['stage'] = 'real-host-reboot-and-api/container-health'
            api = stack.enter_context(mock.patch.object(harness, 'api', return_value={'passed': True}))
            healthy = stack.enter_context(mock.patch.object(harness, 'healthy', side_effect=health_error))
            lan = stack.enter_context(mock.patch.object(harness, 'lan_boundary', return_value={'passed': True}))
            stack.enter_context(mock.patch.object(harness, 'sentinel_state', return_value={'stable': True}))
            try:
                harness.targeted_reboot(SimpleNamespace(), evidence, self.server, self.client, self.IMAGE,
                                        {self.server.name: {'stable': True}, self.client.name: {'stable': True}})
            finally:
                self.observed = evidence; self.api_calls = api.call_args_list; self.lan_count = lan.call_count
        return evidence

    def test_target_pass_is_separate_and_uses_only_reboot_api_phases(self):
        evidence = self.invoke()
        self.assertEqual(evidence['scope'], 'reboot-blocker-only')
        self.assertEqual(evidence['result'], 'passed')
        self.assertEqual([call.args[1] for call in self.api_calls], ['reboot-seed', 'reboot-verify'])
        self.assertEqual(evidence['boundaries']['UI_PDF_OnlyOffice_restore'], 'not executed by this scope')
        self.server.reboot.assert_called_once_with()
        self.assertEqual([r['operation'] for r in evidence['reboot_operations']], ['boot-id-change','container-health','https-lan','file-api'])

    def test_original_health_timeout_stops_api_and_preserves_failure(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.invoke(health_error=subprocess.TimeoutExpired(['ssh', 'PRIVATE'], 210))
        self.assertEqual(self.observed['result'], 'failed')
        self.assertEqual(self.observed['reboot_operations'][-1]['timeout_seconds'], 210)
        self.assertEqual(self.lan_count, 0)
        self.assertEqual(len(self.api_calls), 1)
        self.assertNotIn('PRIVATE', json.dumps(self.observed))

    def test_changed_config_or_mount_uuid_cannot_pass(self):
        for field, value in (('storage_uuid', '87654321-1234-1234-1234-123456789abc'), ('config_sha256', 'd' * 64)):
            state = self.state(); state[field] = value
            with self.subTest(field=field), self.assertRaises(harness.VerificationError):
                self.invoke(after=state)
            self.assertEqual(self.observed['result'], 'failed')
            self.assertEqual(self.lan_count, 0)

    def test_manual_scope_does_not_disable_ordinary_pr_ci(self):
        source = (MODULE_PATH.parents[2] / '.github/workflows/shared-host-delivery.yaml').read_text()
        self.assertEqual(source.count("if: github.event_name != 'workflow_dispatch' || inputs.scope == 'full'"), 3)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.scope || 'full'", source)
        self.assertIn('default: full', source)
        import inspect
        scenario = inspect.getsource(harness.scenario)
        self.assertLess(scenario.index('bootstrap-finish'), scenario.index('if args.scope == "reboot":'))
        self.assertLess(scenario.index('if args.scope == "reboot":'), scenario.index('audit-pending-process-interruption'))


class StorageControlScopeTests(unittest.TestCase):
    def exercise(self, mounted=False, budget='5s'):
        vm=mock.Mock();vm.reboot.side_effect=[{'before':'old','after':'five'},{'before':'five','after':'ninety'}]
        before={'mounted':True}
        failed={'boot_id':'five','mounted':mounted,'journal':{'events':[{'unit':'dev-test.device','JOB_RESULT':'timeout'}]},
                'pid1_events':[],'related_units':{'dev-test.device':{'JobRunningTimeoutUSec':budget}}}
        evidence={};args=SimpleNamespace(source_sha='a'*40,accelerator='tcg')
        with mock.patch.object(harness,'VM',return_value=vm), mock.patch.object(harness,'port',return_value=12345), \
             mock.patch.object(harness,'prerequisites') as prepare, mock.patch.object(harness,'record_stage'), \
             mock.patch.object(harness,'verify_storage_evidence'), \
             mock.patch.object(harness,'storage_evidence',side_effect=[before,failed,{}, {'boot_id':'ninety','mounted':True}]) as probe:
            try:harness.storage_control(args,Path('.'),evidence,Path('base'),Path('key'))
            finally:self.vm=vm;self.evidence=evidence;self.probe=probe;self.prepare=prepare

    def test_only_observed_five_second_device_failure_allows_one_variable_change(self):
        self.exercise()
        self.assertEqual(self.vm.reboot.call_count,2)
        self.assertEqual([c.args[3] for c in self.probe.call_args_list],['before','control-5s','control-90s-before','control-90s'])
        script=self.vm.command_on_guest.call_args_list[-1].args[0]
        self.assertIn("old.replace('x-systemd.device-timeout=5s','x-systemd.device-timeout=90s')",script)
        self.assertNotIn('mount /srv/storage',script);self.assertNotIn('docker start',script)
        self.prepare.assert_called_once_with(self.vm,'a'*40,storage_only=True)
        self.assertEqual(self.evidence['result'],'passed');self.vm.close.assert_called_once()

    def test_unreproduced_or_unverified_failure_stops_before_second_reboot(self):
        for mounted,budget in ((True,'5s'),(False,'unknown')):
            with self.subTest(mounted=mounted,budget=budget),self.assertRaises(harness.VerificationError):
                self.exercise(mounted,budget)
            self.assertEqual(self.vm.reboot.call_count,1);self.vm.close.assert_called_once()

    def test_normal_guest_uses_finite_budget_and_control_retains_original_failure_input(self):
        for storage_only,seconds in ((False,90),(True,5)):
            vm=mock.Mock();vm.name='cf-verification-1'
            harness.prerequisites(vm,'a'*40,storage_only=storage_only)
            script=vm.command_on_guest.call_args.args[0]
            self.assertIn(f'defaults,nofail,x-systemd.device-timeout={seconds}s 0 2',script)
            self.assertNotIn('systemctl edit docker',script)
            self.assertNotIn('chmod -R',script)

    def test_storage_scope_does_not_prepare_product_or_disable_pr_gates(self):
        vm=mock.Mock();harness.prerequisites(vm,'a'*40,storage_only=True)
        script=vm.command_on_guest.call_args.args[0]
        self.assertIn('serial',script.lower());self.assertIn('x-systemd.device-timeout=5s',script)
        self.assertNotIn('git clone',script);self.assertNotIn('manage.sh',script)
        source=(MODULE_PATH.parents[2]/'.github/workflows/shared-host-delivery.yaml').read_text()
        self.assertIn("if: github.event_name != 'workflow_dispatch' || inputs.scope != 'storage'",source)
        self.assertIn("if: github.event_name == 'workflow_dispatch' && inputs.scope == 'storage'",source)
        self.assertEqual(source.count("if: github.event_name != 'workflow_dispatch' || inputs.scope == 'full'"),3)


class RebootAPIAssertionTests(unittest.TestCase):
    def test_permission_or_byte_changes_are_rejected_by_existing_api_assertions(self):
        path = MODULE_PATH.with_name('shared-host-api.py')
        spec = importlib.util.spec_from_file_location('reboot_api_assertions', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        original = b'file contents'
        expected = {'size': len(original), 'sha256': hashlib.sha256(original).hexdigest()}
        for corrupt_permissions, corrupt_bytes in ((True, False), (False, True)):
            test = module.Acceptance.__new__(module.Acceptance)
            test.state = {'reboot_seed_completed': True, 'users': {role: {'username': role, 'password': 'private', 'permissions': module.permissions(create=role=='worker', modify=role=='worker')}
                          for role in ('worker', 'reader')}, 'files': {'original.txt': expected}}
            test.checks = []; test.admin = 'private'; test.login_admin = mock.Mock()
            test.login = lambda username, password, label: username
            def request(label, method, endpoint, **kwargs):
                granted = test.state['users'][kwargs['token']]['permissions'].copy()
                if corrupt_permissions: granted['modify'] = not granted['modify']
                return SimpleNamespace(json=lambda: {'permissions': granted})
            test.request = request; test.resource = mock.Mock()
            test.download = lambda *a, **k: SimpleNamespace(body=b'wrong' if corrupt_bytes else original)
            with self.subTest(permissions=corrupt_permissions), self.assertRaises(module.AcceptanceError):
                test.reboot_verify()
            self.assertTrue(any(not item['passed'] for item in test.checks))


if __name__ == "__main__":
    unittest.main()
