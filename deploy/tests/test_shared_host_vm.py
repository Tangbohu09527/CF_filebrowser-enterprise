#!/usr/bin/env python3
"""QEMU launch and diagnostic regressions; no VM is booted by these tests."""
from __future__ import annotations

import importlib.util
import copy
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import tempfile
import unittest
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
                                    'stage': 'delete' if case == 'crud' else case}).encode() + b'\n'
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
        for case, stages in {'crud': ('login', 'listing', 'upload', 'edit', 'save', 'rename', 'download', 'delete'),
                             'png': ('login', 'listing', 'png'), 'jpg': ('login', 'listing', 'jpg'),
                             'xlsx': ('login', 'listing', 'xlsx'), 'logout': ('login', 'listing', 'logout')}.items():
            for stage in stages:
                with self.subTest(case=case, stage=stage):
                    record = {'case': case, 'status': 'failed', 'retry': 0, 'stage': stage}
                    report = harness.ui_case_evidence(json.dumps(record).encode())
                    self.assertFalse(report['passed'])
                    self.assertEqual(report['attempts'], [record])

    def test_case_summary_rejects_invalid_and_cross_case_operations(self):
        for case, stage in (('crud', 'png'), ('png', 'edit'), ('xlsx', 'logout'), ('logout', 'xlsx'),
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


if __name__ == "__main__":
    unittest.main()
