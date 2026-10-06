"""Control transport failure injection; this is not Gateway/host acceptance.

Socket/DNS stages are simulated to exercise otherwise nondeterministic races.
Actual HTTPS, certificates and protocol integration have separate coverage.
"""
import hashlib
import http.client
import importlib.util
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


PLUGIN = Path(__file__).resolve().parents[1] / "plugin" / "__init__.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
spec = importlib.util.spec_from_file_location("cf_control_bounds_test", PLUGIN)
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
from cf_control_bounds_test import inbound, inbound_control


def config(ca=None):
    return SimpleNamespace(gateway_origin="https://gateway.example.invalid",
        service_token="synthetic-control-test-value-never-a-credential",
        ca_file=str(ca) if ca is not None else None,
        ca_sha256=hashlib.sha256(ca.read_bytes()).hexdigest() if ca is not None else None)


class Socket:
    def __init__(self):
        self.sent = []
        self.closed = False
    def shutdown(self, _how):
        self.closed = True
    def close(self):
        self.closed = True
    def sendall(self, data):
        self.sent.append(data)


class ControlBoundsTests(unittest.TestCase):
    def test_three_second_dns_bound_never_sends_late_authorization(self):
        class SlowDNSConnection:
            def __init__(self):
                self.sock = None
                self.started = threading.Event()
                self.release = threading.Event()
                self.late_closed = threading.Event()
                self.request_calls = 0
                self.close_calls = 0
            def connect(self):
                self.started.set()
                self.release.wait(8)  # Emulates a getaddrinfo ignoring socket timeout.
                self.sock = Socket()
            def request(self, *_args, **_kwargs):
                self.request_calls += 1
                raise AssertionError("Authorization must not be sent after DNS timeout")
            def close(self):
                self.close_calls += 1
                if self.sock is not None:
                    self.sock.close()
                    self.late_closed.set()
        connection = SlowDNSConnection()
        self.addCleanup(connection.release.set)
        client = inbound_control.ControlClient(config())
        with patch.object(inbound_control.http.client, "HTTPSConnection", return_value=connection):
            before = time.monotonic()
            with self.assertRaises(inbound.BridgeError) as raised:
                client._open("POST", "/internal/hermes/inbound-bindings/resolve", {"synthetic": True})
            elapsed = time.monotonic() - before
        self.assertTrue(connection.started.is_set())
        self.assertGreaterEqual(elapsed, 2.8)
        self.assertLess(elapsed, 4.5)
        self.assertEqual(str(raised.exception), "host_control_unavailable")
        self.assertEqual(connection.request_calls, 0)
        connection.release.set()
        self.assertTrue(connection.late_closed.wait(2))
        self.assertEqual(connection.request_calls, 0)
        self.assertTrue(connection.sock.closed)

    def test_abort_before_send_cannot_reopen_https_connection(self):
        # Exercise the real http.client request/send machinery. Pausing at its
        # request entry reproduces cancellation after the caller's deadline check
        # but before HTTPConnection.send sees the socket. Its default auto_open
        # would otherwise reconnect and send the service Authorization late.
        class PausedConnection(http.client.HTTPSConnection):
            def __init__(self):
                super().__init__("gateway.example.invalid", timeout=1)
                self.release = threading.Event()
                self.finished = threading.Event()
                self.connect_calls = 0
                self.sockets = []
            def connect(self):
                self.connect_calls += 1
                self.sock = Socket()
                self.sockets.append(self.sock)
            def request(self, *args, **kwargs):
                self.release.wait(3)
                try:
                    return super().request(*args, **kwargs)
                finally:
                    self.finished.set()
        connection = PausedConnection()
        self.addCleanup(connection.release.set)
        client = inbound_control.ControlClient(config())
        with patch.object(inbound_control.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaises(inbound.BridgeError):
                client._open("POST", "/internal/hermes/inbound-bindings/resolve", {}, timeout=0.15)
        connection.release.set()
        self.assertTrue(connection.finished.wait(2))
        self.assertEqual(connection.connect_calls, 1, "cancelled request reconnected")
        self.assertEqual([data for sock in connection.sockets for data in sock.sent], [])

    def test_ca_replaced_after_initial_pin_check_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="cf-control-ca-race-") as temporary:
            ca = Path(temporary) / "ca.pem"
            original = (FIXTURES / "cert.pem").read_bytes()
            ca.write_bytes(original)
            settings = config(ca)
            checked = inbound_control._client
            def replace_after_check(raw, digest):
                path = checked(raw, digest)
                # A duplicate is still valid PEM/CA input to OpenSSL, but these
                # bytes have a different pin. Loading cafile would accept them.
                path.write_bytes(original + original)
                return path
            with patch.object(inbound_control, "_client", side_effect=replace_after_check):
                with self.assertRaises(inbound.BridgeError) as raised:
                    inbound_control.ControlClient(settings)
            self.assertEqual(str(raised.exception), "host_control_rejected")

    def test_tls_loads_verified_bytes_without_reopening_path(self):
        with tempfile.TemporaryDirectory(prefix="cf-control-ca-bytes-") as temporary:
            ca = Path(temporary) / "ca.pem"
            certificate = (FIXTURES / "cert.pem").read_bytes()
            ca.write_bytes(certificate)
            settings = config(ca)
            loads = []
            class Context:
                def load_verify_locations(self, *, cafile=None, cadata=None):
                    # Replace the path at the exact TLS-load boundary. The
                    # verified in-memory bundle must already be independent.
                    ca.write_bytes(certificate + certificate)
                    loads.append((cafile, cadata))
            context = Context()
            with patch.object(inbound_control.ssl, "SSLContext", return_value=context):
                client = inbound_control.ControlClient(settings)
            self.assertIs(client.tls, context)
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, inbound_control.ssl.CERT_REQUIRED)
            self.assertEqual(loads, [(None, certificate.decode("ascii"))])


if __name__ == "__main__":
    unittest.main()
