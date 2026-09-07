#!/usr/bin/env python3
"""Unit-level rejection/order tests; these do not claim real Docker acceptance."""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "shared-host" / "lifecycle.py"
SPEC = importlib.util.spec_from_file_location("shared_host_lifecycle", MODULE_PATH)
lifecycle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lifecycle)


class LifecycleTests(unittest.TestCase):
    def test_env_rejects_duplicate_and_shell_interpolation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            for value in ("A=one\nA=two\n", "A=$(touch-pwned)\n", "A=${HOME}\n"):
                path.write_text(value, encoding="utf-8")
                with self.assertRaises(lifecycle.DeploymentError):
                    lifecycle.read_env(path)

    def test_share_source_requires_explicit_input_and_never_grants_default_share_permission(self):
        for enabled in (False, True):
            config = {"server": {"sources": [{"config": {"private": True}}]}, "userDefaults": {"account": {"permissions": {"share": False}}}}
            lifecycle.configure_source(config, "base", [], enabled)
            self.assertIs(config["server"]["sources"][0]["config"]["private"], not enabled)
            self.assertIs(config["userDefaults"]["account"]["permissions"]["share"], False)

    def test_lan_source_configuration_preserves_an_explicit_listener_allowlist(self):
        config = {"server": {"sources": [{"config": {"private": True}}]}}
        lifecycle.configure_source(config, "lan", ["192.0.2.12/32"], False)
        self.assertEqual(config["server"]["allowedClientCIDRs"], ["127.0.0.1/32", "192.0.2.12/32"])

    def test_webdav_requires_explicit_input_and_preserves_user_permission_defaults(self):
        for enabled in (False, True):
            config = {"server": {"disableWebDAV": True, "sources": [{"config": {"private": True}}]}, "userDefaults": {"account": {"permissions": {"create": False, "modify": False, "share": False}}}}
            lifecycle.configure_source(config, "base", [], False, enable_webdav=enabled)
            self.assertIs(config["server"]["disableWebDAV"], not enabled)
            self.assertIs(config["server"]["sources"][0]["config"]["private"], True)
            self.assertEqual(config["userDefaults"]["account"]["permissions"], {"create": False, "modify": False, "share": False})

    def test_secret_rejects_multiline_cr_and_short_values(self):
        for value in (b"short", b"a" * 32 + b"\nextra", b"a" * 32 + b"\r\n"):
            with self.assertRaises(lifecycle.DeploymentError):
                lifecycle.secret_bytes(value, 24)
        self.assertEqual(lifecycle.secret_bytes(b"a" * 32 + b"\n", 24), b"a" * 32)

    def test_candidate_requires_nonzero_registry_digest(self):
        for value in ("project:latest", "project@sha256:" + "0" * 64):
            with self.assertRaises(lifecycle.DeploymentError):
                lifecycle.validate_image_reference(value, "candidate")
        lifecycle.validate_image_reference("registry.example/project@sha256:" + "a" * 64, "candidate")

    def test_partial_prepare_does_not_fill_missing_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = lifecycle.Paths(Path(directory))
            paths.config.mkdir(parents=True)
            secret = paths.config / "secrets" / "jwt_token_secret"
            secret.parent.mkdir()
            secret.write_bytes(b"existing-secret")
            with self.assertRaisesRegex(lifecycle.DeploymentError, "partial|existing"):
                lifecycle.assert_empty_install(paths)
            self.assertEqual(secret.read_bytes(), b"existing-secret")
            self.assertFalse((paths.config / "secrets" / "totp_secret").exists())

    def test_compose_is_fixed_project_and_never_implicit_pull_or_build(self):
        paths = lifecycle.Paths()
        command = lifecycle.compose_command(paths, "debug")
        self.assertIn("cf-filebrowser", command)
        self.assertNotIn("compose.build.yaml", " ".join(command))
        self.assertIn("compose.debug.yaml", " ".join(command))
        self.assertEqual(Path(command[command.index("--env-file") + 1]).as_posix(), "/etc/cf-filebrowser-enterprise/.env")

    def test_host_environment_cannot_override_compose_or_docker_target(self):
        with mock.patch.dict("os.environ", {"FILEBROWSER_IMAGE": "poison", "DOCKER_HOST": "tcp://forbidden:2375", "COMPOSE_FILE": "poison"}):
            environment = lifecycle.command_environment()
        self.assertNotIn("FILEBROWSER_IMAGE", environment)
        self.assertEqual(environment["DOCKER_HOST"], "unix:///var/run/docker.sock")
        self.assertNotIn("COMPOSE_FILE", environment)

    def test_login_never_places_password_or_session_in_argv(self):
        calls = []
        def fake_run(command, input_bytes=None):
            calls.append((command, input_bytes))
            if len(calls) == 1:
                return b"secret-session-token"
            return json.dumps({"username": "admin", "permissions": {"admin": True}}).encode()
        with mock.patch.object(lifecycle, "run", side_effect=fake_run):
            lifecycle.verify_admin("abc123", b"never-in-arguments-password", "admin", {"exposure": "debug"})
        self.assertEqual(len(calls), 2)
        self.assertNotIn("never-in-arguments-password", repr([item[0] for item in calls]))
        self.assertNotIn("secret-session-token", repr([item[0] for item in calls]))
        self.assertIn(b"X-Password", calls[0][1])
        self.assertIn(b"Cookie", calls[1][1])

    def test_login_requires_actual_admin_profile(self):
        responses = [b"session", b'{"username":"reader","permissions":{"admin":false}}']
        with mock.patch.object(lifecycle, "run", side_effect=responses):
            with self.assertRaises(lifecycle.DeploymentError):
                lifecycle.verify_admin("abc123", b"password", "admin", {"exposure": "debug"})

    def test_first_login_failure_preserves_bootstrap_and_running_state(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = lifecycle.Paths(Path(directory))
            paths.bootstrap.parent.mkdir(parents=True)
            paths.bootstrap.write_bytes(b"a" * 32)
            paths.data.mkdir(parents=True)
            (paths.data / "database.db").write_bytes(b"initialized")
            deployment = {"image_id": "sha256:" + "a" * 64, "exposure": "debug", "bootstrap_complete": False}
            with mock.patch.object(lifecycle, "protected_secret", return_value=b"a" * 32), \
                 mock.patch.object(lifecycle, "container_identity", return_value=("abc123", deployment["image_id"])), \
                 mock.patch.object(lifecycle, "verify_admin", side_effect=lifecycle.DeploymentError("login failed")), \
                 mock.patch.object(lifecycle, "run") as command:
                with self.assertRaises(lifecycle.DeploymentError):
                    lifecycle.finish_bootstrap(paths, deployment, "admin")
                command.assert_not_called()
            self.assertTrue(paths.bootstrap.exists())

    def test_stop_failure_never_removes_bootstrap(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = lifecycle.Paths(Path(directory))
            paths.bootstrap.parent.mkdir(parents=True)
            paths.bootstrap.write_bytes(b"a" * 32)
            paths.data.mkdir(parents=True)
            (paths.data / "database.db").write_bytes(b"initialized")
            deployment = {"image_id": "sha256:" + "a" * 64, "exposure": "debug", "bootstrap_complete": False}
            with mock.patch.object(lifecycle, "protected_secret", return_value=b"a" * 32), \
                 mock.patch.object(lifecycle, "container_identity", return_value=("abc123", deployment["image_id"])), \
                 mock.patch.object(lifecycle, "verify_admin"), \
                 mock.patch.object(lifecycle, "run", side_effect=lifecycle.DeploymentError("stop failed")):
                with self.assertRaises(lifecycle.DeploymentError):
                    lifecycle.finish_bootstrap(paths, deployment, "admin")
            self.assertTrue(paths.bootstrap.exists())
            self.assertFalse(deployment["bootstrap_complete"])

    def test_post_restart_login_failure_does_not_recreate_bootstrap_or_claim_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = lifecycle.Paths(Path(directory))
            paths.bootstrap.parent.mkdir(parents=True)
            paths.bootstrap.write_bytes(b"a" * 32)
            paths.data.mkdir(parents=True)
            (paths.data / "database.db").write_bytes(b"initialized")
            deployment = {"image_id": "sha256:" + "a" * 64, "exposure": "debug", "bootstrap_complete": False}
            with mock.patch.object(lifecycle, "protected_secret", return_value=b"a" * 32), \
                 mock.patch.object(lifecycle, "container_identity", return_value=("abc123", deployment["image_id"])), \
                 mock.patch.object(lifecycle, "verify_admin", side_effect=[None, lifecycle.DeploymentError("restart login failed")]), \
                 mock.patch.object(lifecycle, "run"), \
                 mock.patch.object(lifecycle, "assert_stopped"), \
                 mock.patch.object(lifecycle, "start_service"), \
                 mock.patch.object(lifecycle, "save_metadata") as save:
                with self.assertRaises(lifecycle.DeploymentError):
                    lifecycle.finish_bootstrap(paths, deployment, "admin")
                save.assert_not_called()
            self.assertFalse(paths.bootstrap.exists())
            self.assertFalse(deployment["bootstrap_complete"])
            self.assertEqual((paths.data / "database.db").read_bytes(), b"initialized")

    def test_bootstrap_finishes_only_after_stop_same_image_restart_and_login(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = lifecycle.Paths(Path(directory))
            paths.bootstrap.parent.mkdir(parents=True)
            paths.bootstrap.write_bytes(b"a" * 32)
            paths.data.mkdir(parents=True)
            (paths.data / "database.db").write_bytes(b"initialized")
            deployment = {"image_id": "sha256:" + "a" * 64, "exposure": "debug", "bootstrap_complete": False}
            events = []
            def login(*args):
                events.append("login-present" if paths.bootstrap.exists() else "login-absent")
            with mock.patch.object(lifecycle, "protected_secret", return_value=b"a" * 32), \
                 mock.patch.object(lifecycle, "container_identity", return_value=("abc123", deployment["image_id"])), \
                 mock.patch.object(lifecycle, "verify_admin", side_effect=login), \
                 mock.patch.object(lifecycle, "run", side_effect=lambda *args, **kwargs: events.append("stop")), \
                 mock.patch.object(lifecycle, "assert_stopped", side_effect=lambda *args: events.append("stopped")), \
                 mock.patch.object(lifecycle, "start_service", side_effect=lambda *args: events.append("start")), \
                 mock.patch.object(lifecycle, "save_metadata", side_effect=lambda *args: events.append("save")):
                lifecycle.finish_bootstrap(paths, deployment, "admin")
            self.assertEqual(events, ["login-present", "stop", "stopped", "start", "login-absent", "save"])
            self.assertFalse(paths.bootstrap.exists())
            self.assertTrue(deployment["bootstrap_complete"])



class TLSInputOpenSSLTests(unittest.TestCase):
    """Real crypto checks with synthetic files; POSIX ownership stays in VM tests."""

    @classmethod
    def setUpClass(cls):
        cls.openssl = shutil.which("openssl")
        if not cls.openssl:
            raise RuntimeError("OpenSSL is required for the TLS input regression")
        cls.temporary = tempfile.TemporaryDirectory(prefix="cf-lifecycle-tls-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.ca, cls.ca_key = cls.root / "ca.crt", cls.root / "ca.key"
        cls.cert, cls.key = cls.root / "server.crt", cls.root / "server.key"
        cls.csr = cls.root / "server.csr"
        cls.empty = cls.root / "empty-password"
        cls.empty.write_bytes(b"")
        cls.openssl_run(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
                         "-subj", "/CN=Isolated lifecycle regression CA", "-keyout", str(cls.ca_key), "-out", str(cls.ca)])
        cls.openssl_run(["req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=files.cf.test",
                         "-keyout", str(cls.key), "-out", str(cls.csr)])
        extension = cls.root / "server.extensions"
        extension.write_text("subjectAltName=DNS:files.cf.test,IP:192.0.2.11\nextendedKeyUsage=serverAuth\n", encoding="ascii")
        cls.signing = ["x509", "-req", "-in", str(cls.csr), "-CA", str(cls.ca), "-CAkey",
                       str(cls.ca_key), "-CAcreateserial", "-extfile", str(extension)]
        cls.openssl_run([*cls.signing, "-days", "3", "-out", str(cls.cert)])
        cls.short_cert = cls.root / "short-lived.crt"
        cls.openssl_run([*cls.signing, "-days", "1", "-out", str(cls.short_cert)])
        cls.other_ca = cls.root / "untrusted.crt"
        cls.openssl_run(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
                         "-subj", "/CN=Untrusted lifecycle regression CA",
                         "-keyout", str(cls.root / "untrusted.key"), "-out", str(cls.other_ca)])
        cls.encrypted_key = cls.root / "encrypted.key"
        cls.openssl_run(["pkey", "-in", str(cls.key), "-aes-256-cbc", "-passout", "stdin",
                         "-out", str(cls.encrypted_key)], b"synthetic-fixture-passphrase\n")

    @classmethod
    def openssl_run(cls, arguments, input_bytes=None):
        result = subprocess.run([cls.openssl, *arguments], input=input_bytes,
                                capture_output=True, timeout=30, check=False)
        if result.returncode:
            # Never expose process output, private key data or synthetic passwords.
            raise lifecycle.DeploymentError("openssl " + arguments[0] + " failed")
        return result.stdout

    def inputs(self, **changes):
        values = dict(lan_bind_address="192.0.2.11", lan_port=18443,
                      lan_allowed_cidrs="192.0.2.12/32", tls_name="files.cf.test",
                      tls_cert_file=self.cert, tls_key_file=self.key, tls_ca_file=self.ca)
        values.update(changes)
        return SimpleNamespace(**values)

    def check_inputs(self, **changes):
        def actual_command(command, input_bytes=None):
            self.assertEqual(command[0], "openssl")
            # /dev/null is an existing empty stream on Linux. Map that exact
            # pre-fix input to an existing empty file for the Windows regression.
            arguments = ["file:" + str(self.empty) if value == "file:/dev/null" else value
                         for value in command[1:]]
            return self.openssl_run(arguments, input_bytes)
        with mock.patch.object(lifecycle, "run", side_effect=actual_command), \
             mock.patch.object(lifecycle, "assert_safe_path"), \
             mock.patch.object(lifecycle.stat, "S_IMODE", return_value=0o600):
            return lifecycle.tls_inputs(self.inputs(**changes))

    def test_valid_unencrypted_private_key_and_matching_dns_are_accepted(self):
        result = self.check_inputs()
        self.assertTrue(result["server.crt"] == self.cert.read_bytes(), "accepted certificate bytes changed")
        self.assertTrue(result["server.key"] == self.key.read_bytes(), "accepted private key bytes changed")
        self.assertTrue(result["ca.crt"] == self.ca.read_bytes(), "accepted CA bytes changed")

    def test_wrong_dns_is_rejected_by_chain_and_name_verification(self):
        with self.assertRaisesRegex(lifecycle.DeploymentError, "openssl verify failed"):
            self.check_inputs(tls_name="wrong.cf.test")

    def test_ip_subject_alternative_name_is_checked(self):
        self.check_inputs(tls_name="192.0.2.11")
        with self.assertRaisesRegex(lifecycle.DeploymentError, "openssl verify failed"):
            self.check_inputs(tls_name="192.0.2.99")

    def test_untrusted_ca_is_rejected(self):
        with self.assertRaisesRegex(lifecycle.DeploymentError, "openssl verify failed"):
            self.check_inputs(tls_ca_file=self.other_ca)

    def test_certificate_with_less_than_one_day_remaining_is_rejected(self):
        with self.assertRaisesRegex(lifecycle.DeploymentError, "openssl x509 failed"):
            self.check_inputs(tls_cert_file=self.short_cert)

    def test_encrypted_private_key_is_rejected_without_prompting(self):
        with self.assertRaisesRegex(lifecycle.DeploymentError, "openssl pkey failed"):
            self.check_inputs(tls_key_file=self.encrypted_key)

    def test_mismatched_private_key_is_rejected(self):
        with self.assertRaisesRegex(lifecycle.DeploymentError, "do not match"):
            self.check_inputs(tls_key_file=self.ca_key)


if __name__ == "__main__":
    unittest.main()
