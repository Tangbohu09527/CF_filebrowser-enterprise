#!/usr/bin/env python3
"""Unit-level rejection/order tests; these do not claim real Docker acceptance."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
