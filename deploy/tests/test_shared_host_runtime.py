#!/usr/bin/env python3
"""Entrypoint rejection contracts; these are not Docker or reboot evidence."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class SharedHostRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, content in {
            "config.yaml": "server: {}\n",
            "jwt": "j" * 64 + "\n",
            "totp": "t" * 64 + "\n",
            "expected": "a" * 64 + "\n",
            "actual": "a" * 64 + "\n",
            "database": "initialized-test-fixture",
        }.items():
            (self.root / name).write_text(content, encoding="utf-8", newline="\n")
        (self.root / "files").mkdir()

    def run_entrypoint(self, *args: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        fields = {
            "FILEBROWSER_CONFIG": "config.yaml",
            "FILEBROWSER_DATABASE": "database",
            "FILEBROWSER_JWT_TOKEN_SECRET_FILE": "jwt",
            "FILEBROWSER_TOTP_SECRET_FILE": "totp",
            "FILEBROWSER_BOOTSTRAP_PASSWORD_FILE": "bootstrap",
            "FILEBROWSER_STORAGE_EXPECTED_FILE": "expected",
            "FILEBROWSER_STORAGE_IDENTITY_FILE": "actual",
            "FILEBROWSER_STORAGE_FILES_ROOT": "files",
        }
        environment.update({key: (self.root / value).as_posix() for key, value in fields.items()})
        environment.update(overrides)
        return subprocess.run(
            [shutil.which("bash") or "bash", (ROOT / "scripts/container-entrypoint.sh").as_posix(), *args],
            env=environment, text=True, capture_output=True, check=False,
        )

    def assert_refuses(self, message: str, **overrides: str) -> None:
        result = self.run_entrypoint("not-an-operation", **overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertEqual((self.root / "database").read_text(), "initialized-test-fixture")

    def test_missing_storage_identity_fails_before_reading_secrets_or_database(self) -> None:
        (self.root / "actual").unlink()
        self.assert_refuses("storage identity", FILEBROWSER_JWT_TOKEN_SECRET_FILE="missing-jwt")

    def test_wrong_storage_identity_fails_closed(self) -> None:
        (self.root / "actual").write_text("b" * 64 + "\n", newline="\n")
        self.assert_refuses("storage identity does not match")

    def test_malformed_or_multiline_storage_identity_fails_closed(self) -> None:
        for value in ("", "bad-id\n", "a" * 64 + "\n\n", "a" * 64 + "\r\n"):
            with self.subTest(value_length=len(value)):
                (self.root / "actual").write_bytes(value.encode())
                self.assert_refuses("storage identity")

    def test_half_configured_storage_guard_fails_closed(self) -> None:
        self.assert_refuses("storage identity", FILEBROWSER_STORAGE_EXPECTED_FILE="")

    def test_matching_identity_passes_guard_without_launching_backend(self) -> None:
        self.assert_refuses("unsupported container command")

    def test_initialized_database_with_bootstrap_still_refuses_restart(self) -> None:
        (self.root / "bootstrap").write_text("b" * 64 + "\n", newline="\n")
        result = self.run_entrypoint()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("remove the bootstrap password file", result.stderr)

    def test_missing_files_directory_is_never_created(self) -> None:
        (self.root / "files").rmdir()
        self.assert_refuses("storage files directory")
        self.assertFalse((self.root / "files").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
