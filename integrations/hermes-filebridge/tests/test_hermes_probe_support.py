"""Synthetic source-integrity/isolation regressions, never Hermes acceptance."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cf_hermes_support_test", HERE / "hermes_probe_support.py")
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


class HermesProbeSupportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cf-hermes-pin-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.commit = "1" * 40
        self.archive = self.root / "source.zip"
        self.files = {"critical.py": b"VALUE = 1\n", "package/unlisted.py": b"VALUE = 7\n"}
        with zipfile.ZipFile(self.archive, "w") as bundle:
            for name, data in self.files.items():
                bundle.writestr("hermes-agent-" + self.commit + "/" + name, data)
        with zipfile.ZipFile(self.archive) as bundle:
            bundle.extractall(self.root)
        self.source = self.root / ("hermes-agent-" + self.commit)
        critical = self.files["critical.py"]
        pin = hashlib.sha1(b"blob " + str(len(critical)).encode() + b"\0" + critical).hexdigest()
        metadata = {"archive_required": True,
                    "archive_sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                    "blobs": {"critical.py": pin}}
        self.catalog = patch.dict(support.VERSIONS, {self.commit: metadata})
        self.catalog.start()
        self.addCleanup(self.catalog.stop)

    def verify(self, source=None):
        return support.verify_source(source or self.source, self.commit, self.archive)

    def test_complete_archive_matches_actual_tree(self):
        self.assertEqual(self.verify(), self.commit)

    def test_extra_importable_file_is_rejected_and_preserved(self):
        extra = self.source / "injected.py"
        extra.write_bytes(b"raise RuntimeError('must never import')\n")
        with self.assertRaisesRegex(ValueError, "extra entries"):
            self.verify()
        self.assertTrue(extra.exists())

    def test_missing_file_is_rejected(self):
        (self.source / "package/unlisted.py").unlink()
        with self.assertRaisesRegex(ValueError, "missing or extra"):
            self.verify()

    def test_tampered_file_outside_critical_pins_is_rejected(self):
        (self.source / "package/unlisted.py").write_bytes(b"VALUE = 9\n")
        with self.assertRaisesRegex(ValueError, "differs from archive"):
            self.verify()

    def make_directory_link(self, link, target):
        if os.name != "nt":
            link.symlink_to(target, target_is_directory=True)
            return
        powershell = Path(os.environ["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        env = support.isolated_environment(self.root, {"CF_COMPAT_LINK": str(link), "CF_COMPAT_TARGET": str(target)})
        result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path $env:CF_COMPAT_LINK -Target $env:CF_COMPAT_TARGET | Out-Null"],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_source_root_link_or_reparse_is_rejected(self):
        link = self.root / "linked-source"
        self.make_directory_link(link, self.source)
        with self.assertRaisesRegex(ValueError, "reparse"):
            self.verify(link)
        self.assertEqual((self.source / "critical.py").read_bytes(), self.files["critical.py"])

    def test_nested_link_or_reparse_is_rejected_before_following(self):
        outside = self.root / "separate-source"
        outside.mkdir()
        sentinel = outside / "unlisted.py"
        sentinel.write_bytes(self.files["package/unlisted.py"])
        (self.source / "package/unlisted.py").unlink()
        (self.source / "package").rmdir()
        self.make_directory_link(self.source / "package", outside)
        with self.assertRaisesRegex(ValueError, "reparse"):
            self.verify()
        self.assertEqual(sentinel.read_bytes(), self.files["package/unlisted.py"])

    def test_unknown_version_and_missing_required_archive_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            support.verify_source(self.source, "0" * 40, self.archive)
        with self.assertRaisesRegex(ValueError, "requires"):
            support.verify_source(self.source, self.commit)

    def test_changed_archive_is_rejected_before_tree_checks(self):
        with self.archive.open("ab") as stream:
            stream.write(b"unexpected appended bytes")
        with self.assertRaisesRegex(ValueError, "archive SHA-256"):
            self.verify()

    def test_environment_never_inherits_credentials_home_or_path(self):
        with patch.dict(os.environ, {"PATH": "untrusted-runtime-path", "HOME": "untrusted-home",
                                    "CF_FILEBRIDGE_HOST_SECRET": "synthetic-secret", "OPENAI_API_KEY": "synthetic-key"}):
            env = support.isolated_environment(self.root)
        self.assertNotIn("untrusted-runtime-path", env["PATH"])
        self.assertNotIn("CF_FILEBRIDGE_HOST_SECRET", env)
        self.assertNotIn("OPENAI_API_KEY", env)
        for key in ("HOME", "USERPROFILE", "HERMES_HOME", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "TMPDIR"):
            path = Path(env[key])
            self.assertTrue(path.is_dir())
            self.assertIn(self.root, path.parents)
        with self.assertRaisesRegex(ValueError, "cannot override"):
            support.isolated_environment(self.root, {"PATH": "injected"})

    def test_sandbox_has_its_own_context_boundary_without_changing_parent_git(self):
        original_git = self.root / ".git"
        original_git.mkdir()
        original_config = original_git / "config"
        original_config.write_bytes(b"synthetic parent checkout config")
        ancestor_context = self.root / "AGENTS.md"
        ancestor_context.write_bytes(b"must remain outside child context")
        sandbox = self.root / "child-sandbox"
        sandbox.mkdir()
        support.isolated_environment(sandbox)
        self.assertTrue((sandbox / ".git").is_dir())
        self.assertEqual(list((sandbox / ".git").iterdir()), [])
        self.assertEqual(original_config.read_bytes(), b"synthetic parent checkout config")
        self.assertEqual(ancestor_context.read_bytes(), b"must remain outside child context")

    def test_existing_nonempty_git_boundary_is_rejected_without_changes(self):
        original_git = self.root / ".git"
        original_git.mkdir()
        sentinel = original_git / "config"
        sentinel.write_bytes(b"preserve existing metadata")
        with self.assertRaisesRegex(RuntimeError, "empty discovery boundary"):
            support.isolated_environment(self.root)
        self.assertEqual(sentinel.read_bytes(), b"preserve existing metadata")
        self.assertFalse((self.root / "profile").exists())

    def test_sqlite_plain_and_readonly_uri_are_limited_to_owned_sandbox(self):
        sandbox = self.root / "sqlite-sandbox"
        sandbox.mkdir()
        database = sandbox / "state.db"
        database.write_bytes(b"owned synthetic database")
        self.assertTrue(support.sqlite_access_allowed(":memory:", sandbox))
        self.assertTrue(support.sqlite_access_allowed(database, sandbox))
        self.assertTrue(support.sqlite_access_allowed(sandbox / "new.db", sandbox))
        self.assertTrue(support.sqlite_access_allowed(database.as_uri() + "?mode=ro", sandbox))
        self.assertTrue(support.sqlite_access_allowed("file:" + str(database) + "?mode=ro", sandbox))
        outside = self.root / "outside.db"
        outside.write_bytes(b"unrelated synthetic database")
        denied = [outside, outside.as_uri() + "?mode=ro", "state.db",
                  database.as_uri() + "?mode=rw", database.as_uri() + "?mode=ro&cache=shared",
                  database.as_uri() + "?immutable=1", database.as_uri() + "?mode=ro#fragment",
                  database.as_uri().replace("file:///", "file://localhost/") + "?mode=ro",
                  (sandbox / "missing.db").as_uri() + "?mode=ro",
                  sandbox.as_uri() + "/%2e%2e/outside.db?mode=ro",
                  "file::memory:?cache=shared", str(sandbox) + os.sep + ".." + os.sep + "outside.db"]
        denied.extend(["file:state.db?mode=ro", "file:" + str(outside) + "?mode=ro"])
        for path in denied:
            with self.subTest(path=str(path)):
                self.assertFalse(support.sqlite_access_allowed(path, sandbox))

    def test_sqlite_uri_rejects_symlink_or_reparse_before_open(self):
        sandbox, target = self.root / "sqlite-sandbox", self.root / "separate-db"
        sandbox.mkdir()
        target.mkdir()
        (target / "state.db").write_bytes(b"separate database")
        link = sandbox / "linked"
        self.make_directory_link(link, target)
        self.assertFalse(support.sqlite_access_allowed(link / "state.db", sandbox))
        self.assertFalse(support.sqlite_access_allowed((link / "state.db").as_uri() + "?mode=ro", sandbox))


if __name__ == "__main__":
    unittest.main()
