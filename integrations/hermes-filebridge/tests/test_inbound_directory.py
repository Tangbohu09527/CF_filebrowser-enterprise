"""Real filesystem checks for private task-directory creation; no live roots."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_hermes_middleware import private_directory


PLUGIN = Path(__file__).resolve().parents[1] / "plugin"
spec = importlib.util.spec_from_file_location("cf_inbound_directory_test", PLUGIN / "__init__.py")
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
directory = __import__(spec.name + ".inbound_directory", fromlist=["create_task_directory"])


class TaskDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cf-inbound-directory-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.ancestor = self.root / "ancestor"
        self.ancestor.mkdir()
        self.work = self.ancestor / "work"
        private_directory(self.work)
        self.sentinel = self.work / "unknown-sentinel.txt"
        self.sentinel.write_bytes(b"unrelated existing file")

    def powershell(self, script, **variables):
        executable = Path(os.environ["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-Command", script],
                                env={**os.environ, **variables}, text=True,
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def acl(self, path):
        return json.loads(self.powershell(r"""
$acl=[IO.Directory]::GetAccessControl($env:CF_DIRECTORY_PATH)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
 @{sid=$_.IdentityReference.Value; inherited=$_.IsInherited; kind=$_.AccessControlType.ToString(); rights=[int]$_.FileSystemRights}
})
@{owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value; current=$sid;
 protected=$acl.AreAccessRulesProtected; rules=$rules; sddl=$acl.Sddl} | ConvertTo-Json -Depth 4 -Compress
""", CF_DIRECTORY_PATH=str(path)))

    def assert_rejected(self, path):
        with self.assertRaises(directory.BridgeError) as failure:
            directory.create_task_directory(path)
        self.assertEqual(str(failure.exception), "task_directory_unavailable")
        self.assertNotIn(str(self.root), str(failure.exception))
        self.assertEqual(self.sentinel.read_bytes(), b"unrelated existing file")

    def test_unique_private_children_and_unchanged_root(self):
        before = self.acl(self.work) if os.name == "nt" else self.work.stat().st_mode
        paths = [Path(directory.create_task_directory(str(self.work))) for _ in range(2)]
        self.assertNotEqual(paths[0], paths[1])
        for path in paths:
            self.assertEqual(path.parent, self.work)
            self.assertRegex(path.name, r"^task-[a-f0-9]{32}$")
            self.assertEqual(list(path.iterdir()), [])
            if os.name == "nt":
                acl = self.acl(path)
                self.assertEqual(acl["owner"], acl["current"])
                self.assertTrue(acl["protected"])
                self.assertEqual({rule["sid"] for rule in acl["rules"]},
                                 {acl["current"], "S-1-5-18", "S-1-5-32-544"})
                self.assertTrue(all(not rule["inherited"] and rule["kind"] == "Allow"
                                    and rule["rights"] == 0x1F01FF for rule in acl["rules"]))
            else:
                self.assertEqual(path.stat().st_mode & 0o7777, 0o700)
                self.assertEqual(path.stat().st_uid, os.geteuid())
        after = self.acl(self.work) if os.name == "nt" else self.work.stat().st_mode
        self.assertEqual(before, after)
        self.assertEqual(self.sentinel.read_bytes(), b"unrelated existing file")

    def test_invalid_roots_fail_without_creating_anything(self):
        paths = [None, 3, "", "relative", ".", str(self.work) + os.sep,
                 str(self.work) + os.sep + "..", str(self.work) + "\0"]
        if os.name == "nt":
            paths += [self.work.drive + "\\", r"\\localhost\share", r"\\?\C:\task",
                      str(self.work) + ":stream", str(self.work / "NUL"), str(self.work / "tail.")]
        else:
            paths += ["/", "//tmp", str(self.work) + "/../work"]
        for path in paths:
            with self.subTest(path=repr(path)):
                self.assert_rejected(path)
        self.assertEqual(list(self.work.iterdir()), [self.sentinel])

    def test_missing_or_file_root_is_not_repaired(self):
        missing = self.work / "missing"
        self.assert_rejected(str(missing))
        self.assertFalse(missing.exists())
        self.assert_rejected(str(self.sentinel))

    def test_collision_keeps_existing_directory_and_files(self):
        collision = self.work / ("task-" + "a" * 32)
        collision.mkdir()
        unknown = collision / "keep.bin"
        unknown.write_bytes(b"never overwrite or remove")
        with patch.object(directory.secrets, "token_hex", return_value="a" * 32):
            self.assert_rejected(str(self.work))
        self.assertEqual(unknown.read_bytes(), b"never overwrite or remove")
        self.assertEqual(set(self.work.iterdir()), {self.sentinel, collision})

    def test_insecure_root_permissions_are_rejected_and_not_changed(self):
        if os.name == "nt":
            self.powershell(r"""
$acl=[IO.Directory]::GetAccessControl($env:CF_DIRECTORY_PATH)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
 [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'ReadAndExecute',
 'ContainerInherit,ObjectInherit','None','Allow'))
[IO.Directory]::SetAccessControl($env:CF_DIRECTORY_PATH,$acl)
""", CF_DIRECTORY_PATH=str(self.work))
            before = self.acl(self.work)
        else:
            os.chmod(self.work, 0o755)  # Only this fresh test fixture is modified.
            before = self.work.stat().st_mode
        self.assert_rejected(str(self.work))
        after = self.acl(self.work) if os.name == "nt" else self.work.stat().st_mode
        self.assertEqual(before, after)
        self.assertEqual(list(self.work.iterdir()), [self.sentinel])

    def test_link_root_and_link_ancestor_are_rejected(self):
        link = self.root / "link"
        if os.name == "nt":
            self.powershell("New-Item -ItemType Junction -Path $env:CF_DIRECTORY_LINK -Target $env:CF_DIRECTORY_TARGET | Out-Null",
                            CF_DIRECTORY_LINK=str(link), CF_DIRECTORY_TARGET=str(self.ancestor))
            self.addCleanup(lambda: os.rmdir(link) if link.exists() else None)
        else:
            link.symlink_to(self.ancestor, target_is_directory=True)
        self.assert_rejected(str(link))
        self.assert_rejected(str(link / "work"))
        self.assertEqual(list(self.work.iterdir()), [self.sentinel])

    @unittest.skipUnless(os.name == "nt", "Windows protected DACL rule")
    def test_unprotected_root_acl_is_rejected_without_repair(self):
        self.powershell(r"""
$acl=[IO.Directory]::GetAccessControl($env:CF_DIRECTORY_PATH)
$acl.SetAccessRuleProtection($false,$true)
[IO.Directory]::SetAccessControl($env:CF_DIRECTORY_PATH,$acl)
""", CF_DIRECTORY_PATH=str(self.work))
        before = self.acl(self.work)
        self.assertFalse(before["protected"])
        self.assert_rejected(str(self.work))
        self.assertEqual(self.acl(self.work), before)

    @unittest.skipUnless(os.name == "nt", "Windows native share-access lock")
    def test_real_ancestor_rename_is_blocked_only_while_locked(self):
        moved = self.root / "moved-ancestor"
        os.rename(self.ancestor, moved)
        os.rename(moved, self.ancestor)
        with directory._windows_root(str(self.work)):
            blocked = False
            try:
                os.rename(self.ancestor, moved)
            except OSError:
                blocked = True
            finally:
                if moved.exists():
                    os.rename(moved, self.ancestor)
            self.assertTrue(blocked, "metadata-only handle failed to block ancestor rename")
        os.rename(self.ancestor, moved)
        os.rename(moved, self.ancestor)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux anchored directory operations")
    def test_linux_root_swap_is_detected_and_never_follows_replacement(self):
        original_mkdir = os.mkdir
        moved = self.ancestor / "moved-authorized-root"
        replacement = self.ancestor / "replacement"
        replacement.mkdir(mode=0o700)
        sentinel = replacement / "keep"
        sentinel.write_bytes(b"replacement must not be touched")

        def swap_before_mkdir(name, mode=0o777, *, dir_fd=None):
            os.rename(self.work, moved)
            self.work.symlink_to(replacement, target_is_directory=True)
            return original_mkdir(name, mode, dir_fd=dir_fd)

        try:
            with patch.object(directory.os, "mkdir", side_effect=swap_before_mkdir):
                with self.assertRaises(directory.BridgeError):
                    directory.create_task_directory(str(self.work))
            self.assertEqual(list(replacement.iterdir()), [sentinel])
            self.assertEqual(sentinel.read_bytes(), b"replacement must not be touched")
            # Failed verification preserves the new private directory on the
            # selected inode instead of deleting through an attacker-held path.
            created = [path for path in moved.iterdir() if re.fullmatch(r"task-[a-f0-9]{32}", path.name)]
            self.assertEqual(len(created), 1)
            self.assertEqual(created[0].stat().st_mode & 0o7777, 0o700)
        finally:
            self.work.unlink()
            os.rename(moved, self.work)


if __name__ == "__main__":
    unittest.main()
