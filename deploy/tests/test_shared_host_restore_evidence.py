#!/usr/bin/env python3
"""Read real temporary recovery evidence; no VM is booted by these tests."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts/tests/shared_host_restore_evidence.py"
SPEC = importlib.util.spec_from_file_location("shared_host_restore_evidence_tests", MODULE_PATH)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class RestoreEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.config = root / "storage.identity"
        self.disk = root / ".storage-identity"
        self.backups = root / "backups"
        self.backups.mkdir()
        self.path = self.backups / "verification.tar.restore-1234567890abcdef.json"
        self.old = "a" * 64
        self.new = "b" * 64
        self.version = {"source_sha": "c" * 40, "image_ref": "localhost:5001/cf-filebrowser@sha256:" + "d" * 64,
                        "image_id": "sha256:" + "e" * 64, "uid": 10001, "gid": 10001, "initialized": True}
        self.record = {"format": 1, "archive_sha256": "f" * 64, "version": self.version.copy(),
                       "previous_storage_identity": self.old, "restored_storage_identity": self.new}
        self.expected = {"archive_sha256": self.record["archive_sha256"], "version": self.version,
                         "previous_storage_identity_sha256": self.digest(self.old)}
        self.config.write_bytes((self.new + "\n").encode("ascii"))
        self.disk.write_bytes(self.config.read_bytes())
        self.write_record()
        # Windows cannot represent the guest's Linux UID/GID. Only metadata
        # validation is isolated; marker/evidence bytes are read from real files.
        self.metadata = mock.patch.object(probe, "check_metadata")
        self.metadata.start()
        self.addCleanup(self.metadata.stop)

    @staticmethod
    def digest(value):
        return hashlib.sha256((value + "\n").encode("ascii")).hexdigest()

    def write_record(self):
        self.path.write_text(json.dumps(self.record), encoding="utf-8")

    def collect(self):
        return probe.collect_restore(self.config, self.disk, self.backups, "verification.tar", self.expected)

    def test_real_record_is_bound_to_backup_version_and_rotated_marker_hashes(self):
        result = self.collect()
        self.assertEqual(result["archive_sha256"], self.expected["archive_sha256"])
        for field in ("source_sha", "image_ref", "image_id"):
            self.assertEqual(result[field], self.version[field])
        self.assertEqual(result["previous_storage_identity_sha256"], self.digest(self.old))
        for field in ("restored_storage_identity_sha256", "config_storage_identity_sha256", "disk_storage_identity_sha256"):
            self.assertEqual(result[field], self.digest(self.new))
        self.assertNotEqual(result["restored_storage_identity_sha256"], result["previous_storage_identity_sha256"])
        self.assertNotIn(self.old, json.dumps(result))
        self.assertNotIn(self.new, json.dumps(result))

    def test_snapshot_reads_both_actual_markers_and_returns_only_hash(self):
        self.assertEqual(probe.collect_snapshot(self.config, self.disk), {"storage_identity_sha256": self.digest(self.new)})
        self.disk.write_bytes((self.old + "\n").encode("ascii"))
        with self.assertRaises(probe.ProbeError):
            probe.collect_snapshot(self.config, self.disk)

    def test_missing_duplicate_or_malformed_evidence_is_rejected(self):
        original = self.path.read_bytes()
        self.path.unlink()
        with self.assertRaises(probe.ProbeError):
            self.collect()
        self.path.write_bytes(original)
        duplicate = self.backups / "verification.tar.restore-fedcba0987654321.json"
        duplicate.write_bytes(original)
        with self.assertRaises(probe.ProbeError):
            self.collect()
        duplicate.unlink()
        self.path.write_bytes(b"not-json")
        with self.assertRaises(probe.ProbeError):
            self.collect()

    def test_each_version_and_archive_mismatch_is_rejected(self):
        for field, value in (("source_sha", "0" * 40), ("image_ref", "localhost:5001/wrong@sha256:" + "d" * 64),
                             ("image_id", "sha256:" + "0" * 64), ("uid", 0), ("gid", 0), ("initialized", False)):
            with self.subTest(field=field):
                self.record["version"] = {**self.version, field: value}
                self.write_record()
                with self.assertRaises(probe.ProbeError):
                    self.collect()
        self.record["version"] = self.version
        for field, value in (("format", 2), ("archive_sha256", "0" * 64)):
            with self.subTest(field=field):
                original = self.record[field]
                self.record[field] = value
                self.write_record()
                with self.assertRaises(probe.ProbeError):
                    self.collect()
                self.record[field] = original

    def test_false_rotation_mismatched_identity_and_bad_format_are_rejected_without_leaking(self):
        for field, value in (("previous_storage_identity", "0" * 64), ("restored_storage_identity", self.old),
                             ("restored_storage_identity", "0" * 64), ("previous_storage_identity", "PRIVATE-SECRET"),
                             ("restored_storage_identity", None)):
            with self.subTest(field=field):
                original = self.record[field]
                self.record[field] = value
                self.write_record()
                with self.assertRaises(probe.ProbeError) as error:
                    self.collect()
                self.assertNotIn("PRIVATE-SECRET", str(error.exception))
                self.assertNotIn(self.old, str(error.exception))
                self.assertNotIn(self.new, str(error.exception))
                self.record[field] = original
        self.write_record()
        self.disk.write_bytes((self.old + "\n").encode("ascii"))
        with self.assertRaises(probe.ProbeError):
            self.collect()
        self.disk.write_bytes(self.new.encode("ascii"))
        with self.assertRaises(probe.ProbeError):
            self.collect()

    def test_matching_but_unrotated_markers_are_rejected(self):
        self.record["restored_storage_identity"] = self.old
        self.write_record()
        self.config.write_bytes((self.old + "\n").encode("ascii"))
        self.disk.write_bytes(self.config.read_bytes())
        with self.assertRaises(probe.ProbeError):
            self.collect()

    def test_protected_record_and_marker_metadata_checks_are_required(self):
        with mock.patch.object(probe, "check_metadata", side_effect=probe.ProbeError("unsafe metadata")):
            with self.assertRaises(probe.ProbeError):
                self.collect()
        with mock.patch.object(probe, "check_metadata") as check:
            self.collect()
        self.assertIn(mock.call(self.path, 0o600, 0), check.call_args_list)
        self.assertIn(mock.call(self.config, 0o440, 10001), check.call_args_list)
        self.assertIn(mock.call(self.disk, 0o440, 10001), check.call_args_list)

    def test_cli_prints_only_sanitized_result(self):
        output = io.StringIO()
        with mock.patch.object(probe, "CONFIG_MARKER", self.config), mock.patch.object(probe, "DISK_MARKER", self.disk), mock.patch.object(probe, "BACKUP_ROOT", self.backups), contextlib.redirect_stdout(output):
            probe.cli(["restore", "--archive-name", "verification.tar", "--archive-sha256", self.expected["archive_sha256"],
                       "--source-sha", self.version["source_sha"], "--image-ref", self.version["image_ref"], "--image-id", self.version["image_id"],
                       "--previous-identity-sha256", self.expected["previous_storage_identity_sha256"]])
        self.assertEqual(json.loads(output.getvalue()), {**self.collect(), "verified": True})
        self.assertNotIn(self.old, output.getvalue())
        self.assertNotIn(self.new, output.getvalue())


class MetadataTests(unittest.TestCase):
    def test_real_metadata_check_rejects_wrong_mode_owner_group_type_and_symlink(self):
        safe = {"st_mode": stat.S_IFREG | 0o600, "st_uid": 0, "st_gid": 0}
        path = mock.Mock()
        path.lstat.return_value = SimpleNamespace(**safe)
        probe.check_metadata(path, 0o600, 0)
        for field, value in (("st_mode", stat.S_IFREG | 0o644), ("st_uid", 1000), ("st_gid", 10001),
                             ("st_mode", stat.S_IFLNK | 0o600), ("st_mode", stat.S_IFDIR | 0o600)):
            with self.subTest(field=field, value=value):
                path.lstat.return_value = SimpleNamespace(**{**safe, field: value})
                with self.assertRaises(probe.ProbeError):
                    probe.check_metadata(path, 0o600, 0)


class ProbeDriverTests(unittest.TestCase):
    def test_guest_failure_is_recorded_before_scenario_assertion(self):
        spec = importlib.util.spec_from_file_location("shared_host_recovery_driver_tests", MODULE_PATH.with_name("shared_host_vm.py"))
        harness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(harness)
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(evidence=Path(directory))
            vm = mock.Mock()
            for output in (b'{"verified": false, "failure": "storage identity was not rotated"}', b'PRIVATE-SECRET'):
                with self.subTest(output_format="json" if output.startswith(b"{") else "invalid"):
                    vm.command_on_guest.return_value = subprocess.CompletedProcess([], 1, output, b"PRIVATE-STDERR")
                    evidence = {}
                    with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(harness.VerificationError):
                        harness.recovery_probe(vm, args, evidence, "restored_storage_identity", ["restore"])
                    saved = (args.evidence / "vm-result.json").read_text(encoding="utf-8")
                    self.assertFalse(json.loads(saved)["restored_storage_identity"]["verified"])
                    self.assertNotIn("PRIVATE-SECRET", saved)
                    self.assertNotIn("PRIVATE-STDERR", saved)
                    self.assertEqual(json.loads(saved)["stage"], "restored_storage_identity")
                    self.assertEqual(vm.command_on_guest.call_args.kwargs, {"check": False})



if __name__ == "__main__":
    unittest.main()
