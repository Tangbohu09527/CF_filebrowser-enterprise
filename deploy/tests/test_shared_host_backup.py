"""Portable archive checks; all payloads and recovery targets are temporary."""
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "shared-host" / "backup.py"
spec = importlib.util.spec_from_file_location("shared_host_backup", MODULE)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class BackupArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.version = {"source_sha": "a" * 40, "image_ref": "local:fixed",
                        "image_id": "sha256:" + "b" * 64,
                        "uid": 10001, "gid": 10001, "initialized": True}
        self.payload = {
            "config": None, "config/.env": b"FILEBROWSER_IMAGE=local:fixed\n",
            "config/config.yaml": b"server: {}\n", "config/secrets": None,
            "config/secrets/jwt_token_secret": b"j" * 32,
            "config/secrets/totp_secret": b"t" * 32,
            "data": None, "data/database.db": b"initialized-db",
            "data/audit.db": b"audit-evidence", "files": None,
            "files/example.txt": b"business-file"}
        self.payload["config/deployment.json"] = json.dumps({
            "version": 1, "source_sha": self.version["source_sha"],
            "image_ref": self.version["image_ref"], "image_id": self.version["image_id"],
            "mode": "staging", "exposure": "debug", "bootstrap_complete": True}).encode()
        self.payload["config/storage.identity"] = b"e" * 64 + b"\n"
        self.payload["config/.env"] = ("\n".join([
            "COMPOSE_PROJECT_NAME=cf-filebrowser", "SOURCE_ROOT=/opt/cf-filebrowser-enterprise",
            "CONFIG_ROOT=/etc/cf-filebrowser-enterprise", "DATA_ROOT=/var/lib/cf-filebrowser-enterprise",
            "CACHE_ROOT=/var/cache/cf-filebrowser-enterprise",
            "FILES_ROOT=/srv/storage/cf-filebrowser-enterprise/files",
            "BACKUP_ROOT=/srv/storage/cf-filebrowser-enterprise/backups",
            "FILEBROWSER_UID=10001", "FILEBROWSER_GID=10001", "FILEBROWSER_IMAGE=local:fixed",
            "BUILD_REVISION=" + self.version["source_sha"]]) + "\n").encode()

    def archive(self, mutate=None, tar_mutate=None):
        entries = []
        for name, value in self.payload.items():
            kind = "directory" if value is None else "file"
            mode, uid, gid = backup.default_metadata(name, kind)
            entry = dict(path=name, kind=kind, mode=mode, uid=uid, gid=gid,
                         size=0 if value is None else len(value))
            if value is not None:
                entry["sha256"] = hashlib.sha256(value).hexdigest()
            entries.append(entry)
        manifest = {"format": 1, "project": "cf-filebrowser", "version": self.version,
                    "entries": entries}
        if mutate:
            mutate(manifest)
        path = self.root / "backup.tar"
        with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
            raw = json.dumps(manifest).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size, info.mode = len(raw), 0o600
            archive.addfile(info, io.BytesIO(raw))
            for entry in entries:
                info = tarfile.TarInfo(entry["path"])
                info.type = tarfile.DIRTYPE if entry["kind"] == "directory" else tarfile.REGTYPE
                info.mode, info.uid, info.gid = entry["mode"], entry["uid"], entry["gid"]
                content = self.payload.get(entry["path"])
                info.size = 0 if content is None else len(content)
                if tar_mutate:
                    tar_mutate(info)
                archive.addfile(info, None if content is None else io.BytesIO(content))
        return path

    def test_round_trip_restores_files_database_audit_and_secrets_without_bootstrap(self):
        path = self.archive()
        targets = {name: self.root / ("restore-" + name) for name in ("config", "data", "files")}
        with mock.patch.object(backup, "set_metadata"):
            backup.restore_archive(path, targets, self.version)
        for name, value in self.payload.items():
            if value is not None:
                root, _, relative = name.partition("/")
                self.assertEqual((targets[root] / relative).read_bytes(), value)
        self.assertFalse((targets["config"] / "secrets/bootstrap_admin_password").exists())
        self.assertFalse((self.root / "cache").exists())

    def test_rejects_hash_corruption_before_creating_targets(self):
        path = self.archive(lambda m: m["entries"][-1].update(sha256="0" * 64))
        targets = {name: self.root / name for name in ("config", "data", "files")}
        with self.assertRaises(backup.BackupError):
            backup.restore_archive(path, targets, self.version)
        self.assertTrue(all(not target.exists() for target in targets.values()))

    def test_rejects_versions_and_incomplete_archives(self):
        for field, value in (("image_id", "sha256:" + "c" * 64), ("source_sha", "d" * 40),
                             ("initialized", False), ("uid", 0)):
            with self.subTest(field=field):
                expected = copy.deepcopy(self.version)
                expected[field] = value
                with self.assertRaises(backup.BackupError):
                    backup.validate_archive(self.archive(), expected)
        del self.payload["data/database.db"]
        with self.assertRaises(backup.BackupError):
            backup.validate_archive(self.archive(), self.version)

    def test_rejects_unsafe_manifest_paths_duplicates_and_modes(self):
        for value in ("../escaped", "/absolute", "files/../escaped", "files//nested",
                      "files\\escaped", "files/example.txt/child", "C:/absolute"):
            with self.subTest(path=value):
                with self.assertRaises(backup.BackupError):
                    backup.validate_archive(self.archive(lambda m: m["entries"][-1].update(path=value)), self.version)
        mutations = [lambda m: m["entries"].append(m["entries"][-1]),
                     lambda m: m["entries"][-1].update(mode=0o777),
                     lambda m: next(e for e in m["entries"] if e["path"] == "files/example.txt").update(uid=0),
                     lambda m: m["entries"][1].update(mode=0o644)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(backup.BackupError):
                backup.validate_archive(self.archive(mutation), self.version)

    def test_rejects_links_devices_and_tar_metadata_mismatch(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE):
            def change(info):
                if info.name == "files/example.txt":
                    info.type = kind
                    info.linkname = "../../outside"
            with self.subTest(kind=kind), self.assertRaises(backup.BackupError):
                backup.validate_archive(self.archive(tar_mutate=change), self.version)
        def wrong_owner(info):
            info.uid = 42
        with self.assertRaises(backup.BackupError):
            backup.validate_archive(self.archive(tar_mutate=wrong_owner), self.version)

    def test_existing_target_is_not_overwritten(self):
        target = self.root / "existing"
        target.mkdir()
        sentinel = target / "database.db"
        sentinel.write_bytes(b"existing-database")
        targets = {"config": self.root / "config", "data": target, "files": self.root / "files"}
        with self.assertRaises(backup.BackupError):
            backup.restore_archive(self.archive(), targets, self.version)
        self.assertEqual(sentinel.read_bytes(), b"existing-database")
        self.assertFalse(targets["config"].exists())

    def test_bootstrap_and_cache_are_rejected(self):
        for name in ("config/secrets/bootstrap_admin_password", "cache/cached.bin"):
            self.payload[name] = b"must-not-be-restored"
            with self.subTest(name=name), self.assertRaises(backup.BackupError):
                backup.validate_archive(self.archive(), self.version)
            del self.payload[name]

    def test_write_failure_preserves_partial_data_and_does_not_resume_service(self):
        targets = {name: self.root / ("partial-" + name) for name in ("config", "data", "files")}
        real_copy = backup.copy_stream
        count = 0
        def fail_later(source, destination):
            nonlocal count
            count += 1
            if count == 3:
                raise OSError("simulated disk full")
            return real_copy(source, destination)
        with mock.patch.object(backup, "set_metadata"), mock.patch.object(backup, "copy_stream", fail_later):
            with self.assertRaises(OSError):
                backup.restore_archive(self.archive(), targets, self.version)
        self.assertTrue((targets["config"] / ".env").exists())

    def test_incomplete_bootstrap_and_lan_without_tls_are_rejected(self):
        for key, value in (("bootstrap_complete", False), ("exposure", "lan")):
            with self.subTest(key=key):
                metadata = json.loads(self.payload["config/deployment.json"])
                metadata[key] = value
                original = self.payload["config/deployment.json"]
                self.payload["config/deployment.json"] = json.dumps(metadata).encode()
                with self.assertRaises(backup.BackupError):
                    backup.validate_archive(self.archive(), self.version)
                self.payload["config/deployment.json"] = original

    def test_lan_backup_retains_all_tls_material(self):
        metadata = json.loads(self.payload["config/deployment.json"])
        metadata["exposure"] = "lan"
        self.payload["config/deployment.json"] = json.dumps(metadata).encode()
        self.payload.update({"config/tls": None, "config/tls/server.crt": b"certificate",
                             "config/tls/server.key": b"private-key", "config/tls/ca.crt": b"CA"})
        manifest = backup.validate_archive(self.archive(), self.version)
        self.assertIn("config/tls/server.key", {entry["path"] for entry in manifest["entries"]})

    def test_truncated_tar_and_trailing_payload_are_rejected(self):
        path = self.archive()
        raw = path.read_bytes()
        with tarfile.open(path, "r:") as archive:
            last = archive.getmembers()[-1]
            end = last.offset_data + ((last.size + 511) // 512) * 512
        for bad in (raw[:end], raw + b"hidden-archive"):
            with self.subTest(length=len(bad)), self.assertRaises(backup.BackupError):
                path.write_bytes(bad)
                backup.validate_archive(path, self.version)

    def run_restore_cli(self, archive, *, checksum=None):
        config = self.root / "blank-config"
        data = self.root / "blank-data"
        storage = self.root / "blank-storage"
        files = storage / "files"
        backups = storage / "backups"
        cache = self.root / "blank-cache"
        targets = {"config": config, "data": data, "files": files}
        def safe_write(path, raw, mode=0o600, gid=0, replace=False):
            with path.open("wb" if replace else "xb") as output:
                output.write(raw)
        patches = {
            "ROOTS": targets, "CONFIG_ROOT": config, "DATA_ROOT": data,
            "FILES_ROOT": files, "BACKUP_ROOT": backups, "CACHE_ROOT": cache,
        }
        with mock.patch.multiple(backup, **patches), contextlib.ExitStack() as stack:
            for name in ("production_guard", "verify_local_version", "require_stopped_for_restore", "set_metadata"):
                stack.enter_context(mock.patch.object(backup, name))
            stack.enter_context(mock.patch.object(backup, "lifecycle_lock", return_value=contextlib.nullcontext()))
            stack.enter_context(mock.patch.object(backup, "backup_path", return_value=archive))
            stack.enter_context(mock.patch.object(backup, "write_private", side_effect=safe_write))
            result = backup.cli(["restore", str(archive), "--hostname", "isolated-test",
                                 "--source-sha", self.version["source_sha"],
                                 "--image-ref", self.version["image_ref"],
                                 "--image-id", self.version["image_id"],
                                 "--sha256", checksum or hashlib.sha256(archive.read_bytes()).hexdigest()])
        return result, targets, backups, cache

    def test_restore_cli_creates_truly_blank_fixed_layout_after_validation(self):
        archive = self.archive()
        result, targets, backups, cache = self.run_restore_cli(archive)
        self.assertEqual(result, 0)
        self.assertEqual((targets["data"] / "database.db").read_bytes(), b"initialized-db")
        self.assertEqual((targets["files"] / "example.txt").read_bytes(), b"business-file")
        self.assertTrue(cache.is_dir())
        new = (targets["config"] / "storage.identity").read_bytes()
        self.assertNotEqual(new, self.payload["config/storage.identity"])
        self.assertEqual(new, (targets["files"].parent / ".storage-identity").read_bytes())
        self.assertEqual(len(list(backups.glob("*.json"))), 1)
        self.assertFalse((targets["config"] / "secrets/bootstrap_admin_password").exists())

    def test_restore_cli_rejects_corruption_before_any_layout_creation(self):
        archive = self.archive(lambda m: m["entries"][-1].update(sha256="0" * 64))
        with self.assertRaises(backup.BackupError):
            self.run_restore_cli(archive)
        self.assertEqual(list(self.root.iterdir()), [archive])

    def test_restore_cli_requires_external_checksum_before_writing(self):
        archive = self.archive()
        with self.assertRaises(backup.BackupError):
            self.run_restore_cli(archive, checksum="0" * 64)
        self.assertEqual(list(self.root.iterdir()), [archive])

    def test_controlled_backup_stop_only_targets_project_container(self):
        running = {"Id": "owned", "Image": self.version["image_id"], "State": {"Running": True}}
        stopped = {"Id": "owned", "Image": self.version["image_id"], "State": {"Running": False, "ExitCode": 0}}
        with mock.patch.object(backup, "service_containers", side_effect=[[running], [stopped]]), \
                mock.patch.object(backup, "assert_no_other_writers") as writers, \
                mock.patch.object(backup, "docker") as docker:
            backup.stop_for_backup(self.version)
        docker.assert_called_once_with("container", "stop", "--time", "60", "owned")
        self.assertEqual(writers.call_count, 2)

    def test_unclean_stop_is_rejected(self):
        stopped = {"Id": "owned", "Image": self.version["image_id"], "State": {"Running": False, "ExitCode": 137}}
        with mock.patch.object(backup, "service_containers", return_value=[stopped]), \
                mock.patch.object(backup, "assert_no_other_writers"), self.assertRaises(backup.BackupError):
            backup.stop_for_backup(self.version)

    def test_env_path_or_image_mismatch_is_rejected(self):
        original = self.payload["config/.env"]
        for old, new in ((b"FILES_ROOT=/srv/storage/cf-filebrowser-enterprise/files", b"FILES_ROOT=/etc"),
                         (b"FILEBROWSER_IMAGE=local:fixed", b"FILEBROWSER_IMAGE=local:different")):
            self.payload["config/.env"] = original.replace(old, new)
            with self.assertRaises(backup.BackupError):
                backup.validate_archive(self.archive(), self.version)
        self.payload["config/.env"] = original

    def test_create_archive_produces_a_verified_restorable_package(self):
        manifest = backup.validate_archive(self.archive(), self.version)
        roots = {name: self.root / ("source-" + name) for name in ("config", "data", "files")}
        for name, value in self.payload.items():
            root, _, relative = name.partition("/")
            target = roots[root] / relative
            if value is None:
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(value)
        destination = self.root / "created.tar"
        # Archive ownership rules are exercised by negative manifest tests.
        # Only source stat inventory is injected on Windows, which lacks UID/GID.
        with mock.patch.object(backup, "collect_entries", return_value=manifest["entries"]):
            digest = backup.create_archive(destination, roots, self.version)
        self.assertEqual(digest, hashlib.sha256(destination.read_bytes()).hexdigest())
        self.assertEqual(backup.validate_archive(destination, self.version), manifest)


if __name__ == "__main__":
    unittest.main(verbosity=2)
