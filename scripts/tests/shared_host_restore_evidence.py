#!/usr/bin/env python3
"""Read protected restore evidence inside the guest; emit only sanitized results."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import subprocess
import json
from pathlib import Path
import re
import stat

CONFIG_MARKER = Path("/etc/cf-filebrowser-enterprise/storage.identity")
DISK_MARKER = Path("/srv/storage/cf-filebrowser-enterprise/.storage-identity")
BACKUP_ROOT = Path("/srv/storage/cf-filebrowser-enterprise/backups")


class ProbeError(RuntimeError):
    pass


def check_metadata(path, mode, gid, directory=False):
    info = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(info.st_mode) or stat.S_IMODE(info.st_mode) != mode or info.st_uid != 0 or info.st_gid != gid:
        raise ProbeError("recovery evidence or marker metadata is unsafe")


def read_marker(path):
    check_metadata(path, 0o440, 10001)
    raw = path.read_bytes()
    if not re.fullmatch(rb"[0-9a-f]{64}\n", raw):
        raise ProbeError("storage identity format is invalid")
    return raw


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def collect_snapshot(config_marker, disk_marker):
    config, disk = read_marker(config_marker), read_marker(disk_marker)
    if config != disk:
        raise ProbeError("original storage identities do not match")
    return {"storage_identity_sha256": digest(config)}


def collect_restore(config_marker, disk_marker, backup_root, archive_name, expected):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.tar", archive_name):
        raise ProbeError("archive evidence name is invalid")
    check_metadata(backup_root, 0o700, 0, directory=True)
    paths = list(backup_root.glob(archive_name + ".restore-*.json"))
    if len(paths) != 1:
        raise ProbeError("restore must create exactly one recovery evidence record")
    if not re.fullmatch(re.escape(archive_name) + r"\.restore-[0-9a-f]{16}\.json", paths[0].name):
        raise ProbeError("recovery evidence filename is invalid")
    check_metadata(paths[0], 0o600, 0)
    try:
        record = json.loads(paths[0].read_bytes())
    except (ValueError, UnicodeError) as error:
        raise ProbeError("recovery evidence is not valid JSON") from error
    if not isinstance(record, dict) or record.get("format") != 1:
        raise ProbeError("recovery evidence format is invalid")
    if record.get("archive_sha256") != expected["archive_sha256"] or record.get("version") != expected["version"]:
        raise ProbeError("recovery evidence does not match the fixed backup and image version")
    old, new = record.get("previous_storage_identity"), record.get("restored_storage_identity")
    if not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in (old, new)):
        raise ProbeError("recovery evidence identity format is invalid")
    old_raw, new_raw = (old + "\n").encode("ascii"), (new + "\n").encode("ascii")
    config, disk = read_marker(config_marker), read_marker(disk_marker)
    if digest(old_raw) != expected["previous_storage_identity_sha256"]:
        raise ProbeError("recovery evidence does not match the independently captured original identity")
    if old_raw == new_raw:
        raise ProbeError("restored storage identity was not rotated")
    if config != disk or config != new_raw:
        raise ProbeError("restored configuration and disk identities do not match recovery evidence")
    return {"archive_sha256": record["archive_sha256"],
            **{key: record["version"][key] for key in ("source_sha", "image_ref", "image_id")},
            "previous_storage_identity_sha256": digest(old_raw),
            "restored_storage_identity_sha256": digest(new_raw),
            "config_storage_identity_sha256": digest(config), "disk_storage_identity_sha256": digest(disk)}



def load_helper(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def compare_payload(archived, actual, *, rotated):
    before = {e["path"]: e for e in archived}
    after = {e["path"]: e for e in actual}
    if before.keys() != after.keys() or "data/database.db" not in before:
        raise ProbeError("recovered payload inventory differs from archive")
    for name, entry in before.items():
        expected = dict(entry)
        if rotated and name == "config/storage.identity":
            if after[name].get("sha256") == expected.get("sha256"):
                raise ProbeError("storage identity must rotate")
            expected["sha256"] = after[name].get("sha256")
        if expected != after[name]:
            raise ProbeError("stopped payload bytes or permissions differ from archive")
    return {"member_count": len(before), "database_bytes_match": True,
            "database_sha256_before_start": before["data/database.db"]["sha256"],
            "file_config_key_metadata_match": True, "expected_change": "storage.identity only" if rotated else "none"}


def collect_payload(path, version, checksum, *, rotated):
    check_metadata(path, 0o600, 0)
    backup = load_helper("restore_backup_probe", Path(__file__).resolve().parents[2] / "deploy/shared-host/backup.py")
    with path.open("rb") as stream:
        if backup.sha256_stream(stream) != checksum:
            raise ProbeError("external backup checksum mismatch")
    manifest = backup.validate_archive(path, version)
    result = compare_payload(manifest["entries"], backup.collect_entries(backup.ROOTS), rotated=rotated)
    result.update(archive_format=manifest["format"], archive_sha256=checksum,
                  bootstrap_absent=not (backup.CONFIG_ROOT / "secrets/bootstrap_admin_password").exists())
    if not result["bootstrap_absent"]:
        raise ProbeError("bootstrap secret remains after initialized restore")
    return result


def collect_inventory():
    if not Path('/etc/cf-shared-host-disposable').is_file():
        raise ProbeError("disposable guest required")
    probe = load_helper("restore_storage_probe", Path(__file__).with_name("shared_host_storage_probe.py"))
    roots = {}
    for name, path in (("config", CONFIG_MARKER.parent), ("data", Path('/var/lib/cf-filebrowser-enterprise')),
                       ("cache", Path('/var/cache/cf-filebrowser-enterprise')), ("storage", DISK_MARKER.parent)):
        tree = probe.underlay_tree(path)
        if not tree.get("complete"):
            raise ProbeError("restore inventory size bound exceeded")
        roots[name] = {"root": probe.path_state(path), **{k: tree[k] for k in ("entry_count", "tree_sha256")}}
    underlay = probe.root_underlay()
    if not underlay.get('complete') or underlay.get('business_path_exists'):
        raise ProbeError("root filesystem contains unexpected business data")
    ids = subprocess.check_output(['docker','ps','-aq','--filter','label=com.docker.compose.project=cf-filebrowser']).decode().split()
    containers = []
    for cid in ids:
        info = json.loads(subprocess.check_output(['docker','inspect',cid]))[0]
        state = info['State']
        containers.append({"id": cid, "image": info['Image'], **{k: state[k] for k in ('Running','Restarting','ExitCode','OOMKilled')}})
    uuid = subprocess.check_output(['findmnt','-n','-o','UUID','--mountpoint','/srv/storage']).decode().strip()
    if not uuid:
        raise ProbeError("independent storage mount UUID unavailable")
    return {"roots": roots, "storage_uuid": uuid, "containers": containers,
            "root_underlay": {k: underlay[k] for k in ('tree_sha256','entry_count','business_path_exists')}}


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("snapshot")
    commands.add_parser("inventory")
    payload = commands.add_parser("payload")
    for name in ("archive", "archive-sha256", "source-sha", "image-ref", "image-id"):
        payload.add_argument("--" + name, required=True)
    payload.add_argument("--rotated", action="store_true")
    restore = commands.add_parser("restore")
    for name in ("archive-name", "archive-sha256", "source-sha", "image-ref", "image-id", "previous-identity-sha256"):
        restore.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "snapshot":
            result = collect_snapshot(CONFIG_MARKER, DISK_MARKER)
        elif args.operation == "inventory":
            result = collect_inventory()
        else:
            version = {"source_sha": args.source_sha, "image_ref": args.image_ref, "image_id": args.image_id,
                       "uid": 10001, "gid": 10001, "initialized": True}
            if args.operation == "payload":
                result = collect_payload(Path(args.archive), version, args.archive_sha256, rotated=args.rotated)
                result["verified"] = True
                print(json.dumps(result, sort_keys=True))
                return 0
            expected = {"archive_sha256": args.archive_sha256, "version": version,
                        "previous_storage_identity_sha256": args.previous_identity_sha256}
            result = collect_restore(CONFIG_MARKER, DISK_MARKER, BACKUP_ROOT, args.archive_name, expected)
        result["verified"] = True
    except ProbeError as error:
        result = {"verified": False, "failure": str(error)}
    except (OSError, ValueError, KeyError):
        # Never include file content, paths or decoder excerpts in CI output.
        result = {"verified": False, "failure": "protected recovery evidence could not be read"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(cli())
