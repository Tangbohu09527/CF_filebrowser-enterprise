#!/usr/bin/env python3
"""Controlled shared-host backups. Never extract an unverified tar archive.

The archive includes JWT/TOTP keys and is therefore sensitive, despite not
containing the one-time bootstrap password. Keep a separately protected copy of
the keys and an externally recorded archive SHA-256. A manifest proves integrity,
not authenticity against an attacker who can rewrite the complete archive.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import secrets
import sys
import tarfile

PROJECT = "cf-filebrowser"
SERVICE = "filebrowser-enterprise"
SOURCE_ROOT = Path("/opt/cf-filebrowser-enterprise")
CONFIG_ROOT = Path("/etc/cf-filebrowser-enterprise")
DATA_ROOT = Path("/var/lib/cf-filebrowser-enterprise")
CACHE_ROOT = Path("/var/cache/cf-filebrowser-enterprise")
FILES_ROOT = Path("/srv/storage/cf-filebrowser-enterprise/files")
BACKUP_ROOT = Path("/srv/storage/cf-filebrowser-enterprise/backups")
LOCK_PATH = Path("/run/lock/cf-filebrowser-enterprise.lock")
ROOTS = {"config": CONFIG_ROOT, "data": DATA_ROOT, "files": FILES_ROOT}
UID = GID = 10001
MANIFEST_LIMIT = 16 * 1024 * 1024
CONFIG_METADATA = {
    "config": (0o750, 0, GID),
    "config/.env": (0o600, 0, 0),
    "config/config.yaml": (0o640, 0, GID),
    "config/deployment.json": (0o600, 0, 0),
    "config/storage.identity": (0o440, 0, GID),
    "config/secrets": (0o750, 0, GID),
    "config/secrets/jwt_token_secret": (0o440, 0, GID),
    "config/secrets/totp_secret": (0o440, 0, GID),
    "config/tls": (0o750, 0, GID),
    "config/tls/server.crt": (0o440, 0, GID),
    "config/tls/server.key": (0o440, 0, GID),
    "config/tls/ca.crt": (0o440, 0, GID),
}
REQUIRED_CONFIG = set(CONFIG_METADATA) - {name for name in CONFIG_METADATA if name.startswith("config/tls")}


class BackupError(RuntimeError):
    """An actionable refusal whose message never contains payload contents."""


def safe_name(name):
    if not isinstance(name, str) or not name or "\\" in name or ":" in name:
        raise BackupError("unsafe archive member path")
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts) or any(ord(c) < 32 for c in name):
        raise BackupError("unsafe archive member path")
    if parts[0] not in ROOTS:
        raise BackupError("archive contains an unexpected root")
    if parts[0] == "config" and name not in CONFIG_METADATA:
        raise BackupError("unexpected config member; bootstrap passwords are never backed up")
    return parts


def default_metadata(name, kind):
    safe_name(name)
    if name in CONFIG_METADATA:
        return CONFIG_METADATA[name]
    return (0o750 if kind == "directory" else 0o640, UID, GID)


def validate_metadata(entry):
    name, kind = entry.get("path"), entry.get("kind")
    safe_name(name)
    if kind not in ("directory", "file"):
        raise BackupError("only regular files and directories are supported; links are refused")
    if any(type(entry.get(key)) is not int for key in ("mode", "uid", "gid", "size")):
        raise BackupError("invalid member metadata")
    if name in CONFIG_METADATA:
        directory = name in ("config", "config/secrets", "config/tls")
        if (kind == "directory") != directory:
            raise BackupError("configuration member has the wrong type")
    expected = default_metadata(name, kind)
    actual = (entry["mode"], entry["uid"], entry["gid"])
    if name in CONFIG_METADATA or name in ROOTS:
        if actual != expected:
            raise BackupError("unexpected root or configuration permissions")
    elif entry["uid"] != UID or entry["gid"] != GID or entry["mode"] not in (
        (0o700, 0o750, 0o755) if kind == "directory" else (0o600, 0o640, 0o644)
    ):
        raise BackupError("unexpected business data ownership or permissions")
    if entry["size"] < 0 or (kind == "directory" and entry["size"] != 0):
        raise BackupError("invalid member size")
    if kind == "file" and not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))):
        raise BackupError("missing member checksum")


def validate_version(version, expected):
    if not isinstance(version, dict) or version != expected:
        raise BackupError("image, source revision or identity does not match the backup")
    if (version.get("uid") != UID or version.get("gid") != GID
            or version.get("initialized") is not True
            or not re.fullmatch(r"[0-9a-f]{40}", str(version.get("source_sha", "")))
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(version.get("image_id", "")))
            or not isinstance(version.get("image_ref"), str) or not version["image_ref"]):
        raise BackupError("backup version is incomplete or uninitialized")


def sha256_stream(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def copy_stream(source, destination):
    for block in iter(lambda: source.read(1024 * 1024), b""):
        destination.write(block)


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BackupError("duplicate JSON member")
        result[key] = value
    return result


def _validate_open_archive(archive, expected_version):
    members = archive.getmembers()
    if not members or members[0].name != "manifest.json":
        raise BackupError("backup manifest must be the first member")
    header = members[0]
    if (not header.isfile() or header.size > MANIFEST_LIMIT or header.size == 0
            or (header.mode, header.uid, header.gid) != (0o600, 0, 0)):
        raise BackupError("invalid backup manifest header")
    try:
        manifest = json.load(archive.extractfile(header), object_pairs_hook=unique_json)
    except (ValueError, UnicodeError) as exc:
        raise BackupError("invalid backup manifest JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != 1 or manifest.get("project") != PROJECT:
        raise BackupError("unsupported backup format")
    validate_version(manifest.get("version"), expected_version)
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != len(members) - 1:
        raise BackupError("archive inventory is incomplete")
    inventory = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise BackupError("invalid archive inventory")
        validate_metadata(entry)
        name = entry["path"]
        if name in inventory:
            raise BackupError("duplicate archive member")
        inventory[name] = entry
    required = REQUIRED_CONFIG | {"data", "data/database.db", "files"}
    if not required.issubset(inventory) or inventory["data/database.db"]["size"] == 0:
        raise BackupError("backup lacks initialized database, configuration or persistent keys")
    for name, entry in inventory.items():
        parent = str(PurePosixPath(name).parent)
        if parent != "." and (parent not in inventory or inventory[parent]["kind"] != "directory"):
            raise BackupError("archive member parent is absent or not a directory")
        must_be_directory = name in ROOTS or name in ("config/secrets", "config/tls")
        if name in required and (entry["kind"] == "directory") != must_be_directory:
            raise BackupError("required archive member has the wrong type")
    seen = {"manifest.json"}
    for member in members[1:]:
        if member.name in seen:
            raise BackupError("duplicate tar member")
        seen.add(member.name)
        safe_name(member.name)
        entry = inventory.get(member.name)
        if entry is None or not (member.isfile() or member.isdir()) or member.linkname:
            raise BackupError("archive contains a link, special file or unlisted member")
        kind = "directory" if member.isdir() else "file"
        if (kind, member.mode, member.uid, member.gid, member.size) != (
            entry["kind"], entry["mode"], entry["uid"], entry["gid"], entry["size"]
        ):
            raise BackupError("tar metadata does not match the manifest")
        if member.isfile() and sha256_stream(archive.extractfile(member)) != entry["sha256"]:
            raise BackupError("backup content checksum failed")
    # Reject missing end markers and hidden data after the first tar archive.
    last = members[-1]
    archive.fileobj.seek(last.offset_data + ((last.size + 511) // 512) * 512)
    trailing_size = 0
    for block in iter(lambda: archive.fileobj.read(1024 * 1024), b""):
        trailing_size += len(block)
        if any(block):
            raise BackupError("unexpected trailing archive content")
    if trailing_size < 1024 or trailing_size % 512:
        raise BackupError("backup is truncated or missing its end marker")
    validate_payload_state(archive, manifest)
    return manifest


def read_member(archive, name, limit=1024 * 1024):
    member = archive.getmember(name)
    if not member.isfile() or member.size > limit:
        raise BackupError("configuration file exceeds supported size")
    return archive.extractfile(member).read()


def validate_payload_state(archive, manifest):
    try:
        metadata = json.loads(read_member(archive, "config/deployment.json"), object_pairs_hook=unique_json)
    except (ValueError, UnicodeError) as exc:
        raise BackupError("invalid deployment metadata") from exc
    version = manifest["version"]
    if (not isinstance(metadata, dict) or metadata.get("version") != 1
            or metadata.get("bootstrap_complete") is not True
            or any(metadata.get(key) != version[key] for key in ("source_sha", "image_ref", "image_id"))
            or metadata.get("mode") not in ("staging", "candidate", "production")
            or metadata.get("exposure") not in ("base", "debug", "lan")):
        raise BackupError("deployment metadata is incomplete or bootstrap has not finished")
    marker = read_member(archive, "config/storage.identity", 65)
    if not re.fullmatch(rb"[0-9a-f]{64}\n", marker):
        raise BackupError("invalid storage identity in backup")
    if metadata["exposure"] == "lan":
        names = {entry["path"] for entry in manifest["entries"]}
        if not {"config/tls", "config/tls/server.crt", "config/tls/server.key", "config/tls/ca.crt"}.issubset(names):
            raise BackupError("LAN backup is missing required TLS material")
    validate_archived_environment(read_member(archive, "config/.env"), version)
    for name in ("config/secrets/jwt_token_secret", "config/secrets/totp_secret"):
        secret = read_member(archive, name, 4097)
        if secret.endswith(b"\n"):
            secret = secret[:-1]
        if not 32 <= len(secret) <= 4096 or b"\n" in secret or b"\r" in secret or b"\0" in secret:
            raise BackupError("invalid persistent secret shape")
    return metadata


def validate_archived_environment(raw, version):
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise BackupError("invalid archived env encoding") from error
    values = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if (not separator or key in values or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key)
                or not value or re.search(r"[\s$`'\"\\]", value)):
            raise BackupError("archived env contains invalid or duplicated values")
        values[key] = value
    expected = {
        "COMPOSE_PROJECT_NAME": PROJECT, "SOURCE_ROOT": "/opt/cf-filebrowser-enterprise",
        "CONFIG_ROOT": "/etc/cf-filebrowser-enterprise", "DATA_ROOT": "/var/lib/cf-filebrowser-enterprise",
        "CACHE_ROOT": "/var/cache/cf-filebrowser-enterprise",
        "FILES_ROOT": "/srv/storage/cf-filebrowser-enterprise/files",
        "BACKUP_ROOT": "/srv/storage/cf-filebrowser-enterprise/backups",
        "FILEBROWSER_UID": str(UID), "FILEBROWSER_GID": str(GID),
        "FILEBROWSER_IMAGE": version["image_ref"], "BUILD_REVISION": version["source_sha"],
    }
    if any(values.get(key) != value for key, value in expected.items()):
        raise BackupError("archived env does not match the fixed paths, image, source or identity")


def validate_archive(path, expected_version):
    try:
        with tarfile.open(path, "r:") as archive:
            return _validate_open_archive(archive, expected_version)
    except (tarfile.TarError, EOFError) as exc:
        raise BackupError("backup is corrupt or truncated") from exc


def no_links(path):
    """Check every existing ancestor without resolving a symlink first."""
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise BackupError("symlink paths are not supported")


def assert_empty_targets(targets):
    if set(targets) != set(ROOTS):
        raise BackupError("all three recovery roots are required")
    for name, target in targets.items():
        no_links(target)
        if target.exists():
            if not target.is_dir() or any(target.iterdir()):
                raise BackupError("restore requires empty config, data and files roots")
            info = target.stat()
            if (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) != default_metadata(name, "directory"):
                raise BackupError("empty recovery root has incorrect ownership or permissions")


def set_metadata(path, entry):
    os.chown(path, entry["uid"], entry["gid"], follow_symlinks=False)
    os.chmod(path, entry["mode"], follow_symlinks=False)


def restore_archive(path, targets, expected_version):
    """Validate the entire open archive before writing; leave partial data on failure.

    The caller holds the shared lifecycle lock and ensures the service is stopped.
    Injectable target roots are for unit tests; the production CLI always uses ROOTS.
    """
    with tarfile.open(path, "r:") as archive:
        manifest = _validate_open_archive(archive, expected_version)
        assert_empty_targets(targets)
        inventory = {entry["path"]: entry for entry in manifest["entries"]}
        # Create private roots first. Service permissions are applied only after
        # all payload writes complete, so a failed restore stays non-operational.
        for target in targets.values():
            target.mkdir(mode=0o700, parents=False, exist_ok=True)
        for entry in sorted(manifest["entries"], key=lambda e: (e["path"].count("/"), e["path"])):
            parts = safe_name(entry["path"])
            destination = targets[parts[0]].joinpath(*parts[1:])
            no_links(destination)
            if entry["kind"] == "directory":
                destination.mkdir(mode=0o700, exist_ok=True)
                continue
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(descriptor, "wb") as output:
                copy_stream(archive.extractfile(entry["path"]), output)
                output.flush()
                os.fsync(output.fileno())
            # Detect media failure or a concurrently rewritten archive before
            # making the restored file accessible to the service identity.
            with destination.open("rb") as restored:
                if sha256_stream(restored) != entry["sha256"]:
                    raise BackupError("restored file checksum failed; partial recovery retained")
        for name, entry in sorted(inventory.items(), key=lambda pair: -pair[0].count("/")):
            parts = safe_name(name)
            set_metadata(targets[parts[0]].joinpath(*parts[1:]), entry)
    return manifest


def collect_entries(roots):
    entries = []
    for root_name, root in roots.items():
        no_links(root)
        if not root.is_dir():
            raise BackupError("required backup root does not exist")
        for path in [root, *sorted(root.rglob("*"))]:
            no_links(path)
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                kind = "directory"
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                kind = "file"
            else:
                raise BackupError("backup refuses symlinks, hardlinks and special files")
            relative = path.relative_to(root).as_posix()
            name = root_name if relative == "." else root_name + "/" + relative
            entry = dict(path=name, kind=kind, mode=stat.S_IMODE(info.st_mode),
                         uid=info.st_uid, gid=info.st_gid,
                         size=info.st_size if kind == "file" else 0)
            if kind == "file":
                with path.open("rb") as source:
                    entry["sha256"] = sha256_stream(source)
            validate_metadata(entry)
            entries.append(entry)
    return entries


def create_archive(path, roots, version):
    validate_version(version, version)
    entries = collect_entries(roots)
    manifest = {"format": 1, "project": PROJECT, "version": version, "entries": entries}
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > MANIFEST_LIMIT:
        raise BackupError("backup inventory exceeds the supported manifest size")
    no_links(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as output:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
            header = tarfile.TarInfo("manifest.json")
            header.size, header.mode = len(raw), 0o600
            archive.addfile(header, io.BytesIO(raw))
            for entry in entries:
                member = tarfile.TarInfo(entry["path"])
                member.type = tarfile.DIRTYPE if entry["kind"] == "directory" else tarfile.REGTYPE
                member.mode, member.uid, member.gid, member.size = (entry[key] for key in ("mode", "uid", "gid", "size"))
                parts = safe_name(entry["path"])
                path_to_read = roots[parts[0]].joinpath(*parts[1:])
                if member.isfile():
                    with path_to_read.open("rb") as source:
                        archive.addfile(member, source)
                else:
                    archive.addfile(member)
        output.flush()
        os.fsync(output.fileno())
    # Never report success for a package that cannot itself be restored.
    validate_archive(path, version)
    with path.open("rb") as stream:
        return sha256_stream(stream)


def lifecycle_module():
    # This import resolves beside backup.py in the fixed checkout. Suppress
    # bytecode writes because the deployed checkout must remain clean.
    sys.dont_write_bytecode = True
    import lifecycle
    return lifecycle


def local_command(arguments):
    lifecycle = lifecycle_module()
    try:
        return lifecycle.run(arguments).decode("utf-8").strip()
    except lifecycle.DeploymentError as error:
        raise BackupError(str(error)) from error


def docker(*arguments):
    return local_command(["docker", "--host", "unix:///var/run/docker.sock", *arguments])


def check_file(path, expected, directory=False):
    no_links(path)
    info = path.lstat()
    correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not correct_type or (not directory and info.st_nlink != 1)
            or (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) != expected):
        raise BackupError("unexpected filesystem type, owner or mode at " + str(path))


def production_guard(hostname, *, creating=False):
    lifecycle = lifecycle_module()
    try:
        lifecycle.host_checks(hostname)
        paths = lifecycle.Paths()
        for directory, group, mode in ((paths.storage_project, GID, 0o750), (paths.backups, 0, 0o700)):
            if creating or directory.exists():
                lifecycle.assert_safe_path(directory, owner=0, group=group, mode=mode, directory=True)
        for target in (paths.config, paths.data, paths.cache, paths.storage_project):
            parent = target.parent
            while not parent.exists():
                parent = parent.parent
            lifecycle.assert_safe_path(parent, owner=0, directory=True)
        for path in (SOURCE_ROOT, CONFIG_ROOT, DATA_ROOT, CACHE_ROOT, FILES_ROOT, BACKUP_ROOT):
            no_links(path)
    except lifecycle.DeploymentError as error:
        raise BackupError(str(error)) from error


@contextlib.contextmanager
def lifecycle_lock():
    lifecycle = lifecycle_module()
    try:
        with lifecycle.deployment_lock():
            yield
    except lifecycle.DeploymentError as error:
        raise BackupError(str(error)) from error


def verify_local_version(version):
    validate_version(version, version)
    lifecycle = lifecycle_module()
    try:
        lifecycle.source_checks(lifecycle.Paths(), version["source_sha"])
        image = lifecycle.inspect_image(version["image_ref"])
    except lifecycle.DeploymentError as error:
        raise BackupError(str(error)) from error
    if image.get("Id") != version["image_id"]:
        raise BackupError("local image does not match the exact backup image ID; no pull was attempted")


def service_containers():
    ids = docker("container", "ls", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + PROJECT).split()
    containers = json.loads(docker("container", "inspect", *ids)) if ids else []
    for container in containers:
        labels = container.get("Config", {}).get("Labels", {})
        if labels.get("com.docker.compose.project") != PROJECT or labels.get("com.docker.compose.service") != SERVICE:
            raise BackupError("unexpected container within the dedicated project")
    return containers


def assert_no_other_writers(own_ids):
    ids = docker("container", "ls", "--quiet").split()
    containers = json.loads(docker("container", "inspect", *ids)) if ids else []
    protected = (CONFIG_ROOT, DATA_ROOT, CACHE_ROOT, FILES_ROOT)
    for container in containers:
        if container.get("Id") in own_ids:
            continue
        for mount in container.get("Mounts", []):
            if not mount.get("RW") or mount.get("Type") != "bind":
                continue
            path = Path(mount.get("Source", "/"))
            if any(path == root or path in root.parents or root in path.parents for root in protected):
                raise BackupError("another running container can write the protected roots")


def stop_for_backup(version):
    containers = service_containers()
    if not containers:
        raise BackupError("backup requires the initialized deployment container")
    ids = {container["Id"] for container in containers}
    assert_no_other_writers(ids)
    if any(container.get("Image") != version["image_id"] for container in containers):
        raise BackupError("deployed container does not use the recorded image")
    running = [container["Id"] for container in containers if container.get("State", {}).get("Running")]
    if running:
        docker("container", "stop", "--time", "60", *running)
    for container in service_containers():
        state = container.get("State", {})
        if state.get("Running") or state.get("Restarting") or state.get("OOMKilled") or state.get("ExitCode") != 0:
            raise BackupError("service did not stop cleanly; backup refused and existing data retained")
    assert_no_other_writers(set())


def require_stopped_for_restore():
    if any(c.get("State", {}).get("Running") or c.get("State", {}).get("Restarting") for c in service_containers()):
        raise BackupError("stop the service before restoring; existing containers are not removed")
    assert_no_other_writers(set())


def backup_path(value, must_exist):
    path = Path(value)
    if not path.is_absolute() or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.tar", path.name):
        raise BackupError("archive must be an absolute path to a named .tar file")
    if not must_exist and path.parent != BACKUP_ROOT:
        raise BackupError("new backups must be directly inside the fixed backup root")
    no_links(path)
    if must_exist:
        lifecycle = lifecycle_module()
        try:
            lifecycle.assert_safe_path(path, owner=0, group=0, mode=0o600)
        except lifecycle.DeploymentError as error:
            raise BackupError(str(error)) from error
    elif path.exists():
        raise BackupError("backup destination already exists; it will not be overwritten")
    return path


def write_private(path, raw, mode=0o600, gid=0, replace=False):
    no_links(path)
    flags = os.O_WRONLY | os.O_NOFOLLOW
    flags |= os.O_TRUNC if replace else os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
        os.fchown(output.fileno(), 0, gid)
        os.fchmod(output.fileno(), mode)


def rotate_storage_identity(config_root, disk_marker):
    old = (config_root / "storage.identity").read_text(encoding="ascii").strip()
    new = secrets.token_hex(32)
    if disk_marker.exists():
        check_file(disk_marker, (0o440, 0, GID))
    write_private(config_root / "storage.identity", (new + "\n").encode(), 0o440, GID, replace=True)
    write_private(disk_marker, (new + "\n").encode(), 0o440, GID, replace=disk_marker.exists())
    return {"previous_storage_identity": old, "restored_storage_identity": new}


def cli(argv=None):
    parser = argparse.ArgumentParser(description="Consistent shared-host backups; success leaves the service stopped.")
    parser.add_argument("operation", choices=("create", "restore", "verify"))
    parser.add_argument("archive", help="create: fixed backup root; restore/verify: root-owned 0600 archive under protected parents")
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--sha256", help="externally recorded archive checksum; required for restore")
    args = parser.parse_args(argv)
    version = {"source_sha": args.source_sha, "image_ref": args.image_ref,
               "image_id": args.image_id, "uid": UID, "gid": GID, "initialized": True}
    production_guard(args.hostname, creating=args.operation == "create")
    os.umask(0o077)
    with lifecycle_lock():
        verify_local_version(version)
        path = backup_path(args.archive, args.operation != "create")
        if args.operation == "create":
            # Check initialized metadata and persistent paths before stopping.
            check_file(CONFIG_ROOT / "deployment.json", (0o600, 0, 0))
            metadata = json.loads((CONFIG_ROOT / "deployment.json").read_bytes())
            if (metadata.get("bootstrap_complete") is not True
                    or any(metadata.get(key) != version[key] for key in ("source_sha", "image_ref", "image_id"))
                    or (CONFIG_ROOT / "secrets/bootstrap_admin_password").exists()
                    or not (DATA_ROOT / "database.db").is_file()
                    or (DATA_ROOT / "database.db").stat().st_size == 0):
                raise BackupError("backup requires completed bootstrap and the recorded initialized database")
            marker = FILES_ROOT.parent / ".storage-identity"
            check_file(marker, (0o440, 0, GID))
            check_file(CONFIG_ROOT / "storage.identity", (0o440, 0, GID))
            if ((CONFIG_ROOT / "storage.identity").read_bytes() != marker.read_bytes()
                    or FILES_ROOT.stat().st_dev != marker.stat().st_dev):
                raise BackupError("storage identity does not match the mounted files root")
            stop_for_backup(version)
            checksum = create_archive(path, ROOTS, version)
            print("Backup verified; service remains stopped. SHA-256: " + checksum)
            return 0
        with path.open("rb") as package:
            checksum = sha256_stream(package)
        if args.operation == "restore" and not re.fullmatch(r"[0-9a-f]{64}", args.sha256 or ""):
            raise BackupError("restore requires the SHA-256 recorded separately when the backup was created")
        if args.sha256 and args.sha256 != checksum:
            raise BackupError("archive does not match the externally recorded checksum")
        validate_archive(path, version)
        if args.operation == "verify":
            print("Backup verified. SHA-256: " + checksum)
            return 0
        require_stopped_for_restore()
        assert_empty_targets(ROOTS)
        no_links(CACHE_ROOT)
        if CACHE_ROOT.exists():
            check_file(CACHE_ROOT, (0o750, UID, GID), directory=True)
            if any(CACHE_ROOT.iterdir()):
                raise BackupError("restore requires an absent or empty cache directory")
        marker = FILES_ROOT.parent / ".storage-identity"
        if marker.exists():
            check_file(marker, (0o440, 0, GID))
        # The complete input archive, identities, local image/source, mount and
        # blank targets are now verified. Only now prepare missing fixed roots.
        if not FILES_ROOT.parent.exists():
            FILES_ROOT.parent.mkdir(mode=0o750)
            set_metadata(FILES_ROOT.parent, {"mode": 0o750, "uid": 0, "gid": GID})
        if not BACKUP_ROOT.exists():
            BACKUP_ROOT.mkdir(mode=0o700)
            set_metadata(BACKUP_ROOT, {"mode": 0o700, "uid": 0, "gid": 0})
        restore_archive(path, ROOTS, version)
        CACHE_ROOT.mkdir(mode=0o750, exist_ok=True)
        set_metadata(CACHE_ROOT, {"mode": 0o750, "uid": UID, "gid": GID})
        identities = rotate_storage_identity(CONFIG_ROOT, marker)
        evidence = {"format": 1, "archive_sha256": checksum, "version": version, **identities}
        evidence_path = BACKUP_ROOT / (path.name + ".restore-" + secrets.token_hex(8) + ".json")
        write_private(evidence_path, json.dumps(evidence, sort_keys=True).encode() + b"\n")
        print("Restore verified; service remains stopped. Recovery evidence: " + str(evidence_path))
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(cli())
    except BackupError as error:
        print("[shared-host-backup] ERROR: " + str(error), file=sys.stderr)
        raise SystemExit(1)
    except (OSError, ValueError, KeyError, tarfile.TarError):
        print("[shared-host-backup] ERROR: operation failed; existing and partial recovery data are retained; service was not started", file=sys.stderr)
        raise SystemExit(1)
