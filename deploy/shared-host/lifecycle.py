#!/usr/bin/env python3
"""Explicit shared-host lifecycle actions; secrets never enter argv or output.

The CLI has fixed production-shaped paths. Paths(root) exists only for unit
tests; no environment variable or CLI flag can redirect a privileged operation.
No action installs packages, formats disks, creates users or cleans Docker.
"""
from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

SERVICE = "filebrowser-enterprise"
PROJECT = "cf-filebrowser"
UID = GID = 10001
LOCK_PATH = Path("/run/lock/cf-filebrowser-enterprise.lock")
REPOSITORY = "https://github.com/Tangbohu09527/CF_filebrowser-enterprise.git"


class DeploymentError(RuntimeError):
    pass


@contextlib.contextmanager
def phase(name: str):
    try:
        yield
    except DeploymentError as error:
        raise DeploymentError(f"{name}: {error}") from error
    except (OSError, ValueError, KeyError) as error:
        raise DeploymentError(f"{name}: invalid state or I/O failure; preserve the installation") from error


class Paths:
    def __init__(self, root: Path | None = None):
        def fixed(value):
            return root / value.lstrip("/") if root is not None else Path(value)
        self.source = fixed("/opt/cf-filebrowser-enterprise")
        self.config = fixed("/etc/cf-filebrowser-enterprise")
        self.data = fixed("/var/lib/cf-filebrowser-enterprise")
        self.cache = fixed("/var/cache/cf-filebrowser-enterprise")
        self.storage = fixed("/srv/storage")
        self.storage_project = self.storage / "cf-filebrowser-enterprise"
        self.files = self.storage_project / "files"
        self.backups = self.storage_project / "backups"
        self.env = self.config / ".env"
        self.metadata = self.config / "deployment.json"
        self.bootstrap = self.config / "secrets" / "bootstrap_admin_password"
        self.assets = self.source / "deploy" / "shared-host"


def command_environment() -> dict[str, str]:
    # Do not inherit Compose interpolation, credentials, proxies, remote Docker
    # contexts, PYTHONPATH or Git override settings from the invoking shell.
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "DOCKER_HOST": "unix:///var/run/docker.sock",
            "PYTHONDONTWRITEBYTECODE": "1"}


def run(argv: list[str], input_bytes: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(argv, input=input_bytes, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False,
                                env=command_environment(), timeout=600)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DeploymentError(f"{Path(argv[0]).name} could not complete; output suppressed") from error
    if result.returncode:
        # curl login responses and Docker diagnostics may contain credentials.
        # Keep every caller's phase while never reflecting raw tool output.
        raise DeploymentError(f"{Path(argv[0]).name} failed (exit {result.returncode}); output suppressed")
    return result.stdout


def read_env(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if (not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key)
                or key in result or not value or re.search(r"[\s$`'\"\\]", value)):
            raise DeploymentError("env file has a duplicate, invalid or interpolated value")
        result[key] = value
    return result


def assert_safe_path(path: Path, *, owner: int | None = None,
                     group: int | None = None, mode: int | None = None,
                     directory: bool = False) -> None:
    if not path.is_absolute():
        raise DeploymentError(f"path must be absolute: {path}")
    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except FileNotFoundError as error:
            raise DeploymentError(f"required path is missing: {item}") from error
        if stat.S_ISLNK(info.st_mode):
            raise DeploymentError(f"symbolic links are forbidden: {item}")
        if item != path and (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
            raise DeploymentError(f"parent must be a root-owned directory without group/other write: {item}")
    info = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(info.st_mode) or (not directory and info.st_nlink != 1):
        raise DeploymentError(f"path must be a regular unlinked {'directory' if directory else 'file'}: {path}")
    if owner is not None and info.st_uid != owner:
        raise DeploymentError(f"incorrect numeric owner: {path}")
    if group is not None and info.st_gid != group:
        raise DeploymentError(f"incorrect numeric group: {path}")
    if mode is not None and stat.S_IMODE(info.st_mode) != mode:
        raise DeploymentError(f"incorrect mode (expected {mode:04o}): {path}")


def secret_bytes(value: bytes, minimum: int) -> bytes:
    if value.endswith(b"\n"):
        value = value[:-1]
    if not minimum <= len(value) <= 4096 or b"\n" in value or b"\r" in value or b"\0" in value:
        raise DeploymentError("secret must be one line within the documented length limits")
    try:
        value.decode("utf-8")
    except UnicodeError as error:
        raise DeploymentError("secret must be valid UTF-8") from error
    return value


def protected_secret(path: Path, minimum: int = 24, *, installed: bool = False) -> bytes:
    assert_safe_path(path, owner=0)
    info = path.stat()
    allowed = (0o440,) if installed else (0o400, 0o600)
    if stat.S_IMODE(info.st_mode) not in allowed or info.st_gid != (GID if installed else 0):
        raise DeploymentError("secret input must be root:root 0400/0600; installed secrets root:10001 0440")
    if info.st_size > 4097:
        raise DeploymentError("secret input is too large")
    return secret_bytes(path.read_bytes(), minimum)


def write_new(path: Path, value: bytes, mode: int, owner: int = 0, group: int = 0) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, owner, group)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(value)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def create_directory(path: Path, mode: int, owner: int = 0, group: int = 0) -> None:
    # Callers preflight all existing parents. No recursive chown/chmod or repair.
    path.mkdir(mode=mode)
    os.chown(path, owner, group)
    path.chmod(mode)


@contextlib.contextmanager
def deployment_lock():
    import fcntl
    assert_safe_path(LOCK_PATH.parent, owner=0, directory=True)
    fd = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise DeploymentError("unsafe deployment lock; do not overwrite it")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise DeploymentError("another lifecycle/backup action holds the deployment lock") from error
        yield
    finally:
        os.close(fd)


def host_checks(hostname: str, paths: Paths | None = None, *, require_storage: bool = True) -> None:
    paths = paths or Paths()
    if sys.platform != "linux" or os.geteuid() != 0:
        raise DeploymentError("run this action through explicitly authorized sudo on Debian 13 amd64")
    os_release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if os_release.get("ID", "").strip('"') != "debian" or os_release.get("VERSION_ID", "").strip('"') != "13" or platform.machine() not in ("x86_64", "amd64"):
        raise DeploymentError("the clean-device installer supports Debian 13 amd64 only")
    if hostname not in (socket.gethostname(), socket.getfqdn()):
        raise DeploymentError("--hostname must confirm the current isolated target host")
    required = ("bash", "docker", "git", "findmnt", "mountpoint", "getent", "ss", "openssl", "python3")
    missing = [name for name in required if not shutil.which(name, path=command_environment()["PATH"])]
    if missing:
        raise DeploymentError("install the documented prerequisites after authorization: " + ", ".join(missing))
    run(["python3", "-c", "import yaml"])
    compose_version = run(["docker", "compose", "version", "--short"]).decode().strip().lstrip("v")
    numbers = re.match(r"(\d+)\.(\d+)", compose_version)
    if not numbers or tuple(map(int, numbers.groups())) < (2, 20):
        raise DeploymentError("Docker Compose >= 2.20 is required")
    engine = json.loads(run(["docker", "info", "--format", "{{json .}}"] ))
    if engine.get("OSType") != "linux" or engine.get("Architecture") not in ("x86_64", "amd64"):
        raise DeploymentError("the local Docker daemon must be Linux amd64")
    security_options = str(engine.get("SecurityOptions", []))
    if "rootless" in security_options or "userns" in security_options:
        raise DeploymentError("rootless/userns-remapped Docker requires a separately reviewed identity contract")
    if require_storage:
        assert_safe_path(paths.storage, owner=0, directory=True)
        run(["mountpoint", "--quiet", str(paths.storage)])
        mount = run(["findmnt", "-n", "-o", "TARGET", "--target", str(paths.storage)]).decode().strip()
        if mount != str(paths.storage):
            raise DeploymentError("/srv/storage must be an independent existing mount; no directories were initialized")
        if paths.storage.stat().st_dev == Path("/").stat().st_dev:
            raise DeploymentError("/srv/storage must use an independent filesystem, not a same-filesystem bind")
    for kind in ("passwd", "group"):
        result = subprocess.run(["getent", kind, str(UID)], capture_output=True, env=command_environment(), check=False)
        if result.returncode != 2:
            raise DeploymentError(f"service identity {UID} conflicts with a host {kind} entry or lookup failed")


def source_checks(paths: Paths, sha: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise DeploymentError("--source-sha requires a full lowercase Git SHA")
    assert_safe_path(paths.source, owner=0, directory=True)
    if Path(__file__).resolve().parent != paths.assets:
        raise DeploymentError("execute the lifecycle entry point from the fixed /opt checkout")
    actual = run(["git", "-C", str(paths.source), "rev-parse", "HEAD"]).decode().strip()
    origin = run(["git", "-C", str(paths.source), "remote", "get-url", "origin"]).decode().strip()
    if actual != sha or origin != REPOSITORY:
        raise DeploymentError("fixed checkout SHA or origin differs from the approved product source")
    if run(["git", "-C", str(paths.source), "status", "--porcelain=v1"]):
        raise DeploymentError("fixed checkout is dirty; preserve it and stop")


def validate_image_reference(reference: str, mode: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]+", reference) or ".invalid" in reference or "replace-with" in reference:
        raise DeploymentError("invalid image reference")
    if mode != "staging":
        match = re.fullmatch(r".+@sha256:([0-9a-f]{64})", reference)
        if not match or match.group(1) == "0" * 64:
            raise DeploymentError("Candidate/production requires a nonzero immutable registry digest")


def inspect_image(reference: str) -> dict:
    images = json.loads(run(["docker", "image", "inspect", reference]))
    if len(images) != 1:
        raise DeploymentError("image must exist locally with one unambiguous identity; build/pull it first")
    image = images[0]
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64" or not re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("Id", "")):
        raise DeploymentError("the actual local image must be Linux amd64 with a valid Image ID")
    return image


def assert_empty_install(paths: Paths) -> None:
    for path in (paths.config, paths.data, paths.cache, paths.storage_project):
        if path.exists() or path.is_symlink():
            raise DeploymentError(f"existing or partial installation at {path}; preserve it for inspection")


def compose_command(paths: Paths, exposure: str) -> list[str]:
    command = ["docker", "compose", "--project-name", PROJECT, "--env-file", str(paths.env), "-f", str(paths.assets / "compose.yaml")]
    if exposure in ("debug", "lan"):
        command += ["-f", str(paths.assets / f"compose.{exposure}.yaml")]
    elif exposure != "base":
        raise DeploymentError("invalid exposure")
    return command + ["--profile", "approved"]


def project_containers() -> list[dict]:
    ids = run(["docker", "ps", "--all", "--quiet", "--filter", f"label=com.docker.compose.project={PROJECT}"]).decode().split()
    if not ids:
        return []
    containers = json.loads(run(["docker", "inspect", *ids]))
    if len(containers) != 1:
        raise DeploymentError("unexpected containers share the fixed project; preserve them and inspect")
    for container in containers:
        labels = container.get("Config", {}).get("Labels", {})
        if labels.get("com.docker.compose.project") != PROJECT or labels.get("com.docker.compose.service") != SERVICE:
            raise DeploymentError("unexpected container labels in the fixed project")
    return containers


def assert_stopped(paths: Paths, exposure: str) -> None:
    del paths, exposure
    for container in project_containers():
        if container.get("State", {}).get("Running") or container.get("State", {}).get("Restarting"):
            raise DeploymentError("the FileBrowser project must be fully stopped")


def container_identity(paths: Paths, exposure: str) -> tuple[str, str]:
    del paths, exposure
    containers = project_containers()
    if len(containers) != 1 or not containers[0].get("State", {}).get("Running"):
        raise DeploymentError("one running FileBrowser container is required")
    return containers[0]["Id"], containers[0]["Image"]


def save_metadata(paths: Paths, metadata: dict) -> None:
    value = (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode()
    if paths.metadata.exists():
        assert_safe_path(paths.metadata, owner=0, group=0, mode=0o600)
        staged = paths.config / ".deployment.json.new"
        write_new(staged, value, 0o600)
        os.replace(staged, paths.metadata)
    else:
        write_new(paths.metadata, value, 0o600)
    fd = os.open(paths.config, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load_metadata(paths: Paths) -> dict:
    assert_safe_path(paths.metadata, owner=0, group=0, mode=0o600)
    result = json.loads(paths.metadata.read_text(encoding="utf-8"))
    if result.get("version") != 1 or result.get("exposure") not in ("base", "debug", "lan") or result.get("mode") not in ("staging", "candidate", "production") or not isinstance(result.get("bootstrap_complete"), bool):
        raise DeploymentError("deployment metadata is missing or unsupported")
    validate_image_reference(result["image_ref"], result["mode"])
    return result


def validate_deployment(paths: Paths, metadata: dict) -> None:
    source_checks(paths, metadata["source_sha"])
    assert_safe_path(paths.env, owner=0, group=0, mode=0o600)
    values = read_env(paths.env)
    expected = {"SOURCE_ROOT": str(paths.source), "CONFIG_ROOT": str(paths.config), "DATA_ROOT": str(paths.data), "CACHE_ROOT": str(paths.cache), "FILES_ROOT": str(paths.files), "BACKUP_ROOT": str(paths.backups), "FILEBROWSER_UID": str(UID), "FILEBROWSER_GID": str(GID), "COMPOSE_PROJECT_NAME": PROJECT, "FILEBROWSER_IMAGE": metadata["image_ref"], "BUILD_REVISION": metadata["source_sha"]}
    if any(values.get(key) != value for key, value in expected.items()):
        raise DeploymentError("runtime env differs from fixed paths, identity or deployment version")
    import yaml
    config = yaml.safe_load((paths.config / "config.yaml").read_bytes())
    sources = config.get("server", {}).get("sources", [])
    enabled = metadata.get("enable_share_source", False)
    if not isinstance(enabled, bool) or len(sources) != 1 or sources[0].get("config", {}).get("private") is not (not enabled):
        raise DeploymentError("source sharing configuration differs from the explicit prepared decision")
    webdav_enabled = metadata.get("enable_webdav", False)
    if not isinstance(webdav_enabled, bool) or config.get("server", {}).get("disableWebDAV") is not (not webdav_enabled):
        raise DeploymentError("WebDAV configuration differs from the explicit prepared decision")
    image = inspect_image(metadata["image_ref"])
    if image["Id"] != metadata["image_id"] or image.get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != metadata["source_sha"]:
        raise DeploymentError("image identity/revision changed; stop and inspect instead of silently upgrading")
    command = ["bash", str(paths.assets / "validate.sh"), "--env-file", str(paths.env), "--mode", metadata["mode"], "--hostname", socket.gethostname()]
    if metadata.get("test_disk"):
        command += ["--test-disk"]
    elif metadata.get("raid_confirmed"):
        command += ["--raid-confirmed"]
    else:
        raise DeploymentError("storage evidence is absent from deployment metadata")
    if metadata["exposure"] in ("lan", "debug"):
        command += ["--" + metadata["exposure"]]
    run(command)


def tls_inputs(args) -> dict[str, bytes]:
    if not args.lan_bind_address or args.lan_port is None or not args.lan_allowed_cidrs or not args.tls_name:
        raise DeploymentError("LAN requires an explicit IPv4 address, unprivileged port, client CIDRs and TLS name")
    address = ipaddress.ip_address(args.lan_bind_address)
    if address.version != 4 or address.is_unspecified or address.is_loopback or address.is_multicast or not 1024 <= args.lan_port <= 65535:
        raise DeploymentError("LAN address must be a specific non-loopback IPv4 address and port 1024-65535")
    for cidr in args.lan_allowed_cidrs.split(","):
        network = ipaddress.ip_network(cidr, strict=True)
        if network.version != 4 or network.prefixlen == 0:
            raise DeploymentError("LAN source CIDRs must be explicit IPv4 networks narrower than /0")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", args.tls_name):
        raise DeploymentError("invalid TLS server name")
    result = {}
    for name, source in (("server.crt", args.tls_cert_file), ("server.key", args.tls_key_file), ("ca.crt", args.tls_ca_file)):
        if source is None:
            raise DeploymentError("LAN requires protected server certificate, private key and CA files")
        assert_safe_path(source, owner=0)
        mode = stat.S_IMODE(source.stat().st_mode)
        if (name == "server.key" and mode not in (0o400, 0o600)) or mode & 0o022 or source.stat().st_size > 1024 * 1024:
            raise DeploymentError("TLS source ownership, permissions or size is invalid")
        result[name] = source.read_bytes()
    run(["openssl", "verify", "-CAfile", str(args.tls_ca_file), str(args.tls_cert_file)])
    try:
        ipaddress.ip_address(args.tls_name)
        check = "-checkip"
    except ValueError:
        check = "-checkhost"
    run(["openssl", "x509", "-in", str(args.tls_cert_file), "-noout", "-checkend", "86400", check, args.tls_name])
    public_cert = run(["openssl", "x509", "-in", str(args.tls_cert_file), "-pubkey", "-noout"])
    public_key = run(["openssl", "pkey", "-in", str(args.tls_key_file), "-pubout", "-passin", "file:/dev/null"])
    if public_cert != public_key:
        raise DeploymentError("TLS certificate and unencrypted private key do not match")
    return result


def configure_source(value: dict, exposure: str, allowed_cidrs: list[str], enable_share_source: bool, enable_webdav: bool = False) -> None:
    sources = value.get("server", {}).get("sources", [])
    if len(sources) != 1:
        raise DeploymentError("the shared-host template must have exactly one managed source")
    sources[0]["config"]["private"] = not enable_share_source
    value["server"]["disableWebDAV"] = not enable_webdav
    if exposure == "lan":
        value["server"]["allowedClientCIDRs"] = ["127.0.0.1/32"] + allowed_cidrs


def prepare(paths: Paths, args) -> None:
    source_checks(paths, args.source_sha)
    validate_image_reference(args.image_ref, args.mode)
    if args.test_disk and args.mode != "staging":
        raise DeploymentError("--test-disk is only valid for isolated Staging; it is not RAID evidence")
    if not args.test_disk and not args.raid_confirmed:
        raise DeploymentError("record either --test-disk or separately reviewed --raid-confirmed evidence")
    if paths.metadata.exists():
        existing = load_metadata(paths)
        if any(existing.get(key) != value for key, value in {"source_sha": args.source_sha, "image_ref": args.image_ref, "mode": args.mode, "exposure": args.exposure}.items()) or existing.get("enable_share_source", False) != args.enable_share_source or existing.get("enable_webdav", False) != args.enable_webdav:
            raise DeploymentError("existing deployment inputs differ; prepare never upgrades or overwrites them")
        validate_deployment(paths, existing)
        print("[shared-host prepare] existing valid deployment retained; no secrets or data changed")
        return
    assert_empty_install(paths)
    assert_stopped(paths, args.exposure)
    for parent in (paths.config.parent, paths.data.parent, paths.cache.parent, paths.storage):
        assert_safe_path(parent, owner=0, directory=True)
        if parent.stat().st_mode & 0o022:
            raise DeploymentError(f"unsafe installation parent: {parent}")
    image = inspect_image(args.image_ref)
    if image.get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != args.source_sha:
        raise DeploymentError("the image revision label must match the fixed checkout")
    if args.bootstrap_password_file is None:
        raise DeploymentError("--bootstrap-password-file is required; retain its protected independent copy for admin login")
    password = protected_secret(args.bootstrap_password_file)
    tls = tls_inputs(args) if args.exposure == "lan" else {}
    template = paths.assets / ("config.lan.yaml.example" if args.exposure == "lan" else "config.yaml.example")
    assert_safe_path(template, owner=0)
    config = template.read_bytes()
    if args.exposure == "lan" or args.enable_share_source or args.enable_webdav:
        import yaml
        config_value = yaml.safe_load(config)
        configure_source(config_value, args.exposure, args.lan_allowed_cidrs.split(",") if args.exposure == "lan" else [], args.enable_share_source, args.enable_webdav)
        config = yaml.safe_dump(config_value, sort_keys=False, allow_unicode=True).encode()
    values = read_env(paths.assets / "compose.env.example")
    values.update(FILEBROWSER_IMAGE=args.image_ref, FILEBROWSER_BUILD_IMAGE=args.image_ref, BUILD_REVISION=args.source_sha, BUILD_VERSION="fixed-" + args.source_sha)
    if args.exposure == "lan":
        values.update(LAN_BIND_IP=args.lan_bind_address, LAN_PORT=str(args.lan_port), LAN_TLS_SERVER_NAME=args.tls_name, LAN_ALLOW_CIDRS=args.lan_allowed_cidrs)
    metadata = {"version": 1, "source_sha": args.source_sha, "image_ref": args.image_ref, "image_id": image["Id"], "mode": args.mode, "exposure": args.exposure, "test_disk": args.test_disk, "raid_confirmed": args.raid_confirmed, "bootstrap_complete": False, "admin_username": "admin", "enable_share_source": args.enable_share_source, "enable_webdav": args.enable_webdav}
    if args.exposure == "lan":
        metadata["tls_name"] = args.tls_name
    # Failures from this point preserve a recognizable partial installation.
    # A rerun cannot fill it with a different secret or adopt existing data.
    create_directory(paths.config, 0o750, group=GID)
    create_directory(paths.config / "secrets", 0o750, group=GID)
    create_directory(paths.data, 0o750, UID, GID)
    create_directory(paths.cache, 0o750, UID, GID)
    create_directory(paths.storage_project, 0o750, group=GID)
    create_directory(paths.files, 0o750, UID, GID)
    create_directory(paths.backups, 0o700)
    write_new(paths.env, ("\n".join(key + "=" + value for key, value in values.items()) + "\n").encode(), 0o600)
    write_new(paths.config / "config.yaml", config, 0o640, group=GID)
    for name in ("jwt_token_secret", "totp_secret"):
        write_new(paths.config / "secrets" / name, secrets.token_hex(32).encode() + b"\n", 0o440, group=GID)
    write_new(paths.bootstrap, password + b"\n", 0o440, group=GID)
    identity = secrets.token_hex(32).encode() + b"\n"
    write_new(paths.config / "storage.identity", identity, 0o440, group=GID)
    write_new(paths.storage_project / ".storage-identity", identity, 0o440, group=GID)
    if tls:
        create_directory(paths.config / "tls", 0o750, group=GID)
        for name, value in tls.items():
            write_new(paths.config / "tls" / name, value, 0o440, group=GID)
    save_metadata(paths, metadata)
    validate_deployment(paths, metadata)
    print("[shared-host prepare] paths, configuration, storage identity and secrets prepared; service remains stopped")


def start_service(paths: Paths, metadata: dict) -> None:
    validate_deployment(paths, metadata)
    command = compose_command(paths, metadata["exposure"])
    run(command + ["up", "-d", "--no-build", "--pull", "never", SERVICE])
    container_id, image_id = container_identity(paths, metadata["exposure"])
    if image_id != metadata["image_id"]:
        run(["docker", "stop", "--time", "60", container_id])
        raise DeploymentError("started Image ID differs from pinned metadata; unexpected container stopped")
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        container = json.loads(run(["docker", "inspect", container_id]))[0]
        if container.get("State", {}).get("Health", {}).get("Status") == "healthy":
            return
        if container.get("State", {}).get("Status") in ("exited", "dead"):
            break
        time.sleep(2)
    raise DeploymentError("service did not become healthy; preserve container/data and inspect protected logs")


def curl_config(url: str, headers: dict[str, str], *, post: bool = False, tls_name: str | None = None) -> bytes:
    lines = ["fail", "silent", "show-error", "max-time = 20", "noproxy = \"*\"", "url = " + json.dumps(url)]
    if post:
        lines.append("request = \"POST\"")
    if tls_name:
        lines += ["cacert = \"/etc/filebrowser-enterprise/tls/ca.crt\"", "resolve = " + json.dumps(tls_name + ":8080:127.0.0.1")]
    lines += ["header = " + json.dumps(key + ": " + value) for key, value in headers.items()]
    return ("\n".join(lines) + "\n").encode()


def verify_admin(container_id: str, password: bytes, username: str, metadata: dict) -> None:
    tls_name = metadata.get("tls_name") if metadata["exposure"] == "lan" else None
    base = f"https://{tls_name}:8080" if tls_name else "http://127.0.0.1:8080"
    login_config = curl_config(base + "/api/auth/login?username=" + urllib.parse.quote(username, safe=""), {"X-Password": urllib.parse.quote(password.decode("utf-8"), safe="")}, post=True, tls_name=tls_name)
    # Normal application password login. The response/session exists only in
    # process memory and the next curl's stdin, never arguments, logs or files.
    token = run(["docker", "exec", "--interactive", container_id, "curl", "--config", "-"], login_config).decode().strip()
    if not token or re.search(r"[\s\x00-\x1f\x7f\"\\;]", token):
        raise DeploymentError("administrator login did not return a valid session")
    user_config = curl_config(base + "/api/users?id=self", {"Cookie": "filebrowser_quantum_jwt=" + token}, tls_name=tls_name)
    user = json.loads(run(["docker", "exec", "--interactive", container_id, "curl", "--config", "-"], user_config))
    if user.get("username") != username or user.get("permissions", {}).get("admin") is not True:
        raise DeploymentError("authenticated account does not have administrator permission")


def finish_bootstrap(paths: Paths, metadata: dict, username: str, password_file: Path | None = None) -> None:
    database = paths.data / "database.db"
    if not database.is_file() or database.is_symlink() or database.stat().st_size == 0:
        raise DeploymentError("bootstrap-finish requires an initialized regular database")
    present = paths.bootstrap.exists() or paths.bootstrap.is_symlink()
    if metadata["bootstrap_complete"]:
        if present:
            raise DeploymentError("completed initialization must not have a residual bootstrap secret")
        print("[shared-host bootstrap-finish] initialization already complete; nothing changed")
        return
    if present:
        password = protected_secret(paths.bootstrap, installed=True)
    elif password_file:
        password = protected_secret(password_file)
    else:
        raise DeploymentError("bootstrap file is absent after an interrupted finish; start the pinned image and retry with --admin-password-file")
    container_id, image_id = container_identity(paths, metadata["exposure"])
    if image_id != metadata["image_id"]:
        raise DeploymentError("bootstrap container does not use the pinned Image ID")
    with phase("administrator verification before bootstrap removal"):
        verify_admin(container_id, password, username, metadata)
    if present:
        with phase("controlled bootstrap stop"):
            run(compose_command(paths, metadata["exposure"]) + ["stop", SERVICE])
            assert_stopped(paths, metadata["exposure"])
        with phase("bootstrap file removal"):
            paths.bootstrap.unlink()
        # The original DB and both persistent secrets remain untouched. The
        # unchanged entrypoint will refuse any accidentally restored bootstrap.
        with phase("same-image restart after bootstrap removal"):
            start_service(paths, metadata)
            container_id, image_id = container_identity(paths, metadata["exposure"])
            if image_id != metadata["image_id"]:
                raise DeploymentError("bootstrap restart changed the pinned Image ID")
        with phase("administrator verification after bootstrap removal"):
            verify_admin(container_id, password, username, metadata)
    metadata["bootstrap_complete"] = True
    metadata["admin_username"] = username
    save_metadata(paths, metadata)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "prepare", "validate", "start", "bootstrap-finish", "stop", "status"))
    parser.add_argument("--hostname", required=True, help="confirm the isolated target host")
    parser.add_argument("--source-sha")
    parser.add_argument("--image-ref")
    parser.add_argument("--mode", choices=("staging", "candidate", "production"), default="staging")
    parser.add_argument("--exposure", choices=("base", "debug", "lan"), default="base")
    evidence = parser.add_mutually_exclusive_group()
    evidence.add_argument("--test-disk", action="store_true", help="isolated staging disk evidence; never claims RAID validation")
    evidence.add_argument("--raid-confirmed", action="store_true", help="assert separately recorded RAID validation")
    parser.add_argument("--enable-share-source", action="store_true", help="explicitly permit sharing from this source; user Share permission remains disabled by default")
    parser.add_argument("--enable-webdav", action="store_true", help="explicitly enable the existing WebDAV endpoint; existing user and Token permissions still apply")
    parser.add_argument("--bootstrap-password-file", type=Path)
    parser.add_argument("--admin-password-file", type=Path, help="retained protected input for interrupted bootstrap-finish recovery")
    parser.add_argument("--admin-username", default="admin")
    parser.add_argument("--lan-bind-address")
    parser.add_argument("--lan-port", type=int)
    parser.add_argument("--lan-allowed-cidrs")
    parser.add_argument("--tls-name")
    parser.add_argument("--tls-cert-file", type=Path)
    parser.add_argument("--tls-key-file", type=Path)
    parser.add_argument("--tls-ca-file", type=Path)
    args = parser.parse_args()
    paths = Paths()
    try:
        host_checks(args.hostname, paths, require_storage=args.action not in ("stop", "status"))
        if args.action == "check":
            print("[shared-host check] Debian, local Docker, dependencies, independent mount and identity checks passed; RAID not inspected")
            return 0
        with deployment_lock():
            if args.action == "prepare":
                if not args.source_sha or not args.image_ref:
                    raise DeploymentError("prepare requires --source-sha and --image-ref")
                prepare(paths, args)
                return 0
            metadata = load_metadata(paths)
            if args.action == "validate":
                validate_deployment(paths, metadata)
            elif args.action == "start":
                start_service(paths, metadata)
            elif args.action == "bootstrap-finish":
                source_checks(paths, metadata["source_sha"])
                finish_bootstrap(paths, metadata, args.admin_username, args.admin_password_file)
            elif args.action == "stop":
                source_checks(paths, metadata["source_sha"])
                assert_safe_path(paths.env, owner=0, group=0, mode=0o600)
                run(compose_command(paths, metadata["exposure"]) + ["stop", SERVICE])
                assert_stopped(paths, metadata["exposure"])
            elif args.action == "status":
                containers = project_containers()
                print(json.dumps({"project": PROJECT, "source_sha": metadata["source_sha"], "image_id": metadata["image_id"], "bootstrap_complete": metadata["bootstrap_complete"], "containers": [{"id": value["Id"], "image_id": value["Image"], "status": value.get("State", {}).get("Status"), "health": value.get("State", {}).get("Health", {}).get("Status")} for value in containers]}, sort_keys=True))
            print(f"[shared-host {args.action}] completed")
        return 0
    except (DeploymentError, OSError, ValueError, KeyError) as error:
        # JSON parser/value errors may include sensitive response bodies. Only
        # our explicitly safe messages are returned to an operator.
        detail = str(error) if isinstance(error, DeploymentError) else "invalid/incomplete state or I/O failure; preserve the installation for inspection"
        print(f"[shared-host {args.action}] ERROR: {detail}; existing data retained", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
