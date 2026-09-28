"""Immutable source pins and isolation shared by explicit compatibility probes.

This module imports only the standard library. It never imports an installed
Hermes, reads a user profile, repairs ACLs, or enables a product plugin.
"""
from __future__ import annotations

import errno
import hashlib
import json
import mimetypes
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
import stat
from urllib.parse import unquote, urlsplit
import zipfile


HERE = Path(__file__).resolve().parent
_catalog = json.loads((HERE / "hermes_versions.json").read_text(encoding="utf-8"))
DEFAULT_HERMES_COMMIT = _catalog["default_commit"]
VERSIONS = _catalog["versions"]


def verify_source(source: Path, commit: str = DEFAULT_HERMES_COMMIT,
                  archive: Path | None = None) -> str:
    """Check the selected version independently; never infer it from filenames."""
    if commit not in VERSIONS:
        raise ValueError("Unsupported pinned Hermes commit")
    version = VERSIONS[commit]
    if archive is None and version["archive_required"]:
        raise ValueError("This Hermes version requires its independently pinned full source archive")
    if archive is not None:
        with Path(archive).open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != version["archive_sha256"]:
            raise ValueError("Pinned Hermes archive SHA-256 mismatch")
        verify_archive_tree(Path(source), Path(archive), commit)
    source = Path(source)
    for relative, expected in version["blobs"].items():
        path = source / relative
        if path.is_symlink():
            raise ValueError("Pinned Hermes source must contain ordinary files: " + relative)
        data = path.read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        if actual != expected:
            raise ValueError("Hermes source mismatch at " + relative + "; require " + commit)
    return commit


def verify_archive_tree(source: Path, archive: Path, commit: str) -> None:
    """Bind every extracted file to the fixed ZIP, including imported helpers."""
    expected_files, expected_directories, entries = set(), {""}, {}
    root_name = "hermes-agent-" + commit

    def ordinary(path, directory):
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                or (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) is not True):
            raise ValueError("Pinned Hermes source has a reparse or unexpected node")
        return info

    ordinary(source, True)
    with zipfile.ZipFile(archive) as bundle:
        for entry in bundle.infolist():
            parts = PurePosixPath(entry.filename).parts
            if (not parts or parts[0] != root_name or ".." in parts
                    or PurePosixPath(entry.filename).is_absolute()
                    or stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError("Pinned Hermes archive has an unsupported entry")
            relative = PurePosixPath(*parts[1:]).as_posix() if len(parts) > 1 else ""
            if entry.is_dir():
                expected_directories.add(relative)
                continue
            if not relative or relative in expected_files:
                raise ValueError("Pinned Hermes archive contains duplicate file entries")
            expected_files.add(relative)
            entries[relative] = entry
            parent = PurePosixPath(relative).parent
            while str(parent) != ".":
                expected_directories.add(parent.as_posix())
                parent = parent.parent
    actual_files, actual_directories = set(), {""}
    for parent, directories, files in os.walk(source, followlinks=False):
        for name in directories:
            path = Path(parent) / name
            ordinary(path, True)
            actual_directories.add(path.relative_to(source).as_posix())
        for name in files:
            path = Path(parent) / name
            ordinary(path, False)
            actual_files.add(path.relative_to(source).as_posix())
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ValueError("Extracted Hermes tree contains missing or extra entries")
    with zipfile.ZipFile(archive) as bundle:
        for relative, entry in entries.items():
            path = source.joinpath(*PurePosixPath(relative).parts)
            before = ordinary(path, False)
            if before.st_size != entry.file_size:
                raise ValueError("Extracted Hermes file size differs from archive: " + relative)
            with bundle.open(entry) as archived, path.open("rb") as extracted:
                if hashlib.file_digest(archived, "sha256").digest() != hashlib.file_digest(extracted, "sha256").digest():
                    raise ValueError("Extracted Hermes file differs from archive: " + relative)
            after = ordinary(path, False)
            if not os.path.samestat(before, after) or before.st_size != after.st_size:
                raise ValueError("Extracted Hermes file changed while verifying: " + relative)


def isolated_environment(sandbox: Path, extra: dict | None = None) -> dict:
    """Prepare only a caller-owned sandbox; do not inherit PATH or credentials."""
    sandbox = Path(sandbox).resolve(strict=True)
    # Hermes stops context discovery at the nearest .git. This empty marker
    # belongs only to the new sandbox; it is not a checkout or a Git command.
    boundary = sandbox / ".git"
    boundary.mkdir(mode=0o700, exist_ok=True)
    _assert_discovery_boundary(sandbox)
    home, user, temporary = sandbox / "profile", sandbox / "user", sandbox / "temp"
    for directory in (home, user, user / "AppData", user / "LocalAppData",
                      temporary, sandbox / "empty-bundled"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = {key: value for key, value in os.environ.items() if key.upper() in {"SYSTEMROOT", "WINDIR"}}
    paths = [Path(sys.executable).resolve().parent, Path(sys.prefix) / "Scripts",
             Path(sys.base_prefix), Path(sys.base_prefix) / "Scripts"]
    if os.name == "nt":
        system = Path(env["SYSTEMROOT"])
        paths.extend((system / "System32", system))
    else:
        paths.extend((Path(sys.base_prefix) / "bin", Path("/usr/bin"), Path("/bin")))
    env.update({"PATH": os.pathsep.join(dict.fromkeys(str(path) for path in paths)),
        "HERMES_HOME": str(home), "HERMES_BUNDLED_PLUGINS": str(sandbox / "empty-bundled"),
        "HERMES_ENABLE_PROJECT_PLUGINS": "false", "HERMES_TEST_ISOLATION": "1",
        "HOME": str(user), "USERPROFILE": str(user), "APPDATA": str(user / "AppData"),
        "LOCALAPPDATA": str(user / "LocalAppData"), "TEMP": str(temporary), "TMP": str(temporary),
        "TMPDIR": str(temporary), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"})
    if extra:
        if any(key.upper() in {name.upper() for name in env} for key in extra):
            raise ValueError("Probe extras cannot override the isolated process environment")
        env.update(extra)
    return env


def _assert_discovery_boundary(sandbox: Path) -> None:
    boundary = sandbox / ".git"
    info = boundary.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400 or any(boundary.iterdir())):
        raise RuntimeError("Compatibility sandbox requires its own empty discovery boundary")


def assert_isolated_environment(sandbox: Path) -> None:
    sandbox = Path(sandbox).resolve(strict=True)
    _assert_discovery_boundary(sandbox)
    expected = {"HERMES_HOME": sandbox / "profile", "HOME": sandbox / "user",
        "USERPROFILE": sandbox / "user", "APPDATA": sandbox / "user/AppData",
        "LOCALAPPDATA": sandbox / "user/LocalAppData", "TEMP": sandbox / "temp",
        "TMP": sandbox / "temp", "TMPDIR": sandbox / "temp",
        "HERMES_BUNDLED_PLUGINS": sandbox / "empty-bundled"}
    if Path.cwd().resolve() != sandbox or os.environ.get("HERMES_TEST_ISOLATION") != "1":
        raise RuntimeError("Compatibility child was not started in its isolated profile")
    for key, path in expected.items():
        if not path.is_dir() or Path(os.environ.get(key, "")).resolve() != path:
            raise RuntimeError("Compatibility child isolation is incomplete: " + key)


def bootstrap_system_metadata() -> None:
    """Cache real stdlib OS facts after HOME redirection, before task auditing."""
    mimetypes.init()
    platform.system()
    platform.processor()
    platform.platform()


class AuditViolations(list):
    def __init__(self):
        super().__init__()
        self.system_reads = set()
        self.platform_probes_denied = []


def sqlite_access_allowed(path, sandbox: Path) -> bool:
    """Allow only the probe's own regular DB or its exact read-only file URI."""
    try:
        raw = os.fsdecode(path)
        if raw == ":memory:":
            return True
        readonly_uri = raw.startswith("file:")
        if readonly_uri:
            uri = urlsplit(raw)
            canonical = raw.startswith("file:///")
            # The old pinned SessionDB uses file:<absolute native path>;
            # the newer release uses Path.as_uri(). Both reach the same
            # ordinary-file and sandbox checks below, never a relative URI.
            if (uri.scheme != "file" or uri.netloc or uri.query != "mode=ro"
                    or uri.fragment or ("\\" in uri.path and (canonical or os.name != "nt"))):
                return False
            raw = unquote(uri.path, encoding="utf-8", errors="strict")
            if canonical and os.name == "nt" and len(raw) > 3 and raw[0] == "/" and raw[2] == ":":
                raw = raw[1:]
        if (not raw or any(ord(character) < 32 for character in raw)
                or raw.startswith(("\\\\", "//"))
                or any(part in {".", ".."} for part in raw.replace("\\", "/").split("/"))):
            return False
        candidate, sandbox = Path(raw), Path(sandbox)
        if not candidate.is_absolute() or not sandbox.is_absolute():
            return False
        root_info = sandbox.lstat()
        if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
                or getattr(root_info, "st_file_attributes", 0) & 0x400):
            return False
        relative = candidate.relative_to(sandbox)
        if not relative.parts:
            return False
        cursor = sandbox
        for index, part in enumerate(relative.parts):
            cursor = cursor / part
            final = index == len(relative.parts) - 1
            try:
                info = cursor.lstat()
            except FileNotFoundError:
                if not final or readonly_uri:
                    return False
                break
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                return False
            if not (stat.S_ISREG(info.st_mode) if final else stat.S_ISDIR(info.st_mode)):
                return False
        return candidate.resolve(strict=readonly_uri).is_relative_to(sandbox.resolve(strict=True))
    except (OSError, ValueError, TypeError):
        return False


def audit_path_within(path, allowed, *, allow_extended=False) -> bool:
    """Compare a canonical Win32 long-path alias to the SAME allowed roots."""
    try:
        raw = os.fsdecode(path)
        extended = os.name == "nt" and raw.startswith("\\\\?\\")
        if extended:
            if not allow_extended:
                return False
            raw = raw[4:]
            if not re.match(r"^[A-Za-z]:\\", raw) or "/" in raw:
                return False
            if any(not part or part in {".", ".."} or part[-1] in ". "
                   or any(ord(character) < 32 or character in '<>:"|?*' for character in part)
                   for part in raw[3:].split("\\")):
                return False
        value = Path(os.path.abspath(raw))
        if not any(value == root or root in value.parents for root in allowed):
            return False
        if extended:
            # Only equivalent reads of existing ordinary objects are accepted.
            # Inspect root-to-leaf without resolve() or following a junction.
            for part in reversed((value, *value.parents)):
                info = Path("\\\\?\\" + str(part)).lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    return False
                if not (stat.S_ISREG(info.st_mode) if part == value else stat.S_ISDIR(info.st_mode)):
                    return False
        return True
    except (OSError, ValueError, TypeError):
        return False


def install_audit_guard(sandbox: Path, source: Path, *, worker: Path | None = None,
                        allow_network: bool = False, allowed_subprocess=None,
                        extra_read_roots=()) -> AuditViolations:
    """Guard before any Hermes import; optional callers may allow exact helpers."""
    sandbox, source = Path(sandbox).resolve(), Path(source).resolve()
    worker = Path(worker).resolve() if worker is not None else None
    roots = (sandbox, source, HERE, Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve(),
             *(Path(root).resolve() for root in extra_read_roots))
    violations = AuditViolations()
    metadata = {"/proc/1/cgroup", "/proc/self/mountinfo", "/proc/stat", "/proc/version",
        "/etc/os-release", "/usr/lib/os-release", "/etc/mime.types", "/etc/localtime",
        "/etc/ssl/certs/ca-certificates.crt", f"/proc/{os.getpid()}/stat"}
    windows_self_stat = os.path.normcase(os.path.abspath(f"/proc/{os.getpid()}/stat"))

    def guard(event, args):
        denied = False
        if event == "open" and not isinstance(args[0], int):
            path, _mode, flags = args
            write = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            if os.name == "nt" and not write and os.path.normcase(os.path.abspath(path)) == windows_self_stat:
                violations.platform_probes_denied.append(os.fsdecode(path))
                raise FileNotFoundError(errno.ENOENT, "Linux self-stat is unavailable on Windows")
            denied = not audit_path_within(path, (sandbox,) if write else roots, allow_extended=not write)
            if not write and (os.fsdecode(path) in metadata or Path(os.path.abspath(path)) == worker):
                denied = False
                if os.fsdecode(path) in metadata:
                    violations.system_reads.add(os.fsdecode(path))
            if not write and flags & getattr(os, "O_DIRECTORY", 0):
                if Path(os.path.abspath(path)) in sandbox.parents:
                    denied = False
            if os.path.normcase(os.fsdecode(path)) == os.path.normcase(os.devnull):
                denied = False
        elif event == "sqlite3.connect":
            denied = not sqlite_access_allowed(args[0], sandbox)
        elif event in {"socket.bind", "socket.connect"}:
            address = args[1]
            denied = (not allow_network or not isinstance(address, tuple)
                      or address[0] not in {"127.0.0.1", "::1"})
        elif event == "socket.getaddrinfo":
            denied = not allow_network or args[0] not in {None, "localhost", "127.0.0.1", "::1"}
        elif event == "subprocess.Popen":
            executable, command, _cwd, environment = args
            native_command = subprocess.list2cmdline([str(worker)]) if os.name == "nt" else [str(worker)]
            allowed = (worker is not None and command == native_command
                       and (executable is None or Path(os.path.abspath(executable)) == worker))
            if not allowed and allowed_subprocess is not None:
                allowed = allowed_subprocess(executable, command, environment or {}) is True
            denied = not allowed
        elif event in {"os.system", "os.exec", "os.posix_spawn"}:
            denied = True
        if denied:
            detail = {"event": event}
            if event in {"open", "sqlite3.connect"}:
                detail["path"] = os.fsdecode(args[0])
            # Retain only file/function/line diagnostics; never subprocess
            # arguments, headers, environment values or frame locals.
            callers = []
            frame = sys._getframe(1)
            for _ in range(5):
                if frame is None:
                    break
                callers.append({"file": frame.f_code.co_filename,
                                "function": frame.f_code.co_name, "line": frame.f_lineno})
                frame = frame.f_back
            del frame
            detail["callers"] = callers
            violations.append(detail)
            raise RuntimeError("Compatibility audit denied " + event)

    sys.addaudithook(guard)
    return violations
