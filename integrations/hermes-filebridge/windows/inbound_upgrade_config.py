"""Narrow, offline configuration planner. Never imports Hermes or a plugin.

Configuration text stays in the input file and, only when requested, a private
candidate file. stdout contains bounded metadata, never configuration values.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile


TOOL = "filebrowser_read_inbound"
TOOLSET = "cf_filebridge_inbound_content"
MAX_CONFIG = 2 * 1024 * 1024
SAFE_STAGES = frozenset({"config_semantic_plan", "runtime_dependencies", "runtime_extract_wheels", "runtime_inventory"})
SAFE_ERRORS = frozenset({
    "absolute_path_required", "reparse_refused", "input_size_or_type", "yaml_mapping_required",
    "plugin_version_conflict", "existing_plugin_not_enabled", "existing_inbound_not_enabled",
    "existing_host_settings_missing", "existing_host_settings_incomplete", "existing_profile_revision_invalid",
    "existing_worker_digest_invalid", "consumer_allowlist_missing", "api_toolsets_missing", "runtime_pin_invalid",
    "yaml_alias_changes_unrelated_settings", "candidate_size_exceeded", "candidate_roundtrip_failed",
    "dependency_inventory_invalid", "dependency_inventory_incomplete", "runtime_reparse_refused",
    "runtime_size_exceeded", "runtime_node_refused", "runtime_empty", "checkpoint_conflict",
    "wheels_directory_required", "wheel_archive_shape", "wheel_archive_member", "wheel_archive_size",
    "runtime_modified_or_unknown", "candidate_absolute_required", "prepared_candidate_conflict",
    "configuration_plan_failed", "platform_toolsets_invalid", "api_toolsets_invalid",
    "known_plugin_toolsets_invalid", "agent_configuration_invalid", "disabled_toolsets_invalid",
    "content_toolset_disabled",
})
_failure_stage = "config_semantic_plan"


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit=MAX_CONFIG):
    path = Path(path)
    need(path.is_absolute(), "absolute_path_required")
    for node in (path, *path.parents):
        info = node.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
             "reparse_refused")
    need(path.is_file() and path.stat().st_size <= limit, "input_size_or_type")
    return path.read_bytes()


def _string_selection(value, code, *, scalar=False):
    """Inspect supported names without rewriting the operator's representation.

    The fixed official reader also understands Python/JSON list-literal strings.
    Malformed/mixed lists are refused here rather than guessing at permissions.
    """
    if value is None:
        return None
    if isinstance(value, str):
        if value.strip().startswith("["):
            try:
                value = ast.literal_eval(value.strip())
            except (ValueError, SyntaxError):
                raise Refused(code) from None
        elif scalar:
            value = [value]
    need(isinstance(value, list) and all(isinstance(name, str) for name in value), code)
    return value


def check_content_selection(document):
    """Keep official default/empty/explicit/MCP/custom selection semantics.

    Newly discovered plugin toolsets are enabled by the official loader unless
    known-and-omitted or globally disabled. Materializing a default selection
    changes its meaning, so no platform or known-toolset field is ever written.
    This does not replace Hermes' final tool-level global suppression.
    """
    platforms = document.get("platform_toolsets")
    need(platforms is None or isinstance(platforms, dict), "platform_toolsets_invalid")
    selected = _string_selection((platforms or {}).get("api_server"), "api_toolsets_invalid")
    known = document.get("known_plugin_toolsets")
    need(known is None or isinstance(known, dict), "known_plugin_toolsets_invalid")
    known_api = (known or {}).get("api_server", [])
    if known_api is None:
        known_api = []  # Official empty-known-set semantics; leave YAML null untouched.
    need(isinstance(known_api, list) and all(isinstance(name, str) for name in known_api),
         "known_plugin_toolsets_invalid")
    need(TOOLSET not in known_api or TOOLSET in (selected or []), "content_toolset_disabled")
    agent = document.get("agent")
    need(agent is None or isinstance(agent, dict), "agent_configuration_invalid")
    disabled = _string_selection((agent or {}).get("disabled_toolsets"), "disabled_toolsets_invalid", scalar=True)
    need(not {name.strip() for name in disabled or []} & {TOOLSET, TOOL, "all", "*"},
         "content_toolset_disabled")


def build(config_bytes, installed_manifest, release_manifest, runtime=None, runtime_sha256=None):
    # Round-trip YAML preserves comments, quotes and unrelated settings. Never
    # rewrite YAML with a regexp, string replacement, or a Hermes core import.
    from ruamel.yaml import YAML
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    yaml.allow_duplicate_keys = False
    config = yaml.load(config_bytes.decode("utf-8-sig"))
    old = yaml.load(installed_manifest.decode("utf-8-sig"))
    release = yaml.load(release_manifest.decode("utf-8-sig"))
    need(isinstance(config, dict) and isinstance(old, dict) and isinstance(release, dict), "yaml_mapping_required")
    need(old.get("name") == release.get("name") == "cf-filebridge"
         and str(old.get("version")) in {"0.3.0", "0.4.0"}
         and str(release.get("version")) == "0.4.0", "plugin_version_conflict")
    # JSON conversion rejects custom YAML scalar tags and cyclic aliases. It
    # also breaks shared aliases for the independent semantic-change check.
    original = json.loads(json.dumps(config))
    expected = copy.deepcopy(original)

    def patch(document):
        plugins = document.get("plugins", {})
        need(isinstance(plugins, dict) and "cf-filebridge" in plugins.get("enabled", [])
             and "cf-filebridge" not in plugins.get("disabled", []), "existing_plugin_not_enabled")
        settings = plugins.get("entries", {}).get("cf-filebridge", {}).get("settings")
        need(isinstance(settings, dict) and settings.get("inbound_enabled") is True
             and settings.get("inbound_host_enabled") is True, "existing_inbound_not_enabled")
        host = settings.get("inbound_host")
        need(isinstance(host, dict), "existing_host_settings_missing")
        for key in ("gateway_origin", "service_token_env", "profile_reference", "work_root",
                    "client_path", "client_sha256"):
            need(isinstance(host.get(key), str) and bool(host[key]), "existing_host_settings_incomplete")
        need(type(host.get("profile_revision")) is int and host["profile_revision"] > 0,
             "existing_profile_revision_invalid")
        need(re.fullmatch(r"[0-9a-fA-F]{64}", host["client_sha256"]), "existing_worker_digest_invalid")
        consumers = host.setdefault("consumer_tools", [])
        need(isinstance(consumers, list) and all(isinstance(value, str) for value in consumers),
             "consumer_allowlist_missing")
        check_content_selection(document)
        settings["inbound_content_enabled"] = True
        if runtime:
            need(Path(runtime).is_absolute() and re.fullmatch(r"[0-9a-f]{64}", runtime_sha256 or ""), "runtime_pin_invalid")
            settings["inbound_content_python"] = runtime
            settings["inbound_content_python_sha256"] = runtime_sha256
        if TOOL not in consumers:
            consumers.append(TOOL)

    patch(expected)
    candidate = copy.deepcopy(config)
    patch(candidate)
    need(json.loads(json.dumps(candidate)) == expected, "yaml_alias_changes_unrelated_settings")
    stream = io.StringIO()
    yaml.dump(candidate, stream)
    encoded = stream.getvalue().encode("utf-8")
    need(len(encoded) <= MAX_CONFIG, "candidate_size_exceeded")
    # Verify the actual emitted document, not only the in-memory mapping.
    need(json.loads(json.dumps(yaml.load(encoded.decode("utf-8")))) == expected, "candidate_roundtrip_failed")
    host = original["plugins"]["entries"]["cf-filebridge"]["settings"]["inbound_host"]
    return encoded, host["client_path"], host["client_sha256"].lower()


def requirements(data):
    required = {}
    logical = ""
    for line in data.decode("utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        logical += " " + line.removesuffix("\\").rstrip()
        if line.endswith("\\"):
            continue
        match = re.fullmatch(r"\s*([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+]*)(?:\s+--hash=sha256:[0-9a-f]{64})+", logical)
        need(match and re.sub(r"[-_.]+", "-", match[1]).lower() not in
             {re.sub(r"[-_.]+", "-", name).lower() for name in required}, "dependency_inventory_invalid")
        required[match[1]] = match[2]
        logical = ""
    need(not logical and required and len(required) <= 64, "dependency_inventory_incomplete")
    return required


def dependencies(data):
    required = requirements(data)
    missing = []
    for name, version in required.items():
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            installed = None
        if installed != version:
            missing.append({"name": name, "required_version": version})
    return missing


def runtime_files(root):
    files = {}
    directories = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400, "runtime_reparse_refused")
        if path.is_file():
            need(info.st_size <= 64 * 1024 * 1024 and len(files) < 20000, "runtime_size_exceeded")
            files[path.relative_to(root).as_posix()] = digest(path.read_bytes())
        else:
            need(path.is_dir(), "runtime_node_refused")
            directories.append(path.relative_to(root).as_posix())
    need(files, "runtime_empty")
    return {"files": files, "directories": directories}


def save_new(path, data):
    if path.exists():
        need(read(path, max(MAX_CONFIG, len(data))) == data, "checkpoint_conflict")
    else:
        with path.open("xb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())


def runtime_mode(args):
    required = read(args.requirements)
    requirements(required)
    if args.extract_wheels:
        need(args.wheels.is_absolute() and args.wheels.is_dir(), "wheels_directory_required")
        total = 0
        with zipfile.ZipFile(args.wheel_archive) as archive:
            infos = archive.infolist()
            need(0 < len(infos) <= 128 and len({item.filename for item in infos}) == len(infos), "wheel_archive_shape")
            for item in infos:
                need(re.fullmatch(r"[A-Za-z0-9_.+!-]+\.whl", item.filename)
                     and not item.is_dir() and ((item.external_attr >> 16) & 0o170000) in {0, stat.S_IFREG}, "wheel_archive_member")
                total += item.file_size
                need(item.file_size <= 64 * 1024 * 1024 and total <= 256 * 1024 * 1024, "wheel_archive_size")
                save_new(args.wheels / item.filename, archive.read(item))
        print(json.dumps({"ok": True, "wheels": len(infos)}))
        return
    if args.runtime_receipt:
        current = {"schema": "cf-inbound-parser-runtime/v1", "requirements_sha256": digest(required),
                   **runtime_files(args.runtime_root)}
        encoded = (json.dumps(current, sort_keys=True) + "\n").encode()
        if args.verify_runtime:
            need(json.loads(read(args.runtime_receipt)) == current, "runtime_modified_or_unknown")
        else:
            save_new(args.runtime_receipt, encoded)
        print(json.dumps({"ok": True, "runtime_verified": True}))
        return
    missing = dependencies(required)
    print(json.dumps({"ok": True, "dependency_ready": not missing, "dependency_blockers": missing,
                      "python_version": list(sys.version_info[:3])}))


def main():
    global _failure_stage
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "installed-manifest", "release-manifest", "requirements"):
        parser.add_argument("--" + name, type=Path, required=name == "requirements")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--runtime-python")
    parser.add_argument("--runtime-sha256")
    parser.add_argument("--dependencies-only", action="store_true")
    parser.add_argument("--extract-wheels", action="store_true")
    parser.add_argument("--wheel-archive", type=Path)
    parser.add_argument("--wheels", type=Path)
    parser.add_argument("--runtime-receipt", type=Path)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--verify-runtime", action="store_true")
    args = parser.parse_args()
    _failure_stage = ("runtime_extract_wheels" if args.extract_wheels else
                      "runtime_inventory" if args.runtime_receipt else
                      "runtime_dependencies" if args.dependencies_only else "config_semantic_plan")
    if args.dependencies_only or args.extract_wheels or args.runtime_receipt:
        runtime_mode(args)
        return
    raw = read(args.config)
    candidate, worker, worker_hash = build(raw, read(args.installed_manifest), read(args.release_manifest),
                                          args.runtime_python, args.runtime_sha256)
    required = requirements(read(args.requirements))
    if args.candidate:
        need(args.candidate.is_absolute(), "candidate_absolute_required")
        if args.candidate.exists():
            need(read(args.candidate) == candidate, "prepared_candidate_conflict")
        else:
            # The parent holds the private destination directory and ancestors.
            with args.candidate.open("xb") as stream:
                stream.write(candidate)
                stream.flush()
                os.fsync(stream.fileno())
    print(json.dumps({"ok": True, "config_before_sha256": digest(raw), "config_after_sha256": digest(candidate),
        "worker_path": worker, "worker_sha256": worker_hash,
        "dependency_blockers": [{"name": name, "required_version": version} for name, version in required.items()],
        "dependency_ready": False,
        "changed_settings": ["inbound_content_enabled", "inbound_host.consumer_tools"]
            + (["inbound_content_python", "inbound_content_python_sha256"] if args.runtime_python else [])}))


def failure_record(error, stage):
    code = str(error) if isinstance(error, Refused) else "configuration_plan_failed"
    return {"ok": False, "stage": stage if stage in SAFE_STAGES else "config_semantic_plan",
            "error": code if code in SAFE_ERRORS else "configuration_plan_failed"}


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # YAML parser exceptions can contain configuration lines. Never print
        # arbitrary exceptions, traceback text, config bodies or environment.
        print(json.dumps(failure_record(error, _failure_stage)))
        raise SystemExit(1) from None
