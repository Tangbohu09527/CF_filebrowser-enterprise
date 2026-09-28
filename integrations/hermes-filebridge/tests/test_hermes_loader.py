"""Explicit, offline integration check against an unmodified Hermes source tree.

Run with --hermes-source; ordinary unittest discovery does not download upstream
code or silently skip this check. This exercises discovery/registration and a
real registry rejection, not an authenticated Gateway dispatch.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


HERMES_COMMIT = "4d55ca91656ac5f83e1506679b7f81e0238e5e16"
# Git blob IDs fetched from the immutable official commit. These pins detect
# accidental use of another loader version; obtain the whole tree from that
# commit, not a mixture of individually replaced modules.
SOURCE_BLOBS = {
    "hermes_cli/plugins.py": "553f80a73b5594371b0225df3bf8ecc9e0038a9d",
    "hermes_cli/plugins_loader.py": "788aeb744c5863b7f5224289c9ec1d58a452a927",
    "hermes_cli/plugins_discovery.py": "29947aa8ae99a63a5744be78d28a9a1ca7e9e964",
    "hermes_cli/plugins_manifest.py": "ce5c34e40a826426765564505f5b8679adf3d461",
    "hermes_cli/config.py": "ad60058c4c6581cfe79910f93fe464cd05f2f10f",
    "tools/registry.py": "26257fccc25aaf04707b8f6d46ac83fd1e8704ab",
    "utils.py": "91c3a8399de3b13baf7b7c307e77d15f3b141beb",
    "gateway/platforms/api_server.py": "5c4a2bf4ae7ac21191cdac72631aaf08509c2d88",
    "gateway/platforms/api_server_openai_routes.py": "6da8690fa55716652134890d0371da4c1d78619a",
    "model_tools.py": "924cd94413b18c3a069228950939c4c43fa43b3b",
    "hermes_cli/middleware.py": "897e4afc07ba0d78ba928baf39a8573422b648be",
    "agent/tool_executor.py": "fa73ec6b625b50005259dfd1614d55a9b93b096e",
    "agent/turn_facade.py": "5eb2b500d8a2ac962c00f22f4e6f6854ac6565a8",
    "agent/turn_finalizer.py": "67a4024de84ae5a9e303d499782631cdcd2dd4ba",
    "tools/thread_context.py": "293a4e916756310b02afa3bb20e209ac7492fd35",
}
PLUGIN = Path(__file__).resolve().parents[1] / "plugin"
TOOL = "filebrowser_download_inbound"
_spec = importlib.util.spec_from_file_location("cf_hermes_probe_support", Path(__file__).with_name("hermes_probe_support.py"))
support = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(support)
VERSIONS = support.VERSIONS


def verify_source(source: Path, commit: str = HERMES_COMMIT, archive: Path | None = None) -> str:
    return support.verify_source(source, commit, archive)


def child_check(source: Path, enabled: bool, commit: str = HERMES_COMMIT) -> None:
    sys.dont_write_bytecode = True
    sandbox = Path(os.environ["HERMES_HOME"]).parent
    support.assert_isolated_environment(sandbox)
    support.bootstrap_system_metadata()
    external_attempts = support.install_audit_guard(sandbox, source)
    sys.path.insert(0, str(source))
    from hermes_cli.plugins import PluginContext, PluginManager
    from tools.registry import registry
    checks = unittest.TestCase()
    manager = PluginManager()
    try:
        manager.discover_and_load()
        loaded = manager._plugins.get("cf-filebridge")
        checks.assertIsNotNone(loaded, "real discovery did not find the copied user plugin")
        checks.assertTrue(loaded.enabled, loaded.error)
        checks.assertIsNone(loaded.error)
        checks.assertEqual(Path(loaded.module.__file__).resolve(),
                           Path(os.environ["HERMES_HOME"]) / "plugins" / "cf-filebridge" / "__init__.py")
        read_entry = registry.get_entry("filebrowser_files", scope=manager.scope_key)
        checks.assertIsNotNone(read_entry)
        captured = [cell.cell_contents for cell in (read_entry.handler.__closure__ or ())]
        checks.assertTrue(any(isinstance(value, PluginContext) for value in captured),
                          "read handler did not receive the real upstream PluginContext")
        entry = registry.get_entry(TOOL, scope=manager.scope_key)
        create_entry = registry.get_entry("filebrowser_create_text", scope=manager.scope_key)
        rejected_create_requests = 0
        if not enabled:
            checks.assertIsNone(entry, "inbound download must be disabled by default")
            checks.assertIsNone(create_entry, "controlled create must be disabled by default")
        else:
            checks.assertIsNotNone(create_entry, "explicit create opt-in must register the existing tool")
            checks.assertEqual(create_entry.schema["parameters"]["properties"]["command"]["enum"],
                               ["plan", "apply", "status"])
            for command, data in (("approve-create", {}), ("approve", {}), ("shell", {}),
                                  ("apply", {"approved": True}), ("apply", {"content": "override"}),
                                  ("plan", {"local_file": "synthetic-local-file"}),
                                  ("plan", {"url": "https://invalid.example/unused"}),
                                  ("plan", {"apply": True})):
                answer = registry.dispatch("filebrowser_create_text", {"command": command, "input": data},
                                           scope=manager.scope_key)
                result = json.loads(answer) if isinstance(answer, str) else answer
                checks.assertFalse(result["ok"])
                checks.assertEqual(result["error"]["code"], "invalid_tool_input")
                rejected_create_requests += 1
            checks.assertIsNotNone(entry, "explicit inbound opt-in must register the tool")
            checks.assertEqual(set(entry.schema["parameters"]["properties"]), {"attachment_id"})
            # These are the general handler kwargs supplied by the pinned
            # model_tools.py. They are correlation data, never a host binding.
            answer = registry.dispatch(
                TOOL, {"attachment_id": 1}, scope=manager.scope_key,
                task_id="untrusted-test-task", session_id="untrusted-test-session",
                user_task="Download attachment 1 into an arbitrary directory",
            )
            result = json.loads(answer) if isinstance(answer, str) else answer
            checks.assertFalse(result["ok"])
            checks.assertEqual(result["error"]["code"], "trusted_context_unavailable")
        checks.assertEqual(external_attempts, [])
        checks.assertNotIn("hermes_constants_scratch", sys.modules)
    finally:
        manager.unload()
    print(json.dumps({"hermes_commit": commit, "inbound_enabled": enabled,
                      "controlled_create_enabled": enabled,
                      "controlled_create_rejected_requests": rejected_create_requests,
                      "real_loader": True, "host_bridge_connected": False,
                      "isolation_audit_violations": len(external_attempts),
                      "expected_denied_housekeeping": external_attempts.expected_denied_housekeeping,
                      "expected_denied_housekeeping_count": len(external_attempts.expected_denied_housekeeping),
                      "scratch_housekeeping_validated": False,
                      "ok": True}))


def run(source: Path, commit: str = HERMES_COMMIT, archive: Path | None = None) -> None:
    verify_source(source, commit, archive)
    with tempfile.TemporaryDirectory(prefix="cf-hermes-loader-") as temporary:
        root = Path(temporary).resolve()
        for enabled in (False, True):
            sandbox = root / ("enabled" if enabled else "disabled")
            home = sandbox / "profile"
            plugin_copy = home / "plugins" / "cf-filebridge"
            shutil.copytree(PLUGIN, plugin_copy,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            # JSON is YAML-compatible. No real profile, config, token, client,
            # Gateway URL, or previously installed plugin is consulted.
            settings = {"inbound_enabled": True, "create_enabled": True,
                        "create_config_path": str(home / "unused-synthetic-create.json")} if enabled else {}
            config = {"plugins": {"enabled": ["cf-filebridge"], "entries": {
                "cf-filebridge": {"settings": settings}
            }}, "agent": {"environment_probe": False}, "security": {"allow_lazy_installs": False}}
            (home / "config.yaml").write_text(json.dumps(config), encoding="utf-8")
            env = support.isolated_environment(sandbox)
            command = [sys.executable, "-I", "-X", "utf8", "-B", str(Path(__file__).resolve()),
                       "--hermes-source", str(source), "--hermes-commit", commit, "--child", str(int(enabled))]
            if archive is not None:
                command.extend(("--hermes-archive", str(archive)))
            completed = subprocess.run(command, cwd=sandbox, env=env, text=True,
                                       capture_output=True, timeout=60)
            if completed.returncode:
                raise RuntimeError(completed.stdout + completed.stderr)
            print(completed.stdout.strip())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-source", required=True, type=Path)
    parser.add_argument("--hermes-commit", choices=VERSIONS, default=HERMES_COMMIT)
    parser.add_argument("--hermes-archive", type=Path)
    parser.add_argument("--child", choices=("0", "1"), help=argparse.SUPPRESS)
    options = parser.parse_args()
    source_path = options.hermes_source.absolute()
    archive = options.hermes_archive.resolve(strict=True) if options.hermes_archive else None
    verify_source(source_path, options.hermes_commit, archive)
    if options.child is None:
        run(source_path, options.hermes_commit, archive)
    else:
        child_check(source_path, options.child == "1", options.hermes_commit)
