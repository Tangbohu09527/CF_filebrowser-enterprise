"""Explicit, offline integration check against an unmodified Hermes source tree.

Run with --hermes-source; ordinary unittest discovery does not download upstream
code or silently skip this check. This exercises discovery/registration and a
real registry rejection, not an authenticated Gateway dispatch.
"""
from __future__ import annotations

import argparse
import hashlib
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
}
PLUGIN = Path(__file__).resolve().parents[1] / "plugin"
TOOL = "filebrowser_download_inbound"


def verify_source(source: Path) -> None:
    for relative, expected in SOURCE_BLOBS.items():
        data = (source / relative).read_bytes()
        blob = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
        if hashlib.sha1(blob).hexdigest() != expected:
            raise ValueError(f"Hermes source mismatch at {relative}; require {HERMES_COMMIT}")


def child_check(source: Path, enabled: bool) -> None:
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source))
    from hermes_cli.plugins import PluginContext, PluginManager
    from tools.registry import registry

    # Observe actual execution without replacing PluginContext, the manager,
    # registry, or handlers. Any network/process launch is a test failure.
    external_attempts = []

    def deny_external(event, _args):
        if event in {"socket.connect", "socket.getaddrinfo", "subprocess.Popen", "os.system"}:
            external_attempts.append(event)
            raise RuntimeError("external operation forbidden in loader test")

    sys.addaudithook(deny_external)
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
        if not enabled:
            checks.assertIsNone(entry, "inbound download must be disabled by default")
        else:
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
    finally:
        manager.unload()
    print(json.dumps({"hermes_commit": HERMES_COMMIT, "inbound_enabled": enabled,
                      "real_loader": True, "host_bridge_connected": False, "ok": True}))


def run(source: Path) -> None:
    verify_source(source)
    with tempfile.TemporaryDirectory(prefix="cf-hermes-loader-") as temporary:
        root = Path(temporary).resolve()
        for enabled in (False, True):
            sandbox = root / ("enabled" if enabled else "disabled")
            home = sandbox / "profile"
            plugin_copy = home / "plugins" / "cf-filebridge"
            shutil.copytree(PLUGIN, plugin_copy,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            bundled = sandbox / "empty-bundled"
            bundled.mkdir()
            # JSON is YAML-compatible. No real profile, config, token, client,
            # Gateway URL, or previously installed plugin is consulted.
            settings = {"inbound_enabled": True} if enabled else {}
            config = {"plugins": {"enabled": ["cf-filebridge"], "entries": {
                "cf-filebridge": {"settings": settings}
            }}}
            (home / "config.yaml").write_text(json.dumps(config), encoding="utf-8")
            env = {key: value for key, value in os.environ.items()
                   if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}}
            env.update({"HERMES_HOME": str(home), "HERMES_BUNDLED_PLUGINS": str(bundled),
                        "HERMES_ENABLE_PROJECT_PLUGINS": "false",
                        "USERPROFILE": str(sandbox / "user"),
                        "APPDATA": str(sandbox / "user" / "AppData"),
                        "LOCALAPPDATA": str(sandbox / "user" / "LocalAppData"),
                        "PYTHONDONTWRITEBYTECODE": "1"})
            command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                       "--hermes-source", str(source), "--child", str(int(enabled))]
            completed = subprocess.run(command, cwd=sandbox, env=env, text=True,
                                       capture_output=True, timeout=60)
            if completed.returncode:
                raise RuntimeError(completed.stdout + completed.stderr)
            print(completed.stdout.strip())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-source", required=True, type=Path)
    parser.add_argument("--child", choices=("0", "1"), help=argparse.SUPPRESS)
    options = parser.parse_args()
    source_path = options.hermes_source.resolve(strict=True)
    verify_source(source_path)
    if options.child is None:
        run(source_path)
    else:
        child_check(source_path, options.child == "1")
