"""Explicit offline upgrade/selection proof against the pinned official Hermes.

Uses real discovery, the API's effective-config loader, and its actual toolset
and tool-name selectors. No model, MCP connection, authenticated dispatch or
check_fn readiness is claimed. Every before/after observation is a fresh process
with a separate disposable profile and an audit installed before Hermes imports.
Both observations use this repository's plugin: before has no content opt-in;
after uses the planner output. No installed or staged release is inspected.
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


HERE = Path(__file__).resolve().parent
COMMIT = "0f4a98f87c17007b81500239d0bd5b9574027b73"
TOOL = "filebrowser_read_inbound"
TOOLSET = "cf_filebridge_inbound_content"
OLD = b"name: cf-filebridge\nversion: '0.3.0'\n"
NEW = b"name: cf-filebridge\nversion: '0.4.0'\n"


def local_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


support = local_module("upgrade_tool_support", HERE / "hermes_probe_support.py")

# An independent operator plugin tests existing custom capabilities and a
# dynamic custom suppression which an offline config-only planner cannot know.
# It registers through public APIs, never replaces a Hermes implementation.
CUSTOM_PLUGIN = '''
def register(ctx):
    from toolsets import create_custom_toolset
    ctx.register_tool(name="synthetic_existing_read", toolset="cf_existing_probe",
        schema={"name": "synthetic_existing_read", "description": "Isolated existing capability",
                "parameters": {"type": "object", "properties": {}}},
        handler=lambda args, **kwargs: "unused", description="Synthetic operator plugin")
    create_custom_toolset("operator_existing", "Existing custom selection",
                          includes=["cf_existing_probe"])
    create_custom_toolset("operator_no_content", "Dynamic explicit suppression",
                          includes=["cf_filebridge_inbound_content"])
'''


def base_config():
    return {
        "plugins": {"enabled": ["cf-filebridge", "cf-existing-probe"], "entries": {
            "cf-filebridge": {"settings": {
                "inbound_enabled": True, "inbound_host_enabled": True,
                "create_enabled": True, "create_config_path": "unused-synthetic-create.json",
                "inbound_host": {"gateway_origin": "https://gateway.invalid",
                    "service_token_env": "CF_FILEBRIDGE_HOST_UNUSED",
                    "profile_reference": "isolated-upgrade", "profile_revision": 1,
                    "work_root": "unused-synthetic-root", "client_path": "unused-synthetic-client",
                    "client_sha256": "b" * 64, "consumer_tools": ["synthetic_existing_read"]}}}}},
        "agent": {"environment_probe": False}, "security": {"allow_lazy_installs": False},
        "platform_toolsets": {"cli": ["file", "operator_existing", "no_mcp"],
                              "telegram": ["memory", "no_mcp"]},
    }


def configurations():
    cases = {}
    cases["missing_section"] = base_config(); del cases["missing_section"]["platform_toolsets"]
    cases["missing_api"] = base_config()
    cases["null_section"] = base_config(); cases["null_section"]["platform_toolsets"] = None
    for label, value in (
        ("null_api", None), ("empty_api", []),
        ("explicit_api", ["file", "cf_filebridge", "cf_filebridge_inbound", "cf_filebridge_create"]),
        ("composite_api", ["hermes-api-server"]),
        ("custom_and_literal", "['file', 'operator_existing', 'no_mcp']"),
        ("explicit_new_known", ["file", TOOLSET]),
        ("mcp_allowlist", ["file", "cf_mcp_a", "operator_existing"]),
        ("mcp_disabled", ["file", "operator_existing", "no_mcp"]),
    ):
        cases[label] = base_config()
        cases[label]["platform_toolsets"]["api_server"] = value
    cases["explicit_new_known"]["known_plugin_toolsets"] = {"api_server": [TOOLSET]}
    for label in ("mcp_allowlist", "mcp_disabled", "missing_api"):
        cases[label]["mcp_servers"] = {"cf_mcp_a": {"enabled": True}, "cf_mcp_b": {"enabled": True},
                                       "cf_mcp_off": {"enabled": False}}
    cases["disabled_unrelated"] = base_config()
    cases["disabled_unrelated"]["agent"]["disabled_toolsets"] = "['web', 'terminal']"
    cases["disabled_bundle"] = base_config()
    cases["disabled_bundle"]["agent"]["disabled_toolsets"] = ["hermes-api-server"]
    cases["known_other_plugin"] = base_config()
    cases["known_other_plugin"]["known_plugin_toolsets"] = {"api_server": ["cf_existing_probe"]}
    cases["known_null_platform"] = base_config()
    cases["known_null_platform"]["known_plugin_toolsets"] = {"api_server": None}
    return cases


def child_check(source):
    sandbox = Path(os.environ["HERMES_HOME"]).parent
    support.assert_isolated_environment(sandbox)
    support.bootstrap_system_metadata()
    violations = support.install_audit_guard(sandbox, source, allow_network=True)
    sys.path.insert(0, str(source))
    from hermes_cli.plugins import discover_plugins, get_plugin_manager
    from hermes_cli.config_effective import load_user_config_effective
    from hermes_cli.tools_config import _get_platform_tools
    from agent.skill_utils import parse_config_string_list
    from model_tools import _select_tool_names
    from tools.registry import registry
    discover_plugins()
    manager = get_plugin_manager()
    try:
        for name in ("cf-filebridge", "cf-existing-probe"):
            plugin = manager._plugins.get(name)
            assert plugin is not None and plugin.enabled and plugin.error is None, name
            assert Path(plugin.module.__file__).resolve() == sandbox / "profile/plugins" / name / "__init__.py"
        config = load_user_config_effective(sandbox / "profile/config.yaml")
        disabled = [name.strip() for name in parse_config_string_list(
            (config.get("agent") or {}).get("disabled_toolsets")) if name.strip()]
        selections = {}
        for platform in ("api_server", "cli", "telegram"):
            enabled = _get_platform_tools(config, platform)
            selected = _select_tool_names(sorted(enabled), disabled, quiet_mode=True)
            selections[platform] = {"toolsets": sorted(enabled), "tools": sorted(selected),
                "registered_selected": sorted(name for name in selected
                    if registry.get_entry(name, scope=manager.scope_key) is not None)}
        registered = {name: registry.get_entry(name, scope=manager.scope_key) is not None
                      for name in ("filebrowser_files", "filebrowser_create_text",
                                   "filebrowser_download_inbound", TOOL, "synthetic_existing_read")}
        assert all(value for name, value in registered.items() if name != TOOL), registered
        if registered[TOOL]:
            answer = registry.dispatch(TOOL, {"attachment_id": 1}, scope=manager.scope_key,
                                       task_id="untrusted-test", session_id="untrusted-test")
            answer = json.loads(answer) if isinstance(answer, str) else answer
            assert answer.get("ok") is False and answer["error"]["code"] == "trusted_context_unavailable", answer
        assert violations == [], violations
        assert "hermes_constants_scratch" not in sys.modules
        result = {"selections": selections, "registered": registered,
                  "unbound_content_rejected": registered[TOOL], "audit_violations": len(violations),
                  "expected_denied_housekeeping": violations.expected_denied_housekeeping}
        (sandbox / "selection.json").write_text(json.dumps(result), encoding="utf-8")
    finally:
        manager.unload()


def observe(source, raw_config, parent, label):
    sandbox = parent / label
    sandbox.mkdir(mode=0o700)
    env = support.isolated_environment(sandbox)
    home = sandbox / "profile"
    shutil.copytree(HERE.parent / "plugin", home / "plugins/cf-filebridge",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    custom = home / "plugins/cf-existing-probe"
    custom.mkdir()
    (custom / "plugin.yaml").write_text('name: cf-existing-probe\nversion: "1.0.0"\nkind: standalone\n')
    (custom / "__init__.py").write_text(CUSTOM_PLUGIN, encoding="utf-8")
    (home / "config.yaml").write_bytes(raw_config)
    command = [sys.executable, "-I", "-X", "utf8", "-B", str(Path(__file__).resolve()),
               "--hermes-source", str(source), "--child"]
    completed = subprocess.run(command, cwd=sandbox, env=env, capture_output=True, text=True, timeout=60)
    if completed.returncode:
        raise AssertionError(label + ": " + completed.stdout + completed.stderr)
    return json.loads((sandbox / "selection.json").read_text(encoding="utf-8"))


def run(source, archive, selected_case=None):
    assert sys.version_info[:3] in {(3, 14, 7), (3, 11, 16)}, "Use an explicitly verified probe interpreter"
    support.verify_source(source, COMMIT, archive)
    upgrade = local_module("upgrade_planner", HERE.parent / "windows/inbound_upgrade_config.py")
    from ruamel.yaml import YAML
    yaml = YAML(typ="safe")
    reports = []
    suppressions = []
    custom_boundary = None
    with tempfile.TemporaryDirectory(prefix="cf-upgrade-tools-") as temporary:
        root = Path(temporary).resolve()
        for label, config in configurations().items():
            if selected_case and selected_case != label:
                continue
            before = json.dumps(config).encode()
            after, _, _ = upgrade.build(before, OLD, NEW)
            candidate = yaml.load(after)
            for key in ("platform_toolsets", "known_plugin_toolsets", "mcp_servers", "agent"):
                assert (key in candidate) == (key in config), (label, key)
                assert candidate.get(key) == config.get(key), (label, key)
            first = observe(source, before, root, label + "-before")
            second = observe(source, after, root, label + "-after")
            assert first["registered"][TOOL] is False and second["registered"][TOOL] is True
            changes = {}
            for platform in ("api_server", "cli", "telegram"):
                old, new = first["selections"][platform], second["selections"][platform]
                for key, addition in (("toolsets", TOOLSET), ("tools", TOOL), ("registered_selected", TOOL)):
                    removed = set(old[key]) - set(new[key])
                    added = set(new[key]) - set(old[key])
                    assert not removed and added <= {addition}, (label, platform, key, removed, added)
                    if platform == "api_server" and key != "toolsets":
                        assert added == {TOOL}, (label, platform, key, added)
                changes[platform] = sorted(set(new["tools"]) - set(old["tools"]))
            if label == "empty_api":
                assert "file" not in first["selections"]["api_server"]["toolsets"]
            if label == "mcp_allowlist":
                assert "cf_mcp_a" in second["selections"]["api_server"]["toolsets"]
                assert "cf_mcp_b" not in second["selections"]["api_server"]["toolsets"]
            if label == "mcp_disabled":
                assert not {"cf_mcp_a", "cf_mcp_b"} & set(second["selections"]["api_server"]["toolsets"])
            reports.append({"case": label, "added_tool_names": changes,
                            "existing_capabilities_preserved": True, "audit_violations": 0})
        assert reports, "unknown or empty case selection"
        if selected_case is None:
            blocked = {"known_omitted": base_config()}
            blocked["known_omitted"]["known_plugin_toolsets"] = {"api_server": [TOOLSET]}
            for label, disabled in (("global_list", [TOOLSET]), ("global_literal", repr([TOOLSET])),
                                    ("global_all", "all"), ("global_wildcard", ["*"])):
                blocked[label] = base_config()
                blocked[label]["agent"]["disabled_toolsets"] = disabled
            for label, config in blocked.items():
                raw = json.dumps(config).encode()
                try:
                    upgrade.build(raw, OLD, NEW)
                except upgrade.Refused as error:
                    assert str(error) == "content_toolset_disabled", (label, str(error))
                else:
                    raise AssertionError("planner accepted explicit suppression: " + label)
                # This is deliberately NOT a planner output or an installed
                # upgrade. Load a synthetic hypothetical opt-in to establish
                # why the real official selector still refuses exposure.
                settings = config["plugins"]["entries"]["cf-filebridge"]["settings"]
                settings["inbound_content_enabled"] = True
                settings["inbound_host"]["consumer_tools"].append(TOOL)
                observation = observe(source, json.dumps(config).encode(), root, "blocked-" + label)
                assert observation["registered"][TOOL] is True
                assert TOOL not in observation["selections"]["api_server"]["tools"], label
                suppressions.append({"case": label, "planner_refused": True,
                                     "official_tool_selection_suppressed": True, "audit_violations": 0})
            # A plugin-defined composite is invisible to a pure configuration
            # planner. Preserve it and prove Hermes retains the final veto;
            # never report this compatibility boundary as a usable upgrade.
            config = base_config()
            config["agent"]["disabled_toolsets"] = ["operator_no_content"]
            after, _, _ = upgrade.build(json.dumps(config).encode(), OLD, NEW)
            assert yaml.load(after)["agent"] == config["agent"]
            observation = observe(source, after, root, "dynamic-custom-suppression")
            assert observation["registered"][TOOL] is True
            assert TOOL not in observation["selections"]["api_server"]["tools"]
            custom_boundary = {"configuration_policy_preserved": True,
                "official_dynamic_custom_veto_preserved": True,
                "usable_content_upgrade": False, "audit_violations": 0}
    print(json.dumps({"ok": True, "hermes_commit": COMMIT, "python": sys.version.split()[0],
        "complete_source_archive_verified": True, "installed_or_staged_release_used": False,
        "before_plugin_code": "current_repository_plugin_without_content_opt_in",
        "real_plugin_discovery": True, "real_api_config_and_tool_selection": True,
        "selection_before_check_fn": True, "mcp_connections_tested": False,
        "model_or_authenticated_dispatch_tested": False, "cases": reports,
        "explicit_suppressions": suppressions, "dynamic_custom_suppression_boundary": custom_boundary}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-source", type=Path, required=True)
    parser.add_argument("--hermes-archive", type=Path)
    parser.add_argument("--case", choices=configurations())
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        child_check(args.hermes_source.absolute())
    else:
        if not args.hermes_archive:
            parser.error("--hermes-archive is required for complete immutable-source verification")
        run(args.hermes_source.absolute(), args.hermes_archive.absolute(), args.case)
