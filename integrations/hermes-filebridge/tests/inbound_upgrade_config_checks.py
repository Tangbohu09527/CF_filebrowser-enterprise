"""Explicit installer-only regressions; invoked by Test-InboundUpgrade.ps1.

Imports only the local configuration helper. The caller supplies a new private
synthetic fixture root; no Hermes installation, environment or network is used.
"""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
import zipfile

BASE = Path(sys.argv[1]).absolute()
sys.argv = sys.argv[:1]
SPEC = importlib.util.spec_from_file_location("upgrade_config", Path(__file__).parents[1] / "windows/inbound_upgrade_config.py")
upgrade = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upgrade)
OLD = b"name: cf-filebridge\nversion: '0.3.0'\n"
NEW = b"name: cf-filebridge\nversion: '0.4.0'\n"
REQUIREMENTS = b"package==1.0 --hash=sha256:" + b"a" * 64 + b"\n"


class ConfigChecks(unittest.TestCase):
    def config(self):
        return {"model": {"provider": "custom", "api_key": "synthetic-value"},
                "platform_toolsets": {"api_server": ["existing"]},
                "plugins": {"enabled": ["cf-filebridge"], "entries": {"cf-filebridge": {"settings": {
                    "inbound_enabled": True, "inbound_host_enabled": True, "unrelated": [1, 2],
                    "inbound_host": {"gateway_origin": "https://gateway.invalid", "service_token_env": "CF_FILEBRIDGE_HOST_TEST",
                        "profile_reference": "synthetic", "profile_revision": 1, "work_root": "synthetic-root",
                        "client_path": "synthetic-client", "client_sha256": "b" * 64, "consumer_tools": ["existing"]}}}}}}

    def test_missing_api_selection_keeps_official_default_resolution(self):
        from ruamel.yaml import YAML
        for section in ({"cli": ["synthetic-cli-choice"]}, {}):
            with self.subTest(section=section):
                config = self.config()
                config["platform_toolsets"] = section
                output, _, _ = upgrade.build(json.dumps(config).encode(), OLD, NEW)
                self.assertEqual(YAML(typ="safe").load(output)["platform_toolsets"], section)

    def test_missing_platform_section_is_not_materialized(self):
        from ruamel.yaml import YAML
        config = self.config()
        del config["platform_toolsets"]
        output, _, _ = upgrade.build(json.dumps(config).encode(), OLD, NEW)
        self.assertNotIn("platform_toolsets", YAML(typ="safe").load(output))

    def test_semantics_and_comment_preserved(self):
        original = self.config()
        output, worker, digest = upgrade.build(b"# operator comment\n" + json.dumps(original).encode(), OLD, NEW)
        from ruamel.yaml import YAML
        parsed = YAML(typ="safe").load(output)
        expected = copy.deepcopy(original)
        settings = expected["plugins"]["entries"]["cf-filebridge"]["settings"]
        settings["inbound_content_enabled"] = True
        settings["inbound_host"]["consumer_tools"].append(upgrade.TOOL)
        self.assertEqual(parsed, expected)
        self.assertIn(b"# operator comment", output)
        self.assertEqual(worker, "synthetic-client")
        self.assertEqual(digest, "b" * 64)

    def test_duplicate_yaml_and_alias_side_effect_refused(self):
        with self.assertRaises(Exception):
            upgrade.build(b"model: a\nmodel: b\n", OLD, NEW)
        config = self.config()
        from ruamel.yaml import YAML
        common = config["plugins"]["entries"]["cf-filebridge"]["settings"]["inbound_host"]["consumer_tools"]
        config["unrelated_alias"] = common
        stream = io.StringIO(); YAML().dump(config, stream)
        with self.assertRaisesRegex(upgrade.Refused, "yaml_alias_changes_unrelated_settings"):
            upgrade.build(stream.getvalue().encode(), OLD, NEW)

    def test_api_alias_and_all_unrelated_comments_are_preserved(self):
        config = self.config()
        from ruamel.yaml import YAML
        config["unrelated_alias"] = config["platform_toolsets"]["api_server"]
        stream = io.StringIO(); YAML().dump(config, stream)
        output, _, _ = upgrade.build(b"# keep operator selection\n" + stream.getvalue().encode(), OLD, NEW)
        parsed = YAML().load(output)
        self.assertIs(parsed["unrelated_alias"], parsed["platform_toolsets"]["api_server"])
        self.assertEqual(parsed["unrelated_alias"], ["existing"])
        self.assertIn(b"# keep operator selection", output)

    def test_null_empty_explicit_and_literal_selections_are_not_rewritten(self):
        from ruamel.yaml import YAML
        for selection in (None, [], ["file", "mcp_existing", "custom", "no_mcp"],
                          "[]", "['file', 'mcp_existing', 'custom']"):
            with self.subTest(selection=selection):
                config = self.config()
                config["platform_toolsets"] = {"api_server": selection, "cli": ["unrelated"]}
                output, _, _ = upgrade.build(json.dumps(config).encode(), OLD, NEW)
                self.assertEqual(YAML(typ="safe").load(output)["platform_toolsets"], config["platform_toolsets"])
        config["platform_toolsets"] = None
        output, _, _ = upgrade.build(json.dumps(config).encode(), OLD, NEW)
        self.assertIsNone(YAML(typ="safe").load(output)["platform_toolsets"])

    def test_ambiguous_invalid_selection_is_refused_without_guessing_permissions(self):
        for value in ("file", "[broken", "['file', 1]", {}, 4, False, ["file", None], ["file", 1], [["file"]]):
            with self.subTest(value=value):
                config = self.config(); config["platform_toolsets"]["api_server"] = value
                with self.assertRaisesRegex(upgrade.Refused, "api_toolsets_invalid"):
                    upgrade.build(json.dumps(config).encode(), OLD, NEW)
        for value in ([], "api_server", 1, False):
            config = self.config(); config["platform_toolsets"] = value
            with self.assertRaisesRegex(upgrade.Refused, "platform_toolsets_invalid"):
                upgrade.build(json.dumps(config).encode(), OLD, NEW)

    def test_known_content_optout_is_refused_other_plugin_selections_preserved(self):
        from ruamel.yaml import YAML
        config = self.config()
        config["known_plugin_toolsets"] = {"api_server": ["operator_declined_plugin"], "cli": ["cli_choice"]}
        output, _, _ = upgrade.build(json.dumps(config).encode(), OLD, NEW)
        self.assertEqual(YAML(typ="safe").load(output)["known_plugin_toolsets"], config["known_plugin_toolsets"])
        config["known_plugin_toolsets"]["api_server"].append(upgrade.TOOLSET)
        with self.assertRaisesRegex(upgrade.Refused, "content_toolset_disabled"):
            upgrade.build(json.dumps(config).encode(), OLD, NEW)
        config["platform_toolsets"]["api_server"].append(upgrade.TOOLSET)
        output, _, _ = upgrade.build(json.dumps(config).encode(), OLD, NEW)
        self.assertEqual(YAML(typ="safe").load(output)["known_plugin_toolsets"], config["known_plugin_toolsets"])
        config["plugins"]["disabled"] = ["cf-filebridge"]
        with self.assertRaisesRegex(upgrade.Refused, "existing_plugin_not_enabled"):
            upgrade.build(json.dumps(config).encode(), OLD, NEW)

    def test_null_known_platform_keeps_official_empty_known_set(self):
        from ruamel.yaml import YAML
        config = self.config()
        config["known_plugin_toolsets"] = {"api_server": None, "cli": ["untouched"]}
        output, _, _ = upgrade.build(json.dumps(config).encode(), OLD, NEW)
        self.assertEqual(YAML(typ="safe").load(output)["known_plugin_toolsets"], config["known_plugin_toolsets"])
        for invalid in ("known", {}, True, ["known", None]):
            config["known_plugin_toolsets"]["api_server"] = invalid
            with self.assertRaisesRegex(upgrade.Refused, "known_plugin_toolsets_invalid"):
                upgrade.build(json.dumps(config).encode(), OLD, NEW)

    def test_global_suppression_never_removed_or_overridden(self):
        from ruamel.yaml import YAML
        for disabled in (["terminal"], "terminal", "['terminal', 'web']", [], None):
            config = self.config(); config["agent"] = {"disabled_toolsets": disabled}
            output, _, _ = upgrade.build(json.dumps(config).encode(), OLD, NEW)
            self.assertEqual(YAML(typ="safe").load(output)["agent"], config["agent"])
        for disabled in ([upgrade.TOOLSET], upgrade.TOOLSET, "all", ["*"], "['all']", [upgrade.TOOL]):
            config = self.config(); config["agent"] = {"disabled_toolsets": disabled}
            with self.assertRaisesRegex(upgrade.Refused, "content_toolset_disabled"):
                upgrade.build(json.dumps(config).encode(), OLD, NEW)
        for disabled in ({}, True, ["terminal", 1], "[broken"):
            config = self.config(); config["agent"] = {"disabled_toolsets": disabled}
            with self.assertRaisesRegex(upgrade.Refused, "disabled_toolsets_invalid"):
                upgrade.build(json.dumps(config).encode(), OLD, NEW)

    def test_failure_record_has_only_safe_stage_and_code(self):
        self.assertEqual(upgrade.failure_record(upgrade.Refused("content_toolset_disabled"), "config_semantic_plan"),
                         {"ok": False, "stage": "config_semantic_plan", "error": "content_toolset_disabled"})
        for error in (upgrade.Refused("private-sentinel"), ValueError("private-sentinel")):
            output = upgrade.failure_record(error, "private-sentinel")
            self.assertEqual(output, {"ok": False, "stage": "config_semantic_plan", "error": "configuration_plan_failed"})
            self.assertNotIn("private-sentinel", json.dumps(output))

    def test_integer_revision_exact(self):
        for revision in (True, False, "1", 0, -1, 1.0, None):
            with self.subTest(revision=revision):
                config = self.config()
                config["plugins"]["entries"]["cf-filebridge"]["settings"]["inbound_host"]["profile_revision"] = revision
                with self.assertRaisesRegex(upgrade.Refused, "existing_profile_revision_invalid"):
                    upgrade.build(json.dumps(config).encode(), OLD, NEW)

    def test_version_conflict_refused(self):
        with self.assertRaisesRegex(upgrade.Refused, "plugin_version_conflict"):
            upgrade.build(json.dumps(self.config()).encode(), b"name: cf-filebridge\nversion: '9.9.9'\n", NEW)

    def test_optional_consumer_allowlist_created_but_invalid_types_refused(self):
        config = self.config()
        host = config["plugins"]["entries"]["cf-filebridge"]["settings"]["inbound_host"]
        del host["consumer_tools"]
        output, _, _ = upgrade.build(json.dumps(config).encode(), OLD, NEW)
        from ruamel.yaml import YAML
        actual = YAML(typ="safe").load(output)
        self.assertEqual(actual["plugins"]["entries"]["cf-filebridge"]["settings"]["inbound_host"]["consumer_tools"], [upgrade.TOOL])
        for invalid in (None, "existing", {}, 1, True):
            with self.subTest(value=invalid):
                host["consumer_tools"] = invalid
                with self.assertRaisesRegex(upgrade.Refused, "consumer_allowlist_missing"):
                    upgrade.build(json.dumps(config).encode(), OLD, NEW)

    def test_hashed_requirements_and_actual_release(self):
        content = (b"package==1.0 \\\n --hash=sha256:" + b"a" * 64 + b" \\\n --hash=sha256:" + b"b" * 64 + b"\n")
        self.assertEqual(upgrade.requirements(content), {"package": "1.0"})
        current = upgrade.requirements((Path(__file__).parents[1] / "requirements-inbound-content.txt").read_bytes())
        self.assertEqual(len(current), 9)

    def test_unsafe_requirements_refused(self):
        for data in (b"package==1.0", REQUIREMENTS + REQUIREMENTS, b"--index-url https://example.invalid\n" + REQUIREMENTS,
                     b"package @ https://example.invalid/package.whl\n", REQUIREMENTS + b"other==1.0 \\\n"):
            with self.subTest(data=data[:24]):
                with self.assertRaises(upgrade.Refused):
                    upgrade.requirements(data)

    def test_archive_traversal_and_source_distribution_refused(self):
        with tempfile.TemporaryDirectory(dir=BASE) as name:
            root = Path(name); requirements = root / "requirements.txt"; requirements.write_bytes(REQUIREMENTS)
            wheels = root / "wheels"; wheels.mkdir(); archive = root / "wheels.zip"
            for member in ("../escape.whl", "nested/a.whl", "a.tar.gz", "a.whl:stream"):
                with zipfile.ZipFile(archive, "w") as output:
                    output.writestr(member, b"unused")
                args = SimpleNamespace(requirements=requirements, extract_wheels=True, wheels=wheels, wheel_archive=archive)
                with self.assertRaisesRegex(upgrade.Refused, "wheel_archive_member"):
                    upgrade.runtime_mode(args)
                self.assertEqual(list(wheels.iterdir()), [])
                self.assertFalse((root / "escape.whl").exists())

    def test_runtime_unknown_empty_directory_detected(self):
        with tempfile.TemporaryDirectory(dir=BASE) as name:
            root = Path(name); requirements = root / "requirements.txt"; requirements.write_bytes(REQUIREMENTS)
            runtime = root / "runtime"; runtime.mkdir(); (runtime / "known").write_bytes(b"known")
            args = SimpleNamespace(requirements=requirements, extract_wheels=False, runtime_root=runtime,
                                   runtime_receipt=root / "runtime.json", verify_runtime=False)
            with contextlib.redirect_stdout(io.StringIO()):
                upgrade.runtime_mode(args)
            args.verify_runtime = True; (runtime / "unknown").mkdir()
            with self.assertRaisesRegex(upgrade.Refused, "runtime_modified_or_unknown"):
                upgrade.runtime_mode(args)
            self.assertTrue((runtime / "unknown").is_dir())


if __name__ == "__main__":
    unittest.main(verbosity=2)
