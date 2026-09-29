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

    def test_semantics_and_comment_preserved(self):
        original = self.config()
        output, worker, digest = upgrade.build(b"# operator comment\n" + json.dumps(original).encode(), OLD, NEW)
        from ruamel.yaml import YAML
        parsed = YAML(typ="safe").load(output)
        expected = copy.deepcopy(original)
        settings = expected["plugins"]["entries"]["cf-filebridge"]["settings"]
        settings["inbound_content_enabled"] = True
        settings["inbound_host"]["consumer_tools"].append(upgrade.TOOL)
        expected["platform_toolsets"]["api_server"].append(upgrade.TOOLSET)
        self.assertEqual(parsed, expected)
        self.assertIn(b"# operator comment", output)
        self.assertEqual(worker, "synthetic-client")
        self.assertEqual(digest, "b" * 64)

    def test_duplicate_yaml_and_alias_side_effect_refused(self):
        with self.assertRaises(Exception):
            upgrade.build(b"model: a\nmodel: b\n", OLD, NEW)
        config = self.config()
        from ruamel.yaml import YAML
        common = config["platform_toolsets"]["api_server"]
        config["unrelated_alias"] = common
        stream = io.StringIO(); YAML().dump(config, stream)
        with self.assertRaisesRegex(upgrade.Refused, "yaml_alias_changes_unrelated_settings"):
            upgrade.build(stream.getvalue().encode(), OLD, NEW)

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
