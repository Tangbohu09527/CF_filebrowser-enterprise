from pathlib import Path
import unittest
import importlib.util
import copy
import ast
import re
import yaml

ROOT = Path(__file__).resolve().parents[2]


class TimezoneDefaultsTests(unittest.TestCase):
    def test_both_deployment_profiles_and_proxy_use_shanghai(self):
        for name in ("deploy/compose.yaml", "deploy/shared-host/compose.yaml"):
            config = yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))
            for service in config["services"].values():
                self.assertEqual(service["environment"]["TZ"], "Asia/Shanghai")

    def test_production_validator_accepts_only_fixed_timezone_and_paths(self):
        spec = importlib.util.spec_from_file_location("tz_deployment_validator", ROOT / "scripts/lib/deployment_validation.py")
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        validator.validate_repository(ROOT)
        original = yaml.safe_load((ROOT / "deploy/compose.yaml").read_text())
        for service in original["services"]:
            for key, value in (("TZ", "UTC"), ("TZ", "/tmp/untrusted-zone"), ("UNREVIEWED", "value")):
                changed = copy.deepcopy(original)
                changed["services"][service]["environment"][key] = value
                with self.assertRaises(validator.ValidationError):
                    validator.validate_compose(changed)

    def test_shared_host_raw_and_rendered_allowlists_remain_exact(self):
        source = (ROOT / "deploy/shared-host/validate.sh").read_text()
        expected = yaml.safe_load((ROOT / "deploy/shared-host/compose.yaml").read_text())["services"]["filebrowser-enterprise"]["environment"]
        for pattern in (r'raw_service.get\("environment"\) == (\{.*?\n    \})', r'expected_environment = (\{.*?\n\})'):
            found = re.search(pattern, source, re.S)
            self.assertIsNotNone(found)
            self.assertEqual(ast.literal_eval(found.group(1)), expected)

    def test_runtime_images_have_timezone_database(self):
        for name in ("_docker/Dockerfile", "_docker/Dockerfile.slim"):
            source = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("ENV TZ=Asia/Shanghai", source)
            self.assertIn("tzdata", source)

    def test_backup_calendar_is_explicit_but_audit_names_remain_utc(self):
        timer = (ROOT / "deploy/systemd/filebrowser-enterprise-backup.timer").read_text()
        self.assertIn("OnCalendar=*-*-* 02:30:00 Asia/Shanghai", timer)
        self.assertIn("RandomizedDelaySec=30m", timer)
        backup = (ROOT / "scripts/backup.sh").read_text()
        self.assertIn("date -u", backup)


if __name__ == "__main__":
    unittest.main()
