from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]


class TimezoneDefaultsTests(unittest.TestCase):
    def test_both_deployment_profiles_and_proxy_use_shanghai(self):
        for name in ("deploy/compose.yaml", "deploy/shared-host/compose.yaml"):
            config = yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))
            for service in config["services"].values():
                self.assertEqual(service["environment"]["TZ"], "Asia/Shanghai")

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
