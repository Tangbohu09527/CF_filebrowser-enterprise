#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import re
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "lib" / "deployment_validation.py"
SPEC = importlib.util.spec_from_file_location("deployment_validation", MODULE_PATH)
assert SPEC and SPEC.loader
validation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validation)


class DeploymentAssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.env = validation.load_env(ROOT / "deploy" / "compose.env.example")
        cls.config = validation.load_yaml(ROOT / "deploy" / "config.yaml.example")
        cls.compose = validation.load_yaml(ROOT / "deploy" / "compose.yaml")
        cls.maintenance = validation.load_yaml(ROOT / "deploy" / "compose.maintenance.yaml")
        cls.build = validation.load_yaml(ROOT / "deploy" / "compose.build.yaml")

    def test_repository_assets_pass_strict_validation(self) -> None:
        validation.validate_repository(ROOT)

    def test_config_missing_critical_path_fails_closed(self) -> None:
        config = copy.deepcopy(self.config)
        del config["server"]["database"]
        with self.assertRaises(validation.ValidationError):
            validation.validate_config(config, self.env, template=True)

    def test_loader_http_gap_cannot_be_misrepresented(self) -> None:
        config = copy.deepcopy(self.config)
        config["http"] = {"disableRateLimit": False, "trustedHeaders": ["X-Real-IP"]}
        with self.assertRaises(validation.ValidationError):
            validation.validate_config(config, self.env, template=True)

    def test_placeholder_digest_fails_production_validation(self) -> None:
        with self.assertRaises(validation.ValidationError):
            validation.validate_env(self.env, template=False)

    def test_upstream_filebrowser_image_is_rejected(self) -> None:
        env = dict(self.env)
        env["FILEBROWSER_IMAGE"] = "gtstef/filebrowser:v1@sha256:" + "0123456789abcdef" * 4
        with self.assertRaises(validation.ValidationError):
            validation.validate_env(env, template=True)

    def test_env_rejects_secondary_interpolation_unknown_keys_and_noncanonical_paths(self) -> None:
        mutations = (
            ("DATA_ROOT", "/var/lib/${UNLISTED}"),
            ("DATA_ROOT", "/var/lib/filebrowser-enterprise/"),
            ("DATA_ROOT", "/var//lib/filebrowser-enterprise"),
            ("DATA_ROOT", "/var/lib/filebrowser # comment"),
            ("DATA_ROOT", '"/var/lib/filebrowser"'),
            ("DEPLOY_ROOT", "/opt/alternate-filebrowser"),
            ("BACKUP_ROOT", "/var/backups/alternate-filebrowser"),
            ("INTERNAL_REGISTRY_HOST", "registry.gitlab.com"),
            ("UNLISTED", "value"),
        )
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                env = dict(self.env)
                env[key] = value
                with self.assertRaises(validation.ValidationError):
                    validation.validate_env(env, template=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / "ambiguous.env"
            env_path.write_text("DATA_ROOT=/var/lib/filebrowser \n", encoding="utf-8")
            with self.assertRaises(validation.ValidationError):
                validation.load_env(env_path)

    def test_filebrowser_has_no_published_port(self) -> None:
        app = self.compose["services"]["filebrowser-enterprise"]
        self.assertNotIn("ports", app)
        self.assertEqual(app["expose"], ["8080"])

    def test_compose_dangerous_mutations_fail_closed(self) -> None:
        mutations = (
            ("project name", lambda value: value.__setitem__("name", "unexpected")),
            ("upstream image", lambda value: value["services"]["filebrowser-enterprise"].__setitem__("image", "docker.io/gtstef/filebrowser:latest")),
            ("root user", lambda value: value["services"]["filebrowser-enterprise"].__setitem__("user", "0:0")),
            ("privileged", lambda value: value["services"]["filebrowser-enterprise"].__setitem__("privileged", True)),
            ("ingress access", lambda value: value["services"]["filebrowser-enterprise"].__setitem__("networks", ["backend", "ingress"])),
            ("replicas", lambda value: value["services"]["filebrowser-enterprise"].__setitem__("deploy", {"replicas": 2})),
            ("scale", lambda value: value["services"]["nginx"].__setitem__("scale", 2)),
            ("docker socket", lambda value: value["services"]["filebrowser-enterprise"]["volumes"].append({"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"})),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                compose = copy.deepcopy(self.compose)
                mutate(compose)
                with self.assertRaises(validation.ValidationError):
                    validation.validate_compose(compose)

    def test_build_and_maintenance_overrides_are_strict(self) -> None:
        validation.validate_build_compose(copy.deepcopy(self.build), ROOT)
        validation.validate_maintenance_compose(copy.deepcopy(self.maintenance))
        build = copy.deepcopy(self.build)
        build["services"]["filebrowser-enterprise"]["deploy"] = {"replicas": 2}
        with self.assertRaises(validation.ValidationError):
            validation.validate_build_compose(build, ROOT)
        maintenance = copy.deepcopy(self.maintenance)
        maintenance["services"]["nginx"]["restart"] = "unless-stopped"
        with self.assertRaises(validation.ValidationError):
            validation.validate_maintenance_compose(maintenance)

    def test_nginx_overwrites_forwarded_headers_and_hides_queries(self) -> None:
        validation.validate_nginx(
            (ROOT / "deploy" / "nginx" / "nginx.conf").read_text(encoding="utf-8"),
            (ROOT / "deploy" / "nginx" / "filebrowser.conf.template").read_text(encoding="utf-8"),
        )

    def test_all_yaml_is_parseable(self) -> None:
        yaml_files = list((ROOT / "deploy").rglob("*.yaml")) + [
            ROOT / ".github" / "workflows" / "deployment-assets.yaml"
        ]
        for path in yaml_files:
            if path.exists():
                with self.subTest(path=path):
                    self.assertIsNotNone(yaml.safe_load(path.read_text(encoding="utf-8")))

    def test_shell_scripts_are_lf_and_fail_fast(self) -> None:
        for path in (ROOT / "scripts").rglob("*.sh"):
            with self.subTest(path=path):
                data = path.read_bytes()
                self.assertNotIn(b"\r\n", data)
                text = data.decode("utf-8")
                self.assertTrue(text.startswith("#!/"))
                if path.name not in {"container-entrypoint.sh", "nginx-entrypoint.sh"}:
                    self.assertIn("set -Eeuo pipefail", text)

    def test_lifecycle_guards_are_present(self) -> None:
        backup = (ROOT / "scripts" / "backup.sh").read_text(encoding="utf-8")
        restore = (ROOT / "scripts" / "restore.sh").read_text(encoding="utf-8")
        upgrade = (ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8")
        rollback = (ROOT / "scripts" / "rollback.sh").read_text(encoding="utf-8")
        self.assertIn("flock", backup)
        self.assertIn("sha256sum -c", restore)
        self.assertIn("rollback.sh", upgrade)
        self.assertIn("restore.sh", rollback)
        self.assertNotIn("docker compose up --scale", upgrade)

    def test_every_lifecycle_start_is_singleton_and_transactions_fail_closed(self) -> None:
        scripts = [
            ROOT / "scripts" / name
            for name in ("backup.sh", "bootstrap-admin.sh", "restore.sh", "rollback.sh", "stack.sh", "upgrade.sh")
        ] + [ROOT / "scripts" / "lib" / "deployment-common.sh"]
        commands: list[str] = []
        for path in scripts:
            logical = path.read_text(encoding="utf-8").replace("\\\n", " ")
            commands.extend(
                line.strip()
                for line in logical.splitlines()
                if re.search(r"\b(?:maintenance_)?compose up\b", line)
            )
        self.assertGreater(len(commands), 10)
        for command in commands:
            with self.subTest(command=command):
                self.assertRegex(command, r"--scale (?:filebrowser-enterprise|nginx)=1")
                self.assertNotRegex(command, r"--scale (?:filebrowser-enterprise|nginx)=(?:0|[2-9][0-9]*)")
        restore = (ROOT / "scripts" / "restore.sh").read_text(encoding="utf-8")
        common = (ROOT / "scripts" / "lib" / "deployment-common.sh").read_text(encoding="utf-8")
        self.assertIn("maintenance_compose up", restore)
        self.assertIn("promote_production_nginx", restore)
        self.assertIn("docker update --restart=unless-stopped", common)
        self.assertIn("assert_no_incomplete_lifecycle_transaction", common)
        for guarded_path in (
            ROOT / "scripts" / "backup.sh",
            ROOT / "scripts" / "bootstrap-admin.sh",
            ROOT / "scripts" / "restore.sh",
            ROOT / "scripts" / "stack.sh",
            ROOT / "scripts" / "validate-deployment.sh",
        ):
            self.assertIn(
                "assert_no_incomplete_lifecycle_transaction",
                guarded_path.read_text(encoding="utf-8"),
            )
        self.assertIn("FILEBROWSER_DEFER_PRODUCTION_PROMOTION=1", (ROOT / "scripts" / "rollback.sh").read_text(encoding="utf-8"))
        self.assertIn("BACKUP_ATTEMPTED=true", (ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8"))
        self.assertIn("BACKUP_ATTEMPTED=true", (ROOT / "scripts" / "rollback.sh").read_text(encoding="utf-8"))

    def test_compose_wrapper_sanitizes_host_environment_and_requires_v220(self) -> None:
        common = (ROOT / "scripts" / "lib" / "deployment-common.sh").read_text(encoding="utf-8")
        compose_text = (ROOT / "deploy" / "compose.yaml").read_text(encoding="utf-8")
        build_text = (ROOT / "deploy" / "compose.build.yaml").read_text(encoding="utf-8")
        interpolation_keys = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", compose_text + build_text))
        array_match = re.search(
            r"declare -ar FILEBROWSER_COMPOSE_ENV_KEYS=\((.*?)\n\)", common, re.DOTALL
        )
        self.assertIsNotNone(array_match)
        guarded_keys = set(re.findall(r"\b[A-Z][A-Z0-9_]*\b", array_match.group(1)))
        self.assertEqual(interpolation_keys, guarded_keys)
        self.assertIn('--project-name "$FILEBROWSER_COMPOSE_PROJECT"', common)
        self.assertIn("2.20.0", common)
        self.assertIn("require_compose_wait_support", (ROOT / "scripts" / "install-debian.sh").read_text(encoding="utf-8"))
        self.assertIn("require_compose_wait_support", (ROOT / "scripts" / "stack.sh").read_text(encoding="utf-8"))

    def test_backup_manifest_contract_is_schema_2_and_space_checked(self) -> None:
        backup = (ROOT / "scripts" / "backup.sh").read_text(encoding="utf-8")
        for field in (
            "deployment_schema\t2",
            "source_image\t$source_image",
            "source_nginx_image\t$source_nginx_image",
            "internal_registry_host\t$INTERNAL_REGISTRY_HOST_VALUE",
            "deploy_root\t$DEPLOY_ROOT",
            "config_root\t$CONFIG_ROOT",
            "data_root\t$DATA_ROOT",
            "cache_root\t$CACHE_ROOT",
            "files_root\t$FILES_ROOT",
            "backup_root\t$BACKUP_ROOT",
            "total_logical_bytes\t$total_logical_bytes",
            "total_archive_bytes\t$total_archive_bytes",
        ):
            with self.subTest(field=field):
                self.assertIn(field, backup)
        self.assertIn("tar --sparse", backup)
        self.assertIn("require_filesystem_space backup", backup)
        self.assertLess(
            backup.index("require_filesystem_space backup"),
            backup.index("payload/database.tar"),
        )

    def test_restore_preflight_and_durable_recovery_guards_are_present(self) -> None:
        restore = (ROOT / "scripts" / "restore.sh").read_text(encoding="utf-8")
        common = (ROOT / "scripts" / "lib" / "deployment-common.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("deployment_schema\" == 2", restore)
        self.assertIn("compare_archived_environment", restore)
        self.assertIn("deployment_validation.py\" --production", restore)
        self.assertIn("require_tar_regular_member", restore)
        self.assertIn("--recover-incomplete", restore)
        self.assertIn("validate_journal_swap \"$count\"", restore)
        self.assertIn("durable_move \"$target\" \"$original\"", restore)
        self.assertIn("validate_restore_atomic_targets", restore)
        self.assertIn("hard-linked backup members are forbidden", restore)
        self.assertIn(
            "FILEBROWSER_RESTORE_JOURNAL=$FILEBROWSER_LIFECYCLE_STATE_ROOT/restore-journal.tsv",
            common,
        )
        app_health = restore.index("wait_for_service_health filebrowser-enterprise 180")
        nginx_start = restore.index(
            'compose up -d --no-deps --scale nginx=1 nginx', app_health
        )
        self.assertLess(app_health, nginx_start)

    def test_upgrade_and_rollback_write_a_durable_power_loss_state_machine(self) -> None:
        upgrade = (ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8")
        rollback = (ROOT / "scripts" / "rollback.sh").read_text(encoding="utf-8")
        restore = (ROOT / "scripts" / "restore.sh").read_text(encoding="utf-8")

        self.assertIn('cat >"$state_temp"', upgrade)
        self.assertNotIn('cat >"$STATE_FILE"', upgrade)
        self.assertLess(
            upgrade.index('durable_move "$state_temp" "$STATE_FILE"'),
            upgrade.index("trap upgrade_exit EXIT"),
        )
        self.assertLess(
            upgrade.index("trap upgrade_exit EXIT"),
            upgrade.index("disable_managed_restart_policy"),
        )
        self.assertIn('[[ "$ENTRY_STATUS" == backed-up', rollback)
        self.assertIn("retain the unchanged old database", rollback)

        rolling_phase = rollback.index('durable_tsv_set "$STATE_FILE" status rolling-back')
        restore_apply = rollback.index(
            '"$SCRIPT_DIR/restore.sh" --backup "$backup_real"', rolling_phase
        )
        self.assertNotIn(
            'env_set "$ENV_FILE" FILEBROWSER_IMAGE "$old_image"',
            rollback[rolling_phase:restore_apply],
        )
        self.assertEqual(
            rollback.count('durable_tsv_set "$STATE_FILE" rollforward_backup'), 1
        )
        self.assertIn("reusing the recorded roll-forward backup", rollback)
        self.assertIn("non-committed rollback state with an old image pin is ambiguous", rollback)

        data_commit = restore.index(
            'durable_tsv_set "$FILEBROWSER_ACTIVE_TRANSACTION_STATE" status rollback-data-restored'
        )
        deferred_clear = restore.index("clear_restore_journal", data_commit)
        self.assertLess(data_commit, deferred_clear)
        self.assertIn(
            '[[ "$ROLLBACK_FILEBROWSER_IMAGE" == "$CURRENT_IMAGE" ]]', restore
        )
        self.assertIn('[[ "$ROLLBACK_NGINX_IMAGE" == "$CURRENT_NGINX_IMAGE" ]]', restore)
        self.assertIn("configured FileBrowser image must match the backup before apply", restore)

        promote = rollback.rindex("promote_production_nginx")
        runtime = rollback.index('validate-deployment.sh" --production --runtime', promote)
        restart_policy = rollback.index("enable_production_restart_policy", runtime)
        terminal = rollback.index(
            'durable_tsv_set "$STATE_FILE" status rolled-back', restart_policy
        )
        self.assertLess(promote, runtime)
        self.assertLess(runtime, restart_policy)
        self.assertLess(restart_policy, terminal)
        self.assertIn("preserving it for rollback resume", upgrade)

    def test_lifecycle_reconciles_systemd_and_all_container_restart_policies(self) -> None:
        common = (ROOT / "scripts" / "lib" / "deployment-common.sh").read_text(
            encoding="utf-8"
        )
        rollback = (ROOT / "scripts" / "rollback.sh").read_text(encoding="utf-8")
        self.assertIn("systemctl start --no-block filebrowser-enterprise.service", common)
        self.assertIn('docker update --restart=no "${container_ids[@]}"', common)
        self.assertNotIn('compose ps --all -q "$1" 2>/dev/null | head', common)
        self.assertGreaterEqual(rollback.count("queue_systemd_stack_ownership"), 4)

    def test_stable_recovery_runner_and_systemd_wrapper_are_installed(self) -> None:
        installer = (ROOT / "scripts" / "install-debian.sh").read_text(encoding="utf-8")
        recovery = (ROOT / "scripts" / "recover-deployment.sh").read_text(encoding="utf-8")
        unit = (ROOT / "deploy" / "systemd" / "filebrowser-enterprise.service").read_text(encoding="utf-8")
        backup = (ROOT / "scripts" / "backup.sh").read_text(encoding="utf-8")
        self.assertIn("/usr/local/sbin/filebrowser-enterprise-recover 0755 root root", installer)
        self.assertLess(
            recovery.index('"$original_root/scripts/restore.sh"'),
            recovery.index('"$deploy_root/scripts/restore.sh"'),
        )
        self.assertIn("restore journal must be root:root with mode 0600", recovery)
        self.assertIn("ExecStart=/opt/filebrowser-enterprise/scripts/stack.sh start", unit)
        self.assertIn("ExecReload=/opt/filebrowser-enterprise/scripts/stack.sh reload", unit)
        self.assertIn("ExecStop=/opt/filebrowser-enterprise/scripts/stack.sh stop", unit)
        self.assertIn("validate_lifecycle_state_root", backup)
        self.assertNotIn("ensure_lifecycle_state_root", backup)

    def test_bootstrap_protects_recovery_files_and_verifies_emergency_login(self) -> None:
        bootstrap = (ROOT / "scripts" / "bootstrap-admin.sh").read_text(encoding="utf-8")
        self.assertIn("protected_admin_password_value", bootstrap)
        self.assertIn("must be owned by root:$expected_gid", bootstrap)
        self.assertIn("emergency administrator login did not return a JWT", bootstrap)

    def test_shell_image_validation_rejects_implicit_and_public_registries(self) -> None:
        common = (ROOT / "scripts" / "lib" / "deployment-common.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("must include an explicit internal registry host", common)
        for registry in (
            "docker.io",
            "index.docker.io",
            "registry-1.docker.io",
            "registry.hub.docker.com",
            "ghcr.io",
            "quay.io",
        ):
            with self.subTest(registry=registry):
                self.assertIn(registry, common)

    def test_tar_link_cannot_escape_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "unsafe.tar"
            with tarfile.open(archive_path, "w") as archive:
                directory = tarfile.TarInfo("files")
                directory.type = tarfile.DIRTYPE
                archive.addfile(directory)
                link = tarfile.TarInfo("files/outside")
                link.type = tarfile.SYMTYPE
                link.linkname = "../../outside"
                archive.addfile(link)
            with self.assertRaises(validation.ValidationError):
                validation.validate_tar(archive_path, ["files"])

    def test_duplicate_tar_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "duplicate.tar"
            with tarfile.open(archive_path, "w") as archive:
                archive.addfile(tarfile.TarInfo("files/value"))
                archive.addfile(tarfile.TarInfo("files/value"))
            with self.assertRaises(validation.ValidationError):
                validation.validate_tar(archive_path, ["files"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
