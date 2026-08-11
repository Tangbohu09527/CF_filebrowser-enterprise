#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
SHARED_HOST = ROOT / "deploy" / "shared-host"


def load_yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} must contain a YAML mapping")
    return value


def load_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or key in result:
            raise AssertionError(f"invalid environment line: {raw_line!r}")
        result[key] = value
    return result


def bash_executable() -> str:
    candidates = [shutil.which("bash")]
    if os.name == "nt":
        candidates.insert(0, r"C:\Program Files\Git\bin\bash.exe")
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise AssertionError("bash is required for shared-host validation tests")


class SharedHostDeploymentAssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base_path = SHARED_HOST / "compose.yaml"
        cls.debug_path = SHARED_HOST / "compose.debug.yaml"
        cls.build_path = SHARED_HOST / "compose.build.yaml"
        cls.env_path = SHARED_HOST / "compose.env.example"
        cls.config_path = SHARED_HOST / "config.yaml.example"
        cls.base = load_yaml(cls.base_path)
        cls.debug = load_yaml(cls.debug_path)
        cls.build = load_yaml(cls.build_path)
        cls.env = load_env(cls.env_path)
        cls.config = load_yaml(cls.config_path)

    def compose_config(self, directory: Path, *files: str) -> dict:
        docker = shutil.which("docker")
        self.assertIsNotNone(docker, "docker CLI is required for Compose merge tests")
        with tempfile.TemporaryDirectory() as docker_config:
            environment = os.environ.copy()
            environment["DOCKER_CONFIG"] = docker_config
            command = [
                docker,
                "compose",
                "--env-file",
                str(directory / "compose.env.example"),
            ]
            for filename in files:
                command.extend(("-f", str(directory / filename)))
            command.extend(("--profile", "approved", "config", "--format", "json"))
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def run_validator(self, directory: Path, mode: str = "staging") -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        with tempfile.TemporaryDirectory() as docker_config:
            environment["DOCKER_CONFIG"] = docker_config
            return subprocess.run(
                [
                    bash_executable(),
                    (directory / "validate.sh").as_posix(),
                    "--assets-only",
                    "--mode",
                    mode,
                    "--env-file",
                    (directory / "compose.env.example").as_posix(),
                ],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )

    def test_base_compose_has_one_hardened_profiled_service(self) -> None:
        self.assertEqual(self.base["name"], "cf-filebrowser")
        self.assertEqual(set(self.base["services"]), {"filebrowser-enterprise"})
        service = self.base["services"]["filebrowser-enterprise"]
        self.assertEqual(
            service["image"],
            "${FILEBROWSER_IMAGE:?FILEBROWSER_IMAGE must be set explicitly}",
        )
        self.assertEqual(
            service["user"],
            "${FILEBROWSER_UID:?FILEBROWSER_UID is required}:${FILEBROWSER_GID:?FILEBROWSER_GID is required}",
        )
        self.assertEqual(service["profiles"], ["approved"])
        self.assertIs(service["init"], True)
        self.assertEqual(service["restart"], "unless-stopped")
        self.assertIs(service["read_only"], True)
        self.assertEqual(service["cap_drop"], ["ALL"])
        self.assertEqual(service["security_opt"], ["no-new-privileges:true"])
        self.assertEqual(service["expose"], ["8080"])
        self.assertNotIn("ports", service)
        self.assertNotIn("container_name", service)
        self.assertIn("/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777", service["tmpfs"])
        for field in ("cpus", "mem_limit", "pids_limit", "stop_grace_period", "healthcheck"):
            self.assertIn(field, service)

    def test_debug_overlay_only_adds_the_loopback_port(self) -> None:
        self.assertEqual(
            self.debug,
            {
                "services": {
                    "filebrowser-enterprise": {
                        "ports": ["127.0.0.1:18081:8080"],
                    }
                }
            },
        )
        base = self.compose_config(SHARED_HOST, "compose.yaml")
        merged = self.compose_config(
            SHARED_HOST, "compose.yaml", "compose.debug.yaml"
        )
        ports = merged["services"]["filebrowser-enterprise"].pop("ports")
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]["host_ip"], "127.0.0.1")
        self.assertEqual(str(ports[0]["published"]), "18081")
        self.assertEqual(ports[0]["target"], 8080)
        self.assertEqual(merged, base)

    def test_network_is_project_private_and_not_external(self) -> None:
        service = self.base["services"]["filebrowser-enterprise"]
        self.assertEqual(service["networks"], ["private"])
        self.assertEqual(self.base["networks"], {"private": {"driver": "bridge"}})
        network = self.base["networks"]["private"]
        self.assertNotIn("external", network)
        self.assertNotIn("name", network)
        self.assertNotIn("internal", network)

    def test_mounts_are_exactly_within_filebrowser_roots(self) -> None:
        volumes = self.base["services"]["filebrowser-enterprise"]["volumes"]
        expected = [
            ("${CONFIG_ROOT:?CONFIG_ROOT is required}/config.yaml", "/etc/filebrowser-enterprise/config.yaml", True),
            ("${CONFIG_ROOT:?CONFIG_ROOT is required}/secrets", "/run/filebrowser-secrets", True),
            ("${DATA_ROOT:?DATA_ROOT is required}", "/var/lib/filebrowser-enterprise", False),
            ("${CACHE_ROOT:?CACHE_ROOT is required}", "/var/cache/filebrowser-enterprise", False),
            ("${FILES_ROOT:?FILES_ROOT is required}", "/srv/filebrowser/files", False),
            ("${SOURCE_ROOT:?SOURCE_ROOT is required}/scripts/container-entrypoint.sh", "/opt/filebrowser-enterprise/scripts/container-entrypoint.sh", True),
        ]
        actual = [
            (volume["source"], volume["target"], volume.get("read_only", False))
            for volume in volumes
        ]
        self.assertEqual(actual, expected)
        self.assertNotIn("BACKUP_ROOT", self.base_path.read_text(encoding="utf-8"))

    def test_build_override_targets_repository_root_and_records_revision(self) -> None:
        self.assertEqual(set(self.build["services"]), {"filebrowser-enterprise"})
        service = self.build["services"]["filebrowser-enterprise"]
        self.assertEqual(
            service["image"],
            "${FILEBROWSER_BUILD_IMAGE:?FILEBROWSER_BUILD_IMAGE is required}",
        )
        self.assertEqual(service["pull_policy"], "build")
        self.assertEqual(service["build"]["context"], "../..")
        self.assertEqual(service["build"]["dockerfile"], "_docker/Dockerfile")
        self.assertEqual(
            service["build"]["args"],
            {
                "VERSION": "${BUILD_VERSION:?BUILD_VERSION is required}",
                "REVISION": "${BUILD_REVISION:?BUILD_REVISION is required}",
            },
        )
        self.assertNotIn("ports", service)
        rendered = self.compose_config(
            SHARED_HOST, "compose.yaml", "compose.build.yaml"
        )["services"]["filebrowser-enterprise"]
        self.assertEqual(rendered["image"], self.env["FILEBROWSER_BUILD_IMAGE"])
        self.assertEqual(rendered["pull_policy"], "build")
        self.assertEqual(Path(rendered["build"]["context"]).resolve(), ROOT.resolve())
        self.assertEqual(rendered["build"]["dockerfile"], "_docker/Dockerfile")
        self.assertEqual(
            rendered["build"]["args"],
            {
                "VERSION": self.env["BUILD_VERSION"],
                "REVISION": self.env["BUILD_REVISION"],
            },
        )

    def test_environment_contract_uses_dedicated_host_paths(self) -> None:
        expected = {
            "COMPOSE_PROJECT_NAME": "cf-filebrowser",
            "SOURCE_ROOT": "/opt/cf-filebrowser-enterprise",
            "CONFIG_ROOT": "/etc/cf-filebrowser-enterprise",
            "DATA_ROOT": "/var/lib/cf-filebrowser-enterprise",
            "CACHE_ROOT": "/var/cache/cf-filebrowser-enterprise",
            "FILES_ROOT": "/srv/storage/cf-filebrowser-enterprise/files",
            "BACKUP_ROOT": "/srv/storage/cf-filebrowser-enterprise/backups",
            "FILEBROWSER_UID": "10001",
            "FILEBROWSER_GID": "10001",
            "FILEBROWSER_CPUS": "2.0",
            "FILEBROWSER_MEMORY": "2g",
            "FILEBROWSER_PIDS": "256",
            "STOP_GRACE_PERIOD": "60s",
        }
        for key, value in expected.items():
            self.assertEqual(self.env.get(key), value)
        self.assertTrue(self.env.get("FILEBROWSER_IMAGE"))
        self.assertTrue(self.env.get("FILEBROWSER_BUILD_IMAGE"))

    def test_config_has_staging_source_and_least_privilege_defaults(self) -> None:
        server = self.config["server"]
        self.assertEqual(server["listen"], "0.0.0.0")
        self.assertEqual(server["port"], 8080)
        self.assertEqual(server["baseURL"], "/")
        self.assertEqual(server["database"], "/var/lib/filebrowser-enterprise/database.db")
        self.assertEqual(server["cacheDir"], "/var/cache/filebrowser-enterprise")
        self.assertIs(server["disableUpdateCheck"], True)
        self.assertIs(server["disableWebDAV"], True)
        self.assertEqual(len(server["sources"]), 1)
        source = server["sources"][0]
        self.assertEqual(source["path"], "/srv/filebrowser/files")
        self.assertEqual(source["name"], "enterprise-files")
        self.assertIs(source["config"]["private"], True)
        self.assertIs(source["config"]["readOnly"], False)
        self.assertIs(source["config"]["denyByDefault"], False)
        self.assertIs(source["config"]["defaultEnabled"], True)
        permissions = self.config["userDefaults"]["account"]["permissions"]
        self.assertEqual(
            permissions,
            {
                "browse": True,
                "preview": True,
                "download": True,
                "api": False,
                "admin": False,
                "share": False,
                "create": False,
                "modify": False,
                "delete": False,
                "realtime": False,
            },
        )

    def test_templates_contain_no_secret_values_or_gateway_dependencies(self) -> None:
        self.assertNotIn("auth", self.config)
        forbidden_services = {"gateway", "nginx", "postgres", "postgresql", "redis"}
        for compose_path in (self.base_path, self.debug_path, self.build_path):
            compose = load_yaml(compose_path)
            services = {name.lower() for name in compose.get("services", {})}
            self.assertTrue(services.isdisjoint(forbidden_services))
            text = compose_path.read_text(encoding="utf-8").lower()
            for forbidden in ("cf_edge", "cf-edge", "systemd"):
                self.assertNotIn(forbidden, text)
        for key in self.env:
            self.assertNotRegex(key, r"(?:PASSWORD|TOKEN|SECRET|COOKIE)")

    def test_validator_is_read_only_and_contains_all_host_guards(self) -> None:
        text = (SHARED_HOST / "validate.sh").read_text(encoding="utf-8")
        self.assertIn("set -Eeuo pipefail", text)
        for required in (
            "/etc/os-release",
            "2.20",
            "/srv/storage",
            "getent",
            "18081",
            "sha256",
            "jwt_token_secret",
            "totp_secret",
            "bootstrap_admin_password",
        ):
            self.assertIn(required, text)
        self.assertNotRegex(
            text,
            r"(?m)^[ \t]*(?:sudo[ \t]+)?(?:mkdir|install|chown|chmod|rm|rmdir|touch|cp|mv|tee|truncate|dd|apt|apt-get|dnf|yum|useradd|usermod|groupadd|systemctl|iptables|nft|firewall-cmd)\b",
        )
        self.assertNotRegex(text, r"(?m)^[ \t]*sed[ \t]+[^\n]*[ \t]-i\b")
        self.assertNotRegex(
            text,
            r"(?m)^[ \t]*(?:sudo[ \t]+)?docker[ \t]+(?:compose[ \t]+)?(?:pull|build|run|up|start|create|network|image|container)\b",
        )

    def test_validator_passes_templates_and_fails_closed(self) -> None:
        valid = self.run_validator(SHARED_HOST)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertIn("host preparation checks were not run", valid.stdout)

        production = self.run_validator(SHARED_HOST, mode="production")
        self.assertNotEqual(production.returncode, 0)
        self.assertIn("immutable digest", production.stderr)

        mutations = {
            "base port": (
                "compose.yaml",
                lambda value: value["services"]["filebrowser-enterprise"].__setitem__(
                    "ports", ["127.0.0.1:19000:8080"]
                ),
            ),
            "container name": (
                "compose.yaml",
                lambda value: value["services"]["filebrowser-enterprise"].__setitem__(
                    "container_name", "forbidden"
                ),
            ),
            "external network": (
                "compose.yaml",
                lambda value: value["networks"].__setitem__(
                    "private", {"external": True, "name": "forbidden-private"}
                ),
            ),
            "fixed network name": (
                "compose.yaml",
                lambda value: value["networks"]["private"].__setitem__(
                    "name", "forbidden-private"
                ),
            ),
            "root user": (
                "compose.yaml",
                lambda value: value["services"]["filebrowser-enterprise"].__setitem__(
                    "user", "0:0"
                ),
            ),
            "privileged service": (
                "compose.yaml",
                lambda value: value["services"]["filebrowser-enterprise"].__setitem__(
                    "privileged", True
                ),
            ),
            "disabled healthcheck": (
                "compose.yaml",
                lambda value: value["services"]["filebrowser-enterprise"].__setitem__(
                    "healthcheck", {"disable": True}
                ),
            ),
            "extra service": (
                "compose.yaml",
                lambda value: value["services"].__setitem__(
                    "nginx", {"image": "nginx:forbidden"}
                ),
            ),
            "host mount": (
                "compose.yaml",
                lambda value: value["services"]["filebrowser-enterprise"]["volumes"].append(
                    {
                        "type": "bind",
                        "source": "/var/run/docker.sock",
                        "target": "/var/run/docker.sock",
                    }
                ),
            ),
            "extra debug port": (
                "compose.debug.yaml",
                lambda value: value["services"]["filebrowser-enterprise"]["ports"].append(
                    "0.0.0.0:18080:8080"
                ),
            ),
        }
        for label, (filename, mutate) in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                copied = Path(temp_dir) / "shared-host"
                shutil.copytree(SHARED_HOST, copied)
                compose_path = copied / filename
                compose = load_yaml(compose_path)
                mutate(compose)
                compose_path.write_text(
                    yaml.safe_dump(compose, sort_keys=False), encoding="utf-8"
                )
                result = self.run_validator(copied)
                self.assertNotEqual(result.returncode, 0)

    def test_validator_rejects_unbounded_resource_values(self) -> None:
        mutations = (
            ("FILEBROWSER_CPUS=2.0", "FILEBROWSER_CPUS=0"),
            ("FILEBROWSER_MEMORY=2g", "FILEBROWSER_MEMORY=0"),
            ("FILEBROWSER_PIDS=256", "FILEBROWSER_PIDS=-1"),
            ("STOP_GRACE_PERIOD=60s", "STOP_GRACE_PERIOD=0s"),
        )
        for original, replacement in mutations:
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temp_dir:
                copied = Path(temp_dir) / "shared-host"
                shutil.copytree(SHARED_HOST, copied)
                env_path = copied / "compose.env.example"
                text = env_path.read_text(encoding="utf-8")
                self.assertIn(original, text)
                env_path.write_text(text.replace(original, replacement), encoding="utf-8")
                result = self.run_validator(copied)
                self.assertNotEqual(result.returncode, 0)

    def test_validator_rejects_secrets_without_printing_them(self) -> None:
        sentinel = "shared-host-validation-secret-sentinel"
        with tempfile.TemporaryDirectory() as temp_dir:
            copied = Path(temp_dir) / "shared-host"
            shutil.copytree(SHARED_HOST, copied)
            config_path = copied / "config.yaml.example"
            config = load_yaml(config_path)
            config["auth"] = {"key": sentinel}
            config_path.write_text(
                yaml.safe_dump(config, sort_keys=False), encoding="utf-8"
            )
            result = self.run_validator(copied)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(sentinel, result.stdout)
            self.assertNotIn(sentinel, result.stderr)

        with tempfile.TemporaryDirectory() as temp_dir:
            copied = Path(temp_dir) / "shared-host"
            shutil.copytree(SHARED_HOST, copied)
            env_path = copied / "compose.env.example"
            with env_path.open("a", encoding="utf-8") as env_file:
                env_file.write(f"\n  export ADMIN_PASSWORD={sentinel}\n")
            result = self.run_validator(copied)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(sentinel, result.stdout)
            self.assertNotIn(sentinel, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
