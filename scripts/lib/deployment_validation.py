#!/usr/bin/env python3
"""Strict structural validation for FileBrowser Enterprise deployment assets."""

from __future__ import annotations

import argparse
import ipaddress
import posixpath
import re
import sys
import tarfile
from pathlib import Path
from typing import Any

import yaml


class ValidationError(ValueError):
    pass


PINNED_IMAGE = re.compile(r"^[^\s]+@sha256:([0-9a-fA-F]{64})$")
PUBLIC_REGISTRIES = {
    "docker.io",
    "index.docker.io",
    "registry-1.docker.io",
    "registry.hub.docker.com",
    "ghcr.io",
    "quay.io",
    "registry.gitlab.com",
    "public.ecr.aws",
}


def fail(message: str) -> None:
    raise ValidationError(message)


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        fail(f"cannot parse YAML {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"YAML root must be a mapping: {path}")
    return value


def load_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        fail(f"cannot read environment file {path}: {exc}")
    for line_number, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw != stripped:
            fail(f"environment assignments must not have leading or trailing whitespace at {path}:{line_number}")
        line = raw
        if "=" not in line:
            fail(f"invalid environment line {path}:{line_number}")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            fail(f"invalid environment key {key!r} at {path}:{line_number}")
        if key in result:
            fail(f"duplicate environment key {key!r} at {path}:{line_number}")
        if "\x00" in value or "\r" in value:
            fail(f"invalid control character in environment value {key!r}")
        result[key] = value
    return result


def require_mapping(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        fail(f"{key} must be a mapping")
    return value


def require_value(parent: dict[str, Any], key: str, expected: Any, prefix: str) -> None:
    if key not in parent:
        fail(f"{prefix}.{key} must be explicit")
    if parent[key] != expected:
        fail(f"{prefix}.{key} must be {expected!r}, got {parent[key]!r}")


def validate_pinned_image(value: str, label: str, template: bool = False) -> None:
    match = PINNED_IMAGE.fullmatch(value)
    if not match:
        fail(f"{label} must be pinned with @sha256:<64 hex>")
    if ":latest@sha256:" in value:
        fail(f"{label} must not use latest")
    digest = match.group(1).lower()
    placeholder = len(set(digest)) == 1
    if placeholder and not template:
        fail(f"{label} uses a placeholder digest")


def validate_internal_registry(value: str, label: str) -> None:
    image_name = value.rsplit("@", 1)[0]
    registry, separator, repository = image_name.partition("/")
    if not separator or not repository or not ("." in registry or ":" in registry):
        fail(f"{label} must be registry-qualified; implicit Docker Hub names are forbidden")
    registry_host = registry.lower().split(":", 1)[0]
    if registry_host in PUBLIC_REGISTRIES:
        fail(f"{label} must use an approved internal registry mirror")


def validate_env(env: dict[str, str], template: bool) -> None:
    required = {
        "COMPOSE_PROJECT_NAME",
        "INTERNAL_REGISTRY_HOST",
        "FILEBROWSER_IMAGE",
        "NGINX_IMAGE",
        "DEPLOY_ROOT",
        "CONFIG_ROOT",
        "DATA_ROOT",
        "CACHE_ROOT",
        "FILES_ROOT",
        "BACKUP_ROOT",
        "BACKUP_RETENTION_COUNT",
        "FILEBROWSER_UID",
        "FILEBROWSER_GID",
        "NGINX_UID",
        "NGINX_GID",
        "HTTP_BIND_ADDRESS",
        "HTTPS_BIND_ADDRESS",
        "PUBLIC_HOST",
        "EXTERNAL_URL",
        "TLS_CERT_FILE",
        "TLS_KEY_FILE",
        "TLS_CERT_CONTAINER_PATH",
        "TLS_KEY_CONTAINER_PATH",
        "HTTP_PORT",
        "HTTPS_PORT",
        "MAX_UPLOAD_SIZE",
        "CLIENT_BODY_TIMEOUT",
        "PROXY_READ_TIMEOUT",
        "PROXY_SEND_TIMEOUT",
        "AUTH_RATE",
        "AUTH_BURST",
        "AUTH_GLOBAL_RATE",
        "AUTH_GLOBAL_BURST",
        "LOG_MAX_SIZE",
        "LOG_MAX_FILES",
        "FILEBROWSER_CPUS",
        "FILEBROWSER_MEMORY",
        "FILEBROWSER_PIDS",
        "NGINX_CPUS",
        "NGINX_MEMORY",
        "NGINX_PIDS",
        "STOP_GRACE_PERIOD",
        "MIN_CACHE_FREE_MB",
        "BOOTSTRAP_ADMIN_USERNAME",
        "EMERGENCY_ADMIN_USERNAME",
    }
    missing = sorted(key for key in required if not env.get(key))
    if missing:
        fail(f"environment keys are missing: {', '.join(missing)}")
    unknown = sorted(set(env) - required)
    if unknown:
        fail(f"unknown environment keys are forbidden: {', '.join(unknown)}")
    interpolated = sorted(key for key, value in env.items() if "$" in value)
    if interpolated:
        fail(f"environment values must not contain secondary interpolation: {', '.join(interpolated)}")
    ambiguous = sorted(
        key
        for key, value in env.items()
        if value != value.strip() or any(character in value for character in ("#", "'", '"', "\\"))
    )
    if ambiguous:
        fail(f"environment values use ambiguous dotenv syntax: {', '.join(ambiguous)}")
    if env["COMPOSE_PROJECT_NAME"] != "filebrowser-enterprise":
        fail("COMPOSE_PROJECT_NAME must be exactly filebrowser-enterprise")
    internal_registry = env["INTERNAL_REGISTRY_HOST"]
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[1-9][0-9]{0,4})?", internal_registry):
        fail("INTERNAL_REGISTRY_HOST must be a lowercase DNS/IPv4 host with an optional port")
    registry_name, _, registry_port = internal_registry.partition(":")
    if registry_port and int(registry_port) > 65535:
        fail("INTERNAL_REGISTRY_HOST port exceeds 65535")
    if registry_name in PUBLIC_REGISTRIES:
        fail("INTERNAL_REGISTRY_HOST must not name a public registry")
    if not template and (
        registry_name in {"localhost", "example.com"}
        or registry_name.endswith((".invalid", ".example", ".test"))
    ):
        fail("INTERNAL_REGISTRY_HOST is still a documentation placeholder")
    validate_pinned_image(env["FILEBROWSER_IMAGE"], "FILEBROWSER_IMAGE", template)
    validate_pinned_image(env["NGINX_IMAGE"], "NGINX_IMAGE", template)
    if "gtstef/filebrowser" in env["FILEBROWSER_IMAGE"].lower():
        fail("FILEBROWSER_IMAGE must not default to the upstream image")
    for key in ("FILEBROWSER_IMAGE", "NGINX_IMAGE"):
        validate_internal_registry(env[key], key)
        image_registry = env[key].rsplit("@", 1)[0].partition("/")[0].lower()
        if image_registry != internal_registry:
            fail(f"{key} registry must exactly match INTERNAL_REGISTRY_HOST")
        lowered = env[key].lower()
        if not template and ".invalid/" in lowered:
            fail(f"{key} still uses the documentation registry")
    for key in ("DEPLOY_ROOT", "CONFIG_ROOT", "DATA_ROOT", "CACHE_ROOT", "FILES_ROOT", "BACKUP_ROOT"):
        value = env[key]
        if (
            not value.startswith("/")
            or value == "/"
            or value.endswith("/")
            or "//" in value
            or "/../" in f"/{value}/"
            or "/./" in f"/{value}/"
        ):
            fail(f"{key} must be a safe absolute path")
    if env["DEPLOY_ROOT"] != "/opt/filebrowser-enterprise":
        fail("DEPLOY_ROOT must match the fixed systemd WorkingDirectory /opt/filebrowser-enterprise")
    if env["BACKUP_ROOT"] != "/var/backups/filebrowser-enterprise":
        fail("BACKUP_ROOT must match the backup unit sandbox /var/backups/filebrowser-enterprise")
    for key in (
        "FILEBROWSER_UID",
        "FILEBROWSER_GID",
        "NGINX_UID",
        "NGINX_GID",
        "FILEBROWSER_PIDS",
        "NGINX_PIDS",
        "MIN_CACHE_FREE_MB",
        "AUTH_BURST",
        "AUTH_GLOBAL_BURST",
        "LOG_MAX_FILES",
        "BACKUP_RETENTION_COUNT",
    ):
        if not env[key].isdigit() or int(env[key]) <= 0:
            fail(f"{key} must be a positive integer")
    if int(env["BACKUP_RETENTION_COUNT"]) > 3650:
        fail("BACKUP_RETENTION_COUNT exceeds the supported safety bound")
    if env["HTTP_PORT"] != "80" or env["HTTPS_PORT"] != "443":
        fail("Nginx must publish the standard host ports 80 and 443")
    for key in ("HTTP_BIND_ADDRESS", "HTTPS_BIND_ADDRESS"):
        try:
            ipaddress.ip_address(env[key])
        except ValueError:
            fail(f"{key} must be a literal IPv4 or IPv6 address")
    if not re.fullmatch(r"[1-9][0-9]*[kKmMgG]", env["MAX_UPLOAD_SIZE"]):
        fail("MAX_UPLOAD_SIZE must be a positive integer with a K, M, or G suffix")
    for key in ("CLIENT_BODY_TIMEOUT", "PROXY_READ_TIMEOUT", "PROXY_SEND_TIMEOUT"):
        if not re.fullmatch(r"[1-9][0-9]*[smh]", env[key]):
            fail(f"{key} must be a positive integer with an s, m, or h suffix")
    if not re.fullmatch(r"[1-9][0-9]*r/[ms]", env["AUTH_RATE"]):
        fail("AUTH_RATE must use Nginx rate syntax such as 10r/m")
    if not re.fullmatch(r"[1-9][0-9]*r/[ms]", env["AUTH_GLOBAL_RATE"]):
        fail("AUTH_GLOBAL_RATE must use Nginx rate syntax such as 8r/m")
    if not re.fullmatch(r"[1-9][0-9]*[kKmMgG]", env["LOG_MAX_SIZE"]):
        fail("LOG_MAX_SIZE must use a bounded Docker size such as 50m")
    for key in ("FILEBROWSER_MEMORY", "NGINX_MEMORY"):
        if not re.fullmatch(r"[1-9][0-9]*[kKmMgG]", env[key]):
            fail(f"{key} must be a positive bounded size such as 512m")
    for key in ("FILEBROWSER_CPUS", "NGINX_CPUS"):
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", env[key]) or float(env[key]) <= 0:
            fail(f"{key} must be a positive decimal CPU limit")
    if not re.fullmatch(r"[1-9][0-9]*s", env["STOP_GRACE_PERIOD"]):
        fail("STOP_GRACE_PERIOD must be a positive number of seconds")
    if env["TLS_CERT_FILE"] != env["CONFIG_ROOT"].rstrip("/") + "/tls/tls.crt":
        fail("TLS_CERT_FILE must be CONFIG_ROOT/tls/tls.crt")
    if env["TLS_KEY_FILE"] != env["CONFIG_ROOT"].rstrip("/") + "/tls/tls.key":
        fail("TLS_KEY_FILE must be CONFIG_ROOT/tls/tls.key")
    if env.get("TLS_CERT_CONTAINER_PATH") != "/etc/nginx/tls/tls.crt":
        fail("TLS_CERT_CONTAINER_PATH must be /etc/nginx/tls/tls.crt")
    if env.get("TLS_KEY_CONTAINER_PATH") != "/etc/nginx/tls/tls.key":
        fail("TLS_KEY_CONTAINER_PATH must be /etc/nginx/tls/tls.key")
    host = env["PUBLIC_HOST"]
    if (
        len(host) > 253
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host)
        or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split("."))
    ):
        fail("PUBLIC_HOST must be a valid lowercase DNS hostname")
    if env["EXTERNAL_URL"] != f"https://{host}":
        fail("EXTERNAL_URL must be exactly https://PUBLIC_HOST")
    if not template and (host.endswith(".invalid") or ".example." in host or host in {"localhost", "example.com"}):
        fail("PUBLIC_HOST is still a documentation placeholder")


def validate_config(config: dict[str, Any], env: dict[str, str], template: bool) -> None:
    if "http" in config:
        fail("top-level http is forbidden until the current application loader stops discarding it")
    allowed_top = {"server", "auth", "frontend", "userDefaults", "integrations"}
    unknown = sorted(set(config) - allowed_top)
    if unknown:
        fail(f"unknown top-level config fields: {', '.join(unknown)}")

    server = require_mapping(config, "server")
    expected_server = {
        "port": 8080,
        "listen": "0.0.0.0",
        "baseURL": "/",
        "database": "/var/lib/filebrowser-enterprise/database.db",
        "cacheDir": "/var/cache/filebrowser-enterprise",
        "cacheDirCleanup": False,
        "disableUpdateCheck": True,
        "disableWebDAV": True,
    }
    for key, expected in expected_server.items():
        require_value(server, key, expected, "server")
    archive_limit = server.get("maxArchiveSize")
    if not isinstance(archive_limit, int) or not 1 <= archive_limit <= 100:
        fail("server.maxArchiveSize must be explicit and between 1 and 100 GiB")
    external_url = server.get("externalUrl")
    if external_url != env["EXTERNAL_URL"]:
        fail("server.externalUrl must match EXTERNAL_URL")
    if not template and str(external_url).endswith(".invalid"):
        fail("server.externalUrl is still a placeholder")

    logging = server.get("logging")
    if not isinstance(logging, list) or not logging or not isinstance(logging[0], dict):
        fail("server.logging must contain an explicit production sink")
    require_value(logging[0], "apiLevels", "disabled", "server.logging[0]")
    require_value(logging[0], "output", "stdout", "server.logging[0]")

    sources = server.get("sources")
    if not isinstance(sources, list) or len(sources) != 1 or not isinstance(sources[0], dict):
        fail("server.sources must contain exactly the enterprise files source")
    source = sources[0]
    require_value(source, "path", "/srv/filebrowser/files", "server.sources[0]")
    require_value(source, "name", "enterprise-files", "server.sources[0]")
    source_config = require_mapping(source, "config")
    require_value(source_config, "private", True, "server.sources[0].config")
    require_value(source_config, "defaultEnabled", True, "server.sources[0].config")

    auth = require_mapping(config, "auth")
    require_value(auth, "key", "", "auth")
    require_value(auth, "adminPassword", "", "auth")
    require_value(auth, "totpSecret", "", "auth")
    require_value(auth, "adminUsername", env["BOOTSTRAP_ADMIN_USERNAME"], "auth")
    methods = require_mapping(auth, "methods")
    require_value(methods, "noauth", False, "auth.methods")
    for method_name in ("proxy", "jwt", "oidc", "ldap"):
        method = methods.get(method_name)
        if isinstance(method, dict) and method.get("enabled") is True:
            fail(f"auth.methods.{method_name} requires a separate deployment security review")
    password = require_mapping(methods, "password")
    require_value(password, "enabled", True, "auth.methods.password")
    require_value(password, "signup", False, "auth.methods.password")
    if not isinstance(password.get("minLength"), int) or password["minLength"] < 14:
        fail("auth.methods.password.minLength must be at least 14")

    defaults = require_mapping(config, "userDefaults")
    account = require_mapping(defaults, "account")
    permissions = require_mapping(account, "permissions")
    for permission in ("api", "admin", "modify", "share", "realtime", "delete", "create"):
        require_value(permissions, permission, False, f"userDefaults.account.permissions")
    for permission in ("browse", "preview", "download"):
        require_value(permissions, permission, True, f"userDefaults.account.permissions")


def validate_compose(compose: dict[str, Any]) -> None:
    if set(compose) != {"name", "services", "networks"}:
        fail("production Compose top-level fields must be exactly name, services, and networks")
    if compose.get("name") != "filebrowser-enterprise":
        fail("Compose project name must be the fixed literal filebrowser-enterprise")
    services = compose.get("services")
    if not isinstance(services, dict):
        fail("compose services must be a mapping")
    if set(services) != {"filebrowser-enterprise", "nginx"}:
        fail("compose must contain only filebrowser-enterprise and nginx")
    if any("hermes" in str(value).lower() for value in services.values()):
        fail("Hermes must not be deployed by this stack")
    app = require_mapping(services, "filebrowser-enterprise")
    nginx = require_mapping(services, "nginx")
    expected_app_keys = {
        "image", "user", "init", "restart", "stop_grace_period", "read_only",
        "entrypoint", "environment", "volumes", "tmpfs", "expose", "networks",
        "healthcheck", "security_opt", "cap_drop", "pids_limit", "mem_limit",
        "cpus", "logging",
    }
    expected_nginx_keys = {
        "image", "user", "init", "restart", "stop_grace_period", "read_only",
        "entrypoint", "environment", "volumes", "tmpfs", "ports", "networks",
        "depends_on", "healthcheck", "security_opt", "cap_drop", "pids_limit",
        "mem_limit", "cpus", "logging",
    }
    if set(app) != expected_app_keys:
        fail("FileBrowser service fields differ from the production allowlist")
    if set(nginx) != expected_nginx_keys:
        fail("Nginx service fields differ from the production allowlist")
    expected_service_values = {
        "FileBrowser": {
            "image": "${FILEBROWSER_IMAGE:?FILEBROWSER_IMAGE must be an internal image pinned by digest}",
            "user": "${FILEBROWSER_UID:?FILEBROWSER_UID is required}:${FILEBROWSER_GID:?FILEBROWSER_GID is required}",
            "init": True,
            "restart": "unless-stopped",
            "stop_grace_period": "${STOP_GRACE_PERIOD:-60s}",
            "entrypoint": ["/opt/filebrowser-enterprise/scripts/container-entrypoint.sh"],
            "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"],
            "networks": ["backend"],
        },
        "Nginx": {
            "image": "${NGINX_IMAGE:?NGINX_IMAGE must be an approved image pinned by digest}",
            "user": "${NGINX_UID:?NGINX_UID is required}:${NGINX_GID:?NGINX_GID is required}",
            "init": True,
            "restart": "unless-stopped",
            "stop_grace_period": "30s",
            "entrypoint": ["/opt/filebrowser-enterprise/scripts/nginx-entrypoint.sh"],
            "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777"],
            "networks": ["ingress", "backend"],
        },
    }
    for label, service in (("FileBrowser", app), ("Nginx", nginx)):
        for key, expected in expected_service_values[label].items():
            require_value(service, key, expected, label)
    expected_app_environment = {
        "FILEBROWSER_CONFIG": "/etc/filebrowser-enterprise/config.yaml",
        "FILEBROWSER_DATABASE": "/var/lib/filebrowser-enterprise/database.db",
        "FILEBROWSER_JWT_TOKEN_SECRET_FILE": "/run/filebrowser-secrets/jwt_token_secret",
        "FILEBROWSER_TOTP_SECRET_FILE": "/run/filebrowser-secrets/totp_secret",
        "FILEBROWSER_BOOTSTRAP_PASSWORD_FILE": "/run/filebrowser-secrets/bootstrap_admin_password",
    }
    if app.get("environment") != expected_app_environment:
        fail("FileBrowser environment must use only the fixed in-container paths")
    expected_app_volumes = [
        {"type": "bind", "source": "${CONFIG_ROOT:?CONFIG_ROOT is required}/config.yaml", "target": "/etc/filebrowser-enterprise/config.yaml", "read_only": True},
        {"type": "bind", "source": "${CONFIG_ROOT:?CONFIG_ROOT is required}/secrets", "target": "/run/filebrowser-secrets", "read_only": True},
        {"type": "bind", "source": "${DATA_ROOT:?DATA_ROOT is required}", "target": "/var/lib/filebrowser-enterprise"},
        {"type": "bind", "source": "${CACHE_ROOT:?CACHE_ROOT is required}", "target": "/var/cache/filebrowser-enterprise"},
        {"type": "bind", "source": "${FILES_ROOT:?FILES_ROOT is required}", "target": "/srv/filebrowser/files"},
        {"type": "bind", "source": "${DEPLOY_ROOT:?DEPLOY_ROOT is required}/scripts/container-entrypoint.sh", "target": "/opt/filebrowser-enterprise/scripts/container-entrypoint.sh", "read_only": True},
    ]
    if app.get("volumes") != expected_app_volumes:
        fail("FileBrowser mounts must match the production allowlist")
    if "ports" in app:
        fail("FileBrowser must not publish a host port")
    if app.get("expose") != ["8080"]:
        fail("FileBrowser must expose only port 8080 to the private network")
    expected_health_tests = {
        "FileBrowser": [
            "CMD-SHELL",
            "app_health=$$(curl --fail --silent --show-error http://127.0.0.1:8080/health) && [ \"$$app_health\" = '{\"message\":\"ok\"}' ]",
        ],
        "Nginx": [
            "CMD-SHELL",
            "wget -q --spider --no-check-certificate --header=Host:$${PUBLIC_HOST} https://127.0.0.1:8443/nginx-health && backend_health=$$(wget -qO- http://filebrowser-enterprise:8080/health) && printf '%s' \"$$backend_health\" | grep -Fqx '{\"message\":\"ok\"}'",
        ],
    }
    for label, service in (("FileBrowser", app), ("Nginx", nginx)):
        if "deploy" in service or "scale" in service:
            fail(f"{label} must not declare deploy replicas or scale; lifecycle scripts enforce one instance")
        require_value(service, "read_only", True, label)
        if service.get("cap_drop") != ["ALL"]:
            fail(f"{label} must drop all Linux capabilities")
        if service.get("security_opt") != ["no-new-privileges:true"]:
            fail(f"{label} must enable no-new-privileges")
        if not service.get("user") or not service.get("healthcheck"):
            fail(f"{label} must have an explicit user and healthcheck")
        healthcheck = require_mapping(service, "healthcheck")
        health_test = healthcheck.get("test")
        if health_test != expected_health_tests[label]:
            fail(f"{label} healthcheck must use the exact fail-closed probe")
        for health_key in ("interval", "timeout", "start_period", "retries"):
            if not healthcheck.get(health_key):
                fail(f"{label} healthcheck.{health_key} must be explicit")
        if not service.get("pids_limit") or not service.get("mem_limit") or not service.get("cpus"):
            fail(f"{label} must have PID, memory, and CPU limits")
        logging = service.get("logging")
        if not isinstance(logging, dict) or logging.get("driver") != "local":
            fail(f"{label} must use Docker's rotating local log driver")
        options = logging.get("options")
        expected_log_options = {
            "max-size": "${LOG_MAX_SIZE:-50m}",
            "max-file": "${LOG_MAX_FILES:-5}",
        }
        if options != expected_log_options:
            fail(f"{label} log rotation limits must use the validated LOG_MAX_SIZE and LOG_MAX_FILES values")
    ports = nginx.get("ports")
    expected_ports = {
        "${HTTP_BIND_ADDRESS:-127.0.0.1}:${HTTP_PORT:-80}:8080",
        "${HTTPS_BIND_ADDRESS:-127.0.0.1}:${HTTPS_PORT:-443}:8443",
    }
    if not isinstance(ports, list) or set(ports) != expected_ports or len(ports) != len(expected_ports):
        fail("Nginx must be the only service publishing 80 and 443")
    nginx_volumes = nginx.get("volumes")
    expected_nginx_volumes = [
        {"type": "bind", "source": "${DEPLOY_ROOT:?DEPLOY_ROOT is required}/nginx/nginx.conf", "target": "/etc/nginx/nginx.conf", "read_only": True},
        {"type": "bind", "source": "${DEPLOY_ROOT:?DEPLOY_ROOT is required}/nginx/filebrowser.conf.template", "target": "/etc/nginx/templates/filebrowser.conf.template", "read_only": True},
        {"type": "bind", "source": "${DEPLOY_ROOT:?DEPLOY_ROOT is required}/scripts/nginx-entrypoint.sh", "target": "/opt/filebrowser-enterprise/scripts/nginx-entrypoint.sh", "read_only": True},
        {"type": "bind", "source": "${CONFIG_ROOT:?CONFIG_ROOT is required}/tls", "target": "/etc/nginx/tls", "read_only": True},
    ]
    if nginx_volumes != expected_nginx_volumes:
        fail("Nginx mounts must match the production allowlist")
    expected_nginx_environment = {
        "PUBLIC_HOST": "${PUBLIC_HOST:?PUBLIC_HOST is required}",
        "MAX_UPLOAD_SIZE": "${MAX_UPLOAD_SIZE:-20g}",
        "CLIENT_BODY_TIMEOUT": "${CLIENT_BODY_TIMEOUT:-3600s}",
        "PROXY_READ_TIMEOUT": "${PROXY_READ_TIMEOUT:-3600s}",
        "PROXY_SEND_TIMEOUT": "${PROXY_SEND_TIMEOUT:-3600s}",
        "AUTH_RATE": "${AUTH_RATE:-3r/m}",
        "AUTH_BURST": "${AUTH_BURST:-2}",
        "AUTH_GLOBAL_RATE": "${AUTH_GLOBAL_RATE:-8r/m}",
        "AUTH_GLOBAL_BURST": "${AUTH_GLOBAL_BURST:-4}",
        "TLS_CERT_CONTAINER_PATH": "${TLS_CERT_CONTAINER_PATH:-/etc/nginx/tls/tls.crt}",
        "TLS_KEY_CONTAINER_PATH": "${TLS_KEY_CONTAINER_PATH:-/etc/nginx/tls/tls.key}",
    }
    if nginx.get("environment") != expected_nginx_environment:
        fail("Nginx environment must match the production allowlist")
    if nginx.get("depends_on") != {"filebrowser-enterprise": {"condition": "service_healthy", "restart": True}}:
        fail("Nginx must depend on a healthy FileBrowser singleton")
    networks = compose.get("networks")
    if networks != {"ingress": {"driver": "bridge"}, "backend": {"driver": "bridge", "internal": True}}:
        fail("Compose networks must be one ingress bridge and one internal backend bridge")


def validate_maintenance_compose(compose: dict[str, Any]) -> None:
    expected = {
        "services": {
            "filebrowser-enterprise": {"restart": "no"},
            "nginx": {
                "restart": "no",
                "volumes": [{
                    "type": "bind",
                    "source": "${DEPLOY_ROOT:?DEPLOY_ROOT is required}/nginx/filebrowser-maintenance.conf.template",
                    "target": "/etc/nginx/templates/filebrowser.conf.template",
                    "read_only": True,
                }],
            },
        }
    }
    if compose != expected:
        fail("maintenance Compose override may only disable restarts and replace the Nginx template")


def validate_maintenance_nginx(template: str) -> None:
    for requirement in (
        "ssl_protocols TLSv1.2 TLSv1.3",
        "location = /nginx-health",
        "allow 127.0.0.1",
        "location /",
        "return 503",
    ):
        if requirement not in template:
            fail(f"maintenance Nginx requirement is missing: {requirement}")
    if "proxy_pass" in template:
        fail("maintenance Nginx must not proxy business requests")


def validate_build_compose(build: dict[str, Any], root: Path) -> None:
    if set(build) != {"services"} or set(require_mapping(build, "services")) != {"filebrowser-enterprise"}:
        fail("build override may contain only the FileBrowser service")
    build_service = require_mapping(require_mapping(build, "services"), "filebrowser-enterprise")
    if set(build_service) != {"image", "pull_policy", "build"}:
        fail("build override FileBrowser fields differ from the allowlist")
    if build_service.get("image") != "${FILEBROWSER_BUILD_IMAGE:-filebrowser-enterprise:local-validation}":
        fail("build override image must use the documented local-only default")
    if build_service.get("pull_policy") != "build":
        fail("build override pull policy must be build")
    build_config = require_mapping(build_service, "build")
    expected_build = {
        "context": "..",
        "dockerfile": "_docker/Dockerfile",
        "args": {
            "VERSION": "${BUILD_VERSION:-internal}",
            "REVISION": "${BUILD_REVISION:-uncommitted}",
        },
    }
    if build_config != expected_build:
        fail("build override must use the exact repository Dockerfile and documented arguments")
    if not (root / "_docker" / "Dockerfile").is_file():
        fail("production build Dockerfile is missing")


def validate_nginx(nginx_conf: str, template: str) -> None:
    combined = nginx_conf + "\n" + template
    requirements = (
        "ssl_protocols TLSv1.2 TLSv1.3",
        "Strict-Transport-Security",
        "proxy_set_header X-Real-IP $remote_addr",
        "proxy_set_header X-Forwarded-For $remote_addr",
        "proxy_set_header X-Forwarded-Proto https",
        "proxy_buffering off",
        "proxy_request_buffering off",
        'if ($http_depth ~* "^[[:space:]]*infinity[[:space:]]*$") { return 403; }',
        "proxy_cookie_flags ~ secure httponly samesite=strict",
        "limit_req_zone $binary_remote_addr",
        "limit_req_zone $server_name",
        '"$request_method $uri $server_protocol"',
    )
    for requirement in requirements:
        if requirement not in combined:
            fail(f"Nginx requirement is missing: {requirement}")
    if "$proxy_add_x_forwarded_for" in combined:
        fail("Nginx must overwrite, not append, X-Forwarded-For")
    for identity_header in ('proxy_set_header X-Forwarded-User ""', 'proxy_set_header X-Auth-Request-User ""'):
        if identity_header not in combined:
            fail(f"Nginx must clear untrusted identity header: {identity_header}")
    log_section = nginx_conf[nginx_conf.find("log_format") : nginx_conf.find("access_log")]
    if "$request_uri" in log_section or "$args" in log_section:
        fail("Nginx access log must not contain query strings")
    if re.search(r"Authorization|\$http_cookie", log_section, re.IGNORECASE):
        fail("Nginx access log must not contain Authorization or Cookie")
    if "$remote_user" in log_section:
        fail("Nginx access log must not derive identity from Authorization")


def validate_tar(path: Path, prefixes: list[str]) -> None:
    if not path.is_file() or path.is_symlink():
        fail(f"tar archive is missing or unsafe: {path}")
    allowed_prefixes = [posixpath.normpath(prefix) for prefix in prefixes]
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot inspect tar archive {path}: {exc}")
    if not members:
        fail(f"tar archive is empty: {path}")
    seen_names: set[str] = set()
    for member in members:
        name = member.name
        normalized = posixpath.normpath(name)
        if name.startswith("/") or normalized in {"", ".", ".."} or normalized.startswith("../"):
            fail(f"unsafe tar member path in {path}: {name}")
        if normalized in seen_names:
            fail(f"duplicate tar member path in {path}: {name}")
        seen_names.add(normalized)
        if allowed_prefixes and not any(
            normalized == prefix or normalized.startswith(prefix + "/") for prefix in allowed_prefixes
        ):
            fail(f"unexpected tar member prefix in {path}: {name}")
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            fail(f"special tar member type is forbidden in {path}: {name}")
        if member.issym() or member.islnk():
            link = member.linkname
            if not link or link.startswith("/"):
                fail(f"absolute or empty tar link is forbidden in {path}: {name}")
            if member.issym():
                resolved_link = posixpath.normpath(posixpath.join(posixpath.dirname(normalized), link))
            else:
                resolved_link = posixpath.normpath(link)
            if resolved_link == ".." or resolved_link.startswith("../"):
                fail(f"tar link escapes archive root in {path}: {name} -> {link}")
            if allowed_prefixes and not any(
                resolved_link == prefix or resolved_link.startswith(prefix + "/") for prefix in allowed_prefixes
            ):
                fail(f"tar link escapes expected payload in {path}: {name} -> {link}")


def validate_repository(root: Path) -> None:
    env = load_env(root / "deploy" / "compose.env.example")
    validate_env(env, template=True)
    validate_config(load_yaml(root / "deploy" / "config.yaml.example"), env, template=True)
    validate_compose(load_yaml(root / "deploy" / "compose.yaml"))
    validate_maintenance_compose(load_yaml(root / "deploy" / "compose.maintenance.yaml"))
    validate_build_compose(load_yaml(root / "deploy" / "compose.build.yaml"), root)
    validate_nginx(
        (root / "deploy" / "nginx" / "nginx.conf").read_text(encoding="utf-8"),
        (root / "deploy" / "nginx" / "filebrowser.conf.template").read_text(encoding="utf-8"),
    )
    validate_maintenance_nginx(
        (root / "deploy" / "nginx" / "filebrowser-maintenance.conf.template").read_text(encoding="utf-8")
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--repository", type=Path)
    mode.add_argument("--production", action="store_true")
    mode.add_argument("--tar", type=Path)
    parser.add_argument("--prefix", action="append", default=[])
    parser.add_argument("--compose", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--env", type=Path)
    args = parser.parse_args()
    try:
        if args.repository:
            validate_repository(args.repository.resolve())
        elif args.tar:
            validate_tar(args.tar.resolve(), args.prefix)
        else:
            if not args.compose or not args.config or not args.env:
                fail("production validation requires --compose, --config, and --env")
            env = load_env(args.env)
            validate_env(env, template=False)
            validate_config(load_yaml(args.config), env, template=False)
            validate_compose(load_yaml(args.compose))
            maintenance_path = args.compose.with_name("compose.maintenance.yaml")
            validate_maintenance_compose(load_yaml(maintenance_path))
            validate_maintenance_nginx(
                (args.compose.parent / "nginx" / "filebrowser-maintenance.conf.template").read_text(encoding="utf-8")
            )
    except ValidationError as exc:
        print(f"deployment validation failed: {exc}", file=sys.stderr)
        return 1
    print("deployment YAML and policy validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
