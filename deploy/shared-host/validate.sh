#!/usr/bin/env bash
set -Eeuo pipefail

# Machine-safe failure locations contain no command, path, configuration value
# or stderr payload. lifecycle.py accepts only this fixed diagnostic grammar.
DIAG_PHASE=arguments
diagnostic() {
  printf '[shared-host-validate-diag] phase=%s kind=%s line=%s exit=%s\n' "$DIAG_PHASE" "$3" "$1" "$2" >&2
}
trap 'diagnostic "$LINENO" "$?" shell' ERR

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
MODE=staging
DEBUG=false
LAN=false
TEST_DISK=false
ASSETS_ONLY=false
ENV_FILE=
EXPECTED_HOSTNAME=${DEPLOY_HOSTNAME:-}
RAID_CHECK_COMMAND=${RAID_CHECK_COMMAND:-}
RAID_CONFIRMED=${RAID_CONFIRMED:-false}

log() {
  printf '[shared-host-validate] %s\n' "$*"
}

die() {
  diagnostic "${BASH_LINENO[0]}" 1 shell
  printf '[shared-host-validate] ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'Usage: validate.sh --env-file PATH [options]' \
    '' \
    'Options:' \
    '  --mode staging|candidate|production' \
    '  --debug | --lan' \
    '  --test-disk (staging only; independent mount, not RAID verification)' \
    '  --hostname NAME' \
    '  --raid-check-command ABSOLUTE_PATH' \
    '  --raid-confirmed' \
    '  --assets-only' \
    '  --help'
}

while (($# > 0)); do
  case "$1" in
    --env-file)
      (($# >= 2)) || die '--env-file requires a path'
      ENV_FILE=$2
      shift 2
      ;;
    --mode)
      (($# >= 2)) || die '--mode requires a value'
      MODE=$2
      shift 2
      ;;
    --lan)
      LAN=true
      shift
      ;;
    --test-disk)
      TEST_DISK=true
      shift
      ;;
    --debug)
      DEBUG=true
      shift
      ;;
    --hostname)
      (($# >= 2)) || die '--hostname requires a value'
      EXPECTED_HOSTNAME=$2
      shift 2
      ;;
    --raid-check-command)
      (($# >= 2)) || die '--raid-check-command requires a path'
      RAID_CHECK_COMMAND=$2
      shift 2
      ;;
    --raid-confirmed)
      RAID_CONFIRMED=true
      shift
      ;;
    --assets-only)
      ASSETS_ONLY=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

case "$MODE" in
  staging|candidate|production) ;;
  *) die "unsupported mode: $MODE" ;;
esac

[[ "$DEBUG" != true || "$LAN" != true ]] || die '--debug and --lan are mutually exclusive'
[[ "$TEST_DISK" != true || "$MODE" == staging ]] || die '--test-disk is allowed only in staging'
[[ -n "$ENV_FILE" ]] || die '--env-file is required'
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || die "env file must be a regular non-symlink: $ENV_FILE"

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

env_value() {
  local key=$1 count line value
  count=$(grep -Ec "^${key}=" "$ENV_FILE" || true)
  [[ "$count" == 1 ]] || die "$key must occur exactly once in the env file"
  line=$(grep -E "^${key}=" "$ENV_FILE")
  value=${line#*=}
  [[ -n "$value" ]] || die "$key must be set explicitly"
  [[ "$value" != *$'\r'* && "$value" != *[[:space:]]* ]] || die "$key contains unsupported whitespace"
  printf '%s' "$value"
}

assert_env_value() {
  local key=$1 expected=$2 actual
  actual=$(env_value "$key")
  [[ "$actual" == "$expected" ]] || die "$key must be $expected"
}

DIAG_PHASE=dependencies
require_command docker
require_command env
require_command grep

if command -v python3 >/dev/null 2>&1 && python3 -c 'import json, yaml' >/dev/null 2>&1; then
  PYTHON_BIN=python3
elif command -v python >/dev/null 2>&1 && python -c 'import json, yaml' >/dev/null 2>&1; then
  PYTHON_BIN=python
else
  die 'an executable Python 3 interpreter with PyYAML is required'
fi

validate_no_plaintext_secrets() {
  "$PYTHON_BIN" - "$1" <<'PY'
import sys
from pathlib import Path

import yaml


def fail() -> None:
    print("[shared-host-validate] ERROR: YAML configuration is invalid or contains a plaintext Secret field", file=sys.stderr)
    raise SystemExit(1)


try:
    value = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, UnicodeError, yaml.YAMLError):
    fail()

sensitive_keys = {
    "key",
    "totpsecret",
    "adminpassword",
    "clientsecret",
    "userpassword",
    "secret",
    "token",
    "cookie",
}


def inspect(item: object) -> None:
    if isinstance(item, dict):
        for key, child in item.items():
            if str(key).lower() in sensitive_keys and child not in (None, ""):
                fail()
            inspect(child)
    elif isinstance(item, list):
        for child in item:
            inspect(child)


if not isinstance(value, dict):
    fail()
inspect(value)
PY
}

compose_version=$(docker compose version --short 2>/dev/null) || die 'Docker Compose version could not be determined'
compose_version=${compose_version#v}
if [[ "$compose_version" =~ ^([0-9]+)\.([0-9]+)(\.[0-9]+)? ]]; then
  compose_major=${BASH_REMATCH[1]}
  compose_minor=${BASH_REMATCH[2]}
else
  die "unrecognized Docker Compose version: $compose_version"
fi
((compose_major > 2 || (compose_major == 2 && compose_minor >= 20))) ||
  die "Docker Compose 2.20 or newer is required; found $compose_version"

DIAG_PHASE=env
if grep -Eiq '^[[:space:]]*(export[[:space:]]+)?[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|COOKIE)[A-Z0-9_]*[[:space:]]*=' "$ENV_FILE"; then
  die 'the env file must not contain password, Secret, Token, or Cookie values'
fi
validate_no_plaintext_secrets "$SCRIPT_DIR/config.yaml.example"

assert_env_value COMPOSE_PROJECT_NAME cf-filebrowser
assert_env_value SOURCE_ROOT /opt/cf-filebrowser-enterprise
assert_env_value CONFIG_ROOT /etc/cf-filebrowser-enterprise
assert_env_value DATA_ROOT /var/lib/cf-filebrowser-enterprise
assert_env_value CACHE_ROOT /var/cache/cf-filebrowser-enterprise
assert_env_value FILES_ROOT /srv/storage/cf-filebrowser-enterprise/files
assert_env_value BACKUP_ROOT /srv/storage/cf-filebrowser-enterprise/backups

SOURCE_ROOT=$(env_value SOURCE_ROOT)
CONFIG_ROOT=$(env_value CONFIG_ROOT)
DATA_ROOT=$(env_value DATA_ROOT)
CACHE_ROOT=$(env_value CACHE_ROOT)
FILES_ROOT=$(env_value FILES_ROOT)
BACKUP_ROOT=$(env_value BACKUP_ROOT)
FILEBROWSER_UID=$(env_value FILEBROWSER_UID)
FILEBROWSER_GID=$(env_value FILEBROWSER_GID)
FILEBROWSER_IMAGE=$(env_value FILEBROWSER_IMAGE)

[[ "$FILEBROWSER_UID" =~ ^[1-9][0-9]*$ ]] || die 'FILEBROWSER_UID must be a positive integer'
[[ "$FILEBROWSER_GID" =~ ^[1-9][0-9]*$ ]] || die 'FILEBROWSER_GID must be a positive integer'

if [[ "$MODE" == candidate || "$MODE" == production ]]; then
  [[ "$FILEBROWSER_IMAGE" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] ||
    die "$MODE mode requires FILEBROWSER_IMAGE to use an approved immutable digest"
  image_digest=${FILEBROWSER_IMAGE##*@sha256:}
  [[ "$image_digest" != 0000000000000000000000000000000000000000000000000000000000000000 ]] ||
    die "$MODE mode rejects an unapproved placeholder immutable digest"
fi

DIAG_PHASE=lan-inputs
LAN_BIND_IP=
LAN_PORT=
LAN_TLS_SERVER_NAME=
LAN_ALLOW_CIDRS=
if [[ "$LAN" == true ]]; then
  LAN_BIND_IP=$(env_value LAN_BIND_IP)
  LAN_PORT=$(env_value LAN_PORT)
  LAN_TLS_SERVER_NAME=$(env_value LAN_TLS_SERVER_NAME)
  LAN_ALLOW_CIDRS=$(env_value LAN_ALLOW_CIDRS)
  "$PYTHON_BIN" - "$LAN_BIND_IP" "$LAN_PORT" "$LAN_TLS_SERVER_NAME" "$LAN_ALLOW_CIDRS" <<'PYLAN'
import ipaddress
import re
import sys
try:
    address = ipaddress.IPv4Address(sys.argv[1])
    assert not (address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local)
    assert str(int(sys.argv[2])) == sys.argv[2] and 1024 <= int(sys.argv[2]) <= 65535
    name = sys.argv[3]
    assert len(name) <= 253 and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in name.split("."))
    cidrs = sys.argv[4].split(",")
    assert cidrs and len(cidrs) == len(set(cidrs))
    for cidr in cidrs:
        network = ipaddress.IPv4Network(cidr, strict=True)
        assert str(network) == cidr and network.prefixlen > 0
        assert not (network.network_address.is_unspecified or network.is_loopback or network.is_multicast or network.is_link_local)
except (ValueError, AssertionError):
    print("[shared-host-validate] ERROR: LAN requires a unicast IPv4 bind, port 1024..65535, TLS DNS name, and explicit canonical source CIDRs", file=sys.stderr)
    raise SystemExit(1)
PYLAN
fi

compose_config() {
  env \
    -u COMPOSE_FILE \
    -u COMPOSE_PROFILES \
    -u COMPOSE_PROJECT_NAME \
    -u FILEBROWSER_IMAGE \
    -u FILEBROWSER_UID \
    -u FILEBROWSER_GID \
    -u FILEBROWSER_CPUS \
    -u FILEBROWSER_MEMORY \
    -u FILEBROWSER_PIDS \
    -u STOP_GRACE_PERIOD \
    -u SOURCE_ROOT \
    -u CONFIG_ROOT \
    -u DATA_ROOT \
    -u CACHE_ROOT \
    -u FILES_ROOT \
    -u BACKUP_ROOT \
    -u LAN_BIND_IP \
    -u LAN_PORT \
    -u LAN_TLS_SERVER_NAME \
    -u LAN_ALLOW_CIDRS \
    docker compose --env-file "$ENV_FILE" "$@" --profile approved config --format json
}

DIAG_PHASE=compose-render
base_json=$(compose_config -f "$SCRIPT_DIR/compose.yaml") || die 'base Compose configuration is invalid'
debug_json=$(compose_config -f "$SCRIPT_DIR/compose.yaml" -f "$SCRIPT_DIR/compose.debug.yaml") ||
  die 'debug Compose configuration is invalid'

lan_json=
if [[ "$LAN" == true ]]; then
  lan_json=$(compose_config -f "$SCRIPT_DIR/compose.yaml" -f "$SCRIPT_DIR/compose.lan.yaml") ||
    die 'LAN Compose configuration is invalid'
fi

DIAG_PHASE=compose-contract
SHARED_HOST_LAN_JSON=$lan_json \
SHARED_HOST_LAN_BIND_IP=$LAN_BIND_IP \
SHARED_HOST_LAN_PORT=$LAN_PORT \
SHARED_HOST_LAN_TLS_SERVER_NAME=$LAN_TLS_SERVER_NAME \
SHARED_HOST_BASE_JSON=$base_json \
SHARED_HOST_DEBUG_JSON=$debug_json \
SHARED_HOST_IMAGE=$FILEBROWSER_IMAGE \
SHARED_HOST_USER=$FILEBROWSER_UID:$FILEBROWSER_GID \
"$PYTHON_BIN" - "$SCRIPT_DIR" <<'PY'
import copy
import json
import os
import re
import sys
from pathlib import Path

import yaml


def fail(message: str, *, line: int | None = None) -> None:
    if line is None:
        line = sys._getframe(1).f_lineno
    # contract line is relative to this embedded Python block, not shell YAML.
    print(f"[shared-host-validate-diag] phase=compose-contract kind=contract line={line} exit=1", file=sys.stderr)
    print(f"[shared-host-validate] ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def expect(condition: bool, message: str) -> None:
    if not condition:
        fail(message, line=sys._getframe(1).f_lineno)


def bind_refuses_host_creation(volume: dict) -> bool:
    # Older compose-go serializes false with omitempty. Raw YAML is checked
    # independently and must explicitly contain create_host_path: false.
    return volume.get("type") == "bind" and volume.get("bind", {}).get("create_host_path", False) is False


def load_yaml(path: Path) -> dict:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        fail(f"{path.name} could not be parsed safely")
    expect(isinstance(value, dict), f"{path.name} must contain a YAML mapping")
    return value


def reject_plaintext_secrets(value: object, location: str) -> None:
    sensitive_keys = {
        "key",
        "totpsecret",
        "adminpassword",
        "clientsecret",
        "userpassword",
        "secret",
        "token",
        "cookie",
    }
    if isinstance(value, dict):
        for key, child in value.items():
            child_location = f"{location}.{key}"
            if str(key).lower() in sensitive_keys and child not in (None, ""):
                fail("plaintext Secret fields are forbidden in YAML configuration")
            reject_plaintext_secrets(child, child_location)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_plaintext_secrets(child, f"{location}[{index}]")


assets = Path(sys.argv[1])
base_raw = load_yaml(assets / "compose.yaml")
debug_raw = load_yaml(assets / "compose.debug.yaml")
lan_raw = load_yaml(assets / "compose.lan.yaml")
lan_config_raw = load_yaml(assets / "config.lan.yaml.example")
build_raw = load_yaml(assets / "compose.build.yaml")
config_raw = load_yaml(assets / "config.yaml.example")

expect(base_raw.get("name") == "cf-filebrowser", "raw Compose project must be cf-filebrowser")
expect(set(base_raw.get("services", {})) == {"filebrowser-enterprise"}, "raw Compose must contain one service")
raw_service = base_raw["services"]["filebrowser-enterprise"]
expect(
    set(raw_service) == {
        "image",
        "profiles",
        "user",
        "init",
        "restart",
        "stop_grace_period",
        "read_only",
        "entrypoint",
        "environment",
        "volumes",
        "tmpfs",
        "expose",
        "networks",
        "healthcheck",
        "security_opt",
        "cap_drop",
        "pids_limit",
        "mem_limit",
        "cpus",
        "logging",
    },
    "raw service contains missing or unapproved fields",
)
expect(raw_service.get("image") == "${FILEBROWSER_IMAGE:?FILEBROWSER_IMAGE must be set explicitly}", "raw image must require FILEBROWSER_IMAGE")
expect(raw_service.get("user") == "${FILEBROWSER_UID:?FILEBROWSER_UID is required}:${FILEBROWSER_GID:?FILEBROWSER_GID is required}", "raw user must require the numeric identity")
expect(raw_service.get("profiles") == ["approved"], "raw service must use the approved profile")
expect(raw_service.get("init") is True and raw_service.get("restart") == "unless-stopped", "init or restart policy is invalid")
expect(raw_service.get("read_only") is True, "raw root filesystem must be read-only")
expect(raw_service.get("stop_grace_period") == "${STOP_GRACE_PERIOD:?STOP_GRACE_PERIOD is required}", "stop grace period contract is invalid")
expect(raw_service.get("cap_drop") == ["ALL"], "raw Compose must drop all capabilities")
expect(raw_service.get("security_opt") == ["no-new-privileges:true"], "raw Compose security options must be exact")
expect(raw_service.get("entrypoint") == ["/opt/filebrowser-enterprise/scripts/container-entrypoint.sh"], "raw entrypoint is invalid")
expect(
    raw_service.get("environment") == {
        "FILEBROWSER_CONFIG": "/etc/filebrowser-enterprise/config.yaml",
        "FILEBROWSER_DATABASE": "/var/lib/filebrowser-enterprise/database.db",
        "FILEBROWSER_JWT_TOKEN_SECRET_FILE": "/run/filebrowser-secrets/jwt_token_secret",
        "FILEBROWSER_TOTP_SECRET_FILE": "/run/filebrowser-secrets/totp_secret",
        "FILEBROWSER_BOOTSTRAP_PASSWORD_FILE": "/run/filebrowser-secrets/bootstrap_admin_password",
        "FILEBROWSER_STORAGE_EXPECTED_FILE": "/etc/filebrowser-enterprise/storage.identity",
        "FILEBROWSER_STORAGE_IDENTITY_FILE": "/run/filebrowser-storage-identity",
        "FILEBROWSER_STORAGE_FILES_ROOT": "/srv/filebrowser/files",
    },
    "raw container environment is invalid",
)
expect(
    raw_service.get("volumes") == [
        {"type": "bind", "source": "${CONFIG_ROOT:?CONFIG_ROOT is required}/config.yaml", "target": "/etc/filebrowser-enterprise/config.yaml", "read_only": True, "bind": {"create_host_path": False}},
        {"type": "bind", "source": "${CONFIG_ROOT:?CONFIG_ROOT is required}/secrets", "target": "/run/filebrowser-secrets", "read_only": True, "bind": {"create_host_path": False}},
        {"type": "bind", "source": "${DATA_ROOT:?DATA_ROOT is required}", "target": "/var/lib/filebrowser-enterprise", "bind": {"create_host_path": False}},
        {"type": "bind", "source": "${CACHE_ROOT:?CACHE_ROOT is required}", "target": "/var/cache/filebrowser-enterprise", "bind": {"create_host_path": False}},
        {"type": "bind", "source": "${FILES_ROOT:?FILES_ROOT is required}", "target": "/srv/filebrowser/files", "bind": {"create_host_path": False}},
        {"type": "bind", "source": "${CONFIG_ROOT:?CONFIG_ROOT is required}/storage.identity", "target": "/etc/filebrowser-enterprise/storage.identity", "read_only": True, "bind": {"create_host_path": False}},
        {"type": "bind", "source": "/srv/storage/cf-filebrowser-enterprise/.storage-identity", "target": "/run/filebrowser-storage-identity", "read_only": True, "bind": {"create_host_path": False}},
        {"type": "bind", "source": "${SOURCE_ROOT:?SOURCE_ROOT is required}/scripts/container-entrypoint.sh", "target": "/opt/filebrowser-enterprise/scripts/container-entrypoint.sh", "read_only": True, "bind": {"create_host_path": False}},
    ],
    "raw bind mounts are invalid",
)
expect(raw_service.get("tmpfs") == ["/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"], "raw /tmp mount is invalid")
expect(raw_service.get("expose") == ["8080"], "raw Compose must expose only port 8080")
expect(raw_service.get("networks") == ["private"], "raw service must use only the private network")
expect(base_raw.get("networks") == {"private": {"driver": "bridge"}}, "raw network must be an unnamed project-private bridge")
expect(
    raw_service.get("healthcheck") == {
        "test": ["CMD-SHELL", "app_health=$$(curl --fail --silent --show-error http://127.0.0.1:8080/health) && [ \"$$app_health\" = '{\"message\":\"ok\"}' ]"],
        "interval": "30s",
        "timeout": "5s",
        "start_period": "30s",
        "retries": 5,
    },
    "raw healthcheck is invalid",
)
expect(raw_service.get("pids_limit") == "${FILEBROWSER_PIDS:?FILEBROWSER_PIDS is required}", "PID limit contract is invalid")
expect(raw_service.get("mem_limit") == "${FILEBROWSER_MEMORY:?FILEBROWSER_MEMORY is required}", "memory limit contract is invalid")
expect(raw_service.get("cpus") == "${FILEBROWSER_CPUS:?FILEBROWSER_CPUS is required}", "CPU limit contract is invalid")
expect(raw_service.get("logging") == {"driver": "local", "options": {"max-size": "50m", "max-file": "5"}}, "logging limits are invalid")
expect(
    debug_raw == {
        "services": {
            "filebrowser-enterprise": {
                "ports": ["127.0.0.1:18081:8080"],
            }
        }
    },
    "Debug override may contain only the approved loopback port",
)
build_service = build_raw.get("services", {}).get("filebrowser-enterprise", {})
expect(set(build_raw.get("services", {})) == {"filebrowser-enterprise"}, "build override must contain one service")
expect(build_service.get("image") == "${FILEBROWSER_BUILD_IMAGE:?FILEBROWSER_BUILD_IMAGE is required}", "build image contract is invalid")
expect(build_service.get("pull_policy") == "build", "build override must use pull_policy build")
expect(
    build_service.get("build") == {
        "context": "../..",
        "dockerfile": "_docker/Dockerfile",
        "args": {
            "VERSION": "${BUILD_VERSION:?BUILD_VERSION is required}",
            "REVISION": "${BUILD_REVISION:?BUILD_REVISION is required}",
            "FFMPEG_IMAGE": "${FFMPEG_IMAGE:-gtstef/ffmpeg:8.1-decode}",
            "GO_IMAGE": "${GO_IMAGE:-golang:alpine}",
            "NODE_IMAGE": "${NODE_IMAGE:-node:jod-slim}",
            "RUNTIME_IMAGE": "${RUNTIME_IMAGE:-alpine:latest}",
        },
    },
    "build context, Dockerfile, or revision arguments are invalid",
)

lan_health = "app_health=$$(curl --fail --silent --show-error --noproxy '*' --cacert /etc/filebrowser-enterprise/tls/ca.crt --resolve \"$$FILEBROWSER_TLS_SERVER_NAME:8080:127.0.0.1\" \"https://$$FILEBROWSER_TLS_SERVER_NAME:8080/health\") && [ \"$$app_health\" = '{\"message\":\"ok\"}' ]"
expected_lan_volume = {
    "type": "bind",
    "source": "${CONFIG_ROOT:?CONFIG_ROOT is required}/tls",
    "target": "/etc/filebrowser-enterprise/tls",
    "read_only": True,
    "bind": {"create_host_path": False},
}
expect(lan_raw == {"services": {"filebrowser-enterprise": {
    "ports": [{"target": 8080, "published": "${LAN_PORT:?LAN_PORT is required}", "host_ip": "${LAN_BIND_IP:?LAN_BIND_IP is required}", "protocol": "tcp"}],
    "environment": {"FILEBROWSER_TLS_SERVER_NAME": "${LAN_TLS_SERVER_NAME:?LAN_TLS_SERVER_NAME is required}"},
    "volumes": [expected_lan_volume],
    "healthcheck": {"test": ["CMD-SHELL", lan_health]},
}}}, "LAN override may add only the explicit native HTTPS binding, trust files and strict healthcheck")
expected_lan_config = copy.deepcopy(config_raw)
expected_lan_config["server"].update({
    "tlsCert": "/etc/filebrowser-enterprise/tls/server.crt",
    "tlsKey": "/etc/filebrowser-enterprise/tls/server.key",
    "allowedClientCIDRs": ["127.0.0.1/32"],
})
expect(lan_config_raw == expected_lan_config, "LAN template must preserve base configuration and enable native TLS with a closed source allowlist")
reject_plaintext_secrets(lan_config_raw, "LAN config template")

server = config_raw.get("server", {})
expect(server.get("listen") == "0.0.0.0" and server.get("port") == 8080, "config template listen contract is invalid")
expect(server.get("baseURL") == "/", "config template baseURL must be root")
expect(server.get("database") == "/var/lib/filebrowser-enterprise/database.db", "config template database path is invalid")
expect(server.get("cacheDir") == "/var/cache/filebrowser-enterprise", "config template cache path is invalid")
expect(server.get("disableUpdateCheck") is True and server.get("disableWebDAV") is True, "update and WebDAV controls must be disabled")
sources = server.get("sources", [])
expect(len(sources) == 1, "config template must contain one source")
source = sources[0]
expect(source.get("path") == "/srv/filebrowser/files" and source.get("name") == "enterprise-files", "source path or name is invalid")
expect(source.get("config", {}).get("private") is True, "source must be private")
expect(source.get("config", {}).get("readOnly") is False, "source readOnly decision is invalid")
expect(source.get("config", {}).get("denyByDefault") is False, "source denyByDefault Staging decision is invalid")
expect(source.get("config", {}).get("defaultEnabled") is True, "source defaultEnabled Staging decision is invalid")
permissions = config_raw.get("userDefaults", {}).get("account", {}).get("permissions", {})
expect(
    permissions == {
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
    "default permission template is invalid",
)
reject_plaintext_secrets(config_raw, "config template")

base = json.loads(os.environ["SHARED_HOST_BASE_JSON"])
debug = json.loads(os.environ["SHARED_HOST_DEBUG_JSON"])
expected_service = "filebrowser-enterprise"
expect(base.get("name") == "cf-filebrowser", "Compose project must be cf-filebrowser")
expect(set(base.get("services", {})) == {expected_service}, "exactly one FileBrowser business service is allowed")
service = base["services"][expected_service]
expect("ports" not in service, "base Compose must not publish ports")
expect("container_name" not in service, "container_name is forbidden")
expect(service.get("profiles") == ["approved"], "the service must use the approved profile")
expect(service.get("image") == os.environ["SHARED_HOST_IMAGE"], "the service image must come from FILEBROWSER_IMAGE")
expect(service.get("user") == os.environ["SHARED_HOST_USER"], "the service must run as FILEBROWSER_UID:FILEBROWSER_GID")
expect(service.get("init") is True, "init must be enabled")
expect(service.get("restart") == "unless-stopped", "restart must be unless-stopped")
expect(service.get("read_only") is True, "the root filesystem must be read-only")
expect(service.get("cap_drop") == ["ALL"], "all Linux capabilities must be dropped")
expect(service.get("security_opt") == ["no-new-privileges:true"], "no-new-privileges must be the only security option")
expect(not service.get("privileged", False), "privileged mode is forbidden")
expect(not service.get("cap_add"), "additional Linux capabilities are forbidden")
expect(service.get("entrypoint") == ["/opt/filebrowser-enterprise/scripts/container-entrypoint.sh"], "the reviewed entrypoint must be reused")
expect(service.get("command") is None, "the reviewed entrypoint must receive no container command")
healthcheck = service.get("healthcheck", {})
expect(healthcheck.get("disable") is not True, "healthcheck must not be disabled")
expect(len(healthcheck.get("test", [])) == 2 and healthcheck["test"][0] == "CMD-SHELL", "healthcheck command is invalid")
expect(all(key in service for key in ("cpus", "mem_limit", "pids_limit", "stop_grace_period")), "CPU, memory, PID, and stop limits are required")
expect(float(service["cpus"]) > 0, "CPU limit must be positive")
expect(int(service["mem_limit"]) > 0, "memory limit must be positive")
expect(int(service["pids_limit"]) > 0, "PID limit must be positive")
expect(re.search(r"[1-9]", str(service["stop_grace_period"])) is not None, "stop grace period must be positive")
expect(service.get("expose") == ["8080"], "only container port 8080 must be exposed")
expect(service.get("tmpfs") == ["/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"], "the hardened /tmp tmpfs is required")

expected_environment = {
    "FILEBROWSER_CONFIG": "/etc/filebrowser-enterprise/config.yaml",
    "FILEBROWSER_DATABASE": "/var/lib/filebrowser-enterprise/database.db",
    "FILEBROWSER_JWT_TOKEN_SECRET_FILE": "/run/filebrowser-secrets/jwt_token_secret",
    "FILEBROWSER_TOTP_SECRET_FILE": "/run/filebrowser-secrets/totp_secret",
    "FILEBROWSER_BOOTSTRAP_PASSWORD_FILE": "/run/filebrowser-secrets/bootstrap_admin_password",
    "FILEBROWSER_STORAGE_EXPECTED_FILE": "/etc/filebrowser-enterprise/storage.identity",
    "FILEBROWSER_STORAGE_IDENTITY_FILE": "/run/filebrowser-storage-identity",
    "FILEBROWSER_STORAGE_FILES_ROOT": "/srv/filebrowser/files",
}
expect(service.get("environment") == expected_environment, "container environment must contain only reviewed file paths")
for forbidden_key in ("depends_on", "links", "external_links", "network_mode", "extra_hosts"):
    expect(forbidden_key not in service, f"{forbidden_key} is forbidden")

service_networks = service.get("networks", {})
if isinstance(service_networks, dict):
    service_network_names = set(service_networks)
else:
    service_network_names = set(service_networks)
expect(service_network_names == {"private"}, "the service must use only the private network")
networks = base.get("networks", {})
expect(set(networks) == {"private"}, "exactly one project-private network is allowed")
private = networks["private"]
expect(private.get("driver") == "bridge", "the private network must use the bridge driver")
expect(not private.get("external", False), "external networks are forbidden")

expected_mounts = [
    ("/etc/cf-filebrowser-enterprise/config.yaml", "/etc/filebrowser-enterprise/config.yaml", True),
    ("/etc/cf-filebrowser-enterprise/secrets", "/run/filebrowser-secrets", True),
    ("/var/lib/cf-filebrowser-enterprise", "/var/lib/filebrowser-enterprise", False),
    ("/var/cache/cf-filebrowser-enterprise", "/var/cache/filebrowser-enterprise", False),
    ("/srv/storage/cf-filebrowser-enterprise/files", "/srv/filebrowser/files", False),
    ("/etc/cf-filebrowser-enterprise/storage.identity", "/etc/filebrowser-enterprise/storage.identity", True),
    ("/srv/storage/cf-filebrowser-enterprise/.storage-identity", "/run/filebrowser-storage-identity", True),
    ("/opt/cf-filebrowser-enterprise/scripts/container-entrypoint.sh", "/opt/filebrowser-enterprise/scripts/container-entrypoint.sh", True),
]
actual_mounts = [
    (item.get("source"), item.get("target"), item.get("read_only", False))
    for item in service.get("volumes", [])
]
expect(actual_mounts == expected_mounts, "bind mounts must match the approved FileBrowser-owned paths")
expect(all(bind_refuses_host_creation(item) for item in service.get("volumes", [])), "all bind mounts must refuse automatic host path creation")
expect("/srv/storage/cf-filebrowser-enterprise/backups" not in {item[0] for item in actual_mounts}, "BACKUP_ROOT must not be mounted")

debug_service = debug.get("services", {}).get(expected_service, {})
ports = debug_service.get("ports", [])
expect(len(ports) == 1, "debug mode must publish exactly one port")
port = ports[0]
expect(port.get("host_ip") == "127.0.0.1", "debug port must bind only to loopback")
expect(str(port.get("published")) == "18081", "debug host port must be 18081")
expect(port.get("target") == 8080, "debug port must target container port 8080")
debug_without_ports = copy.deepcopy(debug)
debug_without_ports["services"][expected_service].pop("ports", None)
expect(debug_without_ports == base, "debug override may only add the approved loopback port")

if os.environ["SHARED_HOST_LAN_JSON"]:
    lan = json.loads(os.environ["SHARED_HOST_LAN_JSON"])
    lan_service = lan.get("services", {}).get(expected_service, {})
    ports = lan_service.get("ports", [])
    expect(len(ports) == 1, "LAN must publish exactly one port")
    port = ports[0]
    expect(port.get("host_ip") == os.environ["SHARED_HOST_LAN_BIND_IP"], "LAN must use the explicit bind IP")
    expect(str(port.get("published")) == os.environ["SHARED_HOST_LAN_PORT"] and port.get("target") == 8080 and port.get("protocol") == "tcp", "LAN port mapping is invalid")
    expect(lan_service["environment"].pop("FILEBROWSER_TLS_SERVER_NAME", None) == os.environ["SHARED_HOST_LAN_TLS_SERVER_NAME"], "LAN TLS name is invalid")
    # Compose config re-escapes dollars in JSON; unlike container inspect,
    # its reviewed healthcheck still contains the original $$ shell escapes.
    expect(lan_service["healthcheck"].get("test") == ["CMD-SHELL", lan_health], "LAN healthcheck must verify CA and hostname")
    lan_service["healthcheck"] = copy.deepcopy(service["healthcheck"])
    tls_mounts = [item for item in lan_service.get("volumes", []) if item.get("target") == "/etc/filebrowser-enterprise/tls"]
    expect(len(tls_mounts) == 1, "LAN must contain one TLS trust mount")
    tls_mount = tls_mounts[0]
    expect(tls_mount.get("source") == "/etc/cf-filebrowser-enterprise/tls" and tls_mount.get("read_only") is True and bind_refuses_host_creation(tls_mount), "LAN TLS mount must be protected and pre-existing")
    lan_service["volumes"].remove(tls_mount)
    lan_service.pop("ports")
    expect(lan == base, "LAN override contains unapproved changes")
PY

if [[ "$ASSETS_ONLY" == true ]]; then
  log 'shared-host asset validation passed; host preparation checks were not run'
  exit 0
fi

DIAG_PHASE=host
case "$FILEBROWSER_IMAGE" in
  *'.invalid'*|*replace-with*) die 'FILEBROWSER_IMAGE still contains a non-deployable placeholder' ;;
esac

require_command awk
require_command cmp
require_command findmnt
require_command getent
require_command hostname
require_command mountpoint
require_command realpath
require_command ss
require_command stat

[[ -r /etc/os-release ]] || die '/etc/os-release is unavailable'
os_id=$(awk -F= '$1 == "ID" {print substr($0, index($0, "=") + 1); exit}' /etc/os-release)
os_version=$(awk -F= '$1 == "VERSION_ID" {print substr($0, index($0, "=") + 1); exit}' /etc/os-release)
os_id=${os_id#\"}
os_id=${os_id%\"}
os_version=${os_version#\"}
os_version=${os_version%\"}
[[ "$os_id" == debian && ("$os_version" == 12 || "$os_version" == 13) ]] ||
  die "only Debian 12/13 is supported; found ${os_id:-unknown} ${os_version:-unknown}"

[[ -n "$EXPECTED_HOSTNAME" && "$EXPECTED_HOSTNAME" != *[[:space:]]* ]] ||
  die 'hostname confirmation is required through --hostname or DEPLOY_HOSTNAME'
actual_hostname=$(hostname) || die 'hostname could not be determined'
fqdn_hostname=$(hostname -f 2>/dev/null || true)
[[ "$EXPECTED_HOSTNAME" == "$actual_hostname" || "$EXPECTED_HOSTNAME" == "$fqdn_hostname" ]] ||
  die "confirmed hostname does not match this host"

DIAG_PHASE=mount
mountpoint -q /srv/storage || die '/srv/storage must be an independent mount point'
storage_target=$(findmnt -n -o TARGET --target /srv/storage 2>/dev/null) ||
  die '/srv/storage mount details could not be determined'
[[ "$storage_target" == /srv/storage ]] || die '/srv/storage must resolve to its own mount target'

raid_confirmation=false
case "${RAID_CONFIRMED,,}" in
  1|true|yes) raid_confirmation=true ;;
  0|false|no|'') ;;
  *) die 'RAID_CONFIRMED must be true or false' ;;
esac
if [[ -n "$RAID_CHECK_COMMAND" && "$raid_confirmation" == true ]]; then
  die 'choose either an external RAID check or explicit RAID confirmation, not both'
elif [[ -n "$RAID_CHECK_COMMAND" ]]; then
  [[ "$RAID_CHECK_COMMAND" == /* ]] || die 'RAID check path must be absolute'
  [[ -f "$RAID_CHECK_COMMAND" && ! -L "$RAID_CHECK_COMMAND" && -x "$RAID_CHECK_COMMAND" ]] ||
    die 'RAID check must be an executable regular non-symlink'
  raid_check_real=$(realpath -e -- "$RAID_CHECK_COMMAND" 2>/dev/null) || die 'RAID check path could not be resolved'
  [[ "$raid_check_real" == "$RAID_CHECK_COMMAND" ]] || die 'RAID check path must not traverse symbolic links'
  raid_check_uid=$(stat -c '%u' -- "$RAID_CHECK_COMMAND") || die 'RAID check owner could not be read'
  raid_check_mode=$(stat -c '%a' -- "$RAID_CHECK_COMMAND") || die 'RAID check mode could not be read'
  [[ "$raid_check_uid" == 0 ]] || die 'RAID check must be root-owned'
  (( (8#$raid_check_mode & 0022) == 0 )) || die 'RAID check must not be writable by group or other'
  raid_check_parent=${RAID_CHECK_COMMAND%/*}
  [[ -n "$raid_check_parent" ]] || raid_check_parent=/
  while :; do
    raid_parent_uid=$(stat -c '%u' -- "$raid_check_parent") || die 'RAID check parent owner could not be read'
    raid_parent_mode=$(stat -c '%a' -- "$raid_check_parent") || die 'RAID check parent mode could not be read'
    [[ "$raid_parent_uid" == 0 ]] || die 'RAID check parent directories must be root-owned'
    (( (8#$raid_parent_mode & 0022) == 0 )) || die 'RAID check parent directories must not be writable by group or other'
    [[ "$raid_check_parent" == / ]] && break
    raid_check_parent=${raid_check_parent%/*}
    [[ -n "$raid_check_parent" ]] || raid_check_parent=/
  done
  "$RAID_CHECK_COMMAND" /srv/storage >/dev/null 2>&1 || die 'external RAID check failed'
elif [[ "$TEST_DISK" == true ]]; then
  log 'independent test-disk mount verified; RAID was not verified'
elif [[ "$raid_confirmation" != true ]]; then
  die 'RAID status requires --raid-check-command or --raid-confirmed'
fi

DIAG_PHASE=host-identity
if getent passwd "$FILEBROWSER_UID" >/dev/null 2>&1; then
  die "FILEBROWSER_UID maps to an existing host account"
else
  getent_status=$?
  [[ "$getent_status" == 2 ]] || die 'host account lookup failed'
fi
if getent group "$FILEBROWSER_GID" >/dev/null 2>&1; then
  die "FILEBROWSER_GID maps to an existing host group"
else
  getent_status=$?
  [[ "$getent_status" == 2 ]] || die 'host group lookup failed'
fi

DIAG_PHASE=port
if [[ "$DEBUG" == true || "$LAN" == true ]]; then
  bind_ip=127.0.0.1
  bind_port=18081
  if [[ "$LAN" == true ]]; then bind_ip=$LAN_BIND_IP; bind_port=$LAN_PORT; fi
  port_listeners=$(ss -H -ltn "sport = :$bind_port" 2>/dev/null) || die 'published port availability could not be checked'
  if [[ -n "$port_listeners" ]]; then
    # Repeated validation accepts only our uniquely identified running service.
    project_containers=$(docker ps --filter label=com.docker.compose.project=cf-filebrowser --filter label=com.docker.compose.service=filebrowser-enterprise --format '{{.ID}}') ||
      die 'running project service could not be located'
    [[ "$project_containers" =~ ^[0-9a-f]{12,64}$ ]] ||
      die 'requested published port is occupied and no unique running project service owns it'
    project_inspect=$(docker inspect "$project_containers") || die 'running project service could not be inspected'
    SHARED_HOST_INSPECT=$project_inspect "$PYTHON_BIN" - "$bind_ip" "$bind_port" <<'PYPORT'
import json
import os
import sys
containers = json.loads(os.environ["SHARED_HOST_INSPECT"])
valid = len(containers) == 1
if valid:
    container = containers[0]
    labels = container.get("Config", {}).get("Labels", {})
    ports = container.get("NetworkSettings", {}).get("Ports", {}).get("8080/tcp", [])
    valid = container.get("State", {}).get("Running") is True and labels.get("com.docker.compose.project") == "cf-filebrowser" and labels.get("com.docker.compose.service") == "filebrowser-enterprise" and ports == [{"HostIp": sys.argv[1], "HostPort": sys.argv[2]}]
if not valid:
    print("[shared-host-validate] ERROR: occupied port does not match this project's exact running service binding", file=sys.stderr)
    raise SystemExit(1)
PYPORT
  fi
fi

require_directory() {
  [[ -d "$1" && ! -L "$1" ]] || die "$2 must be an existing non-symlink directory: $1"
}

assert_canonical_path() {
  local path=$1 label=$2 resolved
  resolved=$(realpath -e -- "$path" 2>/dev/null) || die "$label could not be resolved"
  [[ "$resolved" == "$path" ]] || die "$label must not traverse symbolic links"
}

assert_owner_mode() {
  local path=$1 expected_mode=$2 expected_uid=$3 expected_gid=$4 label=$5
  local actual_mode actual_uid actual_gid
  actual_mode=$(stat -c '%a' -- "$path") || die "$label mode could not be read"
  actual_uid=$(stat -c '%u' -- "$path") || die "$label owner could not be read"
  actual_gid=$(stat -c '%g' -- "$path") || die "$label group could not be read"
  [[ "$actual_mode" == "$expected_mode" ]] || die "$label must have mode 0$expected_mode"
  [[ "$actual_uid" == "$expected_uid" && "$actual_gid" == "$expected_gid" ]] ||
    die "$label must be owned by numeric identity $expected_uid:$expected_gid"
}

assert_owned_directory() {
  local path=$1 label=$2 actual_uid actual_gid
  require_directory "$path" "$label"
  actual_uid=$(stat -c '%u' -- "$path") || die "$label owner could not be read"
  actual_gid=$(stat -c '%g' -- "$path") || die "$label group could not be read"
  [[ "$actual_uid" == "$FILEBROWSER_UID" && "$actual_gid" == "$FILEBROWSER_GID" ]] ||
    die "$label must be owned by numeric identity $FILEBROWSER_UID:$FILEBROWSER_GID"
}

assert_secret_file() {
  local path=$1 minimum_length=$2 label=$3
  [[ -f "$path" && ! -L "$path" ]] || die "$label must be a regular non-symlink file: $path"
  assert_canonical_path "$path" "$label"
  assert_owner_mode "$path" 440 0 "$FILEBROWSER_GID" "$label"
  awk -v minimum="$minimum_length" '
    NR == 1 {
      if (length($0) < minimum || length($0) > 4096 || index($0, "\r") != 0) exit 1
      next
    }
    { exit 1 }
    END { if (NR != 1) exit 1 }
  ' "$path" >/dev/null || die "$label must be one non-empty line with the required length"
}

DIAG_PHASE=paths
require_directory "$SOURCE_ROOT" 'source root'
assert_canonical_path "$SOURCE_ROOT" 'source root'
[[ -f "$SOURCE_ROOT/scripts/container-entrypoint.sh" && ! -L "$SOURCE_ROOT/scripts/container-entrypoint.sh" && -x "$SOURCE_ROOT/scripts/container-entrypoint.sh" ]] ||
  die 'the reviewed container entrypoint is missing, unsafe, or not executable'
assert_canonical_path "$SOURCE_ROOT/scripts/container-entrypoint.sh" 'reviewed container entrypoint'
DIAG_PHASE=config
require_directory "$CONFIG_ROOT" 'configuration root'
assert_canonical_path "$CONFIG_ROOT" 'configuration root'
assert_owner_mode "$CONFIG_ROOT" 750 0 "$FILEBROWSER_GID" 'configuration root'
require_directory "$CONFIG_ROOT/secrets" 'Secret directory'
assert_canonical_path "$CONFIG_ROOT/secrets" 'Secret directory'
assert_owner_mode "$CONFIG_ROOT/secrets" 750 0 "$FILEBROWSER_GID" 'Secret directory'
[[ -f "$CONFIG_ROOT/config.yaml" && ! -L "$CONFIG_ROOT/config.yaml" && -s "$CONFIG_ROOT/config.yaml" ]] ||
  die 'config.yaml must be a non-empty regular non-symlink file'
assert_canonical_path "$CONFIG_ROOT/config.yaml" 'config.yaml'
assert_owner_mode "$CONFIG_ROOT/config.yaml" 640 0 "$FILEBROWSER_GID" 'config.yaml'
validate_no_plaintext_secrets "$CONFIG_ROOT/config.yaml"

[[ "$ENV_FILE" == "$CONFIG_ROOT/.env" ]] || die 'the real env file must be CONFIG_ROOT/.env'
assert_canonical_path "$ENV_FILE" 'real env file'
env_mode=$(stat -c '%a' -- "$ENV_FILE") || die 'env file mode could not be read'
env_uid=$(stat -c '%u' -- "$ENV_FILE") || die 'env file owner could not be read'
[[ "$env_uid" == 0 && "$env_mode" == 600 ]] || die 'the real env file must be root-owned with mode 0600'

DIAG_PHASE=data
assert_owned_directory "$DATA_ROOT" 'data root'
assert_canonical_path "$DATA_ROOT" 'data root'
assert_owned_directory "$CACHE_ROOT" 'cache root'
assert_canonical_path "$CACHE_ROOT" 'cache root'
assert_owned_directory "$FILES_ROOT" 'files root'
assert_canonical_path "$FILES_ROOT" 'files root'
require_directory "$BACKUP_ROOT" 'future backup root'
assert_canonical_path "$BACKUP_ROOT" 'future backup root'

DIAG_PHASE=storage-identity
storage_identity=/srv/storage/cf-filebrowser-enterprise/.storage-identity
for identity_file in "$CONFIG_ROOT/storage.identity" "$storage_identity"; do
  [[ -f "$identity_file" && ! -L "$identity_file" ]] || die 'storage identity is missing or unsafe'
  assert_canonical_path "$identity_file" 'storage identity'
  assert_owner_mode "$identity_file" 440 0 "$FILEBROWSER_GID" 'storage identity'
  [[ $(stat -c '%s' -- "$identity_file") == 65 ]] || die 'storage identity must be 64 hexadecimal bytes and one newline'
  awk 'NR == 1 && length($0) == 64 && $0 !~ /[^0-9a-f]/ { valid = 1; next } { valid = 0 } END { if (NR != 1 || !valid) exit 1 }' "$identity_file" ||
    die 'storage identity has an invalid format'
done
cmp -s -- "$CONFIG_ROOT/storage.identity" "$storage_identity" || die 'storage identities do not match'
[[ $(stat -c '%d' -- "$FILES_ROOT") == "$(stat -c '%d' -- "$storage_identity")" ]] ||
  die 'files and storage identity are on different devices'
[[ $(findmnt -n -o TARGET --target "$FILES_ROOT") == /srv/storage ]] ||
  die 'files root must be on the confirmed /srv/storage mount'

DIAG_PHASE=tls
if [[ "$LAN" == true ]]; then
  require_command openssl
  require_directory "$CONFIG_ROOT/tls" 'TLS directory'
  assert_canonical_path "$CONFIG_ROOT/tls" 'TLS directory'
  assert_owner_mode "$CONFIG_ROOT/tls" 750 0 "$FILEBROWSER_GID" 'TLS directory'
  for tls_name in server.crt server.key ca.crt; do
    tls_file=$CONFIG_ROOT/tls/$tls_name
    [[ -f "$tls_file" && ! -L "$tls_file" && -s "$tls_file" ]] || die "TLS $tls_name is missing or unsafe"
    assert_canonical_path "$tls_file" "TLS $tls_name"
    assert_owner_mode "$tls_file" 440 0 "$FILEBROWSER_GID" "TLS $tls_name"
  done
  openssl verify -CAfile "$CONFIG_ROOT/tls/ca.crt" -verify_hostname "$LAN_TLS_SERVER_NAME" "$CONFIG_ROOT/tls/server.crt" >/dev/null 2>&1 ||
    die 'TLS certificate chain or DNS name is invalid'
  cert_public=$(openssl x509 -in "$CONFIG_ROOT/tls/server.crt" -pubkey -noout 2>/dev/null) ||
    die 'TLS certificate public key could not be read'
  key_public=$(openssl pkey -in "$CONFIG_ROOT/tls/server.key" -pubout -passin pass: 2>/dev/null) ||
    die 'TLS key must be valid and available without interactive passphrase'
  [[ "$cert_public" == "$key_public" ]] || die 'TLS certificate and key do not match'
fi
DIAG_PHASE=runtime-config
"$PYTHON_BIN" - "$CONFIG_ROOT/config.yaml" "$LAN" "$LAN_ALLOW_CIDRS" <<'PYCONFIG'
import sys
import yaml
with open(sys.argv[1], encoding="utf-8") as config_file:
    server = yaml.safe_load(config_file).get("server", {})
if sys.argv[2] == "true":
    expected = ["127.0.0.1/32"] + sys.argv[3].split(",")
    valid = server.get("tlsCert") == "/etc/filebrowser-enterprise/tls/server.crt" and server.get("tlsKey") == "/etc/filebrowser-enterprise/tls/server.key" and server.get("allowedClientCIDRs") == expected
else:
    valid = not server.get("tlsCert") and not server.get("tlsKey") and not server.get("allowedClientCIDRs")
if not valid:
    print("[shared-host-validate] ERROR: native TLS/source allowlist configuration does not match the selected exposure", file=sys.stderr)
    raise SystemExit(1)
PYCONFIG

DIAG_PHASE=secrets
assert_secret_file "$CONFIG_ROOT/secrets/jwt_token_secret" 32 'JWT token Secret'
assert_secret_file "$CONFIG_ROOT/secrets/totp_secret" 32 'TOTP Secret'

DIAG_PHASE=bootstrap
database_file=$DATA_ROOT/database.db
bootstrap_file=$CONFIG_ROOT/secrets/bootstrap_admin_password
[[ ! -L "$database_file" ]] || die 'database.db must not be a symbolic link'
[[ ! -e "$database_file" || -f "$database_file" ]] || die 'database.db must be a regular file when present'
if [[ -s "$database_file" ]]; then
  [[ ! -e "$bootstrap_file" ]] || die 'remove bootstrap_admin_password after initialization before restart validation'
else
  assert_secret_file "$bootstrap_file" 24 'bootstrap administrator password'
fi

if [[ "$DEBUG" == true ]]; then
  log "shared-host $MODE validation passed with Debug port checks"
else
  log "shared-host $MODE validation passed"
fi
