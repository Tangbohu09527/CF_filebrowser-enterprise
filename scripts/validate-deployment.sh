#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=scripts/lib/deployment-common.sh
source "$SCRIPT_DIR/lib/deployment-common.sh"

MODE=
RUNTIME=false
ALLOW_BOOTSTRAP_RECOVERY=false
ALLOW_INCOMPLETE_RESTORE=false

usage() {
  cat <<'USAGE'
Usage:
  validate-deployment.sh --repository
  validate-deployment.sh --production [--runtime|--skip-runtime]

Repository mode validates committed templates without real secrets. Production
mode is fail-closed for image digests, TLS, secrets, permissions, paths, Compose,
and Nginx. --runtime additionally checks both running container health states and
Nginx-to-FileBrowser connectivity.
USAGE
}

while (( $# > 0 )); do
  case "$1" in
    --repository|--production)
      [[ -z "$MODE" ]] || die "choose exactly one validation mode"
      MODE=${1#--}
      shift
      ;;
    --runtime) RUNTIME=true; shift ;;
    --skip-runtime) RUNTIME=false; shift ;;
    --allow-bootstrap-recovery) ALLOW_BOOTSTRAP_RECOVERY=true; shift ;;
    --allow-incomplete-restore) ALLOW_INCOMPLETE_RESTORE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ -n "$MODE" ]] || die "one validation mode is required"

PYTHON_BIN=
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import yaml' >/dev/null 2>&1; then
    PYTHON_BIN=$candidate
    break
  fi
done
[[ -n "$PYTHON_BIN" ]] || die "Python with PyYAML is required (Debian package: python3-yaml)"
export PYTHONDONTWRITEBYTECODE=1

validate_shell_syntax() {
  local root=$1 path
  while IFS= read -r -d '' path; do
    bash -n "$path"
  done < <(find "$root/scripts" "$root/deploy/shared-host" -type f -name '*.sh' -print0)
}

if [[ "$MODE" == repository ]]; then
  [[ "$ALLOW_INCOMPLETE_RESTORE" == false && "$ALLOW_BOOTSTRAP_RECOVERY" == false ]] ||
    die "production recovery flags are not valid in repository mode"
  REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
  require_command git
  require_command docker
  require_command rg
  require_compose_wait_support
  validate_shell_syntax "$REPO_ROOT"
  "$PYTHON_BIN" "$REPO_ROOT/scripts/lib/deployment_validation.py" --repository "$REPO_ROOT"
  "$PYTHON_BIN" "$REPO_ROOT/deploy/tests/test_deployment_assets.py"
  "$PYTHON_BIN" -m unittest discover -s "$REPO_ROOT/deploy/tests" -p 'test_shared_host_*.py' -v
  bash "$REPO_ROOT/scripts/tests/failure-drills.sh"

  repository_docker_config=$(mktemp -d)
  trap 'rm -rf -- "$repository_docker_config"' EXIT
  DEPLOY_ROOT="$REPO_ROOT/deploy"
  ENV_FILE="$REPO_ROOT/deploy/compose.env.example"
  COMPOSE_FILE="$REPO_ROOT/deploy/compose.yaml"
  DOCKER_CONFIG="$repository_docker_config" compose config --quiet
  DOCKER_CONFIG="$repository_docker_config" compose \
    -f "$REPO_ROOT/deploy/compose.build.yaml" config --quiet
  DOCKER_CONFIG="$repository_docker_config" maintenance_compose config --quiet
  maintenance_render="$repository_docker_config/maintenance-render.yaml"
  DOCKER_CONFIG="$repository_docker_config" maintenance_compose config >"$maintenance_render"
  "$PYTHON_BIN" - "$maintenance_render" <<'PY'
import sys
from pathlib import Path

import yaml

rendered = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))
services = rendered.get("services", {})
for service_name in ("filebrowser-enterprise", "nginx"):
    if services.get(service_name, {}).get("restart") != "no":
        raise SystemExit(f"maintenance render did not disable restart for {service_name}")
nginx_volumes = services.get("nginx", {}).get("volumes", [])
template_mounts = [item for item in nginx_volumes if item.get("target") == "/etc/nginx/templates/filebrowser.conf.template"]
if len(template_mounts) != 1 or not str(template_mounts[0].get("source", "")).endswith("filebrowser-maintenance.conf.template"):
    raise SystemExit("maintenance render did not replace the public Nginx template")
PY

  poisoned_render="$repository_docker_config/poisoned-render.yaml"
  COMPOSE_PROJECT_NAME=poisoned-project \
  FILEBROWSER_IMAGE=docker.io/poisoned/filebrowser:latest \
  DATA_ROOT=/poisoned-data-root \
  HTTPS_BIND_ADDRESS=192.0.2.99 \
  PUBLIC_HOST=poisoned.invalid \
    DOCKER_CONFIG="$repository_docker_config" compose config >"$poisoned_render"
  "$PYTHON_BIN" - "$poisoned_render" <<'PY'
import sys
from pathlib import Path

import yaml

path = Path(sys.argv[1])
rendered_text = path.read_text(encoding="utf-8")
rendered = yaml.safe_load(rendered_text)
if rendered.get("name") != "filebrowser-enterprise":
    raise SystemExit("sanitized Compose render did not retain the fixed project name")
for poison in ("poisoned-project", "poisoned/filebrowser", "poisoned-data-root", "192.0.2.99", "poisoned.invalid"):
    if poison in rendered_text:
        raise SystemExit(f"host environment overrode validated Compose input: {poison}")
PY

  [[ ! -f "$REPO_ROOT/deploy/.env" ]] || die "deploy/.env must not exist in the repository"
  if [[ -d "$REPO_ROOT/deploy/secrets" ]]; then
    while IFS= read -r -d '' path; do
      [[ $(basename -- "$path") == README.md ]] || die "runtime secret found under deploy/secrets: $path"
    done < <(find "$REPO_ROOT/deploy/secrets" -type f -print0)
  fi
  set +e
  secret_scan_output=$(rg -n --hidden --no-ignore -g 'deploy/**' -g 'scripts/**' -- \
    '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.' "$REPO_ROOT" 2>&1)
  secret_scan_status=$?
  set -e
  if (( secret_scan_status == 0 )); then
    printf '%s\n' "$secret_scan_output" >&2
    die "a credential-like value was found in deployment assets"
  elif (( secret_scan_status > 1 )); then
    die "credential scan failed: $secret_scan_output"
  fi
  if rg --files --hidden --no-ignore "$REPO_ROOT/deploy" | rg '\.(db|sqlite|p12|pfx|key|pem|crt)$'; then
    die "a runtime database, certificate, or key is tracked under deploy/"
  fi

  while IFS= read -r -d '' path; do
    relative=${path#"$REPO_ROOT/"}
    stage_entry=$(git -C "$REPO_ROOT" ls-files --stage -- "$relative")
    if [[ -n "$stage_entry" ]]; then
      [[ ${stage_entry%% *} == 100755 ]] || die "tracked shell script is not executable in Git: $relative"
    else
      warn "untracked shell script mode will be checked after staging: $relative"
    fi
  done < <(find "$REPO_ROOT/scripts" -type f -name '*.sh' -print0)

  if command -v shellcheck >/dev/null 2>&1; then
    mapfile -d '' shell_files < <(find "$REPO_ROOT/scripts" -type f -name '*.sh' -print0)
    # Warnings and errors block CI. Intentional info-level findings require
    # separate cleanup and are not part of the current release gate.
    shellcheck --severity=warning "${shell_files[@]}"
  elif [[ ${CI:-false} == true ]]; then
    die "shellcheck is required in CI"
  else
    warn "shellcheck is unavailable; CI will enforce it"
  fi

  git -C "$REPO_ROOT" diff --check
  git -C "$REPO_ROOT" diff --cached --check
  log "repository deployment validation passed"
  exit 0
fi

deployment_init_layout
require_root
for command in docker openssl stat df realpath grep fold sort wc sync du sha256sum awk tr timeout mktemp flock; do
  require_command "$command"
done
require_compose_wait_support
acquire_lifecycle_lock
if [[ "$ALLOW_INCOMPLETE_RESTORE" == true ]]; then
  [[ -f "$FILEBROWSER_RESTORE_JOURNAL" && ! -L "$FILEBROWSER_RESTORE_JOURNAL" ]] ||
    die "--allow-incomplete-restore requires an active regular restore journal"
  [[ $(stat -c '%u:%g:%a' "$FILEBROWSER_RESTORE_JOURNAL") == 0:0:600 ]] ||
    die "active restore journal must be owned by root:root with mode 0600"
else
  assert_no_incomplete_lifecycle_transaction
fi

for path in "$DEPLOY_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$CACHE_ROOT" "$FILES_ROOT" "$BACKUP_ROOT"; do
  validate_absolute_path "$path" deployment_path
  [[ -d "$path" && ! -L "$path" ]] || die "required directory is missing or a symlink: $path"
done

declare -A resolved_paths=()
for path in "$DEPLOY_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$CACHE_ROOT" "$FILES_ROOT" "$BACKUP_ROOT"; do
  resolved=$(realpath -e -- "$path")
  [[ -z ${resolved_paths[$resolved]:-} ]] || die "deployment paths resolve to the same directory: $path and ${resolved_paths[$resolved]}"
  resolved_paths[$resolved]=$path
done
resolved_values=("${!resolved_paths[@]}")
for (( i=0; i<${#resolved_values[@]}; i++ )); do
  for (( j=i+1; j<${#resolved_values[@]}; j++ )); do
    first=${resolved_values[$i]}
    second=${resolved_values[$j]}
    if [[ "$first/" == "$second/"* || "$second/" == "$first/"* ]]; then
      die "deployment paths must not be nested: ${resolved_paths[$first]} and ${resolved_paths[$second]}"
    fi
  done
done

config_file="$CONFIG_ROOT/config.yaml"
[[ -s "$config_file" && ! -L "$config_file" ]] || die "production config is missing, empty, or a symlink: $config_file"
[[ -s "$DATA_ROOT/database.db" && ! -L "$DATA_ROOT/database.db" ]] || die "initialized database is missing; run bootstrap-admin.sh before production validation"

"$PYTHON_BIN" "$SCRIPT_DIR/lib/deployment_validation.py" --production \
  --compose "$COMPOSE_FILE" --config "$config_file" --env "$ENV_FILE"

fb_uid=$(env_get "$ENV_FILE" FILEBROWSER_UID)
fb_gid=$(env_get "$ENV_FILE" FILEBROWSER_GID)
nginx_uid=$(env_get "$ENV_FILE" NGINX_UID)
nginx_gid=$(env_get "$ENV_FILE" NGINX_GID)

validate_directory_metadata() {
  local path=$1 label=$2 expected_uid=$3 expected_gid=$4 allowed_modes=$5 mode
  [[ -d "$path" && ! -L "$path" ]] || die "$label must be a real directory: $path"
  [[ $(stat -c '%u' "$path") == "$expected_uid" && $(stat -c '%g' "$path") == "$expected_gid" ]] ||
    die "$label must be owned by $expected_uid:$expected_gid: $path"
  mode=$(stat -c '%a' "$path")
  case " $allowed_modes " in
    *" $mode "*) ;;
    *) die "$label has unsafe permissions $mode; allowed: $allowed_modes" ;;
  esac
}

validate_directory_metadata "$DEPLOY_ROOT" "deployment root" 0 0 "750 755"
validate_directory_metadata "$CONFIG_ROOT" "configuration root" 0 "$fb_gid" "750"
validate_directory_metadata "$CONFIG_ROOT/secrets" "secret root" 0 "$fb_gid" "750"
validate_directory_metadata "$CONFIG_ROOT/tls" "TLS root" 0 "$nginx_gid" "750"
validate_directory_metadata "$DATA_ROOT" "database root" "$fb_uid" "$fb_gid" "700 750"
validate_directory_metadata "$CACHE_ROOT" "cache root" "$fb_uid" "$fb_gid" "700 750"
validate_directory_metadata "$FILES_ROOT" "files root" "$fb_uid" "$fb_gid" "700 750"
validate_directory_metadata "$BACKUP_ROOT" "backup root" 0 "$fb_gid" "700 750"
validate_directory_metadata "$FILEBROWSER_LIFECYCLE_STATE_ROOT" "lifecycle state root" 0 0 "700"

validate_root_managed_file() {
  local path=$1 label=$2 mode owner
  [[ -s "$path" && ! -L "$path" ]] || die "$label is missing, empty, or a symlink: $path"
  owner=$(stat -c '%u' "$path")
  [[ "$owner" == 0 ]] || die "$label must be owned by root: $path"
  mode=$(stat -c '%a' "$path")
  (( (8#$mode & 0022) == 0 )) || die "$label must not be writable by group or other: $path ($mode)"
  ! path_mode_allows_write "$path" "$fb_uid" "$fb_gid" || die "$label is writable by the FileBrowser service identity"
  ! path_mode_allows_write "$path" "$nginx_uid" "$nginx_gid" || die "$label is writable by the Nginx service identity"
}

validate_root_managed_file "$ENV_FILE" "deployment environment file"
validate_root_managed_file "$config_file" "FileBrowser configuration"
for managed_file in \
  "$COMPOSE_FILE" "$DEPLOY_ROOT/compose.maintenance.yaml" \
  "$DEPLOY_ROOT/nginx/nginx.conf" \
  "$DEPLOY_ROOT/nginx/filebrowser.conf.template" \
  "$DEPLOY_ROOT/nginx/filebrowser-maintenance.conf.template" \
  "$DEPLOY_ROOT/scripts/container-entrypoint.sh" \
  "$DEPLOY_ROOT/scripts/nginx-entrypoint.sh" \
  "$DEPLOY_ROOT/scripts/validate-deployment.sh" \
  "$DEPLOY_ROOT/scripts/backup.sh" \
  "$DEPLOY_ROOT/scripts/restore.sh" \
  "$DEPLOY_ROOT/scripts/upgrade.sh" \
  "$DEPLOY_ROOT/scripts/rollback.sh" \
  "$DEPLOY_ROOT/scripts/bootstrap-admin.sh" \
  "$DEPLOY_ROOT/scripts/stack.sh" \
  "$DEPLOY_ROOT/scripts/recover-deployment.sh" \
  "$DEPLOY_ROOT/scripts/lib/deployment-common.sh" \
  "$DEPLOY_ROOT/scripts/lib/deployment_validation.py"; do
  validate_root_managed_file "$managed_file" "deployment asset"
done
recovery_runner=/usr/local/sbin/filebrowser-enterprise-recover
validate_root_managed_file "$recovery_runner" "stable recovery runner"
[[ $(stat -c '%u:%g:%a' "$recovery_runner") == 0:0:755 ]] ||
  die "stable recovery runner must be owned by root:root with mode 0755"
for managed_file in "$ENV_FILE" "$config_file"; do
  managed_mode=$(stat -c '%a' "$managed_file")
  managed_gid=$(stat -c '%g' "$managed_file")
  [[ "$managed_mode" == 440 || "$managed_mode" == 640 ]] ||
    die "$managed_file permissions must be 0440 or 0640, got $managed_mode"
  [[ "$managed_gid" == "$fb_gid" ]] || die "$managed_file must be owned by group $fb_gid"
done

check_secret() {
  local path=$1 label=$2 expected_gid=$3 mode value lines owner group first remainder unique_count
  [[ -s "$path" && ! -L "$path" ]] || die "$label is missing, empty, or a symlink: $path"
  lines=$(wc -l <"$path" | tr -d ' ')
  [[ "$lines" -le 1 ]] || die "$label must contain one line"
  value=$(tr -d '\r\n' <"$path")
  [[ ${#value} -ge 32 ]] || die "$label must contain at least 32 characters"
  [[ "$value" != *PLACEHOLDER* && "$value" != *CHANGEME* ]] || die "$label contains a placeholder"
  first=${value:0:1}
  remainder=${value//$first/}
  [[ -n "$remainder" ]] || die "$label contains a repeated-character placeholder"
  unique_count=$(printf '%s' "$value" | fold -w1 | sort -u | wc -l | tr -d ' ')
  (( unique_count >= 8 )) || die "$label does not contain enough character diversity"
  mode=$(stat -c '%a' "$path")
  [[ "$mode" == 440 || "$mode" == 640 ]] || die "$label permissions must be 0440 or 0640, got $mode"
  owner=$(stat -c '%u' "$path")
  group=$(stat -c '%g' "$path")
  [[ "$owner" == 0 && "$group" == "$expected_gid" ]] || die "$label must be owned by root:$expected_gid"
  printf '%s' "$value"
}

jwt_value=$(check_secret "$CONFIG_ROOT/secrets/jwt_token_secret" "JWT token secret" "$fb_gid")
totp_value=$(check_secret "$CONFIG_ROOT/secrets/totp_secret" "TOTP encryption secret" "$fb_gid")
[[ "$jwt_value" != "$totp_value" ]] || die "JWT and TOTP secrets must be independent"
[[ ! -e "$CONFIG_ROOT/secrets/bootstrap_admin_password" ]] || die "bootstrap password override still exists; remove it before production start"
[[ ! -e "$CONFIG_ROOT/secrets/emergency_admin_password" ]] || die "emergency password staging file still exists; remove it before production start"
if [[ "$ALLOW_BOOTSTRAP_RECOVERY" == false ]]; then
  [[ ! -e "$CONFIG_ROOT/secrets/bootstrap_admin_password.recovery" ]] || die "bootstrap recovery password still exists"
  [[ ! -e "$CONFIG_ROOT/secrets/emergency_admin_password.recovery" ]] || die "emergency recovery password still exists"
fi

tls_cert=$(env_get "$ENV_FILE" TLS_CERT_FILE)
tls_key=$(env_get "$ENV_FILE" TLS_KEY_FILE)
public_host=$(env_get "$ENV_FILE" PUBLIC_HOST)
[[ -s "$tls_cert" && ! -L "$tls_cert" ]] || die "TLS certificate is missing, empty, or a symlink: $tls_cert"
[[ -s "$tls_key" && ! -L "$tls_key" ]] || die "TLS private key is missing, empty, or a symlink: $tls_key"
key_mode=$(stat -c '%a' "$tls_key")
[[ "$key_mode" == 440 || "$key_mode" == 640 ]] || die "TLS private key permissions must be 0440 or 0640, got $key_mode"
[[ $(stat -c '%u' "$tls_key") == 0 && $(stat -c '%g' "$tls_key") == "$nginx_gid" ]] || die "TLS private key must be owned by root:$nginx_gid"
openssl x509 -in "$tls_cert" -noout -checkend 86400 >/dev/null || die "TLS certificate is invalid or expires within 24 hours"
openssl x509 -in "$tls_cert" -noout -checkhost "$public_host" >/dev/null || die "TLS certificate does not cover PUBLIC_HOST"
openssl verify -purpose sslserver -verify_hostname "$public_host" -untrusted "$tls_cert" "$tls_cert" >/dev/null ||
  die "TLS certificate chain is not trusted by the host system trust store"
cert_pub=$(openssl x509 -in "$tls_cert" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
key_pub=$(openssl pkey -in "$tls_key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
[[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || die "TLS certificate and private key do not match"

free_cache_mb=$(df -Pm "$CACHE_ROOT" | awk 'NR == 2 {print $4}')
min_cache_mb=$(env_get_default "$ENV_FILE" MIN_CACHE_FREE_MB 1024)
[[ "$free_cache_mb" =~ ^[0-9]+$ && "$min_cache_mb" =~ ^[0-9]+$ ]] || die "cache free-space values are invalid"
free_space_meets "$CACHE_ROOT" "$min_cache_mb" || die "cache filesystem has only ${free_cache_mb} MiB free; ${min_cache_mb} MiB required"

for writable_path in "$DATA_ROOT" "$DATA_ROOT/database.db" "$CACHE_ROOT" "$FILES_ROOT"; do
  path_mode_allows_write "$writable_path" "$fb_uid" "$fb_gid" || die "FileBrowser identity $fb_uid:$fb_gid cannot write by mode to $writable_path"
done
database_mode=$(stat -c '%a' "$DATA_ROOT/database.db")
[[ $(stat -c '%u' "$DATA_ROOT/database.db") == "$fb_uid" && $(stat -c '%g' "$DATA_ROOT/database.db") == "$fb_gid" ]] ||
  die "database.db must be owned by the FileBrowser identity $fb_uid:$fb_gid"
(( (8#$database_mode & 0022) == 0 )) || die "database.db must not be writable by group or other"

filebrowser_image=$(env_get "$ENV_FILE" FILEBROWSER_IMAGE)
nginx_image=$(env_get "$ENV_FILE" NGINX_IMAGE)
docker image inspect "$filebrowser_image" >/dev/null || die "pinned FileBrowser image is not present locally"
docker image inspect "$nginx_image" >/dev/null || die "pinned Nginx image is not present locally"
compose config --quiet
assert_at_most_one_running filebrowser-enterprise
assert_at_most_one_running nginx
compose run --pull never --rm --no-deps filebrowser-enterprise version >/dev/null
compose run --pull never --rm --no-deps nginx nginx -t -c /etc/nginx/nginx.conf >/dev/null

if [[ "$RUNTIME" == true ]]; then
  assert_exactly_one_running filebrowser-enterprise
  assert_exactly_one_running nginx
  wait_for_service_health filebrowser-enterprise 180 || die "FileBrowser container is not healthy"
  wait_for_service_health nginx 90 || die "Nginx container is not healthy"
  compose exec -T nginx wget -qO- http://filebrowser-enterprise:8080/health | grep -Eq '"message"[[:space:]]*:[[:space:]]*"ok"' || die "Nginx cannot reach the FileBrowser backend"
  compose exec -T filebrowser-enterprise sh -c 'test -w /var/lib/filebrowser-enterprise && test -w /var/cache/filebrowser-enterprise && test -w /srv/filebrowser/files' || die "a required container path is not writable"

  validate_runtime_tls() (
    local https_bind_address https_port connect_host endpoint served_cert expected_fingerprint served_fingerprint
    https_bind_address=$(env_get_default "$ENV_FILE" HTTPS_BIND_ADDRESS 127.0.0.1)
    https_port=$(env_get_default "$ENV_FILE" HTTPS_PORT 443)
    case "$https_bind_address" in
      0.0.0.0|127.0.0.1) connect_host=127.0.0.1 ;;
      ::|::0|0:0:0:0:0:0:0:0|::1) connect_host='[::1]' ;;
      \[*\]) connect_host=$https_bind_address ;;
      *:*) connect_host="[$https_bind_address]" ;;
      *) connect_host=$https_bind_address ;;
    esac
    endpoint="$connect_host:$https_port"
    served_cert=$(mktemp)
    trap 'rm -f -- "$served_cert"' EXIT
    if ! timeout 10 openssl s_client -connect "$endpoint" -servername "$public_host" -showcerts </dev/null 2>/dev/null |
      openssl x509 -out "$served_cert" 2>/dev/null; then
      die "cannot retrieve the running Nginx TLS certificate from $endpoint"
    fi
    openssl x509 -in "$served_cert" -noout -checkend 86400 >/dev/null ||
      die "running Nginx presents an invalid certificate or one expiring within 24 hours"
    openssl x509 -in "$served_cert" -noout -checkhost "$public_host" >/dev/null ||
      die "running Nginx certificate does not cover PUBLIC_HOST"
    expected_fingerprint=$(openssl x509 -in "$tls_cert" -outform DER | sha256sum | awk '{print $1}')
    served_fingerprint=$(openssl x509 -in "$served_cert" -outform DER | sha256sum | awk '{print $1}')
    [[ -n "$expected_fingerprint" && "$served_fingerprint" == "$expected_fingerprint" ]] ||
      die "running Nginx certificate does not match TLS_CERT_FILE; recreate or reload Nginx"
  )
  validate_runtime_tls
fi

log "production deployment validation passed"
