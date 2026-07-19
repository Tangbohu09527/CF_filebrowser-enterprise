#!/usr/bin/env bash
set -Eeuo pipefail

FILEBROWSER_LIFECYCLE_STATE_ROOT=/var/lib/filebrowser-enterprise-lifecycle
FILEBROWSER_RESTORE_JOURNAL=$FILEBROWSER_LIFECYCLE_STATE_ROOT/restore-journal.tsv
FILEBROWSER_COMPOSE_PROJECT=filebrowser-enterprise
COMPOSE_WAIT_SUPPORT_VALIDATED=false

# Host exports take precedence over --env-file. Keep every Compose interpolation
# key out of the child environment so the validated file is authoritative.
declare -ar FILEBROWSER_COMPOSE_ENV_KEYS=(
  AUTH_BURST AUTH_GLOBAL_BURST AUTH_GLOBAL_RATE AUTH_RATE
  BUILD_REVISION BUILD_VERSION CACHE_ROOT CLIENT_BODY_TIMEOUT CONFIG_ROOT
  DATA_ROOT DEPLOY_ROOT FILEBROWSER_BUILD_IMAGE FILEBROWSER_CPUS
  FILEBROWSER_GID FILEBROWSER_IMAGE FILEBROWSER_MEMORY FILEBROWSER_PIDS
  FILEBROWSER_UID FILES_ROOT HTTP_BIND_ADDRESS HTTP_PORT HTTPS_BIND_ADDRESS
  HTTPS_PORT LOG_MAX_FILES LOG_MAX_SIZE MAX_UPLOAD_SIZE NGINX_CPUS NGINX_GID
  NGINX_IMAGE NGINX_MEMORY NGINX_PIDS NGINX_UID PROXY_READ_TIMEOUT
  PROXY_SEND_TIMEOUT PUBLIC_HOST STOP_GRACE_PERIOD TLS_CERT_CONTAINER_PATH
  TLS_KEY_CONTAINER_PATH
)
declare -ar FILEBROWSER_COMPOSE_CONTROL_KEYS=(
  COMPOSE_ANSI COMPOSE_CONVERT_WINDOWS_PATHS COMPOSE_DISABLE_ENV_FILE
  COMPOSE_ENV_FILES COMPOSE_FILE COMPOSE_IGNORE_ORPHANS COMPOSE_MENU
  COMPOSE_PARALLEL_LIMIT COMPOSE_PATH_SEPARATOR COMPOSE_PROFILES
  COMPOSE_PROGRESS COMPOSE_PROJECT_NAME COMPOSE_REMOVE_ORPHANS
  COMPOSE_STATUS_STDOUT
)

log() {
  printf '%s [INFO] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"
}

warn() {
  printf '%s [WARN] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

die() {
  printf '%s [ERROR] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "this operation must run as root"
}

env_get() {
  local file=$1 key=$2 required=${3:-true}
  local -a matches=()
  [[ -f "$file" ]] || die "environment file does not exist: $file"
  mapfile -t matches < <(awk -v key="$key" '
    $0 ~ "^[[:space:]]*" key "=" {
      sub("^[[:space:]]*" key "=", "")
      sub("\\r$", "")
      print
    }
  ' "$file")
  (( ${#matches[@]} <= 1 )) || die "duplicate key $key in $file"
  if (( ${#matches[@]} == 0 )) || [[ -z ${matches[0]} ]]; then
    [[ "$required" == false ]] && return 0
    die "required key $key is missing or empty in $file"
  fi
  printf '%s' "${matches[0]}"
}

env_get_default() {
  local file=$1 key=$2 default=$3 value
  value=$(env_get "$file" "$key" false)
  printf '%s' "${value:-$default}"
}

env_set() {
  local file=$1 key=$2 value=$3 tmp
  [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || die "invalid environment key: $key"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "environment value contains a newline: $key"
  tmp=$(mktemp "${file}.tmp.XXXXXX")
  awk -v key="$key" -v value="$value" '
    BEGIN { changed = 0 }
    $0 ~ "^[[:space:]]*" key "=" {
      if (changed == 0) {
        print key "=" value
        changed = 1
      }
      next
    }
    { print }
    END {
      if (changed == 0) print key "=" value
    }
  ' "$file" >"$tmp"
  chmod --reference="$file" "$tmp"
  chown --reference="$file" "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$file"
  fsync_path "$file"
  fsync_parent "$file"
}

validate_absolute_path() {
  local value=$1 label=$2
  [[ "$value" == /* ]] || die "$label must be an absolute path: $value"
  [[ "$value" != */ && "$value" != *//* ]] ||
    die "$label must use a canonical path without trailing or repeated slashes: $value"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* ]] ||
    die "$label contains unsupported control whitespace"
  [[ "/$value/" != *'/../'* && "/$value/" != *'/./'* ]] || die "$label contains unsafe path traversal: $value"
  [[ "$value" != "/" ]] || die "$label must not be the filesystem root"
}

validate_pinned_image() {
  local image=$1 label=$2 digest first remainder reference registry registry_lower
  [[ "$image" =~ ^[^[:space:]]+@sha256:[0-9a-fA-F]{64}$ ]] || die "$label must be pinned with @sha256:<64 hex>: $image"
  [[ "$image" != *':latest@sha256:'* ]] || die "$label must not use the latest tag"
  reference=${image%@sha256:*}
  [[ "$reference" == */* ]] || die "$label must include an explicit internal registry host"
  registry=${reference%%/*}
  [[ "$registry" == *.* || "$registry" == *:* ]] || die "$label must include a registry-qualified image name"
  registry_lower=${registry,,}
  case "$registry_lower" in
    docker.io|docker.io:*|index.docker.io|index.docker.io:*|registry-1.docker.io|registry-1.docker.io:*|\
    registry.hub.docker.com|registry.hub.docker.com:*|ghcr.io|ghcr.io:*|quay.io|quay.io:*)
      die "$label must not use a public image registry: $registry"
      ;;
  esac
  digest=${image##*@sha256:}
  first=${digest:0:1}
  remainder=${digest//$first/}
  [[ -n "$remainder" ]] || die "$label uses a placeholder digest"
}

validate_internal_image() {
  local image=$1 label=$2 env_file=${3:-$ENV_FILE} expected registry expected_name expected_port
  validate_pinned_image "$image" "$label"
  expected=$(env_get "$env_file" INTERNAL_REGISTRY_HOST)
  [[ "$expected" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?$ ]] ||
    die "INTERNAL_REGISTRY_HOST must be a lowercase DNS/IPv4 host with an optional port"
  expected_name=${expected%%:*}
  expected_port=
  [[ "$expected" != *:* ]] || expected_port=${expected##*:}
  if [[ -n "$expected_port" ]] && (( 10#$expected_port > 65535 )); then
    die "INTERNAL_REGISTRY_HOST port exceeds 65535"
  fi
  case "$expected_name" in
    docker.io|index.docker.io|registry-1.docker.io|registry.hub.docker.com|ghcr.io|quay.io|registry.gitlab.com|public.ecr.aws)
      die "INTERNAL_REGISTRY_HOST must not name a public registry: $expected"
      ;;
  esac
  registry=${image%%/*}
  [[ "${registry,,}" == "$expected" ]] ||
    die "$label registry must exactly match INTERNAL_REGISTRY_HOST ($expected)"
}

require_compose_wait_support() {
  local version major minor
  [[ "$COMPOSE_WAIT_SUPPORT_VALIDATED" == true ]] && return 0
  require_command docker
  require_command env
  version=$(docker compose version --short 2>/dev/null) || die "Docker Compose v2 is unavailable"
  version=${version#v}
  version=${version%%-*}
  version=${version%%+*}
  [[ "$version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "cannot parse Docker Compose version: $version"
  IFS=. read -r major minor _ <<<"$version"
  (( major > 2 || (major == 2 && minor >= 20) )) ||
    die "Docker Compose v2.20.0 or newer is required, found $version"
  COMPOSE_WAIT_SUPPORT_VALIDATED=true
}

deployment_init_layout() {
  DEPLOY_ROOT=${DEPLOY_ROOT:-/opt/filebrowser-enterprise}
  ENV_FILE=${ENV_FILE:-$DEPLOY_ROOT/.env}
  COMPOSE_FILE=${COMPOSE_FILE:-$DEPLOY_ROOT/compose.yaml}
  [[ -f "$ENV_FILE" ]] || die "deployment environment file does not exist: $ENV_FILE"
  [[ -f "$COMPOSE_FILE" ]] || die "compose file does not exist: $COMPOSE_FILE"

  CONFIG_ROOT=$(env_get_default "$ENV_FILE" CONFIG_ROOT /etc/filebrowser-enterprise)
  DATA_ROOT=$(env_get_default "$ENV_FILE" DATA_ROOT /var/lib/filebrowser-enterprise)
  CACHE_ROOT=$(env_get_default "$ENV_FILE" CACHE_ROOT /var/cache/filebrowser-enterprise)
  FILES_ROOT=$(env_get_default "$ENV_FILE" FILES_ROOT /srv/filebrowser/files)
  BACKUP_ROOT=$(env_get_default "$ENV_FILE" BACKUP_ROOT /var/backups/filebrowser-enterprise)
  LOCK_ROOT=${LOCK_ROOT:-/run/lock/filebrowser-enterprise}

  validate_absolute_path "$DEPLOY_ROOT" DEPLOY_ROOT
  validate_absolute_path "$CONFIG_ROOT" CONFIG_ROOT
  validate_absolute_path "$DATA_ROOT" DATA_ROOT
  validate_absolute_path "$CACHE_ROOT" CACHE_ROOT
  validate_absolute_path "$FILES_ROOT" FILES_ROOT
  validate_absolute_path "$BACKUP_ROOT" BACKUP_ROOT
  validate_absolute_path "$LOCK_ROOT" LOCK_ROOT
}

assert_independent_paths() {
  (( $# > 1 )) || die "assert_independent_paths requires at least two paths"
  local path resolved prior index
  local -a paths=() resolved_paths=()
  for path in "$@"; do
    [[ -e "$path" && ! -L "$path" ]] || die "independent-path input is missing or a symlink: $path"
    resolved=$(realpath -e -- "$path")
    for (( index=0; index<${#resolved_paths[@]}; index++ )); do
      prior=${resolved_paths[$index]}
      if [[ "$resolved/" == "$prior/"* || "$prior/" == "$resolved/"* ]]; then
        die "deployment paths must be distinct and non-nested: ${paths[$index]} and $path"
      fi
    done
    paths+=("$path")
    resolved_paths+=("$resolved")
  done
}

assert_non_nested_target_paths() {
  (( $# > 1 )) || die "assert_non_nested_target_paths requires at least two paths"
  local path parent base resolved prior index
  local -a paths=() resolved_paths=()
  for path in "$@"; do
    validate_absolute_path "$path" target_path
    parent=$(dirname -- "$path")
    base=$(basename -- "$path")
    [[ -d "$parent" && ! -L "$parent" ]] || die "target path parent is missing or a symlink: $parent"
    resolved="$(realpath -e -- "$parent")/$base"
    for (( index=0; index<${#resolved_paths[@]}; index++ )); do
      prior=${resolved_paths[$index]}
      if [[ "$resolved/" == "$prior/"* || "$prior/" == "$resolved/"* ]]; then
        die "target paths must be distinct and non-nested: ${paths[$index]} and $path"
      fi
    done
    paths+=("$path")
    resolved_paths+=("$resolved")
  done
}

compose() {
  local key project_directory
  local -a sanitized_env=(env)
  require_compose_wait_support
  project_directory=$(dirname -- "$COMPOSE_FILE")
  [[ -d "$project_directory" && ! -L "$project_directory" ]] ||
    die "Compose project directory is missing or unsafe: $project_directory"
  for key in "${FILEBROWSER_COMPOSE_ENV_KEYS[@]}" "${FILEBROWSER_COMPOSE_CONTROL_KEYS[@]}"; do
    sanitized_env+=(-u "$key")
  done
  "${sanitized_env[@]}" docker compose --project-name "$FILEBROWSER_COMPOSE_PROJECT" \
    --project-directory "$project_directory" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

maintenance_compose() {
  local override_file
  override_file="$(dirname -- "$COMPOSE_FILE")/compose.maintenance.yaml"
  [[ -f "$override_file" && ! -L "$override_file" ]] ||
    die "maintenance Compose override is missing or unsafe: $override_file"
  compose -f "$override_file" "$@"
}

enable_production_restart_policy() {
  local service container_id
  for service in filebrowser-enterprise nginx; do
    assert_exactly_one_running "$service"
    container_id=$(service_container_id "$service")
    [[ -n "$container_id" ]] || die "cannot identify $service while restoring its restart policy"
    docker update --restart=unless-stopped "$container_id" >/dev/null
  done
}

queue_systemd_stack_ownership() {
  require_command systemctl
  if ! systemctl is-active --quiet filebrowser-enterprise.service; then
    systemctl start --no-block filebrowser-enterprise.service
    log "queued filebrowser-enterprise.service start; it will acquire the lifecycle lock after this script exits"
  fi
}

promote_production_nginx() {
  log "replacing the fail-closed maintenance entry point with the production Nginx proxy"
  compose stop --timeout 30 nginx >/dev/null 2>&1 || true
  if ! compose up -d --no-deps --force-recreate --scale nginx=1 nginx; then
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    warn "production Nginx could not be created; the public entry point remains stopped"
    return 1
  fi
  if ! assert_exactly_one_running nginx || ! wait_for_service_health nginx 90; then
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    warn "production Nginx did not become healthy and was stopped"
    return 1
  fi
}

service_container_id() {
  compose ps -q "$1" 2>/dev/null | head -n 1
}

service_container_id_all() {
  compose ps --all -q "$1" 2>/dev/null
}

service_is_running() {
  local id
  id=$(service_container_id "$1")
  [[ -n "$id" ]] || return 1
  [[ $(docker inspect --format '{{.State.Running}}' "$id" 2>/dev/null) == true ]]
}

wait_for_service_health() {
  local service=$1 timeout=${2:-180} deadline id status
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    id=$(service_container_id "$service")
    if [[ -n "$id" ]]; then
      status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$id" 2>/dev/null || true)
      [[ "$status" == healthy ]] && return 0
      [[ "$status" == unhealthy || "$status" == missing ]] && return 1
    fi
    sleep 2
  done
  return 1
}

acquire_lock() {
  local name=$1
  mkdir -p -- "$LOCK_ROOT"
  exec {DEPLOYMENT_LOCK_FD}>"$LOCK_ROOT/$name.lock"
  flock -n "$DEPLOYMENT_LOCK_FD" || die "another $name operation is already running"
}

acquire_lifecycle_lock() {
  local wait_seconds=${1:-0} lock_file inherited_target
  [[ "$wait_seconds" =~ ^[0-9]+$ ]] || die "lifecycle lock wait must be a non-negative integer"
  mkdir -p -- "$LOCK_ROOT"
  lock_file="$LOCK_ROOT/lifecycle.lock"
  if [[ ${FILEBROWSER_LIFECYCLE_LOCK_FD:-} =~ ^[0-9]+$ && -e "/proc/$$/fd/$FILEBROWSER_LIFECYCLE_LOCK_FD" ]]; then
    inherited_target=$(readlink -f -- "/proc/$$/fd/$FILEBROWSER_LIFECYCLE_LOCK_FD" 2>/dev/null || true)
    if [[ "$inherited_target" == "$lock_file" ]] && flock -n "$FILEBROWSER_LIFECYCLE_LOCK_FD"; then
      return 0
    fi
  fi
  exec {FILEBROWSER_LIFECYCLE_LOCK_FD}>"$lock_file"
  if (( wait_seconds > 0 )); then
    flock -w "$wait_seconds" "$FILEBROWSER_LIFECYCLE_LOCK_FD" || die "timed out waiting for another deployment lifecycle operation"
  else
    flock -n "$FILEBROWSER_LIFECYCLE_LOCK_FD" || die "another deployment lifecycle operation is already running"
  fi
  export FILEBROWSER_LIFECYCLE_LOCK_FD
}

running_container_count() {
  local service=$1
  compose ps --status running -q "$service" | awk 'NF { count++ } END { print count + 0 }'
}

assert_at_most_one_running() {
  local service=$1 count
  count=$(running_container_count "$service")
  (( count <= 1 )) || die "$service has $count running containers; refusing a shared-database lifecycle operation"
}

assert_exactly_one_running() {
  local service=$1 count
  count=$(running_container_count "$service")
  (( count == 1 )) || die "$service must have exactly one running container, found $count"
}

assert_no_running() {
  local service=$1 count
  count=$(running_container_count "$service")
  (( count == 0 )) || die "$service still has $count running containers"
}

manifest_get() {
  local manifest=$1 key=$2
  awk -F '\t' -v key="$key" '$1 == key { print substr($0, length($1) + 2); count++ } END { if (count != 1) exit 1 }' "$manifest"
}

tsv_set() {
  local file=$1 key=$2 value=$3 tmp
  [[ "$key" =~ ^[a-z][a-z0-9_]*$ ]] || die "invalid TSV key: $key"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* ]] || die "TSV value contains unsupported whitespace: $key"
  tmp=$(mktemp "${file}.tmp.XXXXXX") || return
  if ! awk -F '\t' -v key="$key" -v value="$value" '
    BEGIN { changed = 0 }
    $1 == key {
      if (changed == 0) {
        print key "\t" value
        changed = 1
      }
      next
    }
    { print }
    END {
      if (changed == 0) print key "\t" value
    }
  ' "$file" >"$tmp"; then
    rm -f -- "$tmp"
    return 1
  fi
  chmod --reference="$file" "$tmp" || { rm -f -- "$tmp"; return 1; }
  chown --reference="$file" "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$file" || { rm -f -- "$tmp"; return 1; }
}

safe_tar_members() {
  local archive=$1 member listing status=0
  listing=$(mktemp)
  if ! tar -tf "$archive" >"$listing"; then
    rm -f -- "$listing"
    return 1
  fi
  while IFS= read -r member; do
    if [[ "$member" == /* || "/$member/" == *'/../'* ]]; then
      status=1
      break
    fi
  done <"$listing"
  rm -f -- "$listing"
  return "$status"
}

mode_bits_allow_write() {
  local mode=$1 owner=$2 group=$3 expected_uid=$4 expected_gid=$5 permission_digit
  mode=${mode: -3}
  if [[ "$owner" == "$expected_uid" ]]; then
    permission_digit=${mode:0:1}
  elif [[ "$group" == "$expected_gid" ]]; then
    permission_digit=${mode:1:1}
  else
    permission_digit=${mode:2:1}
  fi
  (( (8#$permission_digit & 2) != 0 ))
}

path_mode_allows_write() {
  local path=$1 expected_uid=$2 expected_gid=$3 mode owner group
  [[ -e "$path" && ! -L "$path" ]] || return 1
  mode=$(stat -c '%a' "$path") || return 1
  owner=$(stat -c '%u' "$path") || return 1
  group=$(stat -c '%g' "$path") || return 1
  mode_bits_allow_write "$mode" "$owner" "$group" "$expected_uid" "$expected_gid"
}

free_space_meets() {
  local path=$1 minimum_mb=$2 available_mb
  [[ "$minimum_mb" =~ ^[0-9]+$ ]] || return 1
  available_mb=$(df -Pm "$path" | awk 'NR == 2 {print $4}')
  [[ "$available_mb" =~ ^[0-9]+$ ]] || return 1
  (( available_mb >= minimum_mb ))
}

path_logical_bytes() {
  (( $# > 0 )) || die "path_logical_bytes requires at least one path"
  du -s -B1 --apparent-size --total -- "$@" | awk 'END { print $1 }'
}

path_allocated_bytes() {
  (( $# > 0 )) || die "path_allocated_bytes requires at least one path"
  du -s -B1 --total -- "$@" | awk 'END { print $1 }'
}

archive_logical_bytes() {
  local archive=$1
  python3 - "$archive" <<'PY'
import sys
import tarfile

with tarfile.open(sys.argv[1], mode="r:*") as bundle:
    print(sum(member.size for member in bundle.getmembers() if member.isfile()))
PY
}

archive_file_bytes() {
  stat -c '%s' "$1"
}

validate_byte_count() {
  local value=$1 label=${2:-byte_count}
  [[ "$value" == 0 || "$value" =~ ^[1-9][0-9]*$ ]] || die "$label must be a canonical non-negative integer"
  (( ${#value} < 19 )) || [[ ${#value} -eq 19 && "$value" < 1000000000000000001 ]] ||
    die "$label exceeds the supported one-exabyte safety bound"
}

space_with_margin() {
  local bytes=$1 percent=${2:-10} reserve_mb=${3:-64} percentage_bytes result
  validate_byte_count "$bytes" space_bytes
  [[ "$percent" == 0 || "$percent" =~ ^[1-9][0-9]*$ ]] || die "space margin percent must be a canonical non-negative integer"
  [[ "$reserve_mb" == 0 || "$reserve_mb" =~ ^[1-9][0-9]*$ ]] || die "space reserve must be a canonical non-negative integer"
  (( percent <= 100 && reserve_mb <= 1048576 )) || die "space margin exceeds the supported safety bound"
  percentage_bytes=$(( (bytes / 100 * percent) + (bytes % 100 * percent / 100) ))
  result=$(( bytes + percentage_bytes + (reserve_mb * 1024 * 1024) ))
  validate_byte_count "$result" space_requirement
  printf '%s' "$result"
}

require_filesystem_space() {
  local label=$1 path bytes device available current_required
  shift
  (( $# > 0 && $# % 2 == 0 )) || die "require_filesystem_space requires path/byte pairs"
  declare -A required_by_device=()
  declare -A sample_by_device=()

  while (( $# > 0 )); do
    path=$1
    bytes=$2
    shift 2
    [[ -e "$path" && ! -L "$path" ]] || die "$label space-check path is missing or unsafe: $path"
    validate_byte_count "$bytes" "$label byte requirement for $path"
    device=$(stat -c '%d' "$path")
    current_required=${required_by_device[$device]:-0}
    (( current_required <= 1000000000000000000 - bytes )) ||
      die "$label aggregate byte requirement exceeds the supported one-exabyte safety bound"
    required_by_device[$device]=$(( current_required + bytes ))
    validate_byte_count "${required_by_device[$device]}" "$label aggregate byte requirement"
    sample_by_device[$device]=$path
  done

  for device in "${!required_by_device[@]}"; do
    path=${sample_by_device[$device]}
    available=$(df -P -B1 "$path" | awk 'NR == 2 { print $4 }')
    [[ "$available" =~ ^[0-9]+$ ]] || die "cannot determine free space for $path"
    (( available >= required_by_device[$device] )) ||
      die "$label requires ${required_by_device[$device]} bytes on the filesystem containing $path; only $available bytes are free"
  done
}

validate_lifecycle_state_root() {
  [[ -d "$FILEBROWSER_LIFECYCLE_STATE_ROOT" && ! -L "$FILEBROWSER_LIFECYCLE_STATE_ROOT" ]] ||
    die "lifecycle state root must be an existing real directory"
  [[ $(stat -c '%u:%g:%a' "$FILEBROWSER_LIFECYCLE_STATE_ROOT") == 0:0:700 ]] ||
    die "lifecycle state root must be owned by root:root with mode 0700"
}

ensure_lifecycle_state_root() {
  [[ ! -L "$FILEBROWSER_LIFECYCLE_STATE_ROOT" ]] || die "lifecycle state root must not be a symlink"
  mkdir -p -- "$FILEBROWSER_LIFECYCLE_STATE_ROOT"
  chown 0:0 "$FILEBROWSER_LIFECYCLE_STATE_ROOT"
  chmod 0700 "$FILEBROWSER_LIFECYCLE_STATE_ROOT"
  validate_lifecycle_state_root
}

assert_no_incomplete_restore() {
  if [[ -e "$FILEBROWSER_RESTORE_JOURNAL" || -L "$FILEBROWSER_RESTORE_JOURNAL" ]]; then
    die "an incomplete restore journal exists at $FILEBROWSER_RESTORE_JOURNAL; run /usr/local/sbin/filebrowser-enterprise-recover before starting the stack"
  fi
}

lifecycle_status_is_terminal() {
  case "$1" in
    completed|rolled-back|auto-rolled-back|aborted-before-backup|aborted-old-service-restored|rollback-failed-old-service-restored)
      return 0
      ;;
    *) return 1 ;;
  esac
}

first_unfinished_lifecycle_state() {
  local honor_allowed=${1:-true} state_root state_root_real state_dir state_file state_real status allowed_real=
  state_root="$FILEBROWSER_LIFECYCLE_STATE_ROOT/upgrade-history"
  [[ -d "$state_root" && ! -L "$state_root" ]] || return 3
  for command in stat realpath awk; do require_command "$command"; done
  state_root_real=$(realpath -e -- "$state_root")
  if [[ "$honor_allowed" == true && -n ${FILEBROWSER_ACTIVE_TRANSACTION_STATE:-} ]]; then
    [[ -f "$FILEBROWSER_ACTIVE_TRANSACTION_STATE" && ! -L "$FILEBROWSER_ACTIVE_TRANSACTION_STATE" ]] ||
      die "allowed lifecycle state is missing or unsafe: $FILEBROWSER_ACTIVE_TRANSACTION_STATE"
    allowed_real=$(realpath -e -- "$FILEBROWSER_ACTIVE_TRANSACTION_STATE")
    case "$allowed_real" in
      "$state_root_real"/*/state.tsv) ;;
      *) die "allowed lifecycle state is outside $state_root_real" ;;
    esac
  fi
  for state_file in "$state_root"/*/state.tsv; do
    [[ -e "$state_file" || -L "$state_file" ]] || continue
    state_dir=${state_file%/state.tsv}
    [[ -d "$state_dir" && ! -L "$state_dir" ]] || die "unsafe lifecycle state directory: $state_dir"
    [[ -f "$state_file" && ! -L "$state_file" ]] || die "unsafe lifecycle state entry: $state_file"
    state_real=$(realpath -e -- "$state_file")
    case "$state_real" in
      "$state_root_real"/*/state.tsv) ;;
      *) die "lifecycle state resolves outside $state_root_real: $state_file" ;;
    esac
    [[ $(stat -c '%u:%g:%a' "$state_file") == 0:0:600 ]] ||
      die "lifecycle state must be root:root with mode 0600: $state_file"
    status=$(manifest_get "$state_file" status 2>/dev/null) || status=invalid
    lifecycle_status_is_terminal "$status" && continue
    [[ -n "$allowed_real" && "$state_real" == "$allowed_real" ]] && continue
    printf '%s' "$state_real"
    return 0
  done
  return 3
}

assert_no_incomplete_lifecycle_transaction() {
  local unfinished scan_status
  assert_no_incomplete_restore
  if unfinished=$(first_unfinished_lifecycle_state true); then
    die "unfinished upgrade/rollback state exists at $unfinished; inspect it and run rollback.sh --state $unfinished --apply"
  else
    scan_status=$?
    (( scan_status == 3 )) || die "unable to validate upgrade/rollback lifecycle state"
  fi
}

disable_managed_restart_policy() {
  local service container_id_output
  local -a container_ids=()
  for service in nginx filebrowser-enterprise; do
    container_id_output=$(service_container_id_all "$service") ||
      die "cannot enumerate $service containers while disabling restart policy"
    [[ -n "$container_id_output" ]] || continue
    container_ids=()
    mapfile -t container_ids <<<"$container_id_output"
    docker update --restart=no "${container_ids[@]}" >/dev/null
  done
}

fsync_path() {
  sync -f -- "$1"
}

fsync_parent() {
  local parent
  parent=$(dirname -- "$1") || return
  fsync_path "$parent"
}

durable_move() {
  local source=$1 target=$2 source_parent target_parent
  source_parent=$(dirname -- "$source") || return
  target_parent=$(dirname -- "$target") || return
  mv -- "$source" "$target" || return
  fsync_path "$source_parent" || return
  [[ "$target_parent" == "$source_parent" ]] || fsync_path "$target_parent" || return
}

durable_tsv_set() {
  local file=$1 key=$2 value=$3
  tsv_set "$file" "$key" "$value" || return
  fsync_path "$file" || return
  fsync_parent "$file" || return
}

clear_restore_journal() {
  [[ -e "$FILEBROWSER_RESTORE_JOURNAL" || -L "$FILEBROWSER_RESTORE_JOURNAL" ]] || return 0
  rm -f -- "$FILEBROWSER_RESTORE_JOURNAL" || return
  fsync_path "$FILEBROWSER_LIFECYCLE_STATE_ROOT" || return
}


require_tar_regular_member() {
  local archive=$1 member=$2
  python3 - "$archive" "$member" <<'PY'
import posixpath
import sys
import tarfile

archive_path, required_name = sys.argv[1:]
required_name = posixpath.normpath(required_name)
with tarfile.open(archive_path, mode="r:*") as bundle:
    matches = [
        item
        for item in bundle.getmembers()
        if posixpath.normpath(item.name) == required_name
    ]
if len(matches) != 1 or not matches[0].isfile():
    raise SystemExit(f"required regular tar member is missing or duplicated: {required_name}")
PY
}
