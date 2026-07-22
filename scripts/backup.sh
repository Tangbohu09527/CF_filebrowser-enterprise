#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=scripts/lib/deployment-common.sh
source "$SCRIPT_DIR/lib/deployment-common.sh"

KEEP_STOPPED=false
REASON=scheduled
STAGE_DIR=
FINAL_DIR=
APP_WAS_RUNNING=false
NGINX_WAS_RUNNING=false
CAPTURED_VERSION=unknown
BACKUP_COMPLETE=false
RECEIVED_SIGNAL=
APP_CONTAINER_ID=
BACKUP_RETENTION_COUNT=

usage() {
  cat <<'USAGE'
Usage: backup.sh [--keep-stopped] [--reason TEXT]

Creates a consistent local snapshot. By default, services that were running are
restored even when backup fails. --keep-stopped is reserved for a surrounding
maintenance workflow such as upgrade or restore.
USAGE
}

while (( $# > 0 )); do
  case "$1" in
    --keep-stopped) KEEP_STOPPED=true; shift ;;
    --reason)
      (( $# >= 2 )) || die "missing value for --reason"
      [[ -n "$2" && "$2" != --* ]] || die "missing value for --reason"
      REASON=$2
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ "$REASON" != *$'\n'* && "$REASON" != *$'\r'* && "$REASON" != *$'\t'* ]] ||
  die "backup reason contains unsupported control whitespace"

deployment_init_layout
require_root
for command in docker flock fuser tar sha256sum find sort xargs realpath du stat df python3 sync; do
  require_command "$command"
done
acquire_lock backup
acquire_lifecycle_lock
validate_lifecycle_state_root
assert_no_incomplete_lifecycle_transaction
assert_at_most_one_running filebrowser-enterprise
assert_at_most_one_running nginx
BACKUP_RETENTION_COUNT=$(env_get_default "$ENV_FILE" BACKUP_RETENTION_COUNT 7)
[[ "$BACKUP_RETENTION_COUNT" =~ ^[1-9][0-9]*$ ]] || die "BACKUP_RETENTION_COUNT must be a positive integer"
(( BACKUP_RETENTION_COUNT <= 3650 )) || die "BACKUP_RETENTION_COUNT exceeds the supported safety bound"
COMPOSE_PROJECT_NAME_VALUE=$(env_get "$ENV_FILE" COMPOSE_PROJECT_NAME)
[[ "$COMPOSE_PROJECT_NAME_VALUE" == filebrowser-enterprise ]] ||
  die "COMPOSE_PROJECT_NAME must be explicitly set to filebrowser-enterprise"
INTERNAL_REGISTRY_HOST_VALUE=$(env_get "$ENV_FILE" INTERNAL_REGISTRY_HOST)

apply_scheduled_retention() {
  local backup candidate format schema reason registry snapshot_name snapshot_id delete_count index deleted
  local -a scheduled_backups=() verified_backups=()
  mapfile -d '' scheduled_backups < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'backup-*' -print0 | sort -z)
  for candidate in "${scheduled_backups[@]}"; do
    [[ ! -L "$candidate" && -f "$candidate/manifest.tsv" && ! -L "$candidate/manifest.tsv" \
      && -f "$candidate/checksums.sha256" && ! -L "$candidate/checksums.sha256" ]] || continue
    format=$(manifest_get "$candidate/manifest.tsv" format_version 2>/dev/null) || continue
    schema=$(manifest_get "$candidate/manifest.tsv" deployment_schema 2>/dev/null) || continue
    reason=$(manifest_get "$candidate/manifest.tsv" reason 2>/dev/null) || continue
    registry=$(manifest_get "$candidate/manifest.tsv" internal_registry_host 2>/dev/null) || continue
    snapshot_id=$(manifest_get "$candidate/manifest.tsv" snapshot_id 2>/dev/null) || continue
    snapshot_name=$(basename -- "$candidate")
    [[ "$format" == 1 && "$schema" == 2 && "$reason" == scheduled \
      && "$registry" == "$INTERNAL_REGISTRY_HOST_VALUE" && "$snapshot_id" == "$snapshot_name" ]] || continue
    grep -Eq '^[0-9a-fA-F]{64}[[:space:]]+manifest\.tsv$' "$candidate/checksums.sha256" || continue
    for backup in database.tar config.tar secrets.tar files.tar deployment.tar systemd.tar; do
      [[ -f "$candidate/payload/$backup" && ! -L "$candidate/payload/$backup" ]] || continue 2
      grep -Eq "^[0-9a-fA-F]{64}[[:space:]]+payload/${backup}$" "$candidate/checksums.sha256" || continue 2
    done
    ( cd -- "$candidate" && sha256sum -c checksums.sha256 >/dev/null 2>&1 ) || continue
    verified_backups+=("$candidate")
  done
  delete_count=$(( ${#verified_backups[@]} - BACKUP_RETENTION_COUNT ))
  (( delete_count > 0 )) || return 0
  deleted=0
  for (( index=0; index<${#verified_backups[@]} && deleted<delete_count; index++ )); do
    candidate=${verified_backups[$index]}
    [[ "$candidate" != "$FINAL_DIR" ]] || continue
    case "$candidate/" in
      "$BACKUP_ROOT"/backup-*/) ;;
      *) warn "retention refused an unsafe backup path: $candidate"; return 1 ;;
    esac
    log "deleting expired scheduled local backup: $candidate"
    if ! rm -rf -- "$candidate"; then
      warn "failed to delete expired scheduled backup: $candidate"
      return 1
    fi
    deleted=$((deleted + 1))
  done
  (( deleted == delete_count )) || { warn "retention could not select enough safe expired backups"; return 1; }
  fsync_path "$BACKUP_ROOT"
}

restore_previous_service_state() {
  local exit_status=$?
  trap - EXIT
  set +e
  host_stopping=false
  if [[ -n "$RECEIVED_SIGNAL" ]] && command -v systemctl >/dev/null 2>&1; then
    system_state=$(systemctl is-system-running 2>/dev/null || true)
    [[ "$system_state" != stopping && "$system_state" != offline ]] || host_stopping=true
  fi
  if [[ "$host_stopping" == true ]]; then
    warn "host shutdown is in progress; backup cleanup will not restart containers"
  elif [[ "$KEEP_STOPPED" == false || "$BACKUP_COMPLETE" == false ]]; then
    app_recovered=true
    if [[ "$APP_WAS_RUNNING" == true ]] && ! service_is_running filebrowser-enterprise; then
      log "restoring FileBrowser service state"
      compose up -d --no-deps --scale filebrowser-enterprise=1 filebrowser-enterprise
      if ! ( assert_exactly_one_running filebrowser-enterprise ); then
        warn "FileBrowser singleton assertion failed after backup"
        app_recovered=false
        (( exit_status == 0 )) && exit_status=1
      elif ! wait_for_service_health filebrowser-enterprise 180; then
        warn "FileBrowser did not become healthy after backup; inspect compose logs immediately"
        app_recovered=false
        (( exit_status == 0 )) && exit_status=1
      fi
    fi
    if [[ "$NGINX_WAS_RUNNING" == true && "$app_recovered" == true ]] && ! service_is_running nginx; then
      log "restoring Nginx service state"
      compose up -d --no-deps --scale nginx=1 nginx
      if ! ( assert_exactly_one_running nginx ); then
        warn "Nginx singleton assertion failed after backup"
        (( exit_status == 0 )) && exit_status=1
      elif ! wait_for_service_health nginx 90; then
        warn "Nginx did not become healthy after backup; inspect compose logs immediately"
        (( exit_status == 0 )) && exit_status=1
      fi
    elif [[ "$NGINX_WAS_RUNNING" == true && "$app_recovered" == false ]]; then
      warn "Nginx remains stopped because FileBrowser recovery did not become healthy"
    fi
  fi
  if (( exit_status == 0 )) && [[ "$BACKUP_COMPLETE" == true && "$REASON" == scheduled ]]; then
    if ! apply_scheduled_retention; then
      warn "scheduled backup succeeded, but local retention cleanup failed"
      exit_status=1
    fi
  fi
  if [[ "$BACKUP_COMPLETE" == false && -n "$STAGE_DIR" && -d "$STAGE_DIR" ]]; then
    rm -rf -- "$STAGE_DIR"
  fi
  exit "$exit_status"
}
trap restore_previous_service_state EXIT
trap 'RECEIVED_SIGNAL=TERM; exit 143' TERM
trap 'RECEIVED_SIGNAL=INT; exit 130' INT
trap 'RECEIVED_SIGNAL=HUP; exit 129' HUP

for path in "$DEPLOY_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$CACHE_ROOT" "$FILES_ROOT" "$BACKUP_ROOT"; do
  validate_absolute_path "$path" backup_path
  [[ ! -L "$path" ]] || die "backup source must not be a symlink: $path"
  [[ -d "$path" ]] || die "backup source directory does not exist: $path"
done
assert_independent_paths "$DEPLOY_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$CACHE_ROOT" "$FILES_ROOT" "$BACKUP_ROOT"
assert_independent_paths "$DEPLOY_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$CACHE_ROOT" "$FILES_ROOT" "$BACKUP_ROOT" \
  "$FILEBROWSER_LIFECYCLE_STATE_ROOT" "$LOCK_ROOT" /etc/systemd/system
[[ -s "$DATA_ROOT/database.db" && ! -L "$DATA_ROOT/database.db" ]] || die "database is missing, empty, or a symlink: $DATA_ROOT/database.db"
[[ -s "$CONFIG_ROOT/config.yaml" && ! -L "$CONFIG_ROOT/config.yaml" ]] || die "configuration is missing, empty, or a symlink: $CONFIG_ROOT/config.yaml"
[[ -d "$CONFIG_ROOT/secrets" && ! -L "$CONFIG_ROOT/secrets" ]] || die "secrets directory is missing or a symlink: $CONFIG_ROOT/secrets"
for secret_name in jwt_token_secret totp_secret; do
  [[ -s "$CONFIG_ROOT/secrets/$secret_name" && ! -L "$CONFIG_ROOT/secrets/$secret_name" ]] ||
    die "required stable secret is missing, empty, or a symlink: $secret_name"
done
for transient_name in bootstrap_admin_password emergency_admin_password bootstrap_admin_password.recovery emergency_admin_password.recovery; do
  [[ ! -e "$CONFIG_ROOT/secrets/$transient_name" && ! -L "$CONFIG_ROOT/secrets/$transient_name" ]] ||
    die "transient bootstrap secret must not be backed up: $transient_name"
done
[[ -d "$CONFIG_ROOT/tls" && ! -L "$CONFIG_ROOT/tls" ]] || die "TLS directory is missing or a symlink: $CONFIG_ROOT/tls"
[[ -s "$CONFIG_ROOT/tls/tls.crt" && ! -L "$CONFIG_ROOT/tls/tls.crt" ]] || die "TLS certificate is missing, empty, or a symlink"
[[ -s "$CONFIG_ROOT/tls/tls.key" && ! -L "$CONFIG_ROOT/tls/tls.key" ]] || die "TLS private key is missing, empty, or a symlink"
[[ -f "$DEPLOY_ROOT/.env" && ! -L "$DEPLOY_ROOT/.env" ]] || die "deployment payload requires a regular .env"
[[ -f "$DEPLOY_ROOT/compose.yaml" && ! -L "$DEPLOY_ROOT/compose.yaml" ]] || die "deployment payload requires a regular compose.yaml"
python3 "$SCRIPT_DIR/lib/deployment_validation.py" --production \
  --compose "$DEPLOY_ROOT/compose.yaml" --config "$CONFIG_ROOT/config.yaml" --env "$DEPLOY_ROOT/.env"

config_sources=("$CONFIG_ROOT/config.yaml" "$CONFIG_ROOT/tls")
systemd_members=()
systemd_sources=()
for unit in filebrowser-enterprise.service filebrowser-enterprise-backup.service filebrowser-enterprise-backup.timer; do
  [[ -f "/etc/systemd/system/$unit" && ! -L "/etc/systemd/system/$unit" ]] ||
    die "required systemd unit is missing or unsafe: /etc/systemd/system/$unit"
  systemd_members+=("$unit")
  systemd_sources+=("/etc/systemd/system/$unit")
done

database_allocated=$(path_allocated_bytes "$DATA_ROOT/database.db")
config_allocated=$(path_allocated_bytes "${config_sources[@]}")
secrets_allocated=$(path_allocated_bytes "$CONFIG_ROOT/secrets")
files_allocated=$(path_allocated_bytes "$FILES_ROOT")
deployment_allocated=$(path_allocated_bytes "$DEPLOY_ROOT")
systemd_allocated=$(path_allocated_bytes "${systemd_sources[@]}")
for bytes in "$database_allocated" "$config_allocated" "$secrets_allocated" "$files_allocated" "$deployment_allocated" "$systemd_allocated"; do
  validate_byte_count "$bytes" backup_source_bytes
done
estimated_archive_bytes=$(( database_allocated + config_allocated + secrets_allocated + files_allocated + deployment_allocated + systemd_allocated ))
validate_byte_count "$estimated_archive_bytes" backup_estimated_archive_bytes
required_backup_bytes=$(space_with_margin "$estimated_archive_bytes" 15 64)
require_filesystem_space backup "$BACKUP_ROOT" "$required_backup_bytes"
log "backup destination space preflight passed for $required_backup_bytes bytes"

APP_WAS_RUNNING=false
NGINX_WAS_RUNNING=false
service_is_running filebrowser-enterprise && APP_WAS_RUNNING=true
service_is_running nginx && NGINX_WAS_RUNNING=true

if [[ "$APP_WAS_RUNNING" == true ]]; then
  APP_CONTAINER_ID=$(service_container_id filebrowser-enterprise)
  [[ -n "$APP_CONTAINER_ID" ]] || die "running FileBrowser container ID could not be captured"
  CAPTURED_VERSION=$(compose exec -T filebrowser-enterprise /home/filebrowser/filebrowser version 2>/dev/null | tr '\r\n\t' '   ' | sed 's/[[:space:]][[:space:]]*/ /g' || true)
  CAPTURED_VERSION=${CAPTURED_VERSION:-unknown}
fi

if [[ "$NGINX_WAS_RUNNING" == true ]]; then
  log "stopping Nginx before the application"
  compose stop --timeout 30 nginx
fi
if [[ "$APP_WAS_RUNNING" == true ]]; then
  log "gracefully stopping FileBrowser before copying Bolt and business data"
  compose stop --timeout 60 filebrowser-enterprise
fi
assert_no_running nginx
assert_no_running filebrowser-enterprise

if [[ "$APP_WAS_RUNNING" == true ]]; then
  exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$APP_CONTAINER_ID")
  [[ "$exit_code" == 0 ]] || die "FileBrowser did not exit cleanly (exit code $exit_code); refusing backup"
fi
if fuser -s -- "$DATA_ROOT/database.db"; then
  die "database.db is still open after the managed FileBrowser stopped; refuse a potentially inconsistent Bolt backup"
fi

timestamp=$(date -u +'%Y%m%dT%H%M%SZ')
snapshot_id="backup-$timestamp-$$"
STAGE_DIR="$BACKUP_ROOT/.$snapshot_id.incomplete"
FINAL_DIR="$BACKUP_ROOT/$snapshot_id"
[[ ! -e "$STAGE_DIR" && ! -e "$FINAL_DIR" ]] || die "backup destination already exists"
mkdir -m 0700 -- "$STAGE_DIR" "$STAGE_DIR/payload"

log "archiving consistent database, configuration, secrets, business files, and deployment assets"
tar --sparse --acls --xattrs --numeric-owner -C "$DATA_ROOT" -cpf "$STAGE_DIR/payload/database.tar" database.db

config_members=(config.yaml tls)
tar --sparse --acls --xattrs --numeric-owner -C "$CONFIG_ROOT" -cpf "$STAGE_DIR/payload/config.tar" "${config_members[@]}"
tar --sparse --acls --xattrs --numeric-owner -C "$CONFIG_ROOT" -cpf "$STAGE_DIR/payload/secrets.tar" secrets

files_parent=$(dirname -- "$FILES_ROOT")
files_name=$(basename -- "$FILES_ROOT")
tar --sparse --acls --xattrs --numeric-owner -C "$files_parent" -cpf "$STAGE_DIR/payload/files.tar" "$files_name"

deploy_parent=$(dirname -- "$DEPLOY_ROOT")
deploy_name=$(basename -- "$DEPLOY_ROOT")
tar --sparse --acls --xattrs --numeric-owner -C "$deploy_parent" -cpf "$STAGE_DIR/payload/deployment.tar" "$deploy_name"

tar --sparse --acls --xattrs --numeric-owner -C /etc/systemd/system -cpf "$STAGE_DIR/payload/systemd.tar" "${systemd_members[@]}"

python3 "$SCRIPT_DIR/lib/deployment_validation.py" --tar "$STAGE_DIR/payload/database.tar" --prefix database.db
python3 "$SCRIPT_DIR/lib/deployment_validation.py" --tar "$STAGE_DIR/payload/config.tar" --prefix config.yaml --prefix tls
python3 "$SCRIPT_DIR/lib/deployment_validation.py" --tar "$STAGE_DIR/payload/secrets.tar" --prefix secrets
python3 "$SCRIPT_DIR/lib/deployment_validation.py" --tar "$STAGE_DIR/payload/files.tar" --prefix "$files_name"
python3 "$SCRIPT_DIR/lib/deployment_validation.py" --tar "$STAGE_DIR/payload/deployment.tar" --prefix "$deploy_name"
require_tar_regular_member "$STAGE_DIR/payload/database.tar" database.db
require_tar_regular_member "$STAGE_DIR/payload/config.tar" config.yaml
require_tar_regular_member "$STAGE_DIR/payload/config.tar" tls/tls.crt
require_tar_regular_member "$STAGE_DIR/payload/config.tar" tls/tls.key
require_tar_regular_member "$STAGE_DIR/payload/secrets.tar" secrets/jwt_token_secret
require_tar_regular_member "$STAGE_DIR/payload/secrets.tar" secrets/totp_secret
require_tar_regular_member "$STAGE_DIR/payload/deployment.tar" "$deploy_name/.env"
require_tar_regular_member "$STAGE_DIR/payload/deployment.tar" "$deploy_name/compose.yaml"
require_tar_regular_member "$STAGE_DIR/payload/deployment.tar" "$deploy_name/compose.maintenance.yaml"
require_tar_regular_member "$STAGE_DIR/payload/deployment.tar" "$deploy_name/nginx/filebrowser-maintenance.conf.template"
python3 "$SCRIPT_DIR/lib/deployment_validation.py" --tar "$STAGE_DIR/payload/systemd.tar" \
  --prefix filebrowser-enterprise.service \
  --prefix filebrowser-enterprise-backup.service \
  --prefix filebrowser-enterprise-backup.timer
for unit in "${systemd_members[@]}"; do
  require_tar_regular_member "$STAGE_DIR/payload/systemd.tar" "$unit"
done

source_image=$(env_get "$ENV_FILE" FILEBROWSER_IMAGE)
validate_internal_image "$source_image" FILEBROWSER_IMAGE "$ENV_FILE"
source_nginx_image=$(env_get "$ENV_FILE" NGINX_IMAGE)
validate_internal_image "$source_nginx_image" NGINX_IMAGE "$ENV_FILE"
image_id=$(docker image inspect --format '{{.Id}}' "$source_image") || die "FileBrowser image is not available locally: $source_image"
nginx_image_id=$(docker image inspect --format '{{.Id}}' "$source_nginx_image") || die "Nginx image is not available locally: $source_nginx_image"
source_git_sha=$(printf '%s' "$CAPTURED_VERSION" | sed -n 's/.*Commit[[:space:]]*:[[:space:]]*\([^[:space:]]*\).*/\1/p')
source_git_sha=${source_git_sha:-unknown}

database_logical_bytes=$(archive_logical_bytes "$STAGE_DIR/payload/database.tar")
database_archive_bytes=$(archive_file_bytes "$STAGE_DIR/payload/database.tar")
config_logical_bytes=$(archive_logical_bytes "$STAGE_DIR/payload/config.tar")
config_archive_bytes=$(archive_file_bytes "$STAGE_DIR/payload/config.tar")
secrets_logical_bytes=$(archive_logical_bytes "$STAGE_DIR/payload/secrets.tar")
secrets_archive_bytes=$(archive_file_bytes "$STAGE_DIR/payload/secrets.tar")
files_logical_bytes=$(archive_logical_bytes "$STAGE_DIR/payload/files.tar")
files_archive_bytes=$(archive_file_bytes "$STAGE_DIR/payload/files.tar")
deployment_logical_bytes=$(archive_logical_bytes "$STAGE_DIR/payload/deployment.tar")
deployment_archive_bytes=$(archive_file_bytes "$STAGE_DIR/payload/deployment.tar")
systemd_logical_bytes=$(archive_logical_bytes "$STAGE_DIR/payload/systemd.tar")
systemd_archive_bytes=$(archive_file_bytes "$STAGE_DIR/payload/systemd.tar")
for bytes in "$database_logical_bytes" "$database_archive_bytes" "$config_logical_bytes" "$config_archive_bytes" \
  "$secrets_logical_bytes" "$secrets_archive_bytes" "$files_logical_bytes" "$files_archive_bytes" \
  "$deployment_logical_bytes" "$deployment_archive_bytes" "$systemd_logical_bytes" "$systemd_archive_bytes"; do
  validate_byte_count "$bytes" backup_payload_bytes
done
total_logical_bytes=$(( database_logical_bytes + config_logical_bytes + secrets_logical_bytes + files_logical_bytes + deployment_logical_bytes + systemd_logical_bytes ))
total_archive_bytes=$(( database_archive_bytes + config_archive_bytes + secrets_archive_bytes + files_archive_bytes + deployment_archive_bytes + systemd_archive_bytes ))
validate_byte_count "$total_logical_bytes" total_logical_bytes
validate_byte_count "$total_archive_bytes" total_archive_bytes

cat >"$STAGE_DIR/manifest.tsv" <<EOF
format_version	1
deployment_schema	2
database_engine	storm-bbolt
database_schema	2
snapshot_id	$snapshot_id
created_utc	$(date -u +'%Y-%m-%dT%H:%M:%SZ')
reason	$REASON
source_image	$source_image
source_image_id	$image_id
source_nginx_image	$source_nginx_image
source_nginx_image_id	$nginx_image_id
source_git_sha	$source_git_sha
application_version	$CAPTURED_VERSION
compose_project_name	$COMPOSE_PROJECT_NAME_VALUE
internal_registry_host	$INTERNAL_REGISTRY_HOST_VALUE
deploy_root	$DEPLOY_ROOT
config_root	$CONFIG_ROOT
data_root	$DATA_ROOT
cache_root	$CACHE_ROOT
files_root	$FILES_ROOT
backup_root	$BACKUP_ROOT
database_path	$DATA_ROOT/database.db
files_path	$FILES_ROOT
database_logical_bytes	$database_logical_bytes
database_archive_bytes	$database_archive_bytes
config_logical_bytes	$config_logical_bytes
config_archive_bytes	$config_archive_bytes
secrets_logical_bytes	$secrets_logical_bytes
secrets_archive_bytes	$secrets_archive_bytes
files_logical_bytes	$files_logical_bytes
files_archive_bytes	$files_archive_bytes
deployment_logical_bytes	$deployment_logical_bytes
deployment_archive_bytes	$deployment_archive_bytes
systemd_logical_bytes	$systemd_logical_bytes
systemd_archive_bytes	$systemd_archive_bytes
total_logical_bytes	$total_logical_bytes
total_archive_bytes	$total_archive_bytes
cache_included	false
systemd_included	true
secrets_sensitivity	high
EOF

(
  cd -- "$STAGE_DIR"
  find payload -type f -print0 | sort -z | xargs -0 sha256sum
  sha256sum manifest.tsv
) >"$STAGE_DIR/checksums.sha256"
(
  cd -- "$STAGE_DIR"
  sha256sum -c checksums.sha256 >/dev/null
)

find "$STAGE_DIR" -type d -exec chmod 0700 {} +
find "$STAGE_DIR" -type f -exec chmod 0600 {} +
fsync_path "$STAGE_DIR/payload"
fsync_path "$STAGE_DIR/manifest.tsv"
fsync_path "$STAGE_DIR/checksums.sha256"
fsync_path "$STAGE_DIR"
fsync_parent "$STAGE_DIR"
durable_move "$STAGE_DIR" "$FINAL_DIR"
fsync_path "$BACKUP_ROOT"
STAGE_DIR=
BACKUP_COMPLETE=true

log "backup completed: $FINAL_DIR"
warn "this is a same-host local snapshot, not a final disaster-recovery copy; export it with approved Restic/Borg policy"
printf 'BACKUP_PATH=%s\n' "$FINAL_DIR"
