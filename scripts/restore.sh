#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=scripts/lib/deployment-common.sh
source "$SCRIPT_DIR/lib/deployment-common.sh"

BACKUP_PATH=
APPLY=false
RECOVER_INCOMPLETE=false
PRECURRENT_ROLLBACK_POINT=
EXPECTED_IMAGE=
RESTORE_SUCCESS=false
RESTORE_ID=
ROLLBACK_POINT=
ROLLBACK_FILEBROWSER_IMAGE=
ROLLBACK_NGINX_IMAGE=
PREFLIGHT_DIR=
DATABASE_STAGE=
DATABASE_NEW=
CONFIG_NEW=
FILES_NEW=
DEPLOY_NEW=
CACHE_NEW=
SYSTEMD_NEW=
declare -a SUCCESS_ORIGINALS=()

usage() {
  cat <<'USAGE'
Usage:
  restore.sh --backup PATH [--apply] [--expected-image IMAGE]
  restore.sh --recover-incomplete [--apply]

The default is non-mutating. Restore apply takes the global lifecycle lock before
reading backup state, requires the Compose stack to be stopped, validates a
matching rollback point, and starts Nginx only after FileBrowser is healthy.

Incomplete recovery defaults to a journal preview. Add --apply to roll the
filesystem transaction back, restore the recorded pre-restore image pins, and
progressively verify FileBrowser and Nginx before clearing the durable journal.
USAGE
}

require_option_value() {
  local option=$1 value=${2:-}
  [[ -n "$value" && "$value" != --* ]] || die "missing value for $option"
}

is_path_present() {
  [[ -e "$1" || -L "$1" ]]
}

remove_path_if_present() {
  local path=$1
  is_path_present "$path" || return 0
  rm -rf -- "$path"
  fsync_parent "$path"
}

cleanup_preflight() {
  [[ -z "$PREFLIGHT_DIR" || ! -d "$PREFLIGHT_DIR" ]] || rm -rf -- "$PREFLIGHT_DIR"
  PREFLIGHT_DIR=
}

cleanup_restore_staging() {
  [[ -n "$RESTORE_ID" ]] || return 0
  local expected
  for expected in "$DATABASE_STAGE" "$DATABASE_NEW" "$CONFIG_NEW" "$FILES_NEW" "$DEPLOY_NEW" "$CACHE_NEW" "$SYSTEMD_NEW"; do
    [[ -n "$expected" ]] || continue
    case "$expected" in
      *"$RESTORE_ID"*) remove_path_if_present "$expected" ;;
      *) die "refusing to remove an unexpected restore staging path: $expected" ;;
    esac
  done
}

cleanup_success_originals() {
  local index original
  for (( index=${#SUCCESS_ORIGINALS[@]}-1; index>=0; index-- )); do
    original=${SUCCESS_ORIGINALS[$index]}
    is_path_present "$original" || continue
    log "removing immediate pre-restore copy after validated commit: $original"
    if rm -rf -- "$original"; then
      fsync_parent "$original" || warn "failed to sync the parent after removing: $original"
    fi
  done
  for original in "${SUCCESS_ORIGINALS[@]}"; do
    is_path_present "$original" || continue
    warn "pre-restore path could not be removed and is retained: $original"
  done
}

backup_child_realpath() {
  local candidate=$1 label=$2 root_real candidate_real
  [[ -d "$candidate" && ! -L "$candidate" ]] || die "$label must be a real directory and not a symlink input"
  root_real=$(realpath -e -- "$BACKUP_ROOT")
  candidate_real=$(realpath -e -- "$candidate")
  case "$candidate_real/" in
    "$root_real"/*) ;;
    *) die "$label must be a child of $root_real" ;;
  esac
  [[ -d "$candidate_real" && ! -L "$candidate_real" ]] || die "$label must be a real directory"
  printf '%s' "$candidate_real"
}

journal_backup_path() {
  local candidate=$1 label=$2
  validate_absolute_path "$candidate" "$label"
  case "$candidate/" in
    "$BACKUP_ROOT"/backup-*/) ;;
    *) die "$label is outside the recorded backup root or has an invalid snapshot name" ;;
  esac
  if [[ ! -d "$candidate" || -L "$candidate" ]]; then
    warn "$label is currently unavailable; local sibling rollback will continue: $candidate"
  fi
  printf '%s' "$candidate"
}

validate_staged_tls() {
  local config_root=$1 env_file=$2 cert key host cert_pub key_pub
  cert="$config_root/tls/tls.crt"
  key="$config_root/tls/tls.key"
  [[ -s "$cert" && ! -L "$cert" ]] || die "staged TLS certificate is missing, empty, or unsafe"
  [[ -s "$key" && ! -L "$key" ]] || die "staged TLS private key is missing, empty, or unsafe"
  host=$(env_get "$env_file" PUBLIC_HOST)
  openssl x509 -in "$cert" -noout -checkend 86400 >/dev/null ||
    die "staged TLS certificate is invalid or expires within 24 hours"
  openssl x509 -in "$cert" -noout -checkhost "$host" >/dev/null ||
    die "staged TLS certificate does not cover PUBLIC_HOST"
  openssl verify -purpose sslserver -verify_hostname "$host" -untrusted "$cert" "$cert" >/dev/null ||
    die "staged TLS certificate chain is not trusted by the host system trust store"
  cert_pub=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  key_pub=$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || die "staged TLS certificate and private key do not match"
}

manifest_required() {
  local manifest=$1 key=$2 value
  value=$(manifest_get "$manifest" "$key") || die "manifest $key is missing or duplicated"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* ]] ||
    die "manifest $key contains unsupported control whitespace"
  printf '%s' "$value"
}

compare_manifest_root() {
  local manifest=$1 key=$2 current=$3 value
  value=$(manifest_required "$manifest" "$key")
  validate_absolute_path "$value" "manifest $key"
  [[ "$value" == "$current" ]] || die "manifest $key does not match the current deployment: $value != $current"
}

compare_archived_environment() {
  local archived_env=$1 manifest=$2 archived manifest_value
  compare_one() {
    local key=$1 manifest_key=$2 expected=$3
    archived=$(env_get "$archived_env" "$key")
    manifest_value=$(manifest_required "$manifest" "$manifest_key")
    [[ "$archived" == "$manifest_value" && "$archived" == "$expected" ]] ||
      die "archived $key, manifest $manifest_key, and the current deployment disagree"
  }
  compare_one DEPLOY_ROOT deploy_root "$DEPLOY_ROOT"
  compare_one CONFIG_ROOT config_root "$CONFIG_ROOT"
  compare_one DATA_ROOT data_root "$DATA_ROOT"
  compare_one CACHE_ROOT cache_root "$CACHE_ROOT"
  compare_one FILES_ROOT files_root "$FILES_ROOT"
  compare_one BACKUP_ROOT backup_root "$BACKUP_ROOT"
  compare_one COMPOSE_PROJECT_NAME compose_project_name filebrowser-enterprise
  compare_one INTERNAL_REGISTRY_HOST internal_registry_host "$(env_get "$ENV_FILE" INTERNAL_REGISTRY_HOST)"
  compare_one FILEBROWSER_IMAGE source_image "$SOURCE_IMAGE"
  compare_one NGINX_IMAGE source_nginx_image "$SOURCE_NGINX_IMAGE"
  unset -f compare_one
}

validate_payload_metric() {
  local manifest=$1 label=$2 archive=$3 logical archive_bytes expected_logical expected_archive
  expected_logical=$(manifest_required "$manifest" "${label}_logical_bytes")
  expected_archive=$(manifest_required "$manifest" "${label}_archive_bytes")
  validate_byte_count "$expected_logical" "manifest ${label}_logical_bytes"
  validate_byte_count "$expected_archive" "manifest ${label}_archive_bytes"
  logical=$(archive_logical_bytes "$archive")
  archive_bytes=$(archive_file_bytes "$archive")
  validate_byte_count "$logical" "actual ${label}_logical_bytes"
  validate_byte_count "$archive_bytes" "actual ${label}_archive_bytes"
  [[ "$logical" == "$expected_logical" ]] || die "$label logical byte count does not match its manifest"
  [[ "$archive_bytes" == "$expected_archive" ]] || die "$label archive byte count does not match its manifest"
  printf -v "${label}_logical_bytes" '%s' "$logical"
  printf -v "${label}_archive_bytes" '%s' "$archive_bytes"
}

validate_backup_bundle() {
  (( $# == 7 )) || die "validate_backup_bundle requires a backup path and six archive-byte outputs"
  local backup=$1 manifest checksum_file payload archive checksum member extra member_path owner mode links
  local database_archive_bytes_out=$2 config_archive_bytes_out=$3 secrets_archive_bytes_out=$4
  local files_archive_bytes_out=$5 deployment_archive_bytes_out=$6 systemd_archive_bytes_out=$7
  local format_version deployment_schema database_engine database_schema compatibility_image
  local files_prefix deployment_prefix
  local database_logical_bytes=0 config_logical_bytes=0 secrets_logical_bytes=0
  local files_logical_bytes=0 deployment_logical_bytes=0 systemd_logical_bytes=0
  local database_archive_bytes=0 config_archive_bytes=0 secrets_archive_bytes=0
  local files_archive_bytes=0 deployment_archive_bytes=0 systemd_archive_bytes=0
  local total_logical_bytes=0 total_archive_bytes=0

  manifest="$backup/manifest.tsv"
  checksum_file="$backup/checksums.sha256"
  [[ -f "$manifest" && ! -L "$manifest" ]] || die "manifest is missing or unsafe"
  [[ -f "$checksum_file" && ! -L "$checksum_file" ]] || die "checksum file is missing or unsafe"
  [[ -z $(find "$backup" -type l -print -quit) ]] || die "backup bundle must not contain symbolic links"

  while read -r checksum member extra; do
    [[ -n "$checksum" && -n "$member" && -z ${extra:-} ]] || die "malformed checksum entry"
    [[ "$checksum" =~ ^[0-9a-fA-F]{64}$ ]] || die "malformed SHA-256 value"
    [[ "$member" != /* && "/$member/" != *'/../'* ]] || die "unsafe checksum member: $member"
    [[ -f "$backup/$member" && ! -L "$backup/$member" ]] || die "checksummed member is missing or unsafe: $member"
  done <"$checksum_file"
  (
    cd -- "$backup"
    sha256sum -c checksums.sha256
  )

  for member_path in "$BACKUP_ROOT" "$backup"; do
    owner=$(stat -c '%u' "$member_path")
    mode=$(stat -c '%a' "$member_path")
    if [[ "$owner" != 0 ]] || (( (8#$mode & 0022) != 0 )); then
      die "backup path must be root-owned and not writable by group or other: $member_path"
    fi
  done
  while IFS= read -r -d '' member_path; do
    owner=$(stat -c '%u' "$member_path")
    mode=$(stat -c '%a' "$member_path")
    if [[ "$owner" != 0 ]] || (( (8#$mode & 0022) != 0 )); then
      die "backup member must be root-owned and not writable by group or other: $member_path"
    fi
    if [[ -f "$member_path" ]]; then
      links=$(stat -c '%h' "$member_path")
      [[ "$links" == 1 ]] || die "hard-linked backup members are forbidden: $member_path"
    fi
  done < <(find "$backup" -mindepth 1 -print0)

  format_version=$(manifest_required "$manifest" format_version)
  deployment_schema=$(manifest_required "$manifest" deployment_schema)
  database_engine=$(manifest_required "$manifest" database_engine)
  database_schema=$(manifest_required "$manifest" database_schema)
  [[ "$format_version" == 1 && "$deployment_schema" == 2 ]] || die "unsupported backup/deployment manifest version"
  [[ "$database_engine" == storm-bbolt && "$database_schema" == 2 ]] || die "unsupported database engine or schema"
  [[ $(manifest_required "$manifest" compose_project_name) == filebrowser-enterprise ]] ||
    die "backup Compose project name is incompatible"

  SOURCE_IMAGE=$(manifest_required "$manifest" source_image)
  SOURCE_NGINX_IMAGE=$(manifest_required "$manifest" source_nginx_image)
  [[ $(manifest_required "$manifest" internal_registry_host) == $(env_get "$ENV_FILE" INTERNAL_REGISTRY_HOST) ]] ||
    die "backup internal registry host does not match the current deployment"
  validate_internal_image "$SOURCE_IMAGE" manifest_source_image "$ENV_FILE"
  validate_internal_image "$SOURCE_NGINX_IMAGE" manifest_source_nginx_image "$ENV_FILE"
  CURRENT_IMAGE=$(env_get "$ENV_FILE" FILEBROWSER_IMAGE)
  CURRENT_NGINX_IMAGE=$(env_get "$ENV_FILE" NGINX_IMAGE)
  [[ $(env_get "$ENV_FILE" COMPOSE_PROJECT_NAME) == filebrowser-enterprise ]] ||
    die "current COMPOSE_PROJECT_NAME must be filebrowser-enterprise"
  validate_internal_image "$CURRENT_IMAGE" FILEBROWSER_IMAGE "$ENV_FILE"
  validate_internal_image "$CURRENT_NGINX_IMAGE" NGINX_IMAGE "$ENV_FILE"
  compatibility_image=${EXPECTED_IMAGE:-$CURRENT_IMAGE}
  validate_internal_image "$compatibility_image" expected_image "$ENV_FILE"
  [[ "$compatibility_image" == "$SOURCE_IMAGE" ]] || die "expected image does not match the backup source image"
  if [[ "$APPLY" == true && "$CURRENT_IMAGE" != "$SOURCE_IMAGE" ]]; then
    [[ -n "$PRECURRENT_ROLLBACK_POINT" && ${FILEBROWSER_ALLOW_PRECREATED_ROLLBACK:-0} == 1 \
      && -n ${FILEBROWSER_ACTIVE_TRANSACTION_STATE:-} ]] ||
      die "configured FileBrowser image must match the backup before apply"
  elif [[ -z "$EXPECTED_IMAGE" && "$CURRENT_IMAGE" != "$SOURCE_IMAGE" ]]; then
    die "configured image does not match the backup; use rollback.sh to restore image and database together"
  fi
  [[ "$CURRENT_NGINX_IMAGE" == "$SOURCE_NGINX_IMAGE" ]] || die "configured Nginx image does not match the backup source image"

  compare_manifest_root "$manifest" deploy_root "$DEPLOY_ROOT"
  compare_manifest_root "$manifest" config_root "$CONFIG_ROOT"
  compare_manifest_root "$manifest" data_root "$DATA_ROOT"
  compare_manifest_root "$manifest" cache_root "$CACHE_ROOT"
  compare_manifest_root "$manifest" files_root "$FILES_ROOT"
  compare_manifest_root "$manifest" backup_root "$BACKUP_ROOT"
  [[ $(manifest_required "$manifest" database_path) == "$DATA_ROOT/database.db" ]] ||
    die "backup database target does not match this deployment"
  [[ $(manifest_required "$manifest" files_path) == "$FILES_ROOT" ]] ||
    die "backup files target does not match this deployment"

  [[ $(manifest_required "$manifest" systemd_included) == true ]] || die "schema-2 backup must include systemd units"
  required_payloads=(database.tar config.tar secrets.tar files.tar deployment.tar systemd.tar)
  grep -Eq '^[0-9a-fA-F]{64}[[:space:]]+manifest\.tsv$' "$checksum_file" || die "manifest is not covered by checksums"
  for payload in "${required_payloads[@]}"; do
    archive="$backup/payload/$payload"
    [[ -f "$archive" && ! -L "$archive" ]] || die "required payload is missing: $payload"
    grep -Eq "^[0-9a-fA-F]{64}[[:space:]]+payload/${payload}$" "$checksum_file" ||
      die "required payload is not covered by checksums: $payload"
    safe_tar_members "$archive" || die "unsafe path found in payload: $payload"
  done
  files_prefix=$(basename -- "$FILES_ROOT")
  deployment_prefix=$(basename -- "$DEPLOY_ROOT")
  python3 "$SCRIPT_DIR/lib/deployment_validation.py" --tar "$backup/payload/database.tar" --prefix database.db
  python3 "$SCRIPT_DIR/lib/deployment_validation.py" --tar "$backup/payload/config.tar" --prefix config.yaml --prefix tls
  python3 "$SCRIPT_DIR/lib/deployment_validation.py" --tar "$backup/payload/secrets.tar" --prefix secrets
  python3 "$SCRIPT_DIR/lib/deployment_validation.py" --tar "$backup/payload/files.tar" --prefix "$files_prefix"
  python3 "$SCRIPT_DIR/lib/deployment_validation.py" --tar "$backup/payload/deployment.tar" --prefix "$deployment_prefix"
  require_tar_regular_member "$backup/payload/database.tar" database.db
  require_tar_regular_member "$backup/payload/config.tar" config.yaml
  require_tar_regular_member "$backup/payload/config.tar" tls/tls.crt
  require_tar_regular_member "$backup/payload/config.tar" tls/tls.key
  require_tar_regular_member "$backup/payload/deployment.tar" "$deployment_prefix/.env"
  require_tar_regular_member "$backup/payload/deployment.tar" "$deployment_prefix/compose.yaml"
  require_tar_regular_member "$backup/payload/deployment.tar" "$deployment_prefix/compose.maintenance.yaml"
  require_tar_regular_member "$backup/payload/deployment.tar" "$deployment_prefix/nginx/filebrowser-maintenance.conf.template"
  python3 "$SCRIPT_DIR/lib/deployment_validation.py" --tar "$backup/payload/systemd.tar" \
    --prefix filebrowser-enterprise.service \
    --prefix filebrowser-enterprise-backup.service \
    --prefix filebrowser-enterprise-backup.timer
  for unit in filebrowser-enterprise.service filebrowser-enterprise-backup.service filebrowser-enterprise-backup.timer; do
    require_tar_regular_member "$backup/payload/systemd.tar" "$unit"
  done

  validate_payload_metric "$manifest" database "$backup/payload/database.tar"
  validate_payload_metric "$manifest" config "$backup/payload/config.tar"
  validate_payload_metric "$manifest" secrets "$backup/payload/secrets.tar"
  validate_payload_metric "$manifest" files "$backup/payload/files.tar"
  validate_payload_metric "$manifest" deployment "$backup/payload/deployment.tar"
  validate_payload_metric "$manifest" systemd "$backup/payload/systemd.tar"

  total_logical_bytes=$(( database_logical_bytes + config_logical_bytes + secrets_logical_bytes + files_logical_bytes + deployment_logical_bytes + systemd_logical_bytes ))
  total_archive_bytes=$(( database_archive_bytes + config_archive_bytes + secrets_archive_bytes + files_archive_bytes + deployment_archive_bytes + systemd_archive_bytes ))
  validate_byte_count "$total_logical_bytes" total_logical_bytes
  validate_byte_count "$total_archive_bytes" total_archive_bytes
  [[ $(manifest_required "$manifest" total_logical_bytes) == "$total_logical_bytes" ]] || die "total logical bytes do not match the manifest"
  [[ $(manifest_required "$manifest" total_archive_bytes) == "$total_archive_bytes" ]] || die "total archive bytes do not match the manifest"

  PREFLIGHT_DIR=$(mktemp -d "/tmp/filebrowser-restore-preflight.XXXXXX")
  chmod 0700 "$PREFLIGHT_DIR"
  mkdir -m 0700 -- "$PREFLIGHT_DIR/deployment" "$PREFLIGHT_DIR/config" "$PREFLIGHT_DIR/secrets"
  tar --sparse --no-same-owner --no-same-permissions --strip-components=1 \
    -C "$PREFLIGHT_DIR/deployment" -xpf "$backup/payload/deployment.tar"
  tar --sparse --no-same-owner --no-same-permissions \
    -C "$PREFLIGHT_DIR/config" -xpf "$backup/payload/config.tar"
  tar --sparse --no-same-owner --no-same-permissions --strip-components=1 \
    -C "$PREFLIGHT_DIR/secrets" -xpf "$backup/payload/secrets.tar"
  [[ -f "$PREFLIGHT_DIR/deployment/.env" && ! -L "$PREFLIGHT_DIR/deployment/.env" ]] ||
    die "archived deployment .env is not a regular file"
  [[ -f "$PREFLIGHT_DIR/deployment/compose.yaml" && ! -L "$PREFLIGHT_DIR/deployment/compose.yaml" ]] ||
    die "archived deployment compose.yaml is not a regular file"
  [[ -f "$PREFLIGHT_DIR/config/config.yaml" && ! -L "$PREFLIGHT_DIR/config/config.yaml" ]] ||
    die "archived production config is not a regular file"
  for secret_name in jwt_token_secret totp_secret; do
    [[ -s "$PREFLIGHT_DIR/secrets/$secret_name" && ! -L "$PREFLIGHT_DIR/secrets/$secret_name" ]] ||
      die "archived stable secret is missing, empty, or unsafe: $secret_name"
  done
  for transient_name in bootstrap_admin_password emergency_admin_password bootstrap_admin_password.recovery emergency_admin_password.recovery; do
    [[ ! -e "$PREFLIGHT_DIR/secrets/$transient_name" && ! -L "$PREFLIGHT_DIR/secrets/$transient_name" ]] ||
      die "archived secrets contain forbidden transient state: $transient_name"
  done
  compare_archived_environment "$PREFLIGHT_DIR/deployment/.env" "$manifest"
  validate_staged_tls "$PREFLIGHT_DIR/config" "$PREFLIGHT_DIR/deployment/.env"
  python3 "$SCRIPT_DIR/lib/deployment_validation.py" --production \
    --compose "$PREFLIGHT_DIR/deployment/compose.yaml" \
    --config "$PREFLIGHT_DIR/config/config.yaml" \
    --env "$PREFLIGHT_DIR/deployment/.env"
  cleanup_preflight

  printf -v "$database_archive_bytes_out" '%s' "$database_archive_bytes"
  printf -v "$config_archive_bytes_out" '%s' "$config_archive_bytes"
  printf -v "$secrets_archive_bytes_out" '%s' "$secrets_archive_bytes"
  printf -v "$files_archive_bytes_out" '%s' "$files_archive_bytes"
  printf -v "$deployment_archive_bytes_out" '%s' "$deployment_archive_bytes"
  printf -v "$systemd_archive_bytes_out" '%s' "$systemd_archive_bytes"
}

journal_required() {
  manifest_required "$FILEBROWSER_RESTORE_JOURNAL" "$1"
}

load_recovery_layout() {
  local canonical_deploy original_deploy candidate_env candidate_compose
  [[ -f "$FILEBROWSER_RESTORE_JOURNAL" && ! -L "$FILEBROWSER_RESTORE_JOURNAL" ]] ||
    die "no safe incomplete restore journal exists at $FILEBROWSER_RESTORE_JOURNAL"
  [[ $(stat -c '%u:%g:%a' "$FILEBROWSER_RESTORE_JOURNAL") == 0:0:600 ]] ||
    die "restore journal must be owned by root:root with mode 0600"
  [[ $(journal_required format_version) == 1 ]] || die "unsupported restore journal version"
  RESTORE_ID=$(journal_required restore_id)
  [[ "$RESTORE_ID" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || die "restore journal ID is invalid"

  canonical_deploy=${DEPLOY_ROOT:-/opt/filebrowser-enterprise}
  validate_absolute_path "$canonical_deploy" DEPLOY_ROOT
  [[ $(journal_required deploy_root) == "$canonical_deploy" ]] || die "restore journal deploy_root does not match the requested deployment"
  original_deploy="${canonical_deploy}.pre-restore-$RESTORE_ID"
  if [[ -f "$original_deploy/.env" && ! -L "$original_deploy/.env" && -f "$original_deploy/compose.yaml" && ! -L "$original_deploy/compose.yaml" ]]; then
    candidate_env="$original_deploy/.env"
    candidate_compose="$original_deploy/compose.yaml"
  elif [[ -f "$canonical_deploy/.env" && ! -L "$canonical_deploy/.env" && -f "$canonical_deploy/compose.yaml" && ! -L "$canonical_deploy/compose.yaml" ]]; then
    candidate_env="$canonical_deploy/.env"
    candidate_compose="$canonical_deploy/compose.yaml"
  else
    die "neither the current nor pre-restore deployment contains a safe .env and compose.yaml"
  fi

  DEPLOY_ROOT=$canonical_deploy
  ENV_FILE=$candidate_env
  COMPOSE_FILE=$candidate_compose
  deployment_init_layout
  if [[ -d "$LOCK_ROOT" && ! -L "$LOCK_ROOT" ]]; then
    assert_non_nested_target_paths "$DEPLOY_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$CACHE_ROOT" "$FILES_ROOT" "$BACKUP_ROOT" \
      "$FILEBROWSER_LIFECYCLE_STATE_ROOT" "$LOCK_ROOT" /etc/systemd/system
  else
    assert_non_nested_target_paths "$DEPLOY_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$CACHE_ROOT" "$FILES_ROOT" "$BACKUP_ROOT" \
      "$FILEBROWSER_LIFECYCLE_STATE_ROOT" /etc/systemd/system
  fi
  compare_manifest_root "$FILEBROWSER_RESTORE_JOURNAL" deploy_root "$DEPLOY_ROOT"
  compare_manifest_root "$FILEBROWSER_RESTORE_JOURNAL" config_root "$CONFIG_ROOT"
  compare_manifest_root "$FILEBROWSER_RESTORE_JOURNAL" data_root "$DATA_ROOT"
  compare_manifest_root "$FILEBROWSER_RESTORE_JOURNAL" cache_root "$CACHE_ROOT"
  compare_manifest_root "$FILEBROWSER_RESTORE_JOURNAL" files_root "$FILES_ROOT"
  compare_manifest_root "$FILEBROWSER_RESTORE_JOURNAL" backup_root "$BACKUP_ROOT"
}

validate_journal_swap() {
  local index=$1 target original replacement failed original_exists reverted
  local expected_original expected_replacement expected_failed unit_name
  target=$(journal_required "swap_${index}_target")
  original=$(journal_required "swap_${index}_original")
  replacement=$(journal_required "swap_${index}_replacement")
  failed=$(journal_required "swap_${index}_failed")
  original_exists=$(journal_required "swap_${index}_original_exists")
  reverted=$(journal_required "swap_${index}_reverted")
  [[ "$original_exists" == true || "$original_exists" == false ]] || die "journal swap $index has an invalid original_exists flag"
  [[ "$reverted" == true || "$reverted" == false ]] || die "journal swap $index has an invalid reverted flag"

  case "$target" in
    "$DATA_ROOT/database.db")
      [[ "$original_exists" == true ]] || die "database journal entry must record an original"
      expected_replacement="$DATA_ROOT/database.db.restore-new-$RESTORE_ID"
      ;;
    "$CONFIG_ROOT")
      [[ "$original_exists" == true ]] || die "config journal entry must record an original"
      expected_replacement="${CONFIG_ROOT}.restore-new-$RESTORE_ID"
      ;;
    "$FILES_ROOT")
      [[ "$original_exists" == true ]] || die "files journal entry must record an original"
      expected_replacement="${FILES_ROOT}.restore-new-$RESTORE_ID"
      ;;
    "$CACHE_ROOT")
      [[ "$original_exists" == true ]] || die "cache journal entry must record an original"
      expected_replacement="${CACHE_ROOT}.restore-new-$RESTORE_ID"
      ;;
    "$DEPLOY_ROOT")
      [[ "$original_exists" == true ]] || die "deployment journal entry must record an original"
      expected_replacement="${DEPLOY_ROOT}.restore-new-$RESTORE_ID"
      ;;
    /etc/systemd/system/filebrowser-enterprise.service|\
    /etc/systemd/system/filebrowser-enterprise-backup.service|\
    /etc/systemd/system/filebrowser-enterprise-backup.timer)
      unit_name=$(basename -- "$target")
      expected_replacement="/etc/systemd/system/.filebrowser-restore-$RESTORE_ID/$unit_name"
      ;;
    *) die "journal swap $index targets a path outside the restore allowlist: $target" ;;
  esac
  if [[ "$original_exists" == true ]]; then
    expected_original="${target}.pre-restore-$RESTORE_ID"
  else
    expected_original="${target}.absent-pre-restore-$RESTORE_ID"
  fi
  expected_failed="${target}.failed-restore-$RESTORE_ID"
  [[ "$original" == "$expected_original" ]] || die "journal swap $index has an unexpected original path"
  [[ "$replacement" == "$expected_replacement" ]] || die "journal swap $index has an unexpected replacement path"
  [[ "$failed" == "$expected_failed" ]] || die "journal swap $index has an unexpected failed path"

  printf -v "journal_${index}_target" '%s' "$target"
  printf -v "journal_${index}_original" '%s' "$original"
  printf -v "journal_${index}_replacement" '%s' "$replacement"
  printf -v "journal_${index}_failed" '%s' "$failed"
  printf -v "journal_${index}_original_exists" '%s' "$original_exists"
  printf -v "journal_${index}_reverted" '%s' "$reverted"
}

load_and_validate_journal() {
  local status count index target
  declare -A seen_targets=()
  load_recovery_layout
  status=$(journal_required status)
  [[ "$status" == prepared || "$status" == swapping || "$status" == validating || "$status" == reverting ]] ||
    die "restore journal status is invalid: $status"
  count=$(journal_required swap_count)
  [[ "$count" == 0 || "$count" =~ ^[1-8]$ ]] || die "restore journal swap_count is invalid"
  JOURNAL_SWAP_COUNT=$count
  ROLLBACK_POINT=$(journal_backup_path "$(journal_required rollback_point)" "journal rollback point")
  journal_backup_path "$(journal_required backup_path)" "journal source backup" >/dev/null
  ROLLBACK_FILEBROWSER_IMAGE=$(journal_required rollback_filebrowser_image)
  ROLLBACK_NGINX_IMAGE=$(journal_required rollback_nginx_image)
  validate_internal_image "$ROLLBACK_FILEBROWSER_IMAGE" rollback_filebrowser_image "$ENV_FILE"
  validate_internal_image "$ROLLBACK_NGINX_IMAGE" rollback_nginx_image "$ENV_FILE"
  for (( index=1; index<=count; index++ )); do
    validate_journal_swap "$index"
    target_var="journal_${index}_target"
    target=${!target_var}
    [[ -z ${seen_targets[$target]:-} ]] || die "restore journal contains a duplicate target: $target"
    seen_targets[$target]=true
  done
}

preview_incomplete_restore() {
  local index target_var original_var replacement_var target original replacement
  load_and_validate_journal
  log "incomplete restore journal: $FILEBROWSER_RESTORE_JOURNAL"
  log "restore ID: $RESTORE_ID; registered swaps: $JOURNAL_SWAP_COUNT"
  log "durable pre-restore backup: $ROLLBACK_POINT"
  for (( index=JOURNAL_SWAP_COUNT; index>=1; index-- )); do
    target_var="journal_${index}_target"
    original_var="journal_${index}_original"
    replacement_var="journal_${index}_replacement"
    target=${!target_var}
    original=${!original_var}
    replacement=${!replacement_var}
    printf 'ROLLBACK[%s] target=%s target_present=%s original_present=%s replacement_present=%s\n' \
      "$index" "$target" "$(is_path_present "$target" && printf true || printf false)" \
      "$(is_path_present "$original" && printf true || printf false)" \
      "$(is_path_present "$replacement" && printf true || printf false)"
  done
  log "preview complete; rerun with --recover-incomplete --apply to roll back"
}

recover_registered_swap() {
  local index=$1 target_var original_var replacement_var failed_var exists_var reverted_var
  local target original replacement failed original_exists reverted
  target_var="journal_${index}_target"
  original_var="journal_${index}_original"
  replacement_var="journal_${index}_replacement"
  failed_var="journal_${index}_failed"
  exists_var="journal_${index}_original_exists"
  reverted_var="journal_${index}_reverted"
  target=${!target_var}
  original=${!original_var}
  replacement=${!replacement_var}
  failed=${!failed_var}
  original_exists=${!exists_var}
  reverted=${!reverted_var}

  if [[ "$reverted" == true ]]; then
    is_path_present "$original" && die "already-reverted journal swap $index unexpectedly retains its original path"
    if [[ "$original_exists" == true ]]; then
      is_path_present "$target" || die "already-reverted journal swap $index is missing its restored target"
    else
      is_path_present "$target" && die "already-reverted journal swap $index recreated an originally absent target"
    fi
    return 0
  fi

  if [[ "$original_exists" == true ]]; then
    if is_path_present "$original"; then
      if is_path_present "$target"; then
        is_path_present "$failed" && die "cannot preserve failed restore path because it already exists: $failed"
        durable_move "$target" "$failed"
        warn "failed restored candidate retained for inspection: $failed"
      elif ! is_path_present "$failed" && ! is_path_present "$replacement"; then
        die "journal swap $index has lost both its target and replacement"
      fi
      durable_move "$original" "$target"
    elif is_path_present "$failed"; then
      is_path_present "$target" || die "journal swap $index is missing the already-reverted target"
    else
      is_path_present "$target" || die "journal swap $index is missing its untouched original target"
      is_path_present "$replacement" || die "journal swap $index cannot distinguish an untouched target from a corrupt transaction"
    fi
    is_path_present "$target" || die "journal swap $index did not restore its original target"
  else
    is_path_present "$original" && die "absent-original marker unexpectedly exists: $original"
    if is_path_present "$target"; then
      is_path_present "$failed" && die "failed restore path already exists for newly created target: $failed"
      durable_move "$target" "$failed"
      warn "failed restored candidate retained for inspection: $failed"
    fi
    is_path_present "$target" && die "journal swap $index did not remove a newly created target"
  fi
  durable_tsv_set "$FILEBROWSER_RESTORE_JOURNAL" "swap_${index}_reverted" true
}

remove_transaction_staging_from_journal() {
  local index replacement_var replacement
  for (( index=1; index<=JOURNAL_SWAP_COUNT; index++ )); do
    replacement_var="journal_${index}_replacement"
    replacement=${!replacement_var}
    remove_path_if_present "$replacement"
  done
  remove_path_if_present "$DATA_ROOT/.restore-database-$RESTORE_ID"
  remove_path_if_present "$DATA_ROOT/database.db.restore-new-$RESTORE_ID"
  remove_path_if_present "${CONFIG_ROOT}.restore-new-$RESTORE_ID"
  remove_path_if_present "${FILES_ROOT}.restore-new-$RESTORE_ID"
  remove_path_if_present "${DEPLOY_ROOT}.restore-new-$RESTORE_ID"
  remove_path_if_present "${CACHE_ROOT}.restore-new-$RESTORE_ID"
  remove_path_if_present "/etc/systemd/system/.filebrowser-restore-$RESTORE_ID"
}

recover_incomplete_apply() {
  local index runtime_validator pending_state pending_status
  load_and_validate_journal
  if service_is_running nginx; then
    compose stop --timeout 30 nginx
  fi
  if service_is_running filebrowser-enterprise; then
    compose stop --timeout 60 filebrowser-enterprise
  fi
  assert_no_running nginx
  assert_no_running filebrowser-enterprise
  durable_tsv_set "$FILEBROWSER_RESTORE_JOURNAL" status reverting

  for (( index=JOURNAL_SWAP_COUNT; index>=1; index-- )); do
    recover_registered_swap "$index"
  done
  remove_transaction_staging_from_journal
  systemctl daemon-reload

  ENV_FILE="$DEPLOY_ROOT/.env"
  COMPOSE_FILE="$DEPLOY_ROOT/compose.yaml"
  deployment_init_layout
  compare_manifest_root "$FILEBROWSER_RESTORE_JOURNAL" deploy_root "$DEPLOY_ROOT"
  compare_manifest_root "$FILEBROWSER_RESTORE_JOURNAL" config_root "$CONFIG_ROOT"
  compare_manifest_root "$FILEBROWSER_RESTORE_JOURNAL" data_root "$DATA_ROOT"
  compare_manifest_root "$FILEBROWSER_RESTORE_JOURNAL" cache_root "$CACHE_ROOT"
  compare_manifest_root "$FILEBROWSER_RESTORE_JOURNAL" files_root "$FILES_ROOT"
  compare_manifest_root "$FILEBROWSER_RESTORE_JOURNAL" backup_root "$BACKUP_ROOT"
  env_set "$ENV_FILE" FILEBROWSER_IMAGE "$ROLLBACK_FILEBROWSER_IMAGE"
  env_set "$ENV_FILE" NGINX_IMAGE "$ROLLBACK_NGINX_IMAGE"
  fsync_path "$ENV_FILE"
  fsync_parent "$ENV_FILE"
  docker image inspect "$ROLLBACK_FILEBROWSER_IMAGE" >/dev/null || die "rollback FileBrowser image is unavailable locally"
  docker image inspect "$ROLLBACK_NGINX_IMAGE" >/dev/null || die "rollback Nginx image is unavailable locally"

  log "filesystem transaction reverted; starting FileBrowser with the recorded rollback image"
  maintenance_compose up -d --no-deps --scale filebrowser-enterprise=1 filebrowser-enterprise
  assert_exactly_one_running filebrowser-enterprise
  if ! wait_for_service_health filebrowser-enterprise 180; then
    compose stop --timeout 60 filebrowser-enterprise >/dev/null 2>&1 || true
    warn "FileBrowser did not become healthy after filesystem rollback; Nginx remains stopped and the journal is retained"
    return 1
  fi
  log "FileBrowser is healthy; starting Nginx"
  maintenance_compose up -d --no-deps --scale nginx=1 nginx
  assert_exactly_one_running nginx
  if ! wait_for_service_health nginx 90; then
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    warn "Nginx did not become healthy after filesystem rollback; the journal is retained"
    return 1
  fi
  runtime_validator="$DEPLOY_ROOT/scripts/validate-deployment.sh"
  if [[ ! -f "$runtime_validator" || -L "$runtime_validator" ]]; then
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    warn "restored runtime validator is missing or unsafe; Nginx was stopped and the journal is retained"
    return 1
  fi
  if ! "$runtime_validator" --production --runtime --allow-incomplete-restore; then
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    warn "runtime validation failed after filesystem rollback; Nginx was stopped and the journal is retained"
    return 1
  fi
  if ! clear_restore_journal; then
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    warn "restore journal could not be cleared; Nginx was stopped"
    return 1
  fi
  if pending_state=$(first_unfinished_lifecycle_state false); then
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    warn "filesystem recovery committed, but upgrade/rollback state remains unfinished: $pending_state"
    warn "Nginx was stopped; resume with: $DEPLOY_ROOT/scripts/rollback.sh --state $pending_state --apply"
    return 2
  else
    pending_status=$?
    if (( pending_status != 3 )); then
      compose stop --timeout 30 nginx >/dev/null 2>&1 || true
      die "cannot validate lifecycle state after filesystem recovery; Nginx was stopped"
    fi
  fi
  if ! promote_production_nginx; then
    warn "filesystem rollback committed, but production Nginx promotion failed"
    return 1
  fi
  if ! "$runtime_validator" --production --runtime; then
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    warn "production runtime validation failed after rollback commit; Nginx was stopped"
    return 1
  fi
  if ! enable_production_restart_policy; then
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    warn "production restart policy could not be restored; Nginx was stopped"
    return 1
  fi
  queue_systemd_stack_ownership
  log "incomplete restore was rolled back and both services passed health validation"
  log "durable rollback bundle retained at $ROLLBACK_POINT"
}

create_restore_journal() {
  local temp
  ensure_lifecycle_state_root
  assert_no_incomplete_restore
  temp=$(mktemp "$FILEBROWSER_LIFECYCLE_STATE_ROOT/.restore-journal.XXXXXX")
  cat >"$temp" <<EOF
format_version	1
restore_id	$RESTORE_ID
status	prepared
created_utc	$(date -u +'%Y-%m-%dT%H:%M:%SZ')
backup_path	$BACKUP_REAL
rollback_point	$ROLLBACK_POINT
rollback_filebrowser_image	$ROLLBACK_FILEBROWSER_IMAGE
rollback_nginx_image	$ROLLBACK_NGINX_IMAGE
deploy_root	$DEPLOY_ROOT
config_root	$CONFIG_ROOT
data_root	$DATA_ROOT
cache_root	$CACHE_ROOT
files_root	$FILES_ROOT
backup_root	$BACKUP_ROOT
swap_count	0
EOF
  chmod 0600 "$temp"
  chown 0:0 "$temp"
  fsync_path "$temp"
  durable_move "$temp" "$FILEBROWSER_RESTORE_JOURNAL"
}

register_and_swap() {
  local target=$1 replacement=$2 original_exists=$3 count original failed
  [[ "$original_exists" == true || "$original_exists" == false ]] || die "invalid original_exists flag"
  is_path_present "$replacement" || die "restore replacement is missing: $replacement"
  if [[ "$original_exists" == true ]]; then
    is_path_present "$target" || die "restore target is missing: $target"
    validate_atomic_target "$target"
    original="${target}.pre-restore-$RESTORE_ID"
  else
    is_path_present "$target" && die "new restore target already exists: $target"
    [[ $(stat -c '%d' "$replacement") == $(stat -c '%d' "$(dirname -- "$target")") ]] ||
      die "new restore target and replacement are not on the same filesystem: $target"
    original="${target}.absent-pre-restore-$RESTORE_ID"
  fi
  failed="${target}.failed-restore-$RESTORE_ID"
  is_path_present "$original" && die "pre-restore path already exists: $original"
  is_path_present "$failed" && die "failed-restore path already exists: $failed"

  count=$(journal_required swap_count)
  validate_byte_count "$count" journal_swap_count
  count=$((count + 1))
  (( count <= 8 )) || die "restore journal exceeds its target allowlist"
  durable_tsv_set "$FILEBROWSER_RESTORE_JOURNAL" "swap_${count}_target" "$target"
  durable_tsv_set "$FILEBROWSER_RESTORE_JOURNAL" "swap_${count}_original" "$original"
  durable_tsv_set "$FILEBROWSER_RESTORE_JOURNAL" "swap_${count}_replacement" "$replacement"
  durable_tsv_set "$FILEBROWSER_RESTORE_JOURNAL" "swap_${count}_failed" "$failed"
  durable_tsv_set "$FILEBROWSER_RESTORE_JOURNAL" "swap_${count}_original_exists" "$original_exists"
  durable_tsv_set "$FILEBROWSER_RESTORE_JOURNAL" "swap_${count}_reverted" false
  durable_tsv_set "$FILEBROWSER_RESTORE_JOURNAL" swap_count "$count"
  durable_tsv_set "$FILEBROWSER_RESTORE_JOURNAL" status swapping
  validate_journal_swap "$count"

  if [[ "$original_exists" == true ]]; then
    durable_move "$target" "$original"
  fi
  durable_move "$replacement" "$target"
  SUCCESS_ORIGINALS+=("$original")
}

validate_atomic_target() {
  local target=$1 parent target_device parent_device
  parent=$(dirname -- "$target")
  [[ -d "$parent" && ! -L "$parent" ]] || die "restore target parent is missing or a symlink: $parent"
  ! mountpoint -q -- "$target" ||
    die "restore target is a mount point and cannot use atomic sibling swaps: $target"
  target_device=$(stat -c '%d' "$target")
  parent_device=$(stat -c '%d' "$parent")
  [[ "$target_device" == "$parent_device" ]] ||
    die "restore target is a mount point and cannot use atomic sibling swaps: $target"
}

validate_restore_atomic_targets() {
  require_command mountpoint
  validate_atomic_target "$DATA_ROOT/database.db"
  validate_atomic_target "$CONFIG_ROOT"
  validate_atomic_target "$FILES_ROOT"
  validate_atomic_target "$CACHE_ROOT"
  validate_atomic_target "$DEPLOY_ROOT"
}

create_and_validate_staging() {
  (( $# == 6 )) || die "create_and_validate_staging requires six validated archive-byte values"
  local database_archive_bytes=$1 config_archive_bytes=$2 secrets_archive_bytes=$3
  local files_archive_bytes=$4 deployment_archive_bytes=$5 systemd_archive_bytes=$6
  local config_required files_required deploy_required database_required systemd_required cache_required
  local unit_path unit_name
  RESTORE_ID=$(date -u +'%Y%m%dT%H%M%SZ')-$$
  DATABASE_STAGE="$DATA_ROOT/.restore-database-$RESTORE_ID"
  DATABASE_NEW="$DATA_ROOT/database.db.restore-new-$RESTORE_ID"
  CONFIG_NEW="${CONFIG_ROOT}.restore-new-$RESTORE_ID"
  FILES_NEW="${FILES_ROOT}.restore-new-$RESTORE_ID"
  DEPLOY_NEW="${DEPLOY_ROOT}.restore-new-$RESTORE_ID"
  CACHE_NEW="${CACHE_ROOT}.restore-new-$RESTORE_ID"
  SYSTEMD_NEW="/etc/systemd/system/.filebrowser-restore-$RESTORE_ID"

  validate_atomic_target "$CONFIG_ROOT"
  validate_atomic_target "$DATA_ROOT/database.db"
  validate_atomic_target "$FILES_ROOT"
  validate_atomic_target "$DEPLOY_ROOT"
  validate_atomic_target "$CACHE_ROOT"
  database_required=$(space_with_margin "$database_archive_bytes" 15 16)
  config_required=$(space_with_margin "$((config_archive_bytes + secrets_archive_bytes))" 15 16)
  files_required=$(space_with_margin "$files_archive_bytes" 15 16)
  deploy_required=$(space_with_margin "$deployment_archive_bytes" 15 16)
  cache_required=$(space_with_margin 0 0 16)
  systemd_required=$(space_with_margin "$systemd_archive_bytes" 15 4)
  require_filesystem_space restore \
    "$DATA_ROOT" "$database_required" \
    "$(dirname -- "$CONFIG_ROOT")" "$config_required" \
    "$(dirname -- "$FILES_ROOT")" "$files_required" \
    "$(dirname -- "$DEPLOY_ROOT")" "$deploy_required" \
    "$(dirname -- "$CACHE_ROOT")" "$cache_required" \
    /etc/systemd/system "$systemd_required"

  for path in "$DATABASE_STAGE" "$DATABASE_NEW" "$CONFIG_NEW" "$FILES_NEW" "$DEPLOY_NEW" "$CACHE_NEW" "$SYSTEMD_NEW"; do
    is_path_present "$path" && die "restore staging path already exists: $path"
  done
  mkdir -m 0700 -- "$DATABASE_STAGE" "$CONFIG_NEW" "$FILES_NEW" "$DEPLOY_NEW" "$CACHE_NEW" "$SYSTEMD_NEW"
  tar --sparse --acls --xattrs --numeric-owner -C "$DATABASE_STAGE" -xpf "$BACKUP_REAL/payload/database.tar"
  tar --sparse --acls --xattrs --numeric-owner -C "$CONFIG_NEW" -xpf "$BACKUP_REAL/payload/config.tar"
  tar --sparse --acls --xattrs --numeric-owner -C "$CONFIG_NEW" -xpf "$BACKUP_REAL/payload/secrets.tar"
  tar --sparse --acls --xattrs --numeric-owner --strip-components=1 -C "$FILES_NEW" -xpf "$BACKUP_REAL/payload/files.tar"
  tar --sparse --acls --xattrs --numeric-owner --strip-components=1 -C "$DEPLOY_NEW" -xpf "$BACKUP_REAL/payload/deployment.tar"
  tar --sparse --acls --xattrs --numeric-owner -C "$SYSTEMD_NEW" -xpf "$BACKUP_REAL/payload/systemd.tar"
  [[ -s "$DATABASE_STAGE/database.db" && ! -L "$DATABASE_STAGE/database.db" ]] || die "restored database payload is empty or unsafe"
  [[ -s "$CONFIG_NEW/config.yaml" && ! -L "$CONFIG_NEW/config.yaml" && -d "$CONFIG_NEW/secrets" && ! -L "$CONFIG_NEW/secrets" ]] ||
    die "restored configuration payload is incomplete"
  for secret_name in jwt_token_secret totp_secret; do
    [[ -s "$CONFIG_NEW/secrets/$secret_name" && ! -L "$CONFIG_NEW/secrets/$secret_name" ]] ||
      die "restored stable secret is missing, empty, or unsafe: $secret_name"
  done
  for transient_name in bootstrap_admin_password emergency_admin_password bootstrap_admin_password.recovery emergency_admin_password.recovery; do
    [[ ! -e "$CONFIG_NEW/secrets/$transient_name" && ! -L "$CONFIG_NEW/secrets/$transient_name" ]] ||
      die "restored secrets contain forbidden transient state: $transient_name"
  done
  [[ -f "$DEPLOY_NEW/.env" && ! -L "$DEPLOY_NEW/.env" && -f "$DEPLOY_NEW/compose.yaml" && ! -L "$DEPLOY_NEW/compose.yaml" ]] ||
    die "restored deployment payload lacks regular .env or compose.yaml"
  if [[ -n $(find "$SYSTEMD_NEW" -mindepth 1 ! -type f -print -quit) ]]; then
    die "restored systemd payload contains a non-regular entry"
  fi
  [[ $(find "$SYSTEMD_NEW" -mindepth 1 -maxdepth 1 -type f | wc -l) -eq 3 ]] ||
    die "restored systemd payload must contain exactly three unit files"
  for unit_name in filebrowser-enterprise.service filebrowser-enterprise-backup.service filebrowser-enterprise-backup.timer; do
    [[ -f "$SYSTEMD_NEW/$unit_name" && ! -L "$SYSTEMD_NEW/$unit_name" ]] ||
      die "restored systemd payload is missing required unit: $unit_name"
  done
  for unit_path in "$SYSTEMD_NEW"/*; do
    [[ -f "$unit_path" ]] || continue
    unit_name=$(basename -- "$unit_path")
    case "$unit_name" in
      filebrowser-enterprise.service|filebrowser-enterprise-backup.service|filebrowser-enterprise-backup.timer) ;;
      *) die "restored systemd payload contains an unexpected unit: $unit_name" ;;
    esac
  done

  chmod --reference="$CONFIG_ROOT" "$CONFIG_NEW"
  chown --reference="$CONFIG_ROOT" "$CONFIG_NEW"
  chmod --reference="$FILES_ROOT" "$FILES_NEW"
  chown --reference="$FILES_ROOT" "$FILES_NEW"
  chmod --reference="$DEPLOY_ROOT" "$DEPLOY_NEW"
  chown --reference="$DEPLOY_ROOT" "$DEPLOY_NEW"
  chmod --reference="$CACHE_ROOT" "$CACHE_NEW"
  chown --reference="$CACHE_ROOT" "$CACHE_NEW"
  compare_archived_environment "$DEPLOY_NEW/.env" "$BACKUP_REAL/manifest.tsv"
  validate_staged_tls "$CONFIG_NEW" "$DEPLOY_NEW/.env"
  python3 "$SCRIPT_DIR/lib/deployment_validation.py" --production \
    --compose "$DEPLOY_NEW/compose.yaml" --config "$CONFIG_NEW/config.yaml" --env "$DEPLOY_NEW/.env"
  durable_move "$DATABASE_STAGE/database.db" "$DATABASE_NEW"
  rmdir -- "$DATABASE_STAGE"
  fsync_path "$DATA_ROOT"
  for path in "$DATABASE_NEW" "$CONFIG_NEW" "$FILES_NEW" "$DEPLOY_NEW" "$CACHE_NEW" "$SYSTEMD_NEW"; do
    fsync_path "$path"
    fsync_parent "$path"
  done
}

restore_exit() {
  local exit_status=$? recovery_status pending_state pending_status
  trap - EXIT INT TERM HUP
  set +e
  cleanup_preflight
  if [[ "$RESTORE_SUCCESS" == false && "$APPLY" == true && "$RECOVER_INCOMPLETE" == false ]] &&
    is_path_present "$FILEBROWSER_RESTORE_JOURNAL"; then
    warn "restore failed after its durable transaction began; attempting journaled filesystem rollback"
    (
      set -Eeuo pipefail
      recover_incomplete_apply
    )
    recovery_status=$?
    if (( recovery_status == 0 )); then
      warn "the failed restore was rolled back and both original services are healthy"
    else
      if is_path_present "$FILEBROWSER_RESTORE_JOURNAL"; then
        warn "automatic recovery did not complete; Nginx is stopped or serving only maintenance 503 responses"
        warn "the journal remains at $FILEBROWSER_RESTORE_JOURNAL"
        warn "preview it with: /usr/local/sbin/filebrowser-enterprise-recover"
      else
        if pending_state=$(first_unfinished_lifecycle_state false); then
          warn "filesystem rollback committed, but lifecycle state remains unfinished: $pending_state"
          warn "Nginx was stopped; resume with: $DEPLOY_ROOT/scripts/rollback.sh --state $pending_state --apply"
        else
          pending_status=$?
          if (( pending_status == 3 )); then
            warn "filesystem rollback committed, but production Nginx promotion or lifecycle ownership failed"
            warn "Nginx was stopped; after correcting the cause, run: systemctl restart filebrowser-enterprise.service"
            warn "then run: $DEPLOY_ROOT/scripts/validate-deployment.sh --production --runtime"
          else
            warn "filesystem rollback committed, but lifecycle state could not be validated; keep Nginx stopped"
          fi
        fi
      fi
      (( exit_status == 0 )) && exit_status=1
    fi
  elif ! is_path_present "$FILEBROWSER_RESTORE_JOURNAL"; then
    cleanup_restore_staging
  fi
  exit "$exit_status"
}

recovery_exit() {
  local exit_status=$? nginx_count
  trap - EXIT INT TERM HUP
  set +e
  if is_path_present "$FILEBROWSER_RESTORE_JOURNAL" && [[ -n ${COMPOSE_FILE:-} ]]; then
    warn "incomplete recovery is still journaled; stopping the Nginx entry point"
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    nginx_count=$(running_container_count nginx 2>/dev/null || printf unknown)
    [[ "$nginx_count" == 0 ]] ||
      warn "Nginx stop could not be confirmed (running=$nginx_count); the maintenance template still returns 503"
  fi
  exit "$exit_status"
}

main() {
  local validated_database_archive_bytes=0 validated_config_archive_bytes=0
  local validated_secrets_archive_bytes=0 validated_files_archive_bytes=0
  local validated_deployment_archive_bytes=0 validated_systemd_archive_bytes=0

  while (( $# > 0 )); do
    case "$1" in
      --backup)
        (( $# >= 2 )) || die "missing value for --backup"
        require_option_value --backup "$2"
        BACKUP_PATH=$2
        shift 2
        ;;
      --apply) APPLY=true; shift ;;
      --recover-incomplete) RECOVER_INCOMPLETE=true; shift ;;
      --precreated-rollback)
        (( $# >= 2 )) || die "missing value for --precreated-rollback"
        require_option_value --precreated-rollback "$2"
        PRECURRENT_ROLLBACK_POINT=$2
        shift 2
        ;;
      --expected-image)
        (( $# >= 2 )) || die "missing value for --expected-image"
        require_option_value --expected-image "$2"
        EXPECTED_IMAGE=$2
        shift 2
        ;;
      -h|--help) usage; return 0 ;;
      *) die "unknown argument: $1" ;;
    esac
  done

  if [[ "$RECOVER_INCOMPLETE" == true ]]; then
    [[ -z "$BACKUP_PATH" && -z "$PRECURRENT_ROLLBACK_POINT" && -z "$EXPECTED_IMAGE" ]] ||
      die "--recover-incomplete cannot be combined with backup restore arguments"
  else
    [[ -n "$BACKUP_PATH" ]] || die "--backup is required"
  fi
  if [[ -n "$PRECURRENT_ROLLBACK_POINT" ]]; then
    [[ ${FILEBROWSER_ALLOW_PRECREATED_ROLLBACK:-0} == 1 ]] ||
      die "--precreated-rollback is reserved for the verified rollback workflow"
    [[ -n ${FILEBROWSER_ACTIVE_TRANSACTION_STATE:-} ]] ||
      die "internal precreated rollback requires an active lifecycle state"
    [[ -n ${FILEBROWSER_EXPECTED_ROLLBACK_REASON:-} ]] ||
      die "internal precreated rollback requires FILEBROWSER_EXPECTED_ROLLBACK_REASON"
    [[ "$FILEBROWSER_EXPECTED_ROLLBACK_REASON" != *$'\n'* && "$FILEBROWSER_EXPECTED_ROLLBACK_REASON" != *$'\r'* \
      && "$FILEBROWSER_EXPECTED_ROLLBACK_REASON" != *$'\t'* ]] ||
      die "expected rollback reason contains unsupported control whitespace"
  fi

  if [[ "$APPLY" == true ]]; then
    require_root
    for command in flock sync stat; do require_command "$command"; done
    LOCK_ROOT=${LOCK_ROOT:-/run/lock/filebrowser-enterprise}
    validate_absolute_path "$LOCK_ROOT" LOCK_ROOT
    acquire_lock restore
    acquire_lifecycle_lock
    ensure_lifecycle_state_root
  fi

  if [[ "$RECOVER_INCOMPLETE" == true ]]; then
    if [[ "$APPLY" == false ]]; then
      require_command realpath
      require_command stat
      preview_incomplete_restore
      return 0
    fi
    for command in docker systemctl realpath awk mktemp; do require_command "$command"; done
    trap recovery_exit EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    trap 'exit 129' HUP
    recover_incomplete_apply
    return 0
  fi

  if [[ "$APPLY" == true ]]; then
    assert_no_incomplete_restore
  fi
  deployment_init_layout
  assert_no_incomplete_lifecycle_transaction
  for command in realpath sha256sum tar awk grep python3 find stat df du mktemp wc openssl; do
    require_command "$command"
  done
  for path in "$DEPLOY_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$CACHE_ROOT" "$FILES_ROOT" "$BACKUP_ROOT"; do
    [[ -d "$path" && ! -L "$path" ]] || die "restore deployment root is missing or a symlink: $path"
  done
  [[ -s "$DATA_ROOT/database.db" && ! -L "$DATA_ROOT/database.db" ]] ||
    die "current database must be a regular non-empty file"
  assert_independent_paths "$DEPLOY_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$CACHE_ROOT" "$FILES_ROOT" "$BACKUP_ROOT"
  if [[ "$APPLY" == true ]]; then
    assert_independent_paths "$DEPLOY_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$CACHE_ROOT" "$FILES_ROOT" "$BACKUP_ROOT" \
      "$FILEBROWSER_LIFECYCLE_STATE_ROOT" "$LOCK_ROOT" /etc/systemd/system
  fi
  if [[ "$APPLY" == true ]]; then
    for command in docker systemctl mountpoint; do require_command "$command"; done
  fi
  BACKUP_REAL=$(backup_child_realpath "$BACKUP_PATH" backup)
  trap restore_exit EXIT
  trap 'exit 143' TERM
  trap 'exit 130' INT
  trap 'exit 129' HUP
  validate_backup_bundle "$BACKUP_REAL" \
    validated_database_archive_bytes \
    validated_config_archive_bytes \
    validated_secrets_archive_bytes \
    validated_files_archive_bytes \
    validated_deployment_archive_bytes \
    validated_systemd_archive_bytes
  log "backup hashes, schema-2 paths, image pins, payload sizes, and archived production configuration validated"
  validate_restore_atomic_targets

  if [[ "$APPLY" == false ]]; then
    if service_is_running filebrowser-enterprise || service_is_running nginx; then
      warn "dry run only: stop both services before using --apply"
    fi
    log "dry run complete; no files or services were changed"
    RESTORE_SUCCESS=true
    return 0
  fi

  assert_at_most_one_running filebrowser-enterprise
  assert_at_most_one_running nginx
  service_is_running nginx && die "Nginx must be stopped before restore"
  service_is_running filebrowser-enterprise && die "FileBrowser must be stopped before restore"
  for path in "$DEPLOY_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$CACHE_ROOT" "$FILES_ROOT" "$BACKUP_ROOT"; do
    validate_absolute_path "$path" restore_target
    [[ -d "$path" && ! -L "$path" ]] || die "restore target must be an existing real directory: $path"
  done
  [[ -s "$DATA_ROOT/database.db" && ! -L "$DATA_ROOT/database.db" ]] || die "current database must be a regular non-empty file"
  docker image inspect "$SOURCE_IMAGE" >/dev/null || die "restore FileBrowser image is unavailable locally: $SOURCE_IMAGE"
  docker image inspect "$SOURCE_NGINX_IMAGE" >/dev/null || die "restore Nginx image is unavailable locally: $SOURCE_NGINX_IMAGE"

  if [[ -n "$PRECURRENT_ROLLBACK_POINT" ]]; then
    ROLLBACK_POINT=$(backup_child_realpath "$PRECURRENT_ROLLBACK_POINT" "precreated rollback point")
    [[ "$ROLLBACK_POINT" != "$BACKUP_REAL" ]] || die "precreated rollback point must differ from the restore source"
  else
    rollback_log=$(mktemp)
    "$SCRIPT_DIR/backup.sh" --keep-stopped --reason restore-rollback | tee "$rollback_log"
    ROLLBACK_POINT=$(awk -F= '$1 == "BACKUP_PATH" { print substr($0, length($1) + 2) }' "$rollback_log" | tail -n 1)
    rm -f -- "$rollback_log"
    [[ -n "$ROLLBACK_POINT" ]] || die "failed to capture the restore rollback point"
    ROLLBACK_POINT=$(backup_child_realpath "$ROLLBACK_POINT" "generated rollback point")
  fi

  rollback_expected=$(manifest_required "$ROLLBACK_POINT/manifest.tsv" source_image)
  validate_pinned_image "$rollback_expected" precreated_rollback_image
  "$SCRIPT_DIR/restore.sh" --backup "$ROLLBACK_POINT" --expected-image "$rollback_expected"
  ROLLBACK_FILEBROWSER_IMAGE=$(manifest_required "$ROLLBACK_POINT/manifest.tsv" source_image)
  ROLLBACK_NGINX_IMAGE=$(manifest_required "$ROLLBACK_POINT/manifest.tsv" source_nginx_image)
  if [[ -n "$PRECURRENT_ROLLBACK_POINT" ]]; then
    rollback_reason=$(manifest_required "$ROLLBACK_POINT/manifest.tsv" reason)
    [[ "$rollback_reason" == "$FILEBROWSER_EXPECTED_ROLLBACK_REASON" ]] ||
      die "precreated rollback point reason does not match the invoking rollback state"
    [[ "$ROLLBACK_FILEBROWSER_IMAGE" == "$CURRENT_IMAGE" ]] ||
      die "precreated rollback point FileBrowser image does not match the current entry image"
    [[ "$ROLLBACK_NGINX_IMAGE" == "$CURRENT_NGINX_IMAGE" ]] ||
      die "precreated rollback point Nginx image does not match the current entry image"
  fi
  validate_internal_image "$ROLLBACK_FILEBROWSER_IMAGE" rollback_filebrowser_image "$ENV_FILE"
  validate_internal_image "$ROLLBACK_NGINX_IMAGE" rollback_nginx_image "$ENV_FILE"
  docker image inspect "$SOURCE_IMAGE" >/dev/null || die "restore FileBrowser image is unavailable locally: $SOURCE_IMAGE"
  docker image inspect "$SOURCE_NGINX_IMAGE" >/dev/null || die "restore Nginx image is unavailable locally: $SOURCE_NGINX_IMAGE"
  docker image inspect "$ROLLBACK_FILEBROWSER_IMAGE" >/dev/null ||
    die "rollback FileBrowser image is unavailable locally: $ROLLBACK_FILEBROWSER_IMAGE"
  docker image inspect "$ROLLBACK_NGINX_IMAGE" >/dev/null ||
    die "rollback Nginx image is unavailable locally: $ROLLBACK_NGINX_IMAGE"
  log "current state is protected by a fully validated rollback point at $ROLLBACK_POINT"

  create_and_validate_staging \
    "$validated_database_archive_bytes" \
    "$validated_config_archive_bytes" \
    "$validated_secrets_archive_bytes" \
    "$validated_files_archive_bytes" \
    "$validated_deployment_archive_bytes" \
    "$validated_systemd_archive_bytes"
  create_restore_journal
  register_and_swap "$DATA_ROOT/database.db" "$DATABASE_NEW" true
  register_and_swap "$CONFIG_ROOT" "$CONFIG_NEW" true
  register_and_swap "$FILES_ROOT" "$FILES_NEW" true
  register_and_swap "$CACHE_ROOT" "$CACHE_NEW" true
  register_and_swap "$DEPLOY_ROOT" "$DEPLOY_NEW" true
  for unit_path in "$SYSTEMD_NEW"/*; do
    [[ -f "$unit_path" ]] || continue
    unit_name=$(basename -- "$unit_path")
    unit_target="/etc/systemd/system/$unit_name"
    if is_path_present "$unit_target"; then
      register_and_swap "$unit_target" "$unit_path" true
    else
      register_and_swap "$unit_target" "$unit_path" false
    fi
  done
  rmdir -- "$SYSTEMD_NEW"
  fsync_path /etc/systemd/system
  durable_tsv_set "$FILEBROWSER_RESTORE_JOURNAL" status validating
  systemctl daemon-reload

  ENV_FILE="$DEPLOY_ROOT/.env"
  COMPOSE_FILE="$DEPLOY_ROOT/compose.yaml"
  deployment_init_layout
  log "starting the restored FileBrowser instance without Nginx"
  maintenance_compose up -d --no-deps --scale filebrowser-enterprise=1 filebrowser-enterprise
  assert_exactly_one_running filebrowser-enterprise
  wait_for_service_health filebrowser-enterprise 180 || die "restored FileBrowser failed its health check"
  log "FileBrowser is healthy; starting Nginx"
  maintenance_compose up -d --no-deps --scale nginx=1 nginx
  assert_exactly_one_running nginx
  wait_for_service_health nginx 90 || die "restored Nginx failed its health check"
  "$SCRIPT_DIR/validate-deployment.sh" --production --runtime --allow-incomplete-restore

  if [[ ${FILEBROWSER_DEFER_PRODUCTION_PROMOTION:-0} == 1 ]]; then
    [[ -n ${FILEBROWSER_ACTIVE_TRANSACTION_STATE:-} ]] ||
      die "deferred production promotion requires an active lifecycle state"
    [[ $(manifest_required "$FILEBROWSER_ACTIVE_TRANSACTION_STATE" format_version) == 1 ]] ||
      die "active rollback state format is incompatible"
    [[ $(manifest_required "$FILEBROWSER_ACTIVE_TRANSACTION_STATE" status) == rolling-back ]] ||
      die "active rollback state is not ready for a data commit"
    [[ $(manifest_required "$FILEBROWSER_ACTIVE_TRANSACTION_STATE" old_image) == "$SOURCE_IMAGE" ]] ||
      die "active rollback old image does not match the restore source"
    [[ $(manifest_required "$FILEBROWSER_ACTIVE_TRANSACTION_STATE" new_image) == "$ROLLBACK_FILEBROWSER_IMAGE" ]] ||
      die "active rollback new image does not match the roll-forward point"
    [[ $(manifest_required "$FILEBROWSER_ACTIVE_TRANSACTION_STATE" backup_path) == "$BACKUP_REAL" ]] ||
      die "active rollback backup does not match the restore source"
    [[ $(manifest_required "$FILEBROWSER_ACTIVE_TRANSACTION_STATE" rollforward_backup) == "$ROLLBACK_POINT" ]] ||
      die "active rollback roll-forward point does not match the restore journal"
    durable_tsv_set "$FILEBROWSER_ACTIVE_TRANSACTION_STATE" restore_id "$RESTORE_ID"
    durable_tsv_set "$FILEBROWSER_ACTIVE_TRANSACTION_STATE" status rollback-data-restored
    clear_restore_journal
    RESTORE_SUCCESS=true
    cleanup_success_originals
    cleanup_restore_staging
    log "restore data committed under lifecycle ownership; production Nginx promotion is deferred"
    log "durable pre-restore backup: $ROLLBACK_POINT"
    return 0
  fi
  clear_restore_journal
  promote_production_nginx || die "restored state committed, but production Nginx promotion failed"
  if ! "$SCRIPT_DIR/validate-deployment.sh" --production --runtime; then
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    die "restored state committed, but production runtime validation failed; Nginx was stopped"
  fi
  enable_production_restart_policy
  RESTORE_SUCCESS=true
  cleanup_success_originals
  cleanup_restore_staging
  queue_systemd_stack_ownership
  log "restore completed and both services passed runtime validation"
  log "durable pre-restore backup: $ROLLBACK_POINT"
  warn "cache was not restored; FileBrowser will rebuild the empty cache directory"
}

main "$@"
