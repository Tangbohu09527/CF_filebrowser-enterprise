#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=scripts/lib/deployment-common.sh
source "$SCRIPT_DIR/lib/deployment-common.sh"

STATE_INPUT=latest
APPLY=false
ROLLBACK_SUCCESS=false
BACKUP_ATTEMPTED=false
ROLLFORWARD_BACKUP=
ORIGINAL_APP_RUNNING=false
ORIGINAL_NGINX_RUNNING=false
RESTORE_ATTEMPTED=false
ENTRY_STATUS=

usage() {
  cat <<'USAGE'
Usage: rollback.sh [--state PATH|latest] [--apply]

The default is a dry run. Rollback restores the old pinned image and the exact
matching pre-upgrade backup, with a fresh roll-forward backup of the failed or
current state. Cache is rebuilt.
USAGE
}

while (( $# > 0 )); do
  case "$1" in
    --state)
      (( $# >= 2 )) || die "missing value for --state"
      STATE_INPUT=$2
      shift 2
      ;;
    --apply) APPLY=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

deployment_init_layout
for command in realpath sha256sum find sort tail awk; do
  require_command "$command"
done
if [[ "$APPLY" == true ]]; then
  require_root
  for command in docker flock sha256sum sync fuser; do
    require_command "$command"
  done
  acquire_lock rollback
  acquire_lifecycle_lock
  deployment_init_layout
  assert_no_incomplete_restore
fi
state_root="$FILEBROWSER_LIFECYCLE_STATE_ROOT/upgrade-history"
if [[ "$STATE_INPUT" == latest ]]; then
  [[ -d "$state_root" ]] || die "upgrade history does not exist"
  STATE_FILE=$(find "$state_root" -mindepth 2 -maxdepth 2 -type f -name state.tsv -print | sort | tail -n 1)
  [[ -n "$STATE_FILE" ]] || die "no upgrade state file was found"
else
  STATE_FILE=$(realpath -e -- "$STATE_INPUT")
  state_root_real=$(realpath -e -- "$state_root")
  case "$STATE_FILE" in
    "$state_root_real"/*) ;;
    *) die "state file must be inside $state_root_real" ;;
  esac
fi
[[ -f "$STATE_FILE" && ! -L "$STATE_FILE" ]] || die "state file is missing or unsafe"
[[ $(stat -c '%u:%g:%a' "$STATE_FILE") == 0:0:600 ]] ||
  die "state file must be owned by root:root with mode 0600"
export FILEBROWSER_ACTIVE_TRANSACTION_STATE="$STATE_FILE"
assert_no_incomplete_lifecycle_transaction

format_version=$(manifest_get "$STATE_FILE" format_version) || die "invalid state format"
ENTRY_STATUS=$(manifest_get "$STATE_FILE" status) || die "state status is invalid"
old_image=$(manifest_get "$STATE_FILE" old_image) || die "state old_image is invalid"
new_image=$(manifest_get "$STATE_FILE" new_image) || die "state new_image is invalid"
preupgrade_backup=$(manifest_get "$STATE_FILE" backup_path) || die "state backup_path is invalid"
[[ "$format_version" == 1 ]] || die "unsupported rollback state version"
validate_internal_image "$old_image" old_image "$ENV_FILE"
validate_internal_image "$new_image" new_image "$ENV_FILE"
configured_image=$(env_get "$ENV_FILE" FILEBROWSER_IMAGE)
[[ "$configured_image" == "$new_image" || "$configured_image" == "$old_image" ]] ||
  die "configured image matches neither side of the recorded upgrade"

if [[ "$preupgrade_backup" == pending ]]; then
  case "$ENTRY_STATUS" in
    preparing|upgrade-recovery-required|aborted-before-backup) ;;
    *) die "state has no backup but is not a safe pre-backup transaction: $ENTRY_STATUS" ;;
  esac
  [[ "$configured_image" == "$old_image" ]] ||
    die "pre-backup abort requires the original image to remain configured"
  log "rollback plan: abort pre-backup upgrade state and retain the original image/data"
  if [[ "$APPLY" == false ]]; then
    log "dry run complete; no service or file was changed"
    exit 0
  fi
  compose up -d --no-deps --scale filebrowser-enterprise=1 filebrowser-enterprise
  assert_exactly_one_running filebrowser-enterprise
  wait_for_service_health filebrowser-enterprise 180 || die "original FileBrowser is unhealthy during pre-backup abort"
  compose up -d --no-deps --scale nginx=1 nginx
  assert_exactly_one_running nginx
  wait_for_service_health nginx 90 || die "original Nginx is unhealthy during pre-backup abort"
  "$SCRIPT_DIR/validate-deployment.sh" --production --runtime
  if ! enable_production_restart_policy; then
    durable_tsv_set "$STATE_FILE" status upgrade-recovery-required || true
    disable_managed_restart_policy || true
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    die "restart policy could not be restored after the pre-backup abort"
  fi
  durable_tsv_set "$STATE_FILE" status aborted-before-backup
  queue_systemd_stack_ownership
  log "pre-backup upgrade state aborted safely: $STATE_FILE"
  exit 0
fi

backup_real=$(realpath -e -- "$preupgrade_backup")
backup_root_real=$(realpath -e -- "$BACKUP_ROOT")
case "$backup_real/" in
  "$backup_root_real"/*) ;;
  *) die "pre-upgrade backup is outside $backup_root_real" ;;
esac
[[ $(manifest_get "$backup_real/manifest.tsv" source_image) == "$old_image" ]] || die "pre-upgrade backup image does not match rollback image"
(
  cd -- "$backup_real"
  sha256sum -c checksums.sha256
)

"$SCRIPT_DIR/restore.sh" --backup "$backup_real" --expected-image "$old_image"

recorded_rollforward=$(manifest_get "$STATE_FILE" rollforward_backup) ||
  die "state rollforward_backup is invalid"
recorded_new_image_id=$(manifest_get "$STATE_FILE" new_image_id) ||
  die "state new_image_id is invalid"
rollforward_reason="rollback-rollforward-$(basename -- "$(dirname -- "$STATE_FILE")")"
RESUME_PROMOTION=false

ensure_old_image() {
  local local_old_image_id recorded_old_image_id
  if ! docker image inspect "$old_image" >/dev/null 2>&1; then
    log "old image is absent locally; pulling the exact recorded digest before stopping services"
    docker pull "$old_image"
  fi
  local_old_image_id=$(docker image inspect --format '{{.Id}}' "$old_image")
  recorded_old_image_id=$(manifest_get "$STATE_FILE" old_image_id) ||
    die "state old_image_id is invalid"
  [[ "$local_old_image_id" == "$recorded_old_image_id" ]] ||
    die "local old image ID does not match the recorded rollback image ID"
}

validate_rollforward_backup() {
  local candidate=$1 candidate_real reason source_image source_image_id
  [[ "$candidate" != pending ]] || die "roll-forward backup has not been created"
  candidate_real=$(realpath -e -- "$candidate")
  case "$candidate_real/" in
    "$backup_root_real"/*) ;;
    *) die "roll-forward backup is outside $backup_root_real" ;;
  esac
  reason=$(manifest_get "$candidate_real/manifest.tsv" reason) ||
    die "roll-forward backup reason is invalid"
  source_image=$(manifest_get "$candidate_real/manifest.tsv" source_image) ||
    die "roll-forward backup source image is invalid"
  source_image_id=$(manifest_get "$candidate_real/manifest.tsv" source_image_id) ||
    die "roll-forward backup source image ID is invalid"
  [[ "$reason" == "$rollforward_reason" ]] ||
    die "roll-forward backup reason does not match the rollback state"
  [[ "$source_image" == "$new_image" ]] ||
    die "roll-forward backup is not paired with the recorded new image"
  [[ "$recorded_new_image_id" != pending && "$source_image_id" == "$recorded_new_image_id" ]] ||
    die "roll-forward backup image ID does not match the recorded new image ID"
  "$SCRIPT_DIR/restore.sh" --backup "$candidate_real" --expected-image "$new_image"
  ROLLFORWARD_BACKUP=$candidate_real
}

if [[ "$ENTRY_STATUS" == backed-up ||
  ( ( "$ENTRY_STATUS" == preparing || "$ENTRY_STATUS" == upgrade-recovery-required ) && "$configured_image" == "$old_image" ) ]]; then
  log "rollback plan: abort before candidate start and retain the unchanged old database"
  if [[ "$APPLY" == false ]]; then
    log "dry run complete; no service or file was changed"
    exit 0
  fi
  ensure_old_image
  disable_managed_restart_policy
  compose stop --timeout 30 nginx >/dev/null 2>&1 || true
  compose stop --timeout 60 filebrowser-enterprise >/dev/null 2>&1 || true
  assert_no_running nginx
  assert_no_running filebrowser-enterprise
  env_set "$ENV_FILE" FILEBROWSER_IMAGE "$old_image"
  compose up -d --no-deps --scale filebrowser-enterprise=1 filebrowser-enterprise
  assert_exactly_one_running filebrowser-enterprise
  wait_for_service_health filebrowser-enterprise 180 || die "old FileBrowser is unhealthy during pre-candidate abort"
  compose up -d --no-deps --scale nginx=1 nginx
  assert_exactly_one_running nginx
  wait_for_service_health nginx 90 || die "Nginx is unhealthy during pre-candidate abort"
  "$SCRIPT_DIR/validate-deployment.sh" --production --runtime
  if ! enable_production_restart_policy; then
    durable_tsv_set "$STATE_FILE" status upgrade-recovery-required || true
    disable_managed_restart_policy || true
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    die "restart policy could not be restored after the pre-candidate abort"
  fi
  durable_tsv_set "$STATE_FILE" status aborted-old-service-restored
  queue_systemd_stack_ownership
  log "pre-candidate upgrade state aborted safely: $STATE_FILE"
  exit 0
fi

case "$ENTRY_STATUS" in
  rolled-back|auto-rolled-back|aborted-old-service-restored|rollback-failed-old-service-restored)
    [[ "$configured_image" == "$old_image" ]] ||
      die "terminal old-data state does not match the configured old image"
    log "state $ENTRY_STATUS already contains verified old image/data; reconcile runtime and systemd ownership only"
    if [[ "$APPLY" == false ]]; then
      log "dry run complete; no service or file was changed"
      exit 0
    fi
    ensure_old_image
    compose up -d --no-deps --scale filebrowser-enterprise=1 filebrowser-enterprise
    assert_exactly_one_running filebrowser-enterprise
    wait_for_service_health filebrowser-enterprise 180 || die "old FileBrowser is unhealthy during terminal reconciliation"
    compose up -d --no-deps --scale nginx=1 nginx
    assert_exactly_one_running nginx
    wait_for_service_health nginx 90 || die "Nginx is unhealthy during terminal reconciliation"
    "$SCRIPT_DIR/validate-deployment.sh" --production --runtime
    enable_production_restart_policy
    queue_systemd_stack_ownership
    log "terminal rollback state reconciled: $STATE_FILE"
    exit 0
    ;;
esac

if [[ "$recorded_rollforward" != pending ]]; then
  validate_rollforward_backup "$recorded_rollforward"
fi

if [[ "$ENTRY_STATUS" == rollback-data-restored ]]; then
  [[ "$recorded_rollforward" != pending ]] ||
    die "data-restored state is missing its roll-forward backup"
  if [[ "$configured_image" == "$old_image" ]]; then
    RESUME_PROMOTION=true
    log "rollback plan: data is already restored; resume maintenance validation and production promotion"
  else
    [[ "$configured_image" == "$new_image" ]] || die "data-restored state has an unexpected image pin"
    log "restore journal recovery returned to the new image/data; rollback will repeat the journaled restore"
  fi
else
  [[ "$configured_image" == "$new_image" ]] ||
    die "non-committed rollback state with an old image pin is ambiguous; refuse to guess the database generation"
  log "rollback plan: image $configured_image -> $old_image with data $backup_real"
fi

if [[ "$APPLY" == false ]]; then
  log "dry run complete; no service or file was changed"
  exit 0
fi

ensure_old_image
assert_at_most_one_running filebrowser-enterprise
assert_at_most_one_running nginx
service_is_running filebrowser-enterprise && ORIGINAL_APP_RUNNING=true
service_is_running nginx && ORIGINAL_NGINX_RUNNING=true

rollback_exit() {
  local exit_status=$? recovered=false current_phase=invalid
  trap - EXIT
  if [[ "$ROLLBACK_SUCCESS" == false && "$BACKUP_ATTEMPTED" == true ]]; then
    set +e
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    compose stop --timeout 60 filebrowser-enterprise >/dev/null 2>&1 || true
    current_phase=$(manifest_get "$STATE_FILE" status 2>/dev/null || printf invalid)
    if [[ "$current_phase" == rollback-data-restored || "$current_phase" == rolled-back ]]; then
      disable_managed_restart_policy || true
      durable_tsv_set "$STATE_FILE" status rollback-data-restored || true
      warn "rollback data is committed, but production promotion remains incomplete; services were stopped"
    elif [[ "$RESTORE_ATTEMPTED" == false ]] && lifecycle_status_is_terminal "$ENTRY_STATUS" &&
      [[ ! -e "$FILEBROWSER_RESTORE_JOURNAL" ]]; then
      warn "rollback failed before data restore; restoring the verified entry image and service state"
      env_set "$ENV_FILE" FILEBROWSER_IMAGE "$configured_image" || true
      if [[ "$ORIGINAL_APP_RUNNING" == false && "$ORIGINAL_NGINX_RUNNING" == false ]]; then
        recovered=true
      elif [[ "$ORIGINAL_APP_RUNNING" == true && "$ORIGINAL_NGINX_RUNNING" == true ]] &&
        compose up -d --no-deps --scale filebrowser-enterprise=1 filebrowser-enterprise &&
        assert_exactly_one_running filebrowser-enterprise &&
        wait_for_service_health filebrowser-enterprise 180 &&
        compose up -d --no-deps --scale nginx=1 nginx &&
        assert_exactly_one_running nginx &&
        wait_for_service_health nginx 90 &&
        enable_production_restart_policy; then
        recovered=true
      fi
      if [[ "$recovered" == true ]]; then
        durable_tsv_set "$STATE_FILE" status "$ENTRY_STATUS" || true
      else
        durable_tsv_set "$STATE_FILE" status rollback-recovery-required || true
        warn "rollback state remains non-terminal; services are stopped until the recorded rollback is resumed"
      fi
    else
      durable_tsv_set "$STATE_FILE" status rollback-recovery-required || true
      warn "rollback state remains non-terminal; services are stopped until the recorded rollback is resumed"
    fi
    warn "roll-forward recovery point: ${ROLLFORWARD_BACKUP:-unknown}; state file: $STATE_FILE"
  fi
  exit "$exit_status"
}
trap rollback_exit EXIT

BACKUP_ATTEMPTED=true
disable_managed_restart_policy

if [[ "$RESUME_PROMOTION" == false ]]; then
  [[ "$configured_image" == "$new_image" ]] ||
    die "journaled data restore requires the recorded new image as its entry state"
  if [[ "$recorded_rollforward" == pending ]]; then
    durable_tsv_set "$STATE_FILE" status rollback-preparing
    rollforward_log=$(mktemp)
    "$SCRIPT_DIR/backup.sh" --keep-stopped --reason "$rollforward_reason" | tee "$rollforward_log"
    rollforward_backup=$(awk -F= '$1 == "BACKUP_PATH" { print substr($0, length($1) + 2) }' "$rollforward_log" | tail -n 1)
    rm -f -- "$rollforward_log"
    [[ -n "$rollforward_backup" ]] || die "failed to create roll-forward backup"
    validate_rollforward_backup "$rollforward_backup"
    durable_tsv_set "$STATE_FILE" rollforward_backup "$ROLLFORWARD_BACKUP"
  else
    log "reusing the recorded roll-forward backup: $ROLLFORWARD_BACKUP"
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    compose stop --timeout 60 filebrowser-enterprise >/dev/null 2>&1 || true
    assert_no_running nginx
    assert_no_running filebrowser-enterprise
    if fuser -s -- "$DATA_ROOT/database.db"; then
      die "database.db is still open; refuse to reuse a roll-forward backup while another writer may exist"
    fi
  fi
  durable_tsv_set "$STATE_FILE" status rolling-back
  RESTORE_ATTEMPTED=true
  FILEBROWSER_ALLOW_PRECREATED_ROLLBACK=1 \
  FILEBROWSER_EXPECTED_ROLLBACK_REASON="$rollforward_reason" \
  FILEBROWSER_DEFER_PRODUCTION_PROMOTION=1 \
    "$SCRIPT_DIR/restore.sh" --backup "$backup_real" --precreated-rollback "$ROLLFORWARD_BACKUP" --apply
  [[ $(manifest_get "$STATE_FILE" status) == rollback-data-restored ]] ||
    die "restore returned without the durable rollback-data-restored commit"
else
  compose stop --timeout 30 nginx >/dev/null 2>&1 || true
  compose stop --timeout 60 filebrowser-enterprise >/dev/null 2>&1 || true
  assert_no_running nginx
  assert_no_running filebrowser-enterprise
  maintenance_compose up -d --no-deps --scale filebrowser-enterprise=1 filebrowser-enterprise
  assert_exactly_one_running filebrowser-enterprise
  wait_for_service_health filebrowser-enterprise 180 || die "restored FileBrowser is unhealthy while resuming rollback"
  maintenance_compose up -d --no-deps --scale nginx=1 nginx
fi

[[ $(env_get "$ENV_FILE" FILEBROWSER_IMAGE) == "$old_image" ]] ||
  die "restored environment does not contain the recorded old image"
assert_exactly_one_running filebrowser-enterprise
assert_exactly_one_running nginx
wait_for_service_health filebrowser-enterprise 180 || die "FileBrowser is unhealthy after rollback"
wait_for_service_health nginx 90 || die "maintenance Nginx is unhealthy after rollback data commit"

promote_production_nginx
"$SCRIPT_DIR/validate-deployment.sh" --production --runtime
enable_production_restart_policy
durable_tsv_set "$STATE_FILE" rolled_back_utc "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
durable_tsv_set "$STATE_FILE" status rolled-back
ROLLBACK_SUCCESS=true
queue_systemd_stack_ownership
log "rollback completed with old image and matching database"
log "roll-forward recovery point: $ROLLFORWARD_BACKUP"
