#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=scripts/lib/deployment-common.sh
source "$SCRIPT_DIR/lib/deployment-common.sh"

TARGET_IMAGE=
APPLY=false
UPGRADE_SUCCESS=false
ROLLBACK_READY=false
BACKUP_ATTEMPTED=false
STATE_FILE=
BACKUP_PATH=
CANDIDATE_START_ATTEMPTED=false

usage() {
  cat <<'USAGE'
Usage: upgrade.sh --image REGISTRY/IMAGE:TAG@sha256:DIGEST [--apply]

The default is a dry run. --apply pulls the exact digest, creates a stopped
pre-upgrade backup, starts exactly one FileBrowser instance, and starts Nginx
only after health succeeds. Failure triggers rollback of image and data.
USAGE
}

while (( $# > 0 )); do
  case "$1" in
    --image)
      (( $# >= 2 )) || die "missing value for --image"
      TARGET_IMAGE=$2
      shift 2
      ;;
    --apply) APPLY=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ -n "$TARGET_IMAGE" ]] || die "--image is required"
validate_pinned_image "$TARGET_IMAGE" target_image

deployment_init_layout
validate_internal_image "$TARGET_IMAGE" target_image "$ENV_FILE"
require_command docker
if [[ "$APPLY" == true ]]; then
  require_root
  for command in flock sha256sum sync stat mktemp; do
    require_command "$command"
  done
  acquire_lock upgrade
  acquire_lifecycle_lock
  deployment_init_layout
  assert_no_incomplete_lifecycle_transaction
fi
current_image=$(env_get "$ENV_FILE" FILEBROWSER_IMAGE)
validate_internal_image "$current_image" FILEBROWSER_IMAGE "$ENV_FILE"
[[ "$TARGET_IMAGE" != "$current_image" ]] || die "target image is already configured"

log "upgrade plan: $current_image -> $TARGET_IMAGE"
if [[ "$APPLY" == false ]]; then
  log "dry run complete; no image was pulled and no service or file was changed"
  exit 0
fi

"$SCRIPT_DIR/validate-deployment.sh" --production --skip-runtime
assert_exactly_one_running filebrowser-enterprise
assert_exactly_one_running nginx
wait_for_service_health filebrowser-enterprise 180 || die "FileBrowser must be healthy before upgrade"
wait_for_service_health nginx 90 || die "Nginx must be healthy before upgrade"

upgrade_id="upgrade-$(date -u +'%Y%m%dT%H%M%SZ')-$$"
ensure_lifecycle_state_root
state_history="$FILEBROWSER_LIFECYCLE_STATE_ROOT/upgrade-history"
[[ ! -L "$state_history" ]] || die "upgrade history must not be a symlink"
mkdir -m 0700 -p -- "$state_history"
[[ $(stat -c '%u:%g:%a' "$state_history") == 0:0:700 ]] ||
  die "upgrade history must be owned by root:root with mode 0700"
state_dir="$state_history/$upgrade_id"
mkdir -m 0700 -- "$state_dir"
fsync_path "$state_history"
STATE_FILE="$state_dir/state.tsv"
old_image_id=$(docker image inspect --format '{{.Id}}' "$current_image")
old_version=$(compose exec -T filebrowser-enterprise /home/filebrowser/filebrowser version | tr '\r\n\t' '   ' | sed 's/[[:space:]][[:space:]]*/ /g')
old_git_sha=$(printf '%s' "$old_version" | sed -n 's/.*Commit[[:space:]]*:[[:space:]]*\([^[:space:]]*\).*/\1/p')
old_git_sha=${old_git_sha:-unknown}

state_temp=$(mktemp "$state_dir/.state.XXXXXX")
cleanup_initial_state() {
  [[ -z ${state_temp:-} || ! -e "$state_temp" ]] || rm -f -- "$state_temp"
}
trap cleanup_initial_state EXIT
cat >"$state_temp" <<EOF
format_version	1
upgrade_id	$upgrade_id
created_utc	$(date -u +'%Y-%m-%dT%H:%M:%SZ')
status	preparing
old_image	$current_image
old_image_id	$old_image_id
old_git_sha	$old_git_sha
old_version	$old_version
new_image	$TARGET_IMAGE
new_image_id	pending
new_git_sha	pending
new_version	pending
backup_path	pending
rollforward_backup	pending
EOF
chmod 0600 "$state_temp"
fsync_path "$state_temp"
durable_move "$state_temp" "$STATE_FILE"
state_temp=
trap - EXIT
export FILEBROWSER_ACTIVE_TRANSACTION_STATE="$STATE_FILE"

upgrade_exit() {
  local exit_status=$? rollback_phase=invalid
  trap - EXIT
  if [[ "$UPGRADE_SUCCESS" == false && "$ROLLBACK_READY" == true ]]; then
    warn "upgrade failed; invoking image-and-database rollback"
    set +e
    "$SCRIPT_DIR/rollback.sh" --state "$STATE_FILE" --apply
    rollback_status=$?
    set -e
    if (( rollback_status == 0 )); then
      durable_tsv_set "$STATE_FILE" status auto-rolled-back
      warn "automatic rollback completed; upgrade still exits non-zero"
    else
      rollback_phase=$(manifest_get "$STATE_FILE" status 2>/dev/null || printf invalid)
      if [[ "$rollback_phase" == rollback-data-restored || "$rollback_phase" == rolled-back ]]; then
        warn "automatic rollback stopped after durable phase $rollback_phase; preserving it for rollback resume"
      else
        durable_tsv_set "$STATE_FILE" status rollback-failed
        warn "automatic rollback failed; state file: $STATE_FILE; pre-upgrade backup: $BACKUP_PATH"
        if [[ "$CANDIDATE_START_ATTEMPTED" == false && ! -e "$FILEBROWSER_RESTORE_JOURNAL" ]]; then
          warn "the candidate was never started; attempting to restore the old image and prior service state"
          compose stop --timeout 30 nginx >/dev/null 2>&1 || true
          compose stop --timeout 60 filebrowser-enterprise >/dev/null 2>&1 || true
          env_set "$ENV_FILE" FILEBROWSER_IMAGE "$current_image" || true
          if compose up -d --no-deps --scale filebrowser-enterprise=1 filebrowser-enterprise &&
            assert_exactly_one_running filebrowser-enterprise &&
            wait_for_service_health filebrowser-enterprise 180 &&
            compose up -d --no-deps --scale nginx=1 nginx &&
            assert_exactly_one_running nginx &&
            wait_for_service_health nginx 90 &&
            enable_production_restart_policy; then
            durable_tsv_set "$STATE_FILE" status rollback-failed-old-service-restored
            warn "old service state is healthy, but rollback still requires operator review"
          else
            warn "old service state could not be restored; leave the stack isolated and use the recorded backup"
          fi
        else
          warn "candidate start or restore swap was attempted; services remain stopped until data recovery is verified"
          compose stop --timeout 30 nginx >/dev/null 2>&1 || true
          compose stop --timeout 60 filebrowser-enterprise >/dev/null 2>&1 || true
        fi
      fi
    fi
  elif [[ "$UPGRADE_SUCCESS" == false && "$BACKUP_ATTEMPTED" == true ]]; then
    warn "upgrade failed during or after the backup attempt but before rollback metadata was ready; restoring the old service state"
    set +e
    env_set "$ENV_FILE" FILEBROWSER_IMAGE "$current_image" || true
    if [[ ! -e "$FILEBROWSER_RESTORE_JOURNAL" ]] &&
      compose up -d --no-deps --scale filebrowser-enterprise=1 filebrowser-enterprise &&
      assert_exactly_one_running filebrowser-enterprise &&
      wait_for_service_health filebrowser-enterprise 180; then
      if compose up -d --no-deps --scale nginx=1 nginx &&
        assert_exactly_one_running nginx &&
        wait_for_service_health nginx 90 &&
        enable_production_restart_policy; then
        durable_tsv_set "$STATE_FILE" status aborted-old-service-restored
      else
        durable_tsv_set "$STATE_FILE" status upgrade-recovery-required
        warn "Nginx could not be restored after the pre-upgrade backup"
      fi
    else
      durable_tsv_set "$STATE_FILE" status upgrade-recovery-required
      warn "FileBrowser could not be restored; Nginx remains stopped"
    fi
  elif [[ "$UPGRADE_SUCCESS" == false && -n "$STATE_FILE" ]]; then
    warn "upgrade failed before the backup attempt; restoring normal restart policy"
    set +e
    if assert_exactly_one_running filebrowser-enterprise &&
      assert_exactly_one_running nginx &&
      wait_for_service_health filebrowser-enterprise 180 &&
      wait_for_service_health nginx 90 &&
      enable_production_restart_policy; then
      durable_tsv_set "$STATE_FILE" status aborted-before-backup
    else
      durable_tsv_set "$STATE_FILE" status upgrade-recovery-required
      compose stop --timeout 30 nginx >/dev/null 2>&1 || true
      warn "pre-backup failure could not restore a verified service state; Nginx was stopped"
    fi
  fi
  exit "$exit_status"
}
trap upgrade_exit EXIT
disable_managed_restart_policy

if docker image inspect "$TARGET_IMAGE" >/dev/null 2>&1; then
  log "target image is already present locally by immutable digest"
else
  log "pulling target image by immutable digest"
  docker pull "$TARGET_IMAGE"
fi
new_image_id=$(docker image inspect --format '{{.Id}}' "$TARGET_IMAGE")
durable_tsv_set "$STATE_FILE" new_image_id "$new_image_id"

backup_log=$(mktemp)
BACKUP_ATTEMPTED=true
"$SCRIPT_DIR/backup.sh" --keep-stopped --reason "$upgrade_id" | tee "$backup_log"
BACKUP_PATH=$(awk -F= '$1 == "BACKUP_PATH" { print substr($0, length($1) + 2) }' "$backup_log" | tail -n 1)
rm -f -- "$backup_log"
[[ -n "$BACKUP_PATH" ]] || die "pre-upgrade backup path was not returned"
durable_tsv_set "$STATE_FILE" backup_path "$BACKUP_PATH"
durable_tsv_set "$STATE_FILE" status backed-up
ROLLBACK_READY=true

assert_no_running nginx
assert_no_running filebrowser-enterprise

env_set "$ENV_FILE" FILEBROWSER_IMAGE "$TARGET_IMAGE"
durable_tsv_set "$STATE_FILE" status starting-candidate
log "starting one candidate instance; Nginx remains stopped"
CANDIDATE_START_ATTEMPTED=true
maintenance_compose up -d --no-deps --scale filebrowser-enterprise=1 filebrowser-enterprise
assert_exactly_one_running filebrowser-enterprise
wait_for_service_health filebrowser-enterprise 180 || die "candidate FileBrowser failed health validation"

new_version=$(compose exec -T filebrowser-enterprise /home/filebrowser/filebrowser version | tr '\r\n\t' '   ' | sed 's/[[:space:]][[:space:]]*/ /g')
new_git_sha=$(printf '%s' "$new_version" | sed -n 's/.*Commit[[:space:]]*:[[:space:]]*\([^[:space:]]*\).*/\1/p')
new_git_sha=${new_git_sha:-unknown}
durable_tsv_set "$STATE_FILE" new_version "$new_version"
durable_tsv_set "$STATE_FILE" new_git_sha "$new_git_sha"

log "candidate is healthy; starting Nginx"
maintenance_compose up -d --no-deps --scale nginx=1 nginx
assert_exactly_one_running nginx
wait_for_service_health nginx 90 || die "Nginx failed health validation after upgrade"
"$SCRIPT_DIR/validate-deployment.sh" --production --runtime

durable_tsv_set "$STATE_FILE" status completed
durable_tsv_set "$STATE_FILE" completed_utc "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
promote_production_nginx
"$SCRIPT_DIR/validate-deployment.sh" --production --runtime
enable_production_restart_policy
UPGRADE_SUCCESS=true
log "upgrade completed: $STATE_FILE"
log "matching rollback input: $BACKUP_PATH"
