#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=scripts/lib/deployment-common.sh
source "$SCRIPT_DIR/lib/deployment-common.sh"

ACTION=${1:-}
[[ $# -eq 1 ]] || die "usage: stack.sh {start|reload|stop}"
case "$ACTION" in
  start|reload|stop) ;;
  *) die "usage: stack.sh {start|reload|stop}" ;;
esac

deployment_init_layout
require_root
require_command docker
require_command flock
require_compose_wait_support
acquire_lifecycle_lock 240

assert_at_most_one_running filebrowser-enterprise
assert_at_most_one_running nginx

if [[ "$ACTION" == stop ]]; then
  log "stopping Nginx before FileBrowser"
  compose stop --timeout 30 nginx
  assert_no_running nginx
  compose stop --timeout 60 filebrowser-enterprise
  assert_no_running filebrowser-enterprise
  log "FileBrowser Enterprise stack stopped"
  exit 0
fi

STACK_SUCCESS=false
STACK_CHANGE_ATTEMPTED=false
[[ "$ACTION" == start ]] && STACK_CHANGE_ATTEMPTED=true

stop_failed_stack() {
  local exit_status=$? nginx_count app_count
  trap - EXIT
  if [[ "$STACK_SUCCESS" == false && "$STACK_CHANGE_ATTEMPTED" == true ]]; then
    set +e
    warn "$ACTION failed; stopping the stack to avoid leaving a partially validated public entry point"
    compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    compose stop --timeout 60 filebrowser-enterprise >/dev/null 2>&1 || true
    nginx_count=$(running_container_count nginx 2>/dev/null || printf unknown)
    app_count=$(running_container_count filebrowser-enterprise 2>/dev/null || printf unknown)
    if [[ "$nginx_count" != 0 || "$app_count" != 0 ]]; then
      warn "failed stack cleanup could not confirm a full stop (nginx=$nginx_count, filebrowser=$app_count)"
    fi
  fi
  exit "$exit_status"
}
trap stop_failed_stack EXIT

assert_no_incomplete_lifecycle_transaction
"$SCRIPT_DIR/validate-deployment.sh" --production --skip-runtime

if [[ "$ACTION" == reload ]]; then
  STACK_CHANGE_ATTEMPTED=true
  log "stopping Nginx before FileBrowser so updated configuration and TLS material are reloaded"
  compose stop --timeout 30 nginx
  assert_no_running nginx
  compose stop --timeout 60 filebrowser-enterprise
  assert_no_running filebrowser-enterprise
fi

log "starting the singleton Compose stack and waiting for container health"
STACK_CHANGE_ATTEMPTED=true
compose up -d --remove-orphans --wait --wait-timeout 300 \
  --scale filebrowser-enterprise=1 --scale nginx=1
assert_exactly_one_running filebrowser-enterprise
assert_exactly_one_running nginx
wait_for_service_health filebrowser-enterprise 180 || die "FileBrowser did not become healthy"
wait_for_service_health nginx 90 || die "Nginx did not become healthy"
"$SCRIPT_DIR/validate-deployment.sh" --production --runtime
STACK_SUCCESS=true
log "FileBrowser Enterprise stack is healthy"
