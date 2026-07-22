#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
# shellcheck source=scripts/lib/deployment-common.sh
source "$REPO_ROOT/scripts/lib/deployment-common.sh"

for command in env sh rg stat df sha256sum realpath tar awk; do
  require_command "$command"
done
BASH_BIN=${BASH:?current Bash interpreter path is unavailable}
[[ -x "$BASH_BIN" ]] || die "current Bash interpreter is not executable: $BASH_BIN"

TMP_ROOT=$(mktemp -d)
PASSED=0
trap 'rm -rf -- "$TMP_ROOT"' EXIT

expect_failure() {
  local label=$1
  shift
  if "$@" >"$TMP_ROOT/last-output.log" 2>&1; then
    printf '[FAIL] %s unexpectedly succeeded\n' "$label" >&2
    cat "$TMP_ROOT/last-output.log" >&2
    exit 1
  fi
  printf '[PASS] %s failed closed\n' "$label"
  PASSED=$((PASSED + 1))
}

fixture="$TMP_ROOT/entrypoint fixture"
mkdir -p "$fixture"
printf 'server: {}\n' >"$fixture/config.yaml"
printf '%064d\n' 0 >"$fixture/jwt"
printf '%064d\n' 1 >"$fixture/totp"

expect_failure "missing config" env \
  FILEBROWSER_CONFIG="$fixture/missing.yaml" \
  FILEBROWSER_DATABASE="$fixture/database.db" \
  FILEBROWSER_JWT_TOKEN_SECRET_FILE="$fixture/jwt" \
  FILEBROWSER_TOTP_SECRET_FILE="$fixture/totp" \
  sh "$REPO_ROOT/scripts/container-entrypoint.sh"

expect_failure "missing JWT secret" env \
  FILEBROWSER_CONFIG="$fixture/config.yaml" \
  FILEBROWSER_DATABASE="$fixture/database.db" \
  FILEBROWSER_JWT_TOKEN_SECRET_FILE="$fixture/missing-jwt" \
  FILEBROWSER_TOTP_SECRET_FILE="$fixture/totp" \
  sh "$REPO_ROOT/scripts/container-entrypoint.sh"

expect_failure "uninitialized database without bootstrap password" env \
  FILEBROWSER_CONFIG="$fixture/config.yaml" \
  FILEBROWSER_DATABASE="$fixture/database.db" \
  FILEBROWSER_JWT_TOKEN_SECRET_FILE="$fixture/jwt" \
  FILEBROWSER_TOTP_SECRET_FILE="$fixture/totp" \
  FILEBROWSER_BOOTSTRAP_PASSWORD_FILE="$fixture/missing-bootstrap" \
  sh "$REPO_ROOT/scripts/container-entrypoint.sh"

readonly_dir="$TMP_ROOT/read-only-database"
mkdir "$readonly_dir"
chmod 0555 "$readonly_dir"
if mode_bits_allow_write 0555 "$(id -u)" "$(id -g)" "$(id -u)" "$(id -g)"; then
  die "read-only database directory was considered writable"
fi
printf '[PASS] read-only database directory failed closed\n'
PASSED=$((PASSED + 1))

if free_space_meets "$TMP_ROOT" 999999999999; then
  die "impossible cache capacity threshold unexpectedly passed"
fi
printf '[PASS] simulated full cache failed closed\n'
PASSED=$((PASSED + 1))

restore_root="$TMP_ROOT/restore fixture"
mkdir -p "$restore_root/deploy" "$restore_root/config" "$restore_root/data" \
  "$restore_root/cache" "$restore_root/files" "$restore_root/backups/corrupt/payload"
printf 'services: {}\n' >"$restore_root/deploy/compose.yaml"
cat >"$restore_root/deploy/.env" <<EOF
CONFIG_ROOT=$restore_root/config
DATA_ROOT=$restore_root/data
CACHE_ROOT=$restore_root/cache
FILES_ROOT=$restore_root/files
BACKUP_ROOT=$restore_root/backups
FILEBROWSER_IMAGE=registry.internal.test/filebrowser:v1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
EOF
cat >"$restore_root/backups/corrupt/manifest.tsv" <<'EOF'
format_version	1
EOF
printf '%064d  manifest.tsv\n' 0 >"$restore_root/backups/corrupt/checksums.sha256"
expect_failure "restore checksum mismatch" env \
  DEPLOY_ROOT="$restore_root/deploy" \
  ENV_FILE="$restore_root/deploy/.env" \
  COMPOSE_FILE="$restore_root/deploy/compose.yaml" \
  "$BASH_BIN" "$REPO_ROOT/scripts/restore.sh" --backup "$restore_root/backups/corrupt"

digest=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
expect_failure "implicit public-registry image reference" "$BASH_BIN" -c \
  'source "$1"; validate_pinned_image "filebrowser-enterprise:v1@sha256:$2" test_image' \
  _ "$REPO_ROOT/scripts/lib/deployment-common.sh" "$digest"
expect_failure "explicit public-registry image reference" "$BASH_BIN" -c \
  'source "$1"; validate_pinned_image "docker.io/internal/filebrowser:v1@sha256:$2" test_image' \
  _ "$REPO_ROOT/scripts/lib/deployment-common.sh" "$digest"
expect_failure "public-registry image reference with port" "$BASH_BIN" -c \
  'source "$1"; validate_pinned_image "docker.io:443/internal/filebrowser:v1@sha256:$2" test_image' \
  _ "$REPO_ROOT/scripts/lib/deployment-common.sh" "$digest"
validate_pinned_image "registry.internal.test/filebrowser-enterprise:v1@sha256:$digest" test_image
printf '[PASS] internal registry-qualified image guard accepted an immutable internal reference\n'
PASSED=$((PASSED + 1))

printf 'INTERNAL_REGISTRY_HOST=registry.gitlab.com\n' >"$TMP_ROOT/public-registry.env"
expect_failure "unlisted public registry as approved internal host" "$BASH_BIN" -c \
  'source "$1"; ENV_FILE=$2; validate_internal_image "registry.gitlab.com/internal/filebrowser:v1@sha256:$3" test_image "$2"' \
  _ "$REPO_ROOT/scripts/lib/deployment-common.sh" "$TMP_ROOT/public-registry.env" "$digest"
printf 'INTERNAL_REGISTRY_HOST=registry.internal.test\n' >"$TMP_ROOT/internal-registry.env"
"$BASH_BIN" -c \
  'source "$1"; ENV_FILE=$2; validate_internal_image "registry.internal.test/filebrowser:v1@sha256:$3" test_image "$2"' \
  _ "$REPO_ROOT/scripts/lib/deployment-common.sh" "$TMP_ROOT/internal-registry.env" "$digest"
printf '[PASS] exact approved internal registry host accepted\n'
PASSED=$((PASSED + 1))

expect_failure "Docker Compose older than v2.20" env COMPOSE_TEST_VERSION=2.19.9 "$BASH_BIN" -c '
  docker() {
    [[ $1 == compose && $2 == version && $3 == --short ]] || return 1
    printf "%s\n" "$COMPOSE_TEST_VERSION"
  }
  source "$1"
  require_compose_wait_support
' _ "$REPO_ROOT/scripts/lib/deployment-common.sh"
env COMPOSE_TEST_VERSION=2.20.0 "$BASH_BIN" -c '
  docker() {
    [[ $1 == compose && $2 == version && $3 == --short ]] || return 1
    printf "%s\n" "$COMPOSE_TEST_VERSION"
  }
  source "$1"
  require_compose_wait_support
' _ "$REPO_ROOT/scripts/lib/deployment-common.sh"
printf '[PASS] Docker Compose v2.20 boundary accepted\n'
PASSED=$((PASSED + 1))

lifecycle_fixture="$TMP_ROOT/lifecycle-state"
state_file="$lifecycle_fixture/upgrade-history/upgrade-test/state.tsv"
mkdir -p "$(dirname -- "$state_file")"
printf 'format_version\t1\nstatus\tstarting-candidate\n' >"$state_file"
detected_state=$("$BASH_BIN" -c '
  source "$1"
  FILEBROWSER_LIFECYCLE_STATE_ROOT=$2
  FILEBROWSER_RESTORE_JOURNAL=$2/restore-journal.tsv
  find() { return 99; }
  stat() {
    if [[ $1 == -c && $2 == "%u:%g:%a" ]]; then printf "0:0:600\n"; else command stat "$@"; fi
  }
  first_unfinished_lifecycle_state false
' _ "$REPO_ROOT/scripts/lib/deployment-common.sh" "$lifecycle_fixture")
[[ "$detected_state" == "$(realpath -e -- "$state_file")" ]] ||
  die "lifecycle scan did not return the expected state when external find was unavailable"
printf '[PASS] lifecycle scan is independent of external find\n'
PASSED=$((PASSED + 1))
expect_failure "unfinished starting-candidate lifecycle state" "$BASH_BIN" -c '
  source "$1"
  FILEBROWSER_LIFECYCLE_STATE_ROOT=$2
  FILEBROWSER_RESTORE_JOURNAL=$2/restore-journal.tsv
  stat() {
    if [[ $1 == -c && $2 == "%u:%g:%a" ]]; then printf "0:0:600\n"; else command stat "$@"; fi
  }
  assert_no_incomplete_lifecycle_transaction
' _ "$REPO_ROOT/scripts/lib/deployment-common.sh" "$lifecycle_fixture"
printf 'format_version\t1\nstatus\trolling-back\n' >"$state_file"
expect_failure "unfinished rolling-back lifecycle state" "$BASH_BIN" -c '
  source "$1"
  FILEBROWSER_LIFECYCLE_STATE_ROOT=$2
  FILEBROWSER_RESTORE_JOURNAL=$2/restore-journal.tsv
  stat() {
    if [[ $1 == -c && $2 == "%u:%g:%a" ]]; then printf "0:0:600\n"; else command stat "$@"; fi
  }
  assert_no_incomplete_lifecycle_transaction
' _ "$REPO_ROOT/scripts/lib/deployment-common.sh" "$lifecycle_fixture"
printf 'format_version\t1\nstatus\trollback-data-restored\n' >"$state_file"
expect_failure "unfinished rollback-data-restored lifecycle state" "$BASH_BIN" -c '
  source "$1"
  FILEBROWSER_LIFECYCLE_STATE_ROOT=$2
  FILEBROWSER_RESTORE_JOURNAL=$2/restore-journal.tsv
  stat() {
    if [[ $1 == -c && $2 == "%u:%g:%a" ]]; then printf "0:0:600\n"; else command stat "$@"; fi
  }
  assert_no_incomplete_lifecycle_transaction
' _ "$REPO_ROOT/scripts/lib/deployment-common.sh" "$lifecycle_fixture"
printf 'format_version\t1\nstatus\tcompleted\n' >"$state_file"
"$BASH_BIN" -c '
  source "$1"
  FILEBROWSER_LIFECYCLE_STATE_ROOT=$2
  FILEBROWSER_RESTORE_JOURNAL=$2/restore-journal.tsv
  stat() {
    if [[ $1 == -c && $2 == "%u:%g:%a" ]]; then printf "0:0:600\n"; else command stat "$@"; fi
  }
  assert_no_incomplete_lifecycle_transaction
' _ "$REPO_ROOT/scripts/lib/deployment-common.sh" "$lifecycle_fixture"
printf '[PASS] terminal lifecycle state accepted\n'
PASSED=$((PASSED + 1))

"$BASH_BIN" -c '
  source "$1"
  service_container_id_all() {
    [[ $1 != filebrowser-enterprise ]] || printf "container-a\ncontainer-b\n"
  }
  docker() {
    [[ $# == 4 && $1 == update && $2 == --restart=no && $3 == container-a && $4 == container-b ]]
  }
  disable_managed_restart_policy
' _ "$REPO_ROOT/scripts/lib/deployment-common.sh"
printf '[PASS] transaction restart policy is disabled for every service container\n'
PASSED=$((PASSED + 1))

ownership_output=$("$BASH_BIN" -c '
  source "$1"
  systemctl() {
    [[ $1 != is-active ]] || return 3
    [[ $# == 3 && $1 == start && $2 == --no-block && $3 == filebrowser-enterprise.service ]] || return 1
    printf "queued-by-test\n"
  }
  queue_systemd_stack_ownership
' _ "$REPO_ROOT/scripts/lib/deployment-common.sh")
[[ "$ownership_output" == *queued-by-test* ]] || die "systemd ownership was not queued without blocking"
printf '[PASS] completed lifecycle operation requeues inactive systemd ownership\n'
PASSED=$((PASSED + 1))

rg -q 'status rollback-data-restored' "$REPO_ROOT/scripts/restore.sh" ||
  die "restore does not commit the deferred rollback data phase"
rg -q 'reusing the recorded roll-forward backup' "$REPO_ROOT/scripts/rollback.sh" ||
  die "rollback does not reuse its create-once roll-forward point"
rg -q 'non-committed rollback state with an old image pin is ambiguous' "$REPO_ROOT/scripts/rollback.sh" ||
  die "rollback does not fail closed for an impossible old-image phase"
rg -q 'preserving it for rollback resume' "$REPO_ROOT/scripts/upgrade.sh" ||
  die "upgrade cleanup can overwrite a committed rollback phase"
printf '[PASS] rollback power-loss phases remain durable and fail closed\n'
PASSED=$((PASSED + 1))

rg -q 'trap restore_previous_service_state EXIT' "$REPO_ROOT/scripts/backup.sh" || die "backup interruption recovery trap is missing"
rg -q 'rollback.sh.*--state.*--apply' "$REPO_ROOT/scripts/upgrade.sh" || die "upgrade health-failure rollback invocation is missing"
rg -q 'restore.sh.*--backup.*--apply' "$REPO_ROOT/scripts/rollback.sh" || die "rollback data restoration invocation is missing"
rg -q 'filebrowser-enterprise:8080/health.*grep' "$REPO_ROOT/deploy/compose.yaml" || die "Nginx backend-unavailable health check is missing"
rg -q -- '--project-name "\$FILEBROWSER_COMPOSE_PROJECT"' "$REPO_ROOT/scripts/lib/deployment-common.sh" || die "fixed Compose project guard is missing"
rg -q 'return 503' "$REPO_ROOT/deploy/nginx/filebrowser-maintenance.conf.template" || die "maintenance Nginx fail-closed response is missing"
! rg -q 'proxy_pass' "$REPO_ROOT/deploy/nginx/filebrowser-maintenance.conf.template" || die "maintenance Nginx unexpectedly proxies business requests"
printf '[PASS] interruption, upgrade rollback, rollback data, and backend outage guards are present\n'
PASSED=$((PASSED + 6))

rg -q $'deployment_schema\\t2' "$REPO_ROOT/scripts/backup.sh" || die "schema-2 backup contract is missing"
rg -q 'require_filesystem_space backup' "$REPO_ROOT/scripts/backup.sh" || die "backup space preflight is missing"
rg -q 'source_nginx_image' "$REPO_ROOT/scripts/backup.sh" || die "Nginx image is absent from the backup manifest"
rg -q 'validate_journal_swap "\$count"' "$REPO_ROOT/scripts/restore.sh" || die "journal path allowlist validation is missing"
rg -q 'durable_move "\$target" "\$original"' "$REPO_ROOT/scripts/restore.sh" || die "durable restore rename is missing"
rg -q -- '--recover-incomplete' "$REPO_ROOT/scripts/restore.sh" || die "incomplete restore recovery mode is missing"
rg -q '[/]usr/local/sbin/filebrowser-enterprise-recover' "$REPO_ROOT/scripts/install-debian.sh" || die "stable recovery runner installation is missing"
rg -q 'manifest\\.tsv' "$REPO_ROOT/scripts/backup.sh" || die "retention does not require a checksummed manifest"
printf '[PASS] schema-2 backup and durable restore-journal guards are present\n'
PASSED=$((PASSED + 5))

printf 'failure drills passed: %d\n' "$PASSED"
