#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
# shellcheck source=scripts/lib/deployment-common.sh
source "$SCRIPT_DIR/lib/deployment-common.sh"

DRY_RUN=false
ENABLE_UNITS=false
SOURCE_ROOT=$REPO_ROOT
INPUT_ENV_FILE=
INPUT_CONFIG_FILE=
INPUT_TLS_CERT=
INPUT_TLS_KEY=
FB_USER=filebrowser-enterprise
FB_GROUP=filebrowser-enterprise
NGINX_USER=filebrowser-nginx
NGINX_GROUP=filebrowser-nginx
DEPLOY_ROOT=/opt/filebrowser-enterprise
CONFIG_ROOT=/etc/filebrowser-enterprise
DATA_ROOT=/var/lib/filebrowser-enterprise
CACHE_ROOT=/var/cache/filebrowser-enterprise
FILES_ROOT=/srv/filebrowser/files
BACKUP_ROOT=/var/backups/filebrowser-enterprise
ROLLBACK_DIR=
INSTALL_COMPLETE=false
SYSTEMD_RELOADED=false
ENABLE_ATTEMPTED=false
FB_WAS_ENABLED=false
TIMER_WAS_ENABLED=false
declare -a ROLLBACK_TARGETS=()
declare -a ROLLBACK_COPIES=()
declare -A TRACKED_TARGETS=()

usage() {
  cat <<'USAGE'
Usage: install-debian.sh [options]

Options:
  --source-root PATH   Repository checkout containing deploy/ and scripts/.
  --env-file PATH     Install a completed production environment file.
  --config-file PATH  Install a completed FileBrowser config file.
  --tls-cert PATH     Install an existing TLS certificate.
  --tls-key PATH      Install the matching TLS private key.
  --enable            Enable the stack and backup timer after validation; do not start them.
  --dry-run           Print actions without changing the host.
  -h, --help          Show this help.

The script never generates a password, opens a firewall, or starts the stack.
USAGE
}

while (( $# > 0 )); do
  case "$1" in
    --source-root|--env-file|--config-file|--tls-cert|--tls-key)
      (( $# >= 2 )) || die "missing value for $1"
      [[ -n "$2" ]] || die "empty value for $1"
      case "$1" in
        --source-root) SOURCE_ROOT=$2 ;;
        --env-file) INPUT_ENV_FILE=$2 ;;
        --config-file) INPUT_CONFIG_FILE=$2 ;;
        --tls-cert) INPUT_TLS_CERT=$2 ;;
        --tls-key) INPUT_TLS_KEY=$2 ;;
      esac
      shift 2
      ;;
    --enable) ENABLE_UNITS=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

run() {
  if [[ "$DRY_RUN" == true ]]; then
    printf '[dry-run]'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

rollback_install() {
  local i target backup
  [[ "$INSTALL_COMPLETE" == false && "$DRY_RUN" == false ]] || return 0
  warn "installation failed; restoring files replaced during this run"
  for (( i=${#ROLLBACK_TARGETS[@]}-1; i>=0; i-- )); do
    target=${ROLLBACK_TARGETS[$i]}
    backup=${ROLLBACK_COPIES[$i]}
    if [[ "$backup" == NEW ]]; then
      rm -f -- "$target"
    else
      rm -f -- "$target"
      cp -a -- "$backup" "$target"
    fi
  done
}

cleanup() {
  [[ -z "$ROLLBACK_DIR" || ! -d "$ROLLBACK_DIR" ]] || rm -rf -- "$ROLLBACK_DIR"
}

finish_install() {
  local exit_status=$?
  trap - EXIT ERR
  if (( exit_status != 0 )); then
    rollback_install
    if [[ "$ENABLE_ATTEMPTED" == true && "$DRY_RUN" == false ]]; then
      if [[ "$FB_WAS_ENABLED" == true ]]; then
        systemctl enable filebrowser-enterprise.service >/dev/null 2>&1 || true
      else
        systemctl disable filebrowser-enterprise.service >/dev/null 2>&1 || true
      fi
      if [[ "$TIMER_WAS_ENABLED" == true ]]; then
        systemctl enable filebrowser-enterprise-backup.timer >/dev/null 2>&1 || true
      else
        systemctl disable filebrowser-enterprise-backup.timer >/dev/null 2>&1 || true
      fi
    fi
    if [[ "$SYSTEMD_RELOADED" == true && "$DRY_RUN" == false ]]; then
      systemctl daemon-reload >/dev/null 2>&1 || true
    fi
  fi
  cleanup
  exit "$exit_status"
}
trap finish_install EXIT

if [[ -r /etc/os-release ]]; then
  # /etc/os-release is a trusted operating-system file.
  # shellcheck disable=SC1091
  source /etc/os-release
else
  die "/etc/os-release is missing; Debian cannot be verified"
fi
[[ ${ID:-} == debian ]] || die "unsupported operating system: ${ID:-unknown}; Debian is required"
debian_version=${VERSION_ID:-}
case ${debian_version%%.*} in
  12|13) ;;
  *) die "unsupported Debian release: ${debian_version:-unknown}; supported releases are 12 and 13" ;;
esac

if [[ "$DRY_RUN" == false ]]; then
  require_root
fi
for command in install getent docker python3 groupadd useradd id awk mktemp systemctl flock fuser \
  openssl tar sha256sum realpath mountpoint sync find sort xargs du stat df fold wc tr timeout grep env; do
  require_command "$command"
done
python3 -c 'import yaml' >/dev/null 2>&1 || die "Python module PyYAML is required (Debian package: python3-yaml)"
require_compose_wait_support
if [[ "$DRY_RUN" == false ]]; then
  docker info >/dev/null 2>&1 || die "Docker Engine daemon is unavailable"
  LOCK_ROOT=/run/lock/filebrowser-enterprise
  acquire_lifecycle_lock
  if [[ -f "$DEPLOY_ROOT/.env" && -f "$DEPLOY_ROOT/compose.yaml" ]]; then
    ENV_FILE=$DEPLOY_ROOT/.env
    COMPOSE_FILE=$DEPLOY_ROOT/compose.yaml
    deployment_init_layout
    assert_no_incomplete_lifecycle_transaction
    assert_no_running nginx
    assert_no_running filebrowser-enterprise
  fi
else
  log "dry-run does not access the Docker socket; apply will refuse to update a running stack"
fi

for required in \
  deploy/compose.yaml deploy/compose.build.yaml deploy/compose.maintenance.yaml deploy/compose.env.example deploy/config.yaml.example \
  deploy/nginx/nginx.conf deploy/nginx/filebrowser.conf.template deploy/nginx/filebrowser-maintenance.conf.template \
  deploy/systemd/filebrowser-enterprise.service \
  deploy/systemd/filebrowser-enterprise-backup.service \
  deploy/systemd/filebrowser-enterprise-backup.timer \
  scripts/container-entrypoint.sh scripts/nginx-entrypoint.sh \
  scripts/validate-deployment.sh scripts/backup.sh scripts/restore.sh \
  scripts/upgrade.sh scripts/rollback.sh scripts/bootstrap-admin.sh scripts/stack.sh scripts/recover-deployment.sh \
  scripts/lib/deployment-common.sh scripts/lib/deployment_validation.py; do
  [[ -f "$SOURCE_ROOT/$required" ]] || die "required deployment asset is missing: $SOURCE_ROOT/$required"
done

[[ -z "$INPUT_ENV_FILE" || -f "$INPUT_ENV_FILE" ]] || die "input environment file does not exist: $INPUT_ENV_FILE"
[[ -z "$INPUT_CONFIG_FILE" || -f "$INPUT_CONFIG_FILE" ]] || die "input config file does not exist: $INPUT_CONFIG_FILE"
[[ -z "$INPUT_TLS_CERT" || -f "$INPUT_TLS_CERT" ]] || die "TLS certificate does not exist: $INPUT_TLS_CERT"
[[ -z "$INPUT_TLS_KEY" || -f "$INPUT_TLS_KEY" ]] || die "TLS private key does not exist: $INPUT_TLS_KEY"
if [[ ( -z "$INPUT_TLS_CERT" && -n "$INPUT_TLS_KEY" ) || ( -n "$INPUT_TLS_CERT" && -z "$INPUT_TLS_KEY" ) ]]; then
  die "--tls-cert and --tls-key must be provided together"
fi

ROLLBACK_DIR=$(mktemp -d)

ensure_group() {
  local group=$1
  getent group "$group" >/dev/null 2>&1 || run groupadd --system "$group"
}

ensure_user() {
  local user=$1 group=$2 expected_gid actual_gid shell
  if ! getent passwd "$user" >/dev/null 2>&1; then
    run useradd --system --gid "$group" --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$user"
  else
    expected_gid=$(getent group "$group" | awk -F: '{print $3}')
    actual_gid=$(id -g "$user")
    [[ "$actual_gid" == "$expected_gid" ]] || die "existing user $user does not use primary group $group"
    shell=$(getent passwd "$user" | awk -F: '{print $7}')
    [[ "$shell" == /usr/sbin/nologin || "$shell" == /bin/false ]] || die "existing service user $user has a login shell"
  fi
}

track_target() {
  local target=$1 index backup
  if [[ "$DRY_RUN" == false ]]; then
    [[ -z ${TRACKED_TARGETS[$target]:-} ]] || return 0
    TRACKED_TARGETS[$target]=1
    index=${#ROLLBACK_TARGETS[@]}
    if [[ -e "$target" || -L "$target" ]]; then
      backup="$ROLLBACK_DIR/$index"
      cp -a -- "$target" "$backup"
      ROLLBACK_COPIES+=("$backup")
    else
      ROLLBACK_COPIES+=(NEW)
    fi
    ROLLBACK_TARGETS+=("$target")
  fi
}

install_file() {
  local source=$1 target=$2 mode=$3 owner=$4 group=$5
  track_target "$target"
  run install -D -m "$mode" -o "$owner" -g "$group" "$source" "$target"
}

ensure_group "$FB_GROUP"
ensure_user "$FB_USER" "$FB_GROUP"
ensure_group "$NGINX_GROUP"
ensure_user "$NGINX_USER" "$NGINX_GROUP"

run install -d -m 0755 -o root -g root "$DEPLOY_ROOT" "$DEPLOY_ROOT/nginx" "$DEPLOY_ROOT/systemd" "$DEPLOY_ROOT/scripts" "$DEPLOY_ROOT/scripts/lib"
run install -d -m 0750 -o root -g "$FB_GROUP" "$CONFIG_ROOT" "$CONFIG_ROOT/secrets"
run install -d -m 0750 -o root -g "$NGINX_GROUP" "$CONFIG_ROOT/tls"
run install -d -m 0750 -o "$FB_USER" -g "$FB_GROUP" "$DATA_ROOT" "$CACHE_ROOT" "$FILES_ROOT"
run install -d -m 0750 -o root -g "$FB_GROUP" "$BACKUP_ROOT"
run install -d -m 0755 -o root -g root /run/lock/filebrowser-enterprise
[[ ! -L "$FILEBROWSER_LIFECYCLE_STATE_ROOT" ]] || die "lifecycle state root must not be a symlink"
run install -d -m 0700 -o root -g root "$FILEBROWSER_LIFECYCLE_STATE_ROOT"

install_file "$SOURCE_ROOT/deploy/compose.yaml" "$DEPLOY_ROOT/compose.yaml" 0644 root root
install_file "$SOURCE_ROOT/deploy/compose.maintenance.yaml" "$DEPLOY_ROOT/compose.maintenance.yaml" 0644 root root
install_file "$SOURCE_ROOT/deploy/nginx/nginx.conf" "$DEPLOY_ROOT/nginx/nginx.conf" 0644 root root
install_file "$SOURCE_ROOT/deploy/nginx/filebrowser.conf.template" "$DEPLOY_ROOT/nginx/filebrowser.conf.template" 0644 root root
install_file "$SOURCE_ROOT/deploy/nginx/filebrowser-maintenance.conf.template" "$DEPLOY_ROOT/nginx/filebrowser-maintenance.conf.template" 0644 root root

for script in container-entrypoint.sh nginx-entrypoint.sh validate-deployment.sh backup.sh restore.sh upgrade.sh rollback.sh bootstrap-admin.sh stack.sh recover-deployment.sh; do
  install_file "$SOURCE_ROOT/scripts/$script" "$DEPLOY_ROOT/scripts/$script" 0755 root root
done
install_file "$SOURCE_ROOT/scripts/recover-deployment.sh" /usr/local/sbin/filebrowser-enterprise-recover 0755 root root
install_file "$SOURCE_ROOT/scripts/lib/deployment-common.sh" "$DEPLOY_ROOT/scripts/lib/deployment-common.sh" 0644 root root
install_file "$SOURCE_ROOT/scripts/lib/deployment_validation.py" "$DEPLOY_ROOT/scripts/lib/deployment_validation.py" 0644 root root

if [[ -n "$INPUT_ENV_FILE" ]]; then
  install_file "$INPUT_ENV_FILE" "$DEPLOY_ROOT/.env" 0640 root "$FB_GROUP"
elif [[ ! -e "$DEPLOY_ROOT/.env" ]]; then
  install_file "$SOURCE_ROOT/deploy/compose.env.example" "$DEPLOY_ROOT/.env" 0640 root "$FB_GROUP"
fi

if [[ -n "$INPUT_CONFIG_FILE" ]]; then
  install_file "$INPUT_CONFIG_FILE" "$CONFIG_ROOT/config.yaml" 0640 root "$FB_GROUP"
elif [[ ! -e "$CONFIG_ROOT/config.yaml" ]]; then
  install_file "$SOURCE_ROOT/deploy/config.yaml.example" "$CONFIG_ROOT/config.yaml" 0640 root "$FB_GROUP"
fi

if [[ -n "$INPUT_TLS_CERT" ]]; then
  install_file "$INPUT_TLS_CERT" "$CONFIG_ROOT/tls/tls.crt" 0644 root "$NGINX_GROUP"
  install_file "$INPUT_TLS_KEY" "$CONFIG_ROOT/tls/tls.key" 0640 root "$NGINX_GROUP"
fi

for unit in filebrowser-enterprise.service filebrowser-enterprise-backup.service filebrowser-enterprise-backup.timer; do
  install_file "$SOURCE_ROOT/deploy/systemd/$unit" "$DEPLOY_ROOT/systemd/$unit" 0644 root root
  install_file "$SOURCE_ROOT/deploy/systemd/$unit" "/etc/systemd/system/$unit" 0644 root root
done

if [[ "$DRY_RUN" == false ]]; then
  track_target "$DEPLOY_ROOT/.env"
  fb_uid=$(id -u "$FB_USER")
  fb_gid=$(getent group "$FB_GROUP" | awk -F: '{print $3}')
  nginx_uid=$(id -u "$NGINX_USER")
  nginx_gid=$(getent group "$NGINX_GROUP" | awk -F: '{print $3}')
  env_set "$DEPLOY_ROOT/.env" DEPLOY_ROOT "$DEPLOY_ROOT"
  env_set "$DEPLOY_ROOT/.env" CONFIG_ROOT "$CONFIG_ROOT"
  env_set "$DEPLOY_ROOT/.env" DATA_ROOT "$DATA_ROOT"
  env_set "$DEPLOY_ROOT/.env" CACHE_ROOT "$CACHE_ROOT"
  env_set "$DEPLOY_ROOT/.env" FILES_ROOT "$FILES_ROOT"
  env_set "$DEPLOY_ROOT/.env" BACKUP_ROOT "$BACKUP_ROOT"
  env_set "$DEPLOY_ROOT/.env" FILEBROWSER_UID "$fb_uid"
  env_set "$DEPLOY_ROOT/.env" FILEBROWSER_GID "$fb_gid"
  env_set "$DEPLOY_ROOT/.env" NGINX_UID "$nginx_uid"
  env_set "$DEPLOY_ROOT/.env" NGINX_GID "$nginx_gid"
  SYSTEMD_RELOADED=true
  systemctl daemon-reload
else
  log "dry-run uses existing or example UID/GID values because service users are not created"
fi

if [[ "$ENABLE_UNITS" == true ]]; then
  [[ "$DRY_RUN" == true ]] || "$DEPLOY_ROOT/scripts/validate-deployment.sh" --production
  if [[ "$DRY_RUN" == false ]]; then
    systemctl is-enabled --quiet filebrowser-enterprise.service && FB_WAS_ENABLED=true
    systemctl is-enabled --quiet filebrowser-enterprise-backup.timer && TIMER_WAS_ENABLED=true
    ENABLE_ATTEMPTED=true
  fi
  run systemctl enable filebrowser-enterprise.service filebrowser-enterprise-backup.timer
fi

INSTALL_COMPLETE=true
if [[ "$DRY_RUN" == true ]]; then
  log "installation dry run completed; no deployment asset, account, directory, or unit was changed"
else
  log "deployment assets installed; the stack was not started"
  log "configure $DEPLOY_ROOT/.env, $CONFIG_ROOT/config.yaml, TLS, and secrets before running validation"
fi
