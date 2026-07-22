#!/bin/sh
set -eu

die() {
  printf '[container-entrypoint] ERROR: %s\n' "$*" >&2
  exit 1
}

read_secret() {
  secret_file=$1
  minimum_length=$2
  label=$3
  [ -f "$secret_file" ] || die "$label file does not exist: $secret_file"
  [ ! -L "$secret_file" ] || die "$label file must not be a symbolic link: $secret_file"
  [ -r "$secret_file" ] || die "$label file is not readable: $secret_file"
  if ! secret_value=$(awk 'NR == 1 { printf "%s", $0; next } { exit 1 }' "$secret_file"); then
    die "$label must contain exactly one line"
  fi
  carriage_return=$(printf '\r')
  case "$secret_value" in
    *"$carriage_return"*) die "$label must not contain carriage returns" ;;
  esac
  [ "${#secret_value}" -ge "$minimum_length" ] || die "$label must contain at least $minimum_length characters"
  [ "${#secret_value}" -le 4096 ] || die "$label must contain at most 4096 characters"
  printf '%s' "$secret_value"
}

config_file=${FILEBROWSER_CONFIG:-/etc/filebrowser-enterprise/config.yaml}
database_file=${FILEBROWSER_DATABASE:-/var/lib/filebrowser-enterprise/database.db}
jwt_file=${FILEBROWSER_JWT_TOKEN_SECRET_FILE:-/run/filebrowser-secrets/jwt_token_secret}
totp_file=${FILEBROWSER_TOTP_SECRET_FILE:-/run/filebrowser-secrets/totp_secret}
bootstrap_file=${FILEBROWSER_BOOTSTRAP_PASSWORD_FILE:-/run/filebrowser-secrets/bootstrap_admin_password}

[ -f "$config_file" ] && [ ! -L "$config_file" ] && [ -r "$config_file" ] && [ -s "$config_file" ] || die "configuration file is missing, unsafe, or unreadable: $config_file"
[ ! -L "$database_file" ] || die "database file must not be a symbolic link: $database_file"
[ ! -e "$database_file" ] || [ -f "$database_file" ] || die "database path is not a regular file: $database_file"
FILEBROWSER_JWT_TOKEN_SECRET=$(read_secret "$jwt_file" 32 "JWT token secret")
FILEBROWSER_TOTP_SECRET=$(read_secret "$totp_file" 32 "TOTP encryption secret")
export FILEBROWSER_JWT_TOKEN_SECRET FILEBROWSER_TOTP_SECRET

if [ "${1:-}" = "version" ]; then
  exec /home/filebrowser/filebrowser version
fi

[ "$#" -eq 0 ] || die "unsupported container command: $*"
if [ ! -s "$database_file" ]; then
  FILEBROWSER_ADMIN_PASSWORD=$(read_secret "$bootstrap_file" 24 "bootstrap administrator password")
  export FILEBROWSER_ADMIN_PASSWORD
else
  [ ! -e "$bootstrap_file" ] || die "remove the bootstrap password file before restarting an initialized database"
  unset FILEBROWSER_ADMIN_PASSWORD || true
fi

exec /home/filebrowser/filebrowser -c "$config_file"
