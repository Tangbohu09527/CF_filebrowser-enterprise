#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=scripts/lib/deployment-common.sh
source "$SCRIPT_DIR/lib/deployment-common.sh"

APPLY=false
GENERATE_SECRETS=false
START_NGINX=false
RESUME=false
BOOTSTRAP_SUCCEEDED=false

usage() {
  cat <<'USAGE'
Usage: bootstrap-admin.sh [--apply] [--generate-secrets] [--start-nginx] [--resume]

Default is a dry run. The first database is created with Nginx stopped, then
FileBrowser is restarted with stable JWT/TOTP secrets. A token and a probe upload
are verified across restarts. An independent emergency administrator is created.

--generate-secrets creates cryptographically random JWT/TOTP secret files only
when absent. --start-nginx is allowed only while both bind addresses are loopback.
--resume continues a failed bootstrap that retained its recovery password file.
USAGE
}

while (( $# > 0 )); do
  case "$1" in
    --apply) APPLY=true; shift ;;
    --generate-secrets) GENERATE_SECRETS=true; shift ;;
    --start-nginx) START_NGINX=true; shift ;;
    --resume) RESUME=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

deployment_init_layout
assert_no_incomplete_lifecycle_transaction
for command in docker python3 openssl flock stat fold sort wc tr sha256sum awk mktemp chown chmod mv; do
  require_command "$command"
done
python3 -c 'import yaml' >/dev/null 2>&1 || die "Python module PyYAML is required (Debian package: python3-yaml)"
filebrowser_image=$(env_get "$ENV_FILE" FILEBROWSER_IMAGE)
nginx_image=$(env_get "$ENV_FILE" NGINX_IMAGE)
validate_internal_image "$filebrowser_image" FILEBROWSER_IMAGE "$ENV_FILE"
validate_internal_image "$nginx_image" NGINX_IMAGE "$ENV_FILE"
primary_username=$(env_get "$ENV_FILE" BOOTSTRAP_ADMIN_USERNAME)
emergency_username=$(env_get "$ENV_FILE" EMERGENCY_ADMIN_USERNAME)
[[ "$primary_username" != "$emergency_username" ]] || die "bootstrap and emergency usernames must differ"
for username in "$primary_username" "$emergency_username"; do
  [[ "$username" =~ ^[A-Za-z0-9._-]+$ ]] || die "administrator username contains unsupported characters: $username"
done

python3 "$SCRIPT_DIR/lib/deployment_validation.py" --production \
  --compose "$COMPOSE_FILE" --config "$CONFIG_ROOT/config.yaml" --env "$ENV_FILE"
compose config --quiet
docker info >/dev/null 2>&1 || die "Docker Engine daemon is unavailable"
docker image inspect "$filebrowser_image" >/dev/null 2>&1 || die "pinned FileBrowser image is not present locally"
docker image inspect "$nginx_image" >/dev/null 2>&1 || die "pinned Nginx image is not present locally"

database_file="$DATA_ROOT/database.db"
bootstrap_file="$CONFIG_ROOT/secrets/bootstrap_admin_password"
bootstrap_recovery="$CONFIG_ROOT/secrets/bootstrap_admin_password.recovery"
emergency_file="$CONFIG_ROOT/secrets/emergency_admin_password"
emergency_recovery="$CONFIG_ROOT/secrets/emergency_admin_password.recovery"
jwt_file="$CONFIG_ROOT/secrets/jwt_token_secret"
totp_file="$CONFIG_ROOT/secrets/totp_secret"
fb_gid=$(env_get "$ENV_FILE" FILEBROWSER_GID)
nginx_gid=$(env_get "$ENV_FILE" NGINX_GID)

stable_secret_value() {
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

protected_admin_password_value() {
  local path=$1 label=$2 expected_gid=$3 value mode owner group first remainder unique_count
  [[ -f "$path" && ! -L "$path" && -s "$path" ]] ||
    die "$label is missing, empty, or a symlink: $path"
  if ! value=$(awk 'NR == 1 { printf "%s", $0; next } { exit 1 }' "$path"); then
    die "$label must contain exactly one line"
  fi
  [[ "$value" != *$'\r'* ]] || die "$label must not contain carriage returns"
  [[ ${#value} -ge 24 && ${#value} -le 4096 ]] ||
    die "$label must contain between 24 and 4096 characters"
  first=${value:0:1}
  remainder=${value//$first/}
  [[ -n "$remainder" ]] || die "$label contains a repeated-character placeholder"
  unique_count=$(printf '%s' "$value" | fold -w1 | sort -u | wc -l | tr -d ' ')
  (( unique_count >= 8 )) || die "$label does not contain enough character diversity"
  mode=$(stat -c '%a' "$path")
  [[ "$mode" == 440 || "$mode" == 640 ]] ||
    die "$label permissions must be 0440 or 0640, got $mode"
  owner=$(stat -c '%u' "$path")
  group=$(stat -c '%g' "$path")
  [[ "$owner" == 0 && "$group" == "$expected_gid" ]] ||
    die "$label must be owned by root:$expected_gid"
  printf '%s' "$value"
}

validate_tls_material() {
  local cert_pub key_pub key_mode
  [[ -s "$tls_cert" && ! -L "$tls_cert" ]] || die "TLS certificate is missing, empty, or a symlink: $tls_cert"
  [[ -s "$tls_key" && ! -L "$tls_key" ]] || die "TLS private key is missing, empty, or a symlink: $tls_key"
  key_mode=$(stat -c '%a' "$tls_key")
  [[ "$key_mode" == 440 || "$key_mode" == 640 ]] || die "TLS private key permissions must be 0440 or 0640, got $key_mode"
  [[ $(stat -c '%u' "$tls_key") == 0 && $(stat -c '%g' "$tls_key") == "$nginx_gid" ]] ||
    die "TLS private key must be owned by root:$nginx_gid"
  openssl x509 -in "$tls_cert" -noout -checkend 86400 >/dev/null ||
    die "TLS certificate is invalid or expires within 24 hours"
  openssl x509 -in "$tls_cert" -noout -checkhost "$public_host" >/dev/null ||
    die "TLS certificate does not cover PUBLIC_HOST"
  openssl verify -purpose sslserver -verify_hostname "$public_host" -untrusted "$tls_cert" "$tls_cert" >/dev/null ||
    die "TLS certificate chain is not trusted by the host system trust store"
  cert_pub=$(openssl x509 -in "$tls_cert" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  key_pub=$(openssl pkey -in "$tls_key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || die "TLS certificate and private key do not match"
}

service_is_running nginx && die "Nginx must be stopped before bootstrap"
service_is_running filebrowser-enterprise && die "FileBrowser must be stopped before bootstrap"
if [[ "$RESUME" == true ]]; then
  [[ -s "$database_file" ]] || die "--resume requires an existing initialized database"
  [[ -s "$bootstrap_file" || -s "$bootstrap_recovery" ]] || die "--resume requires a retained bootstrap recovery password"
else
  [[ ! -e "$database_file" || ! -s "$database_file" ]] || die "database already exists; use normal administrator recovery, not bootstrap"
fi

jwt_value=
totp_value=
if [[ "$GENERATE_SECRETS" == true && ! -e "$jwt_file" ]]; then
  log "dry-run/apply plan will generate missing stable secret: $jwt_file"
else
  jwt_value=$(stable_secret_value "$jwt_file" "JWT token secret" "$fb_gid")
fi
if [[ "$GENERATE_SECRETS" == true && ! -e "$totp_file" ]]; then
  log "dry-run/apply plan will generate missing stable secret: $totp_file"
else
  totp_value=$(stable_secret_value "$totp_file" "TOTP encryption secret" "$fb_gid")
fi
if [[ -n "$jwt_value" && -n "$totp_value" ]]; then
  [[ "$jwt_value" != "$totp_value" ]] || die "JWT and TOTP secrets must be independent"
fi

tls_cert=$(env_get "$ENV_FILE" TLS_CERT_FILE)
tls_key=$(env_get "$ENV_FILE" TLS_KEY_FILE)
public_host=$(env_get "$ENV_FILE" PUBLIC_HOST)
validate_tls_material

if [[ "$START_NGINX" == true ]]; then
  [[ $(env_get "$ENV_FILE" HTTP_BIND_ADDRESS) == 127.0.0.1 ]] || die "--start-nginx requires HTTP_BIND_ADDRESS=127.0.0.1"
  [[ $(env_get "$ENV_FILE" HTTPS_BIND_ADDRESS) == 127.0.0.1 ]] || die "--start-nginx requires HTTPS_BIND_ADDRESS=127.0.0.1"
fi

if [[ "$APPLY" == false ]]; then
  log "bootstrap dry run passed; no secret, database, user, container, or file was changed"
  exit 0
fi

require_root
acquire_lock bootstrap
acquire_lifecycle_lock
assert_no_running nginx
assert_no_running filebrowser-enterprise

create_random_file() {
  local target=$1 bytes=$2 tmp
  [[ ! -e "$target" ]] || return 0
  tmp=$(mktemp "$CONFIG_ROOT/secrets/.secret.XXXXXX")
  openssl rand -hex "$bytes" >"$tmp"
  chown "0:$fb_gid" "$tmp"
  chmod 0640 "$tmp"
  mv -- "$tmp" "$target"
}

if [[ "$GENERATE_SECRETS" == true ]]; then
  create_random_file "$jwt_file" 32
  create_random_file "$totp_file" 32
fi
jwt_value=$(stable_secret_value "$jwt_file" "JWT token secret" "$fb_gid")
totp_value=$(stable_secret_value "$totp_file" "TOTP encryption secret" "$fb_gid")
[[ "$jwt_value" != "$totp_value" ]] || die "JWT and TOTP secrets must be independent"

if [[ "$RESUME" == false ]]; then
  create_random_file "$bootstrap_file" 32
fi
if [[ -s "$bootstrap_file" ]]; then
  primary_password_file=$bootstrap_file
elif [[ -s "$bootstrap_recovery" ]]; then
  primary_password_file=$bootstrap_recovery
else
  die "bootstrap password or recovery file is missing"
fi
primary_password=$(protected_admin_password_value "$primary_password_file" "bootstrap administrator password" "$fb_gid")

bootstrap_failure() {
  local exit_status=$?
  trap - EXIT
  set +e
  if [[ "$BOOTSTRAP_SUCCEEDED" == false ]]; then
    nginx_before=$(running_container_count nginx 2>/dev/null || printf 1)
    app_before=$(running_container_count filebrowser-enterprise 2>/dev/null || printf 1)
    [[ "$nginx_before" == 0 ]] || compose stop --timeout 30 nginx >/dev/null 2>&1 || true
    [[ "$app_before" == 0 ]] || compose stop --timeout 60 filebrowser-enterprise >/dev/null 2>&1 || true
    nginx_remaining=$(running_container_count nginx 2>/dev/null || printf unknown)
    app_remaining=$(running_container_count filebrowser-enterprise 2>/dev/null || printf unknown)
    if [[ "$nginx_remaining" == 0 && "$app_remaining" == 0 ]]; then
      warn "bootstrap failed; both containers are confirmed stopped"
    else
      warn "bootstrap failed and cleanup could not confirm stop (nginx=$nginx_remaining, filebrowser=$app_remaining); isolate the host immediately"
    fi
    if [[ -s "$database_file" ]]; then
      warn "retain $bootstrap_file or $bootstrap_recovery and rerun with --resume after correcting the failure"
    fi
  fi
  exit "$exit_status"
}
trap bootstrap_failure EXIT

if [[ "$RESUME" == false ]]; then
  log "creating the first database with Nginx stopped"
  compose up -d --no-deps --scale filebrowser-enterprise=1 filebrowser-enterprise
  assert_exactly_one_running filebrowser-enterprise
  wait_for_service_health filebrowser-enterprise 180 || die "initial FileBrowser bootstrap did not become healthy"
  compose stop --timeout 60 filebrowser-enterprise
  [[ -s "$database_file" ]] || die "bootstrap did not create a database"
fi

if [[ -e "$bootstrap_file" && ! -e "$bootstrap_recovery" ]]; then
  mv -- "$bootstrap_file" "$bootstrap_recovery"
elif [[ -e "$bootstrap_file" ]]; then
  die "both bootstrap and recovery password files exist; resolve the ambiguity manually"
fi
primary_password_file=$bootstrap_recovery
primary_password=$(protected_admin_password_value "$primary_password_file" "bootstrap recovery password" "$fb_gid")

log "restarting privately with the permanent JWT and TOTP secrets"
compose up -d --no-deps --scale filebrowser-enterprise=1 filebrowser-enterprise
assert_exactly_one_running filebrowser-enterprise
wait_for_service_health filebrowser-enterprise 180 || die "stable-secret FileBrowser start failed"

login_token=$(printf '%s\n' "$primary_password" | compose exec -T -e BOOTSTRAP_ADMIN_USERNAME="$primary_username" filebrowser-enterprise sh -eu -c '
  IFS= read -r password
  cfg=/tmp/bootstrap-login-curl.conf
  trap "rm -f -- $cfg" EXIT
  umask 077
  {
    printf "url = \\"http://127.0.0.1:8080/api/auth/login?username=%s\\"\\n" "$BOOTSTRAP_ADMIN_USERNAME"
    printf "request = \\"POST\\"\\n"
    printf "header = \\"X-Password: %s\\"\\n" "$password"
    printf "fail-with-body\\n"
    printf "silent\\nshow-error\\n"
  } >"$cfg"
  curl --config "$cfg"
')
[[ "$login_token" == *.*.* ]] || die "bootstrap login did not return a JWT"

probe_id=$(openssl rand -hex 8)
probe_path="/.filebrowser-bootstrap-probe-$probe_id"
probe_body="filebrowser-bootstrap-probe-$probe_id"
printf '%s\n%s\n' "$login_token" "$probe_body" | compose exec -T -e PROBE_PATH="$probe_path" filebrowser-enterprise sh -eu -c '
  IFS= read -r token
  IFS= read -r body
  cfg=/tmp/bootstrap-upload-curl.conf
  data=/tmp/bootstrap-upload-body
  trap "rm -f -- $cfg $data" EXIT
  umask 077
  printf "%s" "$body" >"$data"
  {
    printf "url = \\"http://127.0.0.1:8080/api/resources?source=enterprise-files&path=%s\\"\\n" "$PROBE_PATH"
    printf "request = \\"PUT\\"\\n"
    printf "header = \\"Authorization: Bearer %s\\"\\n" "$token"
    printf "data-binary = \\"@%s\\"\\n" "$data"
    printf "fail-with-body\\nsilent\\nshow-error\\n"
  } >"$cfg"
  curl --config "$cfg" >/dev/null
'

log "restarting FileBrowser to verify stable token and uploaded data"
compose restart --timeout 60 filebrowser-enterprise
assert_exactly_one_running filebrowser-enterprise
wait_for_service_health filebrowser-enterprise 180 || die "FileBrowser failed the token-persistence restart"
downloaded=$(printf '%s\n' "$login_token" | compose exec -T -e PROBE_PATH="$probe_path" filebrowser-enterprise sh -eu -c '
  IFS= read -r token
  cfg=/tmp/bootstrap-download-curl.conf
  trap "rm -f -- $cfg" EXIT
  umask 077
  {
    printf "url = \\"http://127.0.0.1:8080/api/resources/download?source=enterprise-files&file=%s\\"\\n" "$PROBE_PATH"
    printf "header = \\"Authorization: Bearer %s\\"\\n" "$token"
    printf "fail-with-body\\nsilent\\nshow-error\\n"
  } >"$cfg"
  curl --config "$cfg"
')
[[ "$downloaded" == "$probe_body" ]] || die "uploaded probe did not survive restart"

if [[ -e "$emergency_file" && ! -e "$emergency_recovery" ]]; then
  mv -- "$emergency_file" "$emergency_recovery"
elif [[ -e "$emergency_file" ]]; then
  die "both emergency and recovery password files exist; resolve the ambiguity manually"
fi
create_random_file "$emergency_recovery" 32
emergency_password=$(protected_admin_password_value "$emergency_recovery" "emergency recovery password" "$fb_gid")

users_json=$(printf '%s\n' "$login_token" | compose exec -T filebrowser-enterprise sh -eu -c '
  IFS= read -r token
  cfg=/tmp/bootstrap-users-curl.conf
  trap "rm -f -- $cfg" EXIT
  umask 077
  {
    printf "url = \\"http://127.0.0.1:8080/api/users\\"\\n"
    printf "header = \\"Authorization: Bearer %s\\"\\n" "$token"
    printf "fail-with-body\\nsilent\\nshow-error\\n"
  } >"$cfg"
  curl --config "$cfg"
')
existing_emergency_id=$(printf '%s' "$users_json" | EMERGENCY_USERNAME="$emergency_username" python3 -c '
import json, os, sys
users = json.load(sys.stdin)
matches = [str(user["id"]) for user in users if user.get("username") == os.environ["EMERGENCY_USERNAME"]]
if len(matches) > 1:
    raise SystemExit("duplicate emergency administrators")
print(matches[0] if matches else "")
')

if [[ -n "$existing_emergency_id" ]]; then
  printf '%s\n%s\n' "$login_token" "$primary_password" | compose exec -T -e USER_ID="$existing_emergency_id" filebrowser-enterprise sh -eu -c '
    IFS= read -r token
    IFS= read -r actor_password
    cfg=/tmp/bootstrap-delete-user-curl.conf
    trap "rm -f -- $cfg" EXIT
    umask 077
    {
      printf "url = \\"http://127.0.0.1:8080/api/users?id=%s\\"\\n" "$USER_ID"
      printf "request = \\"DELETE\\"\\n"
      printf "header = \\"Authorization: Bearer %s\\"\\n" "$token"
      printf "header = \\"X-Password: %s\\"\\n" "$actor_password"
      printf "fail-with-body\\nsilent\\nshow-error\\n"
    } >"$cfg"
    curl --config "$cfg" >/dev/null
  '
fi

printf '%s\n%s\n%s\n' "$login_token" "$primary_password" "$emergency_password" | compose exec -T -e EMERGENCY_USERNAME="$emergency_username" filebrowser-enterprise sh -eu -c '
  IFS= read -r token
  IFS= read -r actor_password
  IFS= read -r emergency_password
  cfg=/tmp/bootstrap-create-user-curl.conf
  body=/tmp/bootstrap-create-user.json
  trap "rm -f -- $cfg $body" EXIT
  umask 077
  printf "{\\"data\\":{\\"username\\":\\"%s\\",\\"password\\":\\"%s\\",\\"loginMethod\\":\\"password\\",\\"permissions\\":{\\"admin\\":true,\\"api\\":true,\\"modify\\":true,\\"share\\":true,\\"realtime\\":true,\\"delete\\":true,\\"create\\":true,\\"browse\\":true,\\"preview\\":true,\\"download\\":true}}}" \
    "$EMERGENCY_USERNAME" "$emergency_password" >"$body"
  {
    printf "url = \\"http://127.0.0.1:8080/api/users\\"\\n"
    printf "request = \\"POST\\"\\n"
    printf "header = \\"Authorization: Bearer %s\\"\\n" "$token"
    printf "header = \\"X-Password: %s\\"\\n" "$actor_password"
    printf "header = \\"Content-Type: application/json\\"\\n"
    printf "data-binary = \\"@%s\\"\\n" "$body"
    printf "fail-with-body\\nsilent\\nshow-error\\n"
  } >"$cfg"
  curl --config "$cfg" >/dev/null
'

compose restart --timeout 60 filebrowser-enterprise
assert_exactly_one_running filebrowser-enterprise
wait_for_service_health filebrowser-enterprise 180 || die "FileBrowser failed after emergency administrator creation"

emergency_token=$(printf '%s\n' "$emergency_password" | compose exec -T -e EMERGENCY_ADMIN_USERNAME="$emergency_username" filebrowser-enterprise sh -eu -c '
  IFS= read -r password
  cfg=/tmp/emergency-login-curl.conf
  trap "rm -f -- $cfg" EXIT
  umask 077
  {
    printf "url = \\"http://127.0.0.1:8080/api/auth/login?username=%s\\"\\n" "$EMERGENCY_ADMIN_USERNAME"
    printf "request = \\"POST\\"\\n"
    printf "header = \\"X-Password: %s\\"\\n" "$password"
    printf "fail-with-body\\n"
    printf "silent\\nshow-error\\n"
  } >"$cfg"
  curl --config "$cfg"
')
[[ "$emergency_token" == *.*.* ]] || die "emergency administrator login did not return a JWT"

printf '%s\n' "$login_token" | compose exec -T -e PROBE_PATH="$probe_path" filebrowser-enterprise sh -eu -c '
  IFS= read -r token
  cfg=/tmp/bootstrap-delete-probe-curl.conf
  trap "rm -f -- $cfg" EXIT
  umask 077
  {
    printf "url = \\"http://127.0.0.1:8080/api/resources?source=enterprise-files&path=%s\\"\\n" "$PROBE_PATH"
    printf "request = \\"DELETE\\"\\n"
    printf "header = \\"Authorization: Bearer %s\\"\\n" "$token"
    printf "fail-with-body\\nsilent\\nshow-error\\n"
  } >"$cfg"
  curl --config "$cfg" >/dev/null
'

"$SCRIPT_DIR/validate-deployment.sh" --production --skip-runtime --allow-bootstrap-recovery

if [[ "$START_NGINX" == true ]]; then
  compose up -d --no-deps --scale nginx=1 nginx
  wait_for_service_health nginx 90 || die "loopback-only Nginx failed health validation"
  "$SCRIPT_DIR/validate-deployment.sh" --production --runtime --allow-bootstrap-recovery
fi

printf '\nBootstrap administrator: %s\nBootstrap one-time password: %s\n' "$primary_username" "$primary_password"
printf 'Emergency administrator: %s\nEmergency password: %s\n\n' "$emergency_username" "$emergency_password"
warn "store both passwords in the approved vault now; change the bootstrap password at first login"
warn "Nginx remains stopped unless --start-nginx was used with loopback-only binds"
rm -f -- "$bootstrap_recovery" "$emergency_recovery"
BOOTSTRAP_SUCCEEDED=true
