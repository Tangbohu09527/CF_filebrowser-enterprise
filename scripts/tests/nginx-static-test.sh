#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
TMP_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TMP_ROOT"' EXIT

for command in nginx envsubst openssl sed; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'required command is missing: %s\n' "$command" >&2
    exit 1
  }
done

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=files.internal.test' \
  -addext 'subjectAltName=DNS:files.internal.test' \
  -keyout "$TMP_ROOT/tls.key" -out "$TMP_ROOT/tls.crt" >/dev/null 2>&1

export PUBLIC_HOST=files.internal.test
export MAX_UPLOAD_SIZE=20g
export CLIENT_BODY_TIMEOUT=3600s
export PROXY_READ_TIMEOUT=3600s
export PROXY_SEND_TIMEOUT=3600s
export AUTH_RATE=3r/m
export AUTH_BURST=2
export AUTH_GLOBAL_RATE=8r/m
export AUTH_GLOBAL_BURST=4
export TLS_CERT_CONTAINER_PATH="$TMP_ROOT/tls.crt"
export TLS_KEY_CONTAINER_PATH="$TMP_ROOT/tls.key"

envsubst '${PUBLIC_HOST} ${MAX_UPLOAD_SIZE} ${CLIENT_BODY_TIMEOUT} ${PROXY_READ_TIMEOUT} ${PROXY_SEND_TIMEOUT} ${AUTH_RATE} ${AUTH_BURST} ${AUTH_GLOBAL_RATE} ${AUTH_GLOBAL_BURST} ${TLS_CERT_CONTAINER_PATH} ${TLS_KEY_CONTAINER_PATH}' \
  <"$REPO_ROOT/deploy/nginx/filebrowser.conf.template" \
  | sed 's/server filebrowser-enterprise:8080;/server 127.0.0.1:8080;/' \
  >"$TMP_ROOT/filebrowser.conf"

escaped_include=${TMP_ROOT//\/\\}
sed "s|include /tmp/filebrowser.conf;|include $escaped_include/filebrowser.conf;|" \
  "$REPO_ROOT/deploy/nginx/nginx.conf" >"$TMP_ROOT/nginx.conf"
nginx -t -c "$TMP_ROOT/nginx.conf"

envsubst '${PUBLIC_HOST} ${TLS_CERT_CONTAINER_PATH} ${TLS_KEY_CONTAINER_PATH}' \
  <"$REPO_ROOT/deploy/nginx/filebrowser-maintenance.conf.template" \
  >"$TMP_ROOT/filebrowser-maintenance.conf"
sed "s|include /tmp/filebrowser.conf;|include $escaped_include/filebrowser-maintenance.conf;|" \
  "$REPO_ROOT/deploy/nginx/nginx.conf" >"$TMP_ROOT/nginx-maintenance.conf"
nginx -t -c "$TMP_ROOT/nginx-maintenance.conf"
