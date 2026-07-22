#!/bin/sh
set -eu

die() {
  printf '[nginx-entrypoint] ERROR: %s\n' "$*" >&2
  exit 1
}

: "${PUBLIC_HOST:?PUBLIC_HOST is required}"
: "${MAX_UPLOAD_SIZE:?MAX_UPLOAD_SIZE is required}"
: "${CLIENT_BODY_TIMEOUT:?CLIENT_BODY_TIMEOUT is required}"
: "${PROXY_READ_TIMEOUT:?PROXY_READ_TIMEOUT is required}"
: "${PROXY_SEND_TIMEOUT:?PROXY_SEND_TIMEOUT is required}"
: "${AUTH_RATE:?AUTH_RATE is required}"
: "${AUTH_BURST:?AUTH_BURST is required}"
: "${AUTH_GLOBAL_RATE:?AUTH_GLOBAL_RATE is required}"
: "${AUTH_GLOBAL_BURST:?AUTH_GLOBAL_BURST is required}"
: "${TLS_CERT_CONTAINER_PATH:?TLS_CERT_CONTAINER_PATH is required}"
: "${TLS_KEY_CONTAINER_PATH:?TLS_KEY_CONTAINER_PATH is required}"

case "$PUBLIC_HOST" in
  *[!a-z0-9.-]*|.*|*..*|*.|-*|*-|*.-*|*-.*) die "PUBLIC_HOST must be a lowercase DNS hostname" ;;
esac
[ "${#PUBLIC_HOST}" -le 253 ] || die "PUBLIC_HOST exceeds the DNS name length limit"
host_remainder=$PUBLIC_HOST
while [ -n "$host_remainder" ]; do
  case "$host_remainder" in
    *.*) host_label=${host_remainder%%.*}; host_remainder=${host_remainder#*.} ;;
    *) host_label=$host_remainder; host_remainder= ;;
  esac
  [ "${#host_label}" -le 63 ] || die "PUBLIC_HOST contains a DNS label longer than 63 characters"
done

validate_pattern() {
  value=$1
  pattern=$2
  label=$3
  printf '%s\n' "$value" | grep -Eq "$pattern" || die "$label has an invalid value: $value"
}

validate_pattern "$MAX_UPLOAD_SIZE" '^[1-9][0-9]*[kKmMgG]$' MAX_UPLOAD_SIZE
validate_pattern "$CLIENT_BODY_TIMEOUT" '^[1-9][0-9]*[smh]$' CLIENT_BODY_TIMEOUT
validate_pattern "$PROXY_READ_TIMEOUT" '^[1-9][0-9]*[smh]$' PROXY_READ_TIMEOUT
validate_pattern "$PROXY_SEND_TIMEOUT" '^[1-9][0-9]*[smh]$' PROXY_SEND_TIMEOUT
validate_pattern "$AUTH_RATE" '^[1-9][0-9]*r/[ms]$' AUTH_RATE
validate_pattern "$AUTH_GLOBAL_RATE" '^[1-9][0-9]*r/[ms]$' AUTH_GLOBAL_RATE
case "$AUTH_BURST" in
  ''|*[!0-9]*) die "AUTH_BURST must be an integer" ;;
esac
[ "$AUTH_BURST" -gt 0 ] || die "AUTH_BURST must be positive"
case "$AUTH_GLOBAL_BURST" in
  ''|*[!0-9]*) die "AUTH_GLOBAL_BURST must be an integer" ;;
esac
[ "$AUTH_GLOBAL_BURST" -gt 0 ] || die "AUTH_GLOBAL_BURST must be positive"
[ "$TLS_CERT_CONTAINER_PATH" = /etc/nginx/tls/tls.crt ] || die "TLS certificate path must be /etc/nginx/tls/tls.crt"
[ "$TLS_KEY_CONTAINER_PATH" = /etc/nginx/tls/tls.key ] || die "TLS private key path must be /etc/nginx/tls/tls.key"
for tls_file in "$TLS_CERT_CONTAINER_PATH" "$TLS_KEY_CONTAINER_PATH"; do
  [ -f "$tls_file" ] && [ ! -L "$tls_file" ] && [ -r "$tls_file" ] && [ -s "$tls_file" ] || die "TLS file is missing, unsafe, or unreadable: $tls_file"
done
[ -f /etc/nginx/templates/filebrowser.conf.template ] && [ ! -L /etc/nginx/templates/filebrowser.conf.template ] && [ -r /etc/nginx/templates/filebrowser.conf.template ] && [ -s /etc/nginx/templates/filebrowser.conf.template ] || die "Nginx template is missing, unsafe, or unreadable"

export PUBLIC_HOST MAX_UPLOAD_SIZE CLIENT_BODY_TIMEOUT PROXY_READ_TIMEOUT
export PROXY_SEND_TIMEOUT AUTH_RATE AUTH_BURST AUTH_GLOBAL_RATE AUTH_GLOBAL_BURST
export TLS_CERT_CONTAINER_PATH TLS_KEY_CONTAINER_PATH
envsubst '${PUBLIC_HOST} ${MAX_UPLOAD_SIZE} ${CLIENT_BODY_TIMEOUT} ${PROXY_READ_TIMEOUT} ${PROXY_SEND_TIMEOUT} ${AUTH_RATE} ${AUTH_BURST} ${AUTH_GLOBAL_RATE} ${AUTH_GLOBAL_BURST} ${TLS_CERT_CONTAINER_PATH} ${TLS_KEY_CONTAINER_PATH}' \
  </etc/nginx/templates/filebrowser.conf.template >/tmp/filebrowser.conf

nginx -t -c /etc/nginx/nginx.conf
if [ "$#" -eq 0 ]; then
  set -- nginx -c /etc/nginx/nginx.conf -g 'daemon off;'
fi
exec "$@"
