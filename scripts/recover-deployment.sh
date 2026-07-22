#!/usr/bin/env bash
set -Eeuo pipefail

STATE_ROOT=/var/lib/filebrowser-enterprise-lifecycle
JOURNAL=$STATE_ROOT/restore-journal.tsv

die() {
  printf '[filebrowser-enterprise-recover] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "recovery must run as root"
case $# in
  0) recovery_args=(--recover-incomplete) ;;
  1)
    [[ $1 == --apply ]] || die "usage: filebrowser-enterprise-recover [--apply]"
    recovery_args=(--recover-incomplete --apply)
    ;;
  *) die "usage: filebrowser-enterprise-recover [--apply]" ;;
esac

[[ -f "$JOURNAL" && ! -L "$JOURNAL" ]] || die "no regular restore journal exists at $JOURNAL"
[[ $(stat -c '%u:%g:%a' "$JOURNAL") == 0:0:600 ]] || die "restore journal must be root:root with mode 0600"

journal_value() {
  local key=$1
  awk -F '\t' -v key="$key" '
    $1 == key { print substr($0, length($1) + 2); count++ }
    END { if (count != 1) exit 1 }
  ' "$JOURNAL"
}

restore_id=$(journal_value restore_id) || die "restore journal ID is missing or duplicated"
deploy_root=$(journal_value deploy_root) || die "restore journal deploy_root is missing or duplicated"
[[ "$restore_id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || die "restore journal ID is invalid"
[[ "$deploy_root" == /* && "$deploy_root" != / ]] || die "restore journal deploy_root is unsafe"
[[ "$deploy_root" != *$'\n'* && "$deploy_root" != *$'\r'* && "$deploy_root" != *$'\t'* ]] ||
  die "restore journal deploy_root contains control whitespace"
[[ "/$deploy_root/" != *'/../'* && "/$deploy_root/" != *'/./'* ]] || die "restore journal deploy_root traverses directories"

original_root="${deploy_root}.pre-restore-$restore_id"
runner=
for candidate in "$original_root/scripts/restore.sh" "$deploy_root/scripts/restore.sh"; do
  script_root=$(dirname -- "$candidate")
  common_file=$script_root/lib/deployment-common.sh
  if [[ -f "$candidate" && ! -L "$candidate" && -f "$common_file" && ! -L "$common_file" ]]; then
    candidate_mode=$(stat -c '%a' "$candidate")
    common_mode=$(stat -c '%a' "$common_file")
    if [[ $(stat -c '%u' "$candidate") == 0 && $(stat -c '%u' "$common_file") == 0 ]] &&
      (( (8#$candidate_mode & 0022) == 0 )) && (( (8#$common_mode & 0022) == 0 )); then
      runner=$candidate
      break
    fi
  fi
done
[[ -n "$runner" ]] || die "no transaction-matching restore runner is available under $original_root or $deploy_root"

export DEPLOY_ROOT="$deploy_root"
exec bash "$runner" "${recovery_args[@]}"
