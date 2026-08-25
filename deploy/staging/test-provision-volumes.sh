#!/bin/sh
# Disposable root harness for provision-volumes.sh failure and retry behavior.
set -eu
umask 077

provisioner="${1:-/usr/local/bin/backupsheep-provision-staging-volumes}"
[ -x "$provisioner" ] || {
  printf '%s\n' "missing executable provisioner: $provisioner" >&2
  exit 1
}
[ "$(id -u)" = 0 ] || {
  printf '%s\n' "provisioner test requires disposable container root" >&2
  exit 1
}

installation_id='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
intent='migrate-empty-legacy-v3'
witness="$(
  printf '%s' "BackupSheep/staging-layout/v3|${installation_id}|${intent}" \
    | sha256sum | awk '{print $1}'
)"

new_case() {
  root="$1"
  mkdir -p "$root"
  for name in database files storage database-transfer files-transfer restore-transfer backup-storage legacy witness; do
    mkdir "$root/$name"
  done
}

run_case() {
  root="$1"
  candidate_witness="${2:-$witness}"
  DJANGO_SERVER=test \
  BACKUPSHEEP_INSTALLATION_ID="$installation_id" \
  BACKUPSHEEP_STAGING_LAYOUT_INTENT="$intent" \
  BACKUPSHEEP_STAGING_LAYOUT_WITNESS="$candidate_witness" \
  BACKUPSHEEP_STAGING_PROVISION_ROOT="$root" \
    "$provisioner"
}

root_base="/tmp/backupsheep-staging-provision-test.$$"
valid_root="${root_base}/valid"
new_case "$valid_root"
run_case "$valid_root"
run_case "$valid_root"
[ "$(stat -c '%u:%g:%a' "$valid_root/database")" = 10002:10002:700 ]
[ "$(stat -c '%u:%g:%a' "$valid_root/files")" = 10003:10003:700 ]
[ "$(stat -c '%u:%g:%a' "$valid_root/storage")" = 10004:10004:700 ]
[ "$(stat -c '%u:%g:%a' "$valid_root/database-transfer")" = 0:10989:3771 ]
[ "$(stat -c '%u:%g:%a' "$valid_root/files-transfer")" = 0:10991:3771 ]
[ "$(stat -c '%u:%g:%a' "$valid_root/restore-transfer")" = 0:10995:3771 ]
[ "$(stat -c '%u:%g:%a' "$valid_root/backup-storage")" = 10004:10004:700 ]

wrong_root="${root_base}/wrong-witness"
new_case "$wrong_root"
if run_case "$wrong_root" 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
  >/dev/null 2>&1; then
  printf '%s\n' "wrong staging witness unexpectedly succeeded" >&2
  exit 1
fi

capacity_root="${root_base}/capacity"
new_case "$capacity_root"
if BACKUPSHEEP_STAGING_MIN_FREE_BYTES=999999999999999999 \
    run_case "$capacity_root" >/dev/null 2>&1; then
  printf '%s\n' "impossible staging capacity reserve unexpectedly succeeded" >&2
  exit 1
fi

ambiguous_root="${root_base}/ambiguous-legacy"
new_case "$ambiguous_root"
printf '%s\n' plaintext > "$ambiguous_root/legacy/unknown.zip"
if run_case "$ambiguous_root" >/dev/null 2>&1; then
  printf '%s\n' "ambiguous legacy plaintext unexpectedly migrated" >&2
  exit 1
fi
[ -f "$ambiguous_root/legacy/unknown.zip" ] \
  || { printf '%s\n' "ambiguous legacy evidence was mutated" >&2; exit 1; }

unwitnessed_restore_root="${root_base}/unwitnessed-restore"
new_case "$unwitnessed_restore_root"
printf '%s\n' BSE1unknown > "$unwitnessed_restore_root/files-transfer/unknown.bse1"
if run_case "$unwitnessed_restore_root" >/dev/null 2>&1; then
  printf '%s\n' "unwitnessed files-transfer inventory unexpectedly migrated" >&2
  exit 1
fi
[ -f "$unwitnessed_restore_root/files-transfer/unknown.bse1" ] \
  || { printf '%s\n' "unwitnessed restore evidence was mutated" >&2; exit 1; }

storage_root="${root_base}/legacy-storage"
new_case "$storage_root"
printf '%s\n' private > "$storage_root/backup-storage/object.bse1"
chown 10001:10001 "$storage_root/backup-storage/object.bse1"
chmod 0600 "$storage_root/backup-storage/object.bse1"
run_case "$storage_root"
[ "$(stat -c '%u:%g:%a' "$storage_root/backup-storage/object.bse1")" = 10004:10004:600 ]

chmod 0750 "$valid_root/database"
if run_case "$valid_root" >/dev/null 2>&1; then
  printf '%s\n' "witnessed ownership drift was silently repaired" >&2
  exit 1
fi

printf '%s\n' "staging provisioner fail-closed tests passed"
