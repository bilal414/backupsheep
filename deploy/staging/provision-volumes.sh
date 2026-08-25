#!/bin/sh
# One-shot, witness-gated ownership provisioning for staging volumes.
#
# This script never classifies or moves legacy files.  A pre-isolation work volume
# can contain database dumps, website material, credentials, logs, or partial ZIPs
# under indistinguishable names and one historical UID.  Treating those files as a
# particular lane would be a security guess, so an existing non-empty legacy volume
# blocks the upgrade until the operator drains/quarantines it deliberately.
set -eu
umask 077

fail() {
  printf '%s\n' "BackupSheep staging ownership migration refused: $*" >&2
  exit 1
}

[ "$(id -u)" = 0 ] || fail "the one-shot provisioner must run as container root."
[ "$(id -g)" = 0 ] || fail "the one-shot provisioner must use root as its primary group."

installation_id="${BACKUPSHEEP_INSTALLATION_ID:-}"
case "$installation_id" in
  ''|*[!0-9a-f]* ) fail "the installation identity is invalid." ;;
esac
[ "${#installation_id}" = 64 ] || fail "the installation identity is invalid."

intent="${BACKUPSHEEP_STAGING_LAYOUT_INTENT:-}"
case "$intent" in
  new-empty-v3|migrate-empty-legacy-v3) ;;
  *) fail "the staging layout intent is missing or unsupported." ;;
esac

witness="${BACKUPSHEEP_STAGING_LAYOUT_WITNESS:-}"
case "$witness" in
  ''|*[!0-9a-f]* ) fail "the staging layout witness is invalid." ;;
esac
[ "${#witness}" = 64 ] || fail "the staging layout witness is invalid."

minimum_free_bytes="${BACKUPSHEEP_STAGING_MIN_FREE_BYTES:-536870912}"
minimum_free_inodes="${BACKUPSHEEP_STAGING_MIN_FREE_INODES:-1024}"
for capacity_value in "$minimum_free_bytes" "$minimum_free_inodes"; do
  case "$capacity_value" in
    ''|*[!0-9]*) fail "staging capacity reserves must be non-negative integers." ;;
  esac
  [ "${#capacity_value}" -le 18 ] \
    || fail "a staging capacity reserve exceeds the supported bound."
done
if [ "${DJANGO_SERVER:-prod}" = prod ]; then
  [ "$minimum_free_bytes" -ge 67108864 ] \
    || fail "the production staging byte reserve must be at least 64 MiB."
  [ "$minimum_free_inodes" -ge 128 ] \
    || fail "the production staging inode reserve must be at least 128."
fi

expected_witness="$(
  printf '%s' "BackupSheep/staging-layout/v3|${installation_id}|${intent}" \
    | sha256sum | awk '{print $1}'
)"
[ "$witness" = "$expected_witness" ] \
  || fail "the staging layout witness does not authorize this installation and intent."

provision_root="${BACKUPSHEEP_STAGING_PROVISION_ROOT:-/volumes}"
if [ "${DJANGO_SERVER:-prod}" = prod ] && [ "$provision_root" != /volumes ]; then
  fail "the stock production provision root cannot be overridden."
fi
case "$provision_root" in
  /*) ;;
  *) fail "the provision root must be absolute." ;;
esac

database_root="${provision_root}/database"
files_root="${provision_root}/files"
storage_root="${provision_root}/storage"
database_transfer_root="${provision_root}/database-transfer"
files_transfer_root="${provision_root}/files-transfer"
restore_transfer_root="${provision_root}/restore-transfer"
backup_storage_root="${provision_root}/backup-storage"
legacy_root="${provision_root}/legacy"
witness_root="${provision_root}/witness"
witness_file="${witness_root}/layout-v3"

for path in \
  "$database_root" "$files_root" "$storage_root" \
  "$database_transfer_root" "$files_transfer_root" "$restore_transfer_root" \
  "$backup_storage_root" \
  "$legacy_root" "$witness_root"; do
  [ -d "$path" ] && [ ! -L "$path" ] \
    || fail "${path} is missing, a symbolic link, or not a directory."
done

verify_capacity() {
  path="$1"
  capacity="$(stat -f -c '%a:%S:%d' "$path")" \
    || fail "could not inspect filesystem capacity for ${path}."
  available_blocks="${capacity%%:*}"
  remainder="${capacity#*:}"
  block_size="${remainder%%:*}"
  available_inodes="${remainder#*:}"
  case "${available_blocks}:${block_size}:${available_inodes}" in
    *[!0-9:]*) fail "filesystem capacity for ${path} is invalid." ;;
  esac
  available_bytes=$((available_blocks * block_size))
  [ "$available_bytes" -ge "$minimum_free_bytes" ] \
    || fail "${path} has fewer than ${minimum_free_bytes} free bytes."
  [ "$available_inodes" -ge "$minimum_free_inodes" ] \
    || fail "${path} has fewer than ${minimum_free_inodes} free inodes."
}

for path in \
  "$database_root" "$files_root" "$storage_root" \
  "$database_transfer_root" "$files_transfer_root" \
  "$restore_transfer_root" "$backup_storage_root"; do
  verify_capacity "$path"
done

# Each production path must be its own Docker volume mount.  This prevents a
# Compose typo from recursively changing ownership on an image or host directory.
if [ "${DJANGO_SERVER:-prod}" = prod ]; then
  for path in \
    "$database_root" "$files_root" "$storage_root" \
    "$database_transfer_root" "$files_transfer_root" "$restore_transfer_root" \
    "$backup_storage_root" \
    "$legacy_root" "$witness_root"; do
    awk -v wanted="$path" '$5 == wanted { found=1 } END { exit !found }' /proc/self/mountinfo \
      || fail "${path} is not a dedicated container mount."
  done
fi

directory_is_empty() {
  [ -z "$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)" ]
}

record="$(cat <<EOF
schema=3
installation_id=${installation_id}
intent=${intent}
database=10002:10002:0700
files=10003:10003:0700
storage=10004:10004:0700
database_transfer=0:10989:3771
files_transfer=0:10991:3771
restore_transfer=0:10995:3771
backup_storage=10004:10004:0700
legacy=empty
EOF
)"

validate_backup_storage_tree() {
  accepted_state="$1"
  if find "$backup_storage_root" -xdev -mindepth 1 \
      \( ! -type d -a ! -type f \) -print -quit | grep -q .; then
    fail "the local backup-storage volume contains a link or special file."
  fi
  if find "$backup_storage_root" -xdev -type f -links +1 -print -quit | grep -q .; then
    fail "the local backup-storage volume contains a hard-linked file."
  fi
  if find "$backup_storage_root" -xdev -mindepth 1 -perm /0077 -print -quit | grep -q .; then
    fail "the local backup-storage volume contains group/world-accessible data."
  fi
  if find "$backup_storage_root" -xdev -mindepth 1 -perm /7000 -print -quit | grep -q .; then
    fail "the local backup-storage volume contains a privilege or sticky mode bit."
  fi
  case "$accepted_state" in
    migrated)
      if find "$backup_storage_root" -xdev -mindepth 1 \
          \( ! -uid 10004 -o ! -gid 10004 \) -print -quit | grep -q .; then
        fail "the witnessed local backup-storage volume contains foreign ownership."
      fi
      ;;
    legacy-or-retry)
      if find "$backup_storage_root" -xdev -mindepth 1 \
          ! \( \( -uid 10001 -a -gid 10001 \) -o \
                \( -uid 10004 -a -gid 10004 \) \) \
          -print -quit | grep -q .; then
        fail "the local backup-storage volume has ambiguous ownership."
      fi
      ;;
    *) fail "internal backup-storage validation state is invalid." ;;
  esac
}

verify_root() {
  path="$1"
  uid="$2"
  gid="$3"
  mode="$4"
  actual="$(stat -c '%u:%g:%a' "$path")" \
    || fail "could not inspect ${path}."
  [ "$actual" = "${uid}:${gid}:${mode}" ] \
    || fail "${path} ownership or mode differs from the durable layout witness."
}

if [ -e "$witness_file" ]; then
  [ -f "$witness_file" ] && [ ! -L "$witness_file" ] \
    || fail "the durable layout witness is not a regular file."
  [ "$(stat -c '%u:%g:%a:%h' "$witness_file")" = "0:0:400:1" ] \
    || fail "the durable layout witness metadata is unsafe."
  [ "$(cat "$witness_file")" = "$record" ] \
    || fail "the durable layout witness belongs to another installation or intent."
  verify_root "$database_root" 10002 10002 700
  verify_root "$files_root" 10003 10003 700
  verify_root "$storage_root" 10004 10004 700
  verify_root "$database_transfer_root" 0 10989 3771
  verify_root "$files_transfer_root" 0 10991 3771
  verify_root "$restore_transfer_root" 0 10995 3771
  verify_root "$backup_storage_root" 10004 10004 700
  verify_root "$witness_root" 0 0 700
  validate_backup_storage_tree migrated
  directory_is_empty "$legacy_root" \
    || fail "the legacy shared work volume is no longer empty."
  exit 0
fi

directory_is_empty "$witness_root" \
  || fail "the witness volume contains an unknown path."
for path in \
  "$database_root" "$files_root" "$storage_root" \
  "$database_transfer_root" "$files_transfer_root" "$restore_transfer_root"; do
  directory_is_empty "$path" \
    || fail "${path} contains data without a durable layout witness."
done
directory_is_empty "$legacy_root" \
  || fail "the legacy shared work volume contains ambiguous plaintext."
if [ "$intent" = new-empty-v3 ]; then
  directory_is_empty "$backup_storage_root" \
    || fail "a new installation cannot adopt a populated local backup-storage volume."
else
  validate_backup_storage_tree legacy-or-retry
fi

# Validation is complete before the first mutation.  A crash between these
# operations is safe to retry because every data volume remains empty until the
# witness is committed, and only either the stock or exact target metadata is used.
chown 10002:10002 "$database_root"
chmod 0700 "$database_root"
chown 10003:10003 "$files_root"
chmod 0700 "$files_root"
chown 10004:10004 "$storage_root"
chmod 0700 "$storage_root"
chown 0:10989 "$database_transfer_root"
chmod 3771 "$database_transfer_root"
chown 0:10991 "$files_transfer_root"
chmod 3771 "$files_transfer_root"
chown 0:10995 "$restore_transfer_root"
chmod 3771 "$restore_transfer_root"
find "$backup_storage_root" -xdev -exec chown 10004:10004 {} +
chmod 0700 "$backup_storage_root"
chown 0:0 "$witness_root"
chmod 0700 "$witness_root"

temporary_witness="${witness_root}/.layout-v3.$$"
printf '%s\n' "$record" > "$temporary_witness"
chown 0:0 "$temporary_witness"
chmod 0400 "$temporary_witness"
mv -f "$temporary_witness" "$witness_file"

verify_root "$database_root" 10002 10002 700
verify_root "$files_root" 10003 10003 700
verify_root "$storage_root" 10004 10004 700
verify_root "$database_transfer_root" 0 10989 3771
verify_root "$files_transfer_root" 0 10991 3771
verify_root "$restore_transfer_root" 0 10995 3771
verify_root "$backup_storage_root" 10004 10004 700
validate_backup_storage_tree migrated
[ "$(stat -c '%u:%g:%a:%h' "$witness_file")" = "0:0:400:1" ] \
  || fail "the durable layout witness was not committed safely."
