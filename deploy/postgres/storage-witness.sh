#!/bin/sh
set -eu
umask 077

die() { printf '%s\n' "BackupSheep PostgreSQL witness refused: $*" >&2; exit 64; }

generation='18-alpine-icu-v1'
root='/var/lib/postgresql'
marker="${root}/.backupsheep-storage-witness-v1"
receipt="${root}/.backupsheep-logical-migration-receipt-v2"
receipt_version='2'
restore_strategy='fixed-target-v3-roles-unprivileged-custom-v1'
data="${PGDATA:-${root}/18/docker}"
mode="${1:-}"
installation_id="${BACKUPSHEEP_INSTALLATION_ID:-}"
storage_witness="${BACKUPSHEEP_POSTGRES_STORAGE_WITNESS:-}"
storage_intent="${BACKUPSHEEP_POSTGRES_STORAGE_INTENT:-}"
database_name="${POSTGRES_DB:-}"
database_user="${POSTGRES_USER:-}"
password_file="${POSTGRES_PASSWORD_FILE:-}"

case "$database_name" in
    ''|postgres|template0|template1|[0123456789]*|\
    *[!abcdefghijklmnopqrstuvwxyz0123456789_]*)
        die 'POSTGRES_DB must be a non-system lowercase PostgreSQL database identifier'
        ;;
esac
[ "${#database_name}" -le 63 ] \
    || die 'POSTGRES_DB must be a non-system lowercase PostgreSQL database identifier'

[ "$(id -u):$(id -g)" = '70:70' ] || die 'witness must run as UID/GID 70'
case "$installation_id" in *[!0-9a-f]*|'') die 'installation identity is malformed' ;; esac
case "$storage_witness" in *[!0-9a-f]*|'') die 'storage witness is malformed' ;; esac
[ "${#installation_id}" -eq 64 ] && [ "${#storage_witness}" -eq 64 ] || die 'identity or witness length is invalid'
case "$storage_intent" in
    new-empty-v1|migrated-debian-v1|migrated-debian-generation2-v1) ;;
    *) die 'storage intent is invalid' ;;
esac
is_migration_intent() {
    case "$storage_intent" in
        migrated-debian-v1|migrated-debian-generation2-v1) return 0 ;;
        *) return 1 ;;
    esac
}
migration_source_contract() {
    case "$storage_intent" in
        migrated-debian-generation2-v1) printf '%s' generation2-three-role-v1 ;;
        migrated-debian-v1) printf '%s' strict-ten-role-v1 ;;
        *) return 1 ;;
    esac
}
marker_content() {
    printf '%s\n' "status=$1" "generation=${generation}" "installation=${installation_id}" \
        "intent=${storage_intent}" "witness=${storage_witness}"
}

if [ "$mode" = 'initialize-migration' ]; then
    is_migration_intent || die 'migration initialization has the wrong intent'
    [ ! -e "${data}/PG_VERSION" ] || die 'migration target already contains a cluster'
    [ -z "$(find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ] || die 'migration target is not empty'
    marker_tmp="${marker}.tmp.$$"
    marker_content pending > "$marker_tmp"
    chmod 0600 "$marker_tmp" && mv "$marker_tmp" "$marker" || die 'could not publish pending migration witness'
    exit 0
fi

case "$database_user" in
    ''|*[!abcdefghijklmnopqrstuvwxyz0123456789_]*) die 'database identifiers are invalid' ;;
esac
[ -f "$password_file" ] && [ ! -L "$password_file" ] || die 'bootstrap password file is unavailable'
[ -f "${data}/PG_VERSION" ] && [ "$(cat "${data}/PG_VERSION")" = '18' ] || die 'target is not PostgreSQL 18'

password="$(cat "$password_file")" || die 'bootstrap password file could not be read'
version_num="$(PGPASSWORD="$password" psql --no-psqlrc --no-password --host=/var/run/postgresql \
    --username="$database_user" --dbname="$database_name" --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 --command='SHOW server_version_num')" || die 'could not query server version'
[ "$version_num" = '180006' ] || die "unexpected server version number ${version_num}"
locale_rows="$(PGPASSWORD="$password" psql --no-psqlrc --no-password --host=/var/run/postgresql \
    --username="$database_user" --dbname="$database_name" --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 --command="SELECT datname || '|' || datlocprovider::text || '|' || coalesce(datlocale,'') FROM pg_database WHERE datallowconn ORDER BY datname")" \
    || die 'could not query locale providers'
printf '%s\n' "$locale_rows" | awk -F'|' 'NF != 3 || $2 != "i" || $3 != "und" { exit 1 } END { if (NR < 2) exit 1 }' \
    || die 'every connectable database must use the reviewed ICU und locale'

current_marker="$(cat "$marker" 2>/dev/null || true)"
if [ "$mode" = 'finalize-fresh' ] && [ "$current_marker" = "$(marker_content complete)" ]; then
    exit 0
fi
if [ "$mode" = 'verify-migration' ]; then
    is_migration_intent || die 'migration verification has the wrong intent'
    [ "$current_marker" = "$(marker_content complete)" ] \
        || die 'completed migration marker is absent or mismatched'
    [ -f "$receipt" ] && [ ! -L "$receipt" ] \
        || die 'completed migration receipt is absent or unsafe'
    [ "$(wc -l < "$receipt" | tr -d ' ')" = 9 ] \
        || die 'completed migration receipt has the wrong shape'
    sed -n '1p' "$receipt" | grep -qx 'status=complete' \
        || die 'completed migration receipt status is invalid'
    sed -n '2p' "$receipt" | grep -qx "receipt_version=${receipt_version}" \
        || die 'completed migration receipt version is invalid'
    sed -n '3p' "$receipt" | grep -qx "restore_strategy=${restore_strategy}" \
        || die 'completed migration restore strategy is invalid'
    sed -n '4p' "$receipt" | grep -qx "source_contract=$(migration_source_contract)" \
        || die 'completed migration source contract is invalid'
    sed -n '5p' "$receipt" | grep -Ex '^source_image=sha256:[0-9a-f]{64}$' >/dev/null \
        || die 'completed migration receipt source image is invalid'
    sed -n '6p' "$receipt" | grep -Ex '^target_image=sha256:[0-9a-f]{64}$' >/dev/null \
        || die 'completed migration receipt target image is invalid'
    sed -n '7p' "$receipt" | grep -Ex '^roles_sha256=[0-9a-f]{64}$' >/dev/null \
        || die 'completed migration receipt role evidence is invalid'
    sed -n '8p' "$receipt" | grep -Ex '^schema_sha256=[0-9a-f]{64}$' >/dev/null \
        || die 'completed migration receipt schema evidence is invalid'
    sed -n '9p' "$receipt" | grep -Ex '^data_sha256=[0-9a-f]{64}$' >/dev/null \
        || die 'completed migration receipt data evidence is invalid'
    exit 0
fi
[ "$current_marker" = "$(marker_content pending)" ] || die 'pending marker is absent or mismatched'

case "$mode" in
    finalize-fresh)
        [ "$storage_intent" = 'new-empty-v1' ] || die 'fresh finalization has the wrong intent'
        ;;
    finalize-migration)
        is_migration_intent || die 'migration finalization has the wrong intent'
        [ "$#" -eq 6 ] || die 'migration finalization requires exact image/content witnesses'
        source_image_id="$2"; target_image_id="$3"; role_hash="$4"; schema_hash="$5"; data_hash="$6"
        for value in "$source_image_id" "$target_image_id"; do
            case "$value" in sha256:[0-9a-f]*) [ "${#value}" -eq 71 ] || die 'image ID length is invalid' ;; *) die 'image ID is invalid' ;; esac
        done
        for value in "$role_hash" "$schema_hash" "$data_hash"; do
            case "$value" in *[!0-9a-f]*|'') die 'content witness is invalid' ;; esac
            [ "${#value}" -eq 64 ] || die 'content witness length is invalid'
        done
        receipt_tmp="${receipt}.tmp.$$"
        printf '%s\n' 'status=complete' "receipt_version=${receipt_version}" \
            "restore_strategy=${restore_strategy}" \
            "source_contract=$(migration_source_contract)" \
            "source_image=${source_image_id}" "target_image=${target_image_id}" \
            "roles_sha256=${role_hash}" "schema_sha256=${schema_hash}" "data_sha256=${data_hash}" > "$receipt_tmp"
        chmod 0600 "$receipt_tmp" && mv "$receipt_tmp" "$receipt" || die 'could not publish migration receipt'
        ;;
    *) die 'unknown witness finalization mode' ;;
esac

marker_tmp="${marker}.tmp.$$"
marker_content complete > "$marker_tmp"
chmod 0600 "$marker_tmp" && mv "$marker_tmp" "$marker" || die 'could not publish completed witness'
