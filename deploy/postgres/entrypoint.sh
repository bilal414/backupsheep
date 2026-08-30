#!/bin/sh
set -eu
umask 077

die() { printf '%s\n' "BackupSheep PostgreSQL refused: $*" >&2; exit 64; }

generation='18-alpine-icu-v1'
root='/var/lib/postgresql'
marker="${root}/.backupsheep-storage-witness-v1"
receipt="${root}/.backupsheep-logical-migration-receipt-v2"
receipt_version='2'
restore_strategy='fixed-target-v3-roles-unprivileged-custom-v1'
data="${PGDATA:-${root}/18/docker}"
installation_id="${BACKUPSHEEP_INSTALLATION_ID:-}"
storage_state="${BACKUPSHEEP_POSTGRES_STORAGE_GENERATION:-}"
storage_witness="${BACKUPSHEEP_POSTGRES_STORAGE_WITNESS:-}"
storage_intent="${BACKUPSHEEP_POSTGRES_STORAGE_INTENT:-}"

case "$installation_id" in *[!0-9a-f]*|'') die 'installation identity is missing or malformed' ;; esac
[ "${#installation_id}" -eq 64 ] || die 'installation identity length is invalid'
case "$storage_witness" in *[!0-9a-f]*|'') die 'storage witness is missing or malformed' ;; esac
[ "${#storage_witness}" -eq 64 ] || die 'storage witness length is invalid'
case "$storage_intent" in
    new-empty-v1|migrated-debian-v1|migrated-debian-generation2-v1) ;;
    *) die 'storage intent is not reviewed' ;;
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

migration_receipt_is_complete() {
    [ -f "$receipt" ] && [ ! -L "$receipt" ] || return 1
    [ "$(wc -l < "$receipt" | tr -d ' ')" = 9 ] || return 1
    sed -n '1p' "$receipt" | grep -qx 'status=complete' || return 1
    sed -n '2p' "$receipt" | grep -qx "receipt_version=${receipt_version}" || return 1
    sed -n '3p' "$receipt" | grep -qx "restore_strategy=${restore_strategy}" || return 1
    sed -n '4p' "$receipt" | grep -qx "source_contract=$(migration_source_contract)" || return 1
    sed -n '5p' "$receipt" | grep -Ex '^source_image=sha256:[0-9a-f]{64}$' >/dev/null || return 1
    sed -n '6p' "$receipt" | grep -Ex '^target_image=sha256:[0-9a-f]{64}$' >/dev/null || return 1
    sed -n '7p' "$receipt" | grep -Ex '^roles_sha256=[0-9a-f]{64}$' >/dev/null || return 1
    sed -n '8p' "$receipt" | grep -Ex '^schema_sha256=[0-9a-f]{64}$' >/dev/null || return 1
    sed -n '9p' "$receipt" | grep -Ex '^data_sha256=[0-9a-f]{64}$' >/dev/null || return 1
}

marker_content() {
    printf '%s\n' \
        "status=$1" \
        "generation=${generation}" \
        "installation=${installation_id}" \
        "intent=${storage_intent}" \
        "witness=${storage_witness}"
}
read_marker() { [ -f "$marker" ] && [ ! -L "$marker" ] && cat "$marker"; }
write_pending_marker() {
    temporary="${marker}.tmp.$$"
    marker_content pending > "$temporary" || die 'could not prepare pending witness'
    chmod 0600 "$temporary" && mv "$temporary" "$marker" || die 'could not publish pending witness'
}

[ "$(id -u):$(id -g)" = '70:70' ] || die 'database runtime must be UID/GID 70'
[ -d "$root" ] && [ ! -L "$root" ] || die 'database root is not a regular directory'
case "$storage_state" in
    "${generation}-pending-fresh")
        [ "$storage_intent" = 'new-empty-v1' ] || die 'fresh state has the wrong intent'
        if current="$(read_marker 2>/dev/null)"; then
            [ "$current" = "$(marker_content pending)" ] || [ "$current" = "$(marker_content complete)" ] \
                || die 'fresh storage marker does not match this installation'
            if [ -e "${data}/PG_VERSION" ]; then
                [ "$(cat "${data}/PG_VERSION")" = '18' ] || die 'fresh storage contains a non-18 cluster'
            fi
        else
            [ ! -e "${data}/PG_VERSION" ] || die 'an unwitnessed cluster already exists in the fresh volume'
            [ -z "$(find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ] \
                || die 'the fresh target volume is not empty'
            write_pending_marker
        fi
        ;;
    "$generation")
        current="$(read_marker 2>/dev/null || true)"
        [ "$current" = "$(marker_content complete)" ] || die 'completed storage marker is absent or mismatched'
        [ -f "${data}/PG_VERSION" ] && [ "$(cat "${data}/PG_VERSION")" = '18' ] \
            || die 'completed storage is not a PostgreSQL 18 cluster'
        ;;
    "${generation}-pending-upgrade")
        is_migration_intent || die 'pending Debian migration has the wrong intent'
        current="$(read_marker 2>/dev/null || true)"
        [ "$current" = "$(marker_content complete)" ] \
            || die 'pending Debian migration has no completed installation-bound marker'
        migration_receipt_is_complete \
            || die 'pending Debian migration has no complete receipt'
        [ -f "${data}/PG_VERSION" ] && [ "$(cat "${data}/PG_VERSION")" = '18' ] \
            || die 'pending Debian migration is not a PostgreSQL 18 cluster'
        ;;
    *) die 'storage generation is absent or unsupported' ;;
esac

exec /usr/local/bin/docker-entrypoint.sh "$@"
