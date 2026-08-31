#!/usr/bin/env bash
# Stop-the-world PostgreSQL 18 Debian -> Alpine/ICU logical migration.
set -Eeuo pipefail
export LC_ALL=C
IFS=$'\n\t'
umask 077

die() { printf '%s\n' "BackupSheep PostgreSQL migration refused: $*" >&2; exit 64; }
[[ $# -eq 14 ]] || die "expected docker, project, installation, source image, target image, source volume, target volume, secret, database, bootstrap role, comma-separated roles, witness, storage intent, and database identity generation"

docker_bin="$1"; project="$2"; installation_id="$3"; source_image_id="$4"
target_image_ref="$5"; source_volume="$6"; target_volume="$7"; secret_file="$8"
database_name="$9"; bootstrap_user="${10}"; expected_roles_csv="${11}"; storage_witness="${12}"
storage_intent="${13}"; database_identity_generation="${14}"
generation='18-alpine-icu-v1'
source_socket="${project}_postgres_migration_source_socket"
target_socket="${project}_postgres_migration_target_socket"
source_container="${project}-postgres-migration-source"
target_container="${project}-postgres-migration-target"
purpose="postgres-runtime-${storage_witness}"
target_image_id=""
target_bootstrap_secret_file=""
restore_secret_file=""
restrict_key=""
restore_role=""
target_migrator_user=""
reconcile_only=false
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source_identity_contract="${script_dir}/source-identity-contract.sh"

[[ "$database_name" =~ ^[a-z_][a-z0-9_]{0,62}$ ]] \
    || die "database name is outside the stock migration contract"
case "$database_name" in
    postgres|template0|template1)
        die "database name is outside the stock migration contract"
        ;;
esac

[[ -f "$source_identity_contract" && ! -L "$source_identity_contract" ]] \
    || die "source identity contract helper is unavailable"
# shellcheck source=deploy/postgres/source-identity-contract.sh
source "$source_identity_contract"
source_identity_mode="$(backupsheep_postgres_source_identity_mode \
    "$storage_intent" "$database_identity_generation")" \
    || die "source identity state does not authorize this PostgreSQL migration"
if backupsheep_postgres_source_identity_is_reconcile_only "$source_identity_mode"; then
    reconcile_only=true
else
    reconcile_status=$?
    [[ "$reconcile_status" == 1 ]] \
        || die "source identity mode cannot be classified safely"
fi

[[ -x "$docker_bin" ]] || die "Docker executable is invalid"
host_kernel="$(uname -s 2>/dev/null)" \
    || die "could not identify the host kernel for Docker bind attestation"
docker_daemon_identity=""
if [[ "$host_kernel" == Darwin ]]; then
    docker_daemon_identity="$(
        "$docker_bin" info --format '{{.OperatingSystem}}|{{.OSType}}'
    )" || die "could not identify the Docker daemon for bind attestation"
fi
readonly host_kernel docker_daemon_identity
[[ "$project" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] || die "project name is invalid"
[[ "$installation_id" =~ ^[0-9a-f]{64}$ && "$storage_witness" =~ ^[0-9a-f]{64}$ ]] || die "identity or witness is invalid"
[[ "$source_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || die "source image ID is invalid"
[[ "$source_volume" == "${project}_pgdata" && "$target_volume" == "${project}_postgres_data_v1" ]] || die "source or target volume name is non-canonical"
[[ "$bootstrap_user" =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || die "bootstrap role is invalid"
[[ "$storage_intent" == migrated-debian-v1 \
    || "$storage_intent" == migrated-debian-generation2-v1 ]] \
    || die "storage intent is outside the migration contract"
[[ -f "$secret_file" && ! -L "$secret_file" ]] || die "bootstrap secret must be a regular non-symlink file"

expected_roles="$(tr ',' '\n' <<< "$expected_roles_csv" | LC_ALL=C sort -u)"
[[ "$(wc -l <<< "$expected_roles" | tr -d ' ')" == 10 ]] || die "exactly ten stock database roles are required"
while IFS= read -r role; do [[ "$role" =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || die "stock role inventory is malformed"; done <<< "$expected_roles"
[[ "$(cut -d, -f1 <<< "$expected_roles_csv")" == "$bootstrap_user" ]] \
    || die "bootstrap role is not first in the ordered stock inventory"
target_migrator_user="$(cut -d, -f2 <<< "$expected_roles_csv")"
[[ "$target_migrator_user" =~ ^[a-z_][a-z0-9_]{0,62}$ \
    && "$target_migrator_user" != "$bootstrap_user" ]] \
    || die "target migrator role is invalid"

docker_resource_label() {
    local resource_type="$1" resource_id="$2" label_name="$3"
    local frame_marker='__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__'
    local label_root='' framed_value='' framed_payload=''
    local declared_length='' label_value=''
    local LC_ALL=C

    case "$resource_type" in
        container|image) label_root='.Config.Labels' ;;
        volume) label_root='.Labels' ;;
        *) return 1 ;;
    esac
    case "$resource_type" in
        container)
            framed_value="$(
                "$docker_bin" inspect --format \
                    "{{with index ${label_root} \"${label_name}\"}}{{len .}}:{{.}}{{else}}0:{{end}}${frame_marker}" \
                    "$resource_id"
            )" || return 1
            ;;
        image|volume)
            framed_value="$(
                "$docker_bin" "$resource_type" inspect --format \
                    "{{with index ${label_root} \"${label_name}\"}}{{len .}}:{{.}}{{else}}0:{{end}}${frame_marker}" \
                    "$resource_id"
            )" || return 1
            ;;
    esac

    [[ "$framed_value" == *"$frame_marker" ]] || return 1
    framed_payload="${framed_value%"$frame_marker"}"
    [[ "$framed_payload" == *:* ]] || return 1
    declared_length="${framed_payload%%:*}"
    label_value="${framed_payload#*:}"
    [[ "$declared_length" =~ ^(0|[1-9][0-9]{0,6})$ ]] || return 1
    (( 10#$declared_length <= 1048576 )) || return 1
    (( ${#label_value} == 10#$declared_length )) || return 1
    [[ "$label_value" != *[[:cntrl:]]* ]] || return 1
    printf '%s' "$label_value"
}

sort_nonempty_docker_mount_records() {
    # Docker appends its own newline after a template whose range already uses
    # println.  Remove only those empty format records before deterministic sort.
    sed '/^$/d' | LC_ALL=C sort
}

normalize_docker_bind_source() {
    local reported_source="$1" normalized_source=""

    [[ "$reported_source" == /* && "$reported_source" != *[[:cntrl:]]* \
        && "$reported_source" != *'|'* ]] || return 1
    normalized_source="$reported_source"
    case "$normalized_source" in
        /host_mnt/*)
            [[ "$host_kernel" == Darwin \
                && "$docker_daemon_identity" == 'Docker Desktop|linux' ]] \
                || return 1
            normalized_source="${normalized_source#/host_mnt}"
            ;;
    esac
    [[ "$normalized_source" == /* \
        && "$normalized_source" != /host_mnt \
        && "$normalized_source" != /host_mnt/* \
        && "$normalized_source" != *'//'* \
        && "$normalized_source" != */../* \
        && "$normalized_source" != */./* \
        && "$normalized_source" != */.. \
        && "$normalized_source" != */. ]] || return 1
    printf '%s' "$normalized_source"
}

docker_bind_source_matches() {
    local normalized_source=""
    normalized_source="$(normalize_docker_bind_source "$1")" || return 1
    [[ "$normalized_source" == "$2" ]]
}

is_exact_ephemeral_secret_bind_source() {
    local normalized_source="" prefix="" suffix=""
    normalized_source="$(normalize_docker_bind_source "$1")" || return 1
    case "$2" in
        bootstrap|restore) ;;
        *) return 1 ;;
    esac
    prefix="${secret_file}.migration-${2}."
    [[ "$normalized_source" == "$prefix"* ]] || return 1
    suffix="${normalized_source#"$prefix"}"
    [[ "$suffix" =~ ^[A-Za-z0-9]{8}$ ]]
}

classify_existing_target_evidence() {
    local framed_evidence="$1" expected_pending_marker="$2"
    local expected_complete_marker="$3" line_count="" marker="" receipt=""
    local normalized_evidence="" state=""
    local absent_shape=$'--storage-marker-absent-v2--\n--receipt-absent-v2--\n--evidence-end-v2--'
    local pending_without_receipt=""

    if [[ "$framed_evidence" == "$absent_shape" ]]; then
        printf '%s' absent
        return 0
    fi
    pending_without_receipt=$'--storage-marker-present-v2--\n'"${expected_pending_marker}"$'\n--receipt-absent-v2--\n--evidence-end-v2--'
    if [[ "$framed_evidence" == "$pending_without_receipt" ]]; then
        printf '%s' pending-empty
        return 0
    fi

    line_count="$(printf '%s\n' "$framed_evidence" | wc -l | tr -d ' ')" \
        || return 1
    [[ "$line_count" == 17 \
        && "$(sed -n '1p' <<< "$framed_evidence")" == \
            '--storage-marker-present-v2--' \
        && "$(sed -n '7p' <<< "$framed_evidence")" == \
            '--receipt-present-v2--' \
        && "$(sed -n '17p' <<< "$framed_evidence")" == \
            '--evidence-end-v2--' ]] || return 1
    marker="$(sed -n '2,6p' <<< "$framed_evidence")"
    receipt="$(sed -n '8,16p' <<< "$framed_evidence")"
    if [[ "$marker" == "$expected_pending_marker" ]]; then
        state=pending-receipt
    elif [[ "$marker" == "$expected_complete_marker" ]]; then
        state=complete
    else
        return 1
    fi
    normalized_evidence="${marker}"$'\n--receipt--\n'"${receipt}"
    printf '%s\n%s' "$state" "$normalized_evidence"
}

remove_owned_container() {
    local name="$1" id="" runtime_record="" mount_records=""
    local expected_mount_records="" secret_mount_record="" secret_mount_source=""
    local secret_mount_prefix='bind||/run/secrets/db_bootstrap_password|false|'
    local container_image_id=""
    id="$($docker_bin ps --all --no-trunc --quiet --filter "name=^/${name}$")" || die "could not inventory migration container ${name}"
    [[ -n "$id" ]] || return 0
    [[ "$id" != *$'\n'* ]] || die "multiple containers claim canonical migration name ${name}"
    [[ "$(docker_resource_label container "$id" com.backupsheep.installation-id)" == "$installation_id" \
        && "$(docker_resource_label container "$id" com.backupsheep.postgres-migration)" == "$purpose" \
        && "$(docker_resource_label container "$id" com.backupsheep.project)" == "$project" ]] \
        || die "container name ${name} collides with another workload"
    runtime_record="$($docker_bin inspect --format \
        '{{.Image}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{.Path}}' \
        "$id")" || die "could not attest migration container ${name}"
    mount_records="$($docker_bin inspect --format \
        '{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Destination}}|{{.RW}}|{{.Source}}{{println}}{{end}}' \
        "$id" | sort_nonempty_docker_mount_records)" \
        || die "could not attest migration container mounts for ${name}"
    case "$name" in
        "$source_container")
            [[ "$runtime_record" == "${source_image_id}|999:999|none|true|[\"ALL\"]|[\"no-new-privileges:true\"]|/usr/local/bin/docker-entrypoint.sh" ]] \
                || die "interrupted migration source runtime drifted"
            expected_mount_records="$(printf '%s\n%s' \
                "volume|${source_socket}|/var/run/postgresql|true|" \
                "volume|${source_volume}|/var/lib/postgresql|true|" \
                | LC_ALL=C sort)"
            # Named-volume Source paths are engine-owned and intentionally ignored.
            [[ "$(printf '%s\n' "$mount_records" | cut -d'|' -f1-4)" \
                == "$(printf '%s\n' "$expected_mount_records" | cut -d'|' -f1-4)" ]] \
                || die "interrupted migration source mounts drifted"
            ;;
        "$target_container")
            container_image_id="${runtime_record%%|*}"
            [[ "$runtime_record" == "${container_image_id}|70:70|none|true|[\"ALL\"]|[\"no-new-privileges:true\"]|/usr/local/bin/docker-entrypoint.sh" \
                && "$container_image_id" =~ ^sha256:[0-9a-f]{64}$ \
                && "$(docker_resource_label image "$container_image_id" com.backupsheep.postgres.runtime-generation)" == '18.6-alpine3.24-icu-v1' ]] \
                || die "interrupted migration target runtime drifted"
            grep -Fqx "volume|${target_socket}|/var/run/postgresql|true|$(printf '%s\n' "$mount_records" | awk -F'|' -v name="$target_socket" '$2 == name { print $5 }')" <<< "$mount_records" \
                && grep -Fqx "volume|${target_volume}|/var/lib/postgresql|true|$(printf '%s\n' "$mount_records" | awk -F'|' -v name="$target_volume" '$2 == name { print $5 }')" <<< "$mount_records" \
                || die "interrupted migration target data/socket mounts drifted"
            secret_mount_record="$(printf '%s\n' "$mount_records" | awk -F'|' '$1 == "bind" && $3 == "/run/secrets/db_bootstrap_password" && $4 == "false" { print }')"
            [[ -n "$secret_mount_record" && "$secret_mount_record" != *$'\n'* \
                && "$(printf '%s\n' "$mount_records" | grep -c .)" == 3 ]] \
                || die "interrupted migration target credential mount drifted"
            [[ "$secret_mount_record" == "$secret_mount_prefix"* ]] \
                || die "interrupted migration target credential record drifted"
            secret_mount_source="${secret_mount_record#"$secret_mount_prefix"}"
            is_exact_ephemeral_secret_bind_source \
                "$secret_mount_source" bootstrap \
                || die "interrupted migration target credential path drifted"
            ;;
        *) die "internal migration cleanup name is invalid" ;;
    esac
    "$docker_bin" stop --time 30 "$id" >/dev/null 2>&1 || true
    "$docker_bin" rm "$id" >/dev/null || die "could not remove the exact stopped migration container ${name}"
}

validate_interrupted_helper_mounts() {
    local mount_records="$1" record="" type="" name="" destination="" writable="" source=""
    local count=0 source_scope=false target_scope=false
    local source_secret=false bootstrap_secret=false restore_secret=false

    while IFS='|' read -r type name destination writable source; do
        [[ -n "$type" ]] || continue
        count=$((count + 1))
        case "${type}|${name}|${destination}|${writable}" in
            "volume|${source_socket}|/source|false") source_scope=true ;;
            "volume|${target_socket}|/target|false"|\
            "volume|${target_socket}|/var/run/postgresql|false"|\
            "volume|${target_volume}|/var/lib/postgresql|true"|\
            "volume|${target_volume}|/evidence|false") target_scope=true ;;
            "bind||/run/secrets/source_password|false")
                docker_bind_source_matches "$source" "$secret_file" || return 1
                source_secret=true
                ;;
            "bind||/run/secrets/target_password|false"|\
            "bind||/run/secrets/db_bootstrap_password|false")
                is_exact_ephemeral_secret_bind_source "$source" bootstrap \
                    || return 1
                bootstrap_secret=true
                ;;
            "bind||/run/secrets/restore_password|false")
                is_exact_ephemeral_secret_bind_source "$source" restore \
                    || return 1
                restore_secret=true
                ;;
            "bind||/run/secrets/ephemeral_password|false")
                if is_exact_ephemeral_secret_bind_source "$source" bootstrap; then
                    bootstrap_secret=true
                elif is_exact_ephemeral_secret_bind_source "$source" restore; then
                    restore_secret=true
                else
                    return 1
                fi
                ;;
            *) return 1 ;;
        esac
    done <<< "$mount_records"
    (( count >= 1 && count <= 3 )) || return 1
    [[ "$source_scope" == false || "$target_scope" == false ]] || return 1
    if [[ "$source_scope" == true ]]; then
        [[ "$source_secret" == true && "$bootstrap_secret" == false \
            && "$restore_secret" == false && "$count" -eq 2 ]]
        return
    fi
    if [[ "$target_scope" == false ]]; then
        [[ "$source_secret" == false && "$count" -eq 1 \
            && ( "$bootstrap_secret" == true || "$restore_secret" == true ) ]]
    fi
}

remove_owned_interrupted_helpers() {
    local ids="" id="" runtime_record="" mounts="" container_name=""
    local container_image_id=""

    ids="$($docker_bin ps --all --no-trunc --quiet \
        --filter "label=com.backupsheep.project=${project}" \
        --filter "label=com.backupsheep.installation-id=${installation_id}" \
        --filter "label=com.backupsheep.postgres-migration=${purpose}")" \
        || die "could not inventory interrupted migration helpers"
    while IFS= read -r id; do
        [[ -n "$id" ]] || continue
        container_name="$($docker_bin inspect --format '{{.Name}}' "$id" 2>/dev/null || true)"
        [[ -n "$container_name" ]] || continue
        [[ "$container_name" != "/${source_container}" \
            && "$container_name" != "/${target_container}" ]] \
            || die "canonical migration server remained after exact cleanup"
        [[ "$(docker_resource_label container "$id" com.backupsheep.project)" == "$project" \
            && "$(docker_resource_label container "$id" com.backupsheep.installation-id)" == "$installation_id" \
            && "$(docker_resource_label container "$id" com.backupsheep.postgres-migration)" == "$purpose" ]] \
            || die "interrupted migration helper labels drifted"
        runtime_record="$($docker_bin inspect --format \
            '{{.Image}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{.Path}}' \
            "$id")" || die "could not attest interrupted migration helper runtime"
        container_image_id="${runtime_record%%|*}"
        case "$runtime_record" in
            "${container_image_id}|70:70|none|true|[\"ALL\"]|[\"no-new-privileges:true\"]|/bin/sh"|\
            "${container_image_id}|70:70|none|true|[\"ALL\"]|[\"no-new-privileges:true\"]|/usr/local/bin/backupsheep-postgres-storage-witness") ;;
            *) die "interrupted migration helper runtime drifted" ;;
        esac
        [[ "$container_image_id" =~ ^sha256:[0-9a-f]{64}$ \
            && "$(docker_resource_label image "$container_image_id" com.backupsheep.postgres.runtime-generation)" == '18.6-alpine3.24-icu-v1' ]] \
            || die "interrupted migration helper image drifted"
        mounts="$($docker_bin inspect --format \
            '{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Destination}}|{{.RW}}|{{.Source}}{{println}}{{end}}' \
            "$id" | sort_nonempty_docker_mount_records)" \
            || die "could not attest interrupted migration helper mounts"
        validate_interrupted_helper_mounts "$mounts" \
            || die "interrupted migration helper mount boundary drifted"
        "$docker_bin" stop --time 30 "$id" >/dev/null 2>&1 || true
        if ! "$docker_bin" rm "$id" >/dev/null 2>&1; then
            "$docker_bin" inspect "$id" >/dev/null 2>&1 \
                && die "could not remove exact interrupted migration helper ${container_name}"
        fi
    done <<< "$ids"
}

remove_owned_socket_volume() {
    local name="$1"
    "$docker_bin" volume inspect "$name" >/dev/null 2>&1 || return 0
    [[ "$(docker_resource_label volume "$name" com.backupsheep.installation-id)" == "$installation_id" \
        && "$(docker_resource_label volume "$name" com.backupsheep.postgres-migration)" == "$purpose" ]] \
        || die "temporary socket volume ${name} collides with another workload"
    [[ -z "$($docker_bin ps --all --no-trunc --quiet --filter "volume=${name}")" ]] \
        || die "temporary socket volume ${name} remains attached"
    "$docker_bin" volume rm "$name" >/dev/null || die "could not remove exact temporary socket volume ${name}"
}

host_file_uid() {
    stat -c '%u' -- "$1" 2>/dev/null || stat -f '%u' "$1"
}

host_file_mode() {
    stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

host_file_links() {
    stat -c '%h' -- "$1" 2>/dev/null || stat -f '%l' "$1"
}

remove_unattached_ephemeral_secret_residue() {
    local secret_owner="" candidate="" suffix="" value="" byte_count="" mode=""
    local container_ids="" container_id="" mount_sources="" mount_source=""
    local normalized_mount_source=""
    local -a residue_paths=()

    secret_owner="$(host_file_uid "$secret_file")" \
        || die "could not attest the installed database secret owner"
    shopt -s nullglob
    residue_paths=(
        "${secret_file}.migration-bootstrap."*
        "${secret_file}.migration-restore."*
    )
    shopt -u nullglob
    for candidate in "${residue_paths[@]}"; do
        case "$candidate" in
            "${secret_file}.migration-bootstrap."*)
                suffix="${candidate#"${secret_file}.migration-bootstrap."}"
                ;;
            "${secret_file}.migration-restore."*)
                suffix="${candidate#"${secret_file}.migration-restore."}"
                ;;
            *) die "ephemeral credential residue path escaped its canonical basename" ;;
        esac
        [[ "$suffix" =~ ^[A-Za-z0-9]{8}$ \
            && -f "$candidate" && ! -L "$candidate" \
            && "$(host_file_uid "$candidate")" == "$secret_owner" \
            && "$(host_file_links "$candidate")" == 1 ]] \
            || die "ephemeral credential residue has unsafe metadata"
        mode="$(host_file_mode "$candidate")" \
            || die "could not attest ephemeral credential residue permissions"
        byte_count="$(wc -c < "$candidate" | tr -d ' ')"
        [[ "$byte_count" =~ ^[0-9]+$ ]] \
            || die "could not attest ephemeral credential residue size"
        case "$mode" in
            600)
                # mktemp creates mode 0600 before openssl fills the file and the
                # final container-readable chmod.  A hard crash can therefore
                # leave any prefix of the at-most-65-byte credential material.
                (( byte_count <= 65 )) \
                    || die "ephemeral credential construction residue is oversized"
                ;;
            444)
                value="$(<"$candidate")"
                [[ "$byte_count" == 65 && "$value" =~ ^[0-9a-f]{64}$ ]] \
                    || die "ephemeral credential residue has malformed content"
                ;;
            *) die "ephemeral credential residue has unsafe permissions" ;;
        esac

        container_ids="$($docker_bin ps --all --no-trunc --quiet)" \
            || die "could not inventory Docker bind attachments before credential cleanup"
        while IFS= read -r container_id; do
            [[ -n "$container_id" ]] || continue
            if ! mount_sources="$($docker_bin inspect --format \
                '{{range .Mounts}}{{println .Source}}{{end}}' "$container_id")"; then
                "$docker_bin" inspect "$container_id" >/dev/null 2>&1 \
                    && die "could not inspect a Docker bind attachment before credential cleanup"
                continue
            fi
            while IFS= read -r mount_source; do
                [[ -n "$mount_source" ]] || continue
                normalized_mount_source="$(
                    normalize_docker_bind_source "$mount_source"
                )" || die "Docker bind attachment source is unsafe for credential cleanup"
                if [[ "$normalized_mount_source" == "$candidate" ]]; then
                    die "ephemeral credential residue remains attached to a Docker container"
                fi
            done <<< "$mount_sources"
        done <<< "$container_ids"
        rm -- "$candidate" \
            || die "could not remove an unattached exact ephemeral credential residue"
    done
}

cleanup() {
    local status=$?
    local ephemeral_secret=''
    trap - EXIT
    remove_owned_container "$target_container" || status=74
    remove_owned_container "$source_container" || status=74
    remove_owned_interrupted_helpers || status=74
    remove_owned_socket_volume "$target_socket" || status=74
    remove_owned_socket_volume "$source_socket" || status=74
    for ephemeral_secret in "$target_bootstrap_secret_file" "$restore_secret_file"; do
        [[ -n "$ephemeral_secret" ]] || continue
        case "$ephemeral_secret" in
            "${secret_file}.migration-bootstrap."*|"${secret_file}.migration-restore."*)
                if [[ -e "$ephemeral_secret" || -L "$ephemeral_secret" ]]; then
                    [[ -f "$ephemeral_secret" && ! -L "$ephemeral_secret" ]] \
                        || status=74
                    rm -- "$ephemeral_secret" || status=74
                fi
                ;;
            *) status=74 ;;
        esac
    done
    exit "$status"
}
trap cleanup EXIT

remove_owned_container "$target_container"
remove_owned_container "$source_container"
remove_owned_interrupted_helpers
remove_owned_socket_volume "$target_socket"
remove_owned_socket_volume "$source_socket"

[[ "$($docker_bin volume inspect --format '{{.Name}}' "$source_volume")" == "$source_volume" ]] || die "legacy source volume is absent"
[[ "$(docker_resource_label volume "$source_volume" com.docker.compose.project)" == "$project" \
    && "$(docker_resource_label volume "$source_volume" com.docker.compose.volume)" == pgdata ]] || die "legacy source volume ownership is invalid"
[[ -z "$($docker_bin ps --all --no-trunc --quiet --filter "volume=${source_volume}")" ]] || die "legacy source volume is not detached"

[[ "$($docker_bin image inspect --format '{{.Id}}' "$source_image_id")" == "$source_image_id" ]] || die "retained source image ID is unavailable"
[[ "$($docker_bin image inspect --format '{{.Config.User}}' "$source_image_id")" == '999:999' ]] || die "source image is not UID/GID 999"
target_image_id="$($docker_bin image inspect --format '{{.Id}}' "$target_image_ref")" || die "target image is unavailable"
[[ "$target_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || die "target image ID is malformed"
[[ "$($docker_bin image inspect --format '{{.Config.User}}' "$target_image_id")" == '70:70' ]] || die "target image is not UID/GID 70"
[[ "$(docker_resource_label image "$target_image_id" com.backupsheep.postgres.runtime-generation)" == '18.6-alpine3.24-icu-v1' ]] || die "target image runtime label is invalid"

# A prior interrupted attempt may be erased only when the target carries this exact
# installation and migration witness. The legacy source is never removed or relabeled.
if "$docker_bin" volume inspect "$target_volume" >/dev/null 2>&1; then
    [[ "$(docker_resource_label volume "$target_volume" com.docker.compose.project)" == "$project" \
        && "$(docker_resource_label volume "$target_volume" com.docker.compose.volume)" == postgres_data_v1 \
        && "$(docker_resource_label volume "$target_volume" com.backupsheep.installation-id)" == "$installation_id" \
        && "$(docker_resource_label volume "$target_volume" com.backupsheep.postgres-migration)" == "$purpose" ]] \
        || die "existing target volume is not the exact witnessed migration target"
    [[ -z "$($docker_bin ps --all --no-trunc --quiet --filter "volume=${target_volume}")" ]] || die "migration target is attached"
    expected_pending_marker="$(printf '%s\n' 'status=pending' \
        "generation=${generation}" "installation=${installation_id}" \
        "intent=${storage_intent}" "witness=${storage_witness}")"
    expected_complete_marker="$(printf '%s\n' 'status=complete' \
        "generation=${generation}" "installation=${installation_id}" \
        "intent=${storage_intent}" "witness=${storage_witness}")"
    framed_evidence="$($docker_bin run --rm --network none --read-only --cap-drop ALL \
        --security-opt no-new-privileges:true --user 70:70 --entrypoint /bin/sh \
        --label "com.backupsheep.project=${project}" \
        --label "com.backupsheep.installation-id=${installation_id}" \
        --label "com.backupsheep.postgres-migration=${purpose}" \
        -v "${target_volume}:/evidence:ro" "$target_image_id" -ceu '
            bounded_evidence_file() {
                evidence_path="$1"
                expected_lines="$2"
                maximum_bytes="$3"
                evidence_bytes="$(stat -c "%s" "$evidence_path" 2>/dev/null \
                    || stat -f "%z" "$evidence_path" 2>/dev/null)" || return 1
                case "$evidence_bytes" in ""|*[!0-9]*) return 1 ;; esac
                [ "${#evidence_bytes}" -le 4 ] \
                    && [ "$evidence_bytes" -le "$maximum_bytes" ] || return 1
                [ "$(wc -l < "$evidence_path" | tr -d " ")" = "$expected_lines" ] \
                    || return 1
                [ "$(LC_ALL=C tr -d "\012\040-\176" < "$evidence_path" \
                    | wc -c | tr -d " ")" = 0 ] || return 1
            }
            marker=/evidence/.backupsheep-storage-witness-v1
            receipt=/evidence/.backupsheep-logical-migration-receipt-v2
            [ -d /evidence ] && [ ! -L /evidence ] \
                && [ -r /evidence ] && [ -x /evidence ] || exit 64
            if [ -e "$marker" ] || [ -L "$marker" ]; then
                [ -f "$marker" ] && [ ! -L "$marker" ] \
                    && bounded_evidence_file "$marker" 5 512 || exit 65
                printf "%s\n" "--storage-marker-present-v2--"
                cat "$marker"
            else
                printf "%s\n" "--storage-marker-absent-v2--"
            fi
            if [ -e "$receipt" ] || [ -L "$receipt" ]; then
                [ -f "$receipt" ] && [ ! -L "$receipt" ] \
                    && bounded_evidence_file "$receipt" 9 1024 || exit 66
                printf "%s\n" "--receipt-present-v2--"
                cat "$receipt"
            else
                printf "%s\n" "--receipt-absent-v2--"
            fi
            printf "%s\n" "--evidence-end-v2--"
        ')" || die "could not inspect an existing witnessed migration target"
    classified_evidence="$(classify_existing_target_evidence \
        "$framed_evidence" "$expected_pending_marker" \
        "$expected_complete_marker")" \
        || die "existing migration target evidence framing is invalid"
    evidence_state="$(sed -n '1p' <<< "$classified_evidence")"
    evidence="$(sed '1d' <<< "$classified_evidence")"
    if [[ "$evidence_state" == complete ]]; then
        recorded_target_image_id="$(backupsheep_validate_completed_postgres_migration_evidence \
            "$evidence" "$generation" "$installation_id" "$storage_intent" \
            "$storage_witness" "$source_image_id" "$target_image_id")" \
            || die "completed migration evidence is malformed, stale, or belongs to another source"
        "$docker_bin" image inspect "$recorded_target_image_id" >/dev/null \
            || die "completed migration target image is no longer available for reconciliation"
        [[ "$($docker_bin image inspect --format '{{.Config.User}}' "$recorded_target_image_id")" == '70:70' \
            && "$(docker_resource_label image "$recorded_target_image_id" com.backupsheep.postgres.runtime-generation)" == '18.6-alpine3.24-icu-v1' ]] \
            || die "completed migration target image no longer has the reviewed runtime identity"
        remove_unattached_ephemeral_secret_residue
        printf '%s\n' "PostgreSQL migration reconciled from its completed receipt: source=${source_image_id} target=${recorded_target_image_id}"
        exit 0
    fi
    if [[ "$evidence_state" == pending-receipt ]]; then
        completed_evidence=$'status=complete\n'"$(sed '1d' <<< "$evidence")"
        backupsheep_validate_completed_postgres_migration_evidence \
            "$completed_evidence" "$generation" "$installation_id" \
            "$storage_intent" "$storage_witness" "$source_image_id" \
            "$target_image_id" >/dev/null \
            || die "pending migration target receipt is malformed, stale, or belongs to another source"
    else
        [[ "$evidence_state" == absent || "$evidence_state" == pending-empty ]] \
            || die "existing migration target has an unrecognized evidence state"
        [[ -z "$evidence" ]] \
            || die "existing migration target state contains unexpected evidence"
    fi
    [[ "$reconcile_only" == false ]] \
        || die "sealed database identity state requires an already-complete migration receipt; target reset is refused"
    "$docker_bin" volume rm "$target_volume" >/dev/null || die "could not remove exact interrupted migration target"
fi
remove_unattached_ephemeral_secret_residue

[[ "$reconcile_only" == false ]] \
    || die "sealed database identity state cannot authorize a new PostgreSQL migration"

created="$($docker_bin volume create \
    --label "com.docker.compose.project=${project}" \
    --label 'com.docker.compose.volume=postgres_data_v1' \
    --label "com.backupsheep.installation-id=${installation_id}" \
    --label "com.backupsheep.postgres-migration=${purpose}" \
    "$target_volume")" || die "could not create migration target"
[[ "$created" == "$target_volume" ]] || die "Docker returned an unexpected target volume"
for socket_volume in "$source_socket" "$target_socket"; do
    created="$($docker_bin volume create \
        --label "com.backupsheep.project=${project}" \
        --label "com.backupsheep.installation-id=${installation_id}" \
        --label "com.backupsheep.postgres-migration=${purpose}" \
        "$socket_volume")" || die "could not create isolated socket volume"
    [[ "$created" == "$socket_volume" ]] || die "Docker returned an unexpected socket volume"
done

common_labels=(--label "com.backupsheep.project=${project}" --label "com.backupsheep.installation-id=${installation_id}" --label "com.backupsheep.postgres-migration=${purpose}")
common_runtime=(--network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 256 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777)

command -v openssl >/dev/null 2>&1 || die "openssl is required for the ephemeral target credential"
target_bootstrap_secret_file="$(mktemp "${secret_file}.migration-bootstrap.XXXXXXXX")" \
    || die "could not allocate the ephemeral target bootstrap credential"
restore_secret_file="$(mktemp "${secret_file}.migration-restore.XXXXXXXX")" \
    || die "could not allocate the ephemeral restore credential"
for ephemeral_secret in "$target_bootstrap_secret_file" "$restore_secret_file"; do
    chmod 0600 "$ephemeral_secret"
    openssl rand -hex 32 > "$ephemeral_secret" \
        || die "could not generate an isolated ephemeral credential"
    chmod 0444 "$ephemeral_secret" \
        || die "could not make a confined ephemeral credential container-readable"
    [[ -f "$ephemeral_secret" && ! -L "$ephemeral_secret" ]] \
        || die "ephemeral credential is not a regular file"
    "$docker_bin" run --rm "${common_labels[@]}" "${common_runtime[@]}" --user 70:70 \
        --entrypoint /bin/sh -v "${ephemeral_secret}:/run/secrets/ephemeral_password:ro" \
        "$target_image_id" -ceu '
        value="$(cat /run/secrets/ephemeral_password)"
        case "$value" in *[!0-9a-f]*|"") exit 64 ;; esac
        [ "${#value}" -eq 64 ]
    ' credential-read-attestation \
        || die "UID/GID 70 cannot read a confined ephemeral credential"
done
[[ "$(<"$target_bootstrap_secret_file")" != "$(<"$restore_secret_file")" ]] \
    || die "ephemeral target bootstrap and restore credentials must be distinct"
restrict_key="$({
    printf '%s' "BackupSheep/postgres-dump-restrict/v1|${installation_id}|${storage_witness}|"
    cat -- "$secret_file"
} | openssl dgst -sha256 | awk '{ print $NF }')" \
    || die "could not derive the dump restriction key"
[[ "$restrict_key" =~ ^[0-9a-f]{64}$ ]] || die "dump restriction key generation failed"
restore_role="backupsheep_restore_${storage_witness:0:24}"
[[ "$restore_role" =~ ^[a-z_][a-z0-9_]{0,62}$ ]] \
    || die "ephemeral restore role derivation failed"
! grep -Fxq -- "$restore_role" <<< "$expected_roles" \
    || die "ephemeral restore role collides with a configured database identity"

"$docker_bin" run --rm "${common_labels[@]}" "${common_runtime[@]}" --user 70:70 \
    --entrypoint /usr/local/bin/backupsheep-postgres-storage-witness \
    -e "BACKUPSHEEP_INSTALLATION_ID=${installation_id}" \
    -e "BACKUPSHEEP_POSTGRES_STORAGE_INTENT=${storage_intent}" \
    -e "BACKUPSHEEP_POSTGRES_STORAGE_WITNESS=${storage_witness}" \
    -v "${target_volume}:/var/lib/postgresql" \
    "$target_image_id" initialize-migration >/dev/null || die "could not witness the empty migration target"

source_id="$($docker_bin run --detach --name "$source_container" "${common_labels[@]}" "${common_runtime[@]}" \
    --user 999:999 --entrypoint /usr/local/bin/docker-entrypoint.sh \
    -v "${source_volume}:/var/lib/postgresql" -v "${source_socket}:/var/run/postgresql" \
    "$source_image_id" postgres \
    -c listen_addresses= -c unix_socket_directories=/var/run/postgresql \
    -c shared_preload_libraries= -c session_preload_libraries= \
    -c local_preload_libraries= -c archive_mode=off -c archive_command= \
    -c archive_library= -c restore_command= -c archive_cleanup_command= \
    -c recovery_end_command= -c ssl=off -c ssl_passphrase_command= \
    -c logging_collector=off -c autovacuum=off -c jit=off \
    -c log_destination=stderr -c log_statement=none \
    -c log_min_duration_statement=-1 -c log_min_duration_sample=-1 \
    -c log_duration=off -c restart_after_crash=off \
    -c max_worker_processes=0 -c max_logical_replication_workers=0 \
    -c max_sync_workers_per_subscription=0 -c max_parallel_workers=0 \
    -c max_parallel_apply_workers_per_subscription=0 \
    -c max_parallel_maintenance_workers=0 -c output_plugin_libraries= \
    -c default_transaction_read_only=on)" \
    || die "could not start isolated read-only legacy source"
target_id="$($docker_bin run --detach --name "$target_container" "${common_labels[@]}" "${common_runtime[@]}" \
    --user 70:70 --entrypoint /usr/local/bin/docker-entrypoint.sh \
    -e "POSTGRES_DB=${database_name}" -e "POSTGRES_USER=${bootstrap_user}" \
    -e 'POSTGRES_PASSWORD_FILE=/run/secrets/db_bootstrap_password' \
    -e 'POSTGRES_INITDB_ARGS=--locale-provider=icu --icu-locale=und --encoding=UTF8 --auth-local=scram-sha-256 --auth-host=scram-sha-256' \
    -e "BACKUPSHEEP_INSTALLATION_ID=${installation_id}" \
    -e "BACKUPSHEEP_POSTGRES_STORAGE_INTENT=${storage_intent}" \
    -e "BACKUPSHEEP_POSTGRES_STORAGE_WITNESS=${storage_witness}" \
    -v "${target_volume}:/var/lib/postgresql" -v "${target_socket}:/var/run/postgresql" \
    -v "${target_bootstrap_secret_file}:/run/secrets/db_bootstrap_password:ro" \
    "$target_image_id" postgres -c listen_addresses= -c unix_socket_directories=/var/run/postgresql)" || die "could not start isolated ICU target"

for specification in "$source_id|$source_image_id|999:999|$source_volume|/var/lib/postgresql|$source_socket|/var/run/postgresql|2|none" "$target_id|$target_image_id|70:70|$target_volume|/var/lib/postgresql|$target_socket|/var/run/postgresql|3|file"; do
    IFS='|' read -r cid image_id runtime_user data_volume data_target socket_volume socket_target mount_count secret_mount <<< "$specification"
    [[ "$($docker_bin inspect --format '{{.Image}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' "$cid")" \
        == "${image_id}|${runtime_user}|none|true|[\"ALL\"]|[\"no-new-privileges:true\"]" ]] || die "migration container runtime attestation failed"
    mounts="$($docker_bin inspect --format '{{range .Mounts}}{{.Name}}|{{.Destination}}{{println}}{{end}}' "$cid")" || die "could not attest migration mounts"
    grep -Fxq -- "${data_volume}|${data_target}" <<< "$mounts" && grep -Fxq -- "${socket_volume}|${socket_target}" <<< "$mounts" \
        || die "migration container has an unexpected data/socket mount"
    if [[ "$secret_mount" == file ]]; then
        grep -Fxq '|/run/secrets/db_bootstrap_password' <<< "$mounts" \
            || die "target migration container does not use the file-backed credential"
    else
        ! grep -Fq '/run/secrets/' <<< "$mounts" \
            || die "legacy source server must not mount a plaintext credential"
    fi
    [[ "$(grep -c . <<< "$mounts")" == "$mount_count" ]] || die "migration container has an unexpected extra mount"
done
! "$docker_bin" inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$target_id" | grep -q '^POSTGRES_PASSWORD=' \
    || die "target temporary superuser credential leaked into container environment"
[[ "$($docker_bin ps --all --no-trunc --quiet --filter "volume=${source_volume}")" == "$source_id" \
    && "$($docker_bin ps --all --no-trunc --quiet --filter "volume=${target_volume}")" == "$target_id" ]] \
    || die "another container attached to source or target storage during migration"

for attempt in $(seq 1 90); do
    source_ready=false; target_ready=false
    "$docker_bin" exec "$source_id" pg_isready -q -h /var/run/postgresql -U "$bootstrap_user" -d "$database_name" && source_ready=true
    "$docker_bin" exec "$target_id" sh -ceu 'PGPASSWORD="$(cat /run/secrets/db_bootstrap_password)" pg_isready -q -h /var/run/postgresql -U "$1" -d "$2"' ready "$bootstrap_user" "$database_name" && target_ready=true
    [[ "$source_ready" == true && "$target_ready" == true ]] && break
    sleep 1
done
[[ "$source_ready" == true && "$target_ready" == true ]] || die "source or target did not become ready"

psql_source_db() {
    local query_database="$1" query_text="$2"
    "$docker_bin" run --rm "${common_labels[@]}" --network none --read-only --cap-drop ALL \
        --security-opt no-new-privileges:true --pids-limit 64 --user 70:70 \
        --entrypoint /bin/sh -v "${source_socket}:/source:ro" \
        -v "${secret_file}:/run/secrets/source_password:ro" \
        "$target_image_id" -ceu '
            password="$(cat /run/secrets/source_password)"
            PGOPTIONS="-c search_path=pg_catalog -c statement_timeout=30s -c lock_timeout=5s" \
            PGPASSWORD="$password" exec psql --no-psqlrc --no-password \
                -h /source -U "$1" -d "$2" -At -v ON_ERROR_STOP=1 -c "$3"
        ' source-query "$bootstrap_user" "$query_database" "$query_text"
}
psql_source() { psql_source_db "$database_name" "$1"; }
source_version_num="$(psql_source 'SHOW server_version_num')"
[[ "$source_version_num" == 180006 ]] || die "legacy source server is not exact PostgreSQL 18.6"
"$docker_bin" exec "$source_id" sh -ceu 'ldd --version 2>&1 | grep -Eq "(GLIBC|GNU libc)"' \
    || die "legacy source image is not the retained glibc runtime"
[[ "$(psql_source 'SELECT pg_is_in_recovery()')" == f ]] \
    || die "legacy source is not an authoritative primary"
source_dbs="$(psql_source "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY datname")"
[[ "$source_dbs" == "$(printf '%s\n%s' "$database_name" postgres | LC_ALL=C sort)" ]] || die "legacy source has non-stock databases"
source_roles="$(psql_source "SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY rolname")"
application_membership_count="$(psql_source "SELECT count(*) FROM pg_auth_members membership JOIN pg_roles parent_role ON parent_role.oid=membership.roleid JOIN pg_roles member_role ON member_role.oid=membership.member WHERE parent_role.rolname !~ '^pg_' OR member_role.rolname !~ '^pg_'")"
role_security_records="$(psql_source "SELECT role.rolname || '|' || role.rolsuper || '|' || role.rolinherit || '|' || role.rolcreaterole || '|' || role.rolcreatedb || '|' || role.rolcanlogin || '|' || role.rolreplication || '|' || role.rolbypassrls || '|' || role.rolconnlimit || '|' || (role.rolvaliduntil IS NULL) || '|' || (role.rolconfig IS NULL) || '|' || COALESCE(auth.rolpassword LIKE 'SCRAM-SHA-256\$%', false) || '|' || COALESCE(pg_catalog.shobj_description(role.oid, 'pg_authid'), '') FROM pg_roles role JOIN pg_authid auth ON auth.oid=role.oid WHERE role.rolname !~ '^pg_' ORDER BY role.rolname")"
role_settings="$(psql_source "SELECT COALESCE(role.rolname, '<all-roles>') || '|' || COALESCE(database.datname, '<all-databases>') || '|' || setting.value FROM pg_db_role_setting settings LEFT JOIN pg_roles role ON role.oid=settings.setrole LEFT JOIN pg_database database ON database.oid=settings.setdatabase CROSS JOIN LATERAL unnest(settings.setconfig) setting(value) ORDER BY 1")"
database_owner="$(psql_source "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()")"
schema_owner="$(psql_source "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='public'")"
database_acl="$(psql_source "SELECT CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END || '|' || grantor.rolname || '|' || acl.privilege_type || '|' || acl.is_grantable FROM pg_database database CROSS JOIN LATERAL aclexplode(database.datacl) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee JOIN pg_roles grantor ON grantor.oid=acl.grantor WHERE database.datname=current_database() AND acl.grantee <> database.datdba ORDER BY 1")"
schema_acl="$(psql_source "SELECT CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END || '|' || grantor.rolname || '|' || acl.privilege_type || '|' || acl.is_grantable FROM pg_namespace namespace CROSS JOIN LATERAL aclexplode(namespace.nspacl) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee JOIN pg_roles grantor ON grantor.oid=acl.grantor WHERE namespace.nspname='public' AND acl.grantee <> namespace.nspowner ORDER BY 1")"
default_acl="$(psql_source "SELECT owner.rolname || '|' || COALESCE(namespace.nspname, '<global>') || '|' || defaults.defaclobjtype::text || '|' || CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END || '|' || grantor.rolname || '|' || acl.privilege_type || '|' || acl.is_grantable FROM pg_default_acl defaults JOIN pg_roles owner ON owner.oid=defaults.defaclrole LEFT JOIN pg_namespace namespace ON namespace.oid=defaults.defaclnamespace CROSS JOIN LATERAL aclexplode(defaults.defaclacl) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee JOIN pg_roles grantor ON grantor.oid=acl.grantor ORDER BY 1")"
default_acl_records="$(psql_source "SELECT owner.rolname || '|' || COALESCE(namespace.nspname, '<global>') || '|' || defaults.defaclobjtype::text FROM pg_default_acl defaults JOIN pg_roles owner ON owner.oid=defaults.defaclrole LEFT JOIN pg_namespace namespace ON namespace.oid=defaults.defaclnamespace ORDER BY 1")"
public_object_owners="$(psql_source "SELECT DISTINCT inventory.owner FROM (SELECT pg_get_userbyid(relation.relowner) AS owner FROM pg_class relation JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace WHERE namespace.nspname='public' AND relation.relkind IN ('r','p','S') UNION ALL SELECT pg_get_userbyid(procedure.proowner) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public') inventory ORDER BY inventory.owner")"
case "$source_identity_mode" in
    strict-ten-role-v1)
        backupsheep_validate_generation3_source \
            "$installation_id" "$bootstrap_user" "$expected_roles_csv" \
            "$source_roles" "$role_security_records" "$application_membership_count" \
            "$role_settings" "$database_acl" "$schema_acl" "$default_acl" \
            "$default_acl_records" "$database_owner" "$schema_owner" \
            "$public_object_owners" \
            || die "generation-3 source identity validation failed"
        source_expected_roles="$source_roles"
        ;;
    generation2-three-role-v1)
        backupsheep_validate_generation2_source \
            "$installation_id" "$bootstrap_user" "$source_roles" \
            "$role_security_records" "$application_membership_count" \
            "$role_settings" "$database_acl" "$schema_acl" "$default_acl" \
            "$default_acl_records" "$database_owner" "$schema_owner" \
            "$public_object_owners" \
            || die "generation-2 source identity validation failed"
        source_expected_roles="$source_roles"
        ;;
    *) die "internal source identity mode is invalid" ;;
esac
for stock_database in "$database_name" postgres; do
    source_extensions="$(psql_source_db "$stock_database" "SELECT extname FROM pg_extension ORDER BY extname")"
    [[ "$source_extensions" == plpgsql ]] || die "legacy source has non-stock extensions in ${stock_database}"
    [[ "$(psql_source_db "$stock_database" "SELECT count(*) FROM pg_collation c JOIN pg_namespace n ON n.oid=c.collnamespace WHERE n.nspname <> 'pg_catalog'")" == 0 ]] \
        || die "legacy source has non-stock collations in ${stock_database}"
    [[ "$(psql_source_db "$stock_database" 'SELECT count(*) FROM pg_event_trigger')" == 0 ]] \
        || die "legacy source has non-stock event triggers in ${stock_database}"
    [[ "$(psql_source_db "$stock_database" 'SELECT count(*) FROM pg_foreign_data_wrapper')" == 0 \
        && "$(psql_source_db "$stock_database" 'SELECT count(*) FROM pg_foreign_server')" == 0 \
        && "$(psql_source_db "$stock_database" 'SELECT count(*) FROM pg_foreign_table')" == 0 \
        && "$(psql_source_db "$stock_database" 'SELECT count(*) FROM pg_user_mapping')" == 0 ]] \
        || die "legacy source has non-stock foreign-data objects in ${stock_database}"
    [[ "$(psql_source_db "$stock_database" 'SELECT count(*) FROM pg_publication')" == 0 ]] \
        || die "legacy source has non-stock logical publications in ${stock_database}"
    [[ "$(psql_source_db "$stock_database" 'SELECT count(*) FROM pg_largeobject_metadata')" == 0 ]] \
        || die "legacy source has large objects outside the automatic migration contract in ${stock_database}"
    [[ "$(psql_source_db "$stock_database" 'SELECT count(*) FROM pg_seclabel')" == 0 ]] \
        || die "legacy source has security labels outside the automatic migration contract in ${stock_database}"
    [[ "$(psql_source_db "$stock_database" "SELECT count(*) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_language language ON language.oid=procedure.prolang WHERE namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND namespace.nspname <> 'information_schema' AND language.lanname NOT IN ('sql','plpgsql')")" == 0 ]] \
        || die "legacy source has executable routines in an unreviewed language in ${stock_database}"
done
[[ "$(psql_source "SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')")" == 0 ]] \
    || die "legacy source has non-stock tablespaces"
[[ "$(psql_source 'SELECT count(*) FROM pg_replication_slots')" == 0 && "$(psql_source 'SELECT count(*) FROM pg_subscription')" == 0 ]] || die "legacy source has replication state"
[[ "$(psql_source 'SELECT count(*) FROM pg_prepared_xacts')" == 0 ]] \
    || die "legacy source has prepared transactions"
[[ "$(psql_source 'SELECT count(*) FROM pg_parameter_acl')" == 0 ]] \
    || die "legacy source has non-stock parameter privileges"
[[ "$(psql_source 'SELECT count(*) FROM pg_shseclabel')" == 0 ]] \
    || die "legacy source has shared security labels"
grep -Fxq -- "$database_owner" <<< "$source_expected_roles" || die "legacy database owner is not a stock role"
! grep -Fxq -- "$restore_role" <<< "$source_expected_roles" \
    || die "ephemeral restore role collides with the witnessed source identity"
role_hash="$({
    printf 'BackupSheep/postgres-source-identity/v1\n'
    printf 'mode=%s\nroles=\n%s\nrecords=\n%s\nmemberships=%s\n' \
        "$source_identity_mode" "$source_roles" "$role_security_records" \
        "$application_membership_count"
    printf 'settings=\n%s\ndatabase_acl=\n%s\nschema_acl=\n%s\n' \
        "$role_settings" "$database_acl" "$schema_acl"
    printf 'default_acl=\n%s\ndefault_acl_records=\n%s\nowners=%s|%s|%s\n' \
        "$default_acl" "$default_acl_records" "$database_owner" \
        "$schema_owner" "$public_object_owners"
} | openssl dgst -sha256 | awk '{ print $NF }')" \
    || die "could not fingerprint the validated source identity contract"
[[ "$role_hash" =~ ^[0-9a-f]{64}$ ]] \
    || die "source identity contract fingerprint is malformed"

helper_base=(--rm "${common_labels[@]}" --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 128 --user 70:70 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 --entrypoint /bin/sh)
target_initial_helper=("${helper_base[@]}" -v "${target_socket}:/target:ro" -v "${target_bootstrap_secret_file}:/run/secrets/target_password:ro")
target_admin_helper=("${helper_base[@]}" -v "${target_socket}:/target:ro" -v "${secret_file}:/run/secrets/source_password:ro")
target_rotation_helper=("${helper_base[@]}" -v "${target_socket}:/target:ro" -v "${secret_file}:/run/secrets/source_password:ro" -v "${target_bootstrap_secret_file}:/run/secrets/target_password:ro")
target_prepare_helper=("${helper_base[@]}" -v "${target_socket}:/target:ro" -v "${secret_file}:/run/secrets/source_password:ro" -v "${restore_secret_file}:/run/secrets/restore_password:ro")
source_dump_helper=("${helper_base[@]}" -v "${source_socket}:/source:ro" -v "${secret_file}:/run/secrets/source_password:ro")
target_restore_helper=("${helper_base[@]}" -v "${target_socket}:/target:ro" -v "${restore_secret_file}:/run/secrets/restore_password:ro")

target_role_plan="$(printf '%s' "$expected_roles_csv" | awk -F',' \
    -v installation="$installation_id" '
    BEGIN {
        kind[1] = "bootstrap"; kind[2] = "migrator"; kind[3] = "app"
        kind[4] = "preflight"; kind[5] = "beat"; kind[6] = "cloud"
        kind[7] = "database"; kind[8] = "files"; kind[9] = "storage"; kind[10] = "logs"
    }
    NF == 10 {
        for (i = 2; i <= NF; i++)
            print $i "|" kind[i] "|backupsheep:database-identity-v3:" installation ":" kind[i]
    }
')"
[[ "$(wc -l <<< "$target_role_plan" | tr -d ' ')" == 9 ]] \
    || die "could not derive the exact target placeholder plan"
while IFS='|' read -r role_name _role_kind role_marker; do
    "$docker_bin" run "${target_initial_helper[@]}" "$target_image_id" -ceu '
        target_password="$(cat /run/secrets/target_password)"
        {
          printf "%s\n" "SELECT pg_catalog.format('\''CREATE ROLE %I WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 PASSWORD %L'\'', :'\''role_name'\'', :'\''target_password'\'') \\gexec"
          printf "%s\n" "SELECT pg_catalog.format('\''COMMENT ON ROLE %I IS %L'\'', :'\''role_name'\'', :'\''role_marker'\'') \\gexec"
        } | PGPASSWORD="$target_password" psql --no-psqlrc --no-password \
          -h /target -U "$1" -d "$2" -v ON_ERROR_STOP=1 \
          --set="role_name=$3" --set="role_marker=$4" \
          --set="target_password=$target_password"
    ' create-placeholder "$bootstrap_user" "$database_name" "$role_name" \
        "$role_marker" >/dev/null \
        || die "could not create a fixed generation-3 target placeholder"
done <<< "$target_role_plan"

bootstrap_marker="backupsheep:database-identity-v3:${installation_id}:bootstrap"
"$docker_bin" run "${target_rotation_helper[@]}" "$target_image_id" -ceu '
    target_password="$(cat /run/secrets/target_password)"
    source_password="$(cat /run/secrets/source_password)"
    {
      printf "%s\n" "SELECT pg_catalog.format('\''ALTER ROLE %I WITH LOGIN INHERIT SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS CONNECTION LIMIT -1 PASSWORD %L'\'', :'\''bootstrap'\'', :'\''source_password'\'') \\gexec"
      printf "%s\n" "SELECT pg_catalog.format('\''ALTER ROLE %I RESET ALL'\'', :'\''bootstrap'\'') \\gexec"
      printf "%s\n" "SELECT pg_catalog.format('\''COMMENT ON ROLE %I IS %L'\'', :'\''bootstrap'\'', :'\''bootstrap_marker'\'') \\gexec"
    } | PGPASSWORD="$target_password" psql --no-psqlrc --no-password \
      -h /target -U "$1" -d "$2" -v ON_ERROR_STOP=1 \
      --set="bootstrap=$1" --set="bootstrap_marker=$3" \
      --set="source_password=$source_password"
' rotate-bootstrap "$bootstrap_user" "$database_name" "$bootstrap_marker" >/dev/null \
    || die "could not apply the fixed target bootstrap identity"

"$docker_bin" run "${target_rotation_helper[@]}" "$target_image_id" -ceu '
    target_password="$(cat /run/secrets/target_password)"
    if PGPASSWORD="$target_password" psql --no-psqlrc --no-password -h /target \
        -U "$1" -d "$2" -At -v ON_ERROR_STOP=1 -c "SELECT 1" >/dev/null 2>&1; then
        exit 65
    fi
    source_password="$(cat /run/secrets/source_password)"
    PGPASSWORD="$source_password" exec psql --no-psqlrc --no-password -h /target \
        -U "$1" -d "$2" -At -v ON_ERROR_STOP=1 -c "SELECT 1"
' prove-credential-rotation "$bootstrap_user" "$database_name" >/dev/null \
    || die "target bootstrap credential was not replaced by the retained source identity"

attest_target_placeholders() {
    local evidence records memberships settings
    evidence="$(
        "$docker_bin" run --interactive "${target_admin_helper[@]}" \
            "$target_image_id" -seu -- target-placeholder-attestation \
            "$bootstrap_user" "$database_name" \
            <<'TARGET_PLACEHOLDER_SCRIPT'
        [ "$1" = target-placeholder-attestation ]
        shift
        source_password="$(cat /run/secrets/source_password)"
        PGPASSWORD="$source_password" exec psql --no-psqlrc --no-password \
          -h /target -U "$1" -d "$2" -At -v ON_ERROR_STOP=1 <<'SQL'
SELECT role.rolname || '|' || role.rolsuper || '|' || role.rolinherit || '|' ||
       role.rolcreaterole || '|' || role.rolcreatedb || '|' || role.rolcanlogin || '|' ||
       role.rolreplication || '|' || role.rolbypassrls || '|' || role.rolconnlimit || '|' ||
       (role.rolvaliduntil IS NULL) || '|' || (role.rolconfig IS NULL) || '|' ||
       COALESCE(auth.rolpassword LIKE 'SCRAM-SHA-256$%', false) || '|' ||
       COALESCE(pg_catalog.shobj_description(role.oid, 'pg_authid'), '')
  FROM pg_catalog.pg_roles role
  JOIN pg_catalog.pg_authid auth ON auth.oid=role.oid
 WHERE role.rolname !~ '^pg_'
 ORDER BY role.rolname;
\echo --memberships--
SELECT count(*)
  FROM pg_catalog.pg_auth_members membership
  JOIN pg_catalog.pg_roles member ON member.oid=membership.member
  JOIN pg_catalog.pg_roles parent ON parent.oid=membership.roleid
 WHERE member.rolname !~ '^pg_' OR parent.rolname !~ '^pg_';
\echo --settings--
SELECT COALESCE(role.rolname, '<all-roles>') || '|' ||
       COALESCE(database.datname, '<all-databases>') || '|' || setting.value
  FROM pg_catalog.pg_db_role_setting settings
  LEFT JOIN pg_catalog.pg_roles role ON role.oid=settings.setrole
  LEFT JOIN pg_catalog.pg_database database ON database.oid=settings.setdatabase
 CROSS JOIN LATERAL pg_catalog.unnest(settings.setconfig) setting(value)
 ORDER BY 1;
SQL
TARGET_PLACEHOLDER_SCRIPT
    )" \
        || die "could not attest fixed target placeholder identities"
    records="$(sed '/^--memberships--$/,$d' <<< "$evidence")"
    memberships="$(sed -n '/^--memberships--$/,/^--settings--$/p' <<< "$evidence" | sed -n '2p')"
    settings="$(sed -n '/^--settings--$/,$p' <<< "$evidence" | sed '1d')"
    backupsheep_validate_target_placeholders \
        "$installation_id" "$bootstrap_user" "$expected_roles_csv" \
        "$records" "$memberships" "$settings" \
        || die "fixed target placeholder identity validation failed"
}
attest_target_placeholders

rm -- "$target_bootstrap_secret_file" \
    || die "could not remove the retired target bootstrap credential"
[[ ! -e "$target_bootstrap_secret_file" && ! -L "$target_bootstrap_secret_file" ]] \
    || die "retired target bootstrap credential remains after rotation"
target_bootstrap_secret_file=""

restore_role_record="$(
    "$docker_bin" run --interactive "${target_prepare_helper[@]}" \
        "$target_image_id" -seu -- prepare-restore \
        "$bootstrap_user" "$database_name" \
        "$restore_role" "$installation_id" <<'PREPARE_RESTORE_SCRIPT'
    [ "$1" = prepare-restore ]
    shift
    source_password="$(cat /run/secrets/source_password)"
    restore_password="$(cat /run/secrets/restore_password)"
    PGPASSWORD="$source_password" psql --quiet --no-psqlrc --no-password -h /target \
      -U "$1" -d "$2" -v ON_ERROR_STOP=1 -At \
      --set="restore_role=$3" --set="restore_password=$restore_password" \
      --set="installation=$4" --set="database_name=$2" <<'SQL'
SELECT pg_catalog.format(
  'CREATE ROLE %I WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 1 PASSWORD %L',
  :'restore_role', :'restore_password'
) \gexec
SELECT pg_catalog.format(
  'COMMENT ON ROLE %I IS %L',
  :'restore_role', 'backupsheep:postgres-restore-v1:' || :'installation'
) \gexec
SELECT pg_catalog.format('ALTER DATABASE %I OWNER TO %I', :'database_name', :'restore_role') \gexec
SELECT pg_catalog.format('ALTER SCHEMA public OWNER TO %I', :'restore_role') \gexec
SELECT role.rolname || '|' || role.rolsuper || '|' || role.rolinherit || '|' ||
       role.rolcreaterole || '|' || role.rolcreatedb || '|' || role.rolcanlogin || '|' ||
       role.rolreplication || '|' || role.rolbypassrls || '|' || role.rolconnlimit || '|' ||
       (role.rolvaliduntil IS NULL) || '|' || (role.rolconfig IS NULL) || '|' ||
       COALESCE(auth.rolpassword LIKE 'SCRAM-SHA-256$%', false) || '|' ||
       COALESCE(pg_catalog.shobj_description(role.oid, 'pg_authid'), '')
  FROM pg_catalog.pg_roles role
  JOIN pg_catalog.pg_authid auth ON auth.oid=role.oid
 WHERE role.rolname=:'restore_role';
SELECT count(*)
  FROM pg_catalog.pg_auth_members membership
  JOIN pg_catalog.pg_roles member ON member.oid=membership.member
  JOIN pg_catalog.pg_roles parent ON parent.oid=membership.roleid
 WHERE member.rolname=:'restore_role' OR parent.rolname=:'restore_role';
SQL
PREPARE_RESTORE_SCRIPT
)" \
    || die "could not create the isolated unprivileged restore identity"
[[ "$restore_role_record" == "${restore_role}|false|false|false|false|true|false|false|1|true|true|true|backupsheep:postgres-restore-v1:${installation_id}"$'\n''0' ]] \
    || die "ephemeral restore identity privileges, authentication, or memberships drifted"

if ! "$docker_bin" run "${source_dump_helper[@]}" "$target_image_id" -ceu '
    source_password="$(cat /run/secrets/source_password)"
    PGPASSWORD="$source_password" exec pg_dump -h /source -U "$1" -d "$2" \
      --no-password --format=custom --no-owner --no-acl --no-security-labels \
      --lock-wait-timeout=30000
' dump-source "$bootstrap_user" "$database_name" | \
  "$docker_bin" run --interactive "${target_restore_helper[@]}" \
      "$target_image_id" -ceu '
    restore_password="$(cat /run/secrets/restore_password)"
    PGPASSWORD="$restore_password" exec pg_restore --no-password --exit-on-error \
      --single-transaction --no-owner --no-acl --no-security-labels \
      -h /target -U "$1" -d "$2"
' restore-target "$restore_role" "$database_name" >/dev/null; then
    die "isolated unprivileged database restore failed"
fi

if ! "$docker_bin" run --interactive "${target_admin_helper[@]}" \
    "$target_image_id" -seu -- finalize-restore \
    "$bootstrap_user" "$database_name" \
    "$restore_role" "$target_migrator_user" "$target_migrator_user" \
    >/dev/null <<'FINALIZE_RESTORE_SCRIPT'
    [ "$1" = finalize-restore ]
    shift
    source_password="$(cat /run/secrets/source_password)"
    PGPASSWORD="$source_password" psql --no-psqlrc --no-password -h /target \
      -U "$1" -d "$2" -v ON_ERROR_STOP=1 -At \
      --set="restore_role=$3" --set="database_owner=$4" \
      --set="schema_owner=$5" --set="database_name=$2" <<'SQL'
BEGIN;
SELECT pg_catalog.format('ALTER ROLE %I NOLOGIN', :'restore_role') \gexec
SELECT pg_catalog.pg_terminate_backend(activity.pid)
  FROM pg_catalog.pg_stat_activity activity
 WHERE activity.usename=:'restore_role'
   AND activity.pid <> pg_catalog.pg_backend_pid();
SELECT pg_catalog.format('REASSIGN OWNED BY %I TO %I', :'restore_role', :'database_owner') \gexec
SELECT pg_catalog.format('DROP OWNED BY %I', :'restore_role') \gexec
SELECT pg_catalog.format('ALTER DATABASE %I OWNER TO %I', :'database_name', :'database_owner') \gexec
SELECT pg_catalog.format('ALTER SCHEMA public OWNER TO %I', :'schema_owner') \gexec
SELECT pg_catalog.format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'database_name') \gexec
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL ROUTINES IN SCHEMA public FROM PUBLIC;
SELECT pg_catalog.format(
         'REVOKE USAGE ON TYPE %I.%I FROM PUBLIC',
         namespace.nspname,
         type.typname
       )
  FROM pg_catalog.pg_type type
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid=type.typnamespace
 WHERE namespace.nspname='public'
   AND type.typisdefined
   AND type.typtype NOT IN ('m','p')
   AND NOT (
     type.typelem <> 0
     AND type.typsubscript =
       'pg_catalog.array_subscript_handler'::pg_catalog.regproc
   )
 ORDER BY type.oid
\gexec
SELECT pg_catalog.format('DROP ROLE %I', :'restore_role') \gexec
COMMIT;
SQL
FINALIZE_RESTORE_SCRIPT
then
    die "could not retire the ephemeral restore identity and normalize ownership"
fi
attest_target_placeholders

fingerprint_dump() {
    local scope="$1" kind="$2" socket_path=''
    local -a runtime=()
    case "$scope" in
        source) runtime=("${source_dump_helper[@]}"); socket_path=/source ;;
        target) runtime=("${target_admin_helper[@]}"); socket_path=/target ;;
        *) die "internal dump fingerprint scope is invalid" ;;
    esac
    "$docker_bin" run "${runtime[@]}" "$target_image_id" -ceu '
        set -o pipefail
        password="$(cat /run/secrets/source_password)"
        case "$1" in
          schema) dump_mode=--schema-only ;;
          data) dump_mode=--data-only ;;
          *) exit 64 ;;
        esac
        PGPASSWORD="$password" pg_dump --no-password "$dump_mode" \
          --no-owner --no-acl --no-security-labels --restrict-key="$6" \
          --lock-wait-timeout=30000 \
          -h "$2" -U "$3" -d "$4" |
          sed \
            -e "s/^-- Dumped from database version .*/-- Dumped from database version <canonical>/" \
            -e "s/^-- Dumped by pg_dump version .*/-- Dumped by pg_dump version <canonical>/" |
          sha256sum | cut -d" " -f1
    ' dump-fingerprint "$kind" "$socket_path" "$bootstrap_user" \
        "$database_name" "$scope" "$restrict_key"
}

hash_pair() {
    local kind="$1" source_hash target_hash
    source_hash="$(fingerprint_dump source "$kind")" \
        || die "could not fingerprint ${kind} on the isolated source"
    target_hash="$(fingerprint_dump target "$kind")" \
        || die "could not fingerprint ${kind} on the isolated target"
    [[ "$source_hash" =~ ^[0-9a-f]{64}$ && "$source_hash" == "$target_hash" ]] \
        || die "${kind} fingerprint mismatch"
    printf '%s' "$source_hash"
}
schema_hash="$(hash_pair schema)"; data_hash="$(hash_pair data)"

target_roles="$($docker_bin run --rm "${common_labels[@]}" --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 --user 70:70 \
    --entrypoint /bin/sh -v "${target_socket}:/target:ro" \
    -v "${secret_file}:/run/secrets/source_password:ro" "$target_image_id" -ceu '
        password="$(cat /run/secrets/source_password)"
        PGPASSWORD="$password" exec psql --no-psqlrc --no-password -h /target \
            -U "$1" -d "$2" -At -v ON_ERROR_STOP=1 \
            -c "SELECT rolname FROM pg_roles WHERE rolname !~ '\''^pg_'\'' ORDER BY rolname"
    ' target-inventory "$bootstrap_user" "$database_name")"
[[ "$target_roles" == "$expected_roles" ]] \
    || die "target role inventory differs from the fixed generation-3 target identities"
target_ownership="$(
    "$docker_bin" run --interactive --rm "${common_labels[@]}" --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 --user 70:70 \
    --entrypoint /bin/sh -v "${target_socket}:/target:ro" \
    -v "${secret_file}:/run/secrets/source_password:ro" \
    "$target_image_id" -seu -- target-ownership \
    "$bootstrap_user" "$database_name" "$restore_role" \
    <<'TARGET_OWNERSHIP_SCRIPT'
        [ "$1" = target-ownership ]
        shift
        password="$(cat /run/secrets/source_password)"
        PGPASSWORD="$password" exec psql --no-psqlrc --no-password -h /target \
          -U "$1" -d "$2" -At -v ON_ERROR_STOP=1 \
          --set="restore_role=$3" <<'SQL'
SELECT pg_catalog.pg_get_userbyid(database.datdba)
  FROM pg_catalog.pg_database database
 WHERE database.datname=current_database();
SELECT pg_catalog.pg_get_userbyid(namespace.nspowner)
  FROM pg_catalog.pg_namespace namespace
 WHERE namespace.nspname='public';
SELECT DISTINCT inventory.owner
  FROM (
        SELECT pg_catalog.pg_get_userbyid(relation.relowner) AS owner
          FROM pg_catalog.pg_class relation
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='public' AND relation.relkind IN ('r','p','S')
        UNION ALL
        SELECT pg_catalog.pg_get_userbyid(procedure.proowner)
          FROM pg_catalog.pg_proc procedure
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid=procedure.pronamespace
         WHERE namespace.nspname='public'
       ) inventory
 ORDER BY inventory.owner;
SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname=:'restore_role';
SELECT
  (SELECT count(*)
     FROM pg_catalog.pg_database database
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(database.datacl, pg_catalog.acldefault('d', database.datdba))
    ) acl
    WHERE database.datname=pg_catalog.current_database()
      AND acl.grantee <> database.datdba) || '|' ||
  (SELECT count(*)
     FROM pg_catalog.pg_namespace namespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
    ) acl
    WHERE namespace.nspname='public'
      AND acl.grantee <> namespace.nspowner) || '|' ||
  (SELECT count(*)
     FROM pg_catalog.pg_class relation
     JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(
        relation.relacl,
        pg_catalog.acldefault(
          CASE WHEN relation.relkind='S'
               THEN 'S'::pg_catalog."char"
               ELSE 'r'::pg_catalog."char" END,
          relation.relowner
        )
      )
    ) acl
    WHERE namespace.nspname='public'
      AND acl.grantee <> relation.relowner) || '|' ||
  (SELECT count(*)
     FROM pg_catalog.pg_proc procedure
     JOIN pg_catalog.pg_namespace namespace ON namespace.oid=procedure.pronamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))
    ) acl
    WHERE namespace.nspname='public'
      AND acl.grantee <> procedure.proowner) || '|' ||
  (SELECT count(*)
     FROM pg_catalog.pg_type type
     JOIN pg_catalog.pg_namespace namespace ON namespace.oid=type.typnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(type.typacl, pg_catalog.acldefault('T', type.typowner))
    ) acl
    WHERE namespace.nspname='public'
      AND type.typisdefined
      AND type.typtype NOT IN ('m','p')
      AND NOT (
        type.typelem <> 0
        AND type.typsubscript =
          'pg_catalog.array_subscript_handler'::pg_catalog.regproc
      )
      AND acl.grantee <> type.typowner) || '|' ||
  (SELECT count(*)
     FROM pg_catalog.pg_attribute attribute
     JOIN pg_catalog.pg_class relation ON relation.oid=attribute.attrelid
     JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) acl
    WHERE namespace.nspname='public'
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
      AND acl.grantee <> relation.relowner) || '|' ||
  (SELECT count(*) FROM pg_catalog.pg_default_acl) || '|' ||
  (SELECT count(*) FROM pg_catalog.pg_parameter_acl) || '|' ||
  (SELECT count(*) FROM pg_catalog.pg_seclabel) || '|' ||
  (SELECT count(*) FROM pg_catalog.pg_shseclabel) || '|' ||
  (SELECT count(*) FROM pg_catalog.pg_largeobject_metadata);
SQL
TARGET_OWNERSHIP_SCRIPT
)" \
    || die "could not attest target ownership after the unprivileged restore"
expected_target_ownership="$(printf '%s\n%s\n%s\n0\n0|0|0|0|0|0|0|0|0|0|0' \
    "$target_migrator_user" "$target_migrator_user" "$target_migrator_user")"
[[ "$target_ownership" == "$expected_target_ownership" ]] \
    || die "target ownership, ACL isolation, or restore-role retirement differs from the fixed target contract"

[[ "$($docker_bin ps --all --no-trunc --quiet --filter "volume=${source_volume}")" == "$source_id" \
    && "$($docker_bin ps --all --no-trunc --quiet --filter "volume=${target_volume}")" == "$target_id" ]] \
    || die "unexpected storage attachment appeared during migration"
"$docker_bin" run --rm "${common_labels[@]}" --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --pids-limit 64 --user 70:70 \
    --entrypoint /usr/local/bin/backupsheep-postgres-storage-witness \
    -e "BACKUPSHEEP_INSTALLATION_ID=${installation_id}" \
    -e "BACKUPSHEEP_POSTGRES_STORAGE_INTENT=${storage_intent}" \
    -e "BACKUPSHEEP_POSTGRES_STORAGE_WITNESS=${storage_witness}" \
    -e "POSTGRES_USER=${bootstrap_user}" -e "POSTGRES_DB=${database_name}" \
    -e 'POSTGRES_PASSWORD_FILE=/run/secrets/source_password' \
    -v "${target_volume}:/var/lib/postgresql" -v "${target_socket}:/var/run/postgresql:ro" \
    -v "${secret_file}:/run/secrets/source_password:ro" "$target_image_id" finalize-migration \
    "$source_image_id" "$target_image_id" "$role_hash" "$schema_hash" "$data_hash" >/dev/null \
    || die "could not finalize the verified migration receipt"

remove_owned_container "$target_container"
remove_owned_container "$source_container"
rm -- "$restore_secret_file" || die "could not remove the ephemeral restore credential"
[[ ! -e "$restore_secret_file" && ! -L "$restore_secret_file" ]] \
    || die "ephemeral restore credential remains after migration"
restore_secret_file=""
remove_owned_socket_volume "$target_socket"
remove_owned_socket_volume "$source_socket"
printf '%s\n' "PostgreSQL migration verified: source=${source_image_id} target=${target_image_id} roles=${role_hash} schema=${schema_hash} data=${data_hash}"
