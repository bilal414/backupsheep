#!/usr/bin/env bash
# Stop-the-world PostgreSQL 18 Debian -> Alpine/ICU logical migration.
set -Eeuo pipefail
export LC_ALL=C
IFS=$'\n\t'
umask 077

die() { printf '%s\n' "BackupSheep PostgreSQL migration refused: $*" >&2; exit 64; }
[[ $# -eq 12 ]] || die "expected docker, project, installation, source image, target image, source volume, target volume, secret, database, bootstrap role, comma-separated roles, and witness"

docker_bin="$1"; project="$2"; installation_id="$3"; source_image_id="$4"
target_image_ref="$5"; source_volume="$6"; target_volume="$7"; secret_file="$8"
database_name="$9"; bootstrap_user="${10}"; expected_roles_csv="${11}"; storage_witness="${12}"
generation='18-alpine-icu-v1'
source_socket="${project}_postgres_migration_source_socket"
target_socket="${project}_postgres_migration_target_socket"
source_container="${project}-postgres-migration-source"
target_container="${project}-postgres-migration-target"
purpose="postgres-runtime-${storage_witness}"
target_image_id=""
target_secret_file=""
restrict_key=""

[[ -x "$docker_bin" ]] || die "Docker executable is invalid"
[[ "$project" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] || die "project name is invalid"
[[ "$installation_id" =~ ^[0-9a-f]{64}$ && "$storage_witness" =~ ^[0-9a-f]{64}$ ]] || die "identity or witness is invalid"
[[ "$source_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || die "source image ID is invalid"
[[ "$source_volume" == "${project}_pgdata" && "$target_volume" == "${project}_postgres_data_v1" ]] || die "source or target volume name is non-canonical"
[[ "$database_name" =~ ^[a-z_][a-z0-9_]{0,62}$ && "$database_name" != postgres ]] || die "database name is outside the stock migration contract"
[[ "$bootstrap_user" =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || die "bootstrap role is invalid"
[[ -f "$secret_file" && ! -L "$secret_file" ]] || die "bootstrap secret must be a regular non-symlink file"

expected_roles="$(tr ',' '\n' <<< "$expected_roles_csv" | LC_ALL=C sort -u)"
[[ "$(wc -l <<< "$expected_roles" | tr -d ' ')" == 10 ]] || die "exactly ten stock database roles are required"
while IFS= read -r role; do [[ "$role" =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || die "stock role inventory is malformed"; done <<< "$expected_roles"
grep -Fxq -- "$bootstrap_user" <<< "$expected_roles" || die "bootstrap role is absent from the stock inventory"

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

remove_owned_container() {
    local name="$1" id=""
    id="$($docker_bin ps --all --no-trunc --quiet --filter "name=^/${name}$")" || die "could not inventory migration container ${name}"
    [[ -n "$id" ]] || return 0
    [[ "$(docker_resource_label container "$id" com.backupsheep.installation-id)" == "$installation_id" \
        && "$(docker_resource_label container "$id" com.backupsheep.postgres-migration)" == "$purpose" ]] \
        || die "container name ${name} collides with another workload"
    "$docker_bin" stop --time 30 "$id" >/dev/null 2>&1 || true
    "$docker_bin" rm "$id" >/dev/null || die "could not remove the exact stopped migration container ${name}"
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

cleanup() {
    local status=$?
    trap - EXIT
    remove_owned_container "$target_container" || status=74
    remove_owned_container "$source_container" || status=74
    remove_owned_socket_volume "$target_socket" || status=74
    remove_owned_socket_volume "$source_socket" || status=74
    if [[ -n "$target_secret_file" ]]; then
        case "$target_secret_file" in
            "${secret_file}.migration-target."*)
                if [[ -e "$target_secret_file" || -L "$target_secret_file" ]]; then
                    [[ -f "$target_secret_file" && ! -L "$target_secret_file" ]] \
                        || status=74
                    rm -- "$target_secret_file" || status=74
                fi
                ;;
            *) status=74 ;;
        esac
    fi
    exit "$status"
}
trap cleanup EXIT

remove_owned_container "$target_container"
remove_owned_container "$source_container"
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
    evidence="$($docker_bin run --rm --network none --read-only --cap-drop ALL \
        --security-opt no-new-privileges:true --user 70:70 --entrypoint /bin/sh \
        --label "com.backupsheep.project=${project}" \
        --label "com.backupsheep.installation-id=${installation_id}" \
        --label "com.backupsheep.postgres-migration=${purpose}" \
        -v "${target_volume}:/evidence:ro" "$target_image_id" -ceu '
            cat /evidence/.backupsheep-storage-witness-v1 2>/dev/null || true
            printf "%s\n" "--receipt--"
            cat /evidence/.backupsheep-logical-migration-receipt-v1 2>/dev/null || true
        ')" || die "could not inspect an existing witnessed migration target"
    marker_status="$(sed -n '1p' <<< "$evidence")"
    if [[ "$marker_status" == 'status=complete' ]]; then
        [[ "$(sed -n '1p' <<< "$evidence")" == 'status=complete' \
            && "$(sed -n '2p' <<< "$evidence")" == "generation=${generation}" \
            && "$(sed -n '3p' <<< "$evidence")" == "installation=${installation_id}" \
            && "$(sed -n '4p' <<< "$evidence")" == 'intent=migrated-debian-v1' \
            && "$(sed -n '5p' <<< "$evidence")" == "witness=${storage_witness}" \
            && "$(sed -n '6p' <<< "$evidence")" == '--receipt--' \
            && "$(sed -n '7p' <<< "$evidence")" == 'status=complete' \
            && "$(sed -n '8p' <<< "$evidence")" == "source_image=${source_image_id}" ]] \
            || die "completed migration evidence is malformed or belongs to another source"
        recorded_target_image_id="${evidence#*target_image=}"
        recorded_target_image_id="${recorded_target_image_id%%$'\n'*}"
        [[ "$recorded_target_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
            || die "completed migration evidence has a malformed target image ID"
        "$docker_bin" image inspect "$recorded_target_image_id" >/dev/null \
            || die "completed migration target image is no longer available for reconciliation"
        [[ "$($docker_bin image inspect --format '{{.Config.User}}' "$recorded_target_image_id")" == '70:70' \
            && "$(docker_resource_label image "$recorded_target_image_id" com.backupsheep.postgres.runtime-generation)" == '18.6-alpine3.24-icu-v1' ]] \
            || die "completed migration target image no longer has the reviewed runtime identity"
        for line_number in 10 11 12; do
            hash_value="$(sed -n "${line_number}p" <<< "$evidence")"
            [[ "$hash_value" =~ ^(roles|schema|data)_sha256=[0-9a-f]{64}$ ]] \
                || die "completed migration content evidence is malformed"
        done
        printf '%s\n' "PostgreSQL migration reconciled from its completed receipt: source=${source_image_id} target=${recorded_target_image_id}"
        exit 0
    fi
    [[ -z "$marker_status" || "$marker_status" == 'status=pending' ]] \
        || die "existing migration target has an unrecognized marker state"
    "$docker_bin" volume rm "$target_volume" >/dev/null || die "could not remove exact interrupted migration target"
fi

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
target_secret_file="$(mktemp "${secret_file}.migration-target.XXXXXXXX")" \
    || die "could not allocate the ephemeral target credential"
chmod 0600 "$target_secret_file"
openssl rand -hex 32 > "$target_secret_file" || die "could not generate the ephemeral target credential"
restrict_key="$({
    printf '%s' "BackupSheep/postgres-dump-restrict/v1|${installation_id}|${storage_witness}|"
    cat -- "$secret_file"
} | openssl dgst -sha256 | awk '{ print $NF }')" \
    || die "could not derive the dump restriction key"
[[ "$restrict_key" =~ ^[0-9a-f]{64}$ ]] || die "dump restriction key generation failed"

"$docker_bin" run --rm "${common_labels[@]}" "${common_runtime[@]}" --user 70:70 \
    --entrypoint /usr/local/bin/backupsheep-postgres-storage-witness \
    -e "BACKUPSHEEP_INSTALLATION_ID=${installation_id}" \
    -e 'BACKUPSHEEP_POSTGRES_STORAGE_INTENT=migrated-debian-v1' \
    -e "BACKUPSHEEP_POSTGRES_STORAGE_WITNESS=${storage_witness}" \
    -v "${target_volume}:/var/lib/postgresql" \
    "$target_image_id" initialize-migration >/dev/null || die "could not witness the empty migration target"

source_id="$($docker_bin run --detach --name "$source_container" "${common_labels[@]}" "${common_runtime[@]}" \
    --user 999:999 --entrypoint /usr/local/bin/docker-entrypoint.sh \
    -v "${source_volume}:/var/lib/postgresql" -v "${source_socket}:/var/run/postgresql" \
    "$source_image_id" postgres -c listen_addresses= -c unix_socket_directories=/var/run/postgresql)" || die "could not start isolated legacy source"
target_id="$($docker_bin run --detach --name "$target_container" "${common_labels[@]}" "${common_runtime[@]}" \
    --user 70:70 --entrypoint /usr/local/bin/docker-entrypoint.sh \
    -e "POSTGRES_DB=${database_name}" -e "POSTGRES_USER=${bootstrap_user}" \
    -e 'POSTGRES_PASSWORD_FILE=/run/secrets/db_bootstrap_password' \
    -e 'POSTGRES_INITDB_ARGS=--locale-provider=icu --icu-locale=und --encoding=UTF8 --auth-local=scram-sha-256 --auth-host=scram-sha-256' \
    -e "BACKUPSHEEP_INSTALLATION_ID=${installation_id}" \
    -e 'BACKUPSHEEP_POSTGRES_STORAGE_INTENT=migrated-debian-v1' \
    -e "BACKUPSHEEP_POSTGRES_STORAGE_WITNESS=${storage_witness}" \
    -v "${target_volume}:/var/lib/postgresql" -v "${target_socket}:/var/run/postgresql" \
    -v "${target_secret_file}:/run/secrets/db_bootstrap_password:ro" \
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
[[ "$source_roles" == "$expected_roles" ]] || die "legacy source has non-stock or missing roles"
role_attributes="$(psql_source "SELECT rolname || '|' || rolsuper || '|' || rolcreaterole || '|' || rolcreatedb || '|' || rolcanlogin || '|' || rolreplication || '|' || rolbypassrls FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY rolname")"
printf '%s\n' "$role_attributes" | awk -F'|' -v bootstrap="$bootstrap_user" '
    NF != 7 { exit 1 }
    $1 == bootstrap {
        if ($2 != "true" || $3 != "true" || $4 != "true" || $5 != "true" || $6 != "true" || $7 != "true") exit 1
        bootstrap_count++
        next
    }
    $2 != "false" || $3 != "false" || $4 != "false" || $5 != "true" || $6 != "false" || $7 != "false" { exit 1 }
    END { if (bootstrap_count != 1) exit 1 }
' || die "legacy source role privileges are outside the stock contract"
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
done
[[ "$(psql_source "SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')")" == 0 ]] \
    || die "legacy source has non-stock tablespaces"
[[ "$(psql_source 'SELECT count(*) FROM pg_replication_slots')" == 0 && "$(psql_source 'SELECT count(*) FROM pg_subscription')" == 0 ]] || die "legacy source has replication state"
[[ "$(psql_source "SELECT count(*) FROM pg_db_role_setting")" == 0 ]] || die "legacy source has non-stock database/role settings"
[[ "$(psql_source "SELECT count(*) FROM pg_database WHERE NOT datistemplate AND datacl IS NOT NULL")" == 0 ]] \
    || die "legacy source has non-stock database ACLs"
database_owner="$(psql_source "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()")"
grep -Fxq -- "$database_owner" <<< "$expected_roles" || die "legacy database owner is not a stock role"

helper_runtime=(--rm "${common_labels[@]}" --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 128 --user 70:70 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 --entrypoint /bin/sh -v "${source_socket}:/source:ro" -v "${target_socket}:/target:ro" -v "${secret_file}:/run/secrets/source_password:ro" -v "${target_secret_file}:/run/secrets/target_password:ro")
"$docker_bin" run "${helper_runtime[@]}" "$target_image_id" -ceu '
    set -o pipefail
    source_password="$(cat /run/secrets/source_password)"
    target_password="$(cat /run/secrets/target_password)"
    (printf "BEGIN;\n"; PGPASSWORD="$source_password" pg_dumpall -h /source -U "$1" \
      --no-password --roles-only --restrict-key="$4" | \
      sed "/^CREATE ROLE ${1};$/d" || exit 65; printf "COMMIT;\n") |
      PGPASSWORD="$target_password" psql --no-psqlrc --no-password -h /target -U "$2" -d "$3" -v ON_ERROR_STOP=1
' restore-globals "$bootstrap_user" "$bootstrap_user" "$database_name" "$restrict_key" >/dev/null || die "transactional role restore failed"

"$docker_bin" run "${helper_runtime[@]}" "$target_image_id" -ceu '
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

"$docker_bin" run "${helper_runtime[@]}" "$target_image_id" -ceu '
    set -o pipefail
    source_password="$(cat /run/secrets/source_password)"
    (printf "BEGIN;\n"; PGPASSWORD="$source_password" pg_dump -h /source -U "$1" -d "$2" \
      --no-password --format=plain --restrict-key="$5" \
      || exit 65; \
      printf "ALTER DATABASE \"%s\" OWNER TO \"%s\";\nCOMMIT;\n" "$2" "$4") |
      PGPASSWORD="$source_password" psql --no-psqlrc --no-password -h /target -U "$3" -d "$2" -v ON_ERROR_STOP=1
' restore-database "$bootstrap_user" "$database_name" "$bootstrap_user" "$database_owner" "$restrict_key" >/dev/null || die "transactional database restore failed"

hash_pair() {
    local kind="$1" source_hash target_hash
    IFS=' ' read -r source_hash target_hash < <("$docker_bin" run --rm "${common_labels[@]}" --network none \
        --read-only --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 128 \
        --user 70:70 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
        --entrypoint /bin/sh -v "${source_socket}:/source:ro" -v "${target_socket}:/target:ro" \
        -v "${secret_file}:/run/secrets/source_password:ro" "$target_image_id" -ceu '
        set -o pipefail
        password="$(cat /run/secrets/source_password)"
        canonicalize_dump() {
          sed \
            -e "s/^-- Dumped from database version .*/-- Dumped from database version <canonical>/" \
            -e "s/^-- Dumped by pg_dump version .*/-- Dumped by pg_dump version <canonical>/" \
            -e "s/^-- Dumped by pg_dumpall version .*/-- Dumped by pg_dumpall version <canonical>/"
        }
        case "$1" in
          roles) command="pg_dumpall --no-password --roles-only --restrict-key=$4" ;;
          schema) command="pg_dump --no-password --schema-only --restrict-key=$4 -d $3" ;;
          data) command="pg_dump --no-password --data-only --restrict-key=$4 -d $3" ;;
          *) exit 64 ;;
        esac
        source_hash=$(PGPASSWORD="$password" sh -c "$command -h /source -U \"$2\"" | canonicalize_dump | sha256sum | cut -d" " -f1)
        target_hash=$(PGPASSWORD="$password" sh -c "$command -h /target -U \"$2\"" | canonicalize_dump | sha256sum | cut -d" " -f1)
        printf "%s %s\n" "$source_hash" "$target_hash"
    ' hash "$kind" "$bootstrap_user" "$database_name" "$restrict_key")
    [[ "$source_hash" =~ ^[0-9a-f]{64}$ && "$source_hash" == "$target_hash" ]] || die "${kind} fingerprint mismatch"
    printf '%s' "$source_hash"
}
role_hash="$(hash_pair roles)"; schema_hash="$(hash_pair schema)"; data_hash="$(hash_pair data)"

target_roles="$($docker_bin run --rm "${common_labels[@]}" --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 --user 70:70 \
    --entrypoint /bin/sh -v "${target_socket}:/target:ro" \
    -v "${secret_file}:/run/secrets/source_password:ro" "$target_image_id" -ceu '
        password="$(cat /run/secrets/source_password)"
        PGPASSWORD="$password" exec psql --no-psqlrc --no-password -h /target \
            -U "$1" -d "$2" -At -v ON_ERROR_STOP=1 \
            -c "SELECT rolname FROM pg_roles WHERE rolname !~ '\''^pg_'\'' ORDER BY rolname"
    ' target-inventory "$bootstrap_user" "$database_name")"
[[ "$target_roles" == "$expected_roles" ]] || die "target role inventory differs from the exact stock source"

[[ "$($docker_bin ps --all --no-trunc --quiet --filter "volume=${source_volume}")" == "$source_id" \
    && "$($docker_bin ps --all --no-trunc --quiet --filter "volume=${target_volume}")" == "$target_id" ]] \
    || die "unexpected storage attachment appeared during migration"
"$docker_bin" run --rm "${common_labels[@]}" --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --pids-limit 64 --user 70:70 \
    --entrypoint /usr/local/bin/backupsheep-postgres-storage-witness \
    -e "BACKUPSHEEP_INSTALLATION_ID=${installation_id}" \
    -e 'BACKUPSHEEP_POSTGRES_STORAGE_INTENT=migrated-debian-v1' \
    -e "BACKUPSHEEP_POSTGRES_STORAGE_WITNESS=${storage_witness}" \
    -e "POSTGRES_USER=${bootstrap_user}" -e "POSTGRES_DB=${database_name}" \
    -e 'POSTGRES_PASSWORD_FILE=/run/secrets/source_password' \
    -v "${target_volume}:/var/lib/postgresql" -v "${target_socket}:/var/run/postgresql:ro" \
    -v "${secret_file}:/run/secrets/source_password:ro" "$target_image_id" finalize-migration \
    "$source_image_id" "$target_image_id" "$role_hash" "$schema_hash" "$data_hash" >/dev/null \
    || die "could not finalize the verified migration receipt"

remove_owned_container "$target_container"
remove_owned_container "$source_container"
rm -- "$target_secret_file" || die "could not remove the ephemeral target credential"
[[ ! -e "$target_secret_file" && ! -L "$target_secret_file" ]] \
    || die "ephemeral target credential remains after migration"
target_secret_file=""
remove_owned_socket_volume "$target_socket"
remove_owned_socket_volume "$source_socket"
printf '%s\n' "PostgreSQL migration verified: source=${source_image_id} target=${target_image_id} roles=${role_hash} schema=${schema_hash} data=${data_hash}"
