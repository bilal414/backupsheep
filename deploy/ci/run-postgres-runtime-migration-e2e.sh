#!/usr/bin/env bash
# Release-blocking, destructive-only-to-owned-resources PostgreSQL 18.6 migration E2E.
set -Eeuo pipefail
export LC_ALL=C
IFS=$'\n\t'
umask 077

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "${script_dir}/../.." && pwd -P)"
readonly migrator="${repository_root}/deploy/postgres/migrate-runtime.sh"
readonly source_fixture_generation='18.6-trixie-glibc-uid999-v1'
readonly target_generation='18-alpine-icu-v1'
readonly database_name='backupsheep'
readonly bootstrap_role='backupsheep_bootstrap'
readonly migrator_role='backupsheep_migrator'
readonly expected_roles_csv='backupsheep_bootstrap,backupsheep_migrator,backupsheep_app,backupsheep_preflight,backupsheep_beat,backupsheep_cloud,backupsheep_database,backupsheep_files,backupsheep_storage,backupsheep_logs'

fail() {
    printf '%s\n' "BackupSheep PostgreSQL runtime E2E failed: $*" >&2
    exit 1
}

for required_name in TEST_POSTGRES_IMAGE TEST_LEGACY_POSTGRES_IMAGE \
    TEST_POSTGRES_MIGRATION_PREFIX TEST_OWNERSHIP_VALUE; do
    [[ -n "${!required_name:-}" ]] || fail "${required_name} is required"
done
[[ "$TEST_POSTGRES_MIGRATION_PREFIX" =~ ^[a-z0-9][a-z0-9-]{0,39}$ ]] \
    || fail 'the migration project prefix is invalid or too long'
[[ "$TEST_OWNERSHIP_VALUE" =~ ^[A-Za-z0-9._-]{1,160}$ ]] \
    || fail 'the CI ownership value is malformed'
[[ -x "$migrator" && ! -L "$migrator" ]] \
    || fail 'the reviewed runtime migrator is unavailable'
command -v docker >/dev/null 2>&1 || fail 'Docker is unavailable'
command -v openssl >/dev/null 2>&1 || fail 'OpenSSL is unavailable'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'
command -v timeout >/dev/null 2>&1 || fail 'GNU timeout is unavailable'
[[ "$(id -u)" != 0 ]] || fail 'the E2E gate must run as the non-root CI user'
if docker info --format '{{json .SecurityOptions}}' | grep -q 'name=rootless'; then
    fail 'the UID-70/UID-999 file-secret E2E requires a rootful Docker daemon'
fi

readonly docker_command="$(command -v docker)"
readonly timeout_command="$(command -v timeout)"
readonly runtime_parent="${RUNNER_TEMP:-/tmp}"
runtime_root="$(mktemp -d "${runtime_parent}/backupsheep-pg-runtime-e2e.XXXXXXXX")"
readonly runtime_root
readonly runtime_marker="${runtime_root}/.backupsheep-pg-runtime-e2e-owner"
readonly docker_wrapper="${runtime_root}/docker"
printf '%s\n' "$TEST_OWNERSHIP_VALUE" > "$runtime_marker"
chmod 0600 "$runtime_marker"

run_docker() {
    "$timeout_command" --signal=TERM --kill-after=15s 5m "$docker_command" "$@"
}

docker_resource_label() {
    local resource_type="$1" resource_id="$2" label_name="$3"
    local frame_marker='__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__'
    local label_root='' framed_value='' framed_payload=''
    local declared_length='' label_value=''
    case "$resource_type" in
        container|image) label_root='.Config.Labels' ;;
        volume) label_root='.Labels' ;;
        *) return 1 ;;
    esac
    case "$resource_type" in
        container)
            framed_value="$(run_docker inspect --format \
                "{{with index ${label_root} \"${label_name}\"}}{{len .}}:{{.}}{{else}}0:{{end}}${frame_marker}" \
                "$resource_id")" || return 1
            ;;
        image|volume)
            framed_value="$(run_docker "$resource_type" inspect --format \
                "{{with index ${label_root} \"${label_name}\"}}{{len .}}:{{.}}{{else}}0:{{end}}${frame_marker}" \
                "$resource_id")" || return 1
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

readonly source_image_id="$(run_docker image inspect --format '{{.Id}}' "$TEST_LEGACY_POSTGRES_IMAGE")"
readonly target_image_id="$(run_docker image inspect --format '{{.Id}}' "$TEST_POSTGRES_IMAGE")"
for image_id in "$source_image_id" "$target_image_id"; do
    [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'a test image ID is malformed'
    [[ "$(docker_resource_label image "$image_id" com.backupsheep.ci-run)" == "$TEST_OWNERSHIP_VALUE" ]] \
        || fail 'a test image is not owned by this exact CI run'
done
[[ "$(run_docker image inspect --format '{{.Config.User}}' "$source_image_id")" == '999:999' \
    && "$(docker_resource_label image "$source_image_id" com.backupsheep.postgres.runtime-migration-source-fixture)" == "$source_fixture_generation" ]] \
    || fail 'the retired Debian/glibc source fixture identity drifted'
[[ "$(run_docker image inspect --format '{{.Config.User}}' "$target_image_id")" == '70:70' \
    && "$(docker_resource_label image "$target_image_id" com.backupsheep.postgres.runtime-generation)" == '18.6-alpine3.24-icu-v1' ]] \
    || fail 'the current Alpine/ICU target image identity drifted'

cat > "$docker_wrapper" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

for name in BACKUPSHEEP_E2E_REAL_DOCKER BACKUPSHEEP_E2E_TIMEOUT \
    BACKUPSHEEP_E2E_MIGRATION_PID BACKUPSHEEP_E2E_FAILPOINT \
    BACKUPSHEEP_E2E_FAILPOINT_STATE BACKUPSHEEP_E2E_PROJECT; do
    [[ -n "${!name:-}" ]] || exit 96
done
[[ "$BACKUPSHEEP_E2E_MIGRATION_PID" =~ ^[1-9][0-9]*$ ]] || exit 96
[[ "$BACKUPSHEEP_E2E_PROJECT" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] || exit 96

contains_argument() {
    local expected="$1" argument=''
    shift
    for argument in "$@"; do
        [[ "$argument" == "$expected" ]] && return 0
    done
    return 1
}

trigger=false
case "$BACKUPSHEEP_E2E_FAILPOINT" in
    none) exec "$BACKUPSHEEP_E2E_TIMEOUT" --signal=TERM --kill-after=15s 5m \
        "$BACKUPSHEEP_E2E_REAL_DOCKER" "$@" ;;
    credential)
        contains_argument credential-read-attestation "$@" && trigger=true
        ;;
    helper)
        contains_argument "${BACKUPSHEEP_E2E_PROJECT}-postgres-migration-target" "$@" \
            && contains_argument --detach "$@" && trigger=true
        ;;
    receipt)
        contains_argument finalize-migration "$@" && trigger=true
        ;;
    *) exit 96 ;;
esac

status=0
"$BACKUPSHEEP_E2E_TIMEOUT" --signal=TERM --kill-after=15s 5m \
    "$BACKUPSHEEP_E2E_REAL_DOCKER" "$@" || status=$?
[[ "$status" -eq 0 ]] || exit "$status"
if [[ "$trigger" == true && ! -e "$BACKUPSHEEP_E2E_FAILPOINT_STATE" \
    && ! -L "$BACKUPSHEEP_E2E_FAILPOINT_STATE" ]]; then
    printf '%s\n' "$BACKUPSHEEP_E2E_FAILPOINT" > "$BACKUPSHEEP_E2E_FAILPOINT_STATE"
    chmod 0600 "$BACKUPSHEEP_E2E_FAILPOINT_STATE"
    kill -KILL "$BACKUPSHEEP_E2E_MIGRATION_PID"
    exit 137
fi
WRAPPER
chmod 0555 "$docker_wrapper"

declare -a scenario_projects=()
declare -a scenario_installations=()
declare -a scenario_witnesses=()
cleanup_failed=false
active_migration_pid=''

cleanup_scenario() {
    local project="$1" installation_id="$2" storage_witness="$3"
    local purpose="postgres-runtime-${storage_witness}"
    local ids='' id='' ci_owner='' migration_owner='' volume=''
    ids="$(run_docker container ls --all --no-trunc --quiet \
        --filter "label=com.backupsheep.project=${project}" \
        --filter "label=com.backupsheep.installation-id=${installation_id}" 2>/dev/null || true)"
    while IFS= read -r id; do
        [[ -n "$id" ]] || continue
        ci_owner="$(docker_resource_label container "$id" com.backupsheep.postgres-runtime-e2e 2>/dev/null || true)"
        migration_owner="$(docker_resource_label container "$id" com.backupsheep.postgres-migration 2>/dev/null || true)"
        if [[ "$ci_owner" != "$TEST_OWNERSHIP_VALUE" && "$migration_owner" != "$purpose" ]]; then
            printf '%s\n' "Refusing to clean an unexpected container for ${project}." >&2
            cleanup_failed=true
            continue
        fi
        run_docker container rm --force "$id" >/dev/null 2>&1 || cleanup_failed=true
    done <<< "$ids"

    for volume in \
        "${project}_pgdata" \
        "${project}_postgres_data_v1" \
        "${project}_postgres_migration_source_socket" \
        "${project}_postgres_migration_target_socket" \
        "${project}_fixture_socket" \
        "${project}_verify_socket"; do
        run_docker volume inspect "$volume" >/dev/null 2>&1 || continue
        ci_owner="$(docker_resource_label volume "$volume" com.backupsheep.postgres-runtime-e2e 2>/dev/null || true)"
        migration_owner="$(docker_resource_label volume "$volume" com.backupsheep.postgres-migration 2>/dev/null || true)"
        if [[ "$ci_owner" != "$TEST_OWNERSHIP_VALUE" && "$migration_owner" != "$purpose" ]]; then
            printf '%s\n' "Refusing to clean an unexpected volume ${volume}." >&2
            cleanup_failed=true
            continue
        fi
        if run_docker container ls --all --quiet --filter "volume=${volume}" | grep -q .; then
            printf '%s\n' "Refusing to remove attached owned volume ${volume}." >&2
            cleanup_failed=true
            continue
        fi
        run_docker volume rm "$volume" >/dev/null 2>&1 || cleanup_failed=true
    done
}

cleanup() {
    local status=$? index=0
    trap - EXIT HUP INT TERM
    if [[ "$active_migration_pid" =~ ^[1-9][0-9]*$ ]] \
        && kill -0 "$active_migration_pid" >/dev/null 2>&1; then
        kill -TERM "$active_migration_pid" >/dev/null 2>&1 || true
        for _attempt in $(seq 1 20); do
            kill -0 "$active_migration_pid" >/dev/null 2>&1 || break
            sleep 1
        done
        if kill -0 "$active_migration_pid" >/dev/null 2>&1; then
            kill -KILL "$active_migration_pid" >/dev/null 2>&1 || true
        fi
        wait "$active_migration_pid" >/dev/null 2>&1 || true
    fi
    for ((index=0; index<${#scenario_projects[@]}; index++)); do
        cleanup_scenario "${scenario_projects[$index]}" \
            "${scenario_installations[$index]}" "${scenario_witnesses[$index]}"
    done
    if [[ -d "$runtime_root" && ! -L "$runtime_root" \
        && -f "$runtime_marker" && ! -L "$runtime_marker" \
        && "$(<"$runtime_marker")" == "$TEST_OWNERSHIP_VALUE" ]]; then
        if find "$runtime_root" -xdev -type l -print -quit | grep -q .; then
            printf '%s\n' 'Refusing to traverse a symlink in the E2E runtime directory.' >&2
            cleanup_failed=true
        else
            find "$runtime_root" -xdev -type f -delete
            find "$runtime_root" -xdev -depth -type d -empty -delete
        fi
    else
        printf '%s\n' 'Refusing to clean an unowned E2E runtime directory.' >&2
        cleanup_failed=true
    fi
    if [[ "$cleanup_failed" == true && "$status" -eq 0 ]]; then
        status=1
    fi
    exit "$status"
}
on_signal() { exit 130; }
trap cleanup EXIT
trap on_signal HUP INT TERM

scenario_project=''
scenario_installation=''
scenario_witness=''
scenario_intent=''
scenario_database_generation=''
scenario_secret=''
scenario_source_volume=''
scenario_target_volume=''
scenario_purpose=''

register_scenario() {
    local suffix="$1" intent="$2" database_generation="$3"
    local project="${TEST_POSTGRES_MIGRATION_PREFIX}-${suffix}"
    local installation_id witness secret source_volume target_volume purpose
    [[ "$project" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] \
        || fail "scenario ${suffix} produced an invalid project name"
    installation_id="$(openssl rand -hex 32)"
    witness="$(printf '%s' \
        "BackupSheep/postgres-storage/v1|${installation_id}|${project}|postgres_data_v1|${target_generation}|icu=und|${intent}" \
        | sha256sum | awk '{print $1}')"
    [[ "$installation_id" =~ ^[0-9a-f]{64}$ && "$witness" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'could not generate a scenario identity'
    secret="${runtime_root}/${suffix}.source-password"
    openssl rand -hex 32 > "$secret"
    chmod 0444 "$secret"
    source_volume="${project}_pgdata"
    target_volume="${project}_postgres_data_v1"
    purpose="postgres-runtime-${witness}"

    if run_docker volume inspect "$source_volume" >/dev/null 2>&1 \
        || run_docker volume inspect "$target_volume" >/dev/null 2>&1 \
        || run_docker container ls --all --quiet \
            --filter "label=com.backupsheep.project=${project}" | grep -q .; then
        fail "scenario ${suffix} collided with pre-existing Docker state"
    fi
    scenario_projects+=("$project")
    scenario_installations+=("$installation_id")
    scenario_witnesses+=("$witness")
    scenario_project="$project"
    scenario_installation="$installation_id"
    scenario_witness="$witness"
    scenario_intent="$intent"
    scenario_database_generation="$database_generation"
    scenario_secret="$secret"
    scenario_source_volume="$source_volume"
    scenario_target_volume="$target_volume"
    scenario_purpose="$purpose"
}

create_owned_volume() {
    local name="$1" project="$2" installation_id="$3" logical_name="$4"
    local created
    created="$(run_docker volume create \
        --label "com.backupsheep.postgres-runtime-e2e=${TEST_OWNERSHIP_VALUE}" \
        --label "com.backupsheep.project=${project}" \
        --label "com.backupsheep.installation-id=${installation_id}" \
        --label "com.docker.compose.project=${project}" \
        --label "com.docker.compose.volume=${logical_name}" \
        "$name")"
    [[ "$created" == "$name" ]] || fail "Docker returned the wrong volume for ${name}"
}

source_editor_container=''
source_editor_socket=''
open_source_editor() {
    local project="$1" installation_id="$2" source_volume="$3" secret="$4"
    local ready=false container="${project}-fixture-source" socket="${project}_fixture_socket"
    create_owned_volume "$socket" "$project" "$installation_id" fixture_socket
    run_docker run --detach --name "$container" \
        --label "com.backupsheep.postgres-runtime-e2e=${TEST_OWNERSHIP_VALUE}" \
        --label "com.backupsheep.project=${project}" \
        --label "com.backupsheep.installation-id=${installation_id}" \
        --network none --read-only --user 999:999 --cap-drop ALL \
        --security-opt no-new-privileges:true --pids-limit 256 \
        --memory 1g --memory-swap 1g --cpus 1 --ulimit core=0:0 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
        --env "POSTGRES_DB=${database_name}" \
        --env "POSTGRES_USER=${bootstrap_role}" \
        --env 'POSTGRES_PASSWORD_FILE=/run/secrets/source_password' \
        --env 'POSTGRES_INITDB_ARGS=--locale=C.UTF-8 --encoding=UTF8 --auth-local=scram-sha-256 --auth-host=scram-sha-256' \
        --volume "${source_volume}:/var/lib/postgresql" \
        --volume "${socket}:/var/run/postgresql" \
        --volume "${secret}:/run/secrets/source_password:ro" \
        "$source_image_id" postgres -c listen_addresses= \
        -c unix_socket_directories=/var/run/postgresql >/dev/null
    source_editor_container="$container"
    source_editor_socket="$socket"
    for _attempt in $(seq 1 90); do
        if run_docker exec "$container" /bin/sh -ceu '
            password="$(cat /run/secrets/source_password)"
            PGPASSWORD="$password" pg_isready -q -h /var/run/postgresql -U "$1" -d "$2"
        ' source-ready "$bootstrap_role" "$database_name"; then
            ready=true
            break
        fi
        [[ "$(run_docker inspect --format '{{.State.Running}}' "$container")" == true ]] || break
        sleep 1
    done
    if [[ "$ready" != true ]]; then
        run_docker logs --tail 200 "$container" >&2 2>/dev/null || true
        fail "source fixture ${project} did not become ready"
    fi
}

source_psql() {
    local installation_id="$1"
    [[ -n "$source_editor_container" ]] || fail 'source editor is not running'
    run_docker exec --interactive "$source_editor_container" /bin/sh -ceu '
        password="$(cat /run/secrets/source_password)"
        PGPASSWORD="$password" exec psql --no-psqlrc --no-password \
            -h /var/run/postgresql -U "$1" -d "$2" \
            -v ON_ERROR_STOP=1 --set="installation=$3"
    ' source-editor "$bootstrap_role" "$database_name" "$installation_id"
}

source_query() {
    local query="$1"
    run_docker exec "$source_editor_container" /bin/sh -ceu '
        password="$(cat /run/secrets/source_password)"
        PGPASSWORD="$password" exec psql --no-psqlrc --no-password \
            -h /var/run/postgresql -U "$1" -d "$2" -At -v ON_ERROR_STOP=1 -c "$3"
    ' source-query "$bootstrap_role" "$database_name" "$query"
}

close_source_editor() {
    local container="$source_editor_container" socket="$source_editor_socket"
    [[ -n "$container" && -n "$socket" ]] || fail 'source editor state is incomplete'
    run_docker stop --time 30 "$container" >/dev/null
    run_docker container rm "$container" >/dev/null
    run_docker volume rm "$socket" >/dev/null
    source_editor_container=''
    source_editor_socket=''
}

create_generation2_source() {
    open_source_editor "$scenario_project" "$scenario_installation" \
        "$scenario_source_volume" "$scenario_secret"
    source_psql "$scenario_installation" <<'SQL'
CREATE ROLE backupsheep_migrator WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 PASSWORD 'fixture-only-scram-migrator';
CREATE ROLE backupsheep_runtime WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 PASSWORD 'fixture-only-scram-runtime';
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_bootstrap IS %L', 'backupsheep:database-identity-v2:' || :'installation' || ':bootstrap') \gexec
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_migrator IS %L', 'backupsheep:database-identity-v2:' || :'installation' || ':migrator') \gexec
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_runtime IS %L', 'backupsheep:database-identity-v2:' || :'installation' || ':runtime') \gexec
ALTER ROLE backupsheep_migrator SET search_path = public, pg_catalog;
ALTER ROLE backupsheep_runtime SET search_path = public, pg_catalog;
ALTER DATABASE backupsheep OWNER TO backupsheep_migrator;
ALTER SCHEMA public OWNER TO backupsheep_migrator;
SET ROLE backupsheep_migrator;
REVOKE ALL ON DATABASE backupsheep FROM PUBLIC;
GRANT CONNECT ON DATABASE backupsheep TO backupsheep_runtime;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO backupsheep_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO backupsheep_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO backupsheep_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, USAGE ON SEQUENCES TO backupsheep_runtime;
CREATE TYPE public.fixture_state AS ENUM ('queued', 'complete');
CREATE DOMAIN public.fixture_code AS text NOT NULL CHECK (VALUE ~ '^[a-z][a-z0-9-]{2,31}$');
CREATE TYPE public.fixture_pair AS (label text, amount integer);
CREATE TABLE public.migration_fixture (
    id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    state public.fixture_state NOT NULL,
    code public.fixture_code NOT NULL,
    pair public.fixture_pair NOT NULL
);
INSERT INTO public.migration_fixture (state, code, pair) VALUES
    ('queued', 'first-item', ROW('first', 11)::public.fixture_pair),
    ('complete', 'second-item', ROW('second', 29)::public.fixture_pair);
CREATE FUNCTION public.fixture_label(value public.fixture_pair) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
    RETURN (value).label || ':' || (value).amount::text;
RESET ROLE;
SQL
    close_source_editor
}

create_generation3_source() {
    open_source_editor "$scenario_project" "$scenario_installation" \
        "$scenario_source_volume" "$scenario_secret"
    source_psql "$scenario_installation" <<'SQL'
CREATE ROLE backupsheep_migrator WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8 PASSWORD 'fixture-only-scram-migrator';
CREATE ROLE backupsheep_app WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 128 PASSWORD 'fixture-only-scram-app';
CREATE ROLE backupsheep_preflight WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8 PASSWORD 'fixture-only-scram-preflight';
CREATE ROLE backupsheep_beat WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8 PASSWORD 'fixture-only-scram-beat';
CREATE ROLE backupsheep_cloud WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 128 PASSWORD 'fixture-only-scram-cloud';
CREATE ROLE backupsheep_database WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 128 PASSWORD 'fixture-only-scram-database';
CREATE ROLE backupsheep_files WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 128 PASSWORD 'fixture-only-scram-files';
CREATE ROLE backupsheep_storage WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 128 PASSWORD 'fixture-only-scram-storage';
CREATE ROLE backupsheep_logs WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 128 PASSWORD 'fixture-only-scram-logs';
CREATE ROLE backupsheep_runtime WITH NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_bootstrap IS %L', 'backupsheep:database-identity-v3:' || :'installation' || ':bootstrap') \gexec
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_migrator IS %L', 'backupsheep:database-identity-v3:' || :'installation' || ':migrator') \gexec
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_app IS %L', 'backupsheep:database-identity-v3:' || :'installation' || ':app') \gexec
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_preflight IS %L', 'backupsheep:database-identity-v3:' || :'installation' || ':preflight') \gexec
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_beat IS %L', 'backupsheep:database-identity-v3:' || :'installation' || ':beat') \gexec
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_cloud IS %L', 'backupsheep:database-identity-v3:' || :'installation' || ':cloud') \gexec
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_database IS %L', 'backupsheep:database-identity-v3:' || :'installation' || ':database') \gexec
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_files IS %L', 'backupsheep:database-identity-v3:' || :'installation' || ':files') \gexec
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_storage IS %L', 'backupsheep:database-identity-v3:' || :'installation' || ':storage') \gexec
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_logs IS %L', 'backupsheep:database-identity-v3:' || :'installation' || ':logs') \gexec
SELECT pg_catalog.format('COMMENT ON ROLE backupsheep_runtime IS %L', 'backupsheep:database-identity-v3:' || :'installation' || ':retired-v2-runtime') \gexec
SELECT pg_catalog.format('ALTER ROLE %I SET idle_in_transaction_session_timeout = %L', role_name, '5min')
  FROM (VALUES
    ('backupsheep_migrator'), ('backupsheep_app'), ('backupsheep_preflight'),
    ('backupsheep_beat'), ('backupsheep_cloud'), ('backupsheep_database'),
    ('backupsheep_files'), ('backupsheep_storage'), ('backupsheep_logs')
  ) AS roles(role_name) \gexec
SELECT pg_catalog.format('ALTER ROLE %I SET lock_timeout = %L', role_name, '30s')
  FROM (VALUES
    ('backupsheep_migrator'), ('backupsheep_app'), ('backupsheep_preflight'),
    ('backupsheep_beat'), ('backupsheep_cloud'), ('backupsheep_database'),
    ('backupsheep_files'), ('backupsheep_storage'), ('backupsheep_logs')
  ) AS roles(role_name) \gexec
SELECT pg_catalog.format('ALTER ROLE %I SET search_path = public, pg_catalog', role_name)
  FROM (VALUES
    ('backupsheep_migrator'), ('backupsheep_app'), ('backupsheep_preflight'),
    ('backupsheep_beat'), ('backupsheep_cloud'), ('backupsheep_database'),
    ('backupsheep_files'), ('backupsheep_storage'), ('backupsheep_logs')
  ) AS roles(role_name) \gexec
SELECT pg_catalog.format('ALTER ROLE %I SET statement_timeout = %L', role_name, '1h')
  FROM (VALUES
    ('backupsheep_migrator'), ('backupsheep_app'), ('backupsheep_preflight'),
    ('backupsheep_beat'), ('backupsheep_cloud'), ('backupsheep_database'),
    ('backupsheep_files'), ('backupsheep_storage'), ('backupsheep_logs')
  ) AS roles(role_name) \gexec
ALTER DATABASE backupsheep OWNER TO backupsheep_migrator;
ALTER SCHEMA public OWNER TO backupsheep_migrator;
SET ROLE backupsheep_migrator;
REVOKE ALL ON DATABASE backupsheep FROM PUBLIC;
GRANT CONNECT ON DATABASE backupsheep TO backupsheep_app, backupsheep_preflight,
    backupsheep_beat, backupsheep_cloud, backupsheep_database, backupsheep_files,
    backupsheep_storage, backupsheep_logs;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO backupsheep_app, backupsheep_preflight,
    backupsheep_beat, backupsheep_cloud, backupsheep_database, backupsheep_files,
    backupsheep_storage, backupsheep_logs;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE USAGE ON TYPES FROM PUBLIC;
CREATE TYPE public.fixture_state AS ENUM ('queued', 'complete');
CREATE DOMAIN public.fixture_code AS text NOT NULL CHECK (VALUE ~ '^[a-z][a-z0-9-]{2,31}$');
CREATE TYPE public.fixture_pair AS (label text, amount integer);
CREATE TABLE public.migration_fixture (
    id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    state public.fixture_state NOT NULL,
    code public.fixture_code NOT NULL,
    pair public.fixture_pair NOT NULL
);
INSERT INTO public.migration_fixture (state, code, pair) VALUES
    ('queued', 'first-item', ROW('first', 11)::public.fixture_pair),
    ('complete', 'second-item', ROW('second', 29)::public.fixture_pair);
CREATE FUNCTION public.fixture_label(value public.fixture_pair) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
    RETURN (value).label || ':' || (value).amount::text;
RESET ROLE;
SQL
    close_source_editor
}

LAST_MIGRATION_STATUS=''
LAST_MIGRATION_LOG=''
LAST_FAILPOINT_STATE=''
run_migration() {
    local failpoint="$1" database_generation="${2:-$scenario_database_generation}"
    local label="${3:-$failpoint}" log state pid status=0
    log="${runtime_root}/${scenario_project}.${label}.log"
    state="${runtime_root}/${scenario_project}.${label}.failpoint"
    [[ ! -e "$log" && ! -L "$log" && ! -e "$state" && ! -L "$state" ]] \
        || fail "migration evidence path ${label} already exists"
    (
        export BACKUPSHEEP_E2E_REAL_DOCKER="$docker_command"
        export BACKUPSHEEP_E2E_TIMEOUT="$timeout_command"
        export BACKUPSHEEP_E2E_MIGRATION_PID="$BASHPID"
        export BACKUPSHEEP_E2E_FAILPOINT="$failpoint"
        export BACKUPSHEEP_E2E_FAILPOINT_STATE="$state"
        export BACKUPSHEEP_E2E_PROJECT="$scenario_project"
        exec "$migrator" "$docker_wrapper" "$scenario_project" \
            "$scenario_installation" "$source_image_id" "$TEST_POSTGRES_IMAGE" \
            "$scenario_source_volume" "$scenario_target_volume" "$scenario_secret" \
            "$database_name" "$bootstrap_role" "$expected_roles_csv" \
            "$scenario_witness" "$scenario_intent" "$database_generation"
    ) >"$log" 2>&1 &
    pid=$!
    active_migration_pid="$pid"
    wait "$pid" || status=$?
    active_migration_pid=''
    LAST_MIGRATION_STATUS="$status"
    LAST_MIGRATION_LOG="$log"
    LAST_FAILPOINT_STATE="$state"
}

assert_no_ephemeral_credentials() {
    local secret="$1"
    if compgen -G "${secret}.migration-bootstrap.*" >/dev/null \
        || compgen -G "${secret}.migration-restore.*" >/dev/null; then
        fail 'an ephemeral migration credential remained unexpectedly'
    fi
}

ephemeral_credential_inventory() {
    local secret="$1"
    compgen -G "${secret}.migration-bootstrap.*" || true
    compgen -G "${secret}.migration-restore.*" || true
}

assert_migration_quiescent() {
    local project="$1" secret="$2"
    [[ -z "$(run_docker container ls --all --no-trunc --quiet \
        --filter "label=com.backupsheep.postgres-migration=${scenario_purpose}")" ]] \
        || fail 'a migration helper remained after a handled exit'
    for socket in "${project}_postgres_migration_source_socket" \
        "${project}_postgres_migration_target_socket"; do
        ! run_docker volume inspect "$socket" >/dev/null 2>&1 \
            || fail "temporary socket ${socket} remained after a handled exit"
    done
    assert_no_ephemeral_credentials "$secret"
}

expect_refusal() {
    local expected_message="$1" label="$2"
    run_migration none "$scenario_database_generation" "$label"
    [[ "$LAST_MIGRATION_STATUS" -eq 64 ]] \
        || { tail -200 "$LAST_MIGRATION_LOG" >&2; fail "${label} did not fail closed with status 64"; }
    grep -Fq -- "$expected_message" "$LAST_MIGRATION_LOG" \
        || { tail -200 "$LAST_MIGRATION_LOG" >&2; fail "${label} did not produce its exact refusal evidence"; }
    ! grep -Fq 'PostgreSQL migration verified:' "$LAST_MIGRATION_LOG" \
        || fail "${label} reported a false successful migration"
    assert_migration_quiescent "$scenario_project" "$scenario_secret"
}

edit_source() {
    open_source_editor "$scenario_project" "$scenario_installation" \
        "$scenario_source_volume" "$scenario_secret"
    source_psql "$scenario_installation"
    close_source_editor
}

target_query() {
    local container="$1" query="$2"
    run_docker exec "$container" /bin/sh -ceu '
        password="$(cat /run/secrets/source_password)"
        PGPASSWORD="$password" exec psql --no-psqlrc --no-password \
            -h /var/run/postgresql -U "$1" -d "$2" -At -v ON_ERROR_STOP=1 -c "$3"
    ' target-query "$bootstrap_role" "$database_name" "$query"
}

verify_target() {
    local project="$scenario_project" installation_id="$scenario_installation"
    local witness="$scenario_witness" intent="$scenario_intent"
    local target_volume="$scenario_target_volume" secret="$scenario_secret"
    local container="${project}-verify-target" socket="${project}_verify_socket"
    local ready=false evidence expected_roles owners acl_vector effective
    create_owned_volume "$socket" "$project" "$installation_id" verify_socket
    run_docker run --detach --name "$container" \
        --label "com.backupsheep.postgres-runtime-e2e=${TEST_OWNERSHIP_VALUE}" \
        --label "com.backupsheep.project=${project}" \
        --label "com.backupsheep.installation-id=${installation_id}" \
        --network none --read-only --user 70:70 --cap-drop ALL \
        --security-opt no-new-privileges:true --pids-limit 256 \
        --memory 1g --memory-swap 1g --cpus 1 --ulimit core=0:0 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
        --env "BACKUPSHEEP_INSTALLATION_ID=${installation_id}" \
        --env "BACKUPSHEEP_POSTGRES_STORAGE_GENERATION=${target_generation}-pending-upgrade" \
        --env "BACKUPSHEEP_POSTGRES_STORAGE_INTENT=${intent}" \
        --env "BACKUPSHEEP_POSTGRES_STORAGE_WITNESS=${witness}" \
        --env "POSTGRES_DB=${database_name}" --env "POSTGRES_USER=${bootstrap_role}" \
        --volume "${target_volume}:/var/lib/postgresql" \
        --volume "${socket}:/var/run/postgresql" \
        --volume "${secret}:/run/secrets/source_password:ro" \
        "$target_image_id" postgres -c listen_addresses= \
        -c unix_socket_directories=/var/run/postgresql >/dev/null
    for _attempt in $(seq 1 90); do
        if run_docker exec "$container" /bin/sh -ceu '
            password="$(cat /run/secrets/source_password)"
            PGPASSWORD="$password" pg_isready -q -h /var/run/postgresql -U "$1" -d "$2"
        ' target-ready "$bootstrap_role" "$database_name"; then
            ready=true
            break
        fi
        [[ "$(run_docker inspect --format '{{.State.Running}}' "$container")" == true ]] || break
        sleep 1
    done
    if [[ "$ready" != true ]]; then
        run_docker logs --tail 200 "$container" >&2 2>/dev/null || true
        fail "migrated target ${project} did not become ready"
    fi

    evidence="$(target_query "$container" "SELECT id::text || '|' || state::text || '|' || code::text || '|' || (pair).label || '|' || (pair).amount::text FROM public.migration_fixture ORDER BY id")"
    [[ "$evidence" == $'1|queued|first-item|first|11\n2|complete|second-item|second|29' ]] \
        || fail 'migrated row data differs from the witnessed source'
    [[ "$(target_query "$container" "SELECT string_agg(enumlabel, ',' ORDER BY enumsortorder) FROM pg_catalog.pg_enum WHERE enumtypid='public.fixture_state'::pg_catalog.regtype")" == 'queued,complete' ]] \
        || fail 'the public enum definition or order did not survive migration'
    [[ "$(target_query "$container" "SELECT type.typtype::text || '|' || type.typnotnull || '|' || type.typbasetype::pg_catalog.regtype::text FROM pg_catalog.pg_type type WHERE type.oid='public.fixture_code'::pg_catalog.regtype")" == 'd|t|text' ]] \
        || fail 'the public domain definition did not survive migration'
    [[ "$(target_query "$container" "SELECT string_agg(attribute.attname || ':' || attribute.atttypid::pg_catalog.regtype::text, ',' ORDER BY attribute.attnum) FROM pg_catalog.pg_attribute attribute WHERE attribute.attrelid='public.fixture_pair'::pg_catalog.regclass AND attribute.attnum > 0 AND NOT attribute.attisdropped")" == 'label:text,amount:integer' ]] \
        || fail 'the public composite definition did not survive migration'

    expected_roles="$(printf '%s' "$expected_roles_csv" | tr ',' '\n' | LC_ALL=C sort)"
    [[ "$(target_query "$container" "SELECT rolname FROM pg_catalog.pg_roles WHERE rolname !~ '^pg_' ORDER BY rolname")" == "$expected_roles" ]] \
        || fail 'the migrated target role inventory is not the exact active generation-3 roster'
    [[ "$(target_query "$container" "SELECT count(*) FROM pg_catalog.pg_auth_members membership JOIN pg_catalog.pg_roles member ON member.oid=membership.member JOIN pg_catalog.pg_roles parent ON parent.oid=membership.roleid WHERE member.rolname !~ '^pg_' OR parent.rolname !~ '^pg_'")" == 0 \
        && "$(target_query "$container" 'SELECT count(*) FROM pg_catalog.pg_db_role_setting')" == 0 ]] \
        || fail 'the target retained a source membership or role setting'

    owners="$(target_query "$container" "SELECT DISTINCT owner FROM (SELECT pg_catalog.pg_get_userbyid(database.datdba) owner FROM pg_catalog.pg_database database WHERE database.datname=current_database() UNION ALL SELECT pg_catalog.pg_get_userbyid(namespace.nspowner) FROM pg_catalog.pg_namespace namespace WHERE namespace.nspname='public' UNION ALL SELECT pg_catalog.pg_get_userbyid(relation.relowner) FROM pg_catalog.pg_class relation JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace WHERE namespace.nspname='public' AND relation.relkind IN ('r','p','S','c','v','m','f') UNION ALL SELECT pg_catalog.pg_get_userbyid(procedure.proowner) FROM pg_catalog.pg_proc procedure JOIN pg_catalog.pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' UNION ALL SELECT pg_catalog.pg_get_userbyid(type.typowner) FROM pg_catalog.pg_type type JOIN pg_catalog.pg_namespace namespace ON namespace.oid=type.typnamespace WHERE namespace.nspname='public' AND type.typisdefined) inventory ORDER BY owner")"
    [[ "$owners" == "$migrator_role" ]] \
        || fail 'a migrated database, schema, relation, routine, or type has the wrong owner'

    acl_vector="$(target_query "$container" "SELECT (SELECT count(*) FROM pg_catalog.pg_database database CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(database.datacl, pg_catalog.acldefault('d', database.datdba))) acl WHERE database.datname=current_database() AND acl.grantee <> database.datdba) || '|' || (SELECT count(*) FROM pg_catalog.pg_namespace namespace CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))) acl WHERE namespace.nspname='public' AND acl.grantee <> namespace.nspowner) || '|' || (SELECT count(*) FROM pg_catalog.pg_class relation JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(relation.relacl, pg_catalog.acldefault(CASE WHEN relation.relkind='S' THEN 'S'::pg_catalog.\"char\" ELSE 'r'::pg_catalog.\"char\" END, relation.relowner))) acl WHERE namespace.nspname='public' AND acl.grantee <> relation.relowner) || '|' || (SELECT count(*) FROM pg_catalog.pg_proc procedure JOIN pg_catalog.pg_namespace namespace ON namespace.oid=procedure.pronamespace CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))) acl WHERE namespace.nspname='public' AND acl.grantee <> procedure.proowner) || '|' || (SELECT count(*) FROM pg_catalog.pg_type type JOIN pg_catalog.pg_namespace namespace ON namespace.oid=type.typnamespace CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(type.typacl, pg_catalog.acldefault('T', type.typowner))) acl WHERE namespace.nspname='public' AND type.typisdefined AND type.typtype NOT IN ('m','p') AND NOT (type.typelem <> 0 AND type.typsubscript='pg_catalog.array_subscript_handler'::pg_catalog.regproc) AND acl.grantee <> type.typowner) || '|' || (SELECT count(*) FROM pg_catalog.pg_attribute attribute JOIN pg_catalog.pg_class relation ON relation.oid=attribute.attrelid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE namespace.nspname='public' AND attribute.attnum > 0 AND NOT attribute.attisdropped AND acl.grantee <> relation.relowner) || '|' || (SELECT count(*) FROM pg_catalog.pg_default_acl) || '|' || (SELECT count(*) FROM pg_catalog.pg_parameter_acl) || '|' || (SELECT count(*) FROM pg_catalog.pg_seclabel) || '|' || (SELECT count(*) FROM pg_catalog.pg_shseclabel) || '|' || (SELECT count(*) FROM pg_catalog.pg_largeobject_metadata)")"
    [[ "$acl_vector" == '0|0|0|0|0|0|0|0|0|0|0' ]] \
        || fail "target ACL/security zero vector drifted: ${acl_vector}"
    effective="$(target_query "$container" "SELECT pg_catalog.has_database_privilege('backupsheep_app', current_database(), 'CONNECT') || '|' || pg_catalog.has_schema_privilege('backupsheep_app', 'public', 'USAGE') || '|' || pg_catalog.has_table_privilege('backupsheep_app', 'public.migration_fixture', 'SELECT') || '|' || pg_catalog.has_column_privilege('backupsheep_app', 'public.migration_fixture', 'code', 'SELECT') || '|' || pg_catalog.has_sequence_privilege('backupsheep_app', 'public.migration_fixture_id_seq', 'USAGE') || '|' || pg_catalog.has_function_privilege('backupsheep_app', 'public.fixture_label(public.fixture_pair)', 'EXECUTE') || '|' || pg_catalog.has_type_privilege('backupsheep_app', 'public.fixture_state', 'USAGE') || '|' || pg_catalog.has_type_privilege('backupsheep_app', 'public.fixture_code', 'USAGE') || '|' || pg_catalog.has_type_privilege('backupsheep_app', 'public.fixture_pair', 'USAGE') || '|' || pg_catalog.has_database_privilege('backupsheep_migrator', current_database(), 'CONNECT') || '|' || pg_catalog.has_schema_privilege('backupsheep_migrator', 'public', 'USAGE') || '|' || pg_catalog.has_table_privilege('backupsheep_migrator', 'public.migration_fixture', 'SELECT')")"
    [[ "$effective" == 'false|false|false|false|false|false|false|false|false|true|true|true' ]] \
        || fail "effective target privileges were not isolated: ${effective}"

    run_docker stop --time 30 "$container" >/dev/null
    run_docker container rm "$container" >/dev/null
    run_docker volume rm "$socket" >/dev/null
}

run_generation2_path() {
    register_scenario g2 migrated-debian-generation2-v1 3-pending-upgrade
    create_owned_volume "$scenario_source_volume" "$scenario_project" \
        "$scenario_installation" pgdata
    create_generation2_source
    run_migration none "$scenario_database_generation" success
    [[ "$LAST_MIGRATION_STATUS" -eq 0 ]] \
        || { tail -200 "$LAST_MIGRATION_LOG" >&2; fail 'the exact generation-2 migration failed'; }
    grep -Fq 'PostgreSQL migration verified:' "$LAST_MIGRATION_LOG" \
        || fail 'the generation-2 run did not emit verified content evidence'
    assert_migration_quiescent "$scenario_project" "$scenario_secret"
    verify_target

    run_migration none 3 sealed-reconcile
    [[ "$LAST_MIGRATION_STATUS" -eq 0 ]] \
        || { tail -200 "$LAST_MIGRATION_LOG" >&2; fail 'sealed generation-2 receipt reconciliation failed'; }
    grep -Fq 'PostgreSQL migration reconciled from its completed receipt:' "$LAST_MIGRATION_LOG" \
        || fail 'sealed generation-2 reconciliation did not use the completed receipt'
    assert_migration_quiescent "$scenario_project" "$scenario_secret"
    cleanup_scenario "$scenario_project" "$scenario_installation" "$scenario_witness"
    printf '%s\n' 'PostgreSQL runtime E2E: exact generation-2 migration and sealed reconciliation passed.'
}

run_generation3_adversarial_and_resume_path() {
    local credential_residue helper_residue receipt_content
    register_scenario g3 migrated-debian-v1 3
    create_owned_volume "$scenario_source_volume" "$scenario_project" \
        "$scenario_installation" pgdata
    create_generation3_source

    edit_source <<'SQL'
CREATE ROLE backupsheep_attacker WITH LOGIN PASSWORD 'fixture-only-hostile-role';
SQL
    expect_refusal 'generation-3 source identity validation failed' hostile-extra-role
    edit_source <<'SQL'
DROP ROLE backupsheep_attacker;
SQL

    edit_source <<'SQL'
SELECT pg_catalog.lo_create(424242);
SQL
    expect_refusal 'large objects outside the automatic migration contract' hostile-large-object
    edit_source <<'SQL'
SELECT pg_catalog.lo_unlink(424242);
SQL

    edit_source <<'SQL'
GRANT SET ON PARAMETER work_mem TO backupsheep_app;
SQL
    expect_refusal 'non-stock parameter privileges' hostile-parameter-acl
    edit_source <<'SQL'
REVOKE ALL ON PARAMETER work_mem FROM backupsheep_app;
SQL
    open_source_editor "$scenario_project" "$scenario_installation" \
        "$scenario_source_volume" "$scenario_secret"
    [[ "$(source_query 'SELECT count(*) FROM pg_catalog.pg_parameter_acl')" == 0 ]] \
        || fail 'the hostile parameter ACL fixture did not return to the exact source contract'
    close_source_editor

    run_migration credential "$scenario_database_generation" crash-credential
    [[ "$LAST_MIGRATION_STATUS" -eq 137 \
        && -f "$LAST_FAILPOINT_STATE" && "$(<"$LAST_FAILPOINT_STATE")" == credential ]] \
        || { tail -200 "$LAST_MIGRATION_LOG" >&2; fail 'the credential-boundary SIGKILL was not observed'; }
    credential_residue="$(ephemeral_credential_inventory "$scenario_secret")"
    [[ "$(printf '%s\n' "$credential_residue" | grep -c .)" -eq 2 ]] \
        || fail 'the credential-boundary crash did not leave both bounded credentials'
    [[ -z "$(run_docker container ls --all --quiet \
        --filter "label=com.backupsheep.postgres-migration=${scenario_purpose}")" ]] \
        || fail 'the credential-boundary crash occurred after a migration server started'

    run_migration helper "$scenario_database_generation" crash-helper
    [[ "$LAST_MIGRATION_STATUS" -eq 137 \
        && -f "$LAST_FAILPOINT_STATE" && "$(<"$LAST_FAILPOINT_STATE")" == helper ]] \
        || { tail -200 "$LAST_MIGRATION_LOG" >&2; fail 'the helper-boundary SIGKILL was not observed'; }
    while IFS= read -r residue; do
        [[ -n "$residue" && ! -e "$residue" && ! -L "$residue" ]] \
            || fail 'credential-boundary residue was not safely replaced on resume'
    done <<< "$credential_residue"
    [[ -n "$(run_docker container ls --all --quiet \
        --filter "name=^/${scenario_project}-postgres-migration-source$")" \
        && -n "$(run_docker container ls --all --quiet \
        --filter "name=^/${scenario_project}-postgres-migration-target$")" ]] \
        || fail 'the helper-boundary crash did not leave both exact migration servers'
    helper_residue="$(ephemeral_credential_inventory "$scenario_secret")"
    [[ "$(printf '%s\n' "$helper_residue" | grep -c .)" -eq 2 ]] \
        || fail 'the helper-boundary crash did not retain the bounded active credentials'

    run_migration receipt "$scenario_database_generation" crash-receipt
    [[ "$LAST_MIGRATION_STATUS" -eq 137 \
        && -f "$LAST_FAILPOINT_STATE" && "$(<"$LAST_FAILPOINT_STATE")" == receipt ]] \
        || { tail -200 "$LAST_MIGRATION_LOG" >&2; fail 'the receipt-boundary SIGKILL was not observed'; }
    while IFS= read -r residue; do
        [[ -n "$residue" && ! -e "$residue" && ! -L "$residue" ]] \
            || fail 'helper-boundary credential residue was not safely replaced on resume'
    done <<< "$helper_residue"
    receipt_content="$(run_docker exec \
        "${scenario_project}-postgres-migration-target" \
        cat /var/lib/postgresql/.backupsheep-logical-migration-receipt-v2)"
    [[ "$(printf '%s\n' "$receipt_content" | sed -n '1p')" == status=complete \
        && "$(printf '%s\n' "$receipt_content" | sed -n '2p')" == receipt_version=2 \
        && "$(printf '%s\n' "$receipt_content" | sed -n '4p')" == source_contract=strict-ten-role-v1 \
        && "$(printf '%s\n' "$receipt_content" | sed -n '6p')" == "target_image=${target_image_id}" ]] \
        || fail 'the receipt-boundary crash did not leave exact completed evidence'

    run_migration none "$scenario_database_generation" crash-reconcile
    [[ "$LAST_MIGRATION_STATUS" -eq 0 ]] \
        || { tail -200 "$LAST_MIGRATION_LOG" >&2; fail 'receipt-boundary resume failed'; }
    grep -Fq 'PostgreSQL migration reconciled from its completed receipt:' "$LAST_MIGRATION_LOG" \
        || fail 'receipt-boundary resume did not reconcile instead of recopying'
    assert_migration_quiescent "$scenario_project" "$scenario_secret"
    verify_target
    cleanup_scenario "$scenario_project" "$scenario_installation" "$scenario_witness"
    printf '%s\n' 'PostgreSQL runtime E2E: strict generation-3 refusal, SIGKILL, resume, receipt, type, data, ownership, and ACL checks passed.'
}

run_generation2_path
run_generation3_adversarial_and_resume_path
printf '%s\n' 'PostgreSQL runtime migration E2E: PASS (all resources are exact-run labeled and scheduled for bounded cleanup).'
