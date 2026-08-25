#!/usr/bin/env bash
# Boot a bounded production-like topology from the exact images already built by CI.
set -Eeuo pipefail
export LC_ALL=C
umask 077

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "${script_dir}/../.." && pwd -P)"
readonly compose_file="${repository_root}/docker-compose.yml"
readonly topology_override="${script_dir}/docker-compose.security-topology.yml"

fail() {
    printf '%s\n' "BackupSheep CI topology gate failed: $*" >&2
    exit 1
}

docker_resource_label() {
    local resource_type="$1" resource_id="$2" label_name="$3"
    local frame_marker='__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__'
    local label_root='' framed_value='' framed_payload=''
    local declared_length='' label_value=''
    local LC_ALL=C

    case "$resource_type" in
        container|image) label_root='.Config.Labels' ;;
        network|volume) label_root='.Labels' ;;
        *) return 1 ;;
    esac
    case "$resource_type" in
        container)
            framed_value="$(
                docker inspect --format \
                    "{{with index ${label_root} \"${label_name}\"}}{{len .}}:{{.}}{{else}}0:{{end}}${frame_marker}" \
                    "$resource_id"
            )" || return 1
            ;;
        image|network|volume)
            framed_value="$(
                docker "$resource_type" inspect --format \
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

for name in TEST_APP_IMAGE TEST_POSTGRES_IMAGE TEST_EGRESS_IMAGE \
    TEST_TOPOLOGY_PROJECT TEST_OWNERSHIP_VALUE; do
    [[ -n "${!name:-}" ]] || fail "${name} is required."
done
[[ "${TEST_TOPOLOGY_PROJECT}" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] \
    || fail "TEST_TOPOLOGY_PROJECT is not a bounded Compose project name."
command -v docker >/dev/null 2>&1 || fail "Docker is unavailable."
command -v openssl >/dev/null 2>&1 || fail "OpenSSL is unavailable."
command -v ssh-keygen >/dev/null 2>&1 || fail "ssh-keygen is unavailable."

for image in "$TEST_APP_IMAGE" "$TEST_POSTGRES_IMAGE" "$TEST_EGRESS_IMAGE"; do
    docker image inspect "$image" >/dev/null 2>&1 \
        || fail "the required local image ${image} is absent."
    [[ "$(docker_resource_label image "$image" com.backupsheep.ci-run)" == "$TEST_OWNERSHIP_VALUE" ]] \
        || fail "the required local image ${image} is not owned by this CI run."
done
docker run --rm --network none --read-only --user 10001:10001 \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --entrypoint /bin/sh "$TEST_APP_IMAGE" -ceu '
        healthcheck=/usr/local/bin/backupsheep-egress-workload-healthcheck
        test -x "$healthcheck"
        test "$(head -n 1 "$healthcheck")" = "#!/usr/local/bin/python3"
        /usr/local/bin/python3 --version >/dev/null
    ' || fail "the application image does not contain the fixed-interpreter egress workload healthcheck."

# Refuse to adopt any pre-existing object.  This makes the exact-project cleanup
# below safe even on a reused runner.
if docker container ls --all --quiet \
    --filter "label=com.docker.compose.project=${TEST_TOPOLOGY_PROJECT}" \
    | grep -q .; then
    fail "the CI Compose project already owns a container."
fi
if docker volume ls --quiet \
    --filter "label=com.docker.compose.project=${TEST_TOPOLOGY_PROJECT}" \
    | grep -q .; then
    fail "the CI Compose project already owns a volume."
fi
if docker network ls --quiet \
    --filter "label=com.docker.compose.project=${TEST_TOPOLOGY_PROJECT}" \
    | grep -q .; then
    fail "the CI Compose project already owns a network."
fi

runtime_root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/backupsheep-security-topology.XXXXXXXX")"
secret_dir="${runtime_root}/secrets"
environment_file="${runtime_root}/topology.env"
rendered_config="${runtime_root}/compose.json"
installation_id="$(openssl rand -hex 32)"
staging_intent='new-empty-v3'
staging_witness="$(printf '%s' "BackupSheep/staging-layout/v3|${installation_id}|${staging_intent}" | sha256sum | awk '{print $1}')"
postgres_storage_intent='new-empty-v1'
postgres_storage_witness="$(printf '%s' "BackupSheep/postgres-storage/v1|${installation_id}|${TEST_TOPOLOGY_PROJECT}|postgres_data_v1|18-alpine-icu-v1|icu=und|${postgres_storage_intent}" | sha256sum | awk '{print $1}')"
stack_created=false

compose() {
    docker compose \
        --project-name "$TEST_TOPOLOGY_PROJECT" \
        --env-file "$environment_file" \
        --file "$compose_file" \
        --file "$topology_override" \
        "$@"
}

cleanup() {
    status=$?
    cleanup_failed=false
    trap - EXIT HUP INT TERM
    if [[ "$status" -ne 0 && "$stack_created" == true ]]; then
        compose logs --no-color --tail 200 \
            db rabbitmq rabbitmq-provision staging-provision \
            app-egress-guard cloud-egress-guard db-provision migrate db-seal \
            preflight app worker-cloud >&2 2>/dev/null || true
    fi
    if [[ "$stack_created" == true ]]; then
        compose down --volumes --remove-orphans --timeout 30 >/dev/null 2>&1 || true
        # Compose can return while a dependency that never started still owns a
        # network namespace.  The project was proven absent before this run, so
        # remove only residual objects bearing this exact generated project label.
        while IFS= read -r container; do
            [[ -n "$container" ]] || continue
            if [[ "$(docker_resource_label container "$container" com.docker.compose.project 2>/dev/null || true)" != "$TEST_TOPOLOGY_PROJECT" \
                || "$(docker_resource_label container "$container" com.backupsheep.installation-id 2>/dev/null || true)" != "$installation_id" ]]; then
                printf '%s\n' 'Refusing to remove a residual container with a mismatched installation identity.' >&2
                cleanup_failed=true
                continue
            fi
            docker rm --force "$container" >/dev/null 2>&1 || cleanup_failed=true
        done < <(docker container ls --all --quiet \
            --filter "label=com.docker.compose.project=${TEST_TOPOLOGY_PROJECT}")
        while IFS= read -r network; do
            [[ -n "$network" ]] || continue
            if [[ "$(docker_resource_label network "$network" com.docker.compose.project 2>/dev/null || true)" != "$TEST_TOPOLOGY_PROJECT" ]]; then
                printf '%s\n' 'Refusing to remove a residual network with a malformed project identity.' >&2
                cleanup_failed=true
                continue
            fi
            docker network rm "$network" >/dev/null 2>&1 || cleanup_failed=true
        done < <(docker network ls --quiet \
            --filter "label=com.docker.compose.project=${TEST_TOPOLOGY_PROJECT}")
        while IFS= read -r volume; do
            [[ -n "$volume" ]] || continue
            if [[ "$(docker_resource_label volume "$volume" com.docker.compose.project 2>/dev/null || true)" != "$TEST_TOPOLOGY_PROJECT" ]]; then
                printf '%s\n' 'Refusing to remove a residual volume with a malformed project identity.' >&2
                cleanup_failed=true
                continue
            fi
            docker volume rm "$volume" >/dev/null 2>&1 || cleanup_failed=true
        done < <(docker volume ls --quiet \
            --filter "label=com.docker.compose.project=${TEST_TOPOLOGY_PROJECT}")
        if docker container ls --all --quiet \
                --filter "label=com.docker.compose.project=${TEST_TOPOLOGY_PROJECT}" \
                | grep -q . \
            || docker network ls --quiet \
                --filter "label=com.docker.compose.project=${TEST_TOPOLOGY_PROJECT}" \
                | grep -q . \
            || docker volume ls --quiet \
                --filter "label=com.docker.compose.project=${TEST_TOPOLOGY_PROJECT}" \
                | grep -q .; then
            cleanup_failed=true
        fi
    fi
    if [[ -d "$runtime_root" ]]; then
        find "$runtime_root" -xdev -type f -delete
        find "$runtime_root" -xdev -depth -type d -empty -delete
    fi
    if [[ "$cleanup_failed" == true && "$status" -eq 0 ]]; then
        status=1
    fi
    exit "$status"
}
on_signal() {
    exit 130
}
trap cleanup EXIT
trap on_signal HUP INT TERM

install -d -m 0700 "$secret_dir"
write_random_secret() {
    local target="$1"
    openssl rand -hex 32 > "${secret_dir}/${target}"
}

write_random_secret django_secret_key
write_random_secret onboarding_token
for lane in bootstrap migrator app preflight beat cloud database files storage logs; do
    write_random_secret "db_${lane}_password"
done
for lane in bootstrap app preflight beat cloud database files storage logs; do
    write_random_secret "rabbitmq_${lane}_password"
done

for lane in app beat cloud database files storage logs; do
    ssh-keygen -q -t ed25519 -N '' -C '' \
        -f "${secret_dir}/celery_signing_${lane}_private_key"
done
ssh-keygen -q -t ed25519 -N '' -C '' \
    -f "${secret_dir}/ssh_managed_database_private_key"
ssh-keygen -q -t ed25519 -N '' -C '' \
    -f "${secret_dir}/ssh_managed_files_private_key"

database_public_key="$(awk 'NF >= 2 {print $1 " " $2; exit}' \
    "${secret_dir}/ssh_managed_database_private_key.pub")"
files_public_key="$(awk 'NF >= 2 {print $1 " " $2; exit}' \
    "${secret_dir}/ssh_managed_files_private_key.pub")"
[[ "$database_public_key" == ssh-ed25519\ * ]] \
    || fail "the database managed key is not Ed25519."
[[ "$files_public_key" == ssh-ed25519\ * ]] \
    || fail "the files managed key is not Ed25519."
[[ "$database_public_key" != "$files_public_key" ]] \
    || fail "the managed SSH lane keys are not distinct."

python3 - "$secret_dir" "$installation_id" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
installation_id = sys.argv[2]
lanes = ("app", "beat", "cloud", "database", "files", "storage", "logs")
keys = {}
for lane in lanes:
    public_path = root / f"celery_signing_{lane}_private_key.pub"
    fields = public_path.read_text(encoding="ascii").split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise SystemExit("invalid Celery public key")
    keys[lane] = f"{fields[0]} {fields[1]}"
(root / "celery_trusted_public_keys").write_text(
    json.dumps(
        {
            "version": 2,
            "installation_id": installation_id,
            "generation": 1,
            "keys": keys,
        },
        sort_keys=True,
        separators=(",", ":"),
    ),
    encoding="ascii",
)
PY

for public_file in "$secret_dir"/*.pub; do
    rm -- "$public_file"
done
printf '%s\n' \
    '[default]' \
    'aws_access_key_id = disabled' \
    'aws_secret_access_key = disabled' \
    > "${secret_dir}/artifact_kms_database_aws_credentials"
printf '%s\n' \
    '[default]' \
    'aws_access_key_id = disabled' \
    'aws_secret_access_key = disabled' \
    > "${secret_dir}/artifact_kms_files_aws_credentials"
chmod 0444 "$secret_dir"/*

cat > "$environment_file" <<EOF
BACKUPSHEEP_IMAGE=${TEST_APP_IMAGE}
BACKUPSHEEP_POSTGRES_IMAGE=${TEST_POSTGRES_IMAGE}
BACKUPSHEEP_EGRESS_IMAGE=${TEST_EGRESS_IMAGE}
BACKUPSHEEP_COMPOSE_PROJECT_NAME=${TEST_TOPOLOGY_PROJECT}
BACKUPSHEEP_INSTALLATION_ID=${installation_id}
BACKUPSHEEP_POSTGRES_STORAGE_GENERATION=18-alpine-icu-v1-pending-fresh
BACKUPSHEEP_POSTGRES_STORAGE_INTENT=${postgres_storage_intent}
BACKUPSHEEP_POSTGRES_STORAGE_WITNESS=${postgres_storage_witness}
BACKUPSHEEP_SECRETS_DIR=${secret_dir}
BACKUPSHEEP_STAGING_LAYOUT_INTENT=${staging_intent}
BACKUPSHEEP_STAGING_LAYOUT_WITNESS=${staging_witness}
BACKUPSHEEP_STAGING_MIN_FREE_BYTES=67108864
BACKUPSHEEP_STAGING_MIN_FREE_INODES=128
BACKUPSHEEP_PRIVATE_MIN_FREE_BYTES=67108864
BACKUPSHEEP_TRANSFER_MIN_FREE_BYTES=67108864
BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_BYTES=67108864
DJANGO_SERVER=prod
DJANGO_DEBUG=false
DJANGO_ALLOWED_HOSTS=localhost
DJANGO_HTTPS=true
APP_PROTOCOL=https://
APP_DOMAIN=localhost
DB_NAME=backupsheep_ci
DB_BOOTSTRAP_USER=backupsheep_bootstrap
DB_MIGRATOR_USER=backupsheep_migrator
DB_APP_USER=backupsheep_app
DB_PREFLIGHT_USER=backupsheep_preflight
DB_BEAT_USER=backupsheep_beat
DB_CLOUD_USER=backupsheep_cloud
DB_DATABASE_USER=backupsheep_database
DB_FILES_USER=backupsheep_files
DB_STORAGE_USER=backupsheep_storage
DB_LOGS_USER=backupsheep_logs
BACKUPSHEEP_DATABASE_IDENTITY_GENERATION=3
RABBITMQ_HOST=rabbitmq
RABBITMQ_PORT=5672
RABBITMQ_SCHEME=amqp
RABBITMQ_VHOST=backupsheep
RABBITMQ_LEGACY_USER=backupsheep
BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION=2
BACKUPSHEEP_RABBITMQ_DATA_GENERATION=4.3
BACKUPSHEEP_CELERY_SECURITY_GENERATION=3
BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION=1
BACKUPSHEEP_EGRESS_POLICY_GENERATION=2
CELERY_CLOUD_CONCURRENCY=1
CELERY_CLOUD_PREFETCH_MULTIPLIER=1
SSH_MANAGED_DATABASE_PUBLIC_KEY=${database_public_key}
SSH_MANAGED_FILES_PUBLIC_KEY=${files_public_key}
BACKUPSHEEP_ARTIFACT_KMS_KEY_ID=arn:aws:kms:us-east-1:000000000000:key/00000000-0000-4000-8000-000000000001
BACKUPSHEEP_ARTIFACT_KMS_ALLOWED_KEY_ARNS=arn:aws:kms:us-east-1:000000000000:key/00000000-0000-4000-8000-000000000001
BACKUPSHEEP_ARTIFACT_KMS_REGION=us-east-1
EOF
chmod 0600 "$environment_file"

compose --profile operations config --format json > "$rendered_config"
python3 - "$rendered_config" "$TEST_APP_IMAGE" "$TEST_POSTGRES_IMAGE" "$TEST_EGRESS_IMAGE" <<'PY'
import json
import pathlib
import sys

model = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
services = model["services"]
expected_images = {
    "db": sys.argv[3],
    "app-egress-guard": sys.argv[4],
    "cloud-egress-guard": sys.argv[4],
    "staging-provision": sys.argv[2],
    "db-provision": sys.argv[2],
    "migrate": sys.argv[2],
    "db-seal": sys.argv[2],
    "preflight": sys.argv[2],
    "app": sys.argv[2],
    "worker-cloud": sys.argv[2],
}
for service, expected in expected_images.items():
    actual = services[service].get("image")
    if actual != expected:
        raise SystemExit(f"{service} image drifted: {actual!r}")
    if services[service].get("pull_policy") != "never":
        raise SystemExit(f"{service} does not fail closed on a missing local image")
expected_rabbitmq = (
    "rabbitmq:4.3.5-alpine@sha256:"
    "d07d6a0657affe0354ae61b3ca1a3e4d244c247ac5d7e25940c8759658ce7ad7"
)
for service in ("rabbitmq-volume-init", "rabbitmq", "rabbitmq-provision"):
    if services[service].get("image") != expected_rabbitmq:
        raise SystemExit(f"{service} does not use the reviewed RabbitMQ digest")
for service in ("app-egress-guard", "cloud-egress-guard"):
    environment = services[service].get("environment", {})
    if environment.get("BACKUPSHEEP_EGRESS_POLICY_GENERATION") != "2":
        raise SystemExit(f"{service} does not render egress policy generation 2")
    if environment.get("BACKUPSHEEP_EGRESS_MODE") != "deny":
        raise SystemExit(f"{service} does not render the stock deny egress mode")
    if services[service].get("restart") != "no":
        raise SystemExit(f"{service} may restart into a namespace its workload does not share")
    dependencies = services[service].get("depends_on", {})
    for peer in ("db", "rabbitmq"):
        if dependencies.get(peer, {}).get("condition") != "service_healthy":
            raise SystemExit(
                f"{service} may start before its required {peer} peer is healthy"
            )
    for variable in (
        "BACKUPSHEEP_EGRESS_ALLOW_IPV4",
        "BACKUPSHEEP_EGRESS_ALLOW_IPV6",
        "BACKUPSHEEP_EGRESS_ALLOW_DNS_NAMES",
    ):
        if environment.get(variable):
            raise SystemExit(f"{service} unexpectedly renders {variable}")
for service in ("app", "worker-cloud"):
    health_test = services[service].get("healthcheck", {}).get("test")
    if health_test != ["CMD", "/usr/local/bin/backupsheep-egress-workload-healthcheck"]:
        raise SystemExit(f"{service} does not use the stock database/broker healthcheck")
database = services["db"]
if database.get("user") != "70:70":
    raise SystemExit("database does not render as Alpine postgres UID/GID 70")
database_environment = database.get("environment", {})
if database_environment.get("BACKUPSHEEP_POSTGRES_STORAGE_GENERATION") != "18-alpine-icu-v1-pending-fresh":
    raise SystemExit("database does not render the explicit pending fresh storage generation")
if "--locale-provider=icu --icu-locale=und" not in database_environment.get("POSTGRES_INITDB_ARGS", ""):
    raise SystemExit("database does not render the reviewed ICU initialization")
if not any(
    isinstance(mount, dict)
    and mount.get("source") == "postgres_data_v1"
    and mount.get("target") == "/var/lib/postgresql"
    for mount in database.get("volumes", [])
):
    raise SystemExit("database does not mount the distinct Alpine/ICU storage volume")
for service, definition in services.items():
    if definition.get("ports"):
        raise SystemExit(f"{service} unexpectedly publishes a host port")
for service in ("app", "worker-cloud", "preflight"):
    environment = services[service].get("environment", {})
    for forbidden in ("DJANGO_SECRET_KEY", "DB_PASSWORD", "RABBITMQ_PASSWORD"):
        if environment.get(forbidden):
            raise SystemExit(f"{service} exposes {forbidden} directly")
    if definition := services[service].get("env_file"):
        raise SystemExit(f"{service} retains an env_file: {definition!r}")
for service in (
    "staging-provision",
    "db-provision",
    "migrate",
    "db-seal",
    "preflight",
    "app",
    "worker-cloud",
):
    for mount in services[service].get("volumes", []):
        if isinstance(mount, dict) and mount.get("type") == "bind":
            raise SystemExit(
                f"{service} overrides image content with a host bind mount: {mount!r}"
            )
PY

stack_created=true
compose --profile operations up --detach --no-build --wait --wait-timeout 420 \
    app worker-cloud

assert_runtime_image() {
    local service="$1"
    local expected_tag="$2"
    local container expected_id actual_id
    container="$(compose ps --all --quiet "$service")"
    [[ -n "$container" ]] || fail "${service} was not created."
    expected_id="$(docker image inspect --format '{{.Id}}' "$expected_tag")"
    actual_id="$(docker inspect --format '{{.Image}}' "$container")"
    [[ "$actual_id" == "$expected_id" ]] \
        || fail "${service} did not start from the exact image built by this CI run."
}
assert_guard_healthy() {
    local service="$1"
    local container
    container="$(compose ps --all --quiet "$service")"
    [[ -n "$container" ]] || fail "${service} was not created."
    [[ "$(docker inspect --format '{{.State.Status}}:{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container")" == 'running:healthy' ]] \
        || fail "${service} is not running with a fresh kernel-lease health witness."
    docker exec "$container" grep -qx 'mode=deny' \
        /run/backupsheep-egress/ready \
        || fail "${service} did not boot in stock deny mode."
    docker exec "$container" /usr/local/bin/backupsheep-egress-healthcheck \
        >/dev/null \
        || fail "${service} failed its unprivileged kernel-lease health attestation."
}
for service in db; do
    assert_runtime_image "$service" "$TEST_POSTGRES_IMAGE"
done
db_container="$(compose ps --all --quiet db)"
docker exec "$db_container" /usr/local/bin/backupsheep-postgres-storage-witness finalize-fresh \
    >/dev/null || fail "fresh PostgreSQL storage did not prove exact 18.6/ICU initialization."
docker exec "$db_container" grep -qx 'status=complete' \
    /var/lib/postgresql/.backupsheep-storage-witness-v1 \
    || fail "fresh PostgreSQL storage completion witness is absent."
for service in app-egress-guard cloud-egress-guard; do
    assert_runtime_image "$service" "$TEST_EGRESS_IMAGE"
    assert_guard_healthy "$service"
done
for service in staging-provision db-provision migrate db-seal preflight app worker-cloud; do
    assert_runtime_image "$service" "$TEST_APP_IMAGE"
done

assert_completed() {
    local service="$1"
    local container
    container="$(compose ps --all --quiet "$service")"
    [[ -n "$container" ]] || fail "${service} was not created."
    [[ "$(docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$container")" == 'exited:0' ]] \
        || fail "${service} did not complete successfully."
}
for service in rabbitmq-volume-init rabbitmq-provision staging-provision db-provision migrate db-seal preflight; do
    assert_completed "$service"
done

assert_healthy() {
    local service="$1"
    local container
    container="$(compose ps --all --quiet "$service")"
    [[ -n "$container" ]] || fail "${service} was not created."
    [[ "$(docker inspect --format '{{.State.Status}}:{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container")" == 'running:healthy' ]] \
        || fail "${service} is not running and healthy."
    [[ "$(docker inspect --format '{{json .Config.Entrypoint}}' "$container")" == '["/usr/local/bin/init.sh"]' ]] \
        || fail "${service} did not retain the production image entrypoint."
    docker exec "$container" /usr/local/bin/backupsheep-egress-workload-healthcheck \
        >/dev/null \
        || fail "${service} cannot reach its exact database and broker peers."
    docker exec "$container" python manage.py docker_preflight >/dev/null
}
assert_healthy app
assert_healthy worker-cloud

assert_worker_restart_clears_stale_readiness() {
    local service="worker-cloud"
    local container deadline status
    container="$(compose ps --all --quiet "$service")"
    [[ -n "$container" ]] || fail "${service} was not created."

    # Docker preserves a container's tmpfs across a restart.  Seed both forms of
    # stale readiness evidence and prove the exact image entrypoint removes them
    # before the new authenticated Celery consumer publishes a fresh witness.
    docker exec --user 10008:10008 "$container" /bin/sh -ceu '
        printf "%s\n" stale > /run/backupsheep/celery-ready
        printf "%s\n" stale > /run/backupsheep/.celery-ready.999999
    '
    docker restart "$container" >/dev/null

    deadline=$((SECONDS + 180))
    status=""
    while (( SECONDS < deadline )); do
        status="$(docker inspect --format '{{.State.Status}}:{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container")"
        if [[ "$status" == 'running:healthy' ]]; then
            break
        fi
        sleep 2
    done
    [[ "$status" == 'running:healthy' ]] \
        || fail "${service} did not become healthy after a stale-readiness restart (${status})."
    docker exec --user 10008:10008 "$container" /bin/sh -ceu '
        test "$(cat /run/backupsheep/celery-ready)" = cloud
        test ! -e /run/backupsheep/.celery-ready.999999
        test ! -L /run/backupsheep/.celery-ready.999999
    ' || fail "${service} retained stale Celery readiness evidence across restart."
    assert_runtime_image "$service" "$TEST_APP_IMAGE"
    assert_healthy "$service"
}

assert_worker_restart_clears_stale_readiness

assert_guard_renews_kernel_lease() {
    local service="$1"
    local container before after
    container="$(compose ps --all --quiet "$service")"
    before="$(docker exec --user 10020:10020 "$container" \
        awk -F= '$1 == "renewed_monotonic_seconds" { print $2; exit }' \
        /run/backupsheep-egress/reconciler-state)"
    [[ "$before" =~ ^[0-9]+$ ]] \
        || fail "${service} did not publish a monotonic kernel-lease witness."
    after="$before"
    for _attempt in {1..60}; do
        sleep 0.25
        after="$(docker exec --user 10020:10020 "$container" \
            awk -F= '$1 == "renewed_monotonic_seconds" { print $2; exit }' \
            /run/backupsheep-egress/reconciler-state 2>/dev/null || true)"
        if [[ "$after" =~ ^[0-9]+$ ]] && (( after > before )); then
            return 0
        fi
    done
    fail "${service} did not renew its kernel authorization and health witness."
}

assert_guard_renews_kernel_lease app-egress-guard
assert_guard_renews_kernel_lease cloud-egress-guard

# A successfully reconciled RabbitMQ node contains every dedicated identity; the
# provisioner also authenticated their stored hashes, permissions and queue bounds.
rabbitmq_container="$(compose ps --all --quiet rabbitmq)"
[[ -n "$rabbitmq_container" ]] || fail "RabbitMQ was not created."
[[ "$(docker inspect --format '{{.State.Status}}:{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$rabbitmq_container")" == 'running:healthy' ]] \
    || fail "RabbitMQ is not running and healthy."
actual_users="$(docker exec "$rabbitmq_container" rabbitmqctl -q list_users --no-table-headers | awk '{print $1}' | sort)"
expected_users="$(printf '%s\n' app beat bootstrap cloud database files logs preflight storage | sed 's/^/backupsheep_/' | sort)"
[[ "$actual_users" == "$expected_users" ]] || fail "RabbitMQ dedicated identities drifted."

connect_exact_ipv4_endpoint() {
    local container="$1"
    local address="$2"
    local port="$3"
    docker exec "$container" /usr/local/bin/python3 -c '
import socket
import sys

with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1.5):
    pass
' "$address" "$port" >/dev/null 2>&1
}

assert_pair_fails_closed_and_recovers() {
    local guard_service="$1"
    local workload_service="$2"
    local guard_container workload_container replacement_guard replacement_workload
    local restart_count lease_seconds peer_tuple db_address db_port broker_address broker_port
    local expiry_deadline health_deadline status

    guard_container="$(compose ps --all --quiet "$guard_service")"
    workload_container="$(compose ps --all --quiet "$workload_service")"
    [[ -n "$guard_container" && -n "$workload_container" ]] \
        || fail "${guard_service}/${workload_service} was not created."
    [[ "$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$guard_container")" == 'no' ]] \
        || fail "${guard_service} does not use the fail-closed restart=no policy."
    restart_count="$(docker inspect --format '{{.RestartCount}}' "$guard_container")"
    [[ "$restart_count" =~ ^[0-9]+$ ]] \
        || fail "${guard_service} did not expose a bounded restart count."
    lease_seconds="$(docker exec --user 10020:10020 "$guard_container" \
        awk -F= '$1 == "lease_seconds" { print $2; exit }' \
        /run/backupsheep-egress/reconciler-state)"
    [[ "$lease_seconds" =~ ^[0-9]+$ ]] \
        && (( lease_seconds >= 15 && lease_seconds <= 912 )) \
        || fail "${guard_service} did not publish a bounded kernel lease."

    peer_tuple="$(docker exec "$workload_container" /usr/local/bin/python3 -c '
import os
import socket

print(
    socket.gethostbyname(os.environ["DB_HOST"]),
    os.environ["DB_PORT"],
    socket.gethostbyname(os.environ["RABBITMQ_HOST"]),
    os.environ["RABBITMQ_PORT"],
)
')"
    read -r db_address db_port broker_address broker_port <<< "$peer_tuple"
    [[ "$db_address" =~ ^[0-9.]+$ && "$broker_address" =~ ^[0-9.]+$ \
       && "$db_port" =~ ^[0-9]+$ && "$broker_port" =~ ^[0-9]+$ ]] \
        || fail "${workload_service} did not resolve exact internal IPv4 peers."
    connect_exact_ipv4_endpoint "$workload_container" "$db_address" "$db_port" \
        || fail "${workload_service} could not reach its exact database peer before guard loss."
    connect_exact_ipv4_endpoint "$workload_container" "$broker_address" "$broker_port" \
        || fail "${workload_service} could not reach its exact broker peer before guard loss."

    # This raw Docker kill is deliberate attack simulation.  The supported wrapper
    # forbids independent guard lifecycle operations, while Docker itself remains a
    # host-admin trust boundary.  restart=no must leave this guard stopped.
    docker kill "$guard_container" >/dev/null
    sleep 2
    [[ "$(compose ps --all --quiet "$guard_service")" == "$guard_container" ]] \
        || fail "${guard_service} was silently replaced after guard loss."
    [[ "$(docker inspect --format '{{.State.Status}}' "$guard_container")" == 'exited' ]] \
        || fail "${guard_service} did not remain exited after guard loss."
    [[ "$(docker inspect --format '{{.RestartCount}}' "$guard_container")" == "$restart_count" ]] \
        || fail "${guard_service} restarted independently into a different namespace."

    # Wait beyond the last possible authorization lifetime, then address the
    # already-resolved peers directly so DNS-process loss cannot masquerade as
    # proof that the kernel's exact peer leases expired.
    expiry_deadline=$((SECONDS + lease_seconds + 2))
    while (( SECONDS < expiry_deadline )); do
        sleep 1
    done
    if connect_exact_ipv4_endpoint "$workload_container" "$db_address" "$db_port"; then
        fail "${workload_service} retained database access after its guard lease expired."
    fi
    if connect_exact_ipv4_endpoint "$workload_container" "$broker_address" "$broker_port"; then
        fail "${workload_service} retained broker access after its guard lease expired."
    fi

    health_deadline=$((SECONDS + 60))
    status=""
    while (( SECONDS < health_deadline )); do
        status="$(docker inspect --format '{{.State.Status}}:{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$workload_container")"
        if [[ "$status" == 'running:unhealthy' ]]; then
            break
        fi
        sleep 2
    done
    [[ "$status" == 'running:unhealthy' ]] \
        || fail "${workload_service} did not become running:unhealthy after guard lease expiry (${status})."
    if docker exec "$workload_container" \
        /usr/local/bin/backupsheep-egress-workload-healthcheck >/dev/null 2>&1; then
        fail "${workload_service} stock healthcheck accepted an expired guard lease."
    fi

    # Recovery is intentionally the same exact paired operation required by the
    # supported wrapper; no dependency, unrelated service, or image may change.
    compose --profile operations up --detach --no-build --force-recreate --no-deps \
        --wait --wait-timeout 240 "$guard_service" "$workload_service"
    replacement_guard="$(compose ps --all --quiet "$guard_service")"
    replacement_workload="$(compose ps --all --quiet "$workload_service")"
    [[ -n "$replacement_guard" && "$replacement_guard" != "$guard_container" ]] \
        || fail "${guard_service} was not replaced during exact paired recovery."
    [[ -n "$replacement_workload" && "$replacement_workload" != "$workload_container" ]] \
        || fail "${workload_service} was not replaced during exact paired recovery."
    assert_runtime_image "$guard_service" "$TEST_EGRESS_IMAGE"
    assert_runtime_image "$workload_service" "$TEST_APP_IMAGE"
    assert_guard_healthy "$guard_service"
    [[ "$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$replacement_guard")" == 'no' ]] \
        || fail "${guard_service} recovery drifted from restart=no."
    assert_healthy "$workload_service"
    assert_guard_renews_kernel_lease "$guard_service"
}

assert_pair_fails_closed_and_recovers app-egress-guard app
assert_pair_fails_closed_and_recovers cloud-egress-guard worker-cloud

printf '%s\n' \
    'BackupSheep CI topology gate passed: generation-3 database provisioning/sealing,' \
    'authenticated RabbitMQ reconciliation, real entrypoint preflight, and healthy' \
    'web plus cloud-worker processes were proven without publishing a host port;' \
    'both restart=no guard-loss attacks expired exact kernel peer access, made the' \
    'paired workloads unhealthy, and recovered only through exact paired recreation.'
