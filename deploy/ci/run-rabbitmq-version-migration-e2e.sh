#!/usr/bin/env bash
# Prove the exact RabbitMQ 3.13.7 -> 4.2.9 -> 4.3.5 local migration path.
# All resources are private, labeled, collision-checked, bounded, and disposable.
set -euo pipefail

if [[ "$#" -ne 6 ]]; then
    printf '%s\n' \
        'usage: run-rabbitmq-version-migration-e2e.sh HISTORICAL_313_IMAGE PATCHED_SOURCE_313_IMAGE UPGRADE_42_IMAGE TARGET_43_IMAGE RESOURCE_PREFIX OWNERSHIP_VALUE' >&2
    exit 64
fi

historical_image="$1"
source_image="$2"
upgrade_image="$3"
target_image="$4"
resource_prefix="$5"
ownership_value="$6"
expected_historical_image='rabbitmq:3.13.7-management@sha256:e582c0bc7766f3342496d8485efb5a1df782b5ce3886ad017e2eaae442311f69'
expected_historical_repo_digest='rabbitmq@sha256:e582c0bc7766f3342496d8485efb5a1df782b5ce3886ad017e2eaae442311f69'
ownership_label='com.backupsheep.ci-run'
cleanup_label='com.backupsheep.ci-cleanup-token'
installation_id='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
# A historical stock Compose deployment derived its node name from a random
# twelve-hex container hostname. Retaining this exact value is the migration.
node_host='d34db33fcafe'
node_name="rabbit@${node_host}"
queue_name='backupsheep-migration-e2e'
payload='backupsheep-persistent-migration-evidence-v1'

[[ "$historical_image" = "$expected_historical_image" ]] \
    || { printf '%s\n' 'RabbitMQ migration E2E requires the exact historical 3.13.7 fixture image.' >&2; exit 64; }
for image in "$historical_image" "$source_image" "$upgrade_image" "$target_image"; do
    [[ -n "$image" && "$image" != -* && "$image" != *$'\n'* ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E image reference is unsafe.' >&2; exit 64; }
    docker image inspect "$image" >/dev/null
done
[[ "$resource_prefix" =~ ^[a-z0-9][a-z0-9_.-]{0,99}$ ]] \
    || { printf '%s\n' 'RabbitMQ migration E2E resource prefix is unsafe.' >&2; exit 64; }
[[ "$ownership_value" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$ ]] \
    || { printf '%s\n' 'RabbitMQ migration E2E ownership value is unsafe.' >&2; exit 64; }

historical_repo_digests="$(docker image inspect --format '{{join .RepoDigests "\n"}}' "$historical_image" | LC_ALL=C sort)"
[[ "$historical_repo_digests" = "$expected_historical_repo_digest" ]] \
    || { printf '%s\n' 'RabbitMQ migration E2E historical RepoDigest is not the exact reviewed manifest.' >&2; exit 1; }
historical_image_id="$(docker image inspect --format '{{.Id}}' "$historical_image")"
source_image_id="$(docker image inspect --format '{{.Id}}' "$source_image")"
upgrade_image_id="$(docker image inspect --format '{{.Id}}' "$upgrade_image")"
target_image_id="$(docker image inspect --format '{{.Id}}' "$target_image")"
for image_id in "$historical_image_id" "$source_image_id" "$upgrade_image_id" "$target_image_id"; do
    [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E image identity is malformed.' >&2; exit 1; }
done
[[ "$historical_image_id" != "$source_image_id" \
    && "$historical_image_id" != "$upgrade_image_id" \
    && "$historical_image_id" != "$target_image_id" \
    && "$source_image_id" != "$upgrade_image_id" \
    && "$source_image_id" != "$target_image_id" \
    && "$upgrade_image_id" != "$target_image_id" ]] \
    || { printf '%s\n' 'RabbitMQ migration E2E images are not four distinct build/runtime identities.' >&2; exit 1; }

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(CDPATH= cd -- "$script_dir/../.." && pwd -P)"
entrypoint_source="$repository_root/deploy/rabbitmq/entrypoint.sh"
volume_init_source="$repository_root/deploy/rabbitmq/volume-init.sh"
uid_transition_source="$repository_root/deploy/rabbitmq/uid-transition.sh"
provision_source="$repository_root/deploy/rabbitmq/provision.sh"
legacy_config_source="$repository_root/deploy/rabbitmq/90-legacy-source.conf"
current_config_source="$repository_root/deploy/rabbitmq/90-backupsheep.conf"
for source_file in \
    "$entrypoint_source" "$volume_init_source" "$uid_transition_source" \
    "$provision_source" "$legacy_config_source" "$current_config_source"; do
    [[ -f "$source_file" && ! -L "$source_file" ]] \
        || { printf '%s\n' "RabbitMQ migration E2E source is unavailable: $source_file" >&2; exit 1; }
done

scratch_dir="$(mktemp -d "${TMPDIR:-/tmp}/backupsheep-rabbitmq-migration.XXXXXX")"
chmod 0700 "$scratch_dir"
cleanup_token="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$cleanup_token" =~ ^[0-9a-f]{64}$ ]] \
    || { printf '%s\n' 'RabbitMQ migration E2E cleanup token generation failed.' >&2; exit 1; }
secret_dir="$scratch_dir/secrets"
mkdir -m 0755 "$secret_dir"
for role in bootstrap app preflight beat cloud database files storage logs; do
    printf 'backupsheep-ci-%s-%s\n' "$role" "$cleanup_token" \
        > "$secret_dir/rabbitmq_${role}_password"
    chmod 0444 "$secret_dir/rabbitmq_${role}_password"
done

volume_name="${resource_prefix}-data"
network_name="${resource_prefix}-network"
historical_container="${resource_prefix}-historical-313"
source_container="${resource_prefix}-reviewed-313"
upgrade_container="${resource_prefix}-transition-42"
target_container="${resource_prefix}-transition-43"
steady_container="${resource_prefix}-steady-43"
uid_container="${resource_prefix}-uid-transition"
finalize_container="${resource_prefix}-finalize-witness"
provision_container="${resource_prefix}-provision"
containers=(
    "$historical_container" "$source_container" "$upgrade_container"
    "$target_container" "$steady_container" "$uid_container"
    "$finalize_container" "$provision_container"
)

resource_label() {
    local resource_type="$1" resource_name="$2" label_name="$3" label_root=''
    case "$resource_type" in
        container) label_root='.Config.Labels' ;;
        volume|network) label_root='.Labels' ;;
        *) return 64 ;;
    esac
    docker "$resource_type" inspect --format \
        "{{with index ${label_root} \"${label_name}\"}}{{.}}{{end}}" \
        "$resource_name"
}

remove_owned_resource() {
    local resource_type="$1" resource_name="$2" owner='' token=''
    if ! docker "$resource_type" inspect "$resource_name" >/dev/null 2>&1; then
        return 0
    fi
    owner="$(resource_label "$resource_type" "$resource_name" "$ownership_label" 2>/dev/null || true)"
    token="$(resource_label "$resource_type" "$resource_name" "$cleanup_label" 2>/dev/null || true)"
    if [[ "$owner" != "$ownership_value" || "$token" != "$cleanup_token" ]]; then
        printf '%s\n' "Refusing to remove an unowned RabbitMQ migration E2E ${resource_type}: ${resource_name}" >&2
        return 1
    fi
    case "$resource_type" in
        container) docker container rm --force "$resource_name" >/dev/null ;;
        volume) docker volume rm "$resource_name" >/dev/null ;;
        network) docker network rm "$resource_name" >/dev/null ;;
        *) return 64 ;;
    esac
}

cleanup_resources() {
    local cleanup_status=0 resource=''
    for resource in "${containers[@]}"; do
        remove_owned_resource container "$resource" || cleanup_status=1
    done
    remove_owned_resource network "$network_name" || cleanup_status=1
    remove_owned_resource volume "$volume_name" || cleanup_status=1
    rm -rf -- "$scratch_dir"
    return "$cleanup_status"
}
cleanup_on_exit() {
    local initial_status="$1" cleanup_status=0
    trap - EXIT HUP INT TERM
    cleanup_resources || cleanup_status="$?"
    if [[ "$initial_status" -ne 0 ]]; then
        exit "$initial_status"
    fi
    exit "$cleanup_status"
}
cleanup_on_signal() {
    local exit_status="$1"
    trap - EXIT HUP INT TERM
    cleanup_resources || true
    exit "$exit_status"
}
trap 'cleanup_on_exit "$?"' EXIT
trap 'cleanup_on_signal 129' HUP
trap 'cleanup_on_signal 130' INT
trap 'cleanup_on_signal 143' TERM

for resource in "${containers[@]}"; do
    if docker container inspect "$resource" >/dev/null 2>&1; then
        printf '%s\n' "Refusing a pre-existing RabbitMQ migration E2E container collision: $resource" >&2
        exit 1
    fi
done
for resource in "$volume_name" "$network_name"; do
    if docker volume inspect "$resource" >/dev/null 2>&1 \
        || docker network inspect "$resource" >/dev/null 2>&1; then
        printf '%s\n' "Refusing a pre-existing RabbitMQ migration E2E resource collision: $resource" >&2
        exit 1
    fi
done
test "$(docker volume create \
    --label "$ownership_label=$ownership_value" \
    --label "$cleanup_label=$cleanup_token" \
    "$volume_name")" = "$volume_name"
network_id=''
network_error="$scratch_dir/network-create.stderr"
if ! network_id="$(docker network create --internal \
    --label "$ownership_label=$ownership_value" \
    --label "$cleanup_label=$cleanup_token" \
    "$network_name" 2>"$network_error")"; then
    # Busy developer daemons can exhaust their configured automatic address
    # pools. Keep this gate self-contained by trying small private, internal
    # subnets; Docker rejects any candidate that overlaps an existing network.
    network_id=''
    for network_octet in 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254; do
        if network_id="$(docker network create --internal \
            --subnet "172.31.${network_octet}.0/28" \
            --label "$ownership_label=$ownership_value" \
            --label "$cleanup_label=$cleanup_token" \
            "$network_name" 2>"$network_error")"; then
            break
        fi
        network_id=''
    done
fi
[[ "$network_id" =~ ^[0-9a-f]{64}$ ]] \
    || { sed -n '1,20p' "$network_error" >&2; printf '%s\n' 'RabbitMQ migration E2E could not allocate a private internal network.' >&2; exit 1; }
test "$(resource_label volume "$volume_name" "$ownership_label")" = "$ownership_value"
test "$(resource_label network "$network_name" "$ownership_label")" = "$ownership_value"
test "$(resource_label volume "$volume_name" "$cleanup_label")" = "$cleanup_token"
test "$(resource_label network "$network_name" "$cleanup_label")" = "$cleanup_token"

common_labels=(
    --label "$ownership_label=$ownership_value"
    --label "$cleanup_label=$cleanup_token"
)
common_broker_limits=(
    --read-only
    --cap-drop ALL
    --security-opt no-new-privileges:true
    --pids-limit 512
    --memory 1g
    --memory-swap 1g
    --cpus 1
    --ulimit core=0:0
    --ulimit nofile=1024:1024
    --stop-timeout 180
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777
)
common_node_environment=(
    --env "BACKUPSHEEP_RABBITMQ_NODE_HOST=$node_host"
    --env "RABBITMQ_NODENAME=$node_name"
)

assert_container_identity() {
    local container_name="$1" expected_image_id="$2" expected_user="$3"
    test "$(docker container inspect --format '{{.Image}}' "$container_name")" = "$expected_image_id"
    test "$(docker container inspect --format '{{.Config.Hostname}}' "$container_name")" = "$node_host"
    test "$(docker container inspect --format '{{.Config.User}}' "$container_name")" = "$expected_user"
    test "$(resource_label container "$container_name" "$ownership_label")" = "$ownership_value"
    test "$(resource_label container "$container_name" "$cleanup_label")" = "$cleanup_token"
}

show_broker_failure() {
    local container_name="$1" message="$2"
    docker logs --tail 120 "$container_name" 2>&1 | sed -n '1,120p' >&2 || true
    printf '%s\n' "$message" >&2
    return 1
}

wait_for_broker() {
    local container_name="$1" expected_version="$2" attempt=0 server_version='' actual_node=''
    while [[ "$attempt" -lt 180 ]]; do
        attempt=$((attempt + 1))
        if [[ "$(docker container inspect --format '{{.State.Status}}' "$container_name" 2>/dev/null || true)" != running ]]; then
            show_broker_failure "$container_name" "RabbitMQ migration E2E broker exited before readiness: $container_name"
            return 1
        fi
        if docker exec --user rabbitmq "$container_name" \
            rabbitmq-diagnostics -q -n "$node_name" ping >/dev/null 2>&1 \
            && docker exec --user rabbitmq "$container_name" \
                rabbitmqctl -q -n "$node_name" await_startup >/dev/null 2>&1; then
            server_version="$(docker exec --user rabbitmq "$container_name" \
                rabbitmq-diagnostics -q -n "$node_name" server_version 2>/dev/null)"
            actual_node="$(docker exec --user rabbitmq "$container_name" \
                rabbitmqctl -q -n "$node_name" eval 'node().' 2>/dev/null)"
            [[ "$server_version" = "$expected_version" && "$actual_node" = "$node_name" ]] \
                || { show_broker_failure "$container_name" "RabbitMQ migration E2E runtime or node identity drifted: $container_name"; return 1; }
            return 0
        fi
        sleep 1
    done
    show_broker_failure "$container_name" "RabbitMQ migration E2E broker did not become ready: $container_name"
}

stop_cleanly() {
    local container_name="$1"
    docker container stop --time 180 "$container_name" >/dev/null
    test "$(docker container inspect --format '{{.State.Status}}' "$container_name")" = exited
    test "$(docker container inspect --format '{{.State.ExitCode}}' "$container_name")" = 0
    docker container rm "$container_name" >/dev/null
}

kill_abruptly() {
    local container_name="$1"
    docker container kill --signal KILL "$container_name" >/dev/null
    test "$(docker container inspect --format '{{.State.Status}}' "$container_name")" = exited
    test "$(docker container inspect --format '{{.State.ExitCode}}' "$container_name")" = 137
    docker container rm "$container_name" >/dev/null
}

assert_stock_identity() {
    local container_name="$1" vhosts='' users=''
    vhosts="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" list_vhosts name)"
    users="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" list_users)"
    [[ "$vhosts" = / && "$users" = $'guest\t[administrator]' ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E source is not the exact stock single-tenant identity.' >&2; return 1; }
}

assert_migration_message() {
    local container_name="$1" row=''
    row="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" -p / list_queues \
        name durable messages_ready messages_unacknowledged consumers 2>/dev/null)"
    row="$(printf '%s\n' "$row" \
        | awk -v queue="$queue_name" '$1 == queue { print; count++ } END { if (count != 1) exit 1 }')"
    [[ "$row" = "${queue_name}"$'\ttrue\t1\t0\t0' ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E durable message evidence drifted.' >&2; return 1; }
}

assert_feature_flags() {
    local container_name="$1" stable_policy="$2" expected_khepri="$3" rows=''
    rows="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -n "$node_name" list_feature_flags name stability state 2>/dev/null)"
    printf '%s\n' "$rows" | awk \
        -v stable_policy="$stable_policy" -v expected_khepri="$expected_khepri" '
        $1 == "name" && $2 == "stability" && $3 == "state" { next }
        NF != 3 || seen[$1]++ { exit 1 }
        {
            count++
            if (($2 == "required" || (stable_policy == "all" && $2 == "stable")) && $3 != "enabled") exit 1
            if ($1 == "khepri_db") {
                khepri_count++
                khepri_state = $3
            }
        }
        END {
            if (count == 0 || khepri_count != 1 || khepri_state != expected_khepri) exit 1
        }
    '
}

assert_final_topology() {
    local container_name="$1" vhosts='' users='' queues='' expected_users='' expected_queues=''
    local global_parameter_semantics='' user_limits='' vhost_limits=''
    local parameters='' permissions='' expected_permissions='' connections=''
    local exchanges='' expected_product_exchanges='' expected_default_exchanges=''
    local bindings='' policies='' operator_policies=''
    local topic_permissions='' default_queues='' default_exchanges='' default_bindings=''
    local default_policies='' default_operator_policies='' default_permissions=''
    local tab=$'\t'

    vhosts="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" list_vhosts \
        name tracing default_queue_type description tags protected_from_deletion cluster_state \
        2>/dev/null | LC_ALL=C sort)"
    [[ "$vhosts" = \
        "/${tab}false${tab}classic${tab}Default virtual host${tab}[]${tab}false${tab}[{${node_name}, running}]"$'\n'\
"backupsheep${tab}false${tab}classic${tab}${tab}[]${tab}false${tab}[{${node_name}, running}]" ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E final vhost metadata drifted.' >&2; return 1; }

    global_parameter_semantics="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" eval \
        'case {lists:sort([proplists:get_value(name, P) || P <- rabbit_runtime_parameters:list_global()]), rabbit_runtime_parameters:value_global(cluster_tags), rabbit_runtime_parameters:value_global(internal_cluster_id), rabbit_runtime_parameters:lookup_global(imported_definition_hash_value)} of {[cluster_tags, internal_cluster_id], [], <<"rabbitmq-cluster-id-", Id:22/binary>>, not_found} -> case re:run(Id, <<"^[A-Za-z0-9_-]{22}$">>, [{capture, none}]) of match -> true; nomatch -> false end; _ -> false end.' \
        2>/dev/null)"
    [[ "$global_parameter_semantics" = true ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E global runtime-parameter semantics drifted.' >&2; return 1; }

    for reviewed_vhost in / backupsheep; do
        parameters="$(docker exec --user rabbitmq "$container_name" \
            rabbitmqctl -q -s -n "$node_name" -p "$reviewed_vhost" list_parameters 2>/dev/null)"
        [[ -z "$parameters" ]] \
            || { printf '%s\n' "RabbitMQ migration E2E runtime parameter drifted in ${reviewed_vhost}." >&2; return 1; }
        vhost_limits="$(docker exec --user rabbitmq "$container_name" \
            rabbitmqctl -q -s -n "$node_name" list_vhost_limits --vhost "$reviewed_vhost" 2>/dev/null)"
        [[ -z "$vhost_limits" ]] \
            || { printf '%s\n' "RabbitMQ migration E2E vhost limit drifted in ${reviewed_vhost}." >&2; return 1; }
        operator_policies="$(docker exec --user rabbitmq "$container_name" \
            rabbitmqctl -q -s -n "$node_name" -p "$reviewed_vhost" list_operator_policies 2>/dev/null)"
        [[ -z "$operator_policies" ]] \
            || { printf '%s\n' "RabbitMQ migration E2E operator policy drifted in ${reviewed_vhost}." >&2; return 1; }
        topic_permissions="$(docker exec --user rabbitmq "$container_name" \
            rabbitmqctl -q -s -n "$node_name" -p "$reviewed_vhost" list_topic_permissions 2>/dev/null)"
        [[ -z "$topic_permissions" ]] \
            || { printf '%s\n' "RabbitMQ migration E2E topic permission drifted in ${reviewed_vhost}." >&2; return 1; }
    done
    vhost_limits="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" list_vhost_limits --global 2>/dev/null)"
    [[ -z "$vhost_limits" ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E global vhost limit drifted.' >&2; return 1; }
    user_limits="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" list_user_limits --global 2>/dev/null)"
    [[ -z "$user_limits" ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E user limit drifted.' >&2; return 1; }

    expected_users="$(printf '%s\n' bootstrap app preflight beat cloud database files storage logs \
        | sed 's/^/backupsheep_/' | LC_ALL=C sort)"
    users="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" list_users 2>/dev/null \
    )"
    users="$(printf '%s\n' "$users" \
        | awk '$2 == "[]" { print $1; next } { exit 1 }' | LC_ALL=C sort)"
    [[ "$users" = "$expected_users" ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E final user set drifted.' >&2; return 1; }
    expected_queues="$({
        for queue in default cloud database files storage logs; do
            printf '%s\tclassic\ttrue\tfalse\tfalse\t[{"x-queue-type","classic"}]\t0\t0\t0\n' "$queue"
        done
    } | LC_ALL=C sort)"
    queues="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" -p backupsheep list_queues \
        name type durable auto_delete exclusive arguments \
        messages_ready messages_unacknowledged consumers 2>/dev/null \
        | LC_ALL=C sort)"
    [[ "$queues" = "$expected_queues" ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E final queue metadata or state drifted.' >&2; return 1; }

    # RabbitMQ's retained default vhost has the exact internal log exchange;
    # the dedicated product vhost must contain only the ordinary built-ins and
    # BackupSheep's six exchanges. Keep the two inventories independent.
    expected_product_exchanges="$({
        printf '\tdirect\ttrue\tfalse\tfalse\t[]\n'
        printf 'amq.direct\tdirect\ttrue\tfalse\tfalse\t[]\n'
        printf 'amq.fanout\tfanout\ttrue\tfalse\tfalse\t[]\n'
        printf 'amq.headers\theaders\ttrue\tfalse\tfalse\t[]\n'
        printf 'amq.match\theaders\ttrue\tfalse\tfalse\t[]\n'
        printf 'amq.rabbitmq.trace\ttopic\ttrue\tfalse\ttrue\t[]\n'
        printf 'amq.topic\ttopic\ttrue\tfalse\tfalse\t[]\n'
        for queue in default cloud database files storage logs; do
            printf 'backupsheep.%s\tdirect\ttrue\tfalse\tfalse\t[]\n' "$queue"
        done
    } | LC_ALL=C sort)"
    exchanges="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" -p backupsheep list_exchanges \
        name type durable auto_delete internal arguments 2>/dev/null \
        | LC_ALL=C sort)"
    [[ "$exchanges" = "$expected_product_exchanges" ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E final exchange metadata drifted.' >&2; return 1; }

    bindings="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" -p backupsheep list_bindings \
        source_name destination_name destination_kind routing_key arguments 2>/dev/null)"
    printf '%s\n' "$bindings" | awk -F '\t' '
        function reviewed_queue(value) {
            return value ~ /^(default|cloud|database|files|storage|logs)$/
        }
        NF != 5 || !reviewed_queue($2) || $3 != "queue" ||
            $4 != $2 || $5 != "[]" { exit 1 }
        $1 == "" { if (seen_default[$2]++) exit 1; next }
        $1 == "backupsheep." $2 { if (seen_product[$2]++) exit 1; next }
        { exit 1 }
        END {
            split("default cloud database files storage logs", names, " ")
            for (i in names) {
                if (seen_default[names[i]] != 1 || seen_product[names[i]] != 1) exit 1
            }
            if (NR != 12) exit 1
        }
    ' || { printf '%s\n' 'RabbitMQ migration E2E final binding metadata drifted.' >&2; return 1; }

    policies="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" -p backupsheep list_policies 2>/dev/null)"
    printf '%s\n' "$policies" | awk -F '\t' '
        NF != 6 || $1 != "backupsheep" || $2 != "backupsheep-queue-bounds-v1" ||
            $3 != "^(default|cloud|database|files|storage|logs)$" ||
            $4 != "queues" || $6 != "100" { exit 1 }
        {
            definition = $5
            if (gsub(/"max-length":10000/, "", definition) != 1) exit 1
            if (gsub(/"max-length-bytes":67108864/, "", definition) != 1) exit 1
            if (gsub(/"overflow":"reject-publish"/, "", definition) != 1) exit 1
            gsub(/[{},]/, "", definition)
            if (definition != "") exit 1
        }
        END { if (NR != 1) exit 1 }
    ' || { printf '%s\n' 'RabbitMQ migration E2E final queue policy drifted.' >&2; return 1; }

    expected_permissions="$({
        printf 'backupsheep_bootstrap\t^$\t^$\t^$\n'
        printf 'backupsheep_preflight\t^$\t^$\t^$\n'
        printf 'backupsheep_app\t^$\t^(backupsheep\\.(default|cloud|database|files|storage|logs))$\t^$\n'
        printf 'backupsheep_beat\t^$\t^(backupsheep\\.(default|cloud|database|files|storage|logs))$\t^$\n'
        printf 'backupsheep_cloud\t^$\t^(backupsheep\\.(default|cloud|database|files|logs))$\t^(default|cloud)$\n'
        printf 'backupsheep_database\t^$\t^(backupsheep\\.(database|storage|logs))$\t^database$\n'
        printf 'backupsheep_files\t^$\t^(backupsheep\\.(files|storage|logs))$\t^files$\n'
        printf 'backupsheep_storage\t^$\t^(backupsheep\\.(database|files|storage|logs))$\t^storage$\n'
        printf 'backupsheep_logs\t^$\t^backupsheep\\.logs$\t^logs$\n'
    } | LC_ALL=C sort)"
    permissions="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" -p backupsheep list_permissions 2>/dev/null \
        | LC_ALL=C sort)"
    [[ "$permissions" = "$expected_permissions" ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E final permission drifted.' >&2; return 1; }

    default_queues="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" -p / list_queues name 2>/dev/null)"
    [[ -z "$default_queues" ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E retained a default-vhost queue.' >&2; return 1; }
    default_exchanges="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" -p / list_exchanges \
        name type durable auto_delete internal arguments 2>/dev/null \
        | LC_ALL=C sort)"
    expected_default_exchanges="$({
        printf '%s\n' "$expected_product_exchanges" | awk -F '\t' '$1 == "" || $1 ~ /^amq\./'
        printf 'amq.rabbitmq.log\ttopic\ttrue\tfalse\ttrue\t[]\n'
    } | LC_ALL=C sort)"
    [[ "$default_exchanges" = "$expected_default_exchanges" ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E default-vhost exchange drifted.' >&2; return 1; }
    default_bindings="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" -p / list_bindings 2>/dev/null)"
    default_policies="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" -p / list_policies 2>/dev/null)"
    default_operator_policies="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" -p / list_operator_policies 2>/dev/null)"
    default_permissions="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" -p / list_permissions 2>/dev/null)"
    [[ -z "$default_bindings" && -z "$default_policies" \
        && -z "$default_operator_policies" && -z "$default_permissions" ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E default-vhost authorization or topology drifted.' >&2; return 1; }

    connections="$(docker exec --user rabbitmq "$container_name" \
        rabbitmqctl -q -s -n "$node_name" list_connections pid user vhost 2>/dev/null)"
    [[ -z "$connections" ]] \
        || { printf '%s\n' 'RabbitMQ migration E2E retained a client connection.' >&2; return 1; }
    assert_feature_flags "$container_name" required enabled
}

run_provisioner() {
    docker run --rm --pull never \
        "${common_labels[@]}" \
        --name "$provision_container" \
        --network "$network_name" \
        --read-only \
        --user 100:101 \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --pids-limit 128 \
        --memory 256m \
        --memory-swap 256m \
        --cpus 0.5 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777 \
        --mount "type=volume,source=$volume_name,target=/var/lib/rabbitmq,readonly,volume-nocopy" \
        --mount "type=bind,source=$provision_source,target=/usr/local/bin/backupsheep-rabbitmq-provision,readonly" \
        --mount "type=bind,source=$secret_dir,target=/run/secrets,readonly" \
        --env HOME=/var/lib/rabbitmq \
        --env RABBITMQ_LEGACY_USER=backupsheep \
        --env "BACKUPSHEEP_RABBITMQ_NODE_HOST=$node_host" \
        --env "RABBITMQ_NODENAME=$node_name" \
        --entrypoint /bin/sh \
        "$target_image" /usr/local/bin/backupsheep-rabbitmq-provision
}

capture_identity_state() {
    local container_name="$1" role='' user='' stored_hash='' algorithm='' permission=''
    for role in bootstrap app preflight beat cloud database files storage logs; do
        user="backupsheep_${role}"
        stored_hash="$(docker exec --user rabbitmq "$container_name" \
            rabbitmqctl -q -s -n "$node_name" eval \
            "{ok, U} = rabbit_auth_backend_internal:lookup_user(<<\"${user}\">>), base64:encode(element(3, U))." \
            2>/dev/null)"
        algorithm="$(docker exec --user rabbitmq "$container_name" \
            rabbitmqctl -q -s -n "$node_name" eval \
            "{ok, U} = rabbit_auth_backend_internal:lookup_user(<<\"${user}\">>), element(5, U)." \
            2>/dev/null)"
        permission="$(docker exec --user rabbitmq "$container_name" \
            rabbitmqctl -q -s -n "$node_name" list_user_permissions "$user" 2>/dev/null)"
        printf '%s\t%s\t%s\t%s\n' "$user" "$stored_hash" "$algorithm" "$permission"
    done
}

expect_pre_mutation_provisioner_rejection() {
    local container_name="$1" fixture_name="$2" expected_error="$3"
    local stdout_file="$scratch_dir/${fixture_name}.stdout"
    local stderr_file="$scratch_dir/${fixture_name}.stderr"
    local before_state='' after_state='' observed_error=''
    before_state="$(capture_identity_state "$container_name")"
    if run_provisioner >"$stdout_file" 2>"$stderr_file"; then
        printf '%s\n' "RabbitMQ migration E2E provisioner accepted ${fixture_name}." >&2
        return 1
    fi
    observed_error="$(sed -n '1,2p' "$stderr_file")"
    [[ ! -s "$stdout_file" && "$observed_error" = "$expected_error" ]] \
        || { sed -n '1,20p' "$stderr_file" >&2; printf '%s\n' "RabbitMQ migration E2E rejection reason drifted for ${fixture_name}." >&2; return 1; }
    after_state="$(capture_identity_state "$container_name")"
    [[ "$after_state" = "$before_state" ]] \
        || { printf '%s\n' "RabbitMQ migration E2E mutated identities before rejecting ${fixture_name}." >&2; return 1; }
}

# Create a real stock 3.13.7 volume under the historical container-ID node name.
docker run --detach --pull never \
    "${common_labels[@]}" \
    "${common_broker_limits[@]}" \
    "${common_node_environment[@]}" \
    --name "$historical_container" \
    --hostname "$node_host" \
    --network none \
    --user 999:999 \
    --tmpfs /var/log/rabbitmq:rw,noexec,nosuid,nodev,size=64m,mode=0750,uid=999,gid=999 \
    --mount "type=volume,source=$volume_name,target=/var/lib/rabbitmq" \
    --mount "type=bind,source=$legacy_config_source,target=/etc/rabbitmq/conf.d/90-backupsheep.conf,readonly" \
    "$historical_image" >/dev/null
assert_container_identity "$historical_container" "$historical_image_id" 999:999
wait_for_broker "$historical_container" 3.13.7
assert_stock_identity "$historical_container"
docker exec --user rabbitmq "$historical_container" \
    rabbitmqadmin --host localhost --username guest --password guest \
    declare queue name="$queue_name" durable=true auto_delete=false >/dev/null
docker exec --user rabbitmq "$historical_container" \
    rabbitmqadmin --host localhost --username guest --password guest \
    publish exchange=amq.default routing_key="$queue_name" payload="$payload" \
    properties='{"delivery_mode":2,"content_type":"text/plain"}' >/dev/null
assert_migration_message "$historical_container"
assert_feature_flags "$historical_container" all disabled
stop_cleanly "$historical_container"

# Reopen the volume through the reviewed, network-isolated legacy entrypoint.
docker run --detach --pull never \
    "${common_labels[@]}" \
    "${common_broker_limits[@]}" \
    "${common_node_environment[@]}" \
    --name "$source_container" \
    --hostname "$node_host" \
    --network none \
    --user 999:999 \
    --tmpfs /var/log/rabbitmq:rw,noexec,nosuid,nodev,size=64m,mode=0750,uid=999,gid=999 \
    --tmpfs /run/backupsheep-rabbitmq:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=999,gid=999 \
    --mount "type=volume,source=$volume_name,target=/var/lib/rabbitmq,volume-nocopy" \
    --mount "type=bind,source=$legacy_config_source,target=/etc/rabbitmq/conf.d/90-backupsheep.conf,readonly" \
    --mount "type=bind,source=$entrypoint_source,target=/usr/local/bin/backupsheep-rabbitmq-entrypoint,readonly" \
    --mount "type=bind,source=$volume_init_source,target=/usr/local/bin/backupsheep-rabbitmq-volume-init,readonly" \
    --env "BACKUPSHEEP_INSTALLATION_ID=$installation_id" \
    --env BACKUPSHEEP_RABBITMQ_DATA_GENERATION=unattested \
    --env BACKUPSHEEP_RABBITMQ_TRANSITION_TARGET=3.13 \
    --entrypoint /bin/sh \
    "$source_image" /usr/local/bin/backupsheep-rabbitmq-entrypoint legacy-source >/dev/null
assert_container_identity "$source_container" "$source_image_id" 999:999
wait_for_broker "$source_container" 3.13.7
assert_stock_identity "$source_container"
assert_migration_message "$source_container"
assert_feature_flags "$source_container" all disabled
kill_abruptly "$source_container"

# A ledger-authorized same-version source must recover the exact PID-1 crash
# residue before any cross-version image is allowed to open the volume.
docker run --detach --pull never \
    "${common_labels[@]}" \
    "${common_broker_limits[@]}" \
    "${common_node_environment[@]}" \
    --name "$source_container" \
    --hostname "$node_host" \
    --network none \
    --user 999:999 \
    --tmpfs /var/log/rabbitmq:rw,noexec,nosuid,nodev,size=64m,mode=0750,uid=999,gid=999 \
    --tmpfs /run/backupsheep-rabbitmq:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=999,gid=999 \
    --mount "type=volume,source=$volume_name,target=/var/lib/rabbitmq,volume-nocopy" \
    --mount "type=bind,source=$legacy_config_source,target=/etc/rabbitmq/conf.d/90-backupsheep.conf,readonly" \
    --mount "type=bind,source=$entrypoint_source,target=/usr/local/bin/backupsheep-rabbitmq-entrypoint,readonly" \
    --mount "type=bind,source=$volume_init_source,target=/usr/local/bin/backupsheep-rabbitmq-volume-init,readonly" \
    --env "BACKUPSHEEP_INSTALLATION_ID=$installation_id" \
    --env BACKUPSHEEP_RABBITMQ_DATA_GENERATION=unattested \
    --env BACKUPSHEEP_RABBITMQ_TRANSITION_TARGET=3.13 \
    --env BACKUPSHEEP_RABBITMQ_SAME_VERSION_RECOVERY=3.13.7 \
    --entrypoint /bin/sh \
    "$source_image" /usr/local/bin/backupsheep-rabbitmq-entrypoint legacy-source >/dev/null
assert_container_identity "$source_container" "$source_image_id" 999:999
wait_for_broker "$source_container" 3.13.7
assert_stock_identity "$source_container"
assert_migration_message "$source_container"
assert_feature_flags "$source_container" all disabled
stop_cleanly "$source_container"

# Convert only the exact clean 999:999 stock tree to the current RabbitMQ UID.
docker run --rm --pull never \
    "${common_labels[@]}" \
    --name "$uid_container" \
    --hostname "$node_host" \
    --network none \
    --read-only \
    --user 0:0 \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    --pids-limit 32 \
    --memory 64m \
    --memory-swap 64m \
    --cpus 0.25 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777 \
    --mount "type=volume,source=$volume_name,target=/var/lib/rabbitmq,volume-nocopy" \
    --mount "type=bind,source=$uid_transition_source,target=/usr/local/bin/backupsheep-rabbitmq-uid-transition,readonly" \
    --env "BACKUPSHEEP_INSTALLATION_ID=$installation_id" \
    --env BACKUPSHEEP_RABBITMQ_DATA_GENERATION=unattested \
    --env "BACKUPSHEEP_RABBITMQ_NODE_HOST=$node_host" \
    --entrypoint /bin/sh \
    "$upgrade_image" /usr/local/bin/backupsheep-rabbitmq-uid-transition >/dev/null

# Open the converted volume in 4.2.9 through the exact transition entrypoint.
docker run --detach --pull never \
    "${common_labels[@]}" \
    "${common_broker_limits[@]}" \
    "${common_node_environment[@]}" \
    --name "$upgrade_container" \
    --hostname "$node_host" \
    --network none \
    --user 100:101 \
    --tmpfs /var/log/rabbitmq:rw,noexec,nosuid,nodev,size=64m,mode=0750,uid=100,gid=101 \
    --tmpfs /run/backupsheep-rabbitmq:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=100,gid=101 \
    --mount "type=volume,source=$volume_name,target=/var/lib/rabbitmq,volume-nocopy" \
    --mount "type=bind,source=$legacy_config_source,target=/etc/rabbitmq/conf.d/90-backupsheep.conf,readonly" \
    --mount "type=bind,source=$entrypoint_source,target=/usr/local/bin/backupsheep-rabbitmq-entrypoint,readonly" \
    --mount "type=bind,source=$volume_init_source,target=/usr/local/bin/backupsheep-rabbitmq-volume-init,readonly" \
    --env "BACKUPSHEEP_INSTALLATION_ID=$installation_id" \
    --env BACKUPSHEEP_RABBITMQ_DATA_GENERATION=unattested \
    --env BACKUPSHEEP_RABBITMQ_TRANSITION_TARGET=4.2 \
    --entrypoint /bin/sh \
    "$upgrade_image" /usr/local/bin/backupsheep-rabbitmq-entrypoint transition >/dev/null
assert_container_identity "$upgrade_container" "$upgrade_image_id" 100:101
wait_for_broker "$upgrade_container" 4.2.9
assert_migration_message "$upgrade_container"
docker exec --user rabbitmq "$upgrade_container" \
    rabbitmqctl -q -n "$node_name" enable_feature_flag all >/dev/null
docker exec --user rabbitmq "$upgrade_container" \
    rabbitmqctl -q -n "$node_name" enable_feature_flag khepri_db >/dev/null
assert_feature_flags "$upgrade_container" all enabled
assert_migration_message "$upgrade_container"
kill_abruptly "$upgrade_container"

# Recover the exact Khepri-enabled 4.2 target with the same image, then stop it
# cleanly so the 4.3 hop never becomes an implicit crash-recovery mechanism.
docker run --detach --pull never \
    "${common_labels[@]}" \
    "${common_broker_limits[@]}" \
    "${common_node_environment[@]}" \
    --name "$upgrade_container" \
    --hostname "$node_host" \
    --network none \
    --user 100:101 \
    --tmpfs /var/log/rabbitmq:rw,noexec,nosuid,nodev,size=64m,mode=0750,uid=100,gid=101 \
    --tmpfs /run/backupsheep-rabbitmq:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=100,gid=101 \
    --mount "type=volume,source=$volume_name,target=/var/lib/rabbitmq,volume-nocopy" \
    --mount "type=bind,source=$legacy_config_source,target=/etc/rabbitmq/conf.d/90-backupsheep.conf,readonly" \
    --mount "type=bind,source=$entrypoint_source,target=/usr/local/bin/backupsheep-rabbitmq-entrypoint,readonly" \
    --mount "type=bind,source=$volume_init_source,target=/usr/local/bin/backupsheep-rabbitmq-volume-init,readonly" \
    --env "BACKUPSHEEP_INSTALLATION_ID=$installation_id" \
    --env BACKUPSHEEP_RABBITMQ_DATA_GENERATION=unattested \
    --env BACKUPSHEEP_RABBITMQ_TRANSITION_TARGET=4.2 \
    --env BACKUPSHEEP_RABBITMQ_SAME_VERSION_RECOVERY=4.2.9 \
    --entrypoint /bin/sh \
    "$upgrade_image" /usr/local/bin/backupsheep-rabbitmq-entrypoint transition >/dev/null
assert_container_identity "$upgrade_container" "$upgrade_image_id" 100:101
wait_for_broker "$upgrade_container" 4.2.9
assert_feature_flags "$upgrade_container" all enabled
assert_migration_message "$upgrade_container"
stop_cleanly "$upgrade_container"

# Complete the real 4.3.5 data migration and prove the persistent message again.
docker run --detach --pull never \
    "${common_labels[@]}" \
    "${common_broker_limits[@]}" \
    "${common_node_environment[@]}" \
    --name "$target_container" \
    --hostname "$node_host" \
    --network none \
    --user 100:101 \
    --tmpfs /var/log/rabbitmq:rw,noexec,nosuid,nodev,size=64m,mode=0750,uid=100,gid=101 \
    --tmpfs /run/backupsheep-rabbitmq:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=100,gid=101 \
    --mount "type=volume,source=$volume_name,target=/var/lib/rabbitmq,volume-nocopy" \
    --mount "type=bind,source=$legacy_config_source,target=/etc/rabbitmq/conf.d/90-backupsheep.conf,readonly" \
    --mount "type=bind,source=$entrypoint_source,target=/usr/local/bin/backupsheep-rabbitmq-entrypoint,readonly" \
    --mount "type=bind,source=$volume_init_source,target=/usr/local/bin/backupsheep-rabbitmq-volume-init,readonly" \
    --env "BACKUPSHEEP_INSTALLATION_ID=$installation_id" \
    --env BACKUPSHEEP_RABBITMQ_DATA_GENERATION=unattested \
    --env BACKUPSHEEP_RABBITMQ_TRANSITION_TARGET=4.3 \
    --entrypoint /bin/sh \
    "$target_image" /usr/local/bin/backupsheep-rabbitmq-entrypoint transition >/dev/null
assert_container_identity "$target_container" "$target_image_id" 100:101
wait_for_broker "$target_container" 4.3.5
assert_feature_flags "$target_container" required enabled
assert_migration_message "$target_container"
kill_abruptly "$target_container"

# Exercise the final pre-witness crash window under the exact 4.3 transition
# image. The recovery request is same-version only and must retain the message.
docker run --detach --pull never \
    "${common_labels[@]}" \
    "${common_broker_limits[@]}" \
    "${common_node_environment[@]}" \
    --name "$target_container" \
    --hostname "$node_host" \
    --network none \
    --user 100:101 \
    --tmpfs /var/log/rabbitmq:rw,noexec,nosuid,nodev,size=64m,mode=0750,uid=100,gid=101 \
    --tmpfs /run/backupsheep-rabbitmq:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=100,gid=101 \
    --mount "type=volume,source=$volume_name,target=/var/lib/rabbitmq,volume-nocopy" \
    --mount "type=bind,source=$legacy_config_source,target=/etc/rabbitmq/conf.d/90-backupsheep.conf,readonly" \
    --mount "type=bind,source=$entrypoint_source,target=/usr/local/bin/backupsheep-rabbitmq-entrypoint,readonly" \
    --mount "type=bind,source=$volume_init_source,target=/usr/local/bin/backupsheep-rabbitmq-volume-init,readonly" \
    --env "BACKUPSHEEP_INSTALLATION_ID=$installation_id" \
    --env BACKUPSHEEP_RABBITMQ_DATA_GENERATION=unattested \
    --env BACKUPSHEEP_RABBITMQ_TRANSITION_TARGET=4.3 \
    --env BACKUPSHEEP_RABBITMQ_SAME_VERSION_RECOVERY=4.3.5 \
    --entrypoint /bin/sh \
    "$target_image" /usr/local/bin/backupsheep-rabbitmq-entrypoint transition >/dev/null
assert_container_identity "$target_container" "$target_image_id" 100:101
wait_for_broker "$target_container" 4.3.5
assert_feature_flags "$target_container" required enabled
assert_migration_message "$target_container"

# The production gate requires a drained legacy vhost before final reconciliation.
docker exec --user rabbitmq "$target_container" \
    rabbitmqctl -q -n "$node_name" -p / purge_queue "$queue_name" >/dev/null
queue_rows="$(docker exec --user rabbitmq "$target_container" \
    rabbitmqctl -q -s -n "$node_name" -p / list_queues \
    name messages_ready messages_unacknowledged consumers 2>/dev/null)"
printf '%s\n' "$queue_rows" | awk 'NF != 4 || $2 != 0 || $3 != 0 || $4 != 0 { exit 1 }'
docker exec --user rabbitmq "$target_container" \
    rabbitmqctl -q -n "$node_name" -p / delete_queue "$queue_name" >/dev/null
final_legacy_queues="$(docker exec --user rabbitmq "$target_container" \
    rabbitmqctl -q -s -n "$node_name" -p / list_queues name 2>/dev/null)" \
    || { printf '%s\n' 'RabbitMQ migration E2E legacy queue inventory failed.' >&2; exit 1; }
[ -z "$final_legacy_queues" ] \
    || { printf '%s\n' 'RabbitMQ migration E2E legacy queue retirement drifted.' >&2; exit 1; }

stop_cleanly "$target_container"

# Publish the durable 4.3 witness only after the target and final topology pass.
docker run --rm --pull never \
    "${common_labels[@]}" \
    --name "$finalize_container" \
    --hostname "$node_host" \
    --network none \
    --read-only \
    --user 100:101 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 32 \
    --memory 64m \
    --memory-swap 64m \
    --cpus 0.25 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777 \
    --mount "type=volume,source=$volume_name,target=/var/lib/rabbitmq,volume-nocopy" \
    --mount "type=bind,source=$volume_init_source,target=/usr/local/bin/backupsheep-rabbitmq-volume-init,readonly" \
    --env "BACKUPSHEEP_INSTALLATION_ID=$installation_id" \
    --env BACKUPSHEEP_RABBITMQ_DATA_GENERATION=4.3 \
    --env "BACKUPSHEEP_RABBITMQ_NODE_HOST=$node_host" \
    --entrypoint /bin/sh \
    "$target_image" /usr/local/bin/backupsheep-rabbitmq-volume-init finalize-transition >/dev/null

# Recreate the canonical steady model and re-prove topology after a clean restart.
docker run --detach --pull never \
    "${common_labels[@]}" \
    "${common_broker_limits[@]}" \
    "${common_node_environment[@]}" \
    --name "$steady_container" \
    --hostname "$node_host" \
    --network "$network_name" \
    --network-alias "$node_host" \
    --user 100:101 \
    --tmpfs /var/log/rabbitmq:rw,noexec,nosuid,nodev,size=64m,mode=0750,uid=100,gid=101 \
    --tmpfs /run/backupsheep-rabbitmq:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=100,gid=101 \
    --mount "type=volume,source=$volume_name,target=/var/lib/rabbitmq,volume-nocopy" \
    --mount "type=bind,source=$current_config_source,target=/etc/rabbitmq/conf.d/90-backupsheep.conf,readonly" \
    --mount "type=bind,source=$entrypoint_source,target=/usr/local/bin/backupsheep-rabbitmq-entrypoint,readonly" \
    --mount "type=bind,source=$volume_init_source,target=/usr/local/bin/backupsheep-rabbitmq-volume-init,readonly" \
    --mount "type=bind,source=$secret_dir,target=/run/secrets,readonly" \
    --env "BACKUPSHEEP_INSTALLATION_ID=$installation_id" \
    --env BACKUPSHEEP_RABBITMQ_DATA_GENERATION=4.3 \
    --entrypoint /bin/sh \
    "$target_image" /usr/local/bin/backupsheep-rabbitmq-entrypoint >/dev/null
assert_container_identity "$steady_container" "$target_image_id" 100:101
wait_for_broker "$steady_container" 4.3.5

# Only the canonical steady broker regains the private product network. Run the
# real least-privilege provisioner here, never against a transition broker whose
# required network_mode is none.
run_provisioner >/dev/null
assert_final_topology "$steady_container"
canonical_internal_cluster_id="$(docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -s -n "$node_name" eval \
    'rabbit_runtime_parameters:value_global(internal_cluster_id).' 2>/dev/null)"
if [[ "$canonical_internal_cluster_id" =~ ^\<\<\"(rabbitmq-cluster-id-[A-Za-z0-9_-]{22})\"\>\>$ ]]; then
    canonical_internal_cluster_id_json="\"${BASH_REMATCH[1]}\""
else
    printf '%s\n' 'RabbitMQ migration E2E internal cluster ID is malformed.' >&2
    exit 1
fi

# Defeat the former raw-TSV parser deliberately: one parameter name containing
# TAB and LF renders as the two canonical rows after the real core keys are
# removed. Server-side semantic enumeration must still reject it pre-mutation.
crafted_global_parameter=$'cluster_tags\t[]\ninternal_cluster_id'
docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -n "$node_name" clear_global_parameter cluster_tags >/dev/null
docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -n "$node_name" clear_global_parameter internal_cluster_id >/dev/null
docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -n "$node_name" set_global_parameter \
    "$crafted_global_parameter" "$canonical_internal_cluster_id_json" >/dev/null
spoofed_global_rows="$(docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -s -n "$node_name" list_global_parameters 2>/dev/null)"
[[ "$spoofed_global_rows" = \
    "cluster_tags"$'\t'"[]"$'\n'"internal_cluster_id"$'\t'"${canonical_internal_cluster_id_json}" ]] \
    || { printf '%s\n' 'RabbitMQ migration E2E crafted global-parameter fixture did not spoof raw TSV.' >&2; exit 1; }
expect_pre_mutation_provisioner_rejection \
    "$steady_container" forbidden-framed-global-parameter \
    'RabbitMQ global runtime-parameter drift detected.'
docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -n "$node_name" clear_global_parameter \
    "$crafted_global_parameter" >/dev/null
docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -n "$node_name" set_global_parameter cluster_tags '[]' >/dev/null
docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -n "$node_name" set_global_parameter \
    internal_cluster_id "$canonical_internal_cluster_id_json" >/dev/null
[[ "$(docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -s -n "$node_name" eval \
    'rabbit_runtime_parameters:value_global(internal_cluster_id).' 2>/dev/null)" \
    = "$canonical_internal_cluster_id" ]] \
    || { printf '%s\n' 'RabbitMQ migration E2E failed to restore the exact internal cluster ID.' >&2; exit 1; }
assert_final_topology "$steady_container"

# A persistent global runtime parameter that is not one of RabbitMQ's two
# reviewed core values must fail before credential rotation. Clear the exact
# test fixture afterwards and independently re-attest the unchanged topology.
docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -n "$node_name" set_global_parameter \
    backupsheep_e2e_forbidden '{"enabled":true}' >/dev/null
expect_pre_mutation_provisioner_rejection \
    "$steady_container" forbidden-global-parameter \
    'RabbitMQ global runtime-parameter drift detected.'
docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -n "$node_name" clear_global_parameter \
    backupsheep_e2e_forbidden >/dev/null
assert_final_topology "$steady_container"

# The definitions hash is intentionally hidden from list_global_parameters, so
# exercise the dedicated lookup and rejection branch independently.
docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -n "$node_name" set_global_parameter \
    imported_definition_hash_value '{"sha256":"backupsheep-e2e-forbidden"}' >/dev/null
expect_pre_mutation_provisioner_rejection \
    "$steady_container" forbidden-hidden-definition-hash \
    'RabbitMQ global runtime-parameter drift detected.'
docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -n "$node_name" clear_global_parameter \
    imported_definition_hash_value >/dev/null
assert_final_topology "$steady_container"

# RabbitMQ permits spaces and control characters in usernames. Prove that a
# crafted prefix cannot be collapsed into an allowed identity by text parsing.
docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -n "$node_name" add_user \
    'backupsheep_app evil' 'backupsheep-e2e-fixture-password-0000000000000000' >/dev/null
expect_pre_mutation_provisioner_rejection \
    "$steady_container" forbidden-spaced-username \
    'RabbitMQ contains an unexpected user.'
docker exec --user rabbitmq "$steady_container" \
    rabbitmqctl -q -n "$node_name" delete_user 'backupsheep_app evil' >/dev/null
assert_final_topology "$steady_container"

for crafted_case in tab newline; do
    case "$crafted_case" in
        tab) crafted_user=$'backupsheep_app\tevil' ;;
        newline) crafted_user=$'backupsheep_app\nevil' ;;
        *) exit 64 ;;
    esac
    docker exec --user rabbitmq "$steady_container" \
        rabbitmqctl -q -n "$node_name" add_user \
        "$crafted_user" 'backupsheep-e2e-fixture-password-0000000000000000' >/dev/null
    expect_pre_mutation_provisioner_rejection \
        "$steady_container" "forbidden-${crafted_case}-username" \
        'RabbitMQ contains an unexpected user.'
    docker exec --user rabbitmq "$steady_container" \
        rabbitmqctl -q -n "$node_name" delete_user "$crafted_user" >/dev/null
    assert_final_topology "$steady_container"
done
stop_cleanly "$steady_container"

printf '%s\n' \
    'RabbitMQ exact 3.13.7 -> 4.2.9 -> 4.3.5 migration, three same-version crash recoveries, persistent message, Khepri, witness, and final topology verified.'
