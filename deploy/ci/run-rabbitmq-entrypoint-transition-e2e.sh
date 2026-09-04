#!/usr/bin/env bash
# Exercise the reviewed RabbitMQ entrypoint boundary in the real runtime images.
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
    printf '%s\n' \
        'usage: run-rabbitmq-entrypoint-transition-e2e.sh BASE_IMAGE UPGRADE_IMAGE RESOURCE_PREFIX OWNERSHIP_VALUE' >&2
    exit 64
fi

base_image="$1"
upgrade_image="$2"
resource_prefix="$3"
ownership_value="$4"
ownership_label='com.backupsheep.ci-run'
cleanup_label='com.backupsheep.ci-cleanup-token'
vendor_marker='__BACKUPSHEEP_RABBITMQ_VENDOR_ENTRYPOINT_REACHED__'
installation_id='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

for image in "$base_image" "$upgrade_image"; do
    [[ -n "$image" && "$image" != -* && "$image" != *$'\n'* ]] \
        || { printf '%s\n' 'RabbitMQ test image reference is unsafe.' >&2; exit 64; }
done
[[ "$resource_prefix" =~ ^[a-z0-9][a-z0-9_.-]{0,119}$ ]] \
    || { printf '%s\n' 'RabbitMQ test resource prefix is unsafe.' >&2; exit 64; }
[[ "$ownership_value" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$ ]] \
    || { printf '%s\n' 'RabbitMQ test ownership value is unsafe.' >&2; exit 64; }

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(CDPATH= cd -- "$script_dir/../.." && pwd -P)"
entrypoint_source="$repository_root/deploy/rabbitmq/entrypoint.sh"
volume_init_source="$repository_root/deploy/rabbitmq/volume-init.sh"
for source_file in "$entrypoint_source" "$volume_init_source"; do
    [[ -f "$source_file" && ! -L "$source_file" && -x "$source_file" ]] \
        || { printf '%s\n' "RabbitMQ runtime source is unavailable: $source_file" >&2; exit 1; }
done

scratch_dir="$(mktemp -d "${TMPDIR:-/tmp}/backupsheep-rabbitmq-entrypoint.XXXXXX")"
chmod 0700 "$scratch_dir"
cleanup_token="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$cleanup_token" =~ ^[0-9a-f]{64}$ ]] \
    || { printf '%s\n' 'RabbitMQ test cleanup token generation failed.' >&2; exit 1; }
vendor_stub="$scratch_dir/docker-entrypoint.sh"
secret_dir="$scratch_dir/secrets"
mkdir -m 0755 "$secret_dir"
printf '%s\n' 'backupsheep-ci-only-bootstrap-secret-00000000000000000000000000000000' \
    > "$secret_dir/rabbitmq_bootstrap_password"
chmod 0444 "$secret_dir/rabbitmq_bootstrap_password"

printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    '[ "$#" -eq 1 ] && [ "$1" = rabbitmq-server ] || exit 97' \
    "printf '%s\\n' '$vendor_marker'" \
    > "$vendor_stub"
chmod 0555 "$vendor_stub"

volume_suffixes=(
    steady-unattested
    malformed-target
    transition42-empty
    transition42-legacy
    transition42-wrong-image
    transition43-empty
    transition43-legacy
    transition43-khepri
    transition43-wrong-image
    steady43-final
    legacy-v1-khepri
    legacy-v1-wrong-host
    init-legacy
    init-zero-pending
    init-orphan-temp
    finalize-legacy
    finalize-partial-pending
    finalize-existing-final
    finalize-final-only
    resume-absent
    resume-pending
    resume-malformed
    pending-missing-newline
    pending-multiple-newlines
    final-missing-newline
    final-multiple-newlines
    resume-final
    resume-both
)
container_suffixes=(
    seed42-legacy
    seed43-legacy
    final-witness-init
    steady-unattested
    malformed-target
    transition42-empty
    transition42-legacy
    seed42-wrong-image
    transition42-wrong-image
    transition43-empty
    transition43-legacy
    seed43-khepri
    transition43-khepri
    seed43-wrong-image
    transition43-wrong-image
    steady43-no-witness
    steady43-final
    seed-legacy-v1-khepri
    seed-legacy-v1-khepri-witness
    verify-legacy-v1-khepri
    seed-legacy-v1-wrong-host
    seed-legacy-v1-wrong-host-witness
    verify-legacy-v1-wrong-host
    seed-init-legacy
    init-legacy
    seed-init-zero-pending
    init-zero-pending
    seed-init-orphan-temp
    init-orphan-temp
    seed-finalize-legacy
    finalize-legacy
    seed-finalize-partial-legacy
    seed-finalize-partial-pending
    finalize-partial-pending
    seed-finalize-existing-legacy
    seed-finalize-existing-final
    finalize-existing-final
    init-finalize-final-only
    finalize-final-only
    seed-resume-pending
    seed-resume-malformed
    seed-pending-missing-newline
    resume-pending-missing-newline
    seed-pending-multiple-newlines
    resume-pending-multiple-newlines
    seed-final-missing-newline
    verify-final-missing-newline
    seed-final-multiple-newlines
    verify-final-multiple-newlines
    init-resume-final
    init-resume-both
    seed-resume-both-pending
    resume-absent
    resume-pending
    resume-malformed
    resume-final
    resume-both
)
volumes=()
containers=()
for suffix in "${volume_suffixes[@]}"; do
    volumes+=("${resource_prefix}-${suffix}")
done
for suffix in "${container_suffixes[@]}"; do
    containers+=("${resource_prefix}-${suffix}")
done

resource_label() {
    local resource_type="$1" resource_name="$2" label_name="$3"
    local label_root=''
    case "$resource_type" in
        container) label_root='.Config.Labels' ;;
        volume) label_root='.Labels' ;;
        *) return 1 ;;
    esac
    docker "$resource_type" inspect --format \
        "{{with index ${label_root} \"${label_name}\"}}{{.}}{{end}}" \
        "$resource_name"
}

cleanup_resources() {
    local cleanup_status=0 resource='' owner='' token=''
    for resource in "${containers[@]}"; do
        if docker container inspect "$resource" >/dev/null 2>&1; then
            owner="$(resource_label container "$resource" "$ownership_label" 2>/dev/null || true)"
            token="$(resource_label container "$resource" "$cleanup_label" 2>/dev/null || true)"
            if [[ "$owner" = "$ownership_value" && "$token" = "$cleanup_token" ]]; then
                docker container rm --force "$resource" >/dev/null || cleanup_status=1
            else
                printf '%s\n' "Refusing to remove an unowned CI container: $resource" >&2
                cleanup_status=1
            fi
        fi
    done
    for resource in "${volumes[@]}"; do
        if docker volume inspect "$resource" >/dev/null 2>&1; then
            owner="$(resource_label volume "$resource" "$ownership_label" 2>/dev/null || true)"
            token="$(resource_label volume "$resource" "$cleanup_label" 2>/dev/null || true)"
            if [[ "$owner" = "$ownership_value" && "$token" = "$cleanup_token" ]]; then
                docker volume rm "$resource" >/dev/null || cleanup_status=1
            else
                printf '%s\n' "Refusing to remove an unowned CI volume: $resource" >&2
                cleanup_status=1
            fi
        fi
    done
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
        printf '%s\n' "Refusing a pre-existing RabbitMQ CI container collision: $resource" >&2
        exit 1
    fi
done
for resource in "${volumes[@]}"; do
    if docker volume inspect "$resource" >/dev/null 2>&1; then
        printf '%s\n' "Refusing a pre-existing RabbitMQ CI volume collision: $resource" >&2
        exit 1
    fi
done
for resource in "${volumes[@]}"; do
    test "$(docker volume create \
        --label "$ownership_label=$ownership_value" \
        --label "$cleanup_label=$cleanup_token" \
        "$resource")" = "$resource"
    test "$(resource_label volume "$resource" "$ownership_label")" = "$ownership_value"
    test "$(resource_label volume "$resource" "$cleanup_label")" = "$cleanup_token"
done

common_runtime_args=(
    --rm
    --pull never
    --label "$ownership_label=$ownership_value"
    --label "$cleanup_label=$cleanup_token"
    --hostname rabbitmq
    --network none
    --read-only
    --user 100:101
    --cap-drop ALL
    --security-opt no-new-privileges:true
    --pids-limit 64
    --memory 256m
    --memory-swap 256m
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777
    --env BACKUPSHEEP_RABBITMQ_NODE_HOST=rabbitmq
    --env RABBITMQ_NODENAME=rabbit@rabbitmq
)
entrypoint_mount_args=(
    --tmpfs /run/backupsheep-rabbitmq:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=100,gid=101
    --mount "type=bind,source=$entrypoint_source,target=/usr/local/bin/backupsheep-rabbitmq-entrypoint,readonly"
    --mount "type=bind,source=$volume_init_source,target=/usr/local/bin/backupsheep-rabbitmq-volume-init,readonly"
    --mount "type=bind,source=$vendor_stub,target=/usr/local/bin/docker-entrypoint.sh,readonly"
)

seed_safe_legacy_volume() {
    local container_name="$1" image="$2" volume="$3"
    docker run "${common_runtime_args[@]}" \
        --name "$container_name" \
        --mount "type=volume,source=$volume,target=/var/lib/rabbitmq" \
        --entrypoint /bin/sh \
        "$image" -ceu '
            umask 077
            test "$(stat -c "%u:%g" /var/lib/rabbitmq)" = 100:101
            node=rabbit@rabbitmq
            mnesia=/var/lib/rabbitmq/mnesia
            node_dir="${mnesia}/${node}"
            plugins="${mnesia}/${node}-plugins-expand"
            mkdir -p "$node_dir" "$plugins"
            chmod 0755 "$mnesia" "$node_dir" "$plugins"
            printf "%s" 0123456789ABCDEFGHIJ > /var/lib/rabbitmq/.erlang.cookie
            chmod 0400 /var/lib/rabbitmq/.erlang.cookie
            printf "%s\n" "[{rabbitmq_4.0.0,enabled}]" > "${mnesia}/${node}-feature_flags"
            printf "disc.\n" > "${node_dir}/node-type.txt"
            printf "{[%s],[%s]}.\n" "$node" "$node" > "${node_dir}/cluster_nodes.config"
            printf "[%s].\n" "$node" > "${node_dir}/nodes_running_at_shutdown"
            printf "%s\n" schema > "${node_dir}/schema.DAT"
            for table in \
                rabbit_durable_exchange rabbit_durable_queue rabbit_durable_route \
                rabbit_runtime_parameters rabbit_topic_permission rabbit_user \
                rabbit_user_permission rabbit_vhost; do
                printf "%s\n" "$table" > "${node_dir}/${table}.DCD"
            done
            chmod 0644 \
                "${mnesia}/${node}-feature_flags" \
                "${node_dir}/node-type.txt" \
                "${node_dir}/cluster_nodes.config" \
                "${node_dir}/nodes_running_at_shutdown" \
                "${node_dir}/schema.DAT" \
                "${node_dir}"/*.DCD
        '
}

seed_safe_khepri_volume() {
    local container_name="$1" image="$2" volume="$3"
    docker run "${common_runtime_args[@]}" \
        --name "$container_name" \
        --mount "type=volume,source=$volume,target=/var/lib/rabbitmq" \
        --entrypoint /bin/sh \
        "$image" -ceu '
            umask 077
            test "$(stat -c "%u:%g" /var/lib/rabbitmq)" = 100:101
            node=rabbit@rabbitmq
            mnesia=/var/lib/rabbitmq/mnesia
            node_dir="${mnesia}/${node}"
            plugins="${mnesia}/${node}-plugins-expand"
            quorum="${node_dir}/quorum/${node}"
            coordination="${node_dir}/coordination/${node}"
            mkdir -p "$plugins" "$quorum" "$coordination"
            chmod 0755 "$mnesia" "$node_dir" "$plugins" \
                "${node_dir}/quorum" "$quorum" \
                "${node_dir}/coordination" "$coordination"
            printf "%s" 0123456789ABCDEFGHIJ > /var/lib/rabbitmq/.erlang.cookie
            chmod 0400 /var/lib/rabbitmq/.erlang.cookie
            printf "%s\n" "[{khepri_db,enabled}]" > "${mnesia}/${node}-feature_flags"
            for ra_dir in "$quorum" "$coordination"; do
                printf "%s\n" meta > "${ra_dir}/meta.dets"
                printf "%s\n" names > "${ra_dir}/names.dets"
            done
            chmod 0644 \
                "${mnesia}/${node}-feature_flags" \
                "$quorum/meta.dets" "$quorum/names.dets" \
                "$coordination/meta.dets" "$coordination/names.dets"
        '
}

initialize_final_witness() {
    local container_name="$1" volume="$2"
    docker run "${common_runtime_args[@]}" \
        --name "$container_name" \
        --mount "type=volume,source=$volume,target=/var/lib/rabbitmq" \
        --mount "type=bind,source=$volume_init_source,target=/usr/local/bin/backupsheep-rabbitmq-volume-init,readonly" \
        --env "BACKUPSHEEP_INSTALLATION_ID=$installation_id" \
        --env BACKUPSHEEP_RABBITMQ_DATA_GENERATION=4.3 \
        --entrypoint /bin/sh \
        "$base_image" /usr/local/bin/backupsheep-rabbitmq-volume-init init
}

assert_final_witness_v2() {
    local volume="$1"
    docker run "${common_runtime_args[@]}" \
        --mount "type=volume,source=$volume,target=/var/lib/rabbitmq" \
        --env "BACKUPSHEEP_TEST_INSTALLATION_ID=$installation_id" \
        --entrypoint /bin/sh \
        "$base_image" -ceu '
            printf "%s\n" \
                "version=2" \
                "installation_id=${BACKUPSHEEP_TEST_INSTALLATION_ID}" \
                "data_generation=4.3" \
                "node_host=rabbitmq" \
                "uid=100" \
                "gid=101" \
                | cmp -s /var/lib/rabbitmq/.backupsheep-volume-identity -
        '
}

run_witness_creation_case() {
    local expectation="$1" container_name="$2" volume="$3" mode="$4"
    local expected_error="${5:-}"
    local node_host="${6:-rabbitmq}"
    local stdout_file="$scratch_dir/${container_name}.stdout"
    local stderr_file="$scratch_dir/${container_name}.stderr"
    local status=0
    if docker run "${common_runtime_args[@]}" \
        --name "$container_name" \
        --mount "type=volume,source=$volume,target=/var/lib/rabbitmq" \
        --mount "type=bind,source=$volume_init_source,target=/usr/local/bin/backupsheep-rabbitmq-volume-init,readonly" \
        --env "BACKUPSHEEP_INSTALLATION_ID=$installation_id" \
        --env BACKUPSHEEP_RABBITMQ_DATA_GENERATION=4.3 \
        --env "BACKUPSHEEP_RABBITMQ_NODE_HOST=$node_host" \
        --entrypoint /bin/sh \
        "$base_image" /usr/local/bin/backupsheep-rabbitmq-volume-init "$mode" \
        >"$stdout_file" 2>"$stderr_file"; then
        status=0
    else
        status="$?"
    fi
    case "$expectation" in
        reject)
            [[ "$status" -ne 0 && -n "$expected_error" ]] \
                || { printf '%s\n' "RabbitMQ witness rejection case unexpectedly succeeded: $container_name" >&2; return 1; }
            grep -Fxq -- "$expected_error" "$stderr_file" \
                || { sed -n '1,80p' "$stderr_file" >&2; printf '%s\n' "RabbitMQ witness rejection reason drifted: $container_name" >&2; return 1; }
            ;;
        accept)
            [[ "$status" -eq 0 && -z "$expected_error" ]] \
                || { sed -n '1,80p' "$stderr_file" >&2; printf '%s\n' "RabbitMQ witness acceptance case failed: $container_name" >&2; return 1; }
            grep -Fxq -- 'RabbitMQ volume ownership generation 4.3 verified.' "$stdout_file" \
                || { printf '%s\n' "RabbitMQ witness acceptance proof is missing: $container_name" >&2; return 1; }
            ;;
        *) return 64 ;;
    esac
}

seed_raw_witness() {
    local container_name="$1" volume="$2" record_kind="$3" content_mode="$4"
    [[ "$record_kind" = pending || "$record_kind" = final || "$record_kind" = temporary ]] || return 64
    [[ "$content_mode" = exact || "$content_mode" = legacy-exact \
        || "$content_mode" = malformed \
        || "$content_mode" = missing-newline \
        || "$content_mode" = multiple-newlines || "$content_mode" = zero \
        || "$content_mode" = partial ]] || return 64
    docker run "${common_runtime_args[@]}" \
        --name "$container_name" \
        --mount "type=volume,source=$volume,target=/var/lib/rabbitmq" \
        --env "BACKUPSHEEP_TEST_INSTALLATION_ID=$installation_id" \
        --env "BACKUPSHEEP_TEST_RECORD_KIND=$record_kind" \
        --env "BACKUPSHEEP_TEST_CONTENT_MODE=$content_mode" \
        --entrypoint /bin/sh \
        "$base_image" -ceu '
            umask 077
            case "$BACKUPSHEEP_TEST_RECORD_KIND" in
                pending) record=/var/lib/rabbitmq/.backupsheep-volume-identity.pending ;;
                final) record=/var/lib/rabbitmq/.backupsheep-volume-identity ;;
                temporary) record=/var/lib/rabbitmq/.backupsheep-volume-identity.pending.tmp.A1b2C3 ;;
                *) exit 64 ;;
            esac
            test ! -e "$record" && test ! -L "$record"
            # init tightens the named-volume root before its durable pending
            # write. Reproduce that exact state so byte validation is tested,
            # not rejected incidentally by a 01777 root.
            chmod 0700 /var/lib/rabbitmq
            case "$BACKUPSHEEP_TEST_CONTENT_MODE" in
                exact)
                    printf "%s\n" \
                        "version=2" \
                        "installation_id=${BACKUPSHEEP_TEST_INSTALLATION_ID}" \
                        "data_generation=4.3" \
                        "node_host=rabbitmq" \
                        "uid=100" \
                        "gid=101" > "$record"
                    ;;
                legacy-exact)
                    printf "%s\n" \
                        "version=1" \
                        "installation_id=${BACKUPSHEEP_TEST_INSTALLATION_ID}" \
                        "data_generation=4.3" \
                        "uid=100" \
                        "gid=101" > "$record"
                    ;;
                missing-newline)
                    {
                        printf "%s\n" \
                            "version=2" \
                            "installation_id=${BACKUPSHEEP_TEST_INSTALLATION_ID}" \
                            "data_generation=4.3" \
                            "node_host=rabbitmq" \
                            "uid=100"
                        printf "%s" "gid=101"
                    } > "$record"
                    ;;
                multiple-newlines)
                    printf "%s\n" \
                        "version=2" \
                        "installation_id=${BACKUPSHEEP_TEST_INSTALLATION_ID}" \
                        "data_generation=4.3" \
                        "node_host=rabbitmq" \
                        "uid=100" \
                        "gid=101" \
                        "" > "$record"
                    ;;
                malformed)
                    printf "%s\n" "version=malformed" > "$record"
                    ;;
                zero)
                    : > "$record"
                    ;;
                partial)
                    printf "%s\n" "version=2" > "$record"
                    ;;
            esac
            chmod 0600 "$record"
        '
}

seed_pending_witness() {
    seed_raw_witness "$1" "$2" pending "$3"
}

seed_final_witness() {
    seed_raw_witness "$1" "$2" final "$3"
}

seed_temporary_witness() {
    seed_raw_witness "$1" "$2" temporary "$3"
}

assert_no_witness_staging_residue() {
    local volume="$1"
    docker run "${common_runtime_args[@]}" \
        --mount "type=volume,source=$volume,target=/var/lib/rabbitmq" \
        --entrypoint /bin/sh \
        "$base_image" -ceu \
        'test -z "$(find /var/lib/rabbitmq -xdev -mindepth 1 -maxdepth 1 -name ".backupsheep-volume-identity.pending.tmp.*" -print -quit)"'
}

run_resume_case() {
    local expectation="$1" container_name="$2" volume="$3"
    local expected_error="${4:-}"
    local stdout_file="$scratch_dir/${container_name}.stdout"
    local stderr_file="$scratch_dir/${container_name}.stderr"
    local status=0
    if docker run "${common_runtime_args[@]}" \
        --name "$container_name" \
        --mount "type=volume,source=$volume,target=/var/lib/rabbitmq" \
        --mount "type=bind,source=$volume_init_source,target=/usr/local/bin/backupsheep-rabbitmq-volume-init,readonly" \
        --env "BACKUPSHEEP_INSTALLATION_ID=$installation_id" \
        --env BACKUPSHEEP_RABBITMQ_DATA_GENERATION=4.3 \
        --entrypoint /bin/sh \
        "$base_image" /usr/local/bin/backupsheep-rabbitmq-volume-init resume \
        >"$stdout_file" 2>"$stderr_file"; then
        status=0
    else
        status="$?"
    fi
    case "$expectation" in
        reject)
            [[ "$status" -ne 0 && -n "$expected_error" ]] \
                || { printf '%s\n' "RabbitMQ resume rejection case unexpectedly succeeded: $container_name" >&2; return 1; }
            grep -Fxq -- "$expected_error" "$stderr_file" \
                || { sed -n '1,80p' "$stderr_file" >&2; printf '%s\n' "RabbitMQ resume rejection reason drifted: $container_name" >&2; return 1; }
            ;;
        accept)
            [[ "$status" -eq 0 && -z "$expected_error" ]] \
                || { sed -n '1,80p' "$stderr_file" >&2; printf '%s\n' "RabbitMQ resume acceptance case failed: $container_name" >&2; return 1; }
            grep -Fxq -- 'RabbitMQ volume ownership generation 4.3 verified.' "$stdout_file" \
                || { printf '%s\n' "RabbitMQ resume acceptance proof is missing: $container_name" >&2; return 1; }
            ;;
        *) return 64 ;;
    esac
}

run_entrypoint_case() {
    local expectation="$1" container_name="$2" image="$3" volume="$4"
    local generation="$5" target="$6" mode="$7"
    local stdout_file="$scratch_dir/${container_name}.stdout"
    local stderr_file="$scratch_dir/${container_name}.stderr"
    local status=0
    local -a target_args=(--env BACKUPSHEEP_RABBITMQ_TRANSITION_TARGET=)
    local -a command=(/usr/local/bin/backupsheep-rabbitmq-entrypoint)
    local -a case_runtime_args=(
        --name "$container_name"
        "${entrypoint_mount_args[@]}"
    )
    if [[ "$target" != unset ]]; then
        target_args=(--env "BACKUPSHEEP_RABBITMQ_TRANSITION_TARGET=$target")
    fi
    if [[ "$mode" = transition ]]; then
        command+=(transition)
    else
        case_runtime_args+=(
            --mount "type=bind,source=$secret_dir,target=/run/secrets,readonly"
        )
    fi
    case_runtime_args+=(
        --mount "type=volume,source=$volume,target=/var/lib/rabbitmq"
        --env "BACKUPSHEEP_INSTALLATION_ID=$installation_id"
        --env "BACKUPSHEEP_RABBITMQ_DATA_GENERATION=$generation"
    )

    if docker run "${common_runtime_args[@]}" \
        "${case_runtime_args[@]}" \
        "${target_args[@]}" \
        --entrypoint /bin/sh \
        "$image" "${command[@]}" \
        >"$stdout_file" 2>"$stderr_file"; then
        status=0
    else
        status="$?"
    fi

    case "$expectation" in
        reject)
            [[ "$status" -ne 0 ]] \
                || { printf '%s\n' "RabbitMQ rejection case unexpectedly succeeded: $container_name" >&2; return 1; }
            if grep -Fq -- "$vendor_marker" "$stdout_file" "$stderr_file"; then
                printf '%s\n' "RabbitMQ rejection case reached the vendor entrypoint: $container_name" >&2
                return 1
            fi
            ;;
        reach)
            [[ "$status" -eq 0 ]] \
                || { sed -n '1,80p' "$stderr_file" >&2; printf '%s\n' "RabbitMQ handoff case failed: $container_name" >&2; return 1; }
            [[ "$(grep -Fxc -- "$vendor_marker" "$stdout_file")" -eq 1 ]] \
                || { printf '%s\n' "RabbitMQ handoff marker was not emitted exactly once: $container_name" >&2; return 1; }
            if grep -Fq -- "$vendor_marker" "$stderr_file"; then
                printf '%s\n' "RabbitMQ handoff marker appeared on stderr: $container_name" >&2
                return 1
            fi
            ;;
        *) return 64 ;;
    esac
}

run_entrypoint_case reject \
    "${resource_prefix}-steady-unattested" "$base_image" \
    "${resource_prefix}-steady-unattested" unattested unset steady
run_entrypoint_case reject \
    "${resource_prefix}-malformed-target" "$base_image" \
    "${resource_prefix}-malformed-target" unattested 4.3-malformed transition
run_entrypoint_case reject \
    "${resource_prefix}-transition42-empty" "$upgrade_image" \
    "${resource_prefix}-transition42-empty" unattested 4.2 transition
run_entrypoint_case reject \
    "${resource_prefix}-transition43-empty" "$base_image" \
    "${resource_prefix}-transition43-empty" unattested 4.3 transition

seed_safe_legacy_volume \
    "${resource_prefix}-seed42-legacy" "$upgrade_image" \
    "${resource_prefix}-transition42-legacy"
run_entrypoint_case reach \
    "${resource_prefix}-transition42-legacy" "$upgrade_image" \
    "${resource_prefix}-transition42-legacy" unattested 4.2 transition
seed_safe_legacy_volume \
    "${resource_prefix}-seed42-wrong-image" "$base_image" \
    "${resource_prefix}-transition42-wrong-image"
run_entrypoint_case reject \
    "${resource_prefix}-transition42-wrong-image" "$base_image" \
    "${resource_prefix}-transition42-wrong-image" unattested 4.2 transition

seed_safe_legacy_volume \
    "${resource_prefix}-seed43-legacy" "$base_image" \
    "${resource_prefix}-transition43-legacy"
run_entrypoint_case reject \
    "${resource_prefix}-transition43-legacy" "$base_image" \
    "${resource_prefix}-transition43-legacy" unattested 4.3 transition
seed_safe_khepri_volume \
    "${resource_prefix}-seed43-khepri" "$base_image" \
    "${resource_prefix}-transition43-khepri"
run_entrypoint_case reach \
    "${resource_prefix}-transition43-khepri" "$base_image" \
    "${resource_prefix}-transition43-khepri" unattested 4.3 transition
seed_safe_khepri_volume \
    "${resource_prefix}-seed43-wrong-image" "$upgrade_image" \
    "${resource_prefix}-transition43-wrong-image"
run_entrypoint_case reject \
    "${resource_prefix}-transition43-wrong-image" "$upgrade_image" \
    "${resource_prefix}-transition43-wrong-image" unattested 4.3 transition

run_entrypoint_case reject \
    "${resource_prefix}-steady43-no-witness" "$base_image" \
    "${resource_prefix}-steady43-final" 4.3 unset steady
initialize_final_witness \
    "${resource_prefix}-final-witness-init" "${resource_prefix}-steady43-final"
assert_final_witness_v2 "${resource_prefix}-steady43-final"
run_entrypoint_case reach \
    "${resource_prefix}-steady43-final" "$base_image" \
    "${resource_prefix}-steady43-final" 4.3 unset steady

# A version-1 final witness did not serialize node_host. Keep it compatible
# only when the retained nonempty Khepri tree proves the configured node.
seed_safe_khepri_volume \
    "${resource_prefix}-seed-legacy-v1-khepri" "$base_image" \
    "${resource_prefix}-legacy-v1-khepri"
seed_final_witness \
    "${resource_prefix}-seed-legacy-v1-khepri-witness" \
    "${resource_prefix}-legacy-v1-khepri" legacy-exact
run_witness_creation_case accept \
    "${resource_prefix}-verify-legacy-v1-khepri" \
    "${resource_prefix}-legacy-v1-khepri" verify
seed_safe_khepri_volume \
    "${resource_prefix}-seed-legacy-v1-wrong-host" "$base_image" \
    "${resource_prefix}-legacy-v1-wrong-host"
seed_final_witness \
    "${resource_prefix}-seed-legacy-v1-wrong-host-witness" \
    "${resource_prefix}-legacy-v1-wrong-host" legacy-exact
run_witness_creation_case reject \
    "${resource_prefix}-verify-legacy-v1-wrong-host" \
    "${resource_prefix}-legacy-v1-wrong-host" verify \
    'RabbitMQ data contains a foreign or stale node-associated entry.' \
    d34db33fcafe

# The normal first-start initializer may attest only an empty volume. A
# nonempty Khepri tree needs the wrapper's post-4.3-attestation finalizer.
seed_safe_legacy_volume \
    "${resource_prefix}-seed-init-legacy" "$base_image" \
    "${resource_prefix}-init-legacy"
run_witness_creation_case reject \
    "${resource_prefix}-init-legacy" "${resource_prefix}-init-legacy" init \
    'RabbitMQ fresh initialization refuses a nonempty data volume without a witness.'
seed_pending_witness \
    "${resource_prefix}-seed-init-zero-pending" \
    "${resource_prefix}-init-zero-pending" zero
run_witness_creation_case accept \
    "${resource_prefix}-init-zero-pending" \
    "${resource_prefix}-init-zero-pending" init
seed_temporary_witness \
    "${resource_prefix}-seed-init-orphan-temp" \
    "${resource_prefix}-init-orphan-temp" partial
run_witness_creation_case accept \
    "${resource_prefix}-init-orphan-temp" \
    "${resource_prefix}-init-orphan-temp" init
assert_no_witness_staging_residue "${resource_prefix}-init-orphan-temp"
seed_safe_khepri_volume \
    "${resource_prefix}-seed-finalize-legacy" "$base_image" \
    "${resource_prefix}-finalize-legacy"
run_witness_creation_case accept \
    "${resource_prefix}-finalize-legacy" "${resource_prefix}-finalize-legacy" \
    finalize-transition
seed_safe_khepri_volume \
    "${resource_prefix}-seed-finalize-partial-legacy" "$base_image" \
    "${resource_prefix}-finalize-partial-pending"
seed_pending_witness \
    "${resource_prefix}-seed-finalize-partial-pending" \
    "${resource_prefix}-finalize-partial-pending" partial
run_witness_creation_case accept \
    "${resource_prefix}-finalize-partial-pending" \
    "${resource_prefix}-finalize-partial-pending" finalize-transition
seed_safe_khepri_volume \
    "${resource_prefix}-seed-finalize-existing-legacy" "$base_image" \
    "${resource_prefix}-finalize-existing-final"
seed_final_witness \
    "${resource_prefix}-seed-finalize-existing-final" \
    "${resource_prefix}-finalize-existing-final" exact
run_witness_creation_case accept \
    "${resource_prefix}-finalize-existing-final" \
    "${resource_prefix}-finalize-existing-final" finalize-transition
initialize_final_witness \
    "${resource_prefix}-init-finalize-final-only" \
    "${resource_prefix}-finalize-final-only"
run_witness_creation_case reject \
    "${resource_prefix}-finalize-final-only" \
    "${resource_prefix}-finalize-final-only" finalize-transition \
    'RabbitMQ transition finalization refuses an empty data volume.'

# Crash recovery may only promote an exact pending witness or reflush an exact
# final witness. Absence, malformed bytes, and ambiguous final+pending state
# must all remain fail closed in the actual image/runtime boundary.
run_resume_case reject \
    "${resource_prefix}-resume-absent" "${resource_prefix}-resume-absent" \
    'RabbitMQ pending volume identity witness is missing.'
seed_pending_witness \
    "${resource_prefix}-seed-resume-pending" \
    "${resource_prefix}-resume-pending" exact
run_resume_case accept \
    "${resource_prefix}-resume-pending" "${resource_prefix}-resume-pending"
seed_pending_witness \
    "${resource_prefix}-seed-resume-malformed" \
    "${resource_prefix}-resume-malformed" malformed
run_resume_case reject \
    "${resource_prefix}-resume-malformed" "${resource_prefix}-resume-malformed" \
    'RabbitMQ pending volume identity witness is invalid.'
seed_pending_witness \
    "${resource_prefix}-seed-pending-missing-newline" \
    "${resource_prefix}-pending-missing-newline" missing-newline
run_resume_case reject \
    "${resource_prefix}-resume-pending-missing-newline" \
    "${resource_prefix}-pending-missing-newline" \
    'RabbitMQ pending volume identity witness is invalid.'
seed_pending_witness \
    "${resource_prefix}-seed-pending-multiple-newlines" \
    "${resource_prefix}-pending-multiple-newlines" multiple-newlines
run_resume_case reject \
    "${resource_prefix}-resume-pending-multiple-newlines" \
    "${resource_prefix}-pending-multiple-newlines" \
    'RabbitMQ pending volume identity witness is invalid.'
seed_final_witness \
    "${resource_prefix}-seed-final-missing-newline" \
    "${resource_prefix}-final-missing-newline" missing-newline
run_witness_creation_case reject \
    "${resource_prefix}-verify-final-missing-newline" \
    "${resource_prefix}-final-missing-newline" verify \
    'RabbitMQ volume identity witness belongs to another installation, generation, or node host.'
seed_final_witness \
    "${resource_prefix}-seed-final-multiple-newlines" \
    "${resource_prefix}-final-multiple-newlines" multiple-newlines
run_witness_creation_case reject \
    "${resource_prefix}-verify-final-multiple-newlines" \
    "${resource_prefix}-final-multiple-newlines" verify \
    'RabbitMQ volume identity witness belongs to another installation, generation, or node host.'
initialize_final_witness \
    "${resource_prefix}-init-resume-final" "${resource_prefix}-resume-final"
run_resume_case accept \
    "${resource_prefix}-resume-final" "${resource_prefix}-resume-final"
initialize_final_witness \
    "${resource_prefix}-init-resume-both" "${resource_prefix}-resume-both"
seed_pending_witness \
    "${resource_prefix}-seed-resume-both-pending" \
    "${resource_prefix}-resume-both" exact
run_resume_case reject \
    "${resource_prefix}-resume-both" "${resource_prefix}-resume-both" \
    'RabbitMQ volume identity has both final and pending records.'

printf '%s\n' 'Real RabbitMQ entrypoint transition boundary verified.'
