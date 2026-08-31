#!/bin/sh
# Reconcile and prove the dedicated broker's users, permissions and fixed topology.
set -eu
umask 077

node="${RABBITMQ_NODENAME:-}"
node_host="${BACKUPSHEEP_RABBITMQ_NODE_HOST:-}"
case "$node_host" in
    rabbitmq|[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) printf '%s\n' 'RabbitMQ durable node host is invalid.' >&2; exit 1 ;;
esac
[ "$node" = "rabbit@${node_host}" ] \
    || { printf '%s\n' 'RabbitMQ durable node name does not match its configured host.' >&2; exit 1; }
vhost='backupsheep'
queue_policy='backupsheep-queue-bounds-v1'
queue_pattern='^(default|cloud|database|files|storage|logs)$'
queue_max_messages='10000'
queue_max_bytes='67108864'
ctl() {
    /opt/rabbitmq/sbin/rabbitmqctl -q -n "$node" -t 30 "$@"
}

read_secret() {
    secret_file="/run/secrets/rabbitmq_${1}_password"
    [ -f "$secret_file" ] && [ ! -L "$secret_file" ] || exit 1
    secret_value="$(cat "$secret_file")"
    [ "${#secret_value}" -ge 32 ] || exit 1
    printf '%s' "$secret_value"
}

password_hash() (
    set -eu
    cleartext="$1"
    salt_file=''
    digest_file=''
    trap '[ -z "$salt_file" ] || rm -f -- "$salt_file" || :; [ -z "$digest_file" ] || rm -f -- "$digest_file" || :' 0
    salt_file="$(mktemp /tmp/backupsheep-rabbit-salt.XXXXXX)"
    digest_file="$(mktemp /tmp/backupsheep-rabbit-digest.XXXXXX)"
    # RabbitMQ's SHA-256 credential format is base64(salt ||
    # sha256(salt || password)). Compute it through stdin so plaintext never
    # appears in rabbitmqctl/openssl argv, the environment, definitions, or logs.
    /opt/openssl/bin/openssl rand 4 >"$salt_file"
    {
        cat "$salt_file"
        printf '%s' "$cleartext"
    } | /opt/openssl/bin/openssl dgst -sha256 -binary >"$digest_file"
    cleartext=''
    {
        cat "$salt_file"
        cat "$digest_file"
    } | base64 | tr -d '\n'
)

stored_password_hash() {
    lookup_user="$1"
    output="$(
        ctl eval "{ok, U} = rabbit_auth_backend_internal:lookup_user(<<\"${lookup_user}\">>), base64:encode(element(3, U))."
    )"
    printf '%s\n' "$output" | sed -n 's/^<<"\([A-Za-z0-9+/=]*\)">>$/\1/p'
}

stored_password_algorithm() {
    lookup_user="$1"
    ctl eval "{ok, U} = rabbit_auth_backend_internal:lookup_user(<<\"${lookup_user}\">>), element(5, U)."
}

user_was_preclassified() {
    printf '%s\n' "$actual_users" | grep -Fxq "$1"
}

delete_if_present() {
    candidate="$1"
    if user_was_preclassified "$candidate"; then
        ctl delete_user "$candidate" >/dev/null
    fi
}

case "${RABBITMQ_LEGACY_USER:-backupsheep}" in
    ''|*[!a-z0-9_]*|????????????????????????????????????????????????????????????????*)
        printf '%s\n' 'Legacy RabbitMQ username is invalid.' >&2
        exit 1
        ;;
esac

until ctl await_startup >/dev/null 2>&1; do
    sleep 1
done

roles='bootstrap app preflight beat cloud database files storage logs'
tab="$(printf '\t')"
legacy_user="${RABBITMQ_LEGACY_USER:-backupsheep}"
expected_users="$(printf '%s\n' $roles | sed 's/^/backupsheep_/' | sort)"

global_parameter_semantics() {
    ctl eval 'case {lists:sort([proplists:get_value(name, P) || P <- rabbit_runtime_parameters:list_global()]), rabbit_runtime_parameters:value_global(cluster_tags), rabbit_runtime_parameters:value_global(internal_cluster_id), rabbit_runtime_parameters:lookup_global(imported_definition_hash_value)} of {[cluster_tags, internal_cluster_id], [], <<"rabbitmq-cluster-id-", Id:22/binary>>, not_found} -> case re:run(Id, <<"^[A-Za-z0-9_-]{22}$">>, [{capture, none}]) of match -> true; nomatch -> false end; _ -> false end.'
}

validate_vhost_metadata() {
    awk -F '\t' -v product="$vhost" -v expected_node="$node" '
        NF != 7 { exit 1 }
        $1 == product {
            if (seen_product++ || $2 != "false" || $3 != "classic" ||
                $4 != "" || $5 != "[]" || $6 != "false" ||
                $7 != "[{" expected_node ", running}]") exit 1
            next
        }
        $1 == "/" {
            if (seen_default++ || $2 != "false" || $3 != "classic" ||
                $4 != "Default virtual host" || $5 != "[]" || $6 != "false" ||
                $7 != "[{" expected_node ", running}]") exit 1
            next
        }
        { exit 1 }
        END {
            if (seen_product != 1 || seen_default > 1 ||
                NR != seen_product + seen_default) exit 1
        }
    '
}

parse_user_inventory() {
    awk -F '\t' '
        NF != 2 || $1 !~ /^[a-z0-9_]+$/ || seen[$1]++ { exit 1 }
        { print $1 }
    '
}

reported_user_count() {
    ctl eval 'length(rabbit_auth_backend_internal:list_users()).'
}

known_user_exists() {
    lookup_user="$1"
    ctl eval "case rabbit_auth_backend_internal:lookup_user(<<\"${lookup_user}\">>) of {ok, _} -> true; {error, not_found} -> false end."
}

validate_reviewed_exchanges() {
    case "${1:-}" in
        product|default) exchange_inventory="$1" ;;
        *) return 1 ;;
    esac
    awk -F '\t' -v exchange_inventory="$exchange_inventory" '
        function reviewed_exchange(value) {
            return value ~ /^(default|cloud|database|files|storage|logs)$/ ||
                value ~ /^backupsheep\.(default|cloud|database|files|storage|logs)$/
        }
        function accept_builtin(key, expected_type, expected_internal) {
            if (seen_builtin[key]++ || $2 != expected_type || $3 != "true" ||
                $4 != "false" || $5 != expected_internal || $6 != "[]") exit 1
        }
        NF != 6 { exit 1 }
        $1 == "" { accept_builtin("default", "direct", "false"); next }
        $1 == "amq.direct" { accept_builtin($1, "direct", "false"); next }
        $1 == "amq.fanout" { accept_builtin($1, "fanout", "false"); next }
        $1 == "amq.headers" { accept_builtin($1, "headers", "false"); next }
        $1 == "amq.match" { accept_builtin($1, "headers", "false"); next }
        $1 == "amq.rabbitmq.log" {
            if (exchange_inventory != "default") exit 1
            accept_builtin($1, "topic", "true"); next
        }
        $1 == "amq.rabbitmq.trace" { accept_builtin($1, "topic", "true"); next }
        $1 == "amq.topic" { accept_builtin($1, "topic", "false"); next }
        exchange_inventory != "product" || !reviewed_exchange($1) ||
            $2 != "direct" || $3 != "true" ||
            $4 != "false" || $5 != "false" || $6 != "[]" { exit 1 }
        END {
            split("default amq.direct amq.fanout amq.headers amq.match amq.rabbitmq.trace amq.topic", names, " ")
            for (i in names) if (seen_builtin[names[i]] != 1) exit 1
            if (exchange_inventory == "default" &&
                seen_builtin["amq.rabbitmq.log"] != 1) exit 1
            if (exchange_inventory == "product" &&
                seen_builtin["amq.rabbitmq.log"] != 0) exit 1
        }
    '
}

validate_reviewed_bindings() {
    awk -F '\t' '
        function reviewed_queue(value) {
            return value ~ /^(default|cloud|database|files|storage|logs)$/
        }
        NF != 5 || !reviewed_queue($2) || $3 != "queue" ||
            $4 != $2 || $5 != "[]" { exit 1 }
        $1 != "" && $1 != $2 && $1 != "backupsheep." $2 { exit 1 }
    '
}

expected_queue_inventory="$({
    for queue in default cloud database files storage logs; do
        printf '%s\tclassic\ttrue\tfalse\tfalse\t[{"x-queue-type","classic"}]\n' "$queue"
    done
} | sort)"

validate_reviewed_queue_policy() {
    awk -F '\t' -v expected_vhost="$vhost" -v expected_name="$queue_policy" \
        -v expected_pattern="$queue_pattern" '
        NF != 6 || $1 != expected_vhost || $2 != expected_name ||
            $3 != expected_pattern || $4 != "queues" || $6 != "100" { exit 1 }
        {
            definition = $5
            if (gsub(/"max-length":10000/, "", definition) != 1) exit 1
            if (gsub(/"max-length-bytes":67108864/, "", definition) != 1) exit 1
            if (gsub(/"overflow":"reject-publish"/, "", definition) != 1) exit 1
            gsub(/[{},]/, "", definition)
            if (definition != "") exit 1
        }
    '
}

# Complete every read-only classification before rotating credentials. The
# default vhost is retained but inaccessible and must remain exactly empty.
# Definitions import creates the dedicated vhost and fixed topology;
# an unexpected tenant, identity, queue, exchange, binding, policy or topic grant
# must fail without partially mutating the broker.
raw_listed_vhosts="$(ctl list_vhosts name --silent)" \
    || { printf '%s\n' 'RabbitMQ virtual-host inventory failed.' >&2; exit 1; }
listed_vhosts="$(printf '%s\n' "$raw_listed_vhosts" | sort)"
expected_vhosts_with_default="$(printf '/\n%s\n' "$vhost")"
case "$listed_vhosts" in
    "$vhost"|"$expected_vhosts_with_default") ;;
    *) printf '%s\n' 'RabbitMQ contains an unexpected virtual host.' >&2; exit 1 ;;
esac
preexisting_vhost_metadata="$(
    ctl list_vhosts name tracing default_queue_type description tags protected_from_deletion cluster_state --silent
)" || { printf '%s\n' 'RabbitMQ virtual-host metadata inventory failed.' >&2; exit 1; }
printf '%s\n' "$preexisting_vhost_metadata" | validate_vhost_metadata \
    || { printf '%s\n' 'RabbitMQ virtual-host metadata drifted.' >&2; exit 1; }
preexisting_global_parameter_semantics="$(global_parameter_semantics)" \
    || { printf '%s\n' 'RabbitMQ global runtime-parameter inventory failed.' >&2; exit 1; }
[ "$preexisting_global_parameter_semantics" = true ] \
    || { printf '%s\n' 'RabbitMQ global runtime-parameter drift detected.' >&2; exit 1; }
preexisting_internal_cluster_id="$(
    ctl eval 'rabbit_runtime_parameters:value_global(internal_cluster_id).'
)" || { printf '%s\n' 'RabbitMQ internal cluster-ID inventory failed.' >&2; exit 1; }
preexisting_product_parameters="$(ctl -p "$vhost" list_parameters --no-table-headers)" \
    || { printf '%s\n' 'RabbitMQ product runtime-parameter inventory failed.' >&2; exit 1; }
[ -z "$preexisting_product_parameters" ] \
    || { printf '%s\n' 'RabbitMQ product runtime parameters are not allowed.' >&2; exit 1; }
preexisting_user_limits="$(ctl list_user_limits --global --no-table-headers)" \
    || { printf '%s\n' 'RabbitMQ user-limit inventory failed.' >&2; exit 1; }
[ -z "$preexisting_user_limits" ] \
    || { printf '%s\n' 'RabbitMQ user limits are not allowed.' >&2; exit 1; }
preexisting_global_vhost_limits="$(ctl list_vhost_limits --global --no-table-headers)" \
    || { printf '%s\n' 'RabbitMQ global virtual-host limit inventory failed.' >&2; exit 1; }
[ -z "$preexisting_global_vhost_limits" ] \
    || { printf '%s\n' 'RabbitMQ global virtual-host limits are not allowed.' >&2; exit 1; }
preexisting_product_vhost_limits="$(ctl list_vhost_limits --vhost "$vhost" --no-table-headers)" \
    || { printf '%s\n' 'RabbitMQ product virtual-host limit inventory failed.' >&2; exit 1; }
[ -z "$preexisting_product_vhost_limits" ] \
    || { printf '%s\n' 'RabbitMQ product virtual-host limits are not allowed.' >&2; exit 1; }

if printf '%s\n' "$listed_vhosts" | grep -Fxq '/'; then
    default_parameters="$(ctl -p / list_parameters --no-table-headers)" \
        || { printf '%s\n' 'RabbitMQ default runtime-parameter inventory failed.' >&2; exit 1; }
    [ -z "$default_parameters" ] \
        || { printf '%s\n' 'RabbitMQ default runtime parameters are not allowed.' >&2; exit 1; }
    default_vhost_limits="$(ctl list_vhost_limits --vhost / --no-table-headers)" \
        || { printf '%s\n' 'RabbitMQ default virtual-host limit inventory failed.' >&2; exit 1; }
    [ -z "$default_vhost_limits" ] \
        || { printf '%s\n' 'RabbitMQ default virtual-host limits are not allowed.' >&2; exit 1; }
    default_queues="$(ctl -p / list_queues name type durable auto_delete exclusive arguments --silent)" \
        || { printf '%s\n' 'RabbitMQ default virtual-host queue inventory failed.' >&2; exit 1; }
    [ -z "$default_queues" ] \
        || { printf '%s\n' 'RabbitMQ default virtual host contains a queue.' >&2; exit 1; }
    default_exchanges="$(ctl -p / list_exchanges name type durable auto_delete internal arguments --silent)" \
        || { printf '%s\n' 'RabbitMQ default virtual-host exchange inventory failed.' >&2; exit 1; }
    printf '%s\n' "$default_exchanges" | validate_reviewed_exchanges default \
        || { printf '%s\n' 'RabbitMQ default virtual host contains a custom or malformed exchange.' >&2; exit 1; }
    default_bindings="$(ctl -p / list_bindings source_name destination_name destination_kind routing_key arguments --silent)" \
        || { printf '%s\n' 'RabbitMQ default virtual-host binding inventory failed.' >&2; exit 1; }
    [ -z "$default_bindings" ] \
        || { printf '%s\n' 'RabbitMQ default virtual host contains a binding.' >&2; exit 1; }
    default_policies="$(ctl -p / list_policies --silent)" \
        || { printf '%s\n' 'RabbitMQ default virtual-host policy inventory failed.' >&2; exit 1; }
    [ -z "$default_policies" ] \
        || { printf '%s\n' 'RabbitMQ default virtual host contains a policy.' >&2; exit 1; }
    default_operator_policies="$(ctl -p / list_operator_policies --silent)" \
        || { printf '%s\n' 'RabbitMQ default virtual-host operator-policy inventory failed.' >&2; exit 1; }
    [ -z "$default_operator_policies" ] \
        || { printf '%s\n' 'RabbitMQ default virtual host contains an operator policy.' >&2; exit 1; }
    default_topic_permissions="$(ctl -p / list_topic_permissions --no-table-headers)" \
        || { printf '%s\n' 'RabbitMQ default virtual-host topic-permission inventory failed.' >&2; exit 1; }
    [ -z "$default_topic_permissions" ] \
        || { printf '%s\n' 'RabbitMQ default virtual host contains a topic permission.' >&2; exit 1; }
fi

listed_users="$(ctl list_users --no-table-headers)" \
    || { printf '%s\n' 'RabbitMQ user inventory failed.' >&2; exit 1; }
actual_users="$(printf '%s\n' "$listed_users" | parse_user_inventory)" \
    || { printf '%s\n' 'RabbitMQ contains an unexpected user.' >&2; exit 1; }
parsed_user_count="$(printf '%s\n' "$actual_users" | awk 'NF { count++ } END { print count + 0 }')"
actual_user_count="$(reported_user_count)" \
    || { printf '%s\n' 'RabbitMQ exact user-count inventory failed.' >&2; exit 1; }
case "$actual_user_count" in ''|*[!0-9]*) printf '%s\n' 'RabbitMQ exact user count is malformed.' >&2; exit 1 ;; esac
[ "$parsed_user_count" = "$actual_user_count" ] \
    || { printf '%s\n' 'RabbitMQ user inventory contains record-boundary injection.' >&2; exit 1; }
actual_users="$(printf '%s\n' "$actual_users" | sort)"
allowed_users="$({ printf '%s\n' "$expected_users"; printf '%s\n' guest "$legacy_user"; } | sort -u)"
known_actual_users=''
for candidate in $allowed_users; do
    candidate_exists="$(known_user_exists "$candidate")" \
        || { printf '%s\n' 'RabbitMQ exact user-membership inventory failed.' >&2; exit 1; }
    case "$candidate_exists" in
        true) known_actual_users="${known_actual_users}${candidate}\n" ;;
        false) ;;
        *) printf '%s\n' 'RabbitMQ exact user-membership result is malformed.' >&2; exit 1 ;;
    esac
done
known_actual_users="$(printf '%b' "$known_actual_users" | sort)"
[ "$known_actual_users" = "$actual_users" ] \
    || { printf '%s\n' 'RabbitMQ contains an unexpected user.' >&2; exit 1; }
preexisting_connections="$(ctl list_connections pid user vhost --silent)" \
    || { printf '%s\n' 'RabbitMQ connection inventory failed.' >&2; exit 1; }
[ -z "$preexisting_connections" ] \
    || { printf '%s\n' 'RabbitMQ provisioning requires a quiescent broker with zero client connections.' >&2; exit 1; }

raw_preexisting_queues="$(ctl -p "$vhost" list_queues name type durable auto_delete exclusive arguments --silent)" \
    || { printf '%s\n' 'RabbitMQ queue inventory failed.' >&2; exit 1; }
preexisting_queues="$(printf '%s\n' "$raw_preexisting_queues" | sort)"
[ "$preexisting_queues" = "$expected_queue_inventory" ] \
    || { printf '%s\n' 'RabbitMQ queue identity, durability, lifecycle, exclusivity, or arguments drifted.' >&2; exit 1; }
preexisting_exchanges="$(ctl -p "$vhost" list_exchanges name type durable auto_delete internal arguments --silent)" \
    || { printf '%s\n' 'RabbitMQ exchange inventory failed.' >&2; exit 1; }
printf '%s\n' "$preexisting_exchanges" | validate_reviewed_exchanges product \
    || { printf '%s\n' 'RabbitMQ contains an unexpected exchange or exchange metadata drift.' >&2; exit 1; }
preexisting_bindings="$(ctl -p "$vhost" list_bindings source_name destination_name destination_kind routing_key arguments --silent)" \
    || { printf '%s\n' 'RabbitMQ binding inventory failed.' >&2; exit 1; }
printf '%s\n' "$preexisting_bindings" | validate_reviewed_bindings \
    || { printf '%s\n' 'RabbitMQ contains an unexpected binding.' >&2; exit 1; }
for queue in default cloud database files storage logs; do
    printf '%s\n' "$preexisting_exchanges" \
        | grep -Fqx "backupsheep.${queue}${tab}direct${tab}true${tab}false${tab}false${tab}[]" \
        || { printf '%s\n' "RabbitMQ exchange backupsheep.${queue} is missing." >&2; exit 1; }
    printf '%s\n' "$preexisting_bindings" \
        | grep -Fqx "backupsheep.${queue}${tab}${queue}${tab}queue${tab}${queue}${tab}[]" \
        || { printf '%s\n' "RabbitMQ binding for ${queue} is missing." >&2; exit 1; }
done
preexisting_policies="$(ctl -p "$vhost" list_policies --silent)" \
    || { printf '%s\n' 'RabbitMQ policy inventory failed.' >&2; exit 1; }
preexisting_policy_names="$(printf '%s\n' "$preexisting_policies" | awk 'NF {print $2}' | sort)"
case "$preexisting_policy_names" in
    ''|"$queue_policy") ;;
    *) printf '%s\n' 'RabbitMQ contains an unexpected queue policy.' >&2; exit 1 ;;
esac
if [ -n "$preexisting_policies" ]; then
    printf '%s\n' "$preexisting_policies" | validate_reviewed_queue_policy \
        || { printf '%s\n' 'RabbitMQ existing queue policy metadata drifted.' >&2; exit 1; }
fi
preexisting_operator_policies="$(ctl -p "$vhost" list_operator_policies --silent)" \
    || { printf '%s\n' 'RabbitMQ operator-policy inventory failed.' >&2; exit 1; }
[ -z "$preexisting_operator_policies" ] \
    || { printf '%s\n' 'RabbitMQ operator policies are not allowed.' >&2; exit 1; }
preexisting_topic_permissions="$(ctl -p "$vhost" list_topic_permissions --no-table-headers)" \
    || { printf '%s\n' 'RabbitMQ topic-permission inventory failed.' >&2; exit 1; }
[ -z "$preexisting_topic_permissions" ] \
    || { printf '%s\n' 'RabbitMQ topic-permission drift detected.' >&2; exit 1; }

# Read every secret and exercise the complete password-hash toolchain before
# replacing any credential. This keeps a missing
# late-role secret, tmpfs exhaustion, or crypto failure strictly pre-mutation.
prepared_password_hashes=''
for role in $roles; do
    password="$(read_secret "$role")"
    hash="$(password_hash "$password")"
    password=''
    case "$hash" in ''|*[!A-Za-z0-9+/=]*) exit 1 ;; esac
    prepared_password_hashes="${prepared_password_hashes}${role}${tab}${hash}
"
    hash=''
done

actual_vhosts="$(ctl list_vhosts name --silent)" \
    || { printf '%s\n' 'RabbitMQ post-mutation virtual-host inventory failed.' >&2; exit 1; }
actual_vhosts="$(printf '%s\n' "$actual_vhosts" | sort)"
case "$actual_vhosts" in
    "$vhost"|"$expected_vhosts_with_default") ;;
    *) printf '%s\n' 'RabbitMQ contains an unexpected virtual host.' >&2; exit 1 ;;
esac

for role in $roles; do
    delete_if_present "backupsheep_${role}"
done
delete_if_present guest
case "$legacy_user" in
    guest|backupsheep_bootstrap|backupsheep_app|backupsheep_preflight|\
    backupsheep_beat|backupsheep_cloud|backupsheep_database|backupsheep_files|\
    backupsheep_storage|backupsheep_logs) ;;
    *) delete_if_present "$legacy_user" ;;
esac

# A legacy client can connect after the initial quiescence check but before its
# credential is deleted. Close every such already-authenticated session, then
# prove the node is empty before publishing the replacement identities.
ctl close_all_connections --global --per-connection-delay 0 \
    'BackupSheep provisioning credential rotation' >/dev/null
remaining_connections="$(ctl list_connections pid user vhost --silent)" \
    || { printf '%s\n' 'RabbitMQ post-rotation connection inventory failed.' >&2; exit 1; }
[ -z "$remaining_connections" ] \
    || { printf '%s\n' 'RabbitMQ retained a client connection after credential rotation.' >&2; exit 1; }

for role in $roles; do
    user="backupsheep_${role}"
    hash="$(printf '%s' "$prepared_password_hashes" \
        | awk -F '\t' -v expected="$role" '$1 == expected { print $2 }')"
    case "$hash" in ''|*[!A-Za-z0-9+/=]*) exit 1 ;; esac
    ctl add_user "$user" "$hash" --pre-hashed-password >/dev/null
    [ "$(stored_password_hash "$user")" = "$hash" ] \
        || { printf '%s\n' "RabbitMQ password hash drifted for ${user}." >&2; exit 1; }
    [ "$(stored_password_algorithm "$user")" = 'rabbit_password_hashing_sha256' ] \
        || { printf '%s\n' "RabbitMQ password algorithm drifted for ${user}." >&2; exit 1; }
    hash=''
done
prepared_password_hashes=''

all_exchanges='^(backupsheep\.(default|cloud|database|files|storage|logs))$'
empty_permission='^$'
cloud_exchanges='^(backupsheep\.(default|cloud|database|files|logs))$'
database_exchanges='^(backupsheep\.(database|storage|logs))$'
files_exchanges='^(backupsheep\.(files|storage|logs))$'
storage_exchanges='^(backupsheep\.(database|files|storage|logs))$'
logs_exchange='^backupsheep\.logs$'
ctl set_permissions -p "$vhost" backupsheep_bootstrap '^$' '^$' '^$' >/dev/null
ctl set_permissions -p "$vhost" backupsheep_preflight '^$' '^$' '^$' >/dev/null
ctl set_permissions -p "$vhost" backupsheep_app '^$' "$all_exchanges" '^$' >/dev/null
ctl set_permissions -p "$vhost" backupsheep_beat '^$' "$all_exchanges" '^$' >/dev/null
ctl set_permissions -p "$vhost" backupsheep_cloud '^$' \
    "$cloud_exchanges" '^(default|cloud)$' >/dev/null
ctl set_permissions -p "$vhost" backupsheep_database '^$' \
    "$database_exchanges" '^database$' >/dev/null
ctl set_permissions -p "$vhost" backupsheep_files '^$' \
    "$files_exchanges" '^files$' >/dev/null
ctl set_permissions -p "$vhost" backupsheep_storage '^$' \
    "$storage_exchanges" '^storage$' >/dev/null
ctl set_permissions -p "$vhost" backupsheep_logs '^$' "$logs_exchange" '^logs$' >/dev/null

listed_users="$(ctl list_users --no-table-headers)" \
    || { printf '%s\n' 'RabbitMQ post-mutation user inventory failed.' >&2; exit 1; }
actual_users="$(printf '%s\n' "$listed_users" | awk -F '\t' '
    NF != 2 || $1 !~ /^[a-z0-9_]+$/ || $2 != "[]" || seen[$1]++ { exit 1 }
    { print $1 }
')" || { printf '%s\n' 'RabbitMQ post-mutation user inventory is unsafe or ambiguous.' >&2; exit 1; }
parsed_user_count="$(printf '%s\n' "$actual_users" | awk 'NF { count++ } END { print count + 0 }')"
actual_user_count="$(reported_user_count)" \
    || { printf '%s\n' 'RabbitMQ post-mutation exact user-count inventory failed.' >&2; exit 1; }
case "$actual_user_count" in ''|*[!0-9]*) printf '%s\n' 'RabbitMQ exact user count is malformed.' >&2; exit 1 ;; esac
[ "$parsed_user_count" = "$actual_user_count" ] \
    || { printf '%s\n' 'RabbitMQ post-mutation user inventory contains record-boundary injection.' >&2; exit 1; }
actual_users="$(printf '%s\n' "$actual_users" | sort)"
[ "$actual_users" = "$expected_users" ] \
    || { printf '%s\n' 'RabbitMQ user reconciliation drifted.' >&2; exit 1; }
for user in $expected_users; do
    [ "$(known_user_exists "$user")" = true ] \
        || { printf '%s\n' 'RabbitMQ exact user reconciliation drifted.' >&2; exit 1; }
done

raw_actual_queues="$(ctl -p "$vhost" list_queues name type durable auto_delete exclusive arguments --silent)" \
    || { printf '%s\n' 'RabbitMQ post-mutation queue inventory failed.' >&2; exit 1; }
actual_queues="$(printf '%s\n' "$raw_actual_queues" | sort)"
[ "$actual_queues" = "$expected_queue_inventory" ] \
    || { printf '%s\n' 'RabbitMQ queue identity, durability, lifecycle, exclusivity, or arguments drifted.' >&2; exit 1; }

listed_exchanges="$(ctl -p "$vhost" list_exchanges name type durable auto_delete internal arguments --silent)" \
    || { printf '%s\n' 'RabbitMQ post-mutation exchange inventory failed.' >&2; exit 1; }
listed_bindings="$(ctl -p "$vhost" list_bindings source_name destination_name destination_kind routing_key arguments --silent)" \
    || { printf '%s\n' 'RabbitMQ post-mutation binding inventory failed.' >&2; exit 1; }
printf '%s\n' "$listed_bindings" | validate_reviewed_bindings \
    || { printf '%s\n' 'RabbitMQ contains an unexpected binding.' >&2; exit 1; }
for queue in default cloud database files storage logs; do
    printf '%s\n' "$listed_exchanges" \
        | grep -Fqx "backupsheep.${queue}${tab}direct${tab}true${tab}false${tab}false${tab}[]" \
        || { printf '%s\n' "RabbitMQ exchange backupsheep.${queue} is missing." >&2; exit 1; }
    printf '%s\n' "$listed_bindings" \
        | grep -Fqx "backupsheep.${queue}${tab}${queue}${tab}queue${tab}${queue}${tab}[]" \
        || { printf '%s\n' "RabbitMQ binding for ${queue} is missing." >&2; exit 1; }
done

# A policy upgrades existing durable queues without deleting/redeclaring them. Every
# bounded queue rejects new publishes once either limit is reached; dropping the head
# would silently destroy backup/restore intent and is therefore forbidden.
ctl set_policy -p "$vhost" "$queue_policy" "$queue_pattern" \
    "{\"max-length\":${queue_max_messages},\"max-length-bytes\":${queue_max_bytes},\"overflow\":\"reject-publish\"}" \
    --priority 100 --apply-to queues >/dev/null
listed_policies="$(ctl -p "$vhost" list_policies --silent)" \
    || { printf '%s\n' 'RabbitMQ post-mutation policy inventory failed.' >&2; exit 1; }
actual_policy_names="$(printf '%s\n' "$listed_policies" | awk '{print $2}' | sort)"
[ "$actual_policy_names" = "$queue_policy" ] \
    || { printf '%s\n' 'RabbitMQ contains an unexpected queue policy.' >&2; exit 1; }
printf '%s\n' "$listed_policies" | validate_reviewed_queue_policy \
    || { printf '%s\n' 'RabbitMQ queue policy metadata drifted.' >&2; exit 1; }
listed_operator_policies="$(ctl -p "$vhost" list_operator_policies --silent)" \
    || { printf '%s\n' 'RabbitMQ post-mutation operator-policy inventory failed.' >&2; exit 1; }
[ -z "$listed_operator_policies" ] \
    || { printf '%s\n' 'RabbitMQ operator policies are not allowed.' >&2; exit 1; }
printf '%s\n' "$listed_policies" | grep -Fq "$queue_pattern" \
    || { printf '%s\n' 'RabbitMQ queue-bound policy pattern drifted.' >&2; exit 1; }
printf '%s\n' "$listed_policies" | grep -Fq "\"max-length\":${queue_max_messages}" \
    || { printf '%s\n' 'RabbitMQ queue message bound drifted.' >&2; exit 1; }
printf '%s\n' "$listed_policies" | grep -Fq "\"max-length-bytes\":${queue_max_bytes}" \
    || { printf '%s\n' 'RabbitMQ queue byte bound drifted.' >&2; exit 1; }
printf '%s\n' "$listed_policies" | grep -Fq '"overflow":"reject-publish"' \
    || { printf '%s\n' 'RabbitMQ overflow behavior is not reject-publish.' >&2; exit 1; }

effective_queues="$(
    ctl -p "$vhost" list_queues name policy effective_policy_definition --silent
)"
printf '%s\n' "$effective_queues" | while IFS="$tab" read -r queue policy definition; do
    [ -n "$queue" ] || continue
    [ "$policy" = "$queue_policy" ] \
        || { printf '%s\n' "RabbitMQ queue ${queue} has no capacity policy." >&2; exit 1; }
    printf '%s\n' "$definition" | grep -Fq "<<\"max-length\">>, ${queue_max_messages}" \
        || { printf '%s\n' "RabbitMQ queue ${queue} lacks its message bound." >&2; exit 1; }
    printf '%s\n' "$definition" | grep -Fq "<<\"max-length-bytes\">>, ${queue_max_bytes}" \
        || { printf '%s\n' "RabbitMQ queue ${queue} lacks its byte bound." >&2; exit 1; }
    printf '%s\n' "$definition" | grep -Fq '<<"overflow">>, reject-publish' \
        || { printf '%s\n' "RabbitMQ queue ${queue} lacks reject-publish overflow." >&2; exit 1; }
done

# Known pre-generation-2 Celery exchanges may remain while their queue messages drain;
# no generation-2 user can write them. Any other custom exchange is unreviewed drift.
printf '%s\n' "$listed_exchanges" | validate_reviewed_exchanges product \
    || exit 1

for role in $roles; do
    user="backupsheep_${role}"
    case "$role" in
        bootstrap|preflight) expected_permission="${vhost}${tab}${empty_permission}${tab}${empty_permission}${tab}${empty_permission}" ;;
        app|beat) expected_permission="${vhost}${tab}${empty_permission}${tab}${all_exchanges}${tab}${empty_permission}" ;;
        cloud) expected_permission="${vhost}${tab}${empty_permission}${tab}${cloud_exchanges}${tab}^(default|cloud)$" ;;
        database) expected_permission="${vhost}${tab}${empty_permission}${tab}${database_exchanges}${tab}^database$" ;;
        files) expected_permission="${vhost}${tab}${empty_permission}${tab}${files_exchanges}${tab}^files$" ;;
        storage) expected_permission="${vhost}${tab}${empty_permission}${tab}${storage_exchanges}${tab}^storage$" ;;
        logs) expected_permission="${vhost}${tab}${empty_permission}${tab}${logs_exchange}${tab}^logs$" ;;
    esac
    actual_permission="$(ctl list_user_permissions "$user" --no-table-headers)" \
        || { printf '%s\n' "RabbitMQ permission inventory failed for ${user}." >&2; exit 1; }
    [ "$actual_permission" = "$expected_permission" ] \
        || { printf '%s\n' "RabbitMQ permission drift detected for ${user}." >&2; exit 1; }
done

listed_topic_permissions="$(ctl -p "$vhost" list_topic_permissions --no-table-headers)" \
    || { printf '%s\n' 'RabbitMQ post-mutation topic-permission inventory failed.' >&2; exit 1; }
[ -z "$listed_topic_permissions" ] \
    || { printf '%s\n' 'RabbitMQ topic-permission drift detected.' >&2; exit 1; }

# Re-inventory vhosts after identity rotation so a racing legacy administrator
# cannot add a tenant between the preflight snapshot and its credential removal.
final_vhosts="$(ctl list_vhosts name --silent)" \
    || { printf '%s\n' 'RabbitMQ final virtual-host inventory failed.' >&2; exit 1; }
final_vhosts="$(printf '%s\n' "$final_vhosts" | sort)"
case "$final_vhosts" in
    "$vhost"|"$expected_vhosts_with_default") ;;
    *) printf '%s\n' 'RabbitMQ gained an unexpected virtual host during provisioning.' >&2; exit 1 ;;
esac
final_vhost_metadata="$(
    ctl list_vhosts name tracing default_queue_type description tags protected_from_deletion cluster_state --silent
)" || { printf '%s\n' 'RabbitMQ final virtual-host metadata inventory failed.' >&2; exit 1; }
printf '%s\n' "$final_vhost_metadata" | validate_vhost_metadata \
    || { printf '%s\n' 'RabbitMQ final virtual-host metadata drifted.' >&2; exit 1; }
final_global_parameter_semantics="$(global_parameter_semantics)" \
    || { printf '%s\n' 'RabbitMQ final global runtime-parameter inventory failed.' >&2; exit 1; }
[ "$final_global_parameter_semantics" = true ] \
    || { printf '%s\n' 'RabbitMQ final global runtime-parameter drift detected.' >&2; exit 1; }
final_internal_cluster_id="$(
    ctl eval 'rabbit_runtime_parameters:value_global(internal_cluster_id).'
)" || { printf '%s\n' 'RabbitMQ final internal cluster-ID inventory failed.' >&2; exit 1; }
[ "$final_internal_cluster_id" = "$preexisting_internal_cluster_id" ] \
    || { printf '%s\n' 'RabbitMQ internal cluster ID changed during provisioning.' >&2; exit 1; }
final_product_parameters="$(ctl -p "$vhost" list_parameters --no-table-headers)" \
    || { printf '%s\n' 'RabbitMQ final product runtime-parameter inventory failed.' >&2; exit 1; }
[ -z "$final_product_parameters" ] \
    || { printf '%s\n' 'RabbitMQ product runtime parameters are not allowed.' >&2; exit 1; }
final_user_limits="$(ctl list_user_limits --global --no-table-headers)" \
    || { printf '%s\n' 'RabbitMQ final user-limit inventory failed.' >&2; exit 1; }
[ -z "$final_user_limits" ] \
    || { printf '%s\n' 'RabbitMQ user limits are not allowed.' >&2; exit 1; }
final_global_vhost_limits="$(ctl list_vhost_limits --global --no-table-headers)" \
    || { printf '%s\n' 'RabbitMQ final global virtual-host limit inventory failed.' >&2; exit 1; }
[ -z "$final_global_vhost_limits" ] \
    || { printf '%s\n' 'RabbitMQ global virtual-host limits are not allowed.' >&2; exit 1; }
final_product_vhost_limits="$(ctl list_vhost_limits --vhost "$vhost" --no-table-headers)" \
    || { printf '%s\n' 'RabbitMQ final product virtual-host limit inventory failed.' >&2; exit 1; }
[ -z "$final_product_vhost_limits" ] \
    || { printf '%s\n' 'RabbitMQ product virtual-host limits are not allowed.' >&2; exit 1; }

# Keep RabbitMQ's inaccessible default vhost instead of deleting it. This
# avoids a destructive classify/delete race with an already-connected legacy
# client. After legacy identities are removed, prove that the retained vhost
# is still exactly empty; any concurrent creation fails closed without data loss.
if printf '%s\n' "$final_vhosts" | grep -Fxq '/'; then
    final_default_parameters="$(ctl -p / list_parameters --no-table-headers)" \
        || { printf '%s\n' 'RabbitMQ final default runtime-parameter inventory failed.' >&2; exit 1; }
    [ -z "$final_default_parameters" ] \
        || { printf '%s\n' 'RabbitMQ default runtime parameters are not allowed.' >&2; exit 1; }
    final_default_vhost_limits="$(ctl list_vhost_limits --vhost / --no-table-headers)" \
        || { printf '%s\n' 'RabbitMQ final default virtual-host limit inventory failed.' >&2; exit 1; }
    [ -z "$final_default_vhost_limits" ] \
        || { printf '%s\n' 'RabbitMQ default virtual-host limits are not allowed.' >&2; exit 1; }
    final_default_queues="$(ctl -p / list_queues name type durable auto_delete exclusive arguments --silent)" \
        || { printf '%s\n' 'RabbitMQ final default virtual-host queue inventory failed.' >&2; exit 1; }
    [ -z "$final_default_queues" ] \
        || { printf '%s\n' 'RabbitMQ default virtual host gained a queue.' >&2; exit 1; }
    final_default_exchanges="$(ctl -p / list_exchanges name type durable auto_delete internal arguments --silent)" \
        || { printf '%s\n' 'RabbitMQ final default virtual-host exchange inventory failed.' >&2; exit 1; }
    printf '%s\n' "$final_default_exchanges" | validate_reviewed_exchanges default \
        || { printf '%s\n' 'RabbitMQ default virtual host gained a custom or malformed exchange.' >&2; exit 1; }
    final_default_bindings="$(ctl -p / list_bindings source_name destination_name destination_kind routing_key arguments --silent)" \
        || { printf '%s\n' 'RabbitMQ final default virtual-host binding inventory failed.' >&2; exit 1; }
    [ -z "$final_default_bindings" ] \
        || { printf '%s\n' 'RabbitMQ default virtual host gained a binding.' >&2; exit 1; }
    final_default_policies="$(ctl -p / list_policies --silent)" \
        || { printf '%s\n' 'RabbitMQ final default virtual-host policy inventory failed.' >&2; exit 1; }
    [ -z "$final_default_policies" ] \
        || { printf '%s\n' 'RabbitMQ default virtual host gained a policy.' >&2; exit 1; }
    final_default_operator_policies="$(ctl -p / list_operator_policies --silent)" \
        || { printf '%s\n' 'RabbitMQ final default virtual-host operator-policy inventory failed.' >&2; exit 1; }
    [ -z "$final_default_operator_policies" ] \
        || { printf '%s\n' 'RabbitMQ default virtual host gained an operator policy.' >&2; exit 1; }
    final_default_topic_permissions="$(ctl -p / list_topic_permissions --no-table-headers)" \
        || { printf '%s\n' 'RabbitMQ final default virtual-host topic-permission inventory failed.' >&2; exit 1; }
    [ -z "$final_default_topic_permissions" ] \
        || { printf '%s\n' 'RabbitMQ default virtual host gained a topic permission.' >&2; exit 1; }
fi

final_connections="$(ctl list_connections pid user vhost --silent)" \
    || { printf '%s\n' 'RabbitMQ final connection inventory failed.' >&2; exit 1; }
[ -z "$final_connections" ] \
    || { printf '%s\n' 'RabbitMQ gained a client connection during provisioning.' >&2; exit 1; }

printf '%s\n' 'RabbitMQ identity generation 2 provisioned and verified.'
