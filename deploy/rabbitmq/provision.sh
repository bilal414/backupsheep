#!/bin/sh
# Reconcile and prove the dedicated broker's users, permissions and fixed topology.
set -eu
umask 077

node='rabbit@rabbitmq'
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

password_hash() {
    cleartext="$1"
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
    rm -f "$salt_file" "$digest_file"
}

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

user_exists() {
    listed_users="$(ctl list_users --no-table-headers)"
    printf '%s\n' "$listed_users" | awk '{print $1}' | grep -Fxq "$1"
}

delete_if_present() {
    candidate="$1"
    if user_exists "$candidate"; then
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

# Definitions import creates the vhost and durable topology. A stock broker owns no
# other vhost; refuse to erase an unexpected tenant by guess.
listed_vhosts="$(ctl list_vhosts name --silent)"
if printf '%s\n' "$listed_vhosts" | grep -Fxq '/'; then
    ctl delete_vhost / >/dev/null
fi
actual_vhosts="$(ctl list_vhosts name --silent)"
[ "$actual_vhosts" = "$vhost" ] \
    || { printf '%s\n' 'RabbitMQ contains an unexpected virtual host.' >&2; exit 1; }

roles='bootstrap app preflight beat cloud database files storage logs'
tab="$(printf '\t')"
for role in $roles; do
    delete_if_present "backupsheep_${role}"
done
delete_if_present guest
legacy_user="${RABBITMQ_LEGACY_USER:-backupsheep}"
case " $roles " in
    *" ${legacy_user#backupsheep_} "*) ;;
    *) delete_if_present "$legacy_user" ;;
esac

for role in $roles; do
    user="backupsheep_${role}"
    password="$(read_secret "$role")"
    hash="$(password_hash "$password")"
    case "$hash" in ''|*[!A-Za-z0-9+/=]*) exit 1 ;; esac
    ctl add_user "$user" "$hash" --pre-hashed-password >/dev/null
    [ "$(stored_password_hash "$user")" = "$hash" ] \
        || { printf '%s\n' "RabbitMQ password hash drifted for ${user}." >&2; exit 1; }
    [ "$(stored_password_algorithm "$user")" = 'rabbit_password_hashing_sha256' ] \
        || { printf '%s\n' "RabbitMQ password algorithm drifted for ${user}." >&2; exit 1; }
    password=''
    hash=''
done

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

expected_users="$(printf '%s\n' $roles | sed 's/^/backupsheep_/' | sort)"
listed_users="$(ctl list_users --no-table-headers)"
actual_users="$(printf '%s\n' "$listed_users" | awk '{print $1}' | sort)"
[ "$actual_users" = "$expected_users" ] \
    || { printf '%s\n' 'RabbitMQ user reconciliation drifted.' >&2; exit 1; }
printf '%s\n' "$listed_users" | awk '$2 != "[]" { exit 1 }' \
    || { printf '%s\n' 'RabbitMQ user tag drift detected.' >&2; exit 1; }

expected_queues="$(printf '%s\n' default cloud database files storage logs | sort)"
actual_queues="$(ctl -p "$vhost" list_queues name --silent | sort)"
[ "$actual_queues" = "$expected_queues" ] \
    || { printf '%s\n' 'RabbitMQ contains an unexpected queue.' >&2; exit 1; }

listed_exchanges="$(ctl -p "$vhost" list_exchanges name --silent)"
listed_bindings="$(ctl -p "$vhost" list_bindings source_name destination_name routing_key --silent)"
for queue in default cloud database files storage logs; do
    printf '%s\n' "$listed_exchanges" | grep -Fxq "backupsheep.${queue}" \
        || { printf '%s\n' "RabbitMQ exchange backupsheep.${queue} is missing." >&2; exit 1; }
    printf '%s\n' "$listed_bindings" \
        | grep -Fqx "backupsheep.${queue}${tab}${queue}${tab}${queue}" \
        || { printf '%s\n' "RabbitMQ binding for ${queue} is missing." >&2; exit 1; }
done

# A policy upgrades existing durable queues without deleting/redeclaring them. Every
# bounded queue rejects new publishes once either limit is reached; dropping the head
# would silently destroy backup/restore intent and is therefore forbidden.
ctl set_policy -p "$vhost" "$queue_policy" "$queue_pattern" \
    "{\"max-length\":${queue_max_messages},\"max-length-bytes\":${queue_max_bytes},\"overflow\":\"reject-publish\"}" \
    --priority 100 --apply-to queues >/dev/null
listed_policies="$(ctl -p "$vhost" list_policies --silent)"
actual_policy_names="$(printf '%s\n' "$listed_policies" | awk '{print $2}' | sort)"
[ "$actual_policy_names" = "$queue_policy" ] \
    || { printf '%s\n' 'RabbitMQ contains an unexpected queue policy.' >&2; exit 1; }
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
printf '%s\n' "$listed_exchanges" \
    | while IFS= read -r exchange; do
        case "$exchange" in
            ''|amq.*|default|cloud|database|files|storage|logs|backupsheep.default|backupsheep.cloud|backupsheep.database|backupsheep.files|backupsheep.storage|backupsheep.logs) ;;
            *) printf '%s\n' "RabbitMQ contains unreviewed exchange ${exchange}." >&2; exit 1 ;;
        esac
    done

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
    actual_permission="$(ctl list_user_permissions "$user" --no-table-headers)"
    [ "$actual_permission" = "$expected_permission" ] \
        || { printf '%s\n' "RabbitMQ permission drift detected for ${user}." >&2; exit 1; }
done

[ -z "$(ctl -p "$vhost" list_topic_permissions --no-table-headers)" ] \
    || { printf '%s\n' 'RabbitMQ topic-permission drift detected.' >&2; exit 1; }

printf '%s\n' 'RabbitMQ identity generation 2 provisioned and verified.'
