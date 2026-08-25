#!/bin/sh
# Reconcile and prove the dedicated broker's users, permissions and fixed topology.
set -eu
umask 077

node='rabbit@rabbitmq'
vhost='backupsheep'
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
    output="$(
        /opt/rabbitmq/sbin/rabbitmqctl hash_password "$cleartext" \
            --hashing-algorithm sha256 2>/dev/null
    )"
    cleartext=''
    printf '%s\n' "$output" | tail -n 1
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
    password="$(read_secret "$role")"
    ctl authenticate_user "$user" "$password" >/dev/null 2>&1 \
        || { password=''; printf '%s\n' "RabbitMQ authentication failed for ${user}." >&2; exit 1; }
    password=''
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
