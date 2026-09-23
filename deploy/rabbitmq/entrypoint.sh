#!/bin/sh
# Generate the fresh-node bootstrap definition without exporting a plaintext password.
set -eu
umask 077

secret_file=/run/secrets/rabbitmq_bootstrap_password
runtime_dir=/run/backupsheep-rabbitmq
definitions_file="${runtime_dir}/definitions.json"
entrypoint_mode="${1:-steady}"
data_generation="${BACKUPSHEEP_RABBITMQ_DATA_GENERATION:-}"
transition_target="${BACKUPSHEEP_RABBITMQ_TRANSITION_TARGET:-}"
same_version_recovery="${BACKUPSHEEP_RABBITMQ_SAME_VERSION_RECOVERY:-}"
node_host="${BACKUPSHEEP_RABBITMQ_NODE_HOST:-}"
node_name="${RABBITMQ_NODENAME:-}"

case "$node_host" in
    rabbitmq|[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) printf '%s\n' 'RabbitMQ durable node host is invalid.' >&2; exit 1 ;;
esac
[ "$node_name" = "rabbit@${node_host}" ] \
    || { printf '%s\n' 'RabbitMQ durable node name does not match its configured host.' >&2; exit 1; }
[ "$(hostname)" = "$node_host" ] \
    || { printf '%s\n' 'RabbitMQ container hostname does not match its durable node identity.' >&2; exit 1; }

case "$entrypoint_mode" in
    steady)
        [ "$#" -eq 0 ] && [ -z "$transition_target" ] \
            && [ -z "$same_version_recovery" ] \
            || { printf '%s\n' 'RabbitMQ steady-state entrypoint received a transition override.' >&2; exit 1; }
        /usr/local/bin/backupsheep-rabbitmq-volume-init verify >/dev/null
        ;;
    transition)
        [ "$#" -eq 1 ] && [ "$data_generation" = 'unattested' ] \
            || { printf '%s\n' 'RabbitMQ transition requires the exact unattested generation state.' >&2; exit 1; }
        case "$transition_target" in
            4.2) expected_runtime_version=4.2.9 ;;
            4.3) expected_runtime_version=4.3.5 ;;
            *) printf '%s\n' 'RabbitMQ transition target is invalid.' >&2; exit 1 ;;
        esac
        # Prove that this is an owned, non-empty legacy volume before invoking
        # any RabbitMQ CLI. rabbitmqctl may create .erlang.cookie as a side
        # effect, so running it first could make a fresh volume look migratable.
        if [ -n "$same_version_recovery" ]; then
            [ "$same_version_recovery" = "$expected_runtime_version" ] \
                || { printf '%s\n' 'RabbitMQ recovery request does not match the transition runtime.' >&2; exit 1; }
            /usr/local/bin/backupsheep-rabbitmq-volume-init recover "$transition_target" >/dev/null
        else
            /usr/local/bin/backupsheep-rabbitmq-volume-init transition "$transition_target" >/dev/null
        fi
        runtime_version="$(rabbitmqctl version 2>/dev/null)" \
            || { printf '%s\n' 'RabbitMQ transition runtime version is unavailable.' >&2; exit 1; }
        [ "$runtime_version" = "$expected_runtime_version" ] \
            || { printf '%s\n' 'RabbitMQ transition target does not match the runtime image.' >&2; exit 1; }
        # Transition brokers never accept application traffic or receive current
        # credentials. The canonical 4.3 recreation imports the definitions only
        # after the version, feature-flag, image, model and volume witnesses pass.
        exec /usr/local/bin/docker-entrypoint.sh rabbitmq-server
        ;;
    legacy-source)
        [ "$#" -eq 1 ] && [ "$data_generation" = 'unattested' ] \
            && [ "$transition_target" = '3.13' ] \
            || { printf '%s\n' 'RabbitMQ legacy source requires the exact unattested 3.13 state.' >&2; exit 1; }
        # This path never reads a bootstrap secret and never imports current
        # definitions.  Prove the retained stock volume before any RabbitMQ CLI
        # can create a cookie, then bind it to the exact 3.13.7 runtime.
        if [ -n "$same_version_recovery" ]; then
            [ "$same_version_recovery" = '3.13.7' ] \
                || { printf '%s\n' 'RabbitMQ recovery request does not match the legacy runtime.' >&2; exit 1; }
            /usr/local/bin/backupsheep-rabbitmq-volume-init recover 3.13 >/dev/null
        else
            /usr/local/bin/backupsheep-rabbitmq-volume-init transition 3.13 >/dev/null
        fi
        runtime_version="$(rabbitmqctl version 2>/dev/null)" \
            || { printf '%s\n' 'RabbitMQ legacy source runtime version is unavailable.' >&2; exit 1; }
        [ "$runtime_version" = '3.13.7' ] \
            || { printf '%s\n' 'RabbitMQ legacy source does not match the pinned 3.13.7 image.' >&2; exit 1; }
        exec /usr/local/bin/docker-entrypoint.sh rabbitmq-server
        ;;
    *)
        printf '%s\n' 'RabbitMQ entrypoint mode is invalid.' >&2
        exit 1
        ;;
esac

[ -f "$secret_file" ] && [ ! -L "$secret_file" ] \
    || { printf '%s\n' 'RabbitMQ bootstrap secret is unavailable.' >&2; exit 1; }
secret_size="$(wc -c < "$secret_file" | tr -d ' ')"
case "$secret_size" in
    ''|*[!0-9]*) exit 1 ;;
esac
[ "$secret_size" -ge 33 ] && [ "$secret_size" -le 4097 ] \
    || { printf '%s\n' 'RabbitMQ bootstrap secret has an invalid size.' >&2; exit 1; }

password="$(cat "$secret_file")"
[ "${#password}" -ge 32 ] \
    || { printf '%s\n' 'RabbitMQ bootstrap secret is too short.' >&2; exit 1; }
salt_file="$(mktemp /tmp/backupsheep-rabbit-salt.XXXXXX)"
digest_file="$(mktemp /tmp/backupsheep-rabbit-digest.XXXXXX)"
/opt/openssl/bin/openssl rand 4 >"$salt_file"
{
    cat "$salt_file"
    printf '%s' "$password"
} | /opt/openssl/bin/openssl dgst -sha256 -binary >"$digest_file"
password=''
password_hash="$({ cat "$salt_file"; cat "$digest_file"; } | base64 | tr -d '\n')"
rm -f "$salt_file" "$digest_file"
case "$password_hash" in
    ''|*[!A-Za-z0-9+/=]*)
        printf '%s\n' 'RabbitMQ could not derive the bootstrap password hash.' >&2
        exit 1
        ;;
esac

cat > "$definitions_file" <<EOF
{"users":[{"name":"backupsheep_bootstrap","password_hash":"${password_hash}","hashing_algorithm":"rabbit_password_hashing_sha256","tags":[]}],"vhosts":[{"name":"backupsheep"}],"permissions":[{"user":"backupsheep_bootstrap","vhost":"backupsheep","configure":"^$","write":"^$","read":"^$"}],"exchanges":[{"name":"backupsheep.default","vhost":"backupsheep","type":"direct","durable":true,"auto_delete":false,"internal":false,"arguments":{}},{"name":"backupsheep.cloud","vhost":"backupsheep","type":"direct","durable":true,"auto_delete":false,"internal":false,"arguments":{}},{"name":"backupsheep.database","vhost":"backupsheep","type":"direct","durable":true,"auto_delete":false,"internal":false,"arguments":{}},{"name":"backupsheep.files","vhost":"backupsheep","type":"direct","durable":true,"auto_delete":false,"internal":false,"arguments":{}},{"name":"backupsheep.storage","vhost":"backupsheep","type":"direct","durable":true,"auto_delete":false,"internal":false,"arguments":{}},{"name":"backupsheep.logs","vhost":"backupsheep","type":"direct","durable":true,"auto_delete":false,"internal":false,"arguments":{}}],"queues":[{"name":"default","vhost":"backupsheep","durable":true,"auto_delete":false,"arguments":{"x-queue-type":"classic"}},{"name":"cloud","vhost":"backupsheep","durable":true,"auto_delete":false,"arguments":{"x-queue-type":"classic"}},{"name":"database","vhost":"backupsheep","durable":true,"auto_delete":false,"arguments":{"x-queue-type":"classic"}},{"name":"files","vhost":"backupsheep","durable":true,"auto_delete":false,"arguments":{"x-queue-type":"classic"}},{"name":"storage","vhost":"backupsheep","durable":true,"auto_delete":false,"arguments":{"x-queue-type":"classic"}},{"name":"logs","vhost":"backupsheep","durable":true,"auto_delete":false,"arguments":{"x-queue-type":"classic"}}],"bindings":[{"source":"backupsheep.default","vhost":"backupsheep","destination":"default","destination_type":"queue","routing_key":"default","arguments":{}},{"source":"backupsheep.cloud","vhost":"backupsheep","destination":"cloud","destination_type":"queue","routing_key":"cloud","arguments":{}},{"source":"backupsheep.database","vhost":"backupsheep","destination":"database","destination_type":"queue","routing_key":"database","arguments":{}},{"source":"backupsheep.files","vhost":"backupsheep","destination":"files","destination_type":"queue","routing_key":"files","arguments":{}},{"source":"backupsheep.storage","vhost":"backupsheep","destination":"storage","destination_type":"queue","routing_key":"storage","arguments":{}},{"source":"backupsheep.logs","vhost":"backupsheep","destination":"logs","destination_type":"queue","routing_key":"logs","arguments":{}}]}
EOF
password_hash=''
chmod 0600 "$definitions_file"

exec /usr/local/bin/docker-entrypoint.sh rabbitmq-server
