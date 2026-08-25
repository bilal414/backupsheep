#!/bin/sh
# Generate the fresh-node bootstrap definition without exporting a plaintext password.
set -eu
umask 077

secret_file=/run/secrets/rabbitmq_bootstrap_password
runtime_dir=/run/backupsheep-rabbitmq
definitions_file="${runtime_dir}/definitions.json"

/usr/local/bin/backupsheep-rabbitmq-volume-init verify >/dev/null

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
hash_output="$(
    /opt/rabbitmq/sbin/rabbitmqctl hash_password "$password" \
        --hashing-algorithm sha256 2>/dev/null
)"
password=''
password_hash="$(printf '%s\n' "$hash_output" | tail -n 1)"
hash_output=''
case "$password_hash" in
    ''|*[!A-Za-z0-9+/=]*)
        printf '%s\n' 'RabbitMQ could not derive the bootstrap password hash.' >&2
        exit 1
        ;;
esac

cat > "$definitions_file" <<EOF
{"users":[{"name":"backupsheep_bootstrap","password_hash":"${password_hash}","hashing_algorithm":"rabbit_password_hashing_sha256","tags":[]}],"vhosts":[{"name":"backupsheep"}],"permissions":[{"user":"backupsheep_bootstrap","vhost":"backupsheep","configure":"^$","write":"^$","read":"^$"}],"exchanges":[{"name":"backupsheep.default","vhost":"backupsheep","type":"direct","durable":true,"auto_delete":false,"internal":false,"arguments":{}},{"name":"backupsheep.cloud","vhost":"backupsheep","type":"direct","durable":true,"auto_delete":false,"internal":false,"arguments":{}},{"name":"backupsheep.database","vhost":"backupsheep","type":"direct","durable":true,"auto_delete":false,"internal":false,"arguments":{}},{"name":"backupsheep.files","vhost":"backupsheep","type":"direct","durable":true,"auto_delete":false,"internal":false,"arguments":{}},{"name":"backupsheep.storage","vhost":"backupsheep","type":"direct","durable":true,"auto_delete":false,"internal":false,"arguments":{}},{"name":"backupsheep.logs","vhost":"backupsheep","type":"direct","durable":true,"auto_delete":false,"internal":false,"arguments":{}}],"queues":[{"name":"default","vhost":"backupsheep","durable":true,"auto_delete":false,"arguments":{}},{"name":"cloud","vhost":"backupsheep","durable":true,"auto_delete":false,"arguments":{}},{"name":"database","vhost":"backupsheep","durable":true,"auto_delete":false,"arguments":{}},{"name":"files","vhost":"backupsheep","durable":true,"auto_delete":false,"arguments":{}},{"name":"storage","vhost":"backupsheep","durable":true,"auto_delete":false,"arguments":{}},{"name":"logs","vhost":"backupsheep","durable":true,"auto_delete":false,"arguments":{}}],"bindings":[{"source":"backupsheep.default","vhost":"backupsheep","destination":"default","destination_type":"queue","routing_key":"default","arguments":{}},{"source":"backupsheep.cloud","vhost":"backupsheep","destination":"cloud","destination_type":"queue","routing_key":"cloud","arguments":{}},{"source":"backupsheep.database","vhost":"backupsheep","destination":"database","destination_type":"queue","routing_key":"database","arguments":{}},{"source":"backupsheep.files","vhost":"backupsheep","destination":"files","destination_type":"queue","routing_key":"files","arguments":{}},{"source":"backupsheep.storage","vhost":"backupsheep","destination":"storage","destination_type":"queue","routing_key":"storage","arguments":{}},{"source":"backupsheep.logs","vhost":"backupsheep","destination":"logs","destination_type":"queue","routing_key":"logs","arguments":{}}]}
EOF
password_hash=''
chmod 0600 "$definitions_file"

exec /usr/local/bin/docker-entrypoint.sh rabbitmq-server
