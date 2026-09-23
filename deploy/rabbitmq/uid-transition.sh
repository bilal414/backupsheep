#!/bin/sh
# Convert only the exact stock RabbitMQ 3.13 UID/GID ownership to the hardened
# Alpine RabbitMQ identity.  The wrapper runs this script in a networkless,
# capability-bounded one-shot after publishing the protected 4.2 intent.
set -eu
umask 077

data_dir=/var/lib/rabbitmq
installation_id="${BACKUPSHEEP_INSTALLATION_ID:-}"
data_generation="${BACKUPSHEEP_RABBITMQ_DATA_GENERATION:-}"
node_host="${BACKUPSHEEP_RABBITMQ_NODE_HOST:-}"

[ "$(id -u):$(id -g)" = '0:0' ] \
    || { printf '%s\n' 'RabbitMQ ownership transition requires uid/gid 0.' >&2; exit 1; }
invalid_installation_id="$(printf '%s' "$installation_id" | tr -d '0-9a-f')"
[ "${#installation_id}" -eq 64 ] && [ -z "$invalid_installation_id" ] \
    || { printf '%s\n' 'RabbitMQ ownership transition installation identity is malformed.' >&2; exit 1; }
[ "$data_generation" = 'unattested' ] \
    || { printf '%s\n' 'RabbitMQ ownership transition requires the unattested generation.' >&2; exit 1; }
case "$node_host" in
    rabbitmq|[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) printf '%s\n' 'RabbitMQ ownership transition node host is invalid.' >&2; exit 1 ;;
esac
[ -d "$data_dir" ] && [ ! -L "$data_dir" ] \
    || { printf '%s\n' 'RabbitMQ ownership transition data mount is unavailable.' >&2; exit 1; }
[ -n "$(find "$data_dir" -xdev -mindepth 1 -print -quit)" ] \
    || { printf '%s\n' 'RabbitMQ ownership transition refuses an empty data volume.' >&2; exit 1; }
[ ! -e "$data_dir/.backupsheep-volume-identity" ] \
    && [ ! -L "$data_dir/.backupsheep-volume-identity" ] \
    && [ ! -e "$data_dir/.backupsheep-volume-identity.pending" ] \
    && [ ! -L "$data_dir/.backupsheep-volume-identity.pending" ] \
    || { printf '%s\n' 'RabbitMQ ownership transition refuses a finalized or pending 4.3 witness.' >&2; exit 1; }

unexpected_link="$(find "$data_dir" -xdev -type l -print -quit)"
[ -z "$unexpected_link" ] \
    || { printf '%s\n' 'RabbitMQ ownership transition refuses symbolic links.' >&2; exit 1; }
unexpected_type="$(find "$data_dir" -xdev ! -type d ! -type f -print -quit)"
[ -z "$unexpected_type" ] \
    || { printf '%s\n' 'RabbitMQ ownership transition refuses special file types.' >&2; exit 1; }
if ! find "$data_dir" -xdev -type f -exec sh -ceu '
    for entry do
        [ "$(stat -c %h "$entry")" = 1 ] || exit 1
    done
' sh {} +; then
    printf '%s\n' 'RabbitMQ ownership transition refuses hard-linked regular files.' >&2
    exit 1
fi
unexpected_writable="$(find "$data_dir" -xdev ! -path "$data_dir" -perm /022 -print -quit)"
[ -z "$unexpected_writable" ] \
    || { printf '%s\n' 'RabbitMQ ownership transition refuses group/world-writable data.' >&2; exit 1; }
unexpected_owner="$(find "$data_dir" -xdev \
    ! \( \( -user 999 -group 999 \) -o \( -user 100 -group 101 \) \) \
    -print -quit)"
[ -z "$unexpected_owner" ] \
    || { printf '%s\n' 'RabbitMQ ownership transition found an owner outside 999:999 or 100:101.' >&2; exit 1; }

node="rabbit@${node_host}"
mnesia="${data_dir}/mnesia"
node_count=0
for candidate in "${mnesia}"/rabbit@*; do
    [ -e "$candidate" ] || [ -L "$candidate" ] || continue
    candidate_name="$(basename -- "$candidate")"
    case "$candidate_name" in
        "$node"|"${node}-feature_flags"|"${node}-plugins-expand") ;;
        *) printf '%s\n' 'RabbitMQ ownership transition found a foreign or stale node-associated entry.' >&2; exit 1 ;;
    esac
    [ -d "$candidate" ] && [ ! -L "$candidate" ] || continue
    [ "$candidate_name" = "$node" ] || continue
    node_count=$((node_count + 1))
done
[ "$node_count" -eq 1 ] \
    || { printf '%s\n' 'RabbitMQ ownership transition requires exactly one configured node database.' >&2; exit 1; }
printf '{[%s],[%s]}.\n' "$node" "$node" | cmp -s "${mnesia}/${node}/cluster_nodes.config" - \
    || { printf '%s\n' 'RabbitMQ ownership transition cluster identity is invalid.' >&2; exit 1; }

# Per-entry chown is idempotent.  A power loss can leave only a mix of the two
# admitted ownership pairs; the exact prepared host record authorizes retry.
find "$data_dir" -xdev -user 999 -group 999 -exec chown 100:101 -- {} +
unexpected_owner="$(find "$data_dir" -xdev \( ! -user 100 -o ! -group 101 \) -print -quit)"
[ -z "$unexpected_owner" ] \
    || { printf '%s\n' 'RabbitMQ ownership transition did not reach exact 100:101 ownership.' >&2; exit 1; }
sync
printf '%s\n' 'RabbitMQ volume ownership transitioned from 999:999 to 100:101.'
