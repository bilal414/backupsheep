#!/bin/sh
# Create/verify the stock broker volume ownership witness without root privileges.
set -eu
umask 077

data_dir=/var/lib/rabbitmq
witness="${data_dir}/.backupsheep-volume-identity"
mode="${1:-verify}"
installation_id="${BACKUPSHEEP_INSTALLATION_ID:-}"
data_generation="${BACKUPSHEEP_RABBITMQ_DATA_GENERATION:-}"

invalid_installation_id="$(printf '%s' "$installation_id" | tr -d '0-9a-f')"
[ "${#installation_id}" -eq 64 ] && [ -z "$invalid_installation_id" ] \
    || { printf '%s\n' 'RabbitMQ volume installation identity is malformed.' >&2; exit 1; }
[ "$data_generation" = '4.3' ] \
    || { printf '%s\n' 'RabbitMQ volume data generation is not attested as 4.3.' >&2; exit 1; }
case "$mode" in init|verify) ;; *) exit 1 ;; esac

[ -d "$data_dir" ] && [ ! -L "$data_dir" ] \
    || { printf '%s\n' 'RabbitMQ data mount is unavailable.' >&2; exit 1; }
[ "$(stat -c '%u:%g' "$data_dir")" = '100:101' ] \
    || { printf '%s\n' 'RabbitMQ data mount is not owned by uid 100 gid 101.' >&2; exit 1; }
unexpected_owner="$(find "$data_dir" -xdev \( ! -user rabbitmq -o ! -group rabbitmq \) -print -quit)"
[ -z "$unexpected_owner" ] \
    || { printf '%s\n' 'RabbitMQ data contains an entry outside uid 100 gid 101.' >&2; exit 1; }
unexpected_link="$(find "$data_dir" -xdev -type l -print -quit)"
[ -z "$unexpected_link" ] \
    || { printf '%s\n' 'RabbitMQ data contains an unreviewed symbolic link.' >&2; exit 1; }
unexpected_writable="$(find "$data_dir" -xdev ! -path "$data_dir" -perm /022 -print -quit)"
if [ -n "$unexpected_writable" ]; then
    printf '%s\n' 'RabbitMQ data contains a group/world-writable entry.' >&2
    exit 1
fi

expected="version=1
installation_id=${installation_id}
data_generation=${data_generation}
uid=100
gid=101"

if [ "$mode" = init ]; then
    # The official image seeds a fresh named-volume root as 01777. The fixed owner
    # can tighten its own mount without CHOWN/FOWNER/DAC capabilities.
    chmod 0700 "$data_dir"
    if [ ! -e "$witness" ] && [ ! -L "$witness" ]; then
        pending="${witness}.pending"
        [ ! -e "$pending" ] && [ ! -L "$pending" ] \
            || { printf '%s\n' 'RabbitMQ volume witness has an interrupted pending write.' >&2; exit 1; }
        printf '%s\n' "$expected" > "$pending"
        chmod 0600 "$pending"
        mv "$pending" "$witness"
    fi
fi

[ -f "$witness" ] && [ ! -L "$witness" ] \
    || { printf '%s\n' 'RabbitMQ volume identity witness is missing.' >&2; exit 1; }
[ "$(stat -c '%u:%g %a %h' "$witness")" = '100:101 600 1' ] \
    || { printf '%s\n' 'RabbitMQ volume identity witness metadata drifted.' >&2; exit 1; }
[ "$(cat "$witness")" = "$expected" ] \
    || { printf '%s\n' 'RabbitMQ volume identity witness belongs to another installation or generation.' >&2; exit 1; }
[ "$(stat -c '%u:%g %a' "$data_dir")" = '100:101 700' ] \
    || { printf '%s\n' 'RabbitMQ data mount permissions drifted.' >&2; exit 1; }

printf '%s\n' "RabbitMQ volume ownership generation ${data_generation} verified."
