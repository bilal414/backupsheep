#!/usr/bin/env bash
set -euo pipefail

run_id="bs-remed-20260818-0d08dcf"
container="bs-remed-mysql84-scale-tunnel"
key="/mnt/blockstorage/backupsheep-remediation/${run_id}/vultr_ed25519"
known_hosts="/mnt/blockstorage/backupsheep-remediation/${run_id}/vultr_known_hosts"

[[ -f "${key}" && "$(stat -c %a "${key}")" == "600" ]]
[[ -f "${known_hosts}" && "$(stat -c %a "${known_hosts}")" == "600" ]]
[[ -z "$(docker ps -aq --filter name=^/${container}$)" ]]
docker network inspect backupsheep_default >/dev/null

docker run -d \
    --name "${container}" \
    --hostname "${container}" \
    --restart unless-stopped \
    --network backupsheep_default \
    --network-alias "${container}" \
    --label "backupsheep.run_id=${run_id}" \
    --label "backupsheep.purpose=mysql-5m-and-larger-acceptance-tunnel" \
    --mount "type=bind,src=${key},dst=/run/secrets/vultr_ed25519,readonly" \
    --mount "type=bind,src=${known_hosts},dst=/run/secrets/vultr_known_hosts,readonly" \
    --entrypoint ssh \
    backupsheep:latest \
    -N \
    -i /run/secrets/vultr_ed25519 \
    -o BatchMode=yes \
    -o IdentitiesOnly=yes \
    -o UserKnownHostsFile=/run/secrets/vultr_known_hosts \
    -o StrictHostKeyChecking=yes \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=15 \
    -o ServerAliveCountMax=3 \
    -L 0.0.0.0:3309:127.0.0.1:3309 \
    root@64.177.8.4

sleep 2
[[ "$(docker inspect "${container}" --format '{{.State.Status}}')" == "running" ]]
docker exec backupsheep-app-1 sh -lc \
    'getent hosts bs-remed-mysql84-scale-tunnel && python -c "import socket; connection = socket.create_connection(('"'"'bs-remed-mysql84-scale-tunnel'"'"', 3309), 5); print('"'"'tcp_ok'"'"'); connection.close()"'
docker inspect "${container}" --format '{{.Name}} {{.State.Status}} {{json .Config.Labels}} {{json .NetworkSettings.Networks}}'
