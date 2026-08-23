#!/usr/bin/env bash
set -euo pipefail

run_id="bs-remed-20260818-0d08dcf"
mountpoint="/mnt/bs-remed-scale-0d08dcf"
run_dir="${mountpoint}/${run_id}/mysql-5m"
data_dir="${run_dir}/mysql84-data"
env_file="${run_dir}/mysql84.env"
container="bs-remed-mysql84-scale-0d08dcf"
database="bs_remed_mysql_lg5_0d08dcf"

[[ "$(findmnt -rn -o SOURCE -T "${mountpoint}")" == "/dev/vdb1" ]]
[[ "$(lsblk -dn -o SERIAL /dev/vdb | tr -d '[:space:]')" == "ord-1be82b171e9f4a" ]]
[[ ! -e "${data_dir}" ]]
[[ -z "$(docker ps -aq --filter name=^/${container}$)" ]]

install -d -m 0700 "${run_dir}"
install -d -m 0700 "${data_dir}"
umask 077
docker exec bs-remed-mysql84 sh -lc '
    set -eu
    : "${MYSQL_ROOT_PASSWORD:?}"
    : "${MYSQL_USER:?}"
    : "${MYSQL_PASSWORD:?}"
    printf "MYSQL_ROOT_PASSWORD=%s\nMYSQL_USER=%s\nMYSQL_PASSWORD=%s\n" \
        "${MYSQL_ROOT_PASSWORD}" "${MYSQL_USER}" "${MYSQL_PASSWORD}"
' > "${env_file}"
printf 'MYSQL_DATABASE=%s\n' "${database}" >> "${env_file}"
chmod 0600 "${env_file}"

docker run -d \
    --name "${container}" \
    --hostname "${container}" \
    --restart unless-stopped \
    --memory 1536m \
    --cpus 2 \
    --env-file "${env_file}" \
    --label "backupsheep.run_id=${run_id}" \
    --label "backupsheep.purpose=mysql-5m-and-larger-acceptance" \
    --mount "type=bind,src=${data_dir},dst=/var/lib/mysql" \
    --publish 3309:3306 \
    mysql:8.4 \
    --skip-log-bin \
    --max_allowed_packet=536870912 \
    --innodb-flush-log-at-trx-commit=1

for _ in $(seq 1 90); do
    if docker exec "${container}" sh -lc \
        'mysqladmin -uroot -p"${MYSQL_ROOT_PASSWORD}" ping --silent' >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
docker exec "${container}" sh -lc \
    'mysqladmin -uroot -p"${MYSQL_ROOT_PASSWORD}" ping --silent' >/dev/null
docker exec "${container}" sh -lc '
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" --skip-column-names --batch \
        --execute="GRANT ALL PRIVILEGES ON *.* TO '\''bsbackup'\''@'\''%'\'' WITH GRANT OPTION; FLUSH PRIVILEGES;"
' >/dev/null 2>&1

docker inspect "${container}" --format '{{.Name}} {{.State.Status}} {{.HostConfig.Memory}} {{.HostConfig.NanoCpus}} {{json .Config.Labels}}'
docker exec "${container}" sh -lc '
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" --skip-column-names --batch \
        -e "SELECT VERSION(), @@log_bin, @@innodb_flush_log_at_trx_commit;"
' 2>/dev/null
df -h "${mountpoint}"
