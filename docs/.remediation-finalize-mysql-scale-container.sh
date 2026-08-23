#!/usr/bin/env bash
set -euo pipefail

container="bs-remed-mysql84-scale-0d08dcf"
expected_data="/mnt/bs-remed-scale-0d08dcf/bs-remed-20260818-0d08dcf/mysql-5m/mysql84-data"

[[ "$(docker inspect "${container}" --format '{{index .Config.Labels "backupsheep.run_id"}}')" == "bs-remed-20260818-0d08dcf" ]]
[[ "$(docker inspect "${container}" --format '{{index .Config.Labels "backupsheep.purpose"}}')" == "mysql-5m-and-larger-acceptance" ]]
[[ "$(docker inspect "${container}" --format '{{(index .Mounts 0).Source}}')" == "${expected_data}" ]]

docker exec "${container}" sh -lc '
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" --batch --skip-column-names \
        --execute="GRANT ALL PRIVILEGES ON *.* TO '\''bsbackup'\''@'\''%'\'' WITH GRANT OPTION; FLUSH PRIVILEGES;"
' >/dev/null 2>&1

docker inspect "${container}" --format '{{.Name}} {{.State.Status}} {{.HostConfig.Memory}} {{.HostConfig.NanoCpus}} {{json .Config.Labels}}'
docker exec "${container}" sh -lc '
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" --batch --skip-column-names <<SQL
SELECT VERSION(), @@log_bin, @@innodb_flush_log_at_trx_commit;
SELECT User, Host FROM mysql.user WHERE User = "bsbackup";
SHOW GRANTS FOR "bsbackup"@"%";
SQL
' 2>/dev/null
df -h /mnt/bs-remed-scale-0d08dcf
