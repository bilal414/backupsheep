#!/usr/bin/env bash
set -euo pipefail

run_id="bs-remed-20260818-0d08dcf"
container="bs-remed-mysql84-scale-0d08dcf"
database="bs_remed_mysql_lg5_0d08dcf"
evidence="/mnt/bs-remed-scale-0d08dcf/${run_id}/mysql-5m/seed-evidence.txt"

[[ "$(docker inspect "${container}" --format '{{index .Config.Labels "backupsheep.run_id"}}')" == "${run_id}" ]]
count="$(docker exec "${container}" sh -lc '
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" --batch --skip-column-names \
      --execute="SELECT COUNT(*) FROM bs_remed_mysql_lg5_0d08dcf.crash_probe"
' 2>/dev/null)"
[[ "${count}" == "5000000" ]]

docker exec "${container}" sh -lc '
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" --batch --skip-column-names <<SQL
ALTER TABLE bs_remed_mysql_lg5_0d08dcf.crash_probe
  COMMENT = "bs-remed-20260818-0d08dcf mysql 5m scale fixture";
UPDATE bs_remed_mysql_lg5_0d08dcf.fixture_meta
  SET meta_value = "mysql-5m-scale"
  WHERE meta_key = "fixture";
SELECT COUNT(*), COUNT(DISTINCT id), MIN(id), MAX(id), SUM(id),
       SUM(OCTET_LENGTH(payload)), COUNT(DISTINCT source_tag)
FROM bs_remed_mysql_lg5_0d08dcf.crash_probe;
SELECT id, OCTET_LENGTH(payload), SHA2(payload, 256)
FROM bs_remed_mysql_lg5_0d08dcf.crash_probe
WHERE id IN (0, 999999, 1000000, 1999999, 2000000, 2999999, 3000000, 3999999, 4000000, 4999999)
ORDER BY id;
SELECT meta_key, meta_value
FROM bs_remed_mysql_lg5_0d08dcf.fixture_meta
ORDER BY meta_key;
SELECT TABLE_NAME, TABLE_TYPE
FROM information_schema.tables
WHERE table_schema = "bs_remed_mysql_lg5_0d08dcf"
ORDER BY TABLE_NAME;
SELECT @@log_bin, @@innodb_flush_log_at_trx_commit;
SQL
' 2>/dev/null | tee -a "${evidence}"

started_at="$(sed -n 's/^started_at=//p' "${evidence}" | head -n 1)"
started_epoch="$(date -d "${started_at}" +%s)"
finished_epoch="$(date +%s)"
printf 'finished_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "${evidence}"
printf 'elapsed_seconds=%s\n' "$((finished_epoch - started_epoch))" | tee -a "${evidence}"
df -h /mnt/bs-remed-scale-0d08dcf
