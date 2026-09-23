#!/usr/bin/env bash
set -euo pipefail

run_id="bs-remed-20260818-0d08dcf"
source_container="bs-remed-mysql84"
target_container="bs-remed-mysql84-scale-0d08dcf"
source_database="bs_remed_mysql_lg1_0d08dcf"
target_database="bs_remed_mysql_lg5_0d08dcf"
evidence="/mnt/bs-remed-scale-0d08dcf/${run_id}/mysql-5m/seed-evidence.txt"

[[ "$(docker inspect "${target_container}" --format '{{index .Config.Labels "backupsheep.run_id"}}')" == "${run_id}" ]]
source_count="$(docker exec "${source_container}" sh -lc \
    'mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" --batch --skip-column-names --execute="SELECT COUNT(*) FROM bs_remed_mysql_lg1_0d08dcf.crash_probe"' \
    2>/dev/null)"
target_tables="$(docker exec "${target_container}" sh -lc \
    'mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" --batch --skip-column-names --execute="SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '\''bs_remed_mysql_lg5_0d08dcf'\''"' \
    2>/dev/null)"
[[ "${source_count}" == "1000000" ]]
[[ "${target_tables}" == "0" ]]

started_epoch="$(date +%s)"
{
    printf 'run_id=%s\n' "${run_id}"
    printf 'started_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'source_count=%s\n' "${source_count}"
} > "${evidence}"
chmod 0600 "${evidence}"

docker exec "${source_container}" sh -lc '
    exec mysqldump -uroot -p"${MYSQL_ROOT_PASSWORD}" \
        --single-transaction --quick --routines --events --triggers --hex-blob \
        --set-gtid-purged=OFF --no-tablespaces --skip-lock-tables \
        bs_remed_mysql_lg1_0d08dcf
' 2>>"${evidence}" | docker exec -i "${target_container}" sh -lc '
    exec mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" bs_remed_mysql_lg5_0d08dcf
' 2>>"${evidence}"
printf 'clone_completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${evidence}"

for offset in 1000000 2000000 3000000 4000000; do
    docker exec "${target_container}" sh -lc "
        mysql -uroot -p\"\${MYSQL_ROOT_PASSWORD}\" --batch --skip-column-names \
          --execute=\"INSERT INTO ${target_database}.crash_probe (id, payload, source_tag)
            SELECT id + ${offset},
                   RPAD(
                     CONCAT(
                       LPAD(id + ${offset}, 7, '0'), ':',
                       SHA2(CAST(id + ${offset} AS CHAR), 256), ':',
                       '${run_id}', ':'
                     ),
                     1037,
                     LPAD(MOD(id + ${offset}, 100), 2, '0')
                   ),
                   '${run_id}'
            FROM ${target_database}.crash_probe
            WHERE id < 1000000;\"
    " 2>>"${evidence}"
    printf 'offset_%s_completed_at=%s\n' \
        "${offset}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${evidence}"
done

docker exec "${target_container}" sh -lc '
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
SELECT TABLE_NAME, TABLE_TYPE
FROM information_schema.tables
WHERE table_schema = "bs_remed_mysql_lg5_0d08dcf"
ORDER BY TABLE_NAME;
SELECT @@log_bin, @@innodb_flush_log_at_trx_commit;
SQL
' >> "${evidence}" 2>&1

finished_epoch="$(date +%s)"
printf 'finished_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${evidence}"
printf 'elapsed_seconds=%s\n' "$((finished_epoch - started_epoch))" >> "${evidence}"
cat "${evidence}"
df -h /mnt/bs-remed-scale-0d08dcf
