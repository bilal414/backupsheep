#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

run_id="bs-remed-20260818-0d08dcf"
container="bs-remed-mysql84-scale-0d08dcf"
source_db="bs_remed_mysql_lg5_0d08dcf"
target_db="${TARGET_DATABASE:-bs_restore_bf8a463af22f_bs_remed_mysql_lg5_0d0_8e635348dafc}"
expected_correlation_id="${EXPECTED_CORRELATION_ID:-bf8a463a-f22f-4381-a242-1c0b7cc78fe0}"
evidence="${EVIDENCE_PATH:-/mnt/bs-remed-scale-0d08dcf/${run_id}/mysql-5m/restore83-verification.txt}"

[[ "$(docker inspect "${container}" --format '{{index .Config.Labels "backupsheep.run_id"}}')" == "${run_id}" ]]

mysql_query() {
    printf '%s\n' "$1" | docker exec -i "${container}" sh -lc \
        'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -uroot --batch --raw --skip-column-names'
}

normalise_database_names() {
    sed -e "s/${source_db}/__BACKUPSHEEP_DATABASE__/g" \
        -e "s/${target_db}/__BACKUPSHEEP_DATABASE__/g"
}

digest_query() {
    mysql_query "$1" | sha256sum | awk '{print $1}'
}

ddl_digest() {
    mysql_query "SHOW CREATE TABLE $1.crash_probe; SHOW CREATE TABLE $1.fixture_meta; SHOW CREATE VIEW $1.crash_probe_summary;" \
        | normalise_database_names \
        | sha256sum \
        | awk '{print $1}'
}

row_digest() {
    digest_query "SELECT id,SHA2(payload,256),source_tag FROM $1.crash_probe ORDER BY id;"
}

stats_query() {
    mysql_query "SELECT COUNT(*),COUNT(DISTINCT id),MIN(id),MAX(id),SUM(id),SUM(OCTET_LENGTH(payload)),COUNT(DISTINCT source_tag) FROM $1.crash_probe;"
}

sample_query="SELECT id,OCTET_LENGTH(payload),SHA2(payload,256),source_tag FROM %s.crash_probe WHERE id IN (0,999999,1000000,1999999,2000000,2999999,3000000,3999999,4000000,4999999) ORDER BY id;"
meta_query="SELECT meta_key,meta_value FROM %s.fixture_meta ORDER BY meta_key;"
view_query="SELECT * FROM %s.crash_probe_summary ORDER BY 1;"

exec > >(tee "${evidence}") 2>&1

printf 'started_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'run_id=%s\n' "${run_id}"
printf 'source_db=%s\n' "${source_db}"
printf 'target_db=%s\n' "${target_db}"
printf 'expected_correlation_id=%s\n' "${expected_correlation_id}"

source_stats="$(stats_query "${source_db}")"
target_stats="$(stats_query "${target_db}")"
printf 'source_stats=%s\n' "${source_stats}"
printf 'target_stats=%s\n' "${target_stats}"
[[ "${source_stats}" == "${target_stats}" ]]
[[ "${source_stats}" == $'5000000\t5000000\t0\t4999999\t12499997500000\t5185000000\t1' ]]

source_meta="$(digest_query "$(printf "${meta_query}" "${source_db}")")"
target_meta="$(digest_query "$(printf "${meta_query}" "${target_db}")")"
printf 'source_meta_sha256=%s\n' "${source_meta}"
printf 'target_meta_sha256=%s\n' "${target_meta}"
[[ "${source_meta}" == "${target_meta}" ]]

source_samples="$(digest_query "$(printf "${sample_query}" "${source_db}")")"
target_samples="$(digest_query "$(printf "${sample_query}" "${target_db}")")"
printf 'source_samples_sha256=%s\n' "${source_samples}"
printf 'target_samples_sha256=%s\n' "${target_samples}"
[[ "${source_samples}" == "${target_samples}" ]]

source_view="$(digest_query "$(printf "${view_query}" "${source_db}")")"
target_view="$(digest_query "$(printf "${view_query}" "${target_db}")")"
printf 'source_view_sha256=%s\n' "${source_view}"
printf 'target_view_sha256=%s\n' "${target_view}"
[[ "${source_view}" == "${target_view}" ]]

source_ddl="$(ddl_digest "${source_db}")"
target_ddl="$(ddl_digest "${target_db}")"
printf 'source_ddl_sha256=%s\n' "${source_ddl}"
printf 'target_ddl_sha256=%s\n' "${target_ddl}"
[[ "${source_ddl}" == "${target_ddl}" ]]

source_rows="$(row_digest "${source_db}")"
target_rows="$(row_digest "${target_db}")"
printf 'source_ordered_rows_sha256=%s\n' "${source_rows}"
printf 'target_ordered_rows_sha256=%s\n' "${target_rows}"
[[ "${source_rows}" == "${target_rows}" ]]

marker_rows="$(mysql_query "SELECT COUNT(*) FROM ${target_db}.__backupsheep_restore_marker;")"
printf 'restore_marker_rows=%s\n' "${marker_rows}"
[[ "${marker_rows}" == "1" ]]
marker_identity="$(mysql_query "SELECT correlation_id,state,source_database,target_database FROM ${target_db}.__backupsheep_restore_marker WHERE marker_key='primary';")"
printf 'restore_marker_identity=%s\n' "${marker_identity}"
[[ "${marker_identity}" == "${expected_correlation_id}"$'\t'"complete"$'\t'"${source_db}"$'\t'"${target_db}" ]]
printf 'restore_marker=%s\n' "$(mysql_query "SELECT * FROM ${target_db}.__backupsheep_restore_marker ORDER BY 1;")"
printf 'finished_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'RESULT=PASS\n'
