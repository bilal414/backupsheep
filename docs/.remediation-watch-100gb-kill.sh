#!/usr/bin/env bash
set -euo pipefail

run_id="bs-remed-20260818-0d08dcf"
point_id="44"
expected_key="${run_id}/100gb/bs-${run_id}-n101-b42-100gb.zip"
run_dir="/mnt/blockstorage/backupsheep-remediation/${run_id}/vultr-100gb-20260819"
log_file="${run_dir}/kill-watcher.log"
witness_file="${run_dir}/kill-witness.tsv"

cd /opt/backupsheep
printf 'observed_at\tstatus\tattempts\tphase\tcompleted_parts\ttotal_parts\tupload_id\tobject_key\townership_marker\n' > "${witness_file}"

while true; do
    observed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    row="$({
        docker compose exec -T db sh -lc \
            'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -F "|" -c "select status, upload_attempt_count, coalesce(metadata->'"'"'vultr_s3_object'"'"'->>'"'"'phase'"'"','"'"''"'"'), coalesce(metadata->'"'"'vultr_s3_object'"'"'->'"'"'multipart'"'"'->'"'"'progress'"'"'->>'"'"'completed_parts'"'"','"'"'0'"'"'), coalesce(metadata->'"'"'vultr_s3_object'"'"'->'"'"'multipart'"'"'->'"'"'progress'"'"'->>'"'"'total_parts'"'"','"'"'0'"'"'), coalesce(metadata->'"'"'vultr_s3_object'"'"'->'"'"'multipart'"'"'->>'"'"'upload_id'"'"','"'"''"'"'), coalesce(metadata->'"'"'vultr_s3_object'"'"'->>'"'"'object_key'"'"','"'"''"'"'), coalesce(metadata->'"'"'vultr_s3_object'"'"'->>'"'"'ownership_marker'"'"','"'"''"'"') from core_website_backup_mtm_storage_points where id=44"'
    } 2>>"${log_file}")"
    IFS='|' read -r status attempts phase completed total upload_id object_key ownership_marker <<<"${row}"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${observed_at}" "${status}" "${attempts}" "${phase}" "${completed}" \
        "${total}" "${upload_id}" "${object_key}" "${ownership_marker}" \
        >> "${witness_file}"

    if [[ "${completed}" =~ ^[0-9]+$ ]] \
        && (( completed >= 1000 )) \
        && [[ "${total}" == "7881" ]] \
        && [[ -n "${upload_id}" ]] \
        && [[ "${object_key}" == "${expected_key}" ]] \
        && [[ "${ownership_marker}" == "42" ]]; then
        container_before="$(docker inspect backupsheep-worker-storage-1 --format '{{.Id}}')"
        revision_before="$(docker inspect backupsheep-worker-storage-1 --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')"
        printf 'kill_at=%s container=%s revision=%s completed=%s total=%s upload_id=%s\n' \
            "${observed_at}" "${container_before}" "${revision_before}" \
            "${completed}" "${total}" "${upload_id}" >> "${log_file}"
        docker kill --signal=KILL backupsheep-worker-storage-1 >> "${log_file}"
        exit 0
    fi
    sleep 5
done
