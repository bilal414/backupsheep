#!/usr/bin/env bash
set -euo pipefail

run_id="bs-remed-20260818-0d08dcf"
restore_id="84"
correlation_id="bee81612-858e-4587-93a7-3ffd1545b9b0"
target_database="bs_restore_bee81612858e_bs_remed_mysql_lg5_0d0_8e635348dafc"
expected_rows="5000000"
worker="backupsheep-worker-database-1"
expected_revision="ee8ec3487f129b474b3cec72da467a5370162e2a"
fixture_host="64.177.8.4"
fixture_container="bs-remed-mysql84-scale-0d08dcf"
fixture_key="/mnt/blockstorage/backupsheep-remediation/${run_id}/vultr_ed25519"
fixture_known_hosts="/mnt/blockstorage/backupsheep-remediation/${run_id}/vultr_known_hosts"
evidence_dir="/mnt/blockstorage/backupsheep-remediation/${run_id}/mysql-5m-fault-restore84"
evidence="${evidence_dir}/kill-boundary.log"

cd /opt/backupsheep
mkdir -p "${evidence_dir}"

psql_query() {
    printf '%s\n' "$1" | docker compose exec -T db sh -lc \
        'exec psql -X -qAt -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
}

fixture_mysql() {
    local remote_command
    remote_command="docker exec -i ${fixture_container} sh -lc 'MYSQL_PWD=\"\$MYSQL_ROOT_PASSWORD\" exec mysql -uroot --batch --raw --skip-column-names'"
    printf '%s\n' "$1" | timeout 180 ssh \
        -i "${fixture_key}" \
        -o BatchMode=yes \
        -o UserKnownHostsFile="${fixture_known_hosts}" \
        root@"${fixture_host}" \
        "${remote_command}"
}

exec > >(tee -a "${evidence}") 2>&1

printf 'watch_started_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'run_id=%s restore_id=%s correlation_id=%s target_database=%s\n' \
    "${run_id}" "${restore_id}" "${correlation_id}" "${target_database}"

actual_revision="$(docker inspect "${worker}" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')"
[[ "${actual_revision}" == "${expected_revision}" ]]
old_container_id="$(docker inspect "${worker}" --format '{{.Id}}')"
printf 'worker_container_id=%s revision=%s restart_policy=%s\n' \
    "${old_container_id}" \
    "${actual_revision}" \
    "$(docker inspect "${worker}" --format '{{.HostConfig.RestartPolicy.Name}}')"

deadline=$((SECONDS + 1800))
while (( SECONDS < deadline )); do
    restore_state="$(psql_query "SELECT status || '|' || execution_phase || '|' || attempt_count || '|' || COALESCE(celery_task_id,'') FROM core_database_restore WHERE id=${restore_id} AND correlation_id='${correlation_id}';")"
    printf 'observed_at=%s restore_state=%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${restore_state}"
    phase="$(printf '%s' "${restore_state}" | cut -d '|' -f 2)"

    if [[ "${phase}" == "database_importing" || "${phase}" == "database_importing_file" ]]; then
        table_rows="$(fixture_mysql "SELECT COALESCE(TABLE_ROWS,0) FROM information_schema.tables WHERE table_schema='${target_database}' AND table_name='crash_probe';")"
        table_rows="${table_rows:-0}"
        printf 'approximate_committed_rows=%s\n' "${table_rows}"
        if [[ "${table_rows}" =~ ^[0-9]+$ ]] && (( table_rows >= 100000 )); then
            active_restore_ids="$(psql_query "SELECT COALESCE(string_agg(id::text,',' ORDER BY id),'') FROM core_database_restore WHERE status IN (1,2);")"
            active_backup_ids="$(psql_query "SELECT COALESCE(string_agg(id::text,',' ORDER BY id),'') FROM core_database_backup WHERE status IN (1,2,5,6,8,9,10,17,18,22);")"
            queue_state="$(docker compose exec -T rabbitmq rabbitmqctl list_queues name messages_ready messages_unacknowledged consumers | awk '$1 == "database" {print $2 "|" $3 "|" $4}')"
            process_state="$(docker top "${worker}" -eo pid,etimes,pcpu,pmem,args)"
            target_client_count="$(printf '%s\n' "${process_state}" | grep -c "${target_database}" || true)"

            printf 'active_restore_ids=%s active_backup_ids=%s queue_ready_unacked_consumers=%s target_client_count=%s\n' \
                "${active_restore_ids}" "${active_backup_ids}" \
                "${queue_state}" "${target_client_count}"
            printf '%s\n' "${process_state}"

            [[ "${active_restore_ids}" == "${restore_id}" ]]
            [[ -z "${active_backup_ids}" ]]
            [[ "${queue_state}" == 0\|1\|1 ]]
            [[ "${target_client_count}" == "1" ]]

            printf 'kill_requested_at=%s prekill_approximate_committed_rows=%s\n' \
                "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${table_rows}"
            docker kill --signal=KILL "${worker}"
            printf 'kill_completed_at=%s old_container_id=%s\n' \
                "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${old_container_id}"

            restart_deadline=$((SECONDS + 120))
            worker_restarted="false"
            while (( SECONDS < restart_deadline )); do
                current_id="$(docker inspect "${worker}" --format '{{.Id}}' 2>/dev/null || true)"
                running="$(docker inspect "${worker}" --format '{{.State.Running}}' 2>/dev/null || true)"
                if [[ "${current_id}" == "${old_container_id}" && "${running}" == "true" ]]; then
                    printf 'worker_restarted_at=%s container_id=%s\n' \
                        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${current_id}"
                    worker_restarted="true"
                    break
                fi
                sleep 2
            done
            if [[ "${worker_restarted}" != "true" ]]; then
                printf 'RESULT=FAILED_WORKER_DID_NOT_RESTART\n'
                exit 1
            fi

            exact_rows="$(fixture_mysql "SELECT COUNT(*) FROM ${target_database}.crash_probe;")"
            marker_state="$(fixture_mysql "SELECT marker_key,state FROM ${target_database}.__backupsheep_restore_marker ORDER BY marker_key;")"
            durable_after_kill="$(psql_query "SELECT status || '|' || execution_phase || '|' || attempt_count || '|' || progress_completed || '|' || COALESCE(progress_total::text,'') FROM core_database_restore WHERE id=${restore_id};")"
            printf 'postkill_exact_committed_rows=%s marker_state=%s durable_state=%s\n' \
                "${exact_rows}" "${marker_state}" "${durable_after_kill}"
            [[ "${exact_rows}" =~ ^[0-9]+$ ]]
            (( exact_rows > 0 ))
            (( exact_rows < expected_rows ))
            [[ "${marker_state}" == $'primary\timporting' ]]
            [[ "${durable_after_kill}" == 2\|database_importing_file\|1\|0\|1 ]]
            printf 'RESULT=KILL_BOUNDARY_CAPTURED\n'
            exit 0
        fi
    fi

    if [[ "${restore_state}" == 3\|* || "${restore_state}" == 4\|* ]]; then
        printf 'RESULT=FAILED_RESTORE_TERMINATED_BEFORE_KILL\n'
        exit 1
    fi
    sleep 5
done

printf 'RESULT=FAILED_TIMEOUT\n'
exit 1
