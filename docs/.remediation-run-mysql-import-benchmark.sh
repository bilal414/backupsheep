#!/usr/bin/env bash
set -euo pipefail

format="${1:-}"
round="${2:-}"
case "$format" in
  current|row) ;;
  *) echo "format must be current or row" >&2; exit 2 ;;
esac
case "$round" in
  1|2|3) ;;
  *) echo "round must be 1, 2, or 3" >&2; exit 2 ;;
esac

run_id="bs-remed-20260818-0d08dcf"
container="bs-remed-mysql84-bench-0d08dcf"
root="/mnt/blockstorage/backupsheep-remediation/${run_id}/mysql-1m-performance-20260819"
sql_path="${root}/${format}.sql"
database="bs_bench_1m_${format}_r${round}_0d08dcf"
telemetry="${root}/${format}-r${round}-import.csv"
timing="${root}/${format}-r${round}-import.time"
verification="${root}/${format}-r${round}-verification.txt"

test "$(docker inspect --format '{{index .Config.Labels "backupsheep.run_id"}}' "$container")" = "$run_id"
test "$(docker inspect --format '{{index .Config.Labels "backupsheep.purpose"}}' "$container")" = "mysql-1m-performance"
test "$(stat -c '%a' "$sql_path")" = "600"
test "$(stat -c '%s' "$sql_path")" -gt 1000000000

schema_count="$({
  docker exec "$container" sh -lc \
    'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -NBe "$1"' sh \
    "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='${database}'"
} 2>/dev/null)"
test "$schema_count" = "0"

docker exec "$container" sh -lc \
  'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "$1"' sh \
  "CREATE DATABASE \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci" \
  2>/dev/null

install -m 0600 /dev/null "$telemetry"
install -m 0600 /dev/null "$timing"
install -m 0600 /dev/null "$verification"

monitor() {
  while :; do
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
    stats="$(
      docker stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}|{{.BlockIO}}' \
        "$container" 2>/dev/null || true
    )"
    client="$(
      docker exec "$container" ps -C mysql -o rss=,pcpu= 2>/dev/null \
        | head -n 1 | tr -s ' ' | sed 's/^ //' | tr ' ' ',' || true
    )"
    echo "${timestamp}|${stats}|${client}" >> "$telemetry"
    sleep 1
  done
}

monitor &
monitor_pid=$!
trap 'kill "$monitor_pid" 2>/dev/null || true; wait "$monitor_pid" 2>/dev/null || true' EXIT

/usr/bin/time -f 'elapsed_seconds=%e\nuser_seconds=%U\nsystem_seconds=%S\nhost_peak_rss_kib=%M' \
  -o "$timing" \
  docker exec -i "$container" sh -lc \
    'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" "$1"' sh "$database" \
    < "$sql_path" 2>/dev/null

kill "$monitor_pid" 2>/dev/null || true
wait "$monitor_pid" 2>/dev/null || true
trap - EXIT

{
  docker exec "$container" sh -lc \
    'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -NBe "$1" "$2"' sh \
    'SELECT COUNT(*),COUNT(DISTINCT id),MIN(id),MAX(id),SUM(id),SUM(OCTET_LENGTH(payload)) FROM crash_probe; SELECT row_count,min_id,max_id,id_sum FROM crash_probe_summary; SELECT COUNT(*) FROM fixture_meta' \
    "$database" 2>/dev/null
  docker exec "$container" sh -lc \
    'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" --batch --raw --skip-column-names -e "$1" "$2"' sh \
    "SELECT CONCAT(id,'|',SHA2(payload,256)) FROM crash_probe ORDER BY id" \
    "$database" 2>/dev/null | sha256sum
  docker exec "$container" sh -lc \
    'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -NBe "$1"' sh \
    "SELECT default_character_set_name,default_collation_name FROM information_schema.schemata WHERE schema_name='${database}'" \
    2>/dev/null
} > "$verification"

chmod 0600 "$telemetry" "$timing" "$verification"
printf 'database=%s\n' "$database"
cat "$timing"
cat "$verification"
