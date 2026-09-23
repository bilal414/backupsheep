#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 8 ]]; then
  printf 'usage: %s tiny medium large manytables blobs unicode objects mutable\n' "$0" >&2
  exit 2
fi

container="bs-remed-mysql84"
tiny="$1"
medium="$2"
large="$3"
manytables="$4"
blobs="$5"
unicode="$6"
objects="$7"
mutable="$8"

query() {
  local database="$1"
  local sql="$2"
  docker exec "$container" sh -c '
    export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
    exec mysql \
      -uroot \
      --default-character-set=utf8mb4 \
      --batch \
      --raw \
      --quick \
      --skip-column-names \
      "$1" \
      -e "$2"
  ' sh "$database" "$sql"
}

hash_query() {
  local label="$1"
  local database="$2"
  local sql="$3"
  local digest
  digest="$(query "$database" "$sql" | sha256sum | cut -d' ' -f1)"
  printf '%s|%s\n' "$label" "$digest"
}

dump_hash() {
  local label="$1"
  local database="$2"
  local kind="$3"
  local marker_count
  local digest
  marker_count="$(query "$database" "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=0x5f5f6261636b757073686565705f726573746f72655f6d61726b6572;")"
  digest="$({
    docker exec "$container" sh -c '
      export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
      database="$1"
      kind="$2"
      marker_count="$3"
      set -- mysqldump \
        -uroot \
        --default-character-set=utf8mb4 \
        --compact \
        --skip-comments \
        --skip-lock-tables \
        --skip-add-locks \
        --set-gtid-purged=OFF
      if [ "$kind" = data ]; then
        set -- "$@" \
          --no-create-info \
          --skip-triggers \
          --hex-blob \
          --order-by-primary
      else
        set -- "$@" \
          --no-data \
          --routines \
          --events \
          --triggers
      fi
      if [ "$marker_count" = 1 ]; then
        set -- "$@" "--ignore-table=$database.__backupsheep_restore_marker"
      fi
      exec "$@" "$database"
    ' sh "$database" "$kind" "$marker_count"
  } | sed -E '
    s/^USE `[^`]+`;/USE `__DATABASE__`;/
    s/ CHARACTER SET [[:alnum:]_]+ COLLATE/ COLLATE/g
    /^-- Dump completed on /d
  ' | sha256sum | cut -d' ' -f1)"
  printf '%s|%s\n' "$label" "$digest"
}

printf 'server|'
docker exec "$container" sh -c '
  export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
  exec mysql -uroot --batch --raw --skip-column-names \
    -e "SELECT VERSION(), @@global.event_scheduler;"
'

printf 'tiny_metrics|'
query "$tiny" "SELECT COUNT(*), COUNT(DISTINCT id), MIN(id), MAX(id), MD5(GROUP_CONCAT(CONCAT(id, ':', HEX(label), ':', HEX(payload)) ORDER BY id SEPARATOR '|')), (SELECT COUNT(*) FROM tiny_view) FROM tiny_data;"

printf 'medium_counts|'
query "$medium" "SELECT (SELECT COUNT(*) FROM tenants), (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM projects), (SELECT COUNT(*) FROM tasks), (SELECT COUNT(*) FROM comments), (SELECT COUNT(*) FROM tags), (SELECT COUNT(*) FROM project_tags), (SELECT COUNT(*) FROM audit_log);"
printf 'medium_orphans|'
query "$medium" "SELECT (SELECT COUNT(*) FROM users u LEFT JOIN tenants t ON t.id=u.tenant_id WHERE t.id IS NULL), (SELECT COUNT(*) FROM projects p LEFT JOIN tenants t ON t.id=p.tenant_id WHERE t.id IS NULL), (SELECT COUNT(*) FROM tasks x LEFT JOIN projects p ON p.id=x.project_id LEFT JOIN users u ON u.id=x.assignee_id WHERE p.id IS NULL OR u.id IS NULL), (SELECT COUNT(*) FROM comments c LEFT JOIN tasks t ON t.id=c.task_id LEFT JOIN users u ON u.id=c.author_id WHERE t.id IS NULL OR u.id IS NULL), (SELECT COUNT(*) FROM project_tags pt LEFT JOIN projects p ON p.id=pt.project_id LEFT JOIN tags t ON t.id=pt.tag_id WHERE p.id IS NULL OR t.id IS NULL), (SELECT COUNT(*) FROM audit_log a LEFT JOIN users u ON u.id=a.user_id WHERE u.id IS NULL);"

printf 'large_metrics|'
query "$large" "SELECT COUNT(*), COUNT(DISTINCT id), MIN(id), MAX(id), SUM(id), MIN(LENGTH(payload)), MAX(LENGTH(payload)) FROM large_rows;"
hash_query large_rows_sha256 "$large" "SELECT id, payload FROM large_rows ORDER BY id;"

printf 'manytables_metrics|'
query "$manytables" "SELECT COUNT(*), SUM(table_name REGEXP '^t_[0-9]{4}$'), MIN(table_name), MAX(table_name) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_type='BASE TABLE' AND table_name <> '__backupsheep_restore_marker';"
hash_query manytables_names_sha256 "$manytables" "SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND table_type='BASE TABLE' AND table_name <> '__backupsheep_restore_marker' ORDER BY table_name;"

printf 'blob_metrics\n'
query "$blobs" "SELECT id, label, COALESCE(OCTET_LENGTH(binary_data),-1), COALESCE(MD5(binary_data),'-'), COALESCE(OCTET_LENGTH(text_data),-1), COALESCE(MD5(text_data),'-') FROM payloads ORDER BY id;"

printf 'unicode_metrics|'
query "$unicode" "SELECT COUNT(*), COUNT(DISTINCT id), MIN(id), MAX(id) FROM unicode_rows;"
hash_query unicode_rows_sha256 "$unicode" "SELECT id, HEX(value_text) FROM unicode_rows ORDER BY id;"

printf 'object_metrics|'
query "$objects" "SELECT (SELECT COUNT(*) FROM object_parent), (SELECT COUNT(*) FROM object_child), (SELECT COUNT(*) FROM object_audit), (SELECT SUM(child_count) FROM object_summary), (SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema=DATABASE()), (SELECT COUNT(*) FROM information_schema.routines WHERE routine_schema=DATABASE() AND routine_type='PROCEDURE'), (SELECT COUNT(*) FROM information_schema.routines WHERE routine_schema=DATABASE() AND routine_type='FUNCTION'), (SELECT COUNT(*) FROM information_schema.events WHERE event_schema=DATABASE() AND status='DISABLED');"
hash_query object_data_sha256 "$objects" "SELECT 'parent', id, label FROM object_parent UNION ALL SELECT 'child', id, CONCAT(parent_id, ':', label) FROM object_child UNION ALL SELECT 'audit', id, CONCAT(COALESCE(child_id,-1), ':', action_text) FROM object_audit ORDER BY 1,2;"

printf 'mutable_metrics|'
query "$mutable" "SELECT COUNT(*), COUNT(DISTINCT id), MIN(id), MAX(id), SUM(generation=1), SUM(generation=2), SUM(id BETWEEN 91 AND 95), SUM(id BETWEEN 101 AND 120), SUM(id BETWEEN 1 AND 10 AND value_text LIKE 'generation-2-updated-%') FROM mutable_rows;"
hash_query mutable_rows_sha256 "$mutable" "SELECT id, generation, HEX(value_text) FROM mutable_rows ORDER BY id;"

databases=("$tiny" "$medium" "$large" "$manytables" "$blobs" "$unicode" "$objects" "$mutable")
families=(tiny medium large manytables blobs unicode objects mutable)
for index in "${!databases[@]}"; do
  dump_hash "${families[$index]}_data_dump_sha256" "${databases[$index]}" data
  dump_hash "${families[$index]}_schema_dump_sha256" "${databases[$index]}" schema
done
