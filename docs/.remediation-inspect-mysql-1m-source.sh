#!/usr/bin/env bash
set -euo pipefail

docker exec bs-remed-mysql84 sh -lc '
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" --batch --skip-column-names <<SQL
SELECT id, LENGTH(payload), LEFT(payload, 100)
FROM bs_remed_mysql_lg1_0d08dcf.crash_probe
WHERE id IN (0, 1, 999999)
ORDER BY id;
SHOW CREATE TABLE bs_remed_mysql_lg1_0d08dcf.crash_probe;
SHOW CREATE TABLE bs_remed_mysql_lg1_0d08dcf.fixture_meta;
SELECT * FROM bs_remed_mysql_lg1_0d08dcf.fixture_meta ORDER BY 1;
SHOW CREATE VIEW bs_remed_mysql_lg1_0d08dcf.crash_probe_view;
SQL
' 2>/dev/null
