# Observability

BackupSheep exposes application state through the console/REST API, service logs, a simple
liveness endpoint, PostgreSQL and RabbitMQ diagnostics, and optional Sentry reporting. The
repository does not ship a Prometheus exporter, Grafana dashboard or end-to-end synthetic
restore monitor; operators must integrate the signals below into their monitoring stack.

## Signal model

| Layer | Source | What it proves |
| --- | --- | --- |
| Web liveness | `GET /healthz/` returns `ok` | A web process handled one HTTP request |
| Container state | `./backupsheep-compose ps --all`; add `--profile operations` for enabled workers/Beat | Docker health/restart state and one-shot gate exits |
| PostgreSQL | Stock authenticated container healthcheck; database monitoring | File-backed `SELECT 1` authentication plus external capacity/lock/latency metrics |
| RabbitMQ | diagnostics, queue metrics | Broker availability, backlog and consumers |
| Celery | worker ping and inspect | Current worker connectivity and transient task view |
| Durable jobs | console/API and PostgreSQL-backed execution rows | Backup/restore request, phase, retry, progress, provider/reconciliation state |
| Artifact evidence | backup API/storage-copy records | Recorded checksum/bytes/version and verification time |
| Product activity | console Logs and run logs | Human-readable account events and local execution detail |
| Exceptions | optional `SENTRY_DSN` | Application exceptions/performance data sent to Sentry |
| Recoverability | scheduled restore rehearsal | The selected backup can reconstruct verified data |

No single row in this table replaces the others. In particular, web liveness and a green
provider backup job do not prove recoverability.

## Liveness and dependency probes

```bash
curl -fsS http://127.0.0.1:8000/healthz/
DB_CONTAINER="$(./backupsheep-compose ps -q db)"
test -n "${DB_CONTAINER}"
test "$(docker inspect --format '{{.State.Health.Status}}' "${DB_CONTAINER}")" = healthy
./backupsheep-compose exec -T rabbitmq rabbitmq-diagnostics -q ping
```

The database container's stock healthcheck authenticates over TCP with its exact
file-backed bootstrap credential and executes `SELECT 1`; `pg_isready` alone is not an
authentication check.

The profile-less core has no workers by design. When operations have been explicitly
enabled, inspect them separately:

```bash
./backupsheep-compose --profile operations exec -T worker-cloud celery -A backupsheep inspect ping
```

The health endpoint is deliberately unauthenticated and exempt from HTTPS redirect so a
platform can probe it over private HTTP. It always returns `ok`; do not call it readiness
for PostgreSQL, RabbitMQ, workers, storage or cloud providers.

## Durable execution status

Backup and restore API representations include a redacted `execution_status` object. Its
stable operational fields include:

- `durable` and `correlation_id`;
- public `status` and `phase`;
- safe `last_error_code`/message and timestamps;
- `next_retry_at` and attempt count;
- completed/total/unit progress;
- recorded artifact size/checksum/verification evidence when available;
- reconciliation state/reason;
- normalized provider status.

Raw provider responses, credentials, worker lease tokens and internal metadata are not the
public status contract. Alert and support tooling should carry the correlation ID and safe
error code rather than copying raw logs.

Suggested job alerts:

- a scheduled source has no successful backup within its expected interval plus grace;
- any backup/restore becomes failed or `manual_review`;
- `next_retry_at` is overdue and the row has not changed;
- an active phase exceeds its source-specific expected duration;
- a required destination copy is incomplete/unverified;
- no successful restore rehearsal exists within policy.

## RabbitMQ and Celery

```bash
./backupsheep-compose exec -T rabbitmq \
  rabbitmqctl list_queues name messages_ready messages_unacknowledged consumers durable

./backupsheep-compose --profile operations exec -T worker-cloud celery -A backupsheep inspect active
./backupsheep-compose --profile operations exec -T worker-cloud celery -A backupsheep inspect reserved
./backupsheep-compose --profile operations exec -T worker-cloud celery -A backupsheep inspect scheduled
```

Track queue depth and oldest-message age per lane. A sustained `storage` queue with healthy
database/file queues indicates upload throughput pressure; a queue with zero consumers
indicates the corresponding worker is absent or disconnected.

Celery inspection is not durable history. BackupSheep uses late acknowledgements,
persistent delivery and database recovery; correlate queue evidence with the durable API
row before intervening.

## Logs

Container stdout/stderr:

```bash
./backupsheep-compose logs --since=1h app
./backupsheep-compose logs --since=1h db rabbitmq
```

For an operations-enabled deployment, also collect:

```bash
./backupsheep-compose --profile operations logs --since=1h worker-cloud worker-database worker-files worker-storage worker-logs beat
```

The console's Logs page is an account-scoped activity trail with authentication,
connection, node, schedule, backup, storage, member and restore events. Local run and
restore logs live only in their owning `database_workdir`, `files_workdir` or
`storage_workdir`. The daily files-lane `delete_old_logs` task runs at 03:00,
database-lane `delete_old_database_logs` at 03:05, storage-lane
`delete_old_storage_logs` at 03:10, and `CoreLog` database-row pruning separately at
03:30, all according to `LOG_RETENTION_DAYS`.

The self-hosted build does not provide the old SaaS transfer-log/directory-tree download
artifacts. Use the console status, activity log, local volume and container logs instead.

Centralize container logs before their local retention/rotation window expires. Redact:

- `.env`, API tokens and authorization headers;
- database/SSH passwords and private keys;
- signed download URLs and OAuth codes;
- raw provider responses that can contain account/resource details;
- archive contents, SQL dumps and customer filenames when not required.

## Sentry

Set `SENTRY_DSN` to enable the initialized Django integration. `DJANGO_SERVER` becomes the
Sentry environment tag. Transaction tracing and profiling both default to `0` (off). An
operator may explicitly set `SENTRY_TRACES_SAMPLE_RATE` or `SENTRY_PROFILES_SAMPLE_RATE`
to a value from `0` to `1`, after evaluating volume, cost, data handling and retention in
the Sentry project. Invalid or out-of-range values stop application startup.

BackupSheep configures Sentry to omit request bodies, Python local variables and default
PII. A final event scrubber removes credentials, cookies, query strings, raw exception
messages, breadcrumbs, span data and credential-bearing URLs from both error and
transaction events. Do not put secrets into custom Sentry tags; telemetry is not an
approved secret store.

An empty DSN disables event delivery. Sentry does not replace queue, capacity, provider or
restore monitoring.

## Capacity monitoring

Monitor the host filesystems underlying every named volume:

- `pgdata`: free bytes, database size, connections, locks, transaction age and backup age;
- `rabbitmq_data`: free bytes, memory/disk alarms, messages and consumer count;
- `database_workdir`: free bytes/inodes and growth of database dumps/restores/run logs;
- `files_workdir`: free bytes/inodes and growth of file-source work, website caches and logs;
- `storage_workdir`: free bytes/inodes and BSE1 upload/restore materialization;
- `database_ciphertext_transfer`, `files_ciphertext_transfer` and
  `restore_ciphertext_transfer`: published handoff bytes/inodes and stuck fences;
- `backup_storage`: retained BSE1 archive bytes/inodes and projected exhaustion date;
- Docker data root: image/build-cache growth and container writable layers.

Useful local snapshots:

```bash
./backupsheep-compose stats --no-stream
docker system df
for service in worker-database worker-files worker-storage; do
  container="$(./backupsheep-compose --profile operations ps -q "${service}")"
  test -z "${container}" || docker inspect "${container}" \
    --format '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}'
done
```

`docker system df` is diagnostic. Do not automatically prune volumes or image data without
resolving exact ownership and rollback requirements.

## Suggested alert thresholds

Tune thresholds from real job duration and capacity, but start with:

| Condition | Initial severity |
| --- | --- |
| Public HTTPS or app liveness fails twice | Critical |
| PostgreSQL/RabbitMQ unavailable | Critical |
| Any required worker queue has no consumer | Critical |
| Filesystem free space below 15% or projected exhaustion before next maintenance window | Warning/Critical |
| `manual_review` reconciliation | Critical operator review |
| Failed backup/restore | Warning, critical for recovery-objective breach |
| Queue depth rises continuously for 15 minutes | Warning |
| `migrate` exits non-zero after deployment | Critical, keep new app closed |
| Last verified control-plane dump or restore rehearsal exceeds policy | Critical governance breach |

## Synthetic recovery monitoring

The strongest operational signal is a scheduled rehearsal that:

1. backs up a disposable source with a known marker;
2. waits for every required destination to complete;
3. restores to a new disposable target;
4. verifies the marker/data independently;
5. records exact provider and BackupSheep identities;
6. cleans up only resources created by that rehearsal.

Do not run destructive live harnesses against existing resources. Use dedicated test
accounts/projects, exact prefixes/tags and explicit cleanup ledgers.
