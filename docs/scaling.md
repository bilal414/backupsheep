# Scaling & operations

One Docker image runs as several services, each draining a specific Celery queue, so heavy
work can't starve the web UI. Queue routing lives in `backupsheep/settings.py`
(`CELERY_TASK_ROUTES`); the service definitions are in `docker-compose.yml`.

## The services and their queues

| Service | Queue(s) | Work | Scaling |
|---------|----------|------|---------|
| `app` | — | Web console (gunicorn :8000) | Stateless; scale behind a load balancer if needed |
| `worker-cloud` | `cloud`, `default` | API-only provider snapshots plus general default-queue work | Stateless — **safe to scale horizontally**; concurrency can run high (just waits on provider HTTP) |
| `worker-database` | `database` | `pg_dump` / `mysqldump` dumps, restores and database run-log pruning | CPU/disk heavy; low concurrency |
| `worker-files` | `files` | Website / Basecamp work, incremental-cache reset and files run-log pruning | CPU/disk heavy; low concurrency |
| `worker-storage` | `storage` | Uploads BSE1 artifacts, downloads restore ciphertext, finalizes storage state and prunes destination-upload run logs | **Scale this for measured transfer throughput** |
| `worker-logs` | `logs` | DB activity-log entries, Slack/Telegram/Firebase notifications and DB-log pruning; no staging mount | Scale if log/notification volume is high |
| `beat` | — | Fires scheduled backups and lane-specific maintenance | **Singleton — keep exactly one** |

## Scaling rules

**Scale the upload pool** when uploads are the bottleneck:

```bash
./backupsheep-compose --profile operations up --detach --no-build --no-deps \
  --force-recreate --scale worker-storage=4 \
  storage-egress-guard worker-storage
```

Scaling force-recreates the storage guard/workload namespace pair. Drain or reconcile
active storage work and verify durable state before running it. Broad or worker-only
`up --scale` is refused after a pair exists.

All workers and Beat are in the explicit `operations` profile. A profile-less `up` starts
only the non-mutating core and cannot execute backups, restores or scheduled provider work.

**Never run more than one `beat`.** Two schedulers make every scheduled backup (and the
daily log-pruning jobs) fire twice.

**Disk lanes do not share plaintext staging.** `worker-database`, `worker-files` and
`worker-storage` each mount a different mode-`0700` private work volume. Database/files
publish only fenced BSE1 bytes through separate source-writable, storage-read-only transfer
volumes. Storage publishes restore ciphertext through a reverse transfer whose reader
groups are lane-specific. Only storage mounts `/backups`. App, cloud, logs and Beat mount no
work, transfer or Local Storage volume. `reset_incremental_cache` and files run-log pruning
stay in the files lane; database run-log pruning stays in the database lane; destination-
upload run-log pruning stays in the storage lane.

SSH approvals and append-only audit events are account-scoped PostgreSQL state. Each
database/files operation receives only its exact approved trust material in a transient
private-runtime file. Optional database/files Ed25519 identities are distinct and each
private source is granted only to its matching worker; the app receives neither. Stock
Compose is single-host. A separately reviewed multi-host orchestrator must preserve every
private work store and one-way/lane-fenced transfer boundary; do not replace them with one
shared NFS/EFS plaintext work directory.

## Concurrency

The stock single-host concurrency is cloud `4`, database `1`, files `1`, storage `2`, and
logs `2`, with a prefetch multiplier of `1` for every queue. The values are configurable
through `CELERY_<QUEUE>_CONCURRENCY` and
`CELERY_<QUEUE>_PREFETCH_MULTIPLIER`; `.env_sample` and the Compose fallbacks intentionally
match.

The minimum supported stock host has 2 vCPU, 4 GB RAM, 8 GB of SSD-backed swap, and
SSD/NVMe-backed work and Local Storage volumes. Keep the stock limits on that profile.
They allow one database job, one files job, and two storage jobs to use their bounded
lane volumes on the same host at once while excess work stays durably queued. Cloud and log processes
remain independently bounded so they cannot reserve a large hidden backlog.

The minimum-profile acceptance target during that four-lane disk workload is:

- no kernel/container OOM and no worker restart;
- every web probe returns HTTP 200;
- signed-in console p95 latency is at most 1 second;
- `/healthz/` p95 latency is at most 100 milliseconds;
- accepted excess work remains visible and drains without duplication when capacity is
  available.

Treat sustained swap I/O, queue growth, or latency above these targets as an undersized
host. Upgrade the host or reduce concurrency before increasing a queue. On a larger
profile, change one lane at a time and repeat the same workload, queue, OOM, and latency
measurements. Scaling a Compose service multiplies that service's configured concurrency.

## Maintenance tasks

- `delete_old_logs` runs daily at 03:00 (worker timezone) in `worker-files`, pruning that
  lane's run logs older than `LOG_RETENTION_DAYS`.
- `delete_old_database_logs` runs daily at 03:05 in `worker-database`, pruning database
  run logs from its private work volume.
- `delete_old_storage_logs` runs daily at 03:10 in `worker-storage`, pruning destination-
  upload run logs from its private work volume.
- `delete_old_db_logs` runs daily at 03:30 (worker timezone) via beat, pruning activity-log
  (`CoreLog`) rows older than `LOG_RETENTION_DAYS` from the database.
- Scheduled backups are stored in `django_celery_beat`'s database tables and atomically
  reserved by `BackupDatabaseScheduler` on Beat startup/ticks.

## Health & restarts

`db`, `rabbitmq`, every guard and every egress-sharing workload have healthchecks.
Long-running application services use `restart: unless-stopped`; guards and all
provision/migrate/seal/preflight one-shots use `restart: "no"`. Workload health proves
local readiness plus fresh database/broker connections through the guard's current sets.
Before every installer build or migration, `install.sh` removes the complete container/
network topology with ordinary `down` while preserving named volumes. An operations pause
stops workers and Beat but leaves the no-secret guards in place; a lost guard requires
exact paired recreation.
The Compose RabbitMQ service uses the persistent `rabbitmq_data` volume, so queued
backup messages survive a broker/container recreation. Keep that volume and the
PostgreSQL volume when upgrading; deleting either is a data-loss operation.
The installer runs the one-shot `migrate` service to completion on each controlled
rollout, then the one-shot security `preflight` must pass before the app or any
operations-profile service starts. The image entrypoint repeats that preflight before every web, worker and Beat
process, including a later automatic restart after the one-shot gate has exited. This
prevents serving or working against a weakened runtime; preflight also rejects any
unapplied Django migration.

Queue lanes alone are not broker authorization. Stock roles use separate RabbitMQ
principals/fixed queue ACLs and lane-bound signed task envelopes with replay tracking.
Preserve those controls while scaling: do not broaden a worker's queues, reuse a principal
or signing key, or introduce an unsigned compatibility path.
