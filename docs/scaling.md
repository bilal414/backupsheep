# Scaling & operations

One Docker image runs as several services, each draining a specific Celery queue, so heavy
work can't starve the web UI. Queue routing lives in `backupsheep/settings.py`
(`CELERY_TASK_ROUTES`); the service definitions are in `docker-compose.yml`.

## The services and their queues

| Service | Queue(s) | Work | Scaling |
|---------|----------|------|---------|
| `app` | — | Web console (gunicorn :8000) | Stateless; scale behind a load balancer if needed |
| `worker-cloud` | `cloud`, `default` | API-only provider snapshots plus general default-queue work | Stateless — **safe to scale horizontally**; concurrency can run high (just waits on provider HTTP) |
| `worker-database` | `database` | `pg_dump` / `mysqldump` dumps | CPU/disk heavy; low concurrency |
| `worker-files` | `files` | Website / WordPress / Basecamp file dumps | CPU/disk heavy; low concurrency |
| `worker-storage` | `storage` | Uploads finished dumps, finalizes/cleans artifacts, resets incremental caches and prunes on-disk run logs | **Scale this for upload/cleanup throughput** |
| `worker-logs` | `logs` | DB activity-log entries, Slack/Telegram/Firebase notifications and DB-log pruning; no staging mount | Scale if log/notification volume is high |
| `beat` | — | Fires scheduled backups + daily log pruning | **Singleton — keep exactly one** |

## Scaling rules

**Scale the upload pool** when uploads are the bottleneck:

```bash
./backupsheep-compose --profile operations up -d --scale worker-storage=4
```

All workers and Beat are in the explicit `operations` profile. A profile-less `up` starts
only the non-mutating core and cannot execute backups, restores or scheduled provider work.

**Never run more than one `beat`.** Two schedulers make every scheduled backup (and the
daily log-pruning jobs) fire twice.

**Only disk-touching workers share the staging volume.** `worker-database`,
`worker-files` and `worker-storage` mount `backup_workdir` read/write so the upload worker
can see each dump a source worker produced. The app, `worker-cloud`, `worker-logs` and Beat
do not mount it. `reset_incremental_cache` takes the per-node incremental lock and performs
directory-FD-confined deletion in storage; on-disk `delete_old_logs` is routed there too.
The separate `ssh_trust` store is app read/write and database/files read-only; the optional
managed-key source is granted only to those three roles and is copied into each role's
private tmpfs before use. On a **single host** Docker named volumes supply shared bytes.
Across **multiple hosts**, `backup_workdir` **must** be a shared network filesystem
(NFS/EFS) with the same role-specific access policy so replicas see each other's
in-progress files; manage SSH trust and per-host key delivery separately.

## Concurrency

The stock single-host concurrency is cloud `4`, database `1`, files `1`, storage `2`, and
logs `2`, with a prefetch multiplier of `1` for every queue. The values are configurable
through `CELERY_<QUEUE>_CONCURRENCY` and
`CELERY_<QUEUE>_PREFETCH_MULTIPLIER`; `.env_sample` and the Compose fallbacks intentionally
match.

The minimum supported stock host has 2 vCPU, 4 GB RAM, 8 GB of SSD-backed swap, and
SSD/NVMe-backed work and Local Storage volumes. Keep the stock limits on that profile.
They allow one database job, one files job, and two storage jobs to use the shared disk
at once while excess lane-specific work stays durably queued. Cloud and log processes
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

- `delete_old_logs` runs daily at 03:00 (worker timezone) via Beat and is routed to
  `worker-storage`, pruning run logs older than `LOG_RETENTION_DAYS` from local disk.
- `delete_old_db_logs` runs daily at 03:30 (worker timezone) via beat, pruning activity-log
  (`CoreLog`) rows older than `LOG_RETENTION_DAYS` from the database.
- Scheduled backups are stored in `django_celery_beat`'s database tables and atomically
  reserved by `BackupDatabaseScheduler` on Beat startup/ticks.

## Health & restarts

`db`, `rabbitmq`, and `app` have healthchecks; long-running services use
`restart: unless-stopped`, while the one-shot `migrate` and `preflight` gates use
`restart: "no"`.
The Compose RabbitMQ service uses the persistent `rabbitmq_data` volume, so queued
backup messages survive a broker/container recreation. Keep that volume and the
PostgreSQL volume when upgrading; deleting either is a data-loss operation.
The one-shot `migrate` service runs to completion on every `up` (idempotent), then the
one-shot security `preflight` must pass before the app or any operations-profile service
starts. The image entrypoint repeats that preflight before every web, worker and Beat
process, including a later automatic restart after the one-shot gate has exited. This
prevents serving or working against a weakened runtime; preflight also rejects any
unapplied Django migration.

Queue lanes are an availability and mount boundary, not broker authorization. Stock roles
share a RabbitMQ principal/vhost, leaving a High residual cross-role command-relay risk if
one broker-connected role is compromised. Do not treat scale-out queue names as a
security sandbox.
