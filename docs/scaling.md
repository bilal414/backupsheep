# Scaling & operations

One Docker image runs as several services, each draining a specific Celery queue, so heavy
work can't starve the web UI. Queue routing lives in `backupsheep/settings.py`
(`CELERY_TASK_ROUTES`); the service definitions are in `docker-compose.yml`.

## The services and their queues

| Service | Queue(s) | Work | Scaling |
|---------|----------|------|---------|
| `app` | — | Web console (gunicorn :8000) | Stateless; scale behind a load balancer if needed |
| `worker-cloud` | `cloud`, `default` | API-only provider snapshots + general/notification fallback | Stateless — **safe to scale horizontally**; concurrency can run high (just waits on provider HTTP) |
| `worker-database` | `database` | `pg_dump` / `mysqldump` dumps | CPU/disk heavy; low concurrency |
| `worker-files` | `files` | Website / WordPress / Basecamp file dumps | CPU/disk heavy; low concurrency |
| `worker-storage` | `storage` | Uploads each finished dump to storage + cleanup | **Scale this for upload throughput** |
| `worker-logs` | `logs` | DB activity-log entries, Slack/Telegram/Firebase notifications, on-disk + DB log pruning | Scale if log/notification volume is high |
| `beat` | — | Fires scheduled backups + daily log pruning | **Singleton — keep exactly one** |

## Scaling rules

**Scale the upload pool** when uploads are the bottleneck:

```bash
docker compose up -d --scale worker-storage=4
```

**Never run more than one `beat`.** Two schedulers make every scheduled backup (and the
daily log-pruning jobs) fire twice.

**The disk-touching workers share a volume.** `worker-database`, `worker-files`,
`worker-storage`, and `worker-logs` all mount the `backup_workdir` volume so the upload
worker can see the dump a dump-worker produced. On a **single host** this just works and
you can `--scale` any of them. Across **multiple hosts**, `backup_workdir` **must** be a
shared network filesystem (NFS/EFS) so replicas see each other's in-progress files.

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

- `delete_old_logs` runs daily at 03:00 (worker timezone) via beat, pruning run logs older
  than `LOG_RETENTION_DAYS` from local disk.
- `delete_old_db_logs` runs daily at 03:30 (worker timezone) via beat, pruning activity-log
  (`CoreLog`) rows older than `LOG_RETENTION_DAYS` from the database.
- Scheduled backups are stored in `django_celery_beat`'s database tables and synced by the
  `DatabaseScheduler` on beat startup.

## Health & restarts

`db`, `rabbitmq`, and `app` have healthchecks; all services use `restart: unless-stopped`.
The Compose RabbitMQ service uses the persistent `rabbitmq_data` volume, so queued
backup messages survive a broker/container recreation. Keep that volume and the
PostgreSQL volume when upgrading; deleting either is a data-loss operation.
The one-shot `migrate` service runs to completion on every `up` (idempotent) before the
app/workers/beat start, so they never serve an unmigrated schema.
