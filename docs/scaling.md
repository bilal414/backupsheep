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
| `worker-logs` | `logs` | DB log entries, Slack/Telegram/Firebase notifications, on-disk log pruning | Scale if log/notification volume is high |
| `beat` | — | Fires scheduled backups + daily log pruning | **Singleton — keep exactly one** |

## Scaling rules

**Scale the upload pool** when uploads are the bottleneck:

```bash
docker compose up -d --scale worker-storage=4
```

**Never run more than one `beat`.** Two schedulers make every scheduled backup (and the
daily `delete_old_logs` job) fire twice.

**The disk-touching workers share a volume.** `worker-database`, `worker-files`,
`worker-storage`, and `worker-logs` all mount the `backup_workdir` volume so the upload
worker can see the dump a dump-worker produced. On a **single host** this just works and
you can `--scale` any of them. Across **multiple hosts**, `backup_workdir` **must** be a
shared network filesystem (NFS/EFS) so replicas see each other's in-progress files.

## Concurrency

Each worker's `--concurrency` is set in `docker-compose.yml` (cloud 8, the rest 4). Tune
per host: raise `worker-cloud` (I/O-bound on provider APIs) freely; keep
`worker-database`/`worker-files` modest (CPU/disk-bound).

## Maintenance tasks

- `delete_old_logs` runs daily at 03:00 (worker timezone) via beat, pruning run logs older
  than `LOG_RETENTION_DAYS` from local disk.
- Scheduled backups are stored in `django_celery_beat`'s database tables and synced by the
  `DatabaseScheduler` on beat startup.

## Health & restarts

`db`, `redis`, and `app` have healthchecks; all services use `restart: unless-stopped`.
The one-shot `migrate` service runs to completion on every `up` (idempotent) before the
app/workers/beat start, so they never serve an unmigrated schema.
