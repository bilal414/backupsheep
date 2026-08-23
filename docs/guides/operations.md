# Operations runbook

This runbook covers the stock Docker Compose deployment. Replace `/opt/backupsheep` with
the actual installation directory and run commands with the account that owns Docker
access.

## Daily operator view

Check the console for:

- active, retrying or failed backups and restores;
- reconciliation entries that require manual review;
- storage validation failures and incomplete destination copies;
- upcoming schedules and schedules that have stopped producing successful runs;
- capacity trends for Local Storage and the host work filesystem;
- recent authentication, connection, schedule, storage and restore activity.

The public `execution_status` API shape exposes durable status, phase, retry time,
attempts, progress, artifact evidence, provider status and reconciliation state without
returning raw provider responses. Use that durable view—not Celery's result backend—as the
job truth.

## Start, stop and inspect

```bash
cd /opt/backupsheep
docker compose up --detach
docker compose ps --all
docker compose logs --tail=100 app migrate
```

Follow all service logs:

```bash
docker compose logs --follow --tail=200
```

Follow only an execution lane:

```bash
docker compose logs --follow --tail=200 worker-database worker-storage
```

Stop the stack without deleting volumes:

```bash
docker compose stop
```

`docker compose down` removes containers and networks but normally retains named volumes.
Never add `--volumes` during routine operation; it removes PostgreSQL, broker, work and
Local Storage data.

## Dependency checks

```bash
curl -fsS http://127.0.0.1:8000/healthz/
docker compose exec -T db pg_isready -U backupsheep -d backupsheep
docker compose exec -T rabbitmq rabbitmq-diagnostics -q ping
docker compose exec -T worker-cloud celery -A backupsheep inspect ping
```

The health URL returns static `ok` and is liveness only. PostgreSQL, RabbitMQ and worker
checks are separate.

To inspect queue pressure:

```bash
docker compose exec -T rabbitmq \
  rabbitmqctl list_queues name messages_ready messages_unacknowledged consumers durable
```

To inspect Celery work across all connected workers:

```bash
docker compose exec -T worker-cloud celery -A backupsheep inspect active
docker compose exec -T worker-cloud celery -A backupsheep inspect reserved
docker compose exec -T worker-cloud celery -A backupsheep inspect scheduled
```

Celery inspection is transient diagnostic evidence. A missing task there does not mean a
backup row is complete or lost.

## Planned maintenance

1. Announce the window and prevent new user-triggered work if required.
2. Pause schedules in the console, or stop Beat:

   ```bash
   docker compose stop beat
   ```

3. Check active/reserved/scheduled tasks and the console's active backup/restore rows.
4. Allow long provider mutations, dumps, uploads and restores to reach a safe terminal
   state when the maintenance objective permits.
5. Back up the database and configuration.
6. Apply the host/application change.
7. Start the complete stack and verify migrations, dependencies and workers.
8. Re-enable schedules/Beat and watch the first recovery sweep and scheduled run.

If an urgent reboot interrupts work, do not manually trigger the same backup immediately.
RabbitMQ redelivery and the periodic database recovery tasks will resume durable requests,
backups and restores. Watch their existing rows and correlation IDs first.

## What survives a crash

The application commits a durable backup request before broker publication. Concrete
backup execution stores stable task/provider identities, renewable leases, progress,
errors and reconciliation state. Storage artifacts record object identity and integrity
metadata. Restore rows persist their own correlation, provider job/resource and progress.

Periodic Beat tasks run every minute to:

- republish pending backup requests;
- resume in-progress backups;
- resume in-progress restores;
- reconcile Oracle deletions;
- synchronize/resume Lightsail bucket replication and restore work.

RabbitMQ also uses persistent delivery and late task acknowledgements. This layered design
means duplicate delivery is expected and fenced. Operators should preserve the existing
database rows instead of deleting/recreating them to "unstick" work.

## Handling an apparently stuck job

1. Open its current API/console representation and record the correlation ID, status,
   phase, retry timestamp, provider status and reconciliation state.
2. Check the matching worker queue and service logs around that timestamp.
3. Check PostgreSQL, RabbitMQ, filesystem capacity and provider status pages/control plane.
4. Wait through the applicable retry/stale window when the row says retrying or
   reconciliation is in progress.
5. If it changes to `manual_review`, inspect the provider by exact resource/job ID and
   BackupSheep ownership marker. Do not create, delete or adopt a similarly named resource.
6. If intervention is necessary, preserve database and provider evidence and open a
   focused issue. Do not edit orchestration rows directly unless following a reviewed
   repair procedure for that exact version.

When the provider accepted a request but the response was lost, BackupSheep deliberately
reconciles before retrying. A manually repeated provider mutation can defeat that duplicate
guard.

## Queue-specific symptoms

| Symptom | Inspect | Typical action |
| --- | --- | --- |
| Provider snapshots wait | `worker-cloud`, `cloud`/`default` queues, provider API | Restore worker/broker connectivity; let durable polling resume |
| Database dumps wait | `worker-database`, disk, source network/client version | Free capacity or correct source connectivity; preserve the row for retry |
| Website/WordPress/Basecamp waits | `worker-files`, work volume, source network/SSH trust | Fix source/trust/capacity, then observe retry |
| Completed dump is not offsite | `worker-storage`, `storage` queue, destination validation | Restore upload capacity/credentials; do not delete the work artifact |
| Logs/notifications lag | `worker-logs`, `logs` queue, email/channel provider | Scale or repair that lane; backup execution can continue independently |

Scale storage workers when uploads are the measured bottleneck:

```bash
docker compose up --detach --scale worker-storage=4
```

Keep CPU/disk-bound database and file concurrency conservative.

## Log retention and maintenance

Beat dispatches:

- local run-log pruning at 03:00 UTC;
- database activity-log pruning at 03:30 UTC;
- retry of S3 Object Lock-protected deletes every six hours;
- durable request/backup/restore/replication recovery every minute.

The process timezone is UTC. User/member timezones affect presentation, while Celery's
configured timezone remains UTC. `LOG_RETENTION_DAYS` controls local run logs and database
activity entries.

## Account and access operations

- Invite additional console members; do not rerun onboarding.
- Use groups for permissions and optional node scoping. A group with no selected nodes has
  access to all nodes allowed by its permissions.
- Keep the primary account owner protected; it has full account access.
- Reset a console password from the host when email is unavailable:

  ```bash
  docker compose run --rm app python manage.py changepassword user@example.com
  ```

- Create a separate Django superuser only for `/django-admin/`:

  ```bash
  docker compose run --rm app python manage.py createsuperuser
  ```

## Routine evidence to retain

For each recovery-critical source, retain outside BackupSheep:

- the latest successful backup and storage-copy identities;
- the most recent restore-rehearsal result and data-level verification;
- configured retention and expected recovery objectives;
- any active manual-review correlation IDs;
- database/configuration backup verification;
- capacity and queue-alert history.

Continue with [Observability](observability.md), [Upgrades](upgrades.md) and
[Disaster recovery](disaster-recovery.md).
