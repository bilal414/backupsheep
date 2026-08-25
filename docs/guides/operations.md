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
- capacity trends for Local Storage, three private work volumes and ciphertext transfers;
- recent authentication, connection, schedule, storage and restore activity.

The public `execution_status` API shape exposes durable status, phase, retry time,
attempts, progress, artifact evidence, provider status and reconciliation state without
returning raw provider responses. Use that durable view—not Celery's result backend—as the
job truth.

## Start, stop and inspect

Use the exact-ref installer for first creation or after a whole-stack `down`. For an
existing installation whose database, broker and one-shot gates are already healthy,
build the exact checked-out source and force-recreate the web/guard pair. The application,
database and egress-guard service families set `pull_policy: never`, so Compose will not
silently substitute a registry image when a reviewed local image is missing:

```bash
cd /opt/backupsheep
./backupsheep-compose build db app app-egress-guard
./backupsheep-compose up --detach --no-build --no-deps --force-recreate \
  app-egress-guard app
./backupsheep-compose ps --all
./backupsheep-compose logs --tail=100 \
  rabbitmq-volume-init rabbitmq-provision staging-provision \
  db-provision migrate db-seal preflight app-egress-guard app
```

That paired recovery changes only the existing web namespace. It is not a substitute for
first-boot provisioning, migrations or recovery after `down`; rerun the verified
installer for those paths. After reviewing
credentials and durable queue/recovery state, explicitly start the provider-mutating
workers and singleton scheduler:

```bash
./backupsheep-compose --profile operations up --detach --no-build --no-deps \
  --force-recreate \
  cloud-egress-guard database-egress-guard files-egress-guard \
  storage-egress-guard logs-egress-guard \
  worker-cloud worker-database worker-files worker-storage worker-logs
./backupsheep-compose --profile operations up --detach --no-build --no-deps beat
./backupsheep-compose --profile operations ps --all
```

Do not enable the profile merely to make every container green. It can resume queued or
recoverable provider work. Installer-managed installations should normally use the same
exact-commit `install.sh --ref ... --enable-operations` command used at installation.

Operations workers and Beat use `restart: unless-stopped`; namespace guards use
`restart: "no"`. The wrapper refuses independent guard lifecycle commands and recreates a
workload/guard pair together. To pause provider execution while leaving the core
available, stop the exact set explicitly:

```bash
./backupsheep-compose --profile operations stop \
  worker-cloud worker-database worker-files worker-storage worker-logs beat
```

An explicit Docker stop suppresses application-service automatic restart until the
reviewed operations opt-in. No-secret guards remain in place during a provider pause.
Before every build or migration, the installer instead removes the complete topology with
ordinary `down` while preserving named volumes. If Docker later restarts an enabled
application service, its entrypoint reruns deployment preflight, but it cannot restart or
attest the `restart: "no"` guard. After a Docker daemon restart or guard loss, use the
exact paired recovery command before returning that worker to service.

Follow all service logs:

```bash
./backupsheep-compose --profile operations logs --follow --tail=200
```

Follow only an execution lane:

```bash
./backupsheep-compose --profile operations logs --follow --tail=200 worker-database worker-storage
```

Stop the stack without deleting volumes:

```bash
./backupsheep-compose --profile operations down --timeout 300
```

Including the profile removes the complete container/network topology together so no
guard is stopped independently of its namespace-sharing workload. Ordinary `down`
retains named volumes. Never add `--volumes` during routine operation; it removes PostgreSQL, broker,
private/legacy work, ciphertext-transfer, layout-witness and Local Storage data plus the
installation-identity sentinel.

### Control-plane mutation lock

`install.sh` and `backupsheep-compose` share one atomic, owner-only sidecar directory:
`${INSTALL_DIR}.backupsheep-mutation-lock`. Every real wrapper mutation holds it from the
last pre-mutation validation until the Docker command returns; the installer holds it for
its complete validation/build/start transaction. This prevents two operator terminals
from both passing the one-off/guard inventory before either changes the topology. Read-only
commands such as `config`, `ps`, `logs` and `top`, plus structural `--dry-run`, remain
concurrent.

`SIGKILL`, power loss or a filesystem failure can leave the directory behind. That is a
fail-closed condition: neither tool trusts the recorded PID enough to reap it automatically.
First use trusted host process and change-window evidence to prove that no `install.sh` or
`backupsheep-compose` mutation is still active. Inspect the exact owner witness, then remove
only that file and its now-empty directory:

```bash
INSTALL_DIR=/opt/backupsheep
LOCK="${INSTALL_DIR}.backupsheep-mutation-lock"
test -f "${LOCK}/owner" && cat "${LOCK}/owner"
# Only after independent proof that the recorded operation is no longer active:
rm -- "${LOCK}/owner"
rmdir -- "${LOCK}"
```

Never recursively remove a broader parent path, and never clear the lock merely because
its recorded PID is absent or appears reused.

## Dependency checks

```bash
curl -fsS http://127.0.0.1:8000/healthz/
DB_CONTAINER="$(./backupsheep-compose ps -q db)"
test -n "${DB_CONTAINER}"
test "$(docker inspect --format '{{.State.Health.Status}}' "${DB_CONTAINER}")" = healthy
./backupsheep-compose exec -T rabbitmq rabbitmq-diagnostics -q ping
```

The stock database healthcheck authenticates over TCP with its file-backed bootstrap
credential and executes `SELECT 1`; do not substitute unauthenticated `pg_isready`.

The health URL returns static `ok` and is liveness only. PostgreSQL, RabbitMQ and worker
checks are separate. When operations are intentionally enabled, add:

```bash
./backupsheep-compose --profile operations exec -T worker-cloud celery -A backupsheep inspect ping
```

To inspect queue pressure:

```bash
./backupsheep-compose exec -T rabbitmq \
  rabbitmqctl list_queues name messages_ready messages_unacknowledged consumers durable
```

To inspect Celery work across all connected workers:

```bash
./backupsheep-compose --profile operations exec -T worker-cloud celery -A backupsheep inspect active
./backupsheep-compose --profile operations exec -T worker-cloud celery -A backupsheep inspect reserved
./backupsheep-compose --profile operations exec -T worker-cloud celery -A backupsheep inspect scheduled
```

Celery inspection is transient diagnostic evidence. A missing task there does not mean a
backup row is complete or lost.

## Planned maintenance

1. Announce the window and prevent new user-triggered work if required.
2. Pause schedules in the console, or stop Beat:

   ```bash
   ./backupsheep-compose stop beat
   ```

3. Check active/reserved/scheduled tasks and the console's active backup/restore rows.
4. Allow long provider mutations, dumps, uploads and restores to reach a safe terminal
   state when the maintenance objective permits.
5. Back up the database and configuration.
6. Apply the host/application change.
7. Start the complete stack and verify migrations, dependencies and workers.
8. Re-enable schedules/Beat and watch the first recovery sweep and scheduled run.

For an existing stock stack, "complete" means force-recreating all five exact
guard/worker pairs and then starting Beat with the commands above. Broad or workload-only
`up` is refused after any pair exists.

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
| Website/WordPress/Basecamp waits | `worker-files`, work volume, source network/account-scoped SSH approval | Fix source/approval/capacity, then observe retry |
| Completed dump is not offsite | `worker-storage`, `storage` queue, destination validation | Restore upload capacity/credentials; do not delete the work artifact |
| Logs/notifications lag | `worker-logs`, `logs` queue, email/channel provider | Scale or repair that lane; backup execution can continue independently |

Scale storage workers when uploads are the measured bottleneck:

```bash
./backupsheep-compose --profile operations up --detach --no-build --no-deps \
  --force-recreate --scale worker-storage=4 \
  storage-egress-guard worker-storage
```

Keep CPU/disk-bound database and file concurrency conservative.

## Log retention and maintenance

Beat dispatches:

- files run-log pruning at 03:00 UTC, database run-log pruning at 03:05 UTC and
  destination-upload run-log pruning at 03:10 UTC, each in its private worker lane;
- database `CoreLog` activity-row pruning at 03:30 UTC;
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
  ./backupsheep-compose run --rm --no-deps app python manage.py changepassword user@example.com
  ```

- Create a separate Django superuser only for `/django-admin/`:

  ```bash
  ./backupsheep-compose run --rm --no-deps app python manage.py createsuperuser
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
