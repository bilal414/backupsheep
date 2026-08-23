# Upgrades and rollback

Treat an application upgrade as a coordinated code, image and PostgreSQL schema change.
The `migrate` service automatically applies forward migrations before the new app, workers
and Beat start.

## Before the change

1. Read release notes and compare the exact current and target revisions.
2. Verify the checkout has no unexplained changes:

   ```bash
   cd /opt/backupsheep
   git status --short --branch
   git rev-parse HEAD
   ```

   Stop if the worktree is dirty or ownership of a file is unclear. Do not discard local
   overrides or user changes.

3. Record the target branch/tag/commit and the current image/configuration provenance.
4. Check the console for active backups, uploads, deletes and restores.
5. Pause schedules or stop Beat, then drain work when possible:

   ```bash
   docker compose stop beat
   docker compose exec -T worker-cloud celery -A backupsheep inspect active
   ```

6. Create and verify a PostgreSQL dump; copy `.env` and local Compose overrides to an
   encrypted recovery location. Back up Local Storage and critical work-volume material.
7. Confirm free disk for both old/new image layers and migration work.

See [Disaster recovery](disaster-recovery.md#back-up-the-control-plane) for the backup
commands.

## Upgrade the current branch

The server installer uses a shallow clone. For an ordinary fast-forward upgrade of the
currently checked-out branch:

```bash
git fetch origin
git pull --ff-only
git rev-parse HEAD
docker compose config --quiet
docker compose build app
docker compose up --detach --remove-orphans
```

Do not use an unpinned remote branch when your change process requires reproducibility.
Fetch and check out an reviewed release tag or commit instead.

## Verify the deployment

```bash
docker compose ps --all
docker compose logs --tail=200 migrate app
docker compose exec -T app python manage.py check
curl -fsS http://127.0.0.1:8000/healthz/
docker compose exec -T db pg_isready -U backupsheep -d backupsheep
docker compose exec -T rabbitmq rabbitmq-diagnostics -q ping
docker compose exec -T worker-cloud celery -A backupsheep inspect ping
```

Verify that `migrate` exited `0` and every expected worker answers. Then:

1. check login and the dashboard through the public HTTPS URL;
2. inspect existing schedules, storage and source records;
3. re-enable Beat/schedules;
4. observe recovery of any interrupted durable work;
5. run a disposable on-demand backup and restore rehearsal for affected providers;
6. keep the pre-upgrade recovery set until the observation window closes.

`/healthz/` returning `ok` is not a database, broker, worker or provider acceptance test.

## Configuration changes between versions

Compare the new `.env_sample` with the existing `.env` without printing secrets into logs.
Add new non-secret/default keys deliberately and preserve existing values. Because settings
also read `.env_sample` as defaults, a missing optional key may still boot, but that does
not mean its production default was reviewed.

Validate Compose with `docker compose config --quiet`; do not publish the expanded
configuration, which may contain credentials.

## Rollback

A container rollback alone is safe only when the older code supports the already-migrated
schema. Do not assume Django migrations are reversible or that an older application can
read a newer database.

The reliable rollback unit is:

- the previous code revision/image;
- its exact `.env` and deployment overrides;
- the pre-upgrade PostgreSQL dump;
- the matching Local Storage/work-volume state when the upgrade changed them.

For a migration-related rollback:

1. stop `app`, all workers and Beat;
2. preserve the failed-upgrade database and logs for diagnosis;
3. restore the pre-upgrade database into a clean/replacement instance;
4. check out/build the recorded previous revision;
5. restore matching configuration and volume data;
6. start the stack and perform the full dependency and recovery verification.

Do not run `migrate <app> <older-number>` against production merely to force a rollback;
data migrations and application changes may not have a safe reverse path.

## PostgreSQL major-version changes

The stock image currently uses PostgreSQL 18 and mounts `/var/lib/postgresql`, whose
versioned layout differs from older images. A major PostgreSQL change requires a logical
dump/restore or a supported `pg_upgrade` plan, not just changing the image tag against an
old data directory. Rehearse it on a copy and preserve the old volume until the new
database and restore tests pass.

## Upgrade completion record

Record:

- old and new commit/image identifiers;
- backup artifact names and verification results;
- migration exit and Django check result;
- dependency/worker health results;
- first successful backup and restore rehearsal after upgrade;
- any deferred provider or accessibility checks;
- rollback-set retention deadline.
