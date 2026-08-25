# Disaster recovery

BackupSheep protects other systems, but it also has a control plane that must be backed up.
Losing its PostgreSQL database loses account relationships, encrypted credentials,
schedules, provider identities, durable execution records, storage mappings and recovery
evidence even when some remote snapshots or archive objects still exist.

## Define recovery objectives

Before selecting a backup method, define:

- control-plane RPO: how much schedule/execution/configuration history can be lost;
- control-plane RTO: how quickly the console and workers must return;
- archive RPO/RTO per source and destination;
- acceptable handling for work that was in progress at the failure;
- who can retrieve secrets and authorize provider mutations during recovery.

The recovery set must live outside the BackupSheep host and outside any single failure
domain it is intended to recover.

## What to protect

| Material | Why it matters | Recommended protection |
| --- | --- | --- |
| PostgreSQL | All product configuration, encrypted credentials, schedules, backup/restore rows and durable orchestration | Frequent logical dumps or managed-PostgreSQL PITR, encrypted off-host |
| `.env`, `.secrets` / secret-manager object | Runtime/integration settings plus the file-backed Django, DB, broker, onboarding and optional managed-SSH-key secrets | Encrypted secret backup with tightly audited access; preserve ownership and modes |
| Deployment metadata | Exact Git revision/image, Compose overrides, proxy and firewall configuration | Versioned infrastructure repository or encrypted configuration backup |
| `backup_storage` | Archives stored by the Local Storage destination | Filesystem snapshot/backup to a second system; never the only archive copy |
| Critical `backup_workdir` files | In-flight material, restore/run logs and website/database incremental caches | Snapshot active work if preserving in-progress local jobs is required |
| `ssh_trust` | Reviewed SSH `known_hosts` used by app/database/files | Back up independently and preserve out-of-band fingerprint evidence |
| Remote storage/provider state | Cloud snapshots and offsite archive objects live outside the host | Provider-native protection, independent inventory and restore rehearsal |

RabbitMQ persists queued messages in `rabbitmq_data`, but broker state is not the product
source of truth. The database outbox and recovery sweeps can republish durable work. Prefer
a clean compatible broker during disaster recovery unless you have a tested,
application-consistent broker-volume restore procedure.

## Pin the Compose control plane

Run every command below from the exact reviewed checkout. The shipped wrapper reads and
validates the preserved project witness in `.env`; keep this command array in the same
maintenance shell. It prevents ambient application, profile, Bake or orphan-removal
variables from redirecting a recovery command and refuses to silently ignore an override.

```bash
BS_COMPOSE=("$PWD/backupsheep-compose")
# After restoring and reviewing an override, add its exact path:
# BS_COMPOSE+=(--approved-compose-file "$PWD/docker-compose.override.yml")
bs_compose() { "${BS_COMPOSE[@]}" "$@"; }
bs_compose config --quiet
```

## Back up the control plane

### 1. Create a PostgreSQL dump

Run from the Compose directory and write directly to a protected filesystem:

```bash
umask 077
bs_compose exec -T db sh -c \
  'pg_dump --format=custom --no-owner --username="$POSTGRES_USER" "$POSTGRES_DB"' \
  > /secure/backups/backupsheep-control-plane.dump
```

Verify that the custom archive is readable:

```bash
bs_compose exec -T db pg_restore --list \
  < /secure/backups/backupsheep-control-plane.dump > /dev/null
```

This validates archive structure, not a full restore. Periodically restore it into an
isolated PostgreSQL instance and run application checks against the restored copy.

For a managed database, use the provider's snapshot/PITR service plus independent logical
dumps. Validate retention, encryption, account isolation and restore permissions.

### 2. Copy configuration without displaying it

```bash
install -m 600 .env /secure/backups/backupsheep.env
install -d -m 700 /secure/backups/backupsheep.secrets
for secret in django_secret_key db_bootstrap_password db_migrator_password \
  db_password rabbitmq_password onboarding_token ssh_managed_private_key; do
  install -m 400 ".secrets/${secret}" "/secure/backups/backupsheep.secrets/${secret}"
done
test ! -f docker-compose.override.yml || \
  install -m 600 docker-compose.override.yml /secure/backups/docker-compose.override.yml
git rev-parse HEAD > /secure/backups/backupsheep.git-revision
```

Also protect reverse-proxy, DNS, firewall and external-database/broker configuration. Do
not place the resulting directory in the repository.

### 3. Protect Local Storage and work material

Identify the exact mounted volumes and destinations instead of guessing Compose-generated
volume names:

```bash
for service in app worker-database worker-storage; do
  container="$(bs_compose --profile operations ps -q "${service}")"
  test -z "${container}" || docker inspect "${container}" \
    --format '{{range .Mounts}}{{println .Name "->" .Destination}}{{end}}'
done
```

Use an existing filesystem/volume backup product to protect the exact source behind
`/backups`. If Local Storage uses a bind-mounted disk, snapshot or back up that disk with
file metadata intact.

For an application-consistent snapshot of active work material:

1. stop Beat so new schedules are not dispatched;
2. let active database/file/storage/restore work drain;
3. stop `app` and all workers;
4. snapshot/copy `backup_workdir`, `ssh_trust` and `backup_storage`;
5. restart the stack and verify recovery.

At minimum, separately retain the `ssh_trust` volume and
`.secrets/ssh_managed_private_key`. The app has no `backup_workdir` mount; do not infer
work-volume protection from inspecting only its container. Website incremental caches can
rebuild, but a missing in-flight dump may require the
durable backup row to retry from its safe boundary.

## Restore to a replacement host

Use a disposable recovery environment first. Avoid pointing a rehearsal at existing
production provider resources.

### 1. Prepare matching software and storage

- provide operator-managed Docker Engine 28.0.0+ and Compose 2.33.1+ on a supported host;
- check out the recorded BackupSheep revision (or a reviewed compatible newer release);
- restore `.env` with mode `0600`, `.secrets` as mode `0700`, its six required
  owner-owned files and optional `ssh_managed_private_key` source as mode `0444`; an empty
  optional file means disabled; restore deployment overrides;
- recreate/mount the Local Storage, work and `ssh_trust` filesystems at the same container
  paths;
- keep the public endpoint isolated until the database is restored and the first owner is
  confirmed.

### 2. Start only the database and broker

Build the exact checked-out database and application images before either role is started.
The stock services use `pull_policy: never`; they will not fetch an unreviewed registry
substitute:

```bash
bs_compose build db app
bs_compose up --detach db rabbitmq
bs_compose exec -T db pg_isready -U backupsheep -d backupsheep
bs_compose exec -T rabbitmq rabbitmq-diagnostics -q ping
```

The target database must be disposable/empty or explicitly approved for replacement.
Take a final safety dump of any database that already exists before proceeding.

### 3. Restore PostgreSQL

With application services stopped:

```bash
bs_compose exec -T db sh -c \
  'pg_restore --clean --if-exists --no-owner --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"' \
  < /secure/backups/backupsheep-control-plane.dump
```

`--clean` modifies the target database. Resolve the exact target host/database first and
never run this against an unverified database.

### 4. Start the application

```bash
bs_compose up --detach
bs_compose ps --all
bs_compose logs --tail=200 db-provision migrate preflight app
bs_compose exec -T app python manage.py check
```

Forward migrations run automatically if the recovery code is newer than the dump. Do not
attempt to restore a newer schema into older application code.

This starts only the core. Keep workers and Beat disabled while inspecting restored
durable rows, provider identities and broker queues. Once recovery ownership is proven,
enable operations explicitly:

```bash
bs_compose --profile operations up --detach
```

That command can resume old provider mutations immediately.

### 5. Validate before reopening access

Verify:

- the expected account owner and members exist;
- application identity, email, groups and permissions are intact;
- source connections, storage destinations, schedules and retention policies match the
  recovery record;
- Local Storage files are present and download through their recorded backup rows;
- the app can write the restored `ssh_trust` file while database/files see it read-only;
- when configured, the managed-key source is not used directly: app/database/files stage
  the validated non-empty key in private tmpfs at
  `/run/backupsheep/ssh/managed_private_key`, mode `0600`, while other roles receive no key;
- `app`, PostgreSQL, RabbitMQ and every worker lane are healthy;
- existing in-progress rows resume or reach a clear manual-review state;
- a disposable backup and restore completes with data-level verification.

Only then update DNS/load balancer routing or reopen the firewall.

## Lost secrets

### Lost `DJANGO_SECRET_KEY`

Sessions become invalid and saved email-provider credentials cannot be decrypted. Restore
the exact `.secrets/django_secret_key` file from the encrypted configuration backup. If it
cannot be recovered, create a new key, reset access from the host and re-enter email
credentials; do not claim full configuration recovery until every dependent secret is
revalidated.

### Lost provider/account encryption material

Per-account keys live in PostgreSQL. A database copy without those rows cannot decrypt
stored connection/storage credentials. Reconnect providers with newly issued, narrowly
scoped credentials and rotate any credentials whose confidentiality is uncertain.

### Lost onboarding token

The token matters only before the first user is created. Once onboarding is complete, use
normal account/password recovery; do not reopen onboarding.

## Provider-resource reconciliation after recovery

Restored database state may lag provider state by the RPO. For any row that was active at
the backup timestamp:

1. identify the exact BackupSheep correlation, provider operation/resource ID and ownership
   marker;
2. inspect provider state read-only;
3. allow normal recovery/reconciliation to adopt the exact owned operation;
4. stop for manual review on zero, multiple or mismatched candidates;
5. never delete or mutate a resource based on name similarity alone.

## Recovery rehearsal record

At each rehearsal, record the dump timestamp, code revision, restored host/database,
configuration/volume artifacts, migration result, dependency checks, resumed job result,
provider backup/restore identities, data-level assertion and cleanup. A dump that has never
been restored is unverified recovery material.
