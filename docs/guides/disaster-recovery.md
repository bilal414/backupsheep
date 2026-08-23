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
| `.env` / secret-manager object | Django signing/email key, DB/broker credentials, OAuth app secrets and runtime settings | Encrypted secret backup with tightly audited access |
| Deployment metadata | Exact Git revision/image, Compose overrides, proxy and firewall configuration | Versioned infrastructure repository or encrypted configuration backup |
| `backup_storage` | Archives stored by the Local Storage destination | Filesystem snapshot/backup to a second system; never the only archive copy |
| Critical `backup_workdir` files | In-flight material, website cache, reviewed SSH `known_hosts`, optional managed key and install token | Back up trust/key material; snapshot active work if preserving in-progress local jobs is required |
| Remote storage/provider state | Cloud snapshots and offsite archive objects live outside the host | Provider-native protection, independent inventory and restore rehearsal |

RabbitMQ persists queued messages in `rabbitmq_data`, but broker state is not the product
source of truth. The database outbox and recovery sweeps can republish durable work. Prefer
a clean compatible broker during disaster recovery unless you have a tested,
application-consistent broker-volume restore procedure.

## Back up the control plane

### 1. Create a PostgreSQL dump

Run from the Compose directory and write directly to a protected filesystem:

```bash
umask 077
docker compose exec -T db sh -c \
  'pg_dump --format=custom --no-owner --username="$POSTGRES_USER" "$POSTGRES_DB"' \
  > /secure/backups/backupsheep-control-plane.dump
```

Verify that the custom archive is readable:

```bash
docker compose exec -T db pg_restore --list \
  < /secure/backups/backupsheep-control-plane.dump > /dev/null
```

This validates archive structure, not a full restore. Periodically restore it into an
isolated PostgreSQL instance and run application checks against the restored copy.

For a managed database, use the provider's snapshot/PITR service plus independent logical
dumps. Validate retention, encryption, account isolation and restore permissions.

### 2. Copy configuration without displaying it

```bash
install -m 600 .env /secure/backups/backupsheep.env
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
docker inspect "$(docker compose ps -q app)" \
  --format '{{range .Mounts}}{{println .Name "->" .Destination}}{{end}}'
```

Use an existing filesystem/volume backup product to protect the exact source behind
`/backups`. If Local Storage uses a bind-mounted disk, snapshot or back up that disk with
file metadata intact.

For an application-consistent snapshot of active work material:

1. stop Beat so new schedules are not dispatched;
2. let active database/file/storage/restore work drain;
3. stop `app` and all workers;
4. snapshot/copy `backup_workdir` and `backup_storage`;
5. restart the stack and verify recovery.

At minimum, separately retain reviewed `ssh_known_hosts` and any managed SSH private key.
Website incremental caches can rebuild, but a missing in-flight dump may require the
durable backup row to retry from its safe boundary.

## Restore to a replacement host

Use a disposable recovery environment first. Avoid pointing a rehearsal at existing
production provider resources.

### 1. Prepare matching software and storage

- install Docker Engine/Compose on a supported host;
- check out the recorded BackupSheep revision (or a reviewed compatible newer release);
- restore `.env` with mode `0600` and restore deployment overrides;
- recreate/mount the Local Storage and work filesystems at the same container paths;
- keep the public endpoint isolated until the database is restored and the first owner is
  confirmed.

### 2. Start only the database and broker

```bash
docker compose up --detach db rabbitmq
docker compose exec -T db pg_isready -U backupsheep -d backupsheep
docker compose exec -T rabbitmq rabbitmq-diagnostics -q ping
```

The target database must be disposable/empty or explicitly approved for replacement.
Take a final safety dump of any database that already exists before proceeding.

### 3. Restore PostgreSQL

With application services stopped:

```bash
docker compose exec -T db sh -c \
  'pg_restore --clean --if-exists --no-owner --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"' \
  < /secure/backups/backupsheep-control-plane.dump
```

`--clean` modifies the target database. Resolve the exact target host/database first and
never run this against an unverified database.

### 4. Start the application

```bash
docker compose up --build --detach --remove-orphans
docker compose ps --all
docker compose logs --tail=200 migrate app
docker compose exec -T app python manage.py check
```

Forward migrations run automatically if the recovery code is newer than the dump. Do not
attempt to restore a newer schema into older application code.

### 5. Validate before reopening access

Verify:

- the expected account owner and members exist;
- application identity, email, groups and permissions are intact;
- source connections, storage destinations, schedules and retention policies match the
  recovery record;
- Local Storage files are present and download through their recorded backup rows;
- reviewed SSH trust/key files exist with restrictive permissions;
- `app`, PostgreSQL, RabbitMQ and every worker lane are healthy;
- existing in-progress rows resume or reach a clear manual-review state;
- a disposable backup and restore completes with data-level verification.

Only then update DNS/load balancer routing or reopen the firewall.

## Lost secrets

### Lost `DJANGO_SECRET_KEY`

Sessions become invalid and saved email-provider credentials cannot be decrypted. Restore
the exact key from the encrypted configuration backup. If it cannot be recovered, set a
new key, reset access from the host and re-enter email credentials; do not claim full
configuration recovery until every dependent secret is revalidated.

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
