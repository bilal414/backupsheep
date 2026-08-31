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
| `.secrets/artifact_local_file_database_keyring` and `.secrets/artifact_local_file_files_keyring` | The distinct root keys required to unwrap every BSE1 database/files data key, including retained legacy keys | Back up the exact bytes, ownership and modes with PostgreSQL as one encrypted, access-audited cryptographic recovery set; never regenerate or substitute either file |
| `.env`, remaining `.secrets` / secret-manager object | Runtime/integration settings plus file-backed Django, DB, broker, signing, onboarding and optional lane-specific managed-SSH secrets | Encrypted secret backup with tightly audited access; preserve ownership and modes |
| Deployment metadata | Exact Git revision/image, Compose overrides, proxy and firewall configuration | Versioned infrastructure repository or encrypted configuration backup |
| `.backupsheep-backup-storage-identity` | Version-2 installation/project binding, canonical approved Local Storage bind path, separately pinned target device/inode and SHA-256 of only the trusted parent device/inode/owner/mode chain | Preserve the exact owner-only regular file with its override and storage snapshot; the same target inode may transition to storage-service UID `10004`, mode `0700`, but never edit or delete the ledger to authorize a new target |
| `backup_storage` | Archives stored by the Local Storage destination | Filesystem snapshot/backup to a second system; never the only archive copy |
| `database_workdir`, `files_workdir`, `storage_workdir` | Lane-private in-flight material, run logs, website caches and BSE1 materialization | Snapshot the exact lane volumes if preserving in-progress local jobs/caches is required |
| Database/files/restore ciphertext-transfer volumes | Published BSE1 handoffs that can be in flight across a crash | Include them in an application-consistent snapshot; preserve owner/group/mode metadata |
| `staging_layout_witness` | Installation-bound v3 filesystem-layout evidence | Preserve it with the exact volume identity; never synthesize or edit it |
| Remote storage/provider state | Cloud snapshots and offsite archive objects live outside the host | Provider-native protection, independent inventory and restore rehearsal |

SSH host-key approvals and their append-only audit events are part of PostgreSQL. Preserve
the independent fingerprint evidence used for each approval, but do not create or restore
a global `known_hosts` file for stock Compose.

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
for source in .secrets/*; do
  test -f "${source}" && test ! -L "${source}"
  secret="${source##*/}"
  install -m 400 "${source}" "/secure/backups/backupsheep.secrets/${secret}"
done
test ! -f docker-compose.override.yml || \
  install -m 600 docker-compose.override.yml /secure/backups/docker-compose.override.yml
git rev-parse HEAD > /secure/backups/backupsheep.git-revision
```

Also protect reverse-proxy, DNS, firewall and external-database/broker configuration. Do
not place the resulting directory in the repository.

The PostgreSQL dump and both exact artifact keyrings are one inseparable cryptographic
recovery set. PostgreSQL identifies each wrapping key and stores the authenticated data-key
wrap; only the matching lane keyring supplies that root key. Losing, replacing, pruning or
regenerating either keyring is irreversible for every retained artifact that references a
missing key, even when its ciphertext and the database both survive.
The files are exportable software keys rather than non-exportable HSM/KMS keys; protect
host access and every off-host copy as part of the custody boundary.

### 3. Protect Local Storage and work material

Identify the exact mounted volumes and destinations instead of guessing Compose-generated
volume names:

```bash
for service in worker-database worker-files worker-storage; do
  container="$(bs_compose --profile operations ps -q "${service}")"
  test -z "${container}" || docker inspect "${container}" \
    --format '{{range .Mounts}}{{println .Name "->" .Destination}}{{end}}'
done
```

Use an existing filesystem/volume backup product to protect the exact source behind the
storage worker's `/backups` mount. No other runtime role receives that mount. If Local
Storage uses a bind-mounted disk, snapshot or back up that disk with file metadata intact.

For an application-consistent snapshot of active work material:

1. stop Beat so new schedules are not dispatched;
2. let active database/file/storage/restore work drain;
3. stop `app` and all workers;
4. snapshot/copy the three private work volumes, all three ciphertext-transfer volumes,
   `staging_layout_witness`, `backup_storage`, its approved override and
   `.backupsheep-backup-storage-identity` as one recorded recovery set;
5. restart the stack and verify recovery.

At minimum, separately retain both optional lane-specific managed-key secret files when
they are configured. The app has no work, transfer or Local Storage mount; do not infer
data-volume protection from inspecting only its container. Website incremental caches can
rebuild, but a missing in-flight dump may require the durable backup row to retry from its
safe boundary. The legacy `backup_workdir` is provisioner-only emptiness evidence, not a
runtime volume to repopulate.

## Restore to a replacement host

Use a disposable recovery environment first. Avoid pointing a rehearsal at existing
production provider resources.

### 1. Prepare matching software and storage

- provide operator-managed Docker Engine 28.0.0+ and Compose 2.33.1+ on a supported host;
- check out the recorded BackupSheep revision (or a reviewed compatible newer release);
- restore `.env` with mode `0600` and `.secrets` as mode `0700`; restore the exact bytes of
  `artifact_local_file_database_keyring` and `artifact_local_file_files_keyring`, plus
  every other required owner-owned secret file and the two optional lane-specific
  managed-key sources, as mode `0444`; preserve the original owner and single-link
  metadata, and never generate a replacement for a missing artifact keyring; empty
  optional managed-key files mean disabled; restore deployment overrides;
- restore the original `BACKUPSHEEP_INSTALLATION_ID`; both keyring headers and every
  authenticated artifact context are bound to it, so generating a replacement ID makes
  the recovered keyrings intentionally unusable;
- restore the three private work volumes, three ciphertext-transfer volumes, staging
  witness and storage-only Local Storage with their exact identities and metadata; let the
  v3 provisioner validate them rather than adding cross-lane mounts;
- restore an approved-bind identity ledger only when the same canonical directory and
  device/inode are still present. A new host, remount, replacement directory or intentional
  storage move must use a separately named fresh project and authenticated restore; do not
  transplant, delete or edit the old ledger to make a different target appear unchanged;
- keep the public endpoint isolated until the database is restored and the first owner is
  confirmed.

### 2. Start only the database and broker

Build the exact checked-out database and application images before either role is started.
The stock services use `pull_policy: never`; they will not fetch an unreviewed registry
substitute:

```bash
bs_compose build db app app-egress-guard rabbitmq
bs_compose up --detach db rabbitmq
DB_CONTAINER="$(bs_compose ps -q db)"
test -n "${DB_CONTAINER}"
test "$(docker inspect --format '{{.State.Health.Status}}' "${DB_CONTAINER}")" = healthy
bs_compose exec -T rabbitmq rabbitmq-diagnostics -q ping
```

The stock database healthcheck authenticates over TCP with the exact file-backed bootstrap
credential and executes `SELECT 1`; a bare `pg_isready` result is not sufficient evidence.

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
# Valid here only because the replacement topology has no existing guard/workload pair.
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
bs_compose --profile operations up --detach --no-build --no-deps \
  --force-recreate \
  cloud-egress-guard database-egress-guard files-egress-guard \
  storage-egress-guard logs-egress-guard \
  worker-cloud worker-database worker-files worker-storage worker-logs
bs_compose --profile operations up --detach --no-build --no-deps beat
```

Those commands can resume old provider mutations immediately. After any pair exists,
broad, guard-only and workload-only `up` operations are refused; recovery must preserve
the exact [paired egress lifecycle](../../deploy/egress/README.md#paired-lifecycle-commands).

### 5. Validate before reopening access

Verify:

- the expected account owner and members exist;
- application identity, email, groups and permissions are intact;
- source connections, storage destinations, schedules and retention policies match the
  recovery record;
- Local Storage BSE1 objects are present, match their recorded storage-point evidence and
  complete an authenticated restore through the exact database/files reverse lane; direct
  browser/ZIP download remains disabled;
- each recovered BSE1 object is format v2, its random envelope UUID differs from the
  durable backup UUID, and its public header exposes neither the backup UUID nor the
  private plaintext/context digests; the decrypting lane must prove those digests from
  the encrypted terminal record before publishing plaintext;
- an isolated known database artifact unwraps only with the restored database keyring and
  a known files artifact unwraps only with the restored files keyring; swapping the two
  keyrings or crossing either lane is rejected before any plaintext is released;
- BSE1 sealing and isolated restore on each exact recovered worker mount succeeds under
  its real worker identity, proving Linux `O_TMPFILE` plus `linkat(AT_EMPTY_PATH)` support;
  verify the restored data digest/content rather than accepting container health or task
  completion as filesystem/recovery proof;
- account-scoped SSH approvals and append-only approval events are present in PostgreSQL;
  an operation receives only its exact current approval in a transient private-runtime
  file, and unknown or changed keys remain rejected;
- when configured, `worker-database` alone stages the database identity and `worker-files`
  alone stages the files identity at `/run/backupsheep/ssh/managed_private_key`, mode
  `0600`; the app and other roles receive neither private key, and the two identities are
  distinct;
- managed-key mode is active only if the restored database contains exactly one account;
  multi-account installations use customer-supplied private keys;
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

### Lost artifact keyring

There is no password reset or reconstruction path for a lost
`artifact_local_file_database_keyring` or `artifact_local_file_files_keyring`. Do not create
a new file under the missing name and do not prune retained legacy keys speculatively. A
replacement key protects only future wraps and permanently strands all prior artifacts
whose recorded key ID is absent. Recover the exact keyring bytes from the cryptographic
recovery set; if that is impossible, mark the affected lane's artifacts unrecoverable and
make that data-loss boundary explicit to operators.

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
