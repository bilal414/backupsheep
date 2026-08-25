# Installation

BackupSheep is designed to run as a Docker Compose stack. The repository also supports
an advanced, process-by-process installation, but the container image is the canonical
definition of the operating-system tools needed by database and file backups.

## Choose an installation path

| Path | Best for | What it manages |
| --- | --- | --- |
| Verified Docker installer | A host where the operator already manages Docker | Exact checkout, file-backed secrets, image build and core-only startup |
| Manual Docker Compose | Existing Docker hosts and local evaluation | The complete application stack from the checked-out repository |
| Manual processes | Operators who already manage Python, PostgreSQL, RabbitMQ and process supervision | Every web, worker and scheduler process separately |

The stock Compose stack contains PostgreSQL, RabbitMQ, the web application, five
specialized Celery workers, a scheduler, per-role namespace guards and networkless or
single-purpose provision/migrate/seal/preflight one-shots. It publishes the web
application on loopback TCP port `8000`;
PostgreSQL and RabbitMQ are not published to the host.

## Host prerequisites

For the verified installer:

- Git, Bash and ordinary Unix file utilities supplied and maintained by the host operator;
- Docker Engine **28.0.0 or newer** and Docker Compose **2.33.1 or newer**. The installer
  fails closed on older or unparseable versions because the reviewed network model uses
  newer routing controls;
- access to the intended Docker daemon as the invoking user. Docker access is a
  root-equivalent security boundary on a traditional rootful engine; grant it according
  to the host's own policy;
- a user-owned, non-group-writable installation parent directory;
- outbound HTTPS access to GitHub, registries and package sources used by the image build;
- a supported CPU architecture: `x86_64` or `aarch64` (the Dockerfile installs the
  Oracle MySQL 8.4 client for those two architectures);
- enough working disk for the image, PostgreSQL, RabbitMQ, the largest concurrent
  database/file backup, website incremental caches and any Local Storage archives.

Database and file backup workers can need substantially more memory and temporary disk
for large sources. Capacity planning remains a host-operator responsibility.

BackupSheep does not install packages, add apt repositories, enable/restart Docker, or
change firewall, kernel, daemon or service settings. Those are host responsibilities.
Verify the operator-provided tools before continuing:

```bash
git --version
docker version
docker compose version
```

## Verified Docker installer

Choose a reviewed release commit, download the installer from that exact immutable
commit, inspect it, and run it as the same unprivileged user that is already authorized
to use Docker:

```bash
COMMIT='<40-character-reviewed-release-commit>'
KMS_KEY_ARN='arn:aws:kms:us-east-1:123456789012:key/<reviewed-key-id>'
KMS_REGION='us-east-1'
KMS_DATABASE_CREDENTIALS='/absolute/protected/kms-database.credentials'
KMS_FILES_CREDENTIALS='/absolute/protected/kms-files.credentials'
curl -fSLo install.sh \
  "https://raw.githubusercontent.com/bilal414/backupsheep/${COMMIT}/install.sh"
less install.sh
chmod 700 install.sh
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --project-name backupsheep \
  --domain backups.example.com \
  --artifact-kms-key-id "${KMS_KEY_ARN}" \
  --artifact-kms-region "${KMS_REGION}" \
  --artifact-kms-allowed-key-arns "${KMS_KEY_ARN}" \
  --artifact-kms-database-aws-credentials-file "${KMS_DATABASE_CREDENTIALS}" \
  --artifact-kms-files-aws-credentials-file "${KMS_FILES_CREDENTIALS}"
```

The two KMS credential inputs must be distinct canonical, user-owned
mode-`0400`/`0600` files for separate database/files AWS identities with matching
encryption-context policy.

Do not use `sudo` and do not pipe a remote script into a shell. The installer refuses
effective UID 0, including a root shell or `sudo`, because it must not create a
root-owned application checkout or configuration. The invoking user must already have
access to the intended Docker daemon. The installer accepts no branch, tag or
abbreviated revision: it fetches the full commit from the canonical HTTPS repository and
then verifies that its own bytes match `install.sh` in that checkout before invoking
Docker. The default installation directory is
`$XDG_DATA_HOME/backupsheep` or `$HOME/.local/share/backupsheep`; select another
user-writable path explicitly when needed:

```bash
./install.sh \
  --ref "${COMMIT}" \
  --domain backups.example.com \
  --install-dir "$HOME/backupsheep" \
  --project-name backupsheep \
  --artifact-kms-key-id "${KMS_KEY_ARN}" \
  --artifact-kms-region "${KMS_REGION}" \
  --artifact-kms-allowed-key-arns "${KMS_KEY_ARN}" \
  --artifact-kms-database-aws-credentials-file "${KMS_DATABASE_CREDENTIALS}" \
  --artifact-kms-files-aws-credentials-file "${KMS_FILES_CREDENTIALS}"
```

Supported options are:

| Option | Behavior |
| --- | --- |
| `--ref COMMIT` | Required full 40-character commit; mutable or abbreviated references are rejected |
| `--domain HOST` | Configures the accepted/public hostname while the listener remains on server loopback; defaults to `localhost` |
| `--install-dir PATH` | Uses an absolute, user-owned path other than `/` |
| `--project-name NAME` | Pins and persists the Compose project name; every rerun must match that protected witness, and ambient Compose variables are ignored |
| `--adopt-legacy-project NAME` | One-time recovery for the exact stock four-volume layout left by an old `compose down`; see the guarded workflow below |
| `--approved-compose-file PATH` | Accepts only the private regular `INSTALL_DIR/docker-compose.override.yml`, rendered after the base file and included in exact ownership history |
| `--migrate-database-identities` | One-time conversion of an existing stock database to generation-3 bootstrap, owner and exact per-lane ACL/RLS identities |
| `--migrate-rabbitmq-identities` | One-time conversion of the shared broker login to generation-2 per-lane credentials/ACLs |
| `--rotate-celery-signing-keys` | Drained-queue generation-3 task-signing rotation; requires all publishers/consumers stopped and exact broker ownership |
| `--migrate-staging-layout` | One-time existing-install authorization for an empty legacy shared work volume and new layout-v3 witness |
| `--migrate-egress-policy` | One-time fail-closed reset of a uniform stock legacy egress policy to generation-2 deny defaults and blank exact endpoint/name lists; mixed/custom policy is refused |
| `--artifact-kms-key-id ARN` | Resolved symmetric AWS KMS key ARN used for new BSE1 data-key wraps |
| `--artifact-kms-region REGION` | AWS region containing all allowlisted artifact keys |
| `--artifact-kms-allowed-key-arns ARNS` | Comma-separated resolved ARNs accepted for restore and key-wrap rotation |
| `--artifact-kms-database-aws-credentials-file PATH` | Canonical private AWS credential input for the database source lane |
| `--artifact-kms-files-aws-credentials-file PATH` | Different canonical private AWS credential input for the files source lane |
| `--skip-start` | Verifies/configures the installation but does not build or start Compose |
| `--enable-operations` | After core health and security preflight pass, explicitly starts the provider workers and scheduler |

The script does not look up the server's public IP, configure DNS, open a firewall,
issue a TLS certificate or install a reverse proxy.

On a new installation the script:

1. verifies Docker/Compose versions and access without changing the daemon;
2. fetches the exact commit through a configuration-isolated HTTPS Git process, verifies
   the resulting object database, rejects dirty/foreign/symlinked checkouts and compares
   the running installer with the committed copy;
3. creates `.env` as mode `0600` and `.secrets` as a mode `0700` directory;
4. generates independent Django, PostgreSQL bootstrap/migrator/per-lane, RabbitMQ
   bootstrap/per-lane, task-signing, onboarding and lane-specific KMS files plus empty
   optional `ssh_managed_database_private_key` and
   `ssh_managed_files_private_key` files as mode `0444` inside that private directory,
   keeping values out of Compose inspection and staging storage;
5. creates and preserves a random 64-character lowercase hexadecimal installation ID.
   Service containers and an empty labeled sentinel volume carry that identity so a
   reused Compose project name cannot silently adopt another installation's resources,
   including after `compose down` removed its containers and networks. It also inventories
   every exact `${project}_${network-or-volume}` name and rejects an unlabeled/foreign
   collision that Compose could otherwise adopt with only a warning;
6. proves that a broker project is fresh or that its one running, healthy broker reports
   RabbitMQ 4.3 when diagnostics run as the named `rabbitmq` account, then records the
   installer-owned data-generation witness. It refuses orphaned, stopped, unhealthy,
   ambiguous, 3.13 or 4.2 broker state instead of guessing at a volume format;
7. validates Compose through explicit `--project-name`, `--env-file` and `-f` arguments;
8. builds commit-tagged PostgreSQL, application and namespace-guard images and starts only
   PostgreSQL/RabbitMQ, the volume/broker/staging/database provisioners, migrate/seal/
   preflight gates, app guard and web UI on `127.0.0.1:8000`;
9. waits up to five minutes for the `app` health check;
10. prints an SSH-tunnel command and an explicit server-side token retrieval command,
   without writing the token itself to install logs.

Provider workers and Beat do not start unless `--enable-operations` is explicitly
provided. Review provider credentials, queued/recoverable work and restore ownership
before opting in: enabling operations can execute durable work already present in the
database or broker. On every build/migration run the installer first removes the complete
container/network topology with ordinary `down` while preserving named data/identity
volumes; an explicit opt-in recreates operations only after core health and the security
preflight pass. Long-lived application roles use `restart: unless-stopped`, but
namespace guards use `restart: "no"`; the wrapper refuses an independent guard lifecycle
command and requires the workload/guard pair to be recreated together.

An existing directory is reused only when it is the clean canonical repository at the
same requested commit, with the expected ownership and permissions. The installer never
upgrades a checkout in place. It migrates existing direct installation secrets without
rotating them and then blanks their `.env` values. A pre-generation-3 stock database is
the deliberate exception: the operator must first stop work, make a verified encrypted
rollback, and pass `--migrate-database-identities` once. The installer preserves its
legacy credential only as the bootstrap credential and generates new independent
migrator/runtime credentials. See the
[database identity migration gate](database-identity-migration.md). It creates both optional
lane-specific managed SSH files empty for a new deployment. A legacy shared identity cannot
be assigned an account and worker lane safely, so the installer refuses any non-empty
`.secrets/ssh_managed_private_key` or legacy `SSH_MANAGED_PRIVATE_KEY_PATH` /
`SSH_MANAGED_PUBLIC_KEY` value. Follow the [upgrade gate](upgrades.md#one-time-legacy-ssh-trust-and-shared-identity-retirement)
to preserve rollback evidence and create distinct Ed25519 identities. It refuses ambiguous,
missing, mismatched, symlinked or hard-linked secret state. A failed start leaves containers
and volumes intact for evidence and recovery; it never performs an automatic destructive
rollback.

An existing installation without `BACKUPSHEEP_EGRESS_POLICY_GENERATION=2` must also use
`--migrate-egress-policy` once. The installer accepts only a uniform stock public/blank,
blank/blank or deny/blank legacy state, then resets all six roles to `deny` and clears old
and new lists. Internet-dependent operations remain blocked until reviewed exact TCP
tuples and DNS names are added. Preserve and review any customized/mixed legacy policy,
manually reset it to the stock deny state, and only then authorize the migration; the
installer never guesses a translation and rejects reuse of the flag after generation 2.

### One-time legacy compose-down adoption

Releases before the installation-identity sentinel can be left with only four named
volumes after `compose down`: `pgdata`, `rabbitmq_data`, `backup_workdir` and
`backup_storage`. With no exact-path container or sentinel, the installer cannot infer
that those volumes belong to the current installation. Do not work around this by
manually editing the persisted project-name witness.

After independently confirming the old Compose project name and recovery backups, run
the verified installer once with the value-bearing adoption option, preferably with
startup disabled for the first pass:

```bash
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --project-name backupsheep \
  --domain backups.example.com \
  --adopt-legacy-project backupsheep \
  --artifact-kms-key-id "${KMS_KEY_ARN}" \
  --artifact-kms-region "${KMS_REGION}" \
  --artifact-kms-allowed-key-arns "${KMS_KEY_ARN}" \
  --artifact-kms-database-aws-credentials-file "${KMS_DATABASE_CREDENTIALS}" \
  --artifact-kms-files-aws-credentials-file "${KMS_FILES_CREDENTIALS}" \
  --skip-start
```

This gate fails closed unless the existing installation has no persisted project witness,
the named project has zero containers and networks, and its complete labeled volume set
is exactly `${project}_{pgdata,rabbitmq_data,backup_workdir,backup_storage}` with the
standard Compose project/logical labels and no BackupSheep installation-ID labels. It
also rejects pre-existing `installation_identity` or legacy `ssh_trust` names, inventory or
inspection errors, missing volumes, extra volumes and label drift.

Only after those checks does the installer create
`${project}_installation_identity` with the exact Compose project/logical labels and the
new stable installation ID. It immediately re-inspects the name and all labels, then
persists `BACKUPSHEEP_COMPOSE_PROJECT_NAME`. The same generic ownership validator must
pass afterward. If any later independent gate (notably the RabbitMQ
generation gate) stops the run, retain the evidence, complete its documented runbook and
rerun without `--adopt-legacy-project`; adoption is deliberately one-time.

If the legacy containers still exist, no adoption flag is needed. Before any Compose
mutation, the installer proves every project container's exact installation path,
canonical config file and known service; proves every project network and volume has its
canonical physical and logical name; and requires all pre-hardening installation-ID
labels to be blank. Only after the entire inventory passes does it create and re-inspect
the identity sentinel. The wrapper then accepts the immutable blank container IDs only
under that matching sentinel so the reviewed Compose and RabbitMQ transition commands can
recreate them. Any nonblank partial identity, path/model/service drift, noncanonical name,
foreign sentinel or inspection failure stops without creating a Docker resource.

The exact four-volume adoption gate above is only for the older pre-sentinel layout;
do not use it to relabel a develop-era `ssh_trust` volume. Development layout v2 was
prerelease-only. When an already identified project contains its canonical labeled
`ssh_trust` volume, the ordinary ownership validator may accept it only after exact
project, physical-name, logical-name and installation-identity checks. It remains
detached as rollback evidence during the explicit `migrate-empty-legacy-v3` staging
transition. Layout v3 has no trust mount, trust group or provisioning path, and the
wrapper rejects every `--volume` override, so the retired global trust inventory cannot
be imported. Reapprove each exact account/host/port/key in PostgreSQL instead; any
ambiguous or foreign legacy volume stops installation.

An existing RabbitMQ data volume is a separate fail-closed gate. The installer never
performs the 3.13 -> 4.2 -> 4.3/Khepri migration. If the stored data-generation witness is
blank, it accepts only a new project with no broker resources. Existing broker data with
a blank witness must use the explicit wrapper migration/reconciliation path, which attests
the pinned image reference and image ID, exact server version, feature flags and Khepri.
A volume without that witness, a stopped/unhealthy broker, duplicate broker resources, or
another version requires the [operator-run RabbitMQ migration](rabbitmq-upgrade.md).

### Verify an installer deployment

```bash
cd "$HOME/.local/share/backupsheep"
./backupsheep-compose config --quiet
./backupsheep-compose ps --all
./backupsheep-compose logs --tail=100 \
  rabbitmq-volume-init rabbitmq-provision staging-provision \
  db-provision migrate db-seal preflight app-egress-guard app
curl -fsS http://127.0.0.1:8000/healthz/
```

The last command should print `ok`. This proves that the web process can answer a
request; it does not probe PostgreSQL, RabbitMQ or any provider. Complete the
[first-run setup](first-run.md), then follow the [production guide](production.md)
before exposing the instance publicly. When the operational preflight is complete, opt in
using the same exact installer:

The installer and hardened wrapper serialize every real control-plane mutation through
the same `${INSTALL_DIR}.backupsheep-mutation-lock` directory. Do not run two installer or
mutating wrapper commands concurrently. Read-only wrapper inspection remains available
while a mutation is active. If a crash leaves a stale lock, follow the exact inspection and
non-recursive recovery procedure in the
[operations runbook](operations.md#control-plane-mutation-lock); the tools never infer that
a recorded PID is safe to reap.

```bash
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --project-name backupsheep \
  --domain backups.example.com \
  --artifact-kms-key-id "${KMS_KEY_ARN}" \
  --artifact-kms-region "${KMS_REGION}" \
  --artifact-kms-allowed-key-arns "${KMS_KEY_ARN}" \
  --artifact-kms-database-aws-credentials-file "${KMS_DATABASE_CREDENTIALS}" \
  --artifact-kms-files-aws-credentials-file "${KMS_FILES_CREDENTIALS}" \
  --enable-operations
```

The preflight runs Django's deployment checks. Warning-level HTTPS findings are expected
only while the listener is deliberately limited to loopback and reached through an SSH
tunnel. Before public exposure, configure a real TLS proxy, set `DJANGO_HTTPS=true`,
`APP_PROTOCOL=https://`, the exact public `APP_DOMAIN` and allowed hosts, and review every
deployment warning. A passing error-level preflight does not make public HTTP safe.

## Manual Docker Compose installation

### 1. Let the verified installer stage the exact model

Directly cloning and inventing `.env`, secret files, identity generations or layout
witnesses is not a supported stock bootstrap. The model requires independent database and
broker lane credentials, task-signing keys, two KMS identities, an installation ID,
resource labels and the v3 staging witness as one fail-closed set. Use `--skip-start` when
you need to review or add a Compose override before the first build:

```bash
COMMIT='<40-character-reviewed-release-commit>'
KMS_KEY_ARN='arn:aws:kms:us-east-1:123456789012:key/<reviewed-key-id>'
KMS_REGION='us-east-1'
KMS_DATABASE_CREDENTIALS='/absolute/protected/kms-database.credentials'
KMS_FILES_CREDENTIALS='/absolute/protected/kms-files.credentials'
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --project-name backupsheep \
  --domain backups.example.com \
  --artifact-kms-key-id "${KMS_KEY_ARN}" \
  --artifact-kms-region "${KMS_REGION}" \
  --artifact-kms-allowed-key-arns "${KMS_KEY_ARN}" \
  --artifact-kms-database-aws-credentials-file "${KMS_DATABASE_CREDENTIALS}" \
  --artifact-kms-files-aws-credentials-file "${KMS_FILES_CREDENTIALS}" \
  --skip-start
cd "$HOME/.local/share/backupsheep"
test "$(git rev-parse HEAD)" = "${COMMIT}"
```

Do not hand-edit the installer-owned identity/generation/witness values or add arbitrary
files beneath `.secrets`. Keep `.secrets/django_secret_key` stable. It signs sessions and
derives the key used for saved email credentials. See the
[configuration guide](configuration.md) and complete
[environment-variable reference](../reference/environment-variables.md).

If Local Storage must live on a capacity-managed bind/NFS filesystem, create and review
`docker-compose.override.yml` **before the first `up`**. Use the bind-volume example in
`docker-compose.yml`, resolve an absolute host path, and verify its ownership/capacity.
Then add the exact approval flag to the command array in step 2. The wrapper refuses to
auto-load the file. Docker volume driver options are immutable after creation, so a later
configuration edit does not move existing archive bytes or convert an existing named
volume.

### 2. Validate, build and start

```bash
BS_COMPOSE=("$PWD/backupsheep-compose")
# If and only if a reviewed pre-start override exists, add this active line:
# BS_COMPOSE+=(--approved-compose-file "$PWD/docker-compose.override.yml")
bs_compose() { "${BS_COMPOSE[@]}" "$@"; }
bs_compose config --quiet
bs_compose build db app app-egress-guard
# Fresh topology only: no guard/workload container may already exist.
bs_compose up --detach
bs_compose ps --all
```

The profile-less command starts only the core. Start provider workers and Beat only after
the security preflight and recovery review:

```bash
bs_compose --profile operations up --detach --no-build --no-deps \
  --force-recreate \
  cloud-egress-guard database-egress-guard files-egress-guard \
  storage-egress-guard logs-egress-guard \
  worker-cloud worker-database worker-files worker-storage worker-logs
bs_compose --profile operations up --detach --no-build --no-deps beat
```

After any pair exists, broad, guard-only and workload-only `up` operations are refused.
Use the exact paired force-recreation above; see the
[egress lifecycle contract](../../deploy/egress/README.md#paired-lifecycle-commands).

`db-provision`, `migrate` and `preflight` must all exit with code `0`. The provisioner
uses the bootstrap credential only on its dedicated internal bridge, creates or rotates
installation-marked migrator/runtime roles in one transaction, transfers the reviewed
public schema to the migrator and grants the runtime login DML without DDL or temporary
tables. The preflight independently proves the active Django login has that exact
least-privilege boundary, computes Django's migration plan and refuses any unapplied
migration. The application and
worker services wait for all three one-shot gates before starting. Migrations also seed the
integration/storage catalogs and create the database-backed cache table. Application,
PostgreSQL and egress-guard roles use `pull_policy: never`, so all three explicit builds
above are mandatory
and a missing local image cannot be replaced silently from a registry. The database build
uses `Dockerfile.postgres`: it verifies the digest-pinned official 18.6 entrypoint before
replacing its single `gosu` privilege drop with exact Alpine `su-exec=0.3-r0`, then
deletes `gosu` and declares UID/GID `70:70`. Stock Compose starts PostgreSQL directly as
that non-root identity with no capabilities and initializes the distinct
`postgres_data_v1` volume with ICU `und`. A wrong, unwitnessed, or legacy Debian volume
fails closed instead of being repaired or adopted. Existing installations must use the
one-time [PostgreSQL Alpine/ICU migration gate](postgres-runtime-migration.md).

Every application-image command still passes through the image entrypoint. It rejects a
root or weakened runtime, neutralizes shell/Python/dynamic-loader startup hooks and runs
the deployment preflight again before each web, worker or Beat process. This repeated
gate also covers an automatic container restart after the earlier one-shot preflight has
exited. Database identity provisioning, migration and the preflight command itself are
the only intentional exceptions.

An existing RabbitMQ 3.13 volume requires the supported 3.13 -> 4.2 -> 4.3 sequence before
this Compose file can be used. Follow the [RabbitMQ migration gate](rabbitmq-upgrade.md);
never start the 4.3 image directly against a 3.13 data directory.

If startup fails:

```bash
bs_compose logs --tail=200 db-provision migrate preflight app db rabbitmq
```

### 3. Retrieve the install token

Read the generated onboarding token only from the trusted host shell:

```bash
cat .secrets/onboarding_token
```

Open `http://localhost:8000/onboarding/` and enter that token when creating the first
account.

### 4. Migrate existing Local Storage off the Docker-managed disk

The Local Storage destination writes beneath `/backups`, which is the
`backup_storage` named volume by default. For important archives, place that volume on
capacity-managed storage. For an installation that already created the stock volume,
do not merely add an override: Compose will keep the existing volume's original driver
options and no bytes will move. Treat this as a host-storage migration. Stop app plus all
operations writers, resolve the one exact labeled `backup_storage` volume, take a
recoverable snapshot, copy its complete contents and metadata to the approved target,
compare file counts/sizes/hashes, and only then replace that exact old volume with the
reviewed bind-backed definition. Never use broad `down --volumes` or pruning. Re-run the
wrapper's rendered-model, ownership, storage-only write/read and authenticated restore checks before
operations resume. The repository intentionally does not automate deletion of the old
host volume.

## Manual process installation (advanced)

The repository can run as ordinary Django/Celery processes, but there is no bundled
systemd or supervisor definition. The operator must provide process supervision,
restart policy, log handling, equivalent lane-private work and ciphertext handoff
boundaries, Local Storage isolation and upgrades. A shared plaintext work directory is
not equivalent to stock Compose and must not be used.

Use Python 3.14 to match the image. Install PostgreSQL 14 or newer, RabbitMQ, the Python
requirements and the external tools listed in `Dockerfile`, including:

- `lftp`, OpenSSH, `zip` and `unzip` for website/file transfers;
- Oracle MySQL 8.4 `mysql`/`mysqldump` for MySQL targets;
- MariaDB client tools for MariaDB targets;
- PostgreSQL client tools 14 through 18 so the app can select a version-matched
  `pg_dump`/`pg_restore`.

Then create a virtual environment, install dependencies and initialize the database:

```bash
python3.14 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python manage.py migrate --noinput
python manage.py collectstatic --noinput
```

Run one process for each queue, plus web and Beat. These commands mirror the process
roles, but a manual-process deployment does not inherit the Docker entrypoint/runtime
enforcement and must supply equivalent supervision and security controls:

```bash
gunicorn backupsheep.wsgi:application --workers=4 --timeout=3600 --bind 0.0.0.0:8000
celery -A backupsheep worker --loglevel=info --hostname=cloud@%h -Q cloud,default --concurrency=4
celery -A backupsheep worker --loglevel=info --hostname=database@%h -Q database --concurrency=1
celery -A backupsheep worker --loglevel=info --hostname=files@%h -Q files --concurrency=1
celery -A backupsheep worker --loglevel=info --hostname=storage@%h -Q storage --concurrency=2
celery -A backupsheep worker --loglevel=info --hostname=logs@%h -Q logs --concurrency=2
celery -A backupsheep beat --loglevel=info --scheduler backupsheep.scheduler:BackupDatabaseScheduler
```

An equivalent non-Compose supervisor must preserve separate database/files/storage private
work roots and the two forward plus one reverse BSE1 handoff boundaries; one shared
plaintext `_storage` directory is not equivalent. `reset_incremental_cache` and files
run-log pruning execute in the files lane, while database run-log pruning executes in the
database lane and destination-upload run-log pruning executes in the storage lane.
UI-approved host keys and append-only approval events are account-scoped
PostgreSQL records. A database/files worker materializes only the exact approval for one
operation in a transient mode-`0600` private runtime file and removes it afterward; stock
Compose has no trust volume.

Optional `.secrets/ssh_managed_database_private_key` and
`.secrets/ssh_managed_files_private_key` sources are mounted mode `0444` only in their
matching workers. The app and all other roles receive neither private key. Each accepted
Ed25519 identity is copied into that worker's private tmpfs as
`/run/backupsheep/ssh/managed_private_key`, mode `0600`. The identities must be distinct and
managed-key mode is allowed only while the database contains exactly one account.
Multi-account installations use customer-supplied private keys.
`BS_LOCAL_STORAGE_PATH` is mounted read/write only by storage; every other role receives
no Local Storage mount and consumes restore bytes only through the reverse BSE1 handoff.

Keep one Beat process for the normal maintenance cadence. Backup schedule occurrences
have a transactional database claim, but duplicated Beat instances add needless
scheduler load and can duplicate ordinary maintenance dispatches.

## Next steps

1. Complete [first-run setup](first-run.md).
2. Move to [production HTTPS and hardening](production.md).
3. Establish [BackupSheep's own backup and recovery plan](disaster-recovery.md).
4. Use the [operations runbook](operations.md) for routine checks.
