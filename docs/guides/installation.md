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
specialized Celery workers, a scheduler, a one-shot migration service and a one-shot
security preflight. It publishes the web application on loopback TCP port `8000`;
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
curl -fSLo install.sh \
  "https://raw.githubusercontent.com/bilal414/backupsheep/${COMMIT}/install.sh"
less install.sh
chmod 700 install.sh
./install.sh --ref "${COMMIT}" --domain backups.example.com
```

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
  --install-dir "$HOME/backupsheep"
```

Supported options are:

| Option | Behavior |
| --- | --- |
| `--ref COMMIT` | Required full 40-character commit; mutable or abbreviated references are rejected |
| `--domain HOST` | Configures the accepted/public hostname while the listener remains on server loopback; defaults to `localhost` |
| `--install-dir PATH` | Uses an absolute, user-owned path other than `/` |
| `--project-name NAME` | Pins the Compose project name instead of accepting it from `.env` or ambient Compose variables |
| `--adopt-legacy-project NAME` | One-time recovery for the exact stock four-volume layout left by an old `compose down`; see the guarded workflow below |
| `--approved-compose-file PATH` | Accepts only the private regular `INSTALL_DIR/docker-compose.override.yml`, rendered after the base file and included in exact ownership history |
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
4. generates independent Django, PostgreSQL, RabbitMQ and onboarding files plus an empty
   optional `ssh_managed_private_key` file as mode `0444` inside that private directory,
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
8. builds commit-tagged PostgreSQL and application images and starts only PostgreSQL, RabbitMQ,
   migrations, the fail-closed preflight and web UI on `127.0.0.1:8000`;
9. waits up to five minutes for the `app` health check;
10. prints an SSH-tunnel command and an explicit server-side token retrieval command,
   without writing the token itself to install logs.

Provider workers and Beat do not start unless `--enable-operations` is explicitly
provided. Review provider credentials, queued/recoverable work and restore ownership
before opting in: enabling operations can execute durable work already present in the
database or broker. On every build/migration run the installer first stops the exact
worker/Beat service set; an explicit opt-in restarts it only after core health and the
security preflight pass.

An existing directory is reused only when it is the clean canonical repository at the
same requested commit, with the expected ownership and permissions. The installer never
upgrades a checkout in place. It migrates the four existing direct installation secrets
without rotating them and then blanks their `.env` values. It creates the optional managed
SSH-key file empty for a new deployment. If a legacy `SSH_MANAGED_PRIVATE_KEY_PATH` is
configured, the operator must first place that exact key in
`.secrets/ssh_managed_private_key`, set mode `0444`, and clear the old path; the installer
will not guess or copy key material. It refuses ambiguous, missing, mismatched, symlinked
or hard-linked secret state. A failed start leaves containers and volumes intact for
evidence and recovery; it never performs an automatic destructive rollback.

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
  --adopt-legacy-project backupsheep \
  --skip-start
```

This gate fails closed unless the existing installation has no persisted project witness,
the named project has zero containers and networks, and its complete labeled volume set
is exactly `${project}_{pgdata,rabbitmq_data,backup_workdir,backup_storage}` with the
standard Compose project/logical labels and no BackupSheep installation-ID labels. It
also rejects pre-existing `installation_identity` or `ssh_trust` names, inventory or
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
./backupsheep-compose logs --tail=100 migrate preflight app
curl -fsS http://127.0.0.1:8000/healthz/
```

The last command should print `ok`. This proves that the web process can answer a
request; it does not probe PostgreSQL, RabbitMQ or any provider. Complete the
[first-run setup](first-run.md), then follow the [production guide](production.md)
before exposing the instance publicly. When the operational preflight is complete, opt in
using the same exact installer:

```bash
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --enable-operations
```

The preflight runs Django's deployment checks. Warning-level HTTPS findings are expected
only while the listener is deliberately limited to loopback and reached through an SSH
tunnel. Before public exposure, configure a real TLS proxy, set `DJANGO_HTTPS=true`,
`APP_PROTOCOL=https://`, the exact public `APP_DOMAIN` and allowed hosts, and review every
deployment warning. A passing error-level preflight does not make public HTTP safe.

## Manual Docker Compose installation

### 1. Clone and configure

```bash
COMMIT='<40-character-reviewed-release-commit>'
git clone --no-checkout https://github.com/bilal414/backupsheep.git
cd backupsheep
git checkout --detach "${COMMIT}"
test "$(git rev-parse HEAD)" = "${COMMIT}"
cp .env_sample .env
chmod 600 .env
install -d -m 700 .secrets
```

Set at least these values in `.env`:

```dotenv
DJANGO_SERVER='prod'
DJANGO_DEBUG=false
BACKUPSHEEP_IMAGE='backupsheep:<same-40-character-reviewed-commit>'
BACKUPSHEEP_POSTGRES_IMAGE='backupsheep-postgres:<same-40-character-reviewed-commit>'
BACKUPSHEEP_INSTALLATION_ID='<stable-64-character-lowercase-hex-value>'
BACKUPSHEEP_COMPOSE_PROJECT_NAME='backupsheep'
BACKUPSHEEP_SECRETS_DIR='.secrets'
DJANGO_SETTINGS_MODULE='backupsheep.settings'
DJANGO_SECRET_KEY=''
DJANGO_ALLOWED_HOSTS='localhost,127.0.0.1,backups.example.com'
APP_PROTOCOL='http://'
APP_DOMAIN='localhost:8000'
DB_PASSWORD=''
RABBITMQ_PASSWORD=''
ONBOARDING_INSTALL_TOKEN=''
```

Create the four required secret files and the empty optional managed-key file without
writing values to shell history or standard output:

```bash
umask 077
od -An -N 48 -tx1 /dev/urandom | tr -d ' \n' > .secrets/django_secret_key
od -An -N 24 -tx1 /dev/urandom | tr -d ' \n' > .secrets/db_password
od -An -N 32 -tx1 /dev/urandom | tr -d ' \n' > .secrets/rabbitmq_password
od -An -N 32 -tx1 /dev/urandom | tr -d ' \n' > .secrets/onboarding_token
touch .secrets/ssh_managed_private_key
chmod 444 .secrets/django_secret_key .secrets/db_password \
  .secrets/rabbitmq_password .secrets/onboarding_token \
  .secrets/ssh_managed_private_key
```

Generate `BACKUPSHEEP_INSTALLATION_ID` once from 32 random bytes and preserve it with the
installation; it is an ownership marker, not an authentication secret. The verified
installer manages this automatically. Manual deployments must also inspect existing
Compose resources before first start and must never reuse a project name whose ownership
is unclear. The explicit `BACKUPSHEEP_COMPOSE_PROJECT_NAME` must match the reviewed
project name passed to every command; changing it creates or targets a different resource
set.

```bash
od -An -N 32 -tx1 /dev/urandom | tr -d ' \n'
```

Copy that 64-character lowercase result into the placeholder without adding spaces.

Keep `.secrets/django_secret_key` stable. It signs sessions and derives the key used for
saved email credentials. See the [configuration guide](configuration.md) and the complete
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
bs_compose build db app
bs_compose up --detach
bs_compose ps --all
```

The profile-less command starts only the core. Start provider workers and Beat only after
the security preflight and recovery review:

```bash
bs_compose --profile operations up --detach
```

`migrate` and `preflight` must both exit with code `0`. The preflight independently
computes Django's migration plan and refuses any unapplied migration. The application and
worker services wait for both one-shot gates before starting. Migrations also seed the
integration/storage catalogs and create the database-backed cache table. Application
and PostgreSQL roles use `pull_policy: never`, so both explicit builds above are mandatory
and a missing local image cannot be replaced silently from a registry. The database build
uses `Dockerfile.postgres`: it verifies the digest-pinned official 18.6 entrypoint before
replacing its single `gosu` privilege drop with Debian's security-updated `setpriv`, then
deletes `gosu` and verifies the fixed util-linux package versions.

Every application-image command still passes through the image entrypoint. It rejects a
root or weakened runtime, neutralizes shell/Python/dynamic-loader startup hooks and runs
the deployment preflight again before each web, worker or Beat process. This repeated
gate also covers an automatic container restart after the earlier one-shot preflight has
exited. Migration and the preflight command itself are the only intentional exceptions.

An existing RabbitMQ 3.13 volume requires the supported 3.13 -> 4.2 -> 4.3 sequence before
this Compose file can be used. Follow the [RabbitMQ migration gate](rabbitmq-upgrade.md);
never start the 4.3 image directly against a 3.13 data directory.

If startup fails:

```bash
bs_compose logs --tail=200 migrate preflight app db rabbitmq
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
wrapper's rendered-model, ownership, write/read, download and restore checks before
operations resume. The repository intentionally does not automate deletion of the old
host volume.

## Manual process installation (advanced)

The repository can run as ordinary Django/Celery processes, but there is no bundled
systemd or supervisor definition. The operator must provide process supervision,
restart policy, log handling, shared storage and upgrades.

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

Database/file workers create artifacts in shared `_storage`; the storage worker uploads,
finalizes and cleans them. It also handles `reset_incremental_cache` under the per-node
incremental lock with directory-descriptor-confined deletes, plus on-disk
`delete_old_logs`. The stock web process has no staging mount. UI-approved host keys live
in a separate `ssh_trust` volume that app can update and database/files read only. The
optional managed key is `.secrets/ssh_managed_private_key`, mounted only in
app/database/files as a mode-`0444` source. Empty disables it. On each role start, the
entrypoint rejects an invalid, encrypted or larger-than-64-KiB non-empty key, copies an
accepted key into private tmpfs at `/run/backupsheep/ssh/managed_private_key`, applies mode
`0600`, and exports that runtime path. Never configure SSH to read the mode-`0444`
`/run/secrets/ssh_managed_private_key` source directly. The notification/log worker has no
staging/trust/key mount.
`BS_LOCAL_STORAGE_PATH` is writable only by storage; roles that inspect/consume Local
Storage receive it read-only.

Keep one Beat process for the normal maintenance cadence. Backup schedule occurrences
have a transactional database claim, but duplicated Beat instances add needless
scheduler load and can duplicate ordinary maintenance dispatches.

## Next steps

1. Complete [first-run setup](first-run.md).
2. Move to [production HTTPS and hardening](production.md).
3. Establish [BackupSheep's own backup and recovery plan](disaster-recovery.md).
4. Use the [operations runbook](operations.md) for routine checks.
