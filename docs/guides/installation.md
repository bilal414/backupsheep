# Installation

BackupSheep is designed to run as a Docker Compose stack. The repository also supports
an advanced, process-by-process installation, but the container image is the canonical
definition of the operating-system tools needed by database and file backups.

## Choose an installation path

| Path | Best for | What it manages |
| --- | --- | --- |
| Server installer | A new Ubuntu or Debian VM | Git, Docker Engine, Compose, checkout, secrets, build and startup |
| Manual Docker Compose | Existing Docker hosts and local evaluation | The complete application stack from the checked-out repository |
| Manual processes | Operators who already manage Python, PostgreSQL, RabbitMQ and process supervision | Every web, worker and scheduler process separately |

The stock Compose stack contains PostgreSQL, RabbitMQ, the web application, five
specialized Celery workers, a scheduler and a one-shot migration service. It publishes
the web application on TCP port `8000`; PostgreSQL and RabbitMQ are not published to the
host.

## Host prerequisites

For the server installer:

- Ubuntu or Debian with a release codename in `/etc/os-release` and a matching Docker
  Engine apt repository; the installer checks the distribution and codename but does not
  enforce a minimum release number;
- root or passwordless `sudo` access;
- outbound HTTPS access to GitHub, Docker's package repository and the package sources
  used by the image build;
- a supported CPU architecture: `x86_64` or `aarch64` (the Dockerfile installs the
  Oracle MySQL 8.4 client for those two architectures);
- enough working disk for the image, PostgreSQL, RabbitMQ, the largest concurrent
  database/file backup, website incremental caches and any Local Storage archives.

The installer warns when less than 1.5 GiB of memory is available; this is a warning,
not a sizing guarantee. Database and file backup workers can need substantially more
memory and temporary disk for large sources.

For manual Compose installation, install Git, Docker Engine and the Docker Compose
plugin. Verify the plugin before continuing:

```bash
git --version
docker version
docker compose version
```

## Server installer

Review the installer before running it with root privileges:

```bash
curl -fsSLo install.sh https://raw.githubusercontent.com/bilal414/backupsheep/main/install.sh
less install.sh
sudo bash install.sh --domain backups.example.com
```

The installer defaults to the `main` branch and `/opt/backupsheep`. To install another
branch or tag, pass it explicitly:

```bash
sudo bash install.sh \
  --domain backups.example.com \
  --branch develop \
  --install-dir /opt/backupsheep
```

Supported options are:

| Option | Behavior |
| --- | --- |
| `--domain HOST` | Configures `http://HOST:8000`; accepts a hostname or IPv4 address without scheme, path or port |
| `--branch BRANCH` | Checks out that branch or tag; defaults to `main` |
| `--install-dir PATH` | Uses an absolute directory other than `/`; defaults to `/opt/backupsheep` |
| `--skip-start` | Installs/configures the host but does not build or start Compose |

If `--domain` is omitted, the script tries a public IPv4 lookup and then the first local
address reported by `hostname -I`. It does not configure DNS, open a firewall, issue a
TLS certificate or install a reverse proxy.

On a new installation the script:

1. installs Git, Docker Engine and the Compose plugin;
2. clones the requested branch with a shallow checkout;
3. copies `.env_sample` to `.env`;
4. generates independent Django, PostgreSQL and onboarding secrets;
5. sets `.env` mode to `0600`;
6. validates Compose, builds the shared image and starts the stack;
7. waits up to five minutes for the `app` health check;
8. prints the onboarding URL and install token.

An existing directory is reused only when it already contains both
`docker-compose.yml` and `.env_sample`. An existing `.env` is preserved.

### Verify an installer deployment

```bash
cd /opt/backupsheep
sudo docker compose config --quiet
sudo docker compose ps --all
sudo docker compose logs --tail=100 migrate app
curl -fsS http://127.0.0.1:8000/healthz/
```

The last command should print `ok`. This proves that the web process can answer a
request; it does not probe PostgreSQL, RabbitMQ or any provider. Complete the
[first-run setup](first-run.md), then follow the [production guide](production.md)
before exposing the instance publicly.

## Manual Docker Compose installation

### 1. Clone and configure

```bash
git clone https://github.com/bilal414/backupsheep.git
cd backupsheep
cp .env_sample .env
chmod 600 .env
```

Set at least these values in `.env`:

```dotenv
DJANGO_SERVER='prod'
DJANGO_DEBUG=false
DJANGO_SECRET_KEY='replace-with-a-long-random-value'
DJANGO_ALLOWED_HOSTS='localhost,127.0.0.1,backups.example.com'
APP_PROTOCOL='http://'
APP_DOMAIN='localhost:8000'
DB_PASSWORD='replace-with-a-strong-database-password'
```

Generate a signing key without writing it to shell history:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(64))'
```

Keep `DJANGO_SECRET_KEY` stable. It signs sessions and derives the key used for saved
email credentials. See the [configuration guide](configuration.md) and the complete
[environment-variable reference](../reference/environment-variables.md).

### 2. Validate, build and start

```bash
docker compose config --quiet
docker compose build app
docker compose up --detach --remove-orphans
docker compose ps --all
```

`migrate` must exit with code `0`. The application and worker services wait for that
one-shot service before starting. Migrations also seed the integration/storage catalogs
and create the database-backed cache table.

If startup fails:

```bash
docker compose logs --tail=200 migrate app db rabbitmq
```

### 3. Retrieve the install token

When `ONBOARDING_INSTALL_TOKEN` is blank, the app creates a random token on the first
onboarding request and stores it in the shared work volume:

```bash
docker compose exec app cat /code/_storage/install_token
```

Open `http://localhost:8000/onboarding/` and enter that token when creating the first
account.

### 4. Detach local archives from the Docker-managed disk

The Local Storage destination writes beneath `/backups`, which is the
`backup_storage` named volume by default. For important archives, place that volume on
capacity-managed storage. The Compose file includes a bind-mount example; create a local
`docker-compose.override.yml` with a validated absolute device path and verify the
result with `docker compose config` before starting the stack.

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

Run one process for each queue, plus web and Beat. These commands mirror the Compose
service definitions:

```bash
gunicorn backupsheep.wsgi:application --workers=4 --timeout=3600 --bind 0.0.0.0:8000
celery -A backupsheep worker --loglevel=info --hostname=cloud@%h -Q cloud,default --concurrency=8
celery -A backupsheep worker --loglevel=info --hostname=database@%h -Q database --concurrency=4
celery -A backupsheep worker --loglevel=info --hostname=files@%h -Q files --concurrency=4
celery -A backupsheep worker --loglevel=info --hostname=storage@%h -Q storage --concurrency=4
celery -A backupsheep worker --loglevel=info --hostname=logs@%h -Q logs --concurrency=4
celery -A backupsheep beat --loglevel=info --scheduler backupsheep.scheduler:BackupDatabaseScheduler
```

The web process and every disk-touching worker must see the same `_storage` data.
Database/file workers create artifacts there; the storage worker uploads and finalizes
them; the log worker prunes local logs. `BS_LOCAL_STORAGE_PATH` must likewise point to
durable storage visible to `app` and all workers that handle local archives.

Keep one Beat process for the normal maintenance cadence. Backup schedule occurrences
have a transactional database claim, but duplicated Beat instances add needless
scheduler load and can duplicate ordinary maintenance dispatches.

## Next steps

1. Complete [first-run setup](first-run.md).
2. Move to [production HTTPS and hardening](production.md).
3. Establish [BackupSheep's own backup and recovery plan](disaster-recovery.md).
4. Use the [operations runbook](operations.md) for routine checks.
