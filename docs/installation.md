# Installation

BackupSheep runs as a Docker Compose stack. It includes PostgreSQL and RabbitMQ, so you
don't need to install either separately. (You *can* point at external services — see
[Configuration](configuration.md).)

## One-command server installation

For a fresh **Ubuntu 22.04+ or Debian 12+** server with `sudo` access and outbound
internet access, run:

```bash
curl -fsSL https://raw.githubusercontent.com/bilal414/backupsheep/main/install.sh | sudo bash
```

The script is part of this repository. It installs Git, Docker Engine, and Docker Compose
from Docker's official apt repository; clones BackupSheep into `/opt/backupsheep`; creates
a root-readable-only `.env` with random Django, PostgreSQL, RabbitMQ, and onboarding
secrets; and builds/starts the complete stack. It then waits for the app health check and
prints an SSH-tunnel command plus an explicit server-side token retrieval command. The
token itself is never written to unattended install logs.

By default it detects your public IPv4 address. If this server has a DNS name, configure
that from the start so Django accepts requests for it:

```bash
curl -fsSL https://raw.githubusercontent.com/bilal414/backupsheep/main/install.sh | sudo bash -s -- --domain backups.example.com
```

Useful options:

```text
--domain HOST       hostname or IPv4 address (no scheme, path, or port)
--branch BRANCH     install a release branch/tag instead of main
--install-dir PATH  use a directory other than /opt/backupsheep
--skip-start        install/configure only; do not start Docker Compose
```

The initial setup binds plain HTTP to **server loopback at `127.0.0.1:8000`**. Use the
printed SSH tunnel for onboarding; do not open port 8000 in the host/cloud firewall. Before
public use, put it behind a TLS reverse proxy and follow the
[production deployment guide](deployment.md).

To operate the installation later:

```bash
cd /opt/backupsheep
sudo docker compose logs -f
sudo docker compose up --build -d
```

## Manual Docker Compose installation

### Prerequisites

- A Linux host (or any machine) with **Docker** and the **Docker Compose plugin**
  (`docker compose version` should work).
- **git**.
- ~2 GB RAM to start; backups of large databases/sites need disk for the working copy.

### 1. Clone and configure

```bash
git clone <your-fork-or-this-repo-url> backupsheep
cd backupsheep
cp .env_sample .env
chmod 600 .env
```

Open `.env` and set, at minimum:

| Variable | Set it to |
|----------|-----------|
| `DJANGO_SECRET_KEY` | A long random string. Generate one: `python -c "import secrets; print(secrets.token_urlsafe(64))"`. **Keep it stable** — changing it later logs everyone out and makes stored email credentials undecryptable. |
| `DB_PASSWORD` | Any password you choose for the bundled PostgreSQL. |
| `RABBITMQ_PASSWORD` | A separate random password for the bundled RabbitMQ user. Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`. Compose refuses to start when it is blank. |
| `DJANGO_ALLOWED_HOSTS` | The hostname/IP browsers will use, for example `backup.example.com` or `203.0.113.10`. |
| `APP_DOMAIN` | The public hostname used after the TLS proxy is configured. For local-only setup, keep `localhost:8000`. |

The remaining defaults are already wired for the Compose stack:

- `DB_HOST=db`, `DB_PORT=5432`, `DB_NAME=backupsheep`, `DB_USER=backupsheep`
- `RABBITMQ_HOST=rabbitmq`, `RABBITMQ_USER=backupsheep`, `RABBITMQ_VHOST=backupsheep`
- `BACKUPSHEEP_BIND_ADDRESS=127.0.0.1` (put a TLS proxy on the same host)
- `DJANGO_DEBUG=false`, `DJANGO_HTTPS=false` (enable HTTPS only behind a real TLS proxy)

Provider/email/storage credentials can stay blank — you add those later through the UI or
`.env` only for the integrations you actually use. See [Configuration](configuration.md)
for the full reference.

### 2. Build and start

```bash
docker compose up --build
```

On first start, Compose:

1. starts `db` (PostgreSQL) and `rabbitmq`, waiting for both to pass healthchecks;
2. runs the one-shot **`migrate`** service, which applies all database migrations **and
   seeds the reference data** (the 18 backup sources, 26 storage types, and provider
   regions a fresh install needs) and creates the cache table, then exits;
3. starts the web **`app`**, the five Celery **workers**, and **`beat`**.

Add `-d` to run detached. To rebuild after pulling new code: `docker compose up --build -d`.

### 3. Open the setup wizard

Browse to **http://localhost:8000/** on the Docker host (or through an SSH tunnel). A fresh install
redirects you into the first-run wizard automatically. Walk through it — the first account
you create becomes the admin and you're logged straight in. See
[First-run wizard](first-run.md).

### 4. (Optional) Create a Django admin superuser

The wizard's admin runs the BackupSheep console but is intentionally **not** a Django
superuser, so it cannot open `/django-admin/`. If you want the Django admin site, create a
superuser separately:

```bash
docker compose run --rm app python manage.py createsuperuser
```

### 5. Production

The `app` service serves plain HTTP on loopback `127.0.0.1:8000`. For anything internet-facing, put a
TLS-terminating reverse proxy in front of it and harden the config — see
[Production deployment](deployment.md) before you expose it.

### Updating

```bash
git pull
docker compose up --build -d        # re-runs migrate automatically
```

Migrations and the reference-data seed are idempotent, so re-running is safe.

## Running without Docker (advanced)

BackupSheep is a standard Django project (`manage.py`). You can run it directly with
Python 3.12+ (3.14 tested), a PostgreSQL database, a RabbitMQ broker, and the system backup
tools (`lftp`, `pg_dump` 14–18, `mysqldump`/`mariadb-dump`). For MySQL 8 targets you need
the real Oracle MySQL client — the MariaDB-compat `mysqldump` rejects MySQL 8 dump flags;
the Docker image ships the Oracle MySQL 8.4 client in `/opt/mysql/bin` and picks it up
automatically (`CoreAuthDatabase.bin_path`). Install `requirements.txt`,
set the same `.env`, then run `manage.py migrate`, `manage.py collectstatic`, a gunicorn
server, the Celery workers, and Celery beat. The `Dockerfile` is the canonical reference
for the exact system packages required.
