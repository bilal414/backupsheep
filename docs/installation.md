# Installation

This guide stands up a working BackupSheep instance with the bundled Docker Compose
stack. It's the recommended way to self-host.

## Prerequisites

- A Linux host (or any machine) with **Docker** and the **Docker Compose plugin**
  (`docker compose version` should work).
- **git**.
- ~2 GB RAM to start; backups of large databases/sites need disk for the working copy.

The stack includes its own PostgreSQL and Redis, so you don't need to install those
separately. (You *can* point at external ones — see [Configuration](configuration.md).)

## 1. Clone and configure

```bash
git clone <your-fork-or-this-repo-url> backupsheep
cd backupsheep
cp .env_sample .env
```

Open `.env` and set, at minimum:

| Variable | Set it to |
|----------|-----------|
| `DJANGO_SECRET_KEY` | A long random string. Generate one: `python -c "import secrets; print(secrets.token_urlsafe(64))"`. **Keep it stable** — changing it later logs everyone out and makes stored email credentials undecryptable. |
| `DB_PASSWORD` | Any password you choose for the bundled PostgreSQL. |

The remaining defaults are already wired for the Compose stack:

- `DB_HOST=db`, `DB_PORT=5432`, `DB_NAME=backupsheep`, `DB_USER=backupsheep`
- `CELERY_BROKER_URL=redis://redis:6379/0`
- `DJANGO_DEBUG=false`, `DJANGO_ALLOWED_HOSTS=*` (tighten the host for production)

Provider/email/storage credentials can stay blank — you add those later through the UI or
`.env` only for the integrations you actually use. See [Configuration](configuration.md)
for the full reference.

## 2. Build and start

```bash
docker compose up --build
```

On first start, Compose:

1. starts `db` (PostgreSQL) and `redis`, waiting for both to pass healthchecks;
2. runs the one-shot **`migrate`** service, which applies all database migrations **and
   seeds the reference data** (the 20 backup sources, 25 storage types, and provider
   regions a fresh install needs) and creates the cache table, then exits;
3. starts the web **`app`**, the five Celery **workers**, and **`beat`**.

Add `-d` to run detached. To rebuild after pulling new code: `docker compose up --build -d`.

## 3. Open the setup wizard

Browse to **http://localhost:8000/** (or your host's address/port). A fresh install
redirects you into the first-run wizard automatically. Walk through it — the first account
you create becomes the admin and you're logged straight in. See
[First-run wizard](first-run.md).

## 4. (Optional) Create a Django admin superuser

The wizard's admin runs the BackupSheep console but is intentionally **not** a Django
superuser, so it cannot open `/django-admin/`. If you want the Django admin site, create a
superuser separately:

```bash
docker compose run --rm app python manage.py createsuperuser
```

## 5. Production

The `app` service serves plain HTTP on `:8000`. For anything internet-facing, put a
TLS-terminating reverse proxy in front of it and harden the config — see
[Production deployment](deployment.md) before you expose it.

## Updating

```bash
git pull
docker compose up --build -d        # re-runs migrate automatically
```

Migrations and the reference-data seed are idempotent, so re-running is safe.

## Running without Docker (advanced)

BackupSheep is a standard Django project (`manage.py`). You can run it directly with
Python 3.12+ (3.14 tested), a PostgreSQL database, a Redis broker, and the system backup
tools (`lftp`, `pg_dump` 14–18, `mysqldump`/`mariadb-dump`). For MySQL 8 targets you need
the real Oracle MySQL client — the MariaDB-compat `mysqldump` rejects MySQL 8 dump flags;
the Docker image ships the Oracle MySQL 8.4 client in `/opt/mysql/bin` and picks it up
automatically (`CoreAuthDatabase.bin_path`). Install `requirements.txt`,
set the same `.env`, then run `manage.py migrate`, `manage.py collectstatic`, a gunicorn
server, the Celery workers, and Celery beat. The `Dockerfile` is the canonical reference
for the exact system packages required.
