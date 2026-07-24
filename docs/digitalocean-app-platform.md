# DigitalOcean App Platform

BackupSheep can be deployed directly from this public repository with DigitalOcean App
Platform:

[![Deploy to DO](https://www.deploytodo.com/do-btn-blue.svg)](https://cloud.digitalocean.com/apps/new?repo=https://github.com/bilal414/backupsheep/tree/main)

The button reads [`.do/deploy.template.yaml`](../.do/deploy.template.yaml). It creates:

- the public BackupSheep web console;
- an internal RabbitMQ service for Celery;
- one Celery worker that consumes every queue;
- a singleton Celery Beat scheduler;
- a pre-deploy migration job; and
- a PostgreSQL development database.

DigitalOcean deploy buttons require a public repository. This one targets the `main`
branch, so make sure these changes are merged and pushed there before sharing the button.

## Create the app

On the DigitalOcean deployment form, replace all three secret placeholders before clicking
**Create App**:

- `DJANGO_SECRET_KEY` — generate one with `python -c "import secrets; print(secrets.token_urlsafe(64))"`;
- `ONBOARDING_INSTALL_TOKEN` — use another random, private token; and
- `RABBITMQ_DEFAULT_PASS` — use a long random password.

Save the onboarding token. Once the deployment is healthy, open the App Platform URL and
enter it in the first step of the BackupSheep onboarding wizard. The template binds the
DigitalOcean app domain and PostgreSQL credentials automatically, enables HTTPS-aware
Django settings, and runs migrations before the web service is deployed.

If you later add a custom domain in App Platform, update `DJANGO_ALLOWED_HOSTS` to include
it and set `APP_DOMAIN` to that host (with `APP_PROTOCOL=https://`) before using it.

## Important platform limits

App Platform does not provide a durable, shared writable volume to these components. The
template deliberately runs one all-queue worker so a dump and its subsequent upload use
the same temporary filesystem, but it is not a substitute for persistent shared storage.

- Do **not** use BackupSheep's **Local Storage** destination on App Platform. Use S3,
  DigitalOcean Spaces, B2, R2, or another external storage destination instead.
- Treat the included PostgreSQL **development database** and internal RabbitMQ service as
  a low-volume starting point. Upgrade PostgreSQL to a managed database and use the
  Docker Compose install on a DigitalOcean Droplet for production workloads, large local
  working files, or horizontally scaled workers.
- App Platform bills each web service, worker, and database component. Review the
  deployment summary and adjust the region/instance sizes before creating the app.

For a production self-hosted installation with persistent local storage, use the
[one-command Docker installation](installation.md#one-command-server-install) on a
DigitalOcean Droplet instead.
