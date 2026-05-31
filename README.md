# BackupSheep

**Self-hosted backup automation.** Schedule offsite backups of your databases, servers,
and websites, and take snapshots of your cloud instances — across 20+ sources and 25+
storage destinations, with daily/weekly/monthly retention, all from one web console. No
code, no SaaS account.

> **Status: self-hostable (beta).** BackupSheep was a paid SaaS from 2017–2023 serving
> 6,500+ users. It has been rewritten and open-sourced as a self-hosted application: all
> SaaS/billing machinery has been removed so you can run it for yourself. Licensed under
> the GNU GPLv3 (see [LICENSE](LICENSE)).

---

## Quick start (Docker Compose)

You need [Docker](https://docs.docker.com/get-docker/) with the Compose plugin, and `git`.

```bash
git clone <your-fork-or-this-repo-url> backupsheep
cd backupsheep

cp .env_sample .env
# Edit .env and set at least:
#   DJANGO_SECRET_KEY  -> a long random string (python -c "import secrets; print(secrets.token_urlsafe(64))")
#   DB_PASSWORD        -> a database password of your choice
# The other defaults already target the bundled db/redis services.

docker compose up --build
```

Then open **http://localhost:8000/** — you'll be guided through the first-run setup
wizard (create your admin account, configure email + storage, connect your first source).

That's the whole happy path. See **[docs/installation.md](docs/installation.md)** for
details and **[docs/first-run.md](docs/first-run.md)** for a walkthrough of the wizard.

> The web app serves plain HTTP on port 8000 and is meant to sit behind your own
> TLS-terminating reverse proxy in production. Before exposing it to the internet, read
> **[docs/deployment.md](docs/deployment.md)** (TLS, `DJANGO_HTTPS`, `ALLOWED_HOSTS`,
> secrets).

---

## What it backs up

**Databases (offsite dumps)** — MySQL, MariaDB, PostgreSQL.

**Websites / servers (offsite file backups)** — over FTP, FTPS, SFTP, or SSH.

**Cloud server & volume snapshots** — DigitalOcean, AWS (EC2, RDS, Lightsail), Hetzner,
Linode, Vultr, UpCloud, Oracle Cloud, Google Cloud, OVH (CA/EU/US).

**SaaS apps** — WordPress, Basecamp.

**Store backups in** — Amazon S3, Backblaze B2, Wasabi, Cloudflare R2, DigitalOcean
Spaces, Google Cloud Storage, Google Drive, Azure Blob, Dropbox, OneDrive, pCloud,
IDrive e2, IBM COS, Oracle, Scaleway, Linode, Vultr, UpCloud, Exoscale, Filebase, IONOS,
Leviia, RackCorp, Tencent COS, Alibaba OSS. (Connect multiple destinations at once.)

Full provider details: **[docs/providers.md](docs/providers.md)**.

---

## Documentation

| Guide | What's in it |
|-------|--------------|
| [Installation](docs/installation.md) | Prerequisites, Docker Compose setup, the `.env` you must edit |
| [Configuration](docs/configuration.md) | Full environment-variable reference (required vs optional) |
| [First-run wizard](docs/first-run.md) | The 5 setup steps; admin accounts & `/django-admin` |
| [Usage](docs/usage.md) | Connect a source, add storage, schedule backups, retention, restore |
| [Providers](docs/providers.md) | Every backup source & storage destination, and what each needs |
| [Production deployment](docs/deployment.md) | HTTPS/reverse proxy, hardening, secrets, backups of BackupSheep |
| [Scaling & operations](docs/scaling.md) | Worker queues, scaling uploads, the beat singleton, multi-host |
| [Troubleshooting](docs/troubleshooting.md) | Common failures, FAQ, known limitations |

Also: [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md)

---

## Architecture

One Docker image runs as several services so a heavy backup can't starve the web UI:

- **app** — the Django web console (gunicorn + WhiteNoise) on port 8000
- **migrate** — one-shot: applies DB migrations + seeds reference data, then exits
- **worker-cloud / worker-database / worker-files / worker-storage / worker-logs** —
  specialized Celery workers (provider snapshots, DB dumps, file dumps, uploads, logs)
- **beat** — the Celery scheduler that fires scheduled backups (keep exactly one)
- **db** (PostgreSQL) and **redis** (the Celery broker)

Technology: Django 6, PostgreSQL, Redis + Celery, gunicorn, Alpine.js + Tailwind CSS.
See [docs/scaling.md](docs/scaling.md) for how the workers fit together.

---

## License

BackupSheep is free software under the **GNU General Public License v3.0**. It comes with
**no warranty** — see [LICENSE](LICENSE). You may run, study, modify, and redistribute it
under the terms of the GPLv3.
