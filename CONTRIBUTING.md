# Contributing to BackupSheep

Thanks for your interest in improving BackupSheep! It's a Django 6 project (Python 3.12+;
3.14 tested) with Celery workers, a PostgreSQL database, and a Tailwind/Alpine.js console.

## Development setup

The fastest path is the Docker Compose stack (see [docs/installation.md](docs/installation.md)).
For a local Python environment:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env_sample .env          # point DB_* at a local Postgres, set DJANGO_SECRET_KEY
python manage.py migrate
python manage.py runserver
```

You also need a PostgreSQL database and a RabbitMQ broker for full functionality, plus the
system backup tools (`lftp`, `pg_dump` 14–18, `mysqldump`/`mariadb-dump`) if you exercise
real backups — the `Dockerfile` is the canonical list.

## Running the tests

Tests use Django's `TestCase` and run against PostgreSQL (no pytest). The runner creates
and destroys a temporary `test_<DB_NAME>` database, so point `.env` at a Postgres you can
create databases on:

```bash
python manage.py test apps.tests apps.console.onboarding
```

Shared fixtures live in `apps/tests/` (`factories.py` builds an account chain, regions,
connections, storage, schedules; `base.py` provides `BaseTestCase`). External services
(cloud APIs, FTP/SFTP, boto3, email) are mocked. Please add or update tests with your
change, and keep the suite green.

Before opening a PR, also run:

```bash
python manage.py check
python manage.py makemigrations --check --dry-run   # no un-committed model changes
```

## Pull requests

- Branch off `main`; keep PRs focused.
- Match the surrounding code style, comment density, and naming.
- If you change models, include the migration.
- Don't reintroduce SaaS-only concepts (billing, plans/quotas, hosted "managed" storage) —
  this is a self-hosted application.
- Describe what changed and how you tested it.

## Reporting bugs & requesting features

Open a GitHub issue with clear reproduction steps (and `docker compose logs`, secrets
redacted, for runtime problems). For **security** issues, follow [SECURITY.md](SECURITY.md)
instead of filing a public issue.

## License

By contributing, you agree your contributions are licensed under the project's
**GNU GPLv3** (see [LICENSE](LICENSE)).
