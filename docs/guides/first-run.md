# First-run setup

A fresh database is gated by a one-time onboarding wizard. The person creating the first
account must present an install token that proves access to the host or container.

## Before opening the wizard

Confirm that migrations succeeded and the application is healthy:

```bash
docker compose ps --all
docker compose logs --tail=100 migrate app
curl -fsS http://127.0.0.1:8000/healthz/
```

The `migrate` service should be `Exited (0)`, `app` should become healthy and the health
request should return `ok`.

If `ONBOARDING_INSTALL_TOKEN` is set in `.env`, use that value. When it is blank, make one
request to `/onboarding/` so the app creates a token, then read it from the shared volume:

```bash
docker compose exec app cat /code/_storage/install_token
```

Treat the token as a temporary secret. Anyone who can reach an unconfigured instance and
has the token can create the first account.

## The five steps

### 1. Create the account owner

Enter the install token, full name, optional organization, email and password. The email
becomes the Django username. Password validation uses Django's similarity, minimum-length,
common-password and numeric-password validators.

The transaction creates:

- the first Django user;
- a BackupSheep member in UTC;
- the first BackupSheep account with a new account encryption key;
- the primary/current membership linking them.

The browser is signed in immediately. If any Django user already exists, this step refuses
to create another first owner.

### 2. Set application identity and time

Choose the display name, public protocol, public domain and default timezone. The timezone
also becomes the first member's timezone.

Use the actual public URL. For example, after configuring TLS:

```text
Protocol: https://
Domain:   backups.example.com
```

The wizard stores these settings in PostgreSQL. Keep the matching environment values
(`APP_PROTOCOL`, `APP_DOMAIN`, `DJANGO_ALLOWED_HOSTS`, `DJANGO_HTTPS`) aligned as described
in [Configuration](configuration.md#the-public-url-tuple).

### 3. Configure transactional email

Choose Postmark, Mailgun, Amazon SES or Disabled. Required fields are validated for the
chosen provider and a test message can be sent to the owner's email before continuing.

Saved email credentials are encrypted with a key derived from `DJANGO_SECRET_KEY`. Keep
that key stable and included in the instance's disaster-recovery material.

With email disabled, backups still run, but password-reset and invitation messages cannot
be delivered. An operator can recover a password from the host:

```bash
docker compose run --rm app python manage.py changepassword owner@example.com
```

### 4. Add storage

The wizard lists enabled storage types. Opening a provider takes you to its normal storage
setup flow; after adding and validating it, return to onboarding. Multiple destinations
can be added now or later.

Local Storage needs durable capacity beneath `/backups`. Object-storage destinations need
provider credentials and an existing bucket/container as required by their adapter. OAuth
destinations need application credentials in `.env` before starting their connect flow.
See the [provider matrix](../reference/provider-matrix.md).

### 5. Add sources

Connect the first database, website, SaaS application or cloud account, then select a
resource to protect. This step can be deferred until after onboarding.

For SSH/SFTP sources, first install a host key that was verified out-of-band. For cloud
providers, prefer narrowly scoped credentials and validate discovery before scheduling a
backup.

### Finish

Submitting the final step sets `setup_completed` and its timestamp, then redirects to the
dashboard. Once the running processes observe completion, all onboarding URLs redirect to
the console.

## Console owner versus Django superuser

The first account is the BackupSheep account owner, not a Django superuser. These roles are
deliberately separate:

| Role | Interface | Creation |
| --- | --- | --- |
| BackupSheep owner | `/console` | First-run wizard |
| Django superuser | `/django-admin/` | `manage.py createsuperuser` |

Create a Django superuser only when direct Django administration is operationally
required:

```bash
docker compose run --rm app python manage.py createsuperuser
```

A Django superuser is not a substitute for a BackupSheep member and is redirected away
from the normal console.

## Post-onboarding verification

Before relying on the instance:

1. confirm the public HTTPS URL, login and logout;
2. send an email test if email is enabled;
3. validate every storage destination;
4. validate a disposable source connection;
5. create an on-demand backup and watch its durable status through completion;
6. perform a restore rehearsal into a disposable target;
7. verify notifications and activity-log entries;
8. establish the [instance backup plan](disaster-recovery.md).

An installation, migration or green health check does not prove that a provider backup is
recoverable. A successful restore rehearsal is the relevant evidence.

## The wizard cannot be rerun

There is no supported browser workflow for resetting onboarding. Invite additional users
from the console and change application/email settings there. Do not clear users or edit
the setup-completed row in a production database; recover the existing instance or build a
new one and restore verified data.
