# First-run setup wizard

The very first time you open a fresh install, BackupSheep redirects you into a 5-step
setup wizard. You can't skip it — every request is funneled to `/onboarding/` until setup
is finished, and once finished the wizard is **permanently locked** (it can never create a
second admin or be re-run from the browser).

## The steps

### 1. Account
Create the **first admin**: full name, optional organization, email (this is also your
login username), and a password. Submitting it creates your user, member, and account, and
logs you in automatically.

> **Important:** this is a one-time action. The wizard refuses to create a second admin
> once one exists. The first account is the account owner; you can invite more members
> later from the console (see [Usage → Team accounts](usage.md#team-accounts-groups--permissions)).

### 2. Application settings
Set the display **app name**, the public **protocol + domain** this install is reached at
(used for links and OAuth redirects), and the default **timezone**.

### 3. Email (optional but recommended)
Choose a transactional-email provider — **Postmark**, **Mailgun**, or **Amazon SES** — and
enter its credentials, or pick **Disabled** to skip. You can send a **test email** to
confirm the settings before continuing. Credentials are stored encrypted (keyed off your
`DJANGO_SECRET_KEY`).

> **If you disable email**, password-reset emails cannot be delivered. A locked-out admin
> then has to reset the password from the server:
> `docker compose run --rm app python manage.py changepassword <email>`. Keep that in mind,
> or configure a provider. See [Troubleshooting](troubleshooting.md).

### 4. Storage destination
Pick where backups are stored. Each provider tile opens the storage-setup screen in a new
tab; configure it and come back. You can add more destinations any time. (Object-storage
providers like S3/B2/Wasabi just need keys + bucket; OAuth providers like Dropbox/Google
Drive/OneDrive/pCloud need their app credentials in `.env` first — see
[Providers](providers.md).)

### 5. Sources
Connect your first thing to back up — a cloud account, server, database, or website —
again in a new tab. This step is optional; you can do it later from the console.

### Finish
Click **Finish setup**. This marks the install configured, locks the wizard, and drops you
on the dashboard.

## Admin accounts explained

There are two distinct "admin" concepts:

| | Wizard admin (account owner) | Django superuser |
|---|---|---|
| Created by | Step 1 of the wizard | `manage.py createsuperuser` |
| Logs into | the BackupSheep console (`/console`) | the Django admin (`/django-admin/`) |
| Is a Django superuser? | **No** (by design) | Yes |

The console deliberately runs as a non-superuser; the redirect middleware keeps superusers
*out* of `/console`. So the wizard admin can't reach `/django-admin/`, and a superuser
can't use the console — they're separate roles. Most operators only ever need the wizard
admin. Create a superuser only if you want Django's admin site:

```bash
docker compose run --rm app python manage.py createsuperuser
```

## Re-running setup

You generally can't, and shouldn't need to. If you must (e.g. to re-trigger the wizard in
a test environment), it keys off the `setup_completed` flag on the `core_site_settings`
singleton row and the existence of any user — clearing those in the database re-opens it.
