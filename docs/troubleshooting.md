# Troubleshooting & FAQ

## Boot / setup

**The `db` container won't start, or the app can't connect.**
Make sure `.secrets/db_password` exists with the value used to initialize PostgreSQL and
that `DB_HOST=db` / `DB_PORT=5432` are set for the Compose stack. Keep the direct
`DB_PASSWORD` key blank. If you replace the secret *after* the `db` volume was first
created, the volume keeps the original credential. Restore the original value or rotate
the role from a trusted database console. Only for a disposable, proven-empty install may
you recreate volumes; `./backupsheep-compose --allow-data-deletion down -v` irreversibly deletes database, broker,
work, SSH trust and Local Storage data.

**Celery workers log "connection refused" to RabbitMQ (amqp).**
Keep `RABBITMQ_HOST=rabbitmq` (the Compose service name), not `localhost`, and verify the
dedicated `RABBITMQ_USER`, `.secrets/rabbitmq_password`, and `RABBITMQ_VHOST` match the
broker's persistent-volume initialization. Keep direct `RABBITMQ_PASSWORD` blank. Do not
replace the secret for an existing volume without rotating the broker credential through a
trusted session; use the [RabbitMQ migration gate](guides/rabbitmq-upgrade.md).

**`migrate` exits with an error.**
Check the `migrate` service logs: `./backupsheep-compose logs migrate`. It applies schema
migrations + the reference-data seed. It's idempotent; fix the cause (usually DB
connectivity) and `./backupsheep-compose up` again.

**The UI loads but is unstyled.**
Static files are collected into the immutable image at build time and served by
WhiteNoise. Explicitly rebuild the reviewed checkout, then recreate the core:

```bash
./backupsheep-compose build db app
./backupsheep-compose up --detach
```

## Accounts & access

**I forgot the admin password and email isn't configured.**
Reset it from the server (works without email and without a superuser):
```bash
./backupsheep-compose run --rm app python manage.py changepassword <your-login-email>
```

**Password reset says it sent an email but nothing arrives.**
Password reset requires a configured email provider (Postmark/Mailgun/SES). With email
disabled, use `changepassword` above, and configure a provider in the console settings to
enable self-service reset.

**`/django-admin/` redirects me to login / I can't get in with my console account.**
The console admin is intentionally **not** a Django superuser, and superusers are kept out
of the console. Create a separate superuser for the Django admin site:
```bash
./backupsheep-compose run --rm app python manage.py createsuperuser
```

**The setup wizard won't let me create another admin / keeps redirecting.**
By design — the wizard is one-time and locks after setup. Invite additional members from
the console instead.

**An invite email never arrived.**
Invites go out through the configured transactional-email provider; with email disabled
the message can't be delivered (the invite itself is still created). Configure a provider,
then use **Resend** under **Settings → Invites** — resending also restarts the 7-day
acceptance window. Cancelled or expired links simply stop working; send a fresh invite.

## Backups & runs

**Clicking "Transfer log" / "Directory-tree log" download returns "not available".**
Expected. Those per-backup *log download* buttons depended on SaaS-hosted log buckets and
are disabled in the self-hosted build (the endpoints return a clean 404 message). Backup
status and history in the console are unaffected; run logs live on the local `_storage`
volume.

**A storage provider tile shows a blank/non-working connect screen.**
OAuth destinations (Dropbox, Google Drive, OneDrive, pCloud) and the Basecamp source need
their app credentials in `.env` before the "connect" flow works — see
[Configuration](configuration.md). Object-storage providers (S3, B2, Wasabi, …) need no
env config; enter keys in the UI.

**Scheduled backups fire twice.**
You're running more than one `beat`. Keep exactly one — see [scaling.md](scaling.md).

**Uploads are slow / backlogged.**
Scale the already-authorized operations pool:
`./backupsheep-compose --profile operations up -d --scale worker-storage=4`.

## Security / production

**I set `DJANGO_DEBUG=false` but still see debug pages / I can't log in over HTTPS.**
Debug is parsed leniently now (`false/0/no/off` all turn it off) — rebuild so the new
settings are loaded. If login fails after enabling `DJANGO_HTTPS=true`, confirm you're
actually serving HTTPS (Secure cookies require it). See [deployment.md](deployment.md).

**I rotated `.secrets/django_secret_key` and everyone got logged out / email creds broke.**
The secret key signs sessions and derives the email-credential encryption key. Keep it
stable; if you must rotate it, re-enter email-provider credentials afterward.

## Still stuck?

Open an issue on the project's GitHub repository with your `./backupsheep-compose logs` output
(redact secrets) and the steps to reproduce.
