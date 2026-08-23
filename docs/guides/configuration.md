# Configuration

BackupSheep reads configuration when each process starts. Compose passes `.env` to every
application service with `env_file: .env`; changing `.env` therefore requires recreating
the affected containers.

## Configuration precedence

Unless `BACKUPSHEEP_SECRETS` is set, settings are merged in this order:

1. `.env_sample` supplies non-secret defaults;
2. `.env` overrides the sample;
3. process environment variables override both files.

If `BACKUPSHEEP_SECRETS` exists in the process environment, its JSON object becomes the
entire configuration. The sample and `.env` are not merged into it. This mode is for a
secret-manager integration that can supply every required key; an incomplete object can
prevent Django from starting.

For normal Compose deployments, copy `.env_sample` wholesale and retain optional blank
keys. The exhaustive key list is in the
[environment-variable reference](../reference/environment-variables.md).

## Safe editing workflow

```bash
cd /opt/backupsheep
cp -p .env .env.before-config-change
chmod 600 .env .env.before-config-change
# Edit .env with your preferred editor.
docker compose config --quiet
docker compose up --detach --remove-orphans
docker compose ps --all
docker compose logs --tail=100 app worker-cloud beat
```

`docker compose config` expands the Compose model and can include resolved environment
values. Do not paste its full output into issues or chat; use `--quiet` for validation.
Remove the local backup copy after the change is verified, or store it in an encrypted
secrets backup.

## The public URL tuple

These values must agree:

```dotenv
DJANGO_ALLOWED_HOSTS='backups.example.com,localhost,127.0.0.1'
APP_PROTOCOL='https://'
APP_DOMAIN='backups.example.com'
DJANGO_HTTPS=true
```

- `DJANGO_ALLOWED_HOSTS` is a comma-separated host list, without schemes or paths.
- `APP_PROTOCOL` includes `://`.
- `APP_DOMAIN` is the public host and optional port, without a scheme or path.
- `DJANGO_HTTPS=true` is correct only after a real TLS proxy forwards
  `X-Forwarded-Proto: https`.

`APP_PROTOCOL + APP_DOMAIN` forms `APP_URL`, the CSRF trusted origin and the base of OAuth
callback URLs. A mismatch commonly breaks sign-in cookies, generated links or OAuth
callbacks.

## Secrets that must remain stable

`DJANGO_SECRET_KEY` is not a disposable deployment secret. It signs Django data and
derives the encryption key for email-provider credentials stored in PostgreSQL. Rotating
it logs users out and makes those saved email credentials unreadable until re-entered.

Provider, source and storage credentials entered through the console are encrypted with
a per-account Fernet key stored with the account data. Back up PostgreSQL securely and
treat it as sensitive even though credential fields are encrypted.

For the bundled stack, set a strong `DB_PASSWORD` before the `pgdata` volume is created.
Changing only `.env` after PostgreSQL initialization does not change the database role's
existing password.

## Database configuration

The bundled database uses:

```dotenv
DB_NAME='backupsheep'
DB_USER='backupsheep'
DB_PASSWORD='replace-me'
DB_HOST='db'
DB_PORT='5432'
```

For managed PostgreSQL, set `DATABASE_URL`. A non-empty URL overrides all five discrete
connection values for Django. It must use `postgres://` or `postgresql://`. Set
`DB_SSLMODE=require` when the provider requires TLS and the URL does not already contain
an `sslmode` option.

The Compose `db` service still reads the discrete `DB_*` values. If using only an
external database, use a deployment override that removes or ignores the bundled service
and update dependency wiring deliberately; the stock Compose file always starts `db`.

## RabbitMQ configuration

BackupSheep accepts RabbitMQ brokers only. Configuration precedence is:

1. if `RABBITMQ_HOST` is non-empty, build a URL from `RABBITMQ_HOST`,
   `RABBITMQ_PORT`, `RABBITMQ_USER`, `RABBITMQ_PASSWORD` and `RABBITMQ_VHOST`;
2. otherwise use `CLOUDAMQP_URL` when present;
3. otherwise use `CELERY_BROKER_URL`;
4. otherwise fall back to the bundled `rabbitmq` service.

Use `amqp://` or `amqps://`. The well-known `guest/guest` credentials are acceptable
only inside the private Compose network; set unique credentials for any external broker.
The stock RabbitMQ service persists `/var/lib/rabbitmq` in `rabbitmq_data`.

## Filesystem configuration

| Path | Compose volume | Contents | Required visibility |
| --- | --- | --- | --- |
| `/code/_storage` | `backup_workdir` | Work files, restore logs, incremental website cache, reviewed SSH host keys, optional managed SSH private key, install token | `app`, database/files/storage/log workers as mounted in Compose |
| `/backups` | `backup_storage` | Archives created by the Local Storage destination | `app` and all backup workers |

`BS_LOCAL_STORAGE_PATH` changes the Local Storage root inside each process. If it points
somewhere other than `/backups`, mount that same durable path into every service that uses
it. Do not point it at a container-only ephemeral filesystem.

`SSH_KNOWN_HOSTS_PATH` defaults to `_storage/ssh_known_hosts`. Relative values resolve
beneath the repository base directory. Unknown SSH/SFTP hosts are rejected. Populate the
file only after verifying the server fingerprint through an independent channel.

Managed SSH-key authentication is advertised only when both
`SSH_MANAGED_PRIVATE_KEY_PATH` and `SSH_MANAGED_PUBLIC_KEY` are configured and the private
key file exists. Keep the private key on the shared work volume with mode `0600`.

## Email and notifications

The first-run wizard can save Postmark, Mailgun or SES settings in the database; `.env`
values are the fallback. Email is optional for backups, but password resets, invitations
and email notifications cannot be delivered without it.

Slack and Telegram are independent optional channels:

- Slack requires `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET` and `SLACK_TOKEN_URL` before
  connecting a workspace in the console.
- Telegram requires `TELEGRAM_BOT_KEY`; the chat is selected in the console.

After configuration, send provider/channel test messages from the corresponding console
settings rather than assuming a successful container restart proves delivery.

## Provider application credentials

Most cloud-source connections and object-storage destinations accept their credential in
the console. Environment-level application credentials are needed only for provider OAuth
or application-signing flows:

| Integration | Environment keys |
| --- | --- |
| Dropbox storage | `DROPBOX_APP_KEY`, `DROPBOX_APP_SECRET` |
| Google Drive storage | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` |
| Microsoft OneDrive storage | `MS_CLIENT_ID`, `MS_CLIENT_SECRET_VALUE` and the related `MS_*` tenant/application values |
| pCloud storage | `PCLOUD_CLIENT_ID`, `PCLOUD_CLIENT_SECRET` |
| Basecamp source | `BASECAMP_CLIENT_ID`, `BASECAMP_CLIENT_SECRET` |
| DigitalOcean OAuth connection | `DIGITALOCEAN_APP_CLIENT_ID`, `DIGITALOCEAN_APP_CLIENT_SECRET` |
| OVH Public Cloud | matching `OVH_CA_*`, `OVH_EU_*` or `OVH_US_*` application pair |

API-host and OAuth-endpoint variables have public defaults in settings. Override them only
for a reviewed provider change, proxy or test environment.

## Recovery and timeout tuning

The sample values coordinate renewable leases, worker heartbeats and periodic recovery.
Do not shorten or lengthen one value in isolation. In particular:

- heartbeat periods should remain comfortably below their matching lease duration;
- recovery stale windows must exceed normal healthy scheduling/heartbeat jitter;
- `BACKUP_STORAGE_STALE_SECONDS` must allow the largest normal upload to finish;
- provider timeouts must remain bounded so a worker can release/reconcile work;
- restore archive limits protect disk and decompression resources and should be raised
  only with matching capacity and security review.

The defaults are listed in the
[environment-variable reference](../reference/environment-variables.md). Internal
`*_ACCEPTANCE_FAULT_*` and `BACKUPSHEEP_UPCLOUD_FAULT_*` switches exist for controlled
reliability tests; they are not production tuning controls and must remain unset.

## Apply and verify a change

```bash
docker compose up --detach --remove-orphans
docker compose ps --all
curl -fsS http://127.0.0.1:8000/healthz/
docker compose exec app python manage.py check
docker compose exec worker-cloud celery -A backupsheep inspect ping
```

Then verify the affected behavior: complete an OAuth connection, send a test email,
validate a storage destination, or run a disposable backup and restore. A healthy web
container alone does not validate provider credentials or worker execution.
