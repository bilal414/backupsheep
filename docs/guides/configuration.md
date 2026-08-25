# Configuration

BackupSheep reads configuration when each process starts. Compose passes non-secret and
optional integration settings from `.env` to each application service. The stock stack
mounts the Django, three purpose-specific PostgreSQL, and RabbitMQ credentials from
separate files in `.secrets`;
only `app` also receives the onboarding-token file. Changing either configuration source
requires recreating the affected containers.

## Configuration precedence

Unless `BACKUPSHEEP_SECRETS` is non-empty, settings are merged in this order:

1. `.env_sample` supplies non-secret defaults;
2. `.env` overrides the sample;
3. process environment variables override both files;
4. each allowlisted non-empty `*_FILE` pointer overrides its corresponding direct secret.

If `BACKUPSHEEP_SECRETS` is non-empty in a non-Compose process environment, its JSON
object becomes the entire configuration. The sample and `.env` are not merged into it.
This mode is for a separately reviewed PaaS/secret-manager integration that supplies
every required key. The stock installer and `./backupsheep-compose` reject the variable,
and stock Compose pins it blank, because it would bypass the file-backed deployment
contract.

For normal Compose deployments, copy `.env_sample` wholesale and retain optional blank
keys. Keep `DJANGO_SECRET_KEY`, `DB_PASSWORD`, `RABBITMQ_PASSWORD` and
`ONBOARDING_INSTALL_TOKEN` blank after creating the six required protected files and the
optional `ssh_managed_private_key` file exactly as shown in the
[installation guide](installation.md#manual-docker-compose-installation). Keep direct
`SSH_MANAGED_PRIVATE_KEY_PATH` blank: the image entrypoint exports the validated private
tmpfs copy itself. The
exhaustive key list is in the
[environment-variable reference](../reference/environment-variables.md).

Treat `.env` as configuration data, never executable startup input. The verified installer
rejects `LD_AUDIT`, `LD_LIBRARY_PATH`, `LD_PRELOAD` and `SSLKEYLOGFILE`; stock Compose
also blanks those values before application-image startup. The immutable entrypoint then
clears shell and Python startup hooks, loader paths and TLS-key logging, establishes fixed
`PATH`/`PYTHONPATH` values, and executes configured commands as argv without `eval`.

## Safe editing workflow

```bash
cd /opt/backupsheep
cp -p .env .env.before-config-change
chmod 600 .env .env.before-config-change
# Edit .env with your preferred editor.
./backupsheep-compose config --quiet
./backupsheep-compose up --detach
./backupsheep-compose ps --all
./backupsheep-compose logs --tail=100 db-provision migrate preflight app
```

`./backupsheep-compose config` expands the Compose model and can include resolved environment
values. Do not paste its full output into issues or chat; use `--quiet` for validation.
Remove the local backup copy after the change is verified, or store it in an encrypted
configuration backup. If operations were already enabled and the change affects workers,
review durable queue/recovery state before recreating them explicitly:

```bash
./backupsheep-compose --profile operations up --detach
```

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

The Docker deployment preflight runs Django's deployment checks. HTTPS-related warnings
are expected only for the deliberate loopback HTTP/SSH-tunnel onboarding mode. A public
deployment must terminate real TLS, use the HTTPS tuple above, and review/resolve every
deployment warning; the preflight's error threshold is not approval for public HTTP.

## Secrets that must remain stable

The value in `.secrets/django_secret_key` is not a disposable deployment secret. It signs Django data and
derives the encryption key for email-provider credentials stored in PostgreSQL. Rotating
it logs users out and makes those saved email credentials unreadable until re-entered.

Provider, source and storage credentials entered through the console are encrypted with
a per-account Fernet key stored with the account data. Back up PostgreSQL securely and
treat it as sensitive even though credential fields are encrypted.

For the bundled stack, create strong, distinct `.secrets/db_bootstrap_password`,
`.secrets/db_migrator_password`, and `.secrets/db_password` values before the `pgdata`
volume is created. The one-shot provisioner synchronizes the marked role passwords on
each core start; keep direct `.env` password values blank. The bootstrap file is mounted
only into PostgreSQL and the provisioner, the migrator file only into the provisioner
and migration service, and the runtime file only where the application needs it.

## Database configuration

The bundled database uses:

```dotenv
DB_NAME='backupsheep'
BACKUPSHEEP_DATABASE_IDENTITY_GENERATION='2'
DB_BOOTSTRAP_USER='backupsheep_bootstrap'
DB_MIGRATOR_USER='backupsheep_migrator'
DB_USER='backupsheep_runtime'
DB_PASSWORD=''
DB_HOST='db'
DB_PORT='5432'
```

The stock Compose file supplies `DB_PASSWORD_FILE=/run/secrets/db_password` to normal
Django processes. PostgreSQL initializes with `db_bootstrap_password`, while `migrate`
uses `db_migrator_password`. Do not duplicate any value in `.env` or reuse one credential
for another role. Follow the [database identity migration gate](database-identity-migration.md)
for an existing bundled database; never change the generation marker by hand.

For managed PostgreSQL, set `DATABASE_URL`. A non-empty URL overrides all five discrete
connection values for Django. It must use `postgres://` or `postgresql://`. Production
accepts an external host only with certificate and hostname verification:

```dotenv
DB_SSLMODE=verify-full
DB_SSLROOTCERT=/run/secrets/postgres-ca.pem
```

The same `sslmode=verify-full` and `sslrootcert=...` values can be URL query options.
Plaintext is a narrow single-host exception for the exact stock `db` service, loopback,
or a Unix socket. Private/RFC1918 addresses are not automatically trusted.

The Compose `db` service still reads the discrete `DB_*` values. If using only an
external database, use a deployment override that removes or ignores the bundled service
and update dependency wiring deliberately; the stock Compose file always starts `db`.

## RabbitMQ configuration

BackupSheep accepts RabbitMQ brokers only. Configuration precedence is:

1. if `RABBITMQ_HOST` is non-empty, build a URL from `RABBITMQ_SCHEME`,
   `RABBITMQ_HOST`, `RABBITMQ_PORT`, `RABBITMQ_USER`, the resolved broker-password
   secret and `RABBITMQ_VHOST`;
2. otherwise use `CLOUDAMQP_URL` when present;
3. otherwise use `CELERY_BROKER_URL`;
4. otherwise production fails closed until a broker URL or dedicated fragment credentials
   are set (non-production development retains a warning-only compatibility fallback).

Use `amqp://` or `amqps://`. Never use RabbitMQ's well-known `guest/guest` account, even
on an internal network. Stock Compose requires a non-empty
`.secrets/rabbitmq_password`, keeps the direct environment value blank, creates a
dedicated `backupsheep` user/vhost only on a fresh volume, and persists broker state in
`rabbitmq_data`. Plaintext `amqp` is accepted in production only for loopback or the exact
stock `rabbitmq` service. An external broker, including one reached over a private network,
must use `amqps`; BackupSheep requires a trusted certificate and verifies its hostname.
Set `RABBITMQ_CA_CERT` when the broker uses a private CA, otherwise system roots apply.
Do not put `ssl_*` overrides in the broker URL; they are rejected so certificate checking
cannot be disabled. Use one certificate-valid broker/load-balancer hostname in production
rather than a semicolon-separated failover URL.

## Website transfer security

Use SFTP with an out-of-band-verified host key, or FTPS. FTPS always forces TLS for both
the control and data connections; certificate and hostname verification are enabled by
default. The per-connection verification switch exists for a reviewed private/self-signed
endpoint, but disabling it permits a network attacker to impersonate that endpoint.

Plain FTP exposes the username, password and backup contents in transit and is disabled
by default. The `ALLOW_INSECURE_FTP=true` environment setting is a legacy compatibility
escape hatch, not an enterprise-safe mode.

## Filesystem configuration

| Path | Compose volume | Contents | Required visibility |
| --- | --- | --- | --- |
| `/code/_storage` | `backup_workdir` | Staged work, restore/run logs, incremental website cache, manifests and worker locks | Read/write in database, files and storage workers; completely absent from app, cloud, logs and Beat |
| `/var/lib/backupsheep/ssh-trust/known_hosts` | `ssh_trust` | UI-approved, out-of-band-verified OpenSSH host keys | Read/write in app; read-only in database and files workers; absent from cloud, storage, logs and Beat |
| `/run/secrets/ssh_managed_private_key` -> `/run/backupsheep/ssh/managed_private_key` | `.secrets/ssh_managed_private_key` | Optional deployment-managed, unencrypted SSH private key; empty means disabled | Read-only mode-`0444` source mount in app/database/files only; entrypoint validates and copies it to private tmpfs mode `0600` before exporting the target path |
| `/backups` | `backup_storage` | Archives created by the Local Storage destination | Read/write only in the storage worker; read-only in app, cloud, database and files workers; absent from logs and Beat |

`BS_LOCAL_STORAGE_PATH` changes the Local Storage root inside each process. If it points
somewhere other than `/backups`, preserve the same role-specific access policy: writable
only in the storage worker and read-only in roles that inspect or consume archives. Do not
point it at a container-only ephemeral filesystem.

The web/API process can request an incremental-cache reset but has no staging mount.
`reset_incremental_cache` runs in the storage queue, validates the canonical node ID,
anchors every removal to an opened cache-directory descriptor with no-follow checks, and
takes the same per-node incremental lock held across mirror/archive work. It therefore
cannot race a live cache writer or follow a swapped parent path. On-disk `delete_old_logs`,
upload, finalization and local cleanup are also storage-routed. Keep custom queue routing
and Compose overrides consistent with that boundary.

Outside stock Compose, `SSH_KNOWN_HOSTS_PATH` defaults to `_storage/ssh_known_hosts` and
relative values resolve beneath the repository base directory. Stock Compose instead
fixes it to `/var/lib/backupsheep/ssh-trust/known_hosts` on the dedicated `ssh_trust`
volume. Unknown SSH/SFTP hosts are rejected. Add a key through the app only after
verifying the server fingerprint through an independent channel; workers consume the
result read-only.

Managed SSH-key authentication is advertised only when both
`SSH_MANAGED_PRIVATE_KEY_PATH` and `SSH_MANAGED_PUBLIC_KEY` are configured and the private
key file exists. In stock Compose, put the optional key in installer-managed
`.secrets/ssh_managed_private_key` (mode `0444` beneath the mode-`0700` directory). Only
app/database/files receive that immutable source. Docker's source mount cannot be used
directly because OpenSSH rejects a private key with mode `0444`; the entrypoint accepts an
empty file as disabled, otherwise requires a regular, unencrypted, valid key no larger
than 64 KiB, copies it to private tmpfs as mode `0600`, and exports
`SSH_MANAGED_PRIVATE_KEY_PATH=/run/backupsheep/ssh/managed_private_key`. Do not point SSH
at `/run/secrets/ssh_managed_private_key`. Never store the key in `backup_workdir`,
`.env`, a broker message, or an image.

## Email and notifications

The first-run wizard can save Postmark, Mailgun or SES settings in the database; `.env`
values are the fallback. Email is optional for backups, but password resets, invitations
and email notifications cannot be delivered without it.

Slack and Telegram are independent optional channels:

- Slack requires `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET` and `SLACK_TOKEN_URL` before
  connecting a workspace in the console.
- Telegram requires `TELEGRAM_BOT_KEY`; the chat is selected in the console.

New activity creation writes `CoreLog` to PostgreSQL before publishing anything. When
notification fan-out is required, only the opaque integer row ID is queued to the logs
worker after the surrounding transaction commits. That worker reloads the row and performs
Slack/Telegram network I/O, keeping
arbitrary error text, webhook URLs and provider credentials out of new broker messages and
out of web/cloud/storage execution roles. Legacy dict-shaped messages are accepted only as
an upgrade compatibility path and are persisted before delivery.

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
./backupsheep-compose up --detach
./backupsheep-compose ps --all
curl -fsS http://127.0.0.1:8000/healthz/
./backupsheep-compose exec app python manage.py check
```

The profile-less command validates the core without executing provider work. If operations
were previously authorized, recreate and inspect those services separately after checking
durable queue/recovery state:

```bash
./backupsheep-compose --profile operations up --detach
./backupsheep-compose --profile operations exec worker-cloud celery -A backupsheep inspect ping
```

Then verify the affected behavior: complete an OAuth connection, send a test email,
validate a storage destination, or run a disposable backup and restore. A healthy web
container alone does not validate provider credentials or worker execution.
