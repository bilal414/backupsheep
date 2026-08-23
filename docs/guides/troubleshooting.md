# Troubleshooting

Start with evidence and preserve durable rows. Retrying a provider mutation manually or
deleting an in-progress record can defeat BackupSheep's reconciliation and duplicate
guards.

## First response

```bash
cd /opt/backupsheep
git rev-parse HEAD
git status --short --branch
docker compose config --quiet
docker compose ps --all
docker compose logs --tail=200 migrate app
curl -fsS http://127.0.0.1:8000/healthz/
docker compose exec -T db pg_isready -U backupsheep -d backupsheep
docker compose exec -T rabbitmq rabbitmq-diagnostics -q ping
docker compose exec -T worker-cloud celery -A backupsheep inspect ping
```

For a backup or restore, also capture its safe correlation ID, status, phase, retry time,
provider status and reconciliation state from the console/API.

## Installation and startup

### Production refuses the sample Django key

With `DJANGO_SERVER=prod`, the app refuses `DJANGO_SECRET_KEY=change-this-key`. Generate a
long random value, store it in `.env`, keep the file mode restrictive and recreate the
services. Keep the value stable after first use.

### PostgreSQL does not start or authentication fails

For the bundled stack, confirm `DB_HOST=db`, `DB_PORT=5432`, and non-empty matching
`DB_NAME`, `DB_USER`, `DB_PASSWORD` values. PostgreSQL initializes its role/password only
when the volume is first created; changing `.env` later does not alter the existing role.

Do not delete `pgdata` to solve a credential mismatch. Restore the old setting, change the
role password through an authenticated PostgreSQL session, or recover the database into a
new verified instance.

### `migrate` exits non-zero

```bash
docker compose logs --tail=300 migrate db
```

Fix database connectivity, permissions, disk or migration errors, then run `docker compose
up --detach` again. Application services wait for a successful migration. Do not fake the
migration state or start the web image independently against an unverified schema.

### The UI has no styles

The app entrypoint runs `collectstatic`, and WhiteNoise serves the result. Rebuild the
current image and inspect app startup:

```bash
docker compose build app
docker compose up --detach app
docker compose logs --tail=200 app
```

Confirm the browser is not caching a failed asset response and that the reverse proxy
forwards `/static/` to the app.

## HTTP, login and onboarding

### `DisallowedHost`

Add the exact request hostname to comma-separated `DJANGO_ALLOWED_HOSTS`. Do not include a
scheme or path and do not use `*` in production. Ensure the reverse proxy preserves the
real `Host` header.

### HTTPS redirect loop or login cookie failure

`DJANGO_HTTPS=true` requires real TLS at the proxy and
`X-Forwarded-Proto: https`. Verify `APP_PROTOCOL=https://`, the public `APP_DOMAIN`, proxy
header and public URL. Disable HTTPS mode only while deliberately serving a private plain
HTTP environment.

### CSRF failure in the console/API

Browser-session API requests require Django's CSRF token. Confirm the public origin matches
`APP_PROTOCOL + APP_DOMAIN`, cookies are accepted, the frontend sends `X-CSRFToken`, and a
proxy is not stripping headers. External token-authenticated clients should send
`Authorization: Token <token>` and do not use the browser session cookie.

### Install token is rejected or missing

If `ONBOARDING_INSTALL_TOKEN` is blank, request `/onboarding/` once, then read:

```bash
docker compose exec app cat /code/_storage/install_token
```

The web app must have a writable shared `/code/_storage`. If a user already exists, the
first-owner step is intentionally locked; use login/password recovery instead.

### Console owner cannot use `/django-admin/`

The BackupSheep owner is not a Django superuser. Create a separate superuser only when
needed:

```bash
docker compose run --rm app python manage.py createsuperuser
```

### Password email does not arrive

Send an email test from settings and inspect `worker-logs`. If no transactional provider
is configured, reset from the host:

```bash
docker compose run --rm app python manage.py changepassword user@example.com
```

## RabbitMQ and workers

### Workers report connection refused

Inside Compose, RabbitMQ is `rabbitmq`, not `localhost`. Keep `RABBITMQ_HOST=rabbitmq`, use
the dedicated `backupsheep` user/vhost, and confirm `RABBITMQ_PASSWORD` is the same value
used when the persistent broker volume was initialized. For an external broker, verify the
`amqp`/`amqps` URL, credentials, vhost, TLS and firewall.

### One worker lane is missing

```bash
docker compose ps --all
docker compose logs --tail=200 worker-cloud worker-database worker-files worker-storage worker-logs
docker compose exec -T worker-cloud celery -A backupsheep inspect ping
```

Start the missing service. Do not reroute disk-touching tasks to a worker without the
shared `backup_workdir`/Local Storage mount.

### Uploads backlog

Check the `storage` queue, destination provider and work-volume capacity. If workers are
healthy and the destination is the bottleneck, scale the lane:

```bash
docker compose up --detach --scale worker-storage=4
```

Do not scale through provider rate limits without measuring errors/retry behavior.

### Scheduler or maintenance seems duplicated

Confirm only one `beat` container is active. Backup schedule occurrences have a
transactional claim, but multiple schedulers still duplicate ordinary maintenance
dispatch and add load.

## Backup and restore execution

### Job disappeared from Celery inspection

Celery inspection is transient. Find the durable request/backup/restore row in the API or
console. RabbitMQ redelivery and one-minute recovery sweeps can resume stale work. Use the
existing correlation ID rather than launching another job.

### Reconciliation says `manual_review`

BackupSheep stopped because it could not prove a unique owned provider outcome. Inspect the
exact provider operation/resource ID and ownership tags/markers read-only. Multiple, zero
or mismatched candidates must not be resolved by guessing. Preserve evidence and follow a
provider/version-specific repair procedure.

### Work disk is full

Stop new schedules, identify the exact filesystem and active owners, and preserve active
artifacts. Do not delete files under `_storage` merely because they are large. Increase
capacity or safely complete/cancel the owning operation, then let recovery proceed. Check
Local Storage separately; it may share the host disk but has different retention meaning.

### Archive validation or restore safety limit fails

The app enforces archive member count, total uncompressed bytes, compression ratio and free
disk reserve. Treat an unexpected expansion or path/manifest failure as a potentially unsafe
archive. Raise limits only after validating the archive, source, capacity and security
impact; never disable validation to force a restore.

### Cold S3 object cannot download

Glacier Flexible Retrieval/Deep Archive objects require provider restoration before
download. Wait for the thaw status instead of recreating the BackupSheep backup row.

### Object Lock prevents retention cleanup

This is expected while retention or a legal hold applies. BackupSheep keeps the catalog
record and retries protected deletes periodically. Verify the exact S3 version and
retention date; do not grant governance-bypass permission merely to make keep-last counts
match immediately.

## Source connections

### SSH/SFTP host-key error

Unknown or changed host keys are rejected. Verify the new fingerprint through an
independent channel, then update the reviewed file at `SSH_KNOWN_HOSTS_PATH`. Never accept a
changed key based only on the failing connection itself.

### Managed SSH key is not offered

Both `SSH_MANAGED_PUBLIC_KEY` and `SSH_MANAGED_PRIVATE_KEY_PATH` must be set, and the
private file must exist where `app`, `worker-files` and `worker-database` can read it. Use
mode `0600` and the shared work volume.

### FTPS certificate failure

Correct the hostname/certificate chain and keep TLS verification enabled. The connection
model has a per-connection verification switch for exceptional self-signed/mismatched
hosts; disabling it weakens server authentication and should be a documented, scoped risk
decision.

### PostgreSQL dump client mismatch

The image includes PostgreSQL clients 14–18 and selects a version-matched client when
available, falling back through installed newer clients. Confirm the source version
selected in the connection and inspect `worker-database` logs. Older catalog choices can
use a newer installed client, but the actual server/client compatibility remains a
PostgreSQL constraint.

### MySQL 8 authentication or dump flags fail

MySQL targets use the Oracle MySQL 8.4 client under `/opt/mysql/bin`; MariaDB targets use
MariaDB tools. Confirm the correct engine/version was selected. MySQL 8 credentials using
`caching_sha2_password` may require TLS; enable source SSL instead of weakening the source
authentication plugin.

## Storage destinations

### Object-storage validation fails

Confirm the bucket/container already exists where required, the endpoint and region match,
credentials have the minimum list/head/write/read/delete permissions needed by validation,
and the bucket name is DNS-safe. Many S3-compatible adapters perform a live
write/read/delete probe; use a dedicated prefix and inspect provider audit logs.

Vultr Object Storage does not create the bucket during validation. Supply a pre-created
lowercase DNS-safe bucket and the regional endpoint.

### OAuth connect tile does not work

Dropbox, Google Drive, OneDrive and pCloud require their application credentials in `.env`
before the UI can construct/exchange OAuth requests. Confirm the registered redirect URL
exactly matches the public `APP_URL` callback, then recreate the app containers after
editing `.env`.

### Local Storage file is missing

Confirm `BS_LOCAL_STORAGE_PATH`, the app/worker mounts and the destination's optional
subpath. Every relevant process must see the same archive. A container-local path will be
lost or appear empty after recreation.

### Transfer-log download says unavailable

The old per-backup transfer/directory-tree downloads depended on the former SaaS log
bucket and are not available in this self-hosted build. Use durable status, console
activity, container logs and the local work-volume logs.

## Provider-specific boundaries

- AWS S3 sources require versioning; restore requires an explicit existing versioned
  destination bucket. DynamoDB and RDS restore create new targets.
- Hetzner server snapshots cover the primary disk, not attached volumes or network
  dependencies. Back those up separately.
- Vultr managed-database restore creates a new fork; it does not overwrite the source.
- Amazon S3 Object Lock/lifecycle features are not a promise that every S3-compatible
  provider has equivalent semantics.

See the [provider matrix](../reference/provider-matrix.md) before diagnosing an unsupported
resource as a runtime fault.

## Preparing an issue

Include the exact Git revision, deployment type, relevant service names, safe correlation
ID/error code, redacted status payload, timestamps/timezone, reproduction steps and the
smallest relevant log window. Remove secrets, authorization headers, signed URLs, provider
response bodies, hostnames/resource names and customer data not needed to reproduce the
problem. Report security issues privately, not in a public issue.
