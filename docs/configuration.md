# Configuration reference

All configuration is read from environment variables at boot — in the Docker stack, from
the `.env` file (`env_file: .env`). Copy `.env_sample` to `.env` and edit it.

**How keys are read.** `.env_sample` also supplies the non-secret defaults when a platform
injects environment variables without mounting a `.env` file (such as Render or Railway).
A real `.env` and then process environment override those defaults. For a manual install,
the simplest rule remains: **copy `.env_sample` wholesale and don't delete lines**. Only
`DJANGO_SECRET_KEY` and the database connection values need real values to boot.

> Booleans (`DJANGO_DEBUG`, `DJANGO_HTTPS`) are parsed leniently: `true/1/yes/on` ⇒ on,
> anything else ⇒ off.

## Core / Django

| Variable | Required | Default | Purpose |
|----------|:--------:|---------|---------|
| `DJANGO_SECRET_KEY` | ✅ | `change-this-key` (placeholder — **must change**) | Cryptographic signing key; also derives the key that encrypts stored email credentials. Use a long random value and keep it **stable**. |
| `DJANGO_DEBUG` | ✅ | `false` | Django debug mode. **Keep false in production** (debug leaks tracebacks/settings on errors). |
| `DJANGO_ALLOWED_HOSTS` | ✅ | `localhost,127.0.0.1` | Allowed Host header(s). Use your real hostname in production; comma-separated list supported. |
| `DJANGO_HTTPS` | optional | `false` | Set `true` when served over TLS to enable Secure cookies, HSTS, and HTTP→HTTPS redirect. See [deployment](deployment.md). |
| `DJANGO_SERVER` | ✅ | `prod` | Environment label, sent to Sentry as the environment tag. |
| `DJANGO_SETTINGS_MODULE` | ✅ | `backupsheep.settings` | Django settings module path. |
| `APP_NAME` | ✅ | `BackupSheep` | Display name (can also be set in the wizard). |
| `APP_DOMAIN` | ✅ | `localhost:8000` | Public host (`host[:port]`); used for `APP_URL` and CSRF trusted origins. |
| `APP_PROTOCOL` | ✅ | `http://` | URL scheme (`http://` or `https://`), combined with `APP_DOMAIN`. |
| `SENTRY_DSN` | optional | empty | Sentry DSN for error/performance monitoring. Leave blank to disable. |
| `BACKUPSHEEP_SECRETS` | optional | unset | Advanced: if set, its JSON value is used as the entire config instead of `.env` (for secret-manager deployments). |

## Database (PostgreSQL)

| Variable | Required | Compose value | Purpose |
|----------|:--------:|---------------|---------|
| `DB_NAME` | ✅ | `backupsheep` | Database name (the `db` service also reads it as `POSTGRES_DB`). |
| `DB_USER` | ✅ | `backupsheep` | Username (`POSTGRES_USER`). |
| `DB_PASSWORD` | ✅ | *(you set it)* | Password (`POSTGRES_PASSWORD`). |
| `DB_HOST` | ✅ | `db` | Host — the Compose service name. |
| `DB_PORT` | ✅ | `5432` | Port. |
| `DATABASE_URL` | optional | unset | Managed PostgreSQL URL. When set, it overrides the five discrete `DB_*` connection values. |
| `DB_SSLMODE` | optional | unset | PostgreSQL `sslmode`, for example `require` for a managed database that requires TLS. |

## Task queue (Celery / RabbitMQ)

BackupSheep supports RabbitMQ only. Use either a complete AMQP URL or the connection
fragments supplied by hosted-platform templates. When `RABBITMQ_HOST` is set, the fragment
variables take precedence and BackupSheep URL-encodes the username, password, and virtual
host before constructing the AMQP URL. The Heroku template's RabbitMQ-specific CloudAMQP
plan supplies `CLOUDAMQP_URL`; it takes precedence over the Compose default URL when no
fragments are present.

| Variable | Required | Default | Purpose |
|----------|:--------:|---------|---------|
| `CELERY_BROKER_URL` | optional | `amqp://guest:guest@rabbitmq:5672//` | Full RabbitMQ AMQP URL (`amqp://` or `amqps://`). |
| `CLOUDAMQP_URL` | optional | unset | RabbitMQ AMQP URL injected by the Heroku CloudAMQP add-on. |
| `RABBITMQ_HOST` | optional | unset | RabbitMQ hostname for fragment-based configuration. |
| `RABBITMQ_PORT` | optional | `5672` | RabbitMQ AMQP port for fragment-based configuration. |
| `RABBITMQ_USER`, `RABBITMQ_PASSWORD` | optional | `guest` | RabbitMQ credentials for fragment-based configuration. |
| `RABBITMQ_VHOST` | optional | `/` | RabbitMQ virtual host for fragment-based configuration. |
| `LOG_RETENTION_DAYS` | optional | `30` | Days to keep backup run logs on local disk *and* activity-log entries in the database before `delete_old_logs` (03:00) / `delete_old_db_logs` (03:30) prune them. |

## Transactional email

Pick one provider (or none). The wizard can set this per-install; `.env` is the fallback.

| Variable | Purpose |
|----------|---------|
| `EMAIL_PROVIDER` | Default provider: `postmark`, `mailgun`, or `ses`. |
| `POSTMARK_API_KEY`, `POSTMARK_EMAIL`, `POSTMARK_DOMAIN`, `POSTMARK_API_URL` | Postmark settings (`API_URL` defaults to the public host). |
| `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, `MAILGUN_EMAIL`, `MAILGUN_API_URL` | Mailgun settings. |
| `SES_ACCESS_KEY_ID`, `SES_SECRET_ACCESS_KEY`, `SES_REGION_NAME`, `SES_REGION_ENDPOINT` | Amazon SES settings. |

> Without a configured provider, password-reset emails won't send — recover with
> `manage.py changepassword`. See [Troubleshooting](troubleshooting.md).

## Notification channels: Slack / Telegram (optional)

Email notifications work without these; they're only needed to connect the matching
channel under **Settings → Notifications**. Leave blank to keep the channel disabled.

| Variable | Purpose |
|----------|---------|
| `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET` | Slack app credentials — create an app at <https://api.slack.com/apps> with the `incoming-webhook` scope and redirect URL `<APP_URL>/api/v1/callback/slack/`. |
| `SLACK_TOKEN_URL` | Slack OAuth token endpoint used to exchange/refresh tokens (Slack's is `https://slack.com/api/oauth.v2.access`). |
| `TELEGRAM_BOT_KEY` | Telegram bot token from BotFather; chats are then added by chat ID in the console. |

## Application-log storage (optional)

An S3-compatible bucket BackupSheep can use for application logs etc. (tested with AWS S3
and Cloudflare R2). Optional; backup *run* logs are kept on local disk regardless.

`S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_STORAGE_BUCKET_NAME`, `S3_ENDPOINT_URL`,
`S3_SIGNATURE_VERSION` (`s3v4`).

## Local Storage backup destination (optional)

The **Local Storage** provider keeps backup zips as plain files on this server (no
external bucket). It needs no credentials — only the root directory the files live under.

| Variable | Required | Default | Purpose |
|----------|:--------:|---------|---------|
| `BS_LOCAL_STORAGE_PATH` | optional | `/backups` | Root directory for 'Local Storage' backups. In the Compose stack `/backups` is the `backup_storage` volume, mounted into `app` and the workers. |

To keep backups on a bigger disk or an NFS share, either point
`BS_LOCAL_STORAGE_PATH` at that mount, or bind-mount over `/backups` via
`docker-compose.override.yml`:

```yaml
volumes:
  backup_storage:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /mnt/storage/backupsheep
```

Each Local Storage destination can optionally scope itself to a subdirectory of this
root (the *Path* field in the UI).

## Storage-provider OAuth (only for the providers you use)

Object-storage providers (S3, B2, Wasabi, R2, Spaces, …) need **no** environment config —
you enter their keys in the UI. OAuth-based destinations need an app registered with the
provider and its credentials here:

| Provider | Variables |
|----------|-----------|
| Dropbox | `DROPBOX_APP_KEY`, `DROPBOX_APP_SECRET` |
| Google Drive | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` |
| OneDrive | `MS_CLIENT_ID`, `MS_CLIENT_SECRET_VALUE`, `MS_TENANT_ID`, `MS_OBJECT_ID`, `MS_APPLICATION_ID`, `MS_CLIENT_SECRET_ID` (+ the `MS_OAUTH_*`/`MS_SCOPE`/`MS_GRAPH_ENDPOINT` defaults) |
| pCloud | `PCLOUD_CLIENT_ID`, `PCLOUD_CLIENT_SECRET` (auth/token URLs default to pCloud's public hosts) |

## Backup-source provider endpoints & OAuth (optional)

Cloud-snapshot providers work out of the box with token/key credentials entered in the UI;
these env vars only override the public API hosts or enable OAuth-based connections:

- API host overrides: `DIGITALOCEAN_API`, `HETZNER_API`, `UPCLOUD_API`, `VULTR_API`,
  `GOOGLE_COMPUTE_API`, `GOOGLE_RESOURCE_API`.
- DigitalOcean OAuth (only for OAuth connections, not Personal Access Tokens):
  `DIGITALOCEAN_APP_CLIENT_ID`, `DIGITALOCEAN_APP_CLIENT_SECRET`, `DIGITALOCEAN_TOKEN_URL`.
- Google OAuth refresh: `GOOGLE_OAUTH_TOKEN_URL`.
- OVH Public Cloud (required to back up OVH instances/volumes), per region:
  `OVH_CA_APP_KEY`/`OVH_CA_APP_SECRET`, `OVH_EU_APP_KEY`/`OVH_EU_APP_SECRET`,
  `OVH_US_APP_KEY`/`OVH_US_APP_SECRET`.
- Basecamp source OAuth: `BASECAMP_CLIENT_ID`, `BASECAMP_CLIENT_SECRET` (endpoints default
  to Basecamp's public hosts).

See [Providers](providers.md) for which integrations need what.

## Self-hosted server public IPs (optional)

The *Self-hosted* backup-server location auto-detects this server's public IPv4/IPv6
(shown in the connection-setup **Backup Server** dropdown for firewall allow-listing).
`PUBLIC_IPV4_LOOKUP_URL` and `PUBLIC_IPV6_LOOKUP_URL` override the lookup services
(defaults: `https://api.ipify.org` / `https://api6.ipify.org`); any service that returns
a bare IP address as the response body works.
