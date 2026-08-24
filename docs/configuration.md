# Configuration reference

Configuration is resolved at boot. Stock Compose supplies non-secret and optional
integration values from `.env`, while the Django, database, broker, onboarding and
optional managed-SSH-key values come from separate read-only files under `.secrets`. Copy
`.env_sample` to `.env`, retain its keys, and follow the
[manual Compose secret setup](guides/installation.md#manual-docker-compose-installation).

**How keys are read.** `.env_sample` also supplies the non-secret defaults when a platform
injects environment variables without mounting a `.env` file (such as Render or Railway).
A real `.env` and then process environment override those defaults. File-backed values
then override the four allowlisted direct secrets. For a stock manual install, keep
`DJANGO_SECRET_KEY`, `DB_PASSWORD`, `RABBITMQ_PASSWORD` and
`ONBOARDING_INSTALL_TOKEN` blank in `.env`; Compose sets fixed `/run/secrets/...` pointers
and grants each role only the files it needs.

> Booleans (`DJANGO_DEBUG`, `DJANGO_HTTPS`) are parsed leniently: `true/1/yes/on` ⇒ on,
> anything else ⇒ off.

## Core / Django

| Variable | Required | Default | Purpose |
|----------|:--------:|---------|---------|
| `DJANGO_SECRET_KEY` | non-stock only | blank in stock `.env` | Direct cryptographic key for non-Compose deployments; stock Compose uses `.secrets/django_secret_key`, which must remain stable. |
| `DJANGO_SECRET_KEY_FILE` | Compose | `/run/secrets/django_secret_key` | Fixed absolute file pointer injected by stock Compose; do not repoint it through `.env`. |
| `ONBOARDING_INSTALL_TOKEN_SECRET_FILE` | app only | `/run/secrets/onboarding_token` | File-backed first-owner token granted only to the stock web service. |
| `DJANGO_DEBUG` | ✅ | `false` | Django debug mode. **Keep false in production** (debug leaks tracebacks/settings on errors). |
| `DJANGO_ALLOWED_HOSTS` | ✅ | `localhost,127.0.0.1` | Allowed Host header(s). Use your real hostname in production; comma-separated list supported. |
| `DJANGO_HTTPS` | optional | `false` | Set `true` when served over TLS to enable Secure cookies, HSTS, and HTTP→HTTPS redirect. See [deployment](deployment.md). |
| `DJANGO_SERVER` | ✅ | `prod` | Environment label, sent to Sentry as the environment tag. |
| `DJANGO_SETTINGS_MODULE` | ✅ | `backupsheep.settings` | Django settings module path. |
| `APP_NAME` | ✅ | `BackupSheep` | Display name (can also be set in the wizard). |
| `APP_DOMAIN` | ✅ | `localhost:8000` | Public host (`host[:port]`); used for `APP_URL` and CSRF trusted origins. |
| `APP_PROTOCOL` | ✅ | `http://` | URL scheme (`http://` or `https://`), combined with `APP_DOMAIN`. |
| `API_TOKEN_TTL_SECONDS` | optional | `2592000` | Lifetime of newly issued personal API tokens in seconds (30 days). Values above the 90-day maximum are rejected. |
| `SESSION_COOKIE_AGE` | optional | `43200` | Browser-session lifetime in seconds; 12 hours is the hard maximum. |
| `SESSION_EXPIRE_AT_BROWSER_CLOSE` | optional | `true` | Also discard the browser session cookie when the browser closes. |
| `AUTH_THROTTLE_TRUSTED_PROXY_ENABLED` | optional | `false` | Allow authentication throttles to use the dedicated proxy-overwritten client-IP header. |
| `AUTH_THROTTLE_TRUSTED_PROXY_NETWORKS` | required when enabled | empty | Exact comma-separated immediate proxy IPs/CIDRs as seen in `REMOTE_ADDR`. |
| `SENTRY_DSN` | optional | empty | Sentry DSN for scrubbed error/performance monitoring. Leave blank to disable. |
| `SENTRY_TRACES_SAMPLE_RATE` | optional | `0` | Transaction trace sampling rate from 0 to 1. Opt in only after a privacy/cost review. |
| `SENTRY_PROFILES_SAMPLE_RATE` | optional | `0` | Profile sampling rate from 0 to 1. Opt in only after a privacy/cost review. |
| `BACKUPSHEEP_SECRETS` | optional | unset | Advanced: if set, its JSON value is used as the entire config instead of `.env` (for secret-manager deployments). |

Authentication rate limits use the direct server peer by default. If a reverse proxy
causes every client to share that address, trusted-proxy mode is an explicit opt-in: the
listed network must identify the immediate proxy, and that proxy must **overwrite** (not
append) `X-BackupSheep-Client-IP` on every request. For Caddy's `reverse_proxy` handler:

```caddyfile
header_up X-BackupSheep-Client-IP {remote_host}
```

Never list public/client networks as trusted proxies. BackupSheep does not use
`X-Forwarded-For` for these buckets; disabled mode, an untrusted direct peer, or a
missing/malformed/multiple dedicated header safely falls back to `REMOTE_ADDR`.

## Database (PostgreSQL)

| Variable | Required | Compose value | Purpose |
|----------|:--------:|---------------|---------|
| `DB_NAME` | ✅ | `backupsheep` | Database name (the `db` service also reads it as `POSTGRES_DB`). |
| `DB_USER` | ✅ | `backupsheep` | Username (`POSTGRES_USER`). |
| `DB_PASSWORD` | non-stock only | blank in stock `.env` | Direct password for non-Compose deployments. |
| `DB_PASSWORD_FILE` | Compose | `/run/secrets/db_password` | File-backed password for application roles; PostgreSQL reads the same secret with `POSTGRES_PASSWORD_FILE`. |
| `DB_HOST` | ✅ | `db` | Host — the Compose service name. |
| `DB_PORT` | ✅ | `5432` | Port. |
| `DATABASE_URL` | optional | unset | Managed PostgreSQL URL. When set, it overrides the five discrete `DB_*` connection values. |
| `DB_SSLMODE` | optional | unset | PostgreSQL TLS mode; external production databases require `verify-full`. |
| `DB_SSLROOTCERT` | optional | unset | CA bundle path required for an external production database. |

Production allows plaintext PostgreSQL only through a Unix socket, loopback, or the exact
stock `db` Compose service. Any other hostname or address (including RFC1918/private
networks) must use `verify-full` and a CA bundle so the server identity is authenticated.

## Task queue (Celery / RabbitMQ)

BackupSheep supports RabbitMQ only. Use either a complete AMQP URL or the connection
fragments supplied by hosted-platform templates. When `RABBITMQ_HOST` is set, the fragment
variables take precedence and BackupSheep URL-encodes the username, password, and virtual
host before constructing the AMQP URL. The Heroku template's RabbitMQ-specific CloudAMQP
plan supplies `CLOUDAMQP_URL`; it takes precedence over the Compose default URL when no
fragments are present.

| Variable | Required | Default | Purpose |
|----------|:--------:|---------|---------|
| `CELERY_BROKER_URL` | optional | blank | Full managed/external RabbitMQ AMQP URL (`amqp://` or `amqps://`). |
| `CLOUDAMQP_URL` | optional | unset | RabbitMQ AMQP URL injected by the Heroku CloudAMQP add-on. |
| `RABBITMQ_HOST` | Compose | `rabbitmq` | RabbitMQ hostname for fragment-based configuration. |
| `RABBITMQ_PORT` | optional | `5672` | RabbitMQ AMQP port for fragment-based configuration. |
| `RABBITMQ_SCHEME` | optional | `amqp` | Use `amqps` for any broker outside the stock Compose/loopback boundary. |
| `RABBITMQ_USER` | Compose | `backupsheep` | Dedicated RabbitMQ user. |
| `RABBITMQ_PASSWORD` | non-stock only | blank in stock `.env` | Direct broker password for non-Compose deployments. |
| `RABBITMQ_PASSWORD_FILE` | Compose | `/run/secrets/rabbitmq_password` | File-backed dedicated broker password; `install.sh` generates its host file. |
| `RABBITMQ_VHOST` | Compose | `backupsheep` | Dedicated RabbitMQ virtual host. |
| `RABBITMQ_CA_CERT` | optional | system roots | Private CA bundle for `amqps`; hostname verification is always enabled. |
| `LOG_RETENTION_DAYS` | optional | `30` | Days to keep backup run logs on local disk *and* activity-log entries in the database before `delete_old_logs` (03:00) / `delete_old_db_logs` (03:30) prune them. |
| `S3_DOWNLOAD_URL_EXPIRES` | optional | `300` | Seconds before a provider-signed backup URL expires; values above `3600` are rejected. |
| `WORDPRESS_PRIVATE_TARGET_CIDRS` | optional | blank | Exact comma-separated RFC1918/ULA CIDRs allowed for HTTPS WordPress origins. Blank rejects all private targets; loopback, link-local, reserved and metadata addresses are always rejected. |
| `ALLOW_INSECURE_FTP` | optional | `false` | Compatibility escape hatch for plaintext FTP. Keep disabled; prefer SFTP or certificate-verified FTPS because FTP exposes credentials and backup data in transit. |
| `SSH_KNOWN_HOSTS_PATH` | optional | `_storage/ssh_known_hosts` outside stock Compose | Reviewed OpenSSH `known_hosts` file used for SSH/SFTP sources. Stock Compose fixes it at `/var/lib/backupsheep/ssh-trust/known_hosts` on the dedicated trust volume. |
| `SSH_MANAGED_PRIVATE_KEY_PATH` | optional | blank outside stock Compose | Managed private-key runtime path. Stock Compose/entrypoint owns this setting and exports `/run/backupsheep/ssh/managed_private_key` only after staging a valid non-empty source. |

Production allows plaintext AMQP only on loopback or the exact stock `rabbitmq` Compose
service. External and multi-host brokers must use `amqps`; certificate validation and
hostname matching are mandatory. System trust roots are used unless a private CA is set.

WordPress integration keys and optional HTTP Basic credentials are sent only over
certificate-verified HTTPS. BackupSheep resolves each target once, rejects the entire DNS
answer if any address violates the target policy, and connects to one approved IP while
retaining TLS SNI and hostname verification. Private WordPress sites require an explicit
`WORDPRESS_PRIVATE_TARGET_CIDRS` entry; do not use a broader network than the site needs.
This application revision requires a BackupSheep WordPress plugin release that reads the
integration key from `X-BackupSheep-Key`; the legacy query-only v1.8 plugin fails closed
and must be upgraded before rolling this application change out to WordPress users.
Pinned WordPress traffic also ignores ambient HTTP(S) proxy variables because a proxy
would replace the verified connection peer.

In stock Compose, `.secrets/ssh_managed_private_key` is a mode-`0444` source mounted only
in app/database/files. Leave it empty to disable the managed identity. On startup, a
non-empty source must be a regular, NUL-free file no larger than 64 KiB and an unencrypted
key accepted by `ssh-keygen`; the entrypoint copies it into the role's private tmpfs at
`/run/backupsheep/ssh/managed_private_key`, mode `0600`. Do not point SSH directly at the
mode-`0444` `/run/secrets/ssh_managed_private_key` source. See the upgrade guide before
moving trust/key material out of legacy `_storage`.

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
| `BS_LOCAL_STORAGE_PATH` | optional | `/backups` | Root directory for 'Local Storage' backups. Stock Compose mounts `backup_storage` read/write only in `worker-storage`, read-only in app/cloud/database/files, and not at all in logs/Beat. |

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
