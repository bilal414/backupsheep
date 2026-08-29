# Configuration reference

Configuration is resolved at boot. Stock Compose reads non-secret and optional
integration values from `.env`, then blanks known integration credential families and
restores only each role's exact family, while Django, per-lane database/broker/signing,
onboarding, database/files artifact keyrings, and optional managed-SSH-key values come from separate
read-only files under `.secrets`. Prefer the exact-ref installer; for a reviewed manual
pause follow the [installer-staged Compose setup](guides/installation.md#manual-docker-compose-installation).

**How keys are read.** `.env_sample` also supplies the non-secret defaults when a reviewed
process manager injects environment variables without mounting a `.env` file. A real
`.env` and then process environment override those defaults. File-backed values then
override the allowlisted direct secrets. For a stock manual install, keep
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
| `BACKUPSHEEP_DATABASE_IDENTITY_GENERATION` | Compose | `3` | Installer-owned identity/ACL/RLS witness; pending values block every long-lived lane. |
| `DB_BOOTSTRAP_USER` | Compose | `backupsheep_bootstrap` | Bundled-cluster bootstrap superuser used only by PostgreSQL, `db-provision` and `db-seal`. |
| `DB_MIGRATOR_USER` | Compose | `backupsheep_migrator` | Non-superuser database/schema owner used by `migrate`. |
| `DB_APP_USER`, `DB_PREFLIGHT_USER`, `DB_BEAT_USER` | Compose | `backupsheep_<lane>` | Independently authenticated web, gate and scheduler identities. |
| `DB_CLOUD_USER`, `DB_DATABASE_USER`, `DB_FILES_USER`, `DB_STORAGE_USER`, `DB_LOGS_USER` | Compose | `backupsheep_<lane>` | Independently authenticated worker identities with explicit table/column/RLS policy. |
| `DB_USER` | ✅ | `backupsheep_app` | Compatibility alias for non-Compose deployments; stock Compose pins each service user. |
| `DB_PASSWORD` | non-stock only | blank in stock `.env` | Direct password for non-Compose deployments. |
| `DB_PASSWORD_FILE` | Compose | `/run/secrets/db_<lane>_password` | Each long-lived service mounts exactly one lane password; bootstrap/migrator enter only their reviewed one-shots. |
| `DB_HOST` | ✅ | `db` | Host — the Compose service name. |
| `DB_PORT` | ✅ | `5432` | Port. |
| `DATABASE_URL` | optional | unset | Managed PostgreSQL URL. When set, it overrides the five discrete `DB_*` connection values. |
| `DB_SSLMODE` | optional | unset | PostgreSQL TLS mode; external production databases require `verify-full`. |
| `DB_SSLROOTCERT` | optional | unset | CA bundle path required for an external production database. |

Production allows plaintext PostgreSQL only through a Unix socket, loopback, or the exact
stock `db` Compose service. Any other hostname or address (including RFC1918/private
networks) must use `verify-full` and a CA bundle so the server identity is authenticated.

The database/files identities cannot SELECT any `core_storage*` configuration table
and cannot mutate backup-to-destination through rows. Local source work pauses until
the storage lane validates the frozen destination request and commits a non-secret
authorization witness; missing validation fails closed and is recovered by periodic
durable sweeps.

## Task queue (Celery / RabbitMQ)

BackupSheep supports RabbitMQ only. Use either a complete AMQP URL or reviewed connection
fragments. When `RABBITMQ_HOST` is set, the fragment variables take precedence and
BackupSheep URL-encodes the username, password, and virtual host before constructing the
AMQP URL. `CLOUDAMQP_URL` remains a generic managed-RabbitMQ compatibility input and takes
precedence over the Compose default URL when no fragments are present.

| Variable | Required | Default | Purpose |
|----------|:--------:|---------|---------|
| `CELERY_BROKER_URL` | optional | blank | Full managed/external RabbitMQ AMQP URL (`amqp://` or `amqps://`). |
| `CLOUDAMQP_URL` | optional | unset | Compatibility input for a managed RabbitMQ AMQP URL. |
| `RABBITMQ_HOST` | Compose | `rabbitmq` | RabbitMQ hostname for fragment-based configuration. |
| `RABBITMQ_PORT` | optional | `5672` | RabbitMQ AMQP port for fragment-based configuration. |
| `RABBITMQ_SCHEME` | optional | `amqp` | Use `amqps` for any broker outside the stock Compose/loopback boundary. |
| `RABBITMQ_USER` | Compose | `backupsheep_app` | Compatibility/app identity; stock Compose pins a different user for preflight, Beat and every worker lane. |
| `RABBITMQ_PASSWORD` | non-stock only | blank in stock `.env` | Direct broker password for non-Compose deployments. |
| `RABBITMQ_PASSWORD_FILE` | Compose | `/run/secrets/rabbitmq_<lane>_password` | File-backed lane password; `install.sh` generates distinct host files and each service receives only its own. |
| `BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION` | Compose | `2` | Installer-owned per-lane broker identity/ACL witness. |
| `BACKUPSHEEP_CELERY_SECURITY_GENERATION` | Compose | `3` | Installer-owned signed-task protocol/replay witness. |
| `BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION` | Compose | positive integer | Active per-publisher signing-key registry generation. |
| `RABBITMQ_VHOST` | Compose | `backupsheep` | Dedicated RabbitMQ virtual host. |
| `RABBITMQ_CA_CERT` | optional | system roots | Private CA bundle for `amqps`; hostname verification is always enabled. |
| `LOG_RETENTION_DAYS` | optional | `30` | Days to keep run logs in the files/database/storage private work volumes and activity rows in PostgreSQL. Lane tasks prune files at 03:00, database at 03:05 and storage at 03:10; `delete_old_db_logs` prunes `CoreLog` rows at 03:30. |
| `S3_DOWNLOAD_URL_EXPIRES` | optional | `300` | Compatibility-only provider-signed URL lifetime for explicitly enabled non-enterprise legacy artifacts; values above `3600` are rejected. It does not enable stock BSE1 direct download. |
| `ALLOW_INSECURE_FTP` | optional | `false` | Compatibility escape hatch for plaintext FTP. Keep disabled; prefer SFTP or certificate-verified FTPS because FTP exposes credentials and backup data in transit. |
| `SSH_KNOWN_HOSTS_PATH` | compatibility only | `_storage/ssh_known_hosts` outside stock Compose | Separately reviewed non-stock file setting. Stock Compose uses account-scoped PostgreSQL approvals/audit and transient exact per-operation private-runtime trust files instead. |
| `SSH_MANAGED_DATABASE_PUBLIC_KEY` | optional | blank | Public half of the database-worker Ed25519 identity; must match its lane secret and differ from the files identity. |
| `SSH_MANAGED_FILES_PUBLIC_KEY` | optional | blank | Public half of the files-worker Ed25519 identity; must match its lane secret and differ from the database identity. |
| `SSH_MANAGED_PRIVATE_KEY_PATH` / `SSH_MANAGED_PUBLIC_KEY` | legacy | blank | Shared-identity compatibility settings; both must remain blank in stock Compose. |

Production allows plaintext AMQP only on loopback or the exact stock `rabbitmq` Compose
service. External and multi-host brokers must use `amqps`; certificate validation and
hostname matching are mandatory. System trust roots are used unless a private CA is set.

## Artifact encryption and local-file keys

Stock production requires BSE1 chunked AES-256-GCM-SIV envelopes, enterprise mode, the
`local-file` provider, and legacy restore disabled. The installer atomically generates
independent database/files 256-bit keyrings under `.secrets`; Compose grants each only to
its matching source worker. Storage receives ciphertext and no root key.

When `DJANGO_SERVER=prod`, omitting `BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE` defaults to
`bse1`; a direct deployment does not silently write plaintext. `legacy-only` remains an
explicit non-enterprise upgrade compatibility setting and must never be treated as a
hardened production default.

Back up both keyrings with the PostgreSQL recovery set. Reruns preserve their exact bytes,
and a missing keyring in an existing installation fails closed rather than generating a
replacement. Enterprise mode rejects the environment-backed local-development provider.
See [Private staging and ciphertext handoff](security/staging-isolation.md) for rotation,
legacy-key retention, loss consequences, and non-Docker operation.

## Container egress

Each Internet-capable role has a no-secret namespace guard. Stock `deny` mode admits only
the exact internal database and broker peers and blocks every outward destination.
`allowlist` mode adds only that role's reviewed exact IPv4 `CIDR:port` or IPv6
`[CIDR]:port` TCP tuples and exact names. `public` is an explicit compatibility risk
opt-in that permits ordinary public destinations while denying special/private,
discovered-gateway and well-known NAT64 ranges by default. Its exact tuples are explicit
special-range exceptions intended only for narrow reviewed private targets. Fixed
`never` destinations and discovered gateways remain blocked; the fixed set includes both
well-known NAT64 prefixes and no tuple can override them. A tuple can override only the
ordinary private/reserved set. The guard handles
PostgreSQL/RabbitMQ separately as exact directly connected interface/address/TCP-port
tuples on distinct bridges and blocks them when peer resolution is incomplete. Operations
that need the Internet deliberately fail until the operator configures the smallest
practical role allowlist.

In `allowlist` mode, the matching `BACKUPSHEEP_<ROLE>_EGRESS_ALLOW_DNS_NAMES` must list
every exact required name and CNAME target; the complete policy, including non-literal
DB/broker names, is capped at 66 unique names. A loopback-only zero-capability UID-`10021`
parser validates hostile packets and sends only an immutable-name index plus A/AAAA
selector to the distinct zero-capability UID-`10022` forwarder. Only UID 10022 constructs
canonical queries and reaches Docker DNS. Direct external TCP/UDP 53 is blocked. `deny`
uses the same split only for exact internal peers, while `public` uses ordinary DNS and
requires an empty name list.

DNS and exact IP/port grants are independent. The allowlist is transport-level defense
in depth, not a resource-aware exfiltration boundary: a compromised role can still reach
another tenant or resource on the same IP and port. Enterprise operations require
dedicated/private endpoints or a controlled resource-aware proxy. Site-specific NAT64
prefixes remain a host/network responsibility and must be disabled or blocked and tested
separately.

Generation 2 is mandatory and retires non-empty address-only
`BACKUPSHEEP_<ROLE>_EGRESS_ALLOW_IPV4`/`ALLOW_IPV6` values. Existing stock installs must
review dependencies and authorize the safe reset once with `--migrate-egress-policy`;
all six roles become `deny` and all lists are cleared. Customized or mixed legacy policy
must be reviewed and manually reset first, and the migration flag is rejected once
generation 2 is active.

Stock Compose stores host-key approvals and their append-only audit in PostgreSQL, then
materializes the exact current approval only for the operation that needs it. Optional
`.secrets/ssh_managed_database_private_key` and
`.secrets/ssh_managed_files_private_key` Ed25519 sources are distinct and granted only to
their matching workers; the app receives neither. The entrypoint validates and copies its
lane key into private tmpfs as mode `0600`. Managed-key mode requires exactly one account;
multi-account installations use customer-supplied private keys. See the upgrade guide
before retiring legacy global trust or a shared identity.

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

The **Local Storage** provider keeps BSE1 ciphertext archives on this server (no external
bucket). It needs no destination credential, but source-lane artifact encryption still
uses its required local-file root-key ring. Only the storage worker may access the archive
root, and it receives no artifact keyring.

| Variable | Required | Default | Purpose |
|----------|:--------:|---------|---------|
| `BS_LOCAL_STORAGE_PATH` | optional | `/backups` | Root directory for Local Storage backups. Stock Compose mounts `backup_storage` read/write only in `worker-storage`; app/cloud/database/files/logs/Beat receive no `/backups` mount. |

To keep backups on a bigger disk or an NFS share, keep the stock in-container path and back
the `backup_storage` volume with a reviewed bind mount via `docker-compose.override.yml`:

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

Stock Compose grants deployment-wide integration credentials by role: web receives all
families for setup/OAuth callbacks; cloud only DigitalOcean/OVH; files only Basecamp;
storage only Dropbox/pCloud/Microsoft/Google; logs only
Postmark/Mailgun/SES/Slack/Telegram; database, Beat and one-shot roles receive none. The
entrypoint rejects misplaced values even if a stale `.env` contains them. `SENTRY_DSN`
remains shared because every Django/Celery process initializes the scrubbed Sentry client
and the DSN grants event ingestion, not provider-account authorization.

## Self-hosted server public IPs (optional)

The *Self-hosted* backup-server location auto-detects this server's public IPv4/IPv6
(shown in the connection-setup **Backup Server** dropdown for firewall allow-listing).
`PUBLIC_IPV4_LOOKUP_URL` and `PUBLIC_IPV6_LOOKUP_URL` override the lookup services
(defaults: `https://api.ipify.org` / `https://api6.ipify.org`); any service that returns
a bare IP address as the response body works.
