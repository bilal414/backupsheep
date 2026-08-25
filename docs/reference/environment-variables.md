# Environment-variable reference

BackupSheep loads settings once, when each process starts. The effective precedence is:

1. values from `.env_sample`;
2. values from `.env`;
3. process environment variables;
4. allowlisted non-empty `*_FILE` values override their corresponding direct secrets.

If a non-Compose process environment contains a non-empty `BACKUPSHEEP_SECRETS`, its value
must be a JSON object and becomes the complete configuration instead. No sample, `.env`
or other process values are merged into that object. The stock installer and secure
Compose wrapper reject this alternate source and stock Compose pins it blank.

Compose supplies non-secret and optional integration values from `.env` to application
roles. Its six required installation secrets and optional managed SSH key are file-backed
under `.secrets`; see below. After
editing configuration, validate and recreate the core:

```bash
./backupsheep-compose config --quiet
./backupsheep-compose up --detach
```

Provider workers and Beat remain disabled unless the `operations` profile is explicitly
enabled. Recreate them only after reviewing durable queue and recovery state:

```bash
./backupsheep-compose --profile operations up --detach
```

Boolean values recognize `1`, `true`, `yes` or `on` (case-insensitive) as true; other
values are false. Defaults below are repository defaults for `develop`.

## Stock Docker and installer controls

These values control Compose/installer behavior rather than Django application features:

| Variable | Default | Meaning |
| --- | --- | --- |
| `BACKUPSHEEP_IMAGE` | `backupsheep:local` | Exact locally built application image tag; the verified installer requires `backupsheep:<full-commit>` and application roles use `pull_policy: never` |
| `BACKUPSHEEP_POSTGRES_IMAGE` | `backupsheep-postgres:local` | Exact locally built database image tag; the verified installer requires `backupsheep-postgres:<full-commit>` and the database role uses `pull_policy: never` |
| `BACKUPSHEEP_INSTALLATION_ID` | blank sample; installer generates it | Stable random 64-character lowercase hexadecimal ownership marker. Required by stock Compose; do not rotate or copy it between installations |
| `BACKUPSHEEP_DATABASE_IDENTITY_GENERATION` | blank sample; installer records `2` | Stock PostgreSQL identity-contract witness. Never set it manually on an existing installation to bypass provisioning |
| `BACKUPSHEEP_SECRETS_DIR` | `.secrets` | Host directory containing the stock Compose secret files; the verified installer accepts only this relative path |
| `BACKUPSHEEP_BIND_ADDRESS` | `127.0.0.1` | Host address that publishes the app; the verified installer accepts loopback only |
| `BACKUPSHEEP_BIND_PORT` | `8000` | Host loopback port published to container port 8000 |
| `BACKUPSHEEP_RABBITMQ_DATA_GENERATION` | blank sample; wrapper/installer records `4.3` | Broker data-format witness, not a version switch. Never set it by guess to bypass the legacy-volume migration gate |

The installation ID labels service containers and an empty `installation_identity`
sentinel volume. The installer combines that persistent witness with Compose project,
path, service/network/volume and configuration labels before mutating an existing
project. A fresh installation refuses any pre-existing resources under its requested
project name; an existing installation fails closed on missing, foreign, ambiguous or
unexpected ownership evidence.

Before any mutation, the installer also enumerates every exact Compose network and volume
name for the selected project. An exact-name object that lacks the expected Compose
project/logical-name labels is a collision, even if it is otherwise unused, and stops the
install. Delete, rename or deliberately migrate that foreign object; never relabel it to
bypass the ownership proof.

For the broker witness, the installer records `4.3` only for a fresh project with no
broker resources. Existing broker data delegates witness creation to the reviewed wrapper
after the explicit 4.3 hop, and only when
the post-transition container passes exact base-model, installation-ID, image-reference,
local image-ID, health, version and Khepri attestation.
The proof command runs inside the container as the named `rabbitmq` account using
`rabbitmq-diagnostics -q server_version`; it does not borrow root's cookie. A stopped broker,
orphan volume, duplicate resource, unknown generation, or 3.13/4.2 result requires the
documented operator-run migration. The installer never migrates broker data automatically.

Installer-managed `.env` files may not define `LD_AUDIT`, `LD_LIBRARY_PATH`,
`LD_PRELOAD` or `SSLKEYLOGFILE`. Stock Compose blanks those four values, and the image
entrypoint additionally clears shell/Python/loader startup hooks and establishes fixed
executable/import paths before it invokes the requested command.

## Django and application identity

| Variable | Default | Meaning |
| --- | --- | --- |
| `DJANGO_SERVER` | `prod` | Environment label, including the Sentry environment tag |
| `DJANGO_DEBUG` | `false` | Enables Django debug pages and browsable API; never enable publicly |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated request hosts, without schemes/paths |
| `DJANGO_SECRET_KEY` | unsafe placeholder outside stock Compose; blank in stock `.env` | Stable signing key and email-credential key material; stock Compose resolves `/run/secrets/django_secret_key` |
| `DJANGO_SECRET_KEY_FILE` | unset outside stock Compose | Absolute file-backed secret pointer; stock Compose sets `/run/secrets/django_secret_key` |
| `DJANGO_SETTINGS_MODULE` | `backupsheep.settings` | Django settings module |
| `DJANGO_HTTPS` | `false` | Secure cookies, HTTP redirect and one-year HSTS; requires a correct TLS proxy |
| `ONBOARDING_INSTALL_TOKEN` | blank | Fixed first-owner token for non-stock deployments; stock Compose deliberately leaves it blank |
| `ONBOARDING_INSTALL_TOKEN_SECRET_FILE` | unset outside stock Compose | Fixed first-owner token file; stock `app` alone receives `/run/secrets/onboarding_token` |
| `APP_DOMAIN` | `localhost:8000` | Public host and optional port, no scheme/path |
| `APP_PROTOCOL` | `http://` | Public scheme, including `://`; combines with `APP_DOMAIN` for CSRF/OAuth URLs |
| `APP_NAME` | `BackupSheep` | Display name |
| `BACKUPSHEEP_SECRETS` | unset | Complete JSON configuration replacement; see warning above |
| `SENTRY_DSN` | blank | Enables scrubbed Sentry error delivery when non-empty |
| `SENTRY_TRACES_SAMPLE_RATE` | `0` | Transaction trace sampling rate from 0 to 1; disabled unless explicitly opted in |
| `SENTRY_PROFILES_SAMPLE_RATE` | `0` | Profile sampling rate from 0 to 1; disabled unless explicitly opted in |
| `SESSION_COOKIE_AGE` | `43200` | Browser-session maximum in seconds; values above 12 hours are rejected |
| `SESSION_EXPIRE_AT_BROWSER_CLOSE` | `true` | Remove the browser's session cookie when the browser closes |
| `AUTH_THROTTLE_TRUSTED_PROXY_ENABLED` | `false` | Trust a dedicated, proxy-overwritten client-IP header for authentication rate-limit buckets |
| `AUTH_THROTTLE_TRUSTED_PROXY_NETWORKS` | blank | Exact comma-separated immediate proxy IPs/CIDRs; required when trusted-proxy mode is enabled |

`APP_PROTOCOL`, `APP_DOMAIN`, proxy forwarding and `DJANGO_HTTPS` must describe the same
public URL. Keep `DJANGO_SECRET_KEY` stable and backed up as a secret.
Session cookies are always HttpOnly and SameSite=Lax. They become Secure when
`DJANGO_HTTPS=true`; do not serve an authenticated production console over plain HTTP.
The Docker preflight's warning-level HTTPS deployment findings are expected only during
deliberate loopback HTTP access through an SSH tunnel. Public deployments must use a real
TLS proxy, the matching HTTPS tuple, and review/resolve every deployment warning.

Authentication throttles ignore `X-Forwarded-For` and use `REMOTE_ADDR` unless trusted-
proxy mode is explicitly enabled. In trusted-proxy mode, the direct peer must match
`AUTH_THROTTLE_TRUSTED_PROXY_NETWORKS` and the proxy must overwrite
`X-BackupSheep-Client-IP` with one client IP on every request. Do not append the header or
trust client/public networks. Missing, malformed, multiple, or untrusted-peer values fall
back to the direct peer. With Caddy, set this inside `reverse_proxy`:

```caddyfile
header_up X-BackupSheep-Client-IP {remote_host}
```

## API tokens

| Variable | Default | Meaning |
| --- | ---: | --- |
| `API_TOKEN_TTL_SECONDS` | `2592000` | Personal API token lifetime in seconds (30 days); values above the 90-day maximum are rejected |

Shorten this value for stricter environments. It controls the lifetime assigned when an
API token is issued.

## PostgreSQL

| Variable | Default | Meaning |
| --- | --- | --- |
| `DB_NAME` | `backupsheep` | Database name; also initializes bundled PostgreSQL |
| `DB_BOOTSTRAP_USER` | `backupsheep_bootstrap` | Bundled PostgreSQL bootstrap login. The official image initializes it as the cluster superuser; it is mounted/used only by PostgreSQL and `db-provision` |
| `DB_MIGRATOR_USER` | `backupsheep_migrator` | Non-superuser owner of the database/public schema used only by the one-shot migration service |
| `DB_USER` | `backupsheep_runtime` | Non-owner runtime login shared by long-lived application roles |
| `DB_PASSWORD` | unsafe placeholder outside stock Compose; blank in stock `.env` | Direct database password for non-stock deployments |
| `DB_PASSWORD_FILE` | unset outside stock Compose | Absolute file-backed database-password pointer; stock application roles use `/run/secrets/db_password` |
| `DB_HOST` | `db` | Database hostname in stock Compose |
| `DB_PORT` | `5432` | Database port |
| `DATABASE_URL` | blank | `postgres://` or `postgresql://` URL; overrides the five discrete Django values |
| `DB_SSLMODE` | blank | libpq `sslmode`; external production databases require `verify-full` |
| `DB_SSLROOTCERT` | blank | CA/root-certificate bundle for external PostgreSQL hostname verification |

The bundled `db` service consumes `DB_NAME`/`DB_BOOTSTRAP_USER` and
`db_bootstrap_password` as `POSTGRES_PASSWORD_FILE`. `db-provision` rotates the two
marked application-role passwords transactionally before every migration; the migration
service receives only `db_migrator_password`, and long-lived roles receive only
`db_password`. In
production, plaintext PostgreSQL is allowed only for an exact
stock `db` service name, loopback address, or Unix socket. Every other hostname or IP,
including RFC1918 addresses, requires `sslmode=verify-full` plus `sslrootcert`; the two
options may instead be supplied in the `DATABASE_URL` query string.

## RabbitMQ

| Variable | Default | Meaning |
| --- | --- | --- |
| `CELERY_BROKER_URL` | blank | Complete managed/external RabbitMQ URL |
| `CLOUDAMQP_URL` | unset | Managed RabbitMQ URL used ahead of `CELERY_BROKER_URL` |
| `RABBITMQ_HOST` | `rabbitmq` | When non-empty, fragment mode takes highest precedence |
| `RABBITMQ_PORT` | `5672` | Fragment-mode port |
| `RABBITMQ_SCHEME` | `amqp` | Fragment-mode scheme; use `amqps` for every external broker |
| `RABBITMQ_USER` | `backupsheep` | Dedicated bundled-broker username |
| `RABBITMQ_PASSWORD` | blank | Direct broker password for non-stock deployments; must remain blank in stock `.env` |
| `RABBITMQ_PASSWORD_FILE` | unset outside stock Compose | Absolute file-backed broker-password pointer; stock application roles use `/run/secrets/rabbitmq_password` |
| `RABBITMQ_VHOST` | `backupsheep` | Dedicated virtual host; components are URL encoded |
| `RABBITMQ_CA_CERT` | blank | Optional private CA bundle for `amqps`; system roots are used when blank |

Only `amqp://` and `amqps://` broker URLs are accepted. The stock Compose deployment does
not use RabbitMQ's well-known `guest` account. Production permits plaintext AMQP only on
loopback or the exact stock `rabbitmq` Compose service. Every external/internal-network
hostname or non-loopback IP must use `amqps`; BackupSheep requires the peer certificate
and verifies it against the broker hostname using system roots or `RABBITMQ_CA_CERT`.
TLS query-string overrides are rejected. Production accepts one broker URL; put broker
high availability behind one certificate-valid load-balancer/DNS endpoint instead of a
semicolon failover list whose members could cross transport trust boundaries.

## Stock Compose secret files

The verified installer creates `.secrets` as an owner-only mode-`0700` directory and
stores `django_secret_key`, `db_bootstrap_password`, `db_migrator_password`,
`db_password`, `rabbitmq_password` and `onboarding_token` as separate owner-owned,
non-linked, mode-`0444` files. It also creates an empty optional
`ssh_managed_private_key` file with the same ownership/link/mode rules. The private parent
prevents host directory traversal while Docker bind-mounts each granted file read-only for
the non-root application UID. Direct copies of required values and any legacy
managed-key path remain blank in `.env`, Compose expansion and container inspection. Do
not change the modes independently or add arbitrary entries to the installer-managed
directory.

Only `app`, `worker-database` and `worker-files` receive the managed-key source at
`/run/secrets/ssh_managed_private_key`, mode `0444`. Empty means disabled. On each start,
the entrypoint rejects a non-regular, NUL-containing, larger-than-64-KiB, encrypted or
invalid non-empty key; otherwise it copies the key to private tmpfs at
`/run/backupsheep/ssh/managed_private_key`, sets mode `0600`, and exports that runtime path
as `SSH_MANAGED_PRIVATE_KEY_PATH`. Do not configure SSH to read the mode-`0444` source
directly. See the upgrade guide before moving a key from legacy `_storage`.

`BACKUPSHEEP_SECRETS_DIR` selects that host directory for Compose and defaults to
`.secrets`; installer-managed installations require exactly that relative value. The
runtime `*_FILE` paths above are separately fixed to `/run/secrets/...` by Compose and must
not be repointed through `.env`.

## Paths, logs and downloads

| Variable | Default | Unit / meaning |
| --- | --- | --- |
| `BACKUPSHEEP_PIDS_LIMIT` | `512` | Maximum processes per app/migrate/preflight/worker/Beat container in stock non-Swarm Compose |
| `BS_LOCAL_STORAGE_PATH` | `/backups` | Root used by the Local Storage destination; mount identically in relevant roles |
| `LOG_RETENTION_DAYS` | `30` | Days before local run logs and database activity are pruned |
| `S3_DOWNLOAD_URL_EXPIRES` | `300` | Provider-signed archive URL seconds; hard maximum `3600` |
| `WORDPRESS_PRIVATE_TARGET_CIDRS` | blank | Exact RFC1918/ULA CIDRs permitted for DNS-pinned, certificate-verified HTTPS WordPress targets; special/metadata ranges remain denied |
| `ALLOW_INSECURE_FTP` | `false` | Explicit legacy compatibility opt-in for plaintext FTP; prefer SFTP or certificate-verified FTPS |
| `SSH_KNOWN_HOSTS_PATH` | `_storage/ssh_known_hosts` outside stock Compose | Reviewed OpenSSH known-hosts file; stock Compose overrides it to `/var/lib/backupsheep/ssh-trust/known_hosts` on the dedicated `ssh_trust` volume |
| `SSH_MANAGED_PRIVATE_KEY_PATH` | blank outside stock Compose | Optional managed private key; stock entrypoint exports `/run/backupsheep/ssh/managed_private_key` only after validating/copying the file-backed source into private tmpfs |
| `SSH_MANAGED_PUBLIC_KEY` | blank | Matching public key advertised by the console only when private key exists |

`S3_DOWNLOAD_URL_EXPIRES` applies to the S3-compatible, Google Cloud, Azure, Alibaba and
Tencent signatures that BackupSheep creates. Dropbox, OneDrive and similar APIs may issue
their own temporary links without accepting a caller-selected lifetime; those remain
bounded by the provider rather than this setting.

WordPress credentials never use plaintext HTTP. Public HTTPS targets work by default.
Private targets require the smallest practical comma-separated CIDR allowlist in
`WORDPRESS_PRIVATE_TARGET_CIDRS`; DNS failures and mixed public/private answers fail closed.

## Durable execution and recovery

These values coordinate database claims, renewable leases, heartbeats and one-minute
recovery sweeps. Change them as a set after load testing; a heartbeat must remain well
below its corresponding lease.

| Variable | Default | Unit / purpose |
| --- | ---: | --- |
| `BACKUP_RECOVERY_STALE_SECONDS` | `900` | Seconds before generic active backup state is considered stale |
| `BACKUP_RECOVERY_BATCH_SIZE` | `100` | Backup rows examined per recovery pass |
| `BACKUP_REQUEST_RETRY_SECONDS` | `60` | Initial durable request retry delay |
| `BACKUP_REQUEST_RETRY_MAX_SECONDS` | `900` | Maximum durable request retry delay |
| `BACKUP_REQUEST_CLAIM_TIMEOUT_SECONDS` | `300` | Initial request claim timeout |
| `BACKUP_REQUEST_CLAIM_TIMEOUT_MAX_SECONDS` | `3600` | Maximum request claim timeout |
| `BACKUP_REQUEST_DISPATCH_LEASE_SECONDS` | `60` | Outbox/dispatch lease |
| `BACKUP_REQUEST_RECOVERY_BATCH_SIZE` | `100` | Request rows reclaimed per pass |
| `BACKUP_POLL_INTERVAL` | `120` | Provider poll delay in seconds |
| `BACKUP_WORKER_LEASE_SECONDS` | `180` | Renewable source-worker lease |
| `BACKUP_WORKER_HEARTBEAT_SECONDS` | `30` | Source-worker heartbeat interval |
| `BACKUP_CREATE_LEASE_SECONDS` | `3600` | Provider create-phase lease |
| `BACKUP_DELETE_LEASE_SECONDS` | `300` | Provider delete-phase lease |
| `STORAGE_POINT_DELETE_LEASE_SECONDS` | `3600` | Fenced storage-point delete lease; coordinator recovery remains five minutes |
| `BACKUP_STORAGE_LEASE_SECONDS` | `180` | Renewable destination-copy lease |
| `BACKUP_STORAGE_HEARTBEAT_SECONDS` | `30` | Destination-copy heartbeat interval |
| `BACKUP_STORAGE_STALE_SECONDS` | `21600` | Seconds before a storage upload claimant is stale |
| `RESTORE_WORKER_LEASE_SECONDS` | `180` | Renewable restore-worker lease |
| `RESTORE_WORKER_HEARTBEAT_SECONDS` | `30` | Restore-worker heartbeat interval |
| `RESTORE_RECOVERY_STALE_SECONDS` | `300` | Seconds before restore execution is stale |
| `RESTORE_RECOVERY_DISPATCH_LEASE_SECONDS` | `120` | Restore recovery-dispatch lease |
| `RESTORE_RECOVERY_BATCH_SIZE` | `100` | Restore rows reclaimed per pass |

## Network and command limits

| Variable | Default | Unit / purpose |
| --- | ---: | --- |
| `SSH_CONNECT_TIMEOUT` | `15` | SSH connect seconds |
| `SSH_BANNER_TIMEOUT` | `15` | SSH banner seconds |
| `SSH_AUTH_TIMEOUT` | `15` | SSH authentication seconds |
| `SSH_KEEPALIVE_SECONDS` | `30` | SSH keepalive interval |
| `DATABASE_CONNECT_TIMEOUT` | `15` | Source-database connect seconds |
| `DATABASE_STATEMENT_TIMEOUT_MS` | `15000` | Validation statement milliseconds |
| `DATABASE_LOCK_TIMEOUT_MS` | `5000` | PostgreSQL validation lock milliseconds |
| `DATABASE_COMMAND_TIMEOUT` | `82800` | Dump/restore command seconds (23 hours) |
| `DATABASE_VALIDATION_COMMAND_TIMEOUT` | `30` | Client binary validation seconds |
| `PROVIDER_HTTP_CONNECT_TIMEOUT` | `10` | Shared provider HTTP connect seconds |
| `PROVIDER_HTTP_READ_TIMEOUT` | `60` | Shared provider HTTP read seconds |
| `PROVIDER_HTTP_MAX_TIMEOUT` | `300` | Upper bound accepted by shared provider clients |
| `PROVIDER_HTTP_MAX_RETRIES` | `4` | Shared provider HTTP retry count |
| `PROVIDER_HTTP_MAX_POOL_CONNECTIONS` | `50` | Shared HTTP pool size |
| `PROVIDER_HTTP_BACKOFF_FACTOR` | `0.5` | Shared retry backoff factor |
| `VULTR_API_CONNECT_TIMEOUT` | `10` | Vultr-specific connect seconds |
| `VULTR_API_READ_TIMEOUT` | `60` | Vultr-specific read seconds |
| `S3_MULTIPART_THRESHOLD_BYTES` | `8388608` | S3-compatible multipart threshold |
| `S3_MULTIPART_PART_SIZE_BYTES` | `8388608` | S3-compatible part size |
| `DROPBOX_UPLOAD_CHUNK_SIZE_BYTES` | `8388608` | Dropbox upload chunk size |

## Restore archive guards

| Variable | Default | Meaning |
| --- | ---: | --- |
| `RESTORE_MAX_ARCHIVE_MEMBERS` | `1000000` | Maximum archive entries |
| `RESTORE_MAX_UNCOMPRESSED_BYTES` | `2199023255552` | Maximum total expansion (2 TiB) |
| `RESTORE_MAX_COMPRESSION_RATIO` | `1000` | Maximum expanded/compressed ratio |
| `RESTORE_DISK_RESERVE_BYTES` | `536870912` | Free space kept after projected extraction (512 MiB) |

These are security and capacity controls. Do not raise them merely to force an unknown
archive through validation.

## Email and notification services

| Integration | Variables | Defaults / notes |
| --- | --- | --- |
| Provider selection | `EMAIL_PROVIDER` | `postmark`; supported values are `postmark`, `mailgun`, `ses` |
| Postmark | `POSTMARK_API_KEY`, `POSTMARK_DOMAIN`, `POSTMARK_EMAIL`, `POSTMARK_API_URL` | Credentials blank; URL `https://api.postmarkapp.com` |
| Mailgun | `MAILGUN_DOMAIN`, `MAILGUN_EMAIL`, `MAILGUN_API_KEY`, `MAILGUN_API_URL` | Credentials blank; URL `https://api.mailgun.net/v3` |
| Amazon SES | `SES_REGION_NAME`, `SES_REGION_ENDPOINT`, `SES_ACCESS_KEY_ID`, `SES_SECRET_ACCESS_KEY` | Blank |
| Slack notifications | `SLACK_TOKEN_URL`, `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET` | Blank disables connection |
| Telegram notifications | `TELEGRAM_BOT_KEY` | Blank disables connection |

The setup wizard can persist email-provider settings in PostgreSQL; environment values
are the fallback. Test delivery from the console after configuration.

## Application-log object storage

| Variable | Default | Meaning |
| --- | --- | --- |
| `S3_ACCESS_KEY_ID` | blank | Access key for legacy application-log object storage |
| `S3_SECRET_ACCESS_KEY` | blank | Secret key |
| `S3_STORAGE_BUCKET_NAME` | blank | Bucket |
| `S3_ENDPOINT_URL` | blank | AWS S3 or compatible endpoint |
| `S3_SIGNATURE_VERSION` | `s3v4` | Botocore signature version |

These are not destination credentials entered through the Storage page and do not
configure customer backup copies.

## OAuth application settings

| Integration | Required application variables | Optional endpoint variables and defaults |
| --- | --- | --- |
| Dropbox destination | `DROPBOX_APP_KEY`, `DROPBOX_APP_SECRET` | Provider public endpoints are SDK-managed |
| Google Drive destination | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | `GOOGLE_RESPONSE_TYPE=code`, `GOOGLE_OAUTH_TOKEN_URL=https://oauth2.googleapis.com/token` |
| OneDrive destination | `MS_CLIENT_ID`, `MS_CLIENT_SECRET_VALUE`; registration metadata may use `MS_OBJECT_ID`, `MS_TENANT_ID`, `MS_APPLICATION_ID`, `MS_CLIENT_SECRET_ID` | `MS_OAUTH_ENDPOINT`, `MS_OAUTH_TOKEN_URL`, `MS_REDIRECT_URL=/api/v1/callback/microsoft`, `MS_SCOPE`, `MS_RESPONSE_TYPE=code`, `MS_GRAPH_ENDPOINT` |
| pCloud destination | `PCLOUD_CLIENT_ID`, `PCLOUD_CLIENT_SECRET` | `PCLOUD_AUTH_URL`, `PCLOUD_OAUTH_TOKEN_URL`, `PCLOUD_RESPONSE_TYPE=code`, `PCLOUD_REDIRECT_URL=/api/v1/callback/pcloud` |
| Basecamp source | `BASECAMP_CLIENT_ID`, `BASECAMP_CLIENT_SECRET` | `BASECAMP_OAUTH_ENDPOINT`, `BASECAMP_TOKEN_ENDPOINT`, `BASECAMP_REDIRECT_URL=/api/v1/callback/basecamp` |
| DigitalOcean source OAuth | `DIGITALOCEAN_APP_CLIENT_ID`, `DIGITALOCEAN_APP_CLIENT_SECRET` | `DIGITALOCEAN_TOKEN_URL=https://cloud.digitalocean.com/v1/oauth/token`; PAT connections do not need app keys |
| OVH source | matching `OVH_CA_APP_KEY` + `OVH_CA_APP_SECRET`, `OVH_EU_APP_KEY` + `OVH_EU_APP_SECRET`, or `OVH_US_APP_KEY` + `OVH_US_APP_SECRET` | Region is selected by integration |

Callback paths are combined with the public application URL. Register an exact HTTPS URL
with each provider.

## Provider endpoints and local-IP discovery

These variables have public defaults in settings and normally should not be set:

| Variable | Default |
| --- | --- |
| `DIGITALOCEAN_API` | `https://api.digitalocean.com` |
| `HETZNER_API` | `https://api.hetzner.cloud` |
| `UPCLOUD_API` | `https://api.upcloud.com/1.3` |
| `VULTR_API` | `https://api.vultr.com` |
| `GOOGLE_COMPUTE_API` | `https://compute.googleapis.com` |
| `GOOGLE_RESOURCE_API` | `https://cloudresourcemanager.googleapis.com` |
| `PUBLIC_IPV4_LOOKUP_URL` | `https://api.ipify.org` |
| `PUBLIC_IPV6_LOOKUP_URL` | `https://api6.ipify.org` |

Override endpoints only for a reviewed provider migration, proxy or test harness. The IP
lookup endpoints must return a bare IP address and are used to show the self-hosted
backup server's outbound addresses for firewall allow-listing.

## Test-only fault injection

Settings contains narrowly selected `AWS_RESTORE_ACCEPTANCE_FAULT_*`,
`ORACLE_BACKUP_ACCEPTANCE_FAULT_*`, `ORACLE_RESTORE_ACCEPTANCE_FAULT_*` and
`BACKUPSHEEP_UPCLOUD_FAULT_*` switches for controlled live reliability tests. They can
pause or terminate a worker after a provider mutation. Keep all of them unset in normal
deployments. Do not copy test harness values into `.env`; use an isolated worker and the
exact row, task, correlation and provider identifiers required by the harness.
