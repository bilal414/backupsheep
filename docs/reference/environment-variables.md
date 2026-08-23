# Environment-variable reference

BackupSheep loads settings once, when each process starts. The effective precedence is:

1. values from `.env_sample`;
2. values from `.env`;
3. process environment variables.

If the process environment contains `BACKUPSHEEP_SECRETS`, its value must be a JSON object
and becomes the complete configuration instead. No sample, `.env` or other process values
are merged into that object. It therefore must contain every key accessed by settings.

Compose supplies `.env` to application roles. After editing it, validate and recreate:

```bash
docker compose config --quiet
docker compose up --detach --remove-orphans
```

Boolean values recognize `1`, `true`, `yes` or `on` (case-insensitive) as true; other
values are false. Defaults below are repository defaults for `develop`.

## Django and application identity

| Variable | Default | Meaning |
| --- | --- | --- |
| `DJANGO_SERVER` | `prod` | Environment label, including the Sentry environment tag |
| `DJANGO_DEBUG` | `false` | Enables Django debug pages and browsable API; never enable publicly |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated request hosts, without schemes/paths |
| `DJANGO_SECRET_KEY` | unsafe placeholder | Stable signing key and email-credential key material; production refuses `change-this-key` |
| `DJANGO_SETTINGS_MODULE` | `backupsheep.settings` | Django settings module |
| `DJANGO_HTTPS` | `false` | Secure cookies, HTTP redirect and one-year HSTS; requires a correct TLS proxy |
| `ONBOARDING_INSTALL_TOKEN` | blank | Fixed first-owner token; blank generates `_storage/install_token` on first onboarding request |
| `APP_DOMAIN` | `localhost:8000` | Public host and optional port, no scheme/path |
| `APP_PROTOCOL` | `http://` | Public scheme, including `://`; combines with `APP_DOMAIN` for CSRF/OAuth URLs |
| `APP_NAME` | `BackupSheep` | Display name |
| `BACKUPSHEEP_SECRETS` | unset | Complete JSON configuration replacement; see warning above |
| `SENTRY_DSN` | blank | Enables Sentry event/performance delivery when non-empty |

`APP_PROTOCOL`, `APP_DOMAIN`, proxy forwarding and `DJANGO_HTTPS` must describe the same
public URL. Keep `DJANGO_SECRET_KEY` stable and backed up as a secret.

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
| `DB_USER` | `backupsheep` | Database role; also initializes bundled PostgreSQL |
| `DB_PASSWORD` | unsafe placeholder | Database password; set before creating `pgdata` |
| `DB_HOST` | `db` | Database hostname in stock Compose |
| `DB_PORT` | `5432` | Database port |
| `DATABASE_URL` | blank | `postgres://` or `postgresql://` URL; overrides the five discrete Django values |
| `DB_SSLMODE` | blank | libpq `sslmode`; overrides/adds the URL query option when set |

The bundled `db` service still consumes the discrete `DB_*` keys even when Django uses
`DATABASE_URL`. Changing `DB_PASSWORD` after PostgreSQL initialized does not change the
existing database role.

## RabbitMQ

| Variable | Default | Meaning |
| --- | --- | --- |
| `CELERY_BROKER_URL` | blank | Complete managed/external RabbitMQ URL |
| `CLOUDAMQP_URL` | unset | Managed RabbitMQ URL used ahead of `CELERY_BROKER_URL` |
| `RABBITMQ_HOST` | `rabbitmq` | When non-empty, fragment mode takes highest precedence |
| `RABBITMQ_PORT` | `5672` | Fragment-mode port |
| `RABBITMQ_USER` | `backupsheep` | Dedicated bundled-broker username |
| `RABBITMQ_PASSWORD` | blank (required by Compose) | Dedicated broker password; `install.sh` generates it |
| `RABBITMQ_VHOST` | `backupsheep` | Dedicated virtual host; components are URL encoded |

Only `amqp://` and `amqps://` broker URLs are accepted. The stock Compose deployment does
not use RabbitMQ's well-known `guest` account.

## Paths, logs and downloads

| Variable | Default | Unit / meaning |
| --- | --- | --- |
| `BS_LOCAL_STORAGE_PATH` | `/backups` | Root used by the Local Storage destination; mount identically in relevant roles |
| `LOG_RETENTION_DAYS` | `30` | Days before local run logs and database activity are pruned |
| `S3_DOWNLOAD_URL_EXPIRES` | `86400` | Seconds that generated archive download URLs remain valid |
| `SSH_KNOWN_HOSTS_PATH` | `_storage/ssh_known_hosts` | Reviewed OpenSSH known-hosts file; relative paths resolve under repository root |
| `SSH_MANAGED_PRIVATE_KEY_PATH` | blank | Optional managed private key file; relative paths resolve under repository root |
| `SSH_MANAGED_PUBLIC_KEY` | blank | Matching public key advertised by the console only when private key exists |

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
