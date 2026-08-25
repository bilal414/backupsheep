# Configuration

BackupSheep reads configuration when each process starts. Compose passes non-secret and
optional integration settings from `.env` to each application service. The stock stack
mounts Django, per-lane PostgreSQL/RabbitMQ, task-signing, onboarding and source-lane KMS
material from separate files in `.secrets`, and each role receives only its exact grant.
Changing either configuration source requires recreating the affected containers.

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
`ONBOARDING_INSTALL_TOKEN` blank. Let the exact installer create the protected per-lane
database, broker, signing, onboarding and KMS files plus the two optional lane-specific
managed-key files exactly as shown in the
[installation guide](installation.md#manual-docker-compose-installation). Keep legacy
`SSH_MANAGED_PRIVATE_KEY_PATH` and `SSH_MANAGED_PUBLIC_KEY` blank: each eligible worker
exports only its validated private-tmpfs copy. The
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
./backupsheep-compose up --detach --no-build --no-deps --force-recreate \
  app-egress-guard app
./backupsheep-compose ps --all
./backupsheep-compose logs --tail=100 \
  rabbitmq-volume-init rabbitmq-provision staging-provision \
  db-provision migrate db-seal preflight app-egress-guard app
```

`./backupsheep-compose config` expands the Compose model and can include resolved environment
values. Do not paste its full output into issues or chat; use `--quiet` for validation.
Remove the local backup copy after the change is verified, or store it in an encrypted
configuration backup. If operations were already enabled and the change affects workers,
review durable queue/recovery state before recreating them explicitly:

```bash
./backupsheep-compose --profile operations up --detach --no-build --no-deps \
  --force-recreate \
  cloud-egress-guard database-egress-guard files-egress-guard \
  storage-egress-guard logs-egress-guard \
  worker-cloud worker-database worker-files worker-storage worker-logs
./backupsheep-compose --profile operations up --detach --no-build --no-deps beat
```

Once a guard/workload pair exists, broad, guard-only and workload-only `up` operations
are refused; configuration changes use the exact paired lifecycle above.

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

For the bundled stack, let the verified installer create strong, distinct
`db_bootstrap_password`, `db_migrator_password`, and `db_<lane>_password` files for
app, preflight, Beat, cloud, database, files, storage and logs. Keep the direct `.env`
password blank. Bootstrap is mounted only into PostgreSQL and the provision/seal
one-shots, migrator only into those one-shots and `migrate`, and every long-lived
service receives exactly one lane password.

## Database configuration

The bundled database uses:

```dotenv
DB_NAME='backupsheep'
BACKUPSHEEP_DATABASE_IDENTITY_GENERATION='3'
DB_BOOTSTRAP_USER='backupsheep_bootstrap'
DB_MIGRATOR_USER='backupsheep_migrator'
DB_APP_USER='backupsheep_app'
DB_PREFLIGHT_USER='backupsheep_preflight'
DB_BEAT_USER='backupsheep_beat'
DB_CLOUD_USER='backupsheep_cloud'
DB_DATABASE_USER='backupsheep_database'
DB_FILES_USER='backupsheep_files'
DB_STORAGE_USER='backupsheep_storage'
DB_LOGS_USER='backupsheep_logs'
DB_USER='backupsheep_app'
DB_PASSWORD=''
DB_HOST='db'
DB_PORT='5432'
```

Stock Compose pins `DB_USER`, `BACKUPSHEEP_DATABASE_LANE`, and
`DB_PASSWORD_FILE=/run/secrets/db_<lane>_password` independently per service.
PostgreSQL initializes with `db_bootstrap_password`; `migrate` uses
`db_migrator_password`; `db-seal` applies exact ACL/RLS policy before preflight.
Do not duplicate any value in `.env` or reuse a credential. Follow the
[database identity migration gate](database-identity-migration.md) for an existing
bundled database; never change the generation marker by hand.

`worker-database` and `worker-files` have no SQL visibility into `core_storage*`
destination configuration and have SELECT-only access to their destination through
rows. The storage lane validates the frozen destination selection and commits the
non-secret authorization witness before it republishes the stable source task.

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
on an internal network. Stock Compose keeps the direct password blank and gives app,
preflight, Beat, cloud, database, files, storage and logs distinct
`.secrets/rabbitmq_<lane>_password` files. The networked `rabbitmq-provision` one-shot
reconciles the exact users/vhost/ACL/topology; workers cannot configure topology or read
another queue. Task-auth generation 3 also gives each publisher a private Ed25519 signing
key while consumers receive only the installation-bound public registry. Broker state
persists in `rabbitmq_data`. Plaintext `amqp` is accepted in production only for loopback
or the exact stock `rabbitmq` service. An external broker, including one reached over a
private network, must use `amqps`; BackupSheep requires a trusted certificate and verifies its hostname.
Set `RABBITMQ_CA_CERT` when the broker uses a private CA, otherwise system roots apply.
Do not put `ssl_*` overrides in the broker URL; they are rejected so certificate checking
cannot be disabled. Use one certificate-valid broker/load-balancer hostname in production
rather than a semicolon-separated failover URL.

## Artifact encryption and AWS KMS

Stock production requires `BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE=bse1`, enterprise mode,
AWS KMS and legacy restore disabled. The installer requires one resolved symmetric key
ARN, its region, an ARN allowlist containing every key still needed for restore/rotation,
and two distinct canonical AWS credential files. It stores each credential file beneath
`.secrets` and mounts it only into the matching database or files source lane. Storage,
web, cloud, logs and Beat receive no KMS identity.

Use two AWS principals. Their identity policies and the KMS key policy must condition
cryptographic actions on the exact installation-bound encryption context and
`bse:lane=database` or `bse:lane=files`; do not grant an unconditional alternate path
through an instance profile, role, grant or container credential endpoint. Prove both
same-lane success and cross-lane denial before enabling operations. Enterprise mode also
rejects a custom KMS endpoint, an insecure endpoint and the local-development provider.
See [Private staging and ciphertext handoff](../security/staging-isolation.md) for the
exact context and key-wrap rotation procedure.

## Container egress policy

App and each Internet-capable worker share a network namespace with its own no-secret
guard. Stock `deny` mode admits only the exact internal PostgreSQL/RabbitMQ peers and
blocks every outward destination. Generation-2 `allowlist` permits only the role's
reviewed exact IPv4 `CIDR:port` or IPv6 `[CIDR]:port` TCP tuples and names. `public` is
an explicit compatibility risk opt-in that permits ordinary public endpoints while
blocking special/private, discovered-gateway and well-known NAT64 destinations by
default. Exact tuples are explicit special-range exceptions intended only for narrow
reviewed private targets in public mode. Fixed `never` destinations and discovered
gateways remain blocked; the fixed set includes both well-known NAT64 prefixes and no
tuple can override them. A tuple can override only the ordinary private/reserved set. In
`allowlist` mode, also set the role's exact comma-separated
`BACKUPSHEEP_<ROLE>_EGRESS_ALLOW_DNS_NAMES`; every CNAME target must be listed separately.
Operations that need the Internet deliberately fail until their role receives the
smallest workable exact tuple and name allowlists. The complete canonical name policy is
capped at 66 unique names, including non-literal DB/broker names.

The guard authorizes stock PostgreSQL and RabbitMQ independently from outward policy:
only the exact directly connected interface/address/TCP-port tuple for each peer is
accepted, the two peers must be on distinct bridges, and a one-second DNS refresh blocks
both if either becomes absent or ambiguous. Never add a whole Docker bridge CIDR as a
shortcut.

Public mode uses ordinary DNS and requires an empty exact-name list. `deny` and strict
`allowlist` redirect workload Docker-DNS traffic to a loopback-only zero-capability
UID-`10021` parser. It validates the hostile packet and sends only an immutable-name index
plus A/AAAA selector over a Unix socket. A distinct zero-capability UID-`10022` forwarder
authenticates the parser, constructs the canonical query and alone reaches Docker DNS.
Direct external TCP/UDP 53 is blocked.

In `allowlist`, name approval and the outward exact IP/port tuple are independent; both
must permit a provider connection. This is transport-level defense in depth, not resource
authorization: a compromised role can reach another tenant or resource served on the
same IP and port. Enterprise operations require dedicated/private endpoints or a
resource-aware controlled proxy. Deployment-specific NAT64 prefixes remain a host/network
control.

Set `BACKUPSHEEP_EGRESS_POLICY_GENERATION=2`. Address-only `ALLOW_IPV4`/`ALLOW_IPV6`
values are retired and fail closed. For an older stock install, review outbound
dependencies and run the installer once with `--migrate-egress-policy`; it resets all six
roles to `deny`, clears all lists, and refuses later reuse. Mixed or customized legacy
policy requires manual review and reset rather than automatic translation.

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
| `/code/_storage` | `database_workdir` | Plaintext database dump/restore work, database run logs and lane-local locks | Read/write only in `worker-database`; absent from every other runtime role |
| `/code/_storage` | `files_workdir` | Plaintext website/WordPress/Basecamp work, website incremental cache, files-lane run logs and locks | Read/write only in `worker-files`; absent from every other runtime role |
| `/code/_storage` | `storage_workdir` | Storage-private BSE1 materialization, provider transfer work and destination-upload run logs | Read/write only in `worker-storage`; absent from every other runtime role |
| `/var/lib/backupsheep/transfer/database` | `database_ciphertext_transfer` | Fenced, published BSE1 handoff from database to storage | Read/write in `worker-database`, read-only in `worker-storage`; absent elsewhere |
| `/var/lib/backupsheep/transfer/files` | `files_ciphertext_transfer` | Fenced, published BSE1 handoff from files to storage | Read/write in `worker-files`, read-only in `worker-storage`; absent elsewhere |
| `/var/lib/backupsheep/restore-transfer` | `restore_ciphertext_transfer` | Fenced BSE1 reverse handoff from storage to the exact restore lane | Read/write in `worker-storage`, read-only in database/files; per-lane reader groups prevent cross-lane access |
| `/run/backupsheep/ssh` | private tmpfs | Exact per-operation approved host keys and, when enabled, the current lane's managed identity | Present only in database/files workers; trust/key files are mode `0600`, scoped to the operation/lane and removed after use |
| `/run/secrets/ssh_managed_database_private_key` | `.secrets/ssh_managed_database_private_key` | Optional database-lane Ed25519 identity; empty means disabled | Read-only mode-`0444` source in `worker-database` only; copied to private tmpfs before use |
| `/run/secrets/ssh_managed_files_private_key` | `.secrets/ssh_managed_files_private_key` | Optional files-lane Ed25519 identity; empty means disabled | Read-only mode-`0444` source in `worker-files` only; copied to private tmpfs before use |
| `/backups` | `backup_storage` | BSE1 archives created by the Local Storage destination | Read/write only in `worker-storage`; no other runtime role receives this mount |

The legacy `backup_workdir` is not a runtime handoff. It is mounted only in the networkless
`staging-provision` one-shot so an existing installation can prove the old shared volume is
empty before the v3 layout witness is committed. Do not restore data into it or attach it to
an application role.

Stock Compose fixes `BS_LOCAL_STORAGE_PATH` at `/backups`. A reviewed override that changes
the path must mount the same durable target read/write only in `worker-storage` and must pass
the entrypoint/preflight mount checks; do not add a Local Storage mount to app, cloud,
database, files, logs or Beat.

The web/API process can request an incremental-cache reset but has no staging mount.
`reset_incremental_cache` runs in the files lane, validates the canonical node ID, anchors
every removal to an opened cache-directory descriptor with no-follow checks, and takes the
same per-node incremental lock held across mirror/archive work. Files-lane run-log pruning
runs there at 03:00 UTC as `delete_old_logs`; database run-log pruning runs separately at
03:05 UTC in the database lane as `delete_old_database_logs`; destination-upload run-log
pruning runs at 03:10 UTC in the storage lane as `delete_old_storage_logs`. PostgreSQL
`CoreLog` rows are pruned separately at 03:30 UTC by `delete_old_db_logs`. Storage
upload/finalization otherwise touches only
storage-private work and the fenced ciphertext handoffs. Keep custom queue routing and
Compose overrides consistent with those ownership boundaries.

`SSH_KNOWN_HOSTS_PATH` is a compatibility-only file setting for separately reviewed
non-stock deployments. Stock Compose does not set or mount it. The app stores exact,
account-scoped host-key approvals and append-only approval/replacement/revocation events in
PostgreSQL. Workers materialize only the current approval required by one operation in a
transient private-runtime file. Unknown, changed, noncanonical or stale-generation keys are
rejected. Approve or replace a key only after verifying its fingerprint independently.

Stock managed SSH authentication uses distinct Ed25519 identities. Put the database
private half in `.secrets/ssh_managed_database_private_key` and the files private half in
`.secrets/ssh_managed_files_private_key`, each mode `0444` beneath the mode-`0700` secret
directory; the installer derives their public settings. `worker-database` and
`worker-files` each receive only their own source, validate it, and copy it into private
tmpfs as mode `0600`. The app and other roles receive neither private key. Both identities
must be configured together and differ. This mode is available only when PostgreSQL
contains exactly one account; creation of a second account atomically disables and fences
managed-key connections. Multi-account installations use customer-supplied private keys.
Never store a private key in a work/transfer volume, `.env`, a broker message, or an image.

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

`WORDPRESS_INTEGRATION_ENABLED` and `BASECAMP_INTEGRATION_ENABLED` both default to `false`.
They are compatibility switches, not enterprise feature switches: either source is usable
only when enterprise mode is explicitly false, artifact mode is `legacy-only`, and legacy
restore/download is explicitly enabled. Enterprise/BSE1 installs ignore a true family
switch, hide the source choices, reject every new-protection/backup initiation boundary,
and preserve existing records for inspection.

### Compose credential-lane boundary

Stock Compose reads `.env` only as an interpolation source and never attaches the file
wholesale to an application container. The model names every accepted configuration
key, blanks loader/proxy hooks and deployment-wide credentials, and restores each
credential family only to its required consumer:

| Runtime role | Deployment-wide integration credentials available |
| --- | --- |
| `app` (web) | All families, for OAuth/setup callbacks, notification setup and authenticated legacy log-URL handling |
| `worker-cloud` | DigitalOcean application credentials and the matching OVH CA/EU/US application pairs |
| `worker-files` | Basecamp application credentials |
| `worker-storage` | Dropbox, pCloud, Microsoft OneDrive and Google Drive application credentials |
| `worker-logs` | Postmark, Mailgun, SES, Slack and Telegram credentials |
| `worker-database`, Beat, migration/preflight/provisioning roles | None of these integration credential families |

The immutable entrypoint independently rejects a non-empty credential from any
non-owning role, so a stale or tampered `.env` cannot silently broaden a lane. A new or
unknown key is not passed until the Compose allowlist and its consumer contract are
reviewed. This is a
process-compromise containment boundary, not permission to reuse provider secrets: scope
each credential at the provider and rotate it on suspected disclosure. `SENTRY_DSN`
remains available to every Django/Celery role because each initializes the scrubbed Sentry
integration and a DSN is an ingest identifier, not a provider-authorization credential.

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
./backupsheep-compose up --detach --no-build --no-deps --force-recreate \
  app-egress-guard app
./backupsheep-compose ps --all
curl -fsS http://127.0.0.1:8000/healthz/
./backupsheep-compose exec app python manage.py check
```

The profile-less command validates the core without executing provider work. If operations
were previously authorized, recreate and inspect those services separately after checking
durable queue/recovery state:

```bash
./backupsheep-compose --profile operations up --detach --no-build --no-deps \
  --force-recreate \
  cloud-egress-guard database-egress-guard files-egress-guard \
  storage-egress-guard logs-egress-guard \
  worker-cloud worker-database worker-files worker-storage worker-logs
./backupsheep-compose --profile operations up --detach --no-build --no-deps beat
./backupsheep-compose --profile operations exec worker-cloud celery -A backupsheep inspect ping
```

Then verify the affected behavior: complete an OAuth connection, send a test email,
validate a storage destination, or run a disposable backup and restore. A healthy web
container alone does not validate provider credentials or worker execution.
