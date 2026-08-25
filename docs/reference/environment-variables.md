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
roles. Its required installation secrets, separate database/files KMS credentials and
optional lane-specific managed SSH identities are file-backed under `.secrets`; see below. After
editing configuration on an existing installation, validate and recreate the web/guard
pair:

```bash
./backupsheep-compose config --quiet
./backupsheep-compose up --detach --no-build --no-deps --force-recreate \
  app-egress-guard app
```

Provider workers and Beat remain disabled unless the `operations` profile is explicitly
enabled. Recreate them only after reviewing durable queue and recovery state:

```bash
./backupsheep-compose --profile operations up --detach --no-build --no-deps \
  --force-recreate \
  cloud-egress-guard database-egress-guard files-egress-guard \
  storage-egress-guard logs-egress-guard \
  worker-cloud worker-database worker-files worker-storage worker-logs
./backupsheep-compose --profile operations up --detach --no-build --no-deps beat
```

A broad `up` is reserved for the first creation of a topology (or after a reviewed
whole-stack `down`). Once any pair exists, the wrapper refuses broad, guard-only and
workload-only lifecycle changes.

Boolean values recognize `1`, `true`, `yes` or `on` (case-insensitive) as true; other
values are false. Defaults below are repository defaults for `develop`.

## Stock Docker and installer controls

These values control Compose/installer behavior rather than Django application features:

| Variable | Default | Meaning |
| --- | --- | --- |
| `BACKUPSHEEP_IMAGE` | `backupsheep:local` | Exact locally built application image tag; the verified installer requires `backupsheep:<full-commit>` and application roles use `pull_policy: never` |
| `BACKUPSHEEP_POSTGRES_IMAGE` | `backupsheep-postgres:local` | Exact locally built database image tag; the verified installer requires `backupsheep-postgres:<full-commit>` and the database role uses `pull_policy: never` |
| `BACKUPSHEEP_EGRESS_IMAGE` | `backupsheep-egress:local` | Exact locally built namespace-guard image; verified installation builds it from the reviewed commit and guard roles use `pull_policy: never` |
| `BACKUPSHEEP_COMPOSE_PROJECT_NAME` | blank sample; installer pins the requested/default `backupsheep` name | Stable lowercase Compose ownership namespace. The wrapper reads only this protected `.env` witness and supplies the same explicit `--project-name`; ambient `COMPOSE_PROJECT_NAME` and caller project overrides are refused. Do not edit it to adopt, rename or recover resources. |
| `BACKUPSHEEP_INSTALLATION_ID` | blank sample; installer generates it | Stable random 64-character lowercase hexadecimal ownership marker. Required by stock Compose; do not rotate or copy it between installations |
| `BACKUPSHEEP_POSTGRES_STORAGE_GENERATION` | blank sample; installer records `18-alpine-icu-v1` through a pending state | Fail-closed bundled-database runtime/storage generation. Never advance it manually; completion follows an in-volume marker and, for upgrades, a verified logical-migration receipt |
| `BACKUPSHEEP_POSTGRES_STORAGE_INTENT` | blank sample; installer records `new-empty-v1` or `migrated-debian-v1` | Immutable origin of the active `postgres_data_v1` volume, included in the storage witness |
| `BACKUPSHEEP_POSTGRES_STORAGE_WITNESS` | blank sample; installer derives it | SHA-256 binding of installation ID, Compose project, logical volume, Alpine/ICU generation and intent; do not copy or edit it |
| `BACKUPSHEEP_POSTGRES_RETIRED_IMAGE_ID` | blank for fresh installs; installer records an exact `sha256:` ID during migration | Exact Debian/UID-999 runtime retained with detached legacy `pgdata` for rollback proof; never substitute a tag or delete it before the retention decision |
| `BACKUPSHEEP_DATABASE_IDENTITY_GENERATION` | blank sample; installer records `3` | Stock PostgreSQL identity/ACL/RLS contract witness. Never set it manually on an existing installation to bypass provisioning |
| `BACKUPSHEEP_STAGING_LAYOUT_INTENT` | blank sample; installer records `new-empty-v3` or `migrate-empty-legacy-v3` | Exact one-time layout intent bound into the durable witness; never edit it manually |
| `BACKUPSHEEP_STAGING_LAYOUT_WITNESS` | blank sample; installer derives it | SHA-256 witness binding layout v3, installation ID and intent; the networkless provisioner verifies it before any runtime mounts lane volumes |
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
| `BACKUPSHEEP_DATABASE_IDENTITY_GENERATION` | blank sample / installer-owned `3` | Fail-closed stock identity/ACL/RLS contract witness. Pending values cannot start a long-lived lane; never change it manually |
| `DB_BOOTSTRAP_USER` | `backupsheep_bootstrap` | Bundled PostgreSQL bootstrap login. The official image initializes it as cluster superuser; only PostgreSQL, `db-provision`, and `db-seal` receive its password |
| `DB_MIGRATOR_USER` | `backupsheep_migrator` | Non-superuser database/schema/object owner used by `migrate`; its password also enters provision/seal |
| `DB_APP_USER` | `backupsheep_app` | Non-owner web/control-plane lane |
| `DB_PREFLIGHT_USER` | `backupsheep_preflight` | Read-only deployment/catalog gate lane |
| `DB_BEAT_USER` | `backupsheep_beat` | Scheduler lane; workers cannot read or mutate its schedule tables |
| `DB_CLOUD_USER` | `backupsheep_cloud` | Explicit remote-provider worker lane |
| `DB_DATABASE_USER` | `backupsheep_database` | Database source/backup/restore lane |
| `DB_FILES_USER` | `backupsheep_files` | Website, WordPress and Basecamp source lane |
| `DB_STORAGE_USER` | `backupsheep_storage` | Local storage/artifact handoff lane |
| `DB_LOGS_USER` | `backupsheep_logs` | Run-log/notification and bounded replay-retention lane |
| `DB_USER` | `backupsheep_app` | Compatibility alias used by non-Compose deployments; stock Compose pins each service to its lane user |
| `DB_PASSWORD` | unsafe placeholder outside stock Compose; blank in stock `.env` | Direct database password for non-stock deployments |
| `DB_PASSWORD_FILE` | unset outside stock Compose | Absolute database-password pointer; stock long-lived services receive only `/run/secrets/db_<lane>_password` |
| `DB_HOST` | `db` | Database hostname in stock Compose |
| `DB_PORT` | `5432` | Database port |
| `DATABASE_URL` | blank | `postgres://` or `postgresql://` URL; overrides the five discrete Django values |
| `DB_SSLMODE` | blank | libpq `sslmode`; external production databases require `verify-full` |
| `DB_SSLROOTCERT` | blank | CA/root-certificate bundle for external PostgreSQL hostname verification |

The bundled `db` service consumes `DB_NAME`/`DB_BOOTSTRAP_USER` and
`db_bootstrap_password` as `POSTGRES_PASSWORD_FILE`. `db-provision` prepares all
marked identities and revokes runtime access; `migrate` receives only
`db_migrator_password`; then `db-seal` applies the exact per-lane grants and
RLS contract. App, preflight, Beat and each worker receive only their own lane password.
Database/files workers cannot read any `core_storage*` table or change the
storage-owned per-backup destination authorization witness; source access begins only
after the storage lane has durably validated the frozen destination set.
In production, plaintext PostgreSQL is allowed only for an exact
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
| `RABBITMQ_USER` | `backupsheep_app` | Stock application broker identity; Compose pins each other role independently |
| `RABBITMQ_PASSWORD` | blank | Direct broker password for non-stock deployments; must remain blank in stock `.env` |
| `RABBITMQ_PASSWORD_FILE` | unset outside stock Compose | Absolute file-backed broker-password pointer; stock roles receive only `/run/secrets/rabbitmq_<lane>_password` |
| `BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION` | blank sample / installer-owned `2` | Fail-closed stock broker identity witness; existing installs use the explicit migration flag |
| `BACKUPSHEEP_CELERY_SECURITY_GENERATION` | blank sample / installer-owned `3` | Authenticated-task protocol witness; generation-2 installs require the explicit drained-queue signing rotation |
| `BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION` | blank sample / installer-owned positive integer | Active public-registry/key generation; increments after every reviewed rotation |
| `BACKUPSHEEP_CELERY_SECURITY_REQUIRED` | `true` in stock Compose | Requires signed lane-bound task envelopes; do not disable in stock Docker |
| `BACKUPSHEEP_CELERY_LANE` | service-owned | Fixed app, Beat, preflight, or worker identity used for credential/key selection |
| `CELERY_TASK_REPLAY_RETENTION_SECONDS` | `1209600` | Retains terminal replay identities for 14 days; cannot be shorter than the seven-day signed lifetime plus clock skew |
| `CELERY_TASK_REPLAY_CLEANUP_BATCH_SIZE` | `1000` | Bounded terminal replay rows deleted by one logs-lane cleanup run (`1`-`10000`) |
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

## Artifact encryption and KMS

| Variable | Stock value/default | Meaning |
| --- | --- | --- |
| `BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE` | `bse1` | Requires the versioned chunked AES-256-GCM-SIV envelope; stock production does not write legacy plaintext artifacts |
| `BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE` | `true` | Enforces BSE1, standard-endpoint AWS KMS and legacy-restore denial |
| `BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE` | `false` | Must remain false in enterprise mode; an old non-BSE1 object fails closed |
| `BACKUPSHEEP_ARTIFACT_KEY_PROVIDER` | `aws-kms` | Stock production key provider. `local-development` is rejected in production/enterprise mode |
| `BACKUPSHEEP_ARTIFACT_CHUNK_SIZE` | `4194304` | Authenticated-record plaintext bytes; accepted range is 64 KiB through 64 MiB |
| `BACKUPSHEEP_ARTIFACT_KMS_KEY_ID` | installer-required | Resolved symmetric KMS key ARN used for new data-key wraps; aliases are not accepted by the installer |
| `BACKUPSHEEP_ARTIFACT_KMS_REGION` | installer-required | AWS region containing every allowlisted artifact key |
| `BACKUPSHEEP_ARTIFACT_KMS_ALLOWED_KEY_ARNS` | installer-required | Comma-separated resolved ARNs accepted for restore and key-wrap rotation; include the active key |
| `BACKUPSHEEP_ARTIFACT_KMS_ENDPOINT_URL` | blank | Custom endpoint; enterprise mode requires blank |
| `BACKUPSHEEP_ARTIFACT_KMS_ALLOW_INSECURE_ENDPOINT` | `false` | Insecure endpoint opt-in; enterprise mode requires false |
| `BACKUPSHEEP_ARTIFACT_KMS_CONNECT_TIMEOUT_SECONDS` | `5` | KMS connect timeout, maximum 60 seconds |
| `BACKUPSHEEP_ARTIFACT_KMS_READ_TIMEOUT_SECONDS` | `20` from `.env_sample` | KMS read timeout, maximum 120 seconds |
| `BACKUPSHEEP_ARTIFACT_KMS_MAX_ATTEMPTS` | `3` | Bounded KMS client attempts, maximum 5 |

AWS credentials never belong in `.env`. The installer requires two different canonical
user-owned source files and stores them as
`.secrets/artifact_kms_database_aws_credentials` and
`.secrets/artifact_kms_files_aws_credentials`. Only the matching source worker receives
each file; storage and every other role receive neither. IAM identity policy and the KMS
key policy must restrict actions by the exact `bse:lane` and complete encryption-context
key set. See [Private staging and ciphertext handoff](../security/staging-isolation.md)
before enabling operations or rotating a key wrap.

## Per-role egress guards

For each role name `APP`, `CLOUD`, `DATABASE`, `FILES`, `STORAGE` and `LOGS`:

| Variable pattern | Default | Meaning |
| --- | --- | --- |
| `BACKUPSHEEP_EGRESS_POLICY_GENERATION` | `2` | Mandatory fail-closed policy generation. The wrapper, preflight and guard refuse missing, padded, or unsupported values. |
| `BACKUPSHEEP_<ROLE>_EGRESS_MODE` | `deny` | `deny` admits only exact internal PostgreSQL/RabbitMQ peers; `allowlist` adds only reviewed exact TCP endpoint tuples and DNS names; `public` is an explicit compatibility risk opt-in that permits ordinary public IPs while denying special/private destinations unless explicitly excepted and always denying discovered gateways and the two well-known NAT64 prefixes. |
| `BACKUPSHEEP_<ROLE>_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS` | blank | Comma-separated exact IPv4 `CIDR:port` entries, for example `203.0.113.10/32:443`; required in `allowlist` unless the IPv6 list is non-empty. In `public`, entries are explicit special-range exceptions intended only for narrow reviewed private targets. |
| `BACKUPSHEEP_<ROLE>_EGRESS_ALLOW_IPV6_TCP_ENDPOINTS` | blank | Comma-separated exact IPv6 `[CIDR]:port` entries, for example `[2001:db8::10/128]:443`; otherwise the same semantics as the IPv4 list. |
| `BACKUPSHEEP_<ROLE>_EGRESS_ALLOW_DNS_NAMES` | blank | Comma-separated exact provider/source names accepted only in `allowlist`. The complete canonical policy is capped at 66 unique names including non-literal DB/broker names; there are no wildcard/suffix semantics, and every CNAME target must be listed separately. |

Compose supplies the DB/broker hostnames and ports internally. Do not use an outward CIDR
to model those peers: the guard accepts only their exact directly connected
interface/address/TCP-port tuples on two distinct internal bridges, refreshes Docker DNS
every second and blocks both peers while resolution is absent or ambiguous. See
[`deploy/egress/README.md`](../../deploy/egress/README.md) for the threat model and test.

`deny` and `allowlist` redirect workload Docker-DNS queries to a loopback-only,
zero-capability UID-`10021` parser. It validates hostile packets and sends only a fixed
two-byte allowed-name index and A/AAAA selector over a Unix socket. A distinct
zero-capability UID-`10022` forwarder authenticates that peer, constructs the canonical
query, and is the sole DNS process permitted to reach Docker DNS. Both processes must
remain live and match immutable readiness witnesses. The monitor renews the exact peer
sets and strict workload authorization on every complete cycle; health requires that
fresh renewal to be younger than the kernel lease, not merely that PID 1 exists. The
workload healthcheck separately proves local web/worker readiness and fresh TCP
connections to both database and broker through the current sets.

`public` has neither strict DNS process and must have an empty DNS-name list. Its exact
tuples are evaluated as explicit special-range exceptions intended only for narrow
reviewed private targets. Fixed `never` destinations and discovered gateways remain
blocked; the fixed set includes `64:ff9b::/96` and `64:ff9b:1::/48`, and no tuple can
override either. A tuple can override only the ordinary private/reserved set. In
`allowlist`, name permission never grants a connection
by itself: the result must also match an exact IP-and-TCP-port tuple. A tuple is only
transport-level defense in depth; a compromised role can still reach another tenant or
resource served on the same IP and port. Enterprise operations require dedicated/private
endpoints or a resource-aware controlled proxy. Site-specific NAT64 prefixes remain a
host/network control and must be blocked or disabled and tested separately.

The address-only `BACKUPSHEEP_<ROLE>_EGRESS_ALLOW_IPV4` and
`BACKUPSHEEP_<ROLE>_EGRESS_ALLOW_IPV6` variables are retired; any non-empty legacy value
fails closed. An existing stock installation without a generation must run the installer
once with `--migrate-egress-policy`. The authorized migration accepts only uniform stock
public/blank, blank/blank, or deny/blank state, resets all six roles to `deny`, clears
every old/new list, writes generation 2, and is rejected on a later run. Mixed or
customized legacy policy requires manual review and reset; the installer never translates
it implicitly.

## Stock Compose secret files

The verified installer creates `.secrets` as an owner-only mode-`0700` directory and
stores `django_secret_key`, `db_bootstrap_password`, `db_migrator_password`,
the eight `db_<lane>_password` files, `rabbitmq_bootstrap_password`, the eight
`rabbitmq_<lane>_password` files, seven lane signing keys,
`celery_trusted_public_keys`, `onboarding_token`, and the two required lane-specific
artifact-KMS credential files as separate owner-owned, non-linked, mode-`0444` files. It
also creates empty optional `ssh_managed_database_private_key` and
`ssh_managed_files_private_key` files with the same ownership/link/mode rules. The private
parent prevents host directory traversal while Docker bind-mounts each file read-only only
to its granted non-root role. Direct copies of required values and any legacy managed-key
path remain blank in `.env`, Compose expansion and container inspection. Do not change the
modes independently or add arbitrary entries to the installer-managed directory.

Only `worker-database` receives the database private-key source and only `worker-files`
receives the files private-key source. The app and every other role receive neither private
key. Empty means disabled. On each worker start, the entrypoint rejects a non-regular,
NUL-containing, larger-than-64-KiB, encrypted, non-Ed25519 or otherwise invalid non-empty
key. It copies the lane's accepted key to private tmpfs at
`/run/backupsheep/ssh/managed_private_key`, sets mode `0600`, and exports that runtime path
internally. SSH never reads a mode-`0444` source directly. The two public keys must be
distinct and match their private halves.

Managed-key mode is a convenience for installations containing exactly one account. The
database atomically disables and fences all managed-key connections when a second account
is created. Multi-account installations must use customer-supplied, account-scoped private
keys. See the upgrade guide before retiring a legacy shared identity.

`BACKUPSHEEP_SECRETS_DIR` selects that host directory for Compose and defaults to
`.secrets`; installer-managed installations require exactly that relative value. The
runtime `*_FILE` paths above are separately fixed to `/run/secrets/...` by Compose and must
not be repointed through `.env`.

## Paths, logs and downloads

| Variable | Default | Unit / meaning |
| --- | --- | --- |
| `BACKUPSHEEP_PIDS_LIMIT` | `512` | Maximum processes per app/migrate/preflight/worker/Beat container in stock non-Swarm Compose |
| `BACKUPSHEEP_STAGING_MIN_FREE_BYTES` / `BACKUPSHEEP_STAGING_MIN_FREE_INODES` | `536870912` / `1024` | Minimum free capacity each dedicated v3 mount must have before the networkless provisioner changes ownership or verifies its witness |
| `BACKUPSHEEP_PRIVATE_MIN_FREE_BYTES` / `BACKUPSHEEP_PRIVATE_MIN_FREE_INODES` | `536870912` / `1024` | Reserve added to a source/storage lane's projected private-work requirement |
| `BACKUPSHEEP_TRANSFER_MIN_FREE_BYTES` / `BACKUPSHEEP_TRANSFER_MIN_FREE_INODES` | `536870912` / `1024` | Reserve added before a database/files forward ciphertext fence is created or published |
| `BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_BYTES` / `BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_INODES` | `536870912` / `1024` | Reserve added before a storage-owned reverse ciphertext handoff is created or published |
| `BS_LOCAL_STORAGE_PATH` | `/backups` | Stock Local Storage root, mounted read/write only in `worker-storage`; every other runtime role must have no `/backups` mount |
| `LOG_RETENTION_DAYS` | `30` | Days before files/database/storage private run logs and PostgreSQL `CoreLog` activity rows are pruned |
| `S3_DOWNLOAD_URL_EXPIRES` | `300` | Compatibility-only provider-signed URL lifetime for an explicitly enabled non-enterprise legacy artifact; hard maximum `3600`. Stock BSE1 direct download is refused |
| `WORDPRESS_INTEGRATION_ENABLED` | `false` | Explicit non-enterprise compatibility opt-in for WordPress secure connector v2; it has no effect in enterprise/BSE1 mode or unless legacy artifact download is enabled |
| `BASECAMP_INTEGRATION_ENABLED` | `false` | Explicit non-enterprise compatibility opt-in for Basecamp; it has no effect in enterprise/BSE1 mode or unless legacy artifact download is enabled |
| `WORDPRESS_PRIVATE_TARGET_CIDRS` | blank | Exact RFC1918/ULA CIDRs permitted for DNS-pinned, certificate-verified HTTPS WordPress targets; special/metadata ranges remain denied |
| `ALLOW_INSECURE_FTP` | `false` | Explicit legacy compatibility opt-in for plaintext FTP; prefer SFTP or certificate-verified FTPS |
| `SSH_KNOWN_HOSTS_PATH` | `_storage/ssh_known_hosts` outside stock Compose | Compatibility-only file setting for separately reviewed non-stock deployments. Stock Compose ignores this shared-file model: approvals and append-only audit events are account-scoped PostgreSQL records, and each SSH operation receives only its exact approved keys in a transient mode-`0600` private-runtime file |
| `SSH_MANAGED_DATABASE_PUBLIC_KEY` | blank | Public half of the optional database-worker Ed25519 identity; it must match `.secrets/ssh_managed_database_private_key` and differ from the files identity |
| `SSH_MANAGED_FILES_PUBLIC_KEY` | blank | Public half of the optional files-worker Ed25519 identity; it must match `.secrets/ssh_managed_files_private_key` and differ from the database identity |
| `SSH_MANAGED_PRIVATE_KEY_PATH` | blank | Legacy compatibility setting that must remain blank in stock `.env`; the database/files entrypoint exports its own lane-private runtime target only after validating the granted source |
| `SSH_MANAGED_PUBLIC_KEY` | blank | Legacy shared-identity setting; stock Compose requires it to remain blank |

`S3_DOWNLOAD_URL_EXPIRES` does not enable BSE1 export. It applies only when a separately
reviewed non-enterprise legacy-artifact deployment is explicitly allowed to create an S3-
compatible, Google Cloud, Azure, Alibaba or Tencent signature. Dropbox, OneDrive and
similar APIs may issue provider-bounded temporary links in that legacy path without
accepting a caller-selected lifetime.

WordPress and Basecamp do not currently have an authenticated BSE1 plaintext-export or
automatic-restore action. Their family switches take effect only when all of the following
are explicit: `BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=false`,
`BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE=legacy-only`, and
`BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=true`. Stock enterprise mode hides both choices
and rejects direct API, schedule, outbox, retry, and worker-task bypasses while retaining
existing records for inspection.

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

Although all of these variables remain valid `.env` inputs, stock Compose does not make
them ambient in every process. It first blanks all known integration credential families,
then grants all families to web for setup/OAuth callback handling, DigitalOcean/OVH only
to cloud, Basecamp only to files, Dropbox/pCloud/Microsoft/Google only to storage, and
Postmark/Mailgun/SES/Slack/Telegram only to logs. Database, Beat and one-shot roles receive
none. `init.sh` rechecks the lane boundary and refuses startup on a misplaced value.
`SENTRY_DSN` is deliberately shared because every Django/Celery process initializes the
scrubbed client and the DSN grants event ingestion rather than provider-account access.

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
