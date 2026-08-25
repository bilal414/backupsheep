# Production deployment

The bundled web service is Gunicorn on plain HTTP port `8000`. A production operator is
responsible for TLS termination, network policy, host maintenance, secrets, capacity,
monitoring and recovery.

## Production checklist

Before making an instance reachable from the internet:

- [ ] install an exact reviewed 40-character commit (the verified installer rejects
      branches, tags and abbreviations);
- [ ] verify `BACKUPSHEEP_IMAGE`, `BACKUPSHEEP_POSTGRES_IMAGE` and
      `BACKUPSHEEP_EGRESS_IMAGE` are the installer-owned local tags derived from that
      exact commit; `pull_policy: never` prevents registry substitution;
- [ ] create/verify the protected `.secrets` files and keep
      `.secrets/django_secret_key` stable;
- [ ] preserve the installer-generated 64-hex `BACKUPSHEEP_INSTALLATION_ID` and verify the
      labeled empty ownership sentinel before reusing a Compose project name;
- [ ] resolve every exact-name Docker network/volume collision; the installer must refuse
      an unlabeled or foreign object rather than adopting it;
- [ ] preserve the installer's distinct database bootstrap, migrator and per-lane password
      files; never collapse them into one runtime login;
- [ ] preserve the distinct RabbitMQ bootstrap/per-lane passwords, queue ACLs and signed
      task keys; never replace them with one shared broker identity;
- [ ] configure BSE1 with a resolved allowlisted AWS KMS key and two different
      database/files credential identities; prove same-lane success and cross-lane denial;
- [ ] for existing broker data, prove the live RabbitMQ generation and complete the
      documented 3.13 -> 4.2 -> 4.3/Khepri gate; never invent the installer-owned
      `BACKUPSHEEP_RABBITMQ_DATA_GENERATION` witness (the proof requires exactly one
      running, healthy broker and diagnostics as the named `rabbitmq` account);
- [ ] keep `DJANGO_DEBUG=false`;
- [ ] set `DJANGO_ALLOWED_HOSTS` to explicit public hosts, never `*`;
- [ ] terminate TLS at a trusted reverse proxy and set `DJANGO_HTTPS=true` only after it
      forwards `X-Forwarded-Proto: https`;
- [ ] set `APP_PROTOCOL=https://` and `APP_DOMAIN` to the real public host;
- [ ] run Django's deployment checks and review/resolve every warning before public
      exposure; HTTPS warnings are tolerated only during loopback/SSH-tunnel onboarding;
- [ ] keep browser sessions at or below 12 hours and require reauthentication after the
      browser closes (`SESSION_COOKIE_AGE=43200`, `SESSION_EXPIRE_AT_BROWSER_CLOSE=true`);
- [ ] block public access to PostgreSQL, RabbitMQ and direct port `8000`;
- [ ] restrict the console with firewall, VPN or identity-aware access when practical;
- [ ] capacity-monitor every private work, ciphertext-transfer and Local Storage volume;
- [ ] configure transactional email or document host-level password recovery;
- [ ] back up and restore-test the BackupSheep database, configuration and local archives;
- [ ] run a disposable backup and restore rehearsal for every provider you will rely on.

## Network layout

The stock Compose file publishes only `app`:

```text
Internet -> TLS reverse proxy -> app egress-guard namespace -> app:8000
                              each outward role -> its guard -> deny by default / reviewed peers
                                                   | exact DB tuple -> PostgreSQL
                                                   ` exact broker tuple -> RabbitMQ
Beat ------------------------------------------------ exact internal bridges -> DB/RabbitMQ
```

Do not publish the `db` or `rabbitmq` ports. Stock Compose binds app port `8000` to host
loopback; keep `BACKUPSHEEP_BIND_ADDRESS=127.0.0.1` and keep the host/cloud firewall closed
to that port from untrusted networks. If the proxy is another container, connect it to an
explicit reviewed network and avoid a public app-port mapping entirely.

The exact stock `db` and `rabbitmq` service names, loopback, and PostgreSQL Unix sockets
are the only production plaintext exceptions. They assume one controlled host and a
private Docker bridge. For an external PostgreSQL endpoint, require
`DB_SSLMODE=verify-full` and `DB_SSLROOTCERT=/path/to/ca.pem`. For any external RabbitMQ
endpoint, use `amqps` with a valid hostname certificate; set `RABBITMQ_CA_CERT` only when
the broker uses a private CA. RFC1918 addresses and internal DNS names still require TLS.

For app and every Internet-capable worker, the secret-bearing process shares only its
network namespace with a no-secret egress guard; PID, mount, IPC, user and secret contexts
remain separate. Treat each guard/workload pair as one lifecycle unit and always recreate
both together. The wrapper refuses independent guard lifecycle commands, and guards use
`restart: "no"` so Docker cannot silently replace the namespace owner beneath its running
workload. The guard trusts no bridge subnet: it
allows PostgreSQL and RabbitMQ only when interface, current resolved address, TCP protocol
and destination port match on two distinct directly connected internal bridges. A
one-second reconciler atomically refreshes those exact peer sets after Docker DNS changes
and blocks both sets on absence or ambiguity. Its health witness must come from a fresh
successful renewal within the kernel lease; monitor liveness alone is insufficient.
The workload healthcheck separately proves local web/worker readiness plus fresh TCP
connections to both database and broker through those current sets, so a stranded old
namespace becomes unhealthy rather than appearing available.
Stock `deny` mode admits only those internal peers and blocks every outward destination.
Internet-dependent operations deliberately fail until the operator supplies the smallest
reviewed per-role exact TCP tuples: IPv4 `CIDR:port` and IPv6 `[CIDR]:port`. `public` is
an explicit compatibility risk opt-in. It permits ordinary public space and may carry a
narrow exact special-range exception intended only for a reviewed private target. Fixed
`never` destinations and discovered gateways remain blocked; the fixed set includes both
well-known NAT64 prefixes and no tuple can override them. A tuple can override only the
ordinary private/reserved set.

For `allowlist`, list every exact required name and CNAME target in the role-specific
`EGRESS_ALLOW_DNS_NAMES` value; the complete policy, including non-literal DB/broker
names, is capped at 66 unique names. Workload Docker-DNS traffic is redirected to a
loopback-only zero-capability UID-`10021` parser. It can send only an immutable name index
and A/AAAA selector to a distinct zero-capability UID-`10022` forwarder, which alone can
construct a canonical query and reach Docker DNS. Direct external TCP/UDP 53 is blocked.
`deny` accepts only internal peer names; public mode uses ordinary DNS and requires an
empty exact-name list.

DNS approval and an exact IP/port tuple are independent. The resulting allowlist is
transport-level defense in depth, not a resource authorization boundary: another tenant
or resource on the same IP and port remains reachable. Enterprise operations require
dedicated/private endpoints or a resource-aware controlled proxy. Disable or block any
site-specific NAT64 prefix at the host/network boundary and prove it cannot translate a
restricted IPv4 destination.

`BACKUPSHEEP_EGRESS_POLICY_GENERATION=2` is mandatory. For an older stock installation,
review outbound dependencies and run `install.sh` once with `--migrate-egress-policy`.
That explicit migration resets all six roles to `deny`, clears old and new lists, and is
rejected after generation 2 is active. Customized or mixed legacy egress is never
translated automatically; review it and reset every role/list before authorizing the
migration.

Source systems and storage providers must allow the BackupSheep workers' outbound address.
The connection setup UI shows the self-hosted server's detected public IPv4/IPv6 for
allow-listing. Treat that detection as a hint and verify the real egress address.

## TLS reverse proxy

BackupSheep trusts `X-Forwarded-Proto: https` through Django's
`SECURE_PROXY_SSL_HEADER`. With `DJANGO_HTTPS=true`, it also enables Secure session/CSRF
cookies, HTTPS redirects and one-year HSTS with subdomains and preload.

Because of that HSTS scope, confirm that every subdomain is HTTPS-ready before enabling it
on a parent domain.

### Caddy example

```caddyfile
backups.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8000
}
```

### nginx example

```nginx
server {
    listen 80;
    server_name backups.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name backups.example.com;

    ssl_certificate     /etc/letsencrypt/live/backups.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/backups.example.com/privkey.pem;

    client_max_body_size 10m;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

After the certificate and proxy work over HTTPS, update `.env`:

```dotenv
DJANGO_ALLOWED_HOSTS='backups.example.com,localhost,127.0.0.1'
APP_PROTOCOL='https://'
APP_DOMAIN='backups.example.com'
DJANGO_HTTPS=true
```

Then recreate the application services and verify both URLs:

```bash
./backupsheep-compose up --detach --no-build --no-deps --force-recreate \
  app-egress-guard app
curl -fsS http://127.0.0.1:8000/healthz/
curl -fsS https://backups.example.com/healthz/
```

If operations were already enabled, review durable queue/recovery state before recreating
workers and Beat explicitly:

```bash
./backupsheep-compose --profile operations up --detach --no-build --no-deps \
  --force-recreate \
  cloud-egress-guard database-egress-guard files-egress-guard \
  storage-egress-guard logs-egress-guard \
  worker-cloud worker-database worker-files worker-storage worker-logs
./backupsheep-compose --profile operations up --detach --no-build --no-deps beat
```

Long-running core and operations application services use `restart: unless-stopped`;
egress guards use `restart: "no"` and are recreated only with their paired workload. The
installer removes the complete container/network topology with ordinary `down` before any
build or migration while preserving named data/identity volumes. Stop workloads and Beat
explicitly for a provider pause. A daemon-triggered application restart still reruns the
immutable entrypoint and deployment preflight, but cannot restart or attest its
`restart: "no"` guard. After a Docker daemon restart or guard loss, use the paired command
above before returning the role to service.

If `DJANGO_HTTPS=true` is enabled while users still connect over direct HTTP, login can
fail because cookies are Secure and requests redirect to HTTPS.

The Docker preflight treats deployment-check errors as fatal. Warning-level HTTPS findings
can remain during the deliberate loopback HTTP/SSH-tunnel onboarding mode only. They are
not a production waiver: before any public access, use real TLS, configure the complete
HTTPS tuple and review/resolve every deployment warning.

## Host and container hardening

- Apply operating-system and Docker security updates on a planned cadence.
- Run only the required inbound services. Use SSH keys, disable direct root login where
  appropriate and restrict administrative SSH by source network.
- Keep `.env` mode `0600` and `.secrets` mode `0700`; do not commit either, bake them into
  an image or paste their contents into an issue. Installer-managed installation secret
  files are individually mode `0444` beneath the non-traversable parent so the non-root
  container can read only its granted bind mounts. The repository's build context is
  default-deny: only the lock file, entrypoint,
  public sample configuration and runtime Python/template/static source roots are sent to
  the builder. Tests, VCS data, installer/docs and credential-shaped artifacts inside an
  allowed source root are re-excluded.
- Application roles use fixed lane identities: web `10001`, database `10002`, files
  `10003`, storage `10004`, logs `10005`, Beat `10006`, migration/preflight `10007` and
  cloud `10008` (UID and primary GID match). They drop all Linux capabilities, set
  `no-new-privileges`, use Docker's init process, disable core dumps and default to 512
  processes per container. The image clears setuid/setgid bits and its entrypoint refuses
  root or the wrong lane identity. An arbitrary runtime UID is intentionally unsupported;
  preserve the provisioner's exact per-volume owner/group/mode contract.
- Every application-image command passes through that entrypoint. Stock Compose blanks
  dynamic-loader/TLS-key-log variables; the installer rejects them in `.env`; and the
  entrypoint clears shell/Python/loader hooks, fixes executable/import paths and executes
  argv without `eval`. It verifies the runtime boundary and runs `docker_preflight` before
  every web, worker and Beat process, including later automatic restarts. Do not override
  the entrypoint or treat Compose's earlier one-shot result as a permanent attestation.
- PostgreSQL starts directly as fixed UID/GID `70:70`, with all capabilities dropped;
  fresh stock storage is bound to the Alpine/ICU generation witness and legacy Debian
  volumes fail closed. RabbitMQ alone retains a narrow bootstrap capability set to repair its
  named volume before dropping privilege. Both exec a non-root server as PID 1, without
  Docker's root-owned init shim. Verify identity and capabilities after every image change.
- Use narrowly scoped provider credentials. Separate source-discovery/snapshot permissions
  from unrelated account administration whenever the provider supports it.
- Preserve the stock optional-integration credential matrix. The shared environment
  blanks all known families, then web receives setup/OAuth credentials, cloud only
  DigitalOcean/OVH, files only Basecamp, storage only Dropbox/pCloud/Microsoft/Google,
  and logs only Postmark/Mailgun/SES/Slack/Telegram; database, Beat and one-shots receive
  none. The entrypoint refuses misplaced non-empty values. `SENTRY_DSN` remains shared so
  every scrubbed Django/Celery client can submit events; it is not provider authorization.
- Protect PostgreSQL backups and `.secrets/django_secret_key` together. Provider
  credentials are encrypted at rest, but the database and encryption material remain
  sensitive.
- Approve SSH host keys only after out-of-band fingerprint verification. Stock Compose
  stores account-scoped approvals and append-only audit events in PostgreSQL. Each operation
  receives only its exact approved keys in a transient mode-`0600` private-runtime file.
  Optional database/files managed identities use distinct Ed25519 secret files granted only
  to the matching worker lane; the app receives neither private key. Managed identities are
  allowed only in exactly-one-account installations. Multi-account deployments use
  customer-supplied private keys.
- Use token authentication for external API clients and protect tokens as passwords.
  Browser-session API requests use Django CSRF enforcement.
- Browser sessions are HttpOnly, SameSite=Lax, limited to 12 hours, and discarded on
  browser close by default. Direct browser/ZIP download is refused for stock BSE1
  artifacts. The five-minute, maximum-one-hour provider-signature setting applies only
  to explicitly enabled non-enterprise legacy artifacts; if that compatibility mode is
  separately reviewed, treat every URL as a secret and keep it out of logs and tickets.
- Review the repository's `SECURITY.md` and report vulnerabilities privately through a
  GitHub Security Advisory.

### Image trust and writable boundaries

The stock application services use a read-only root filesystem. Static assets are
collected without network access as UID/GID `10001:10001` during the image build and then
made root-owned and read-only with the rest of `/code`. At runtime, writable paths are
role-specific and limited to:

- `/tmp`, a bounded `noexec,nosuid,nodev` tmpfs for libraries and external clients;
- `/run/backupsheep`, a private bounded tmpfs for home, caches and Gunicorn heartbeat
  files;
- `/code/_storage`, backed by a different mode-`0700` private volume in each of database,
  files and storage; no role receives another lane's work volume;
- `/var/lib/backupsheep/transfer/database` and `/files`, source-writable and
  storage-read-only fenced BSE1 handoffs, plus the storage-writable lane-fenced reverse
  `/var/lib/backupsheep/restore-transfer`;
- `/run/backupsheep/ssh`, private tmpfs populated only in database/files workers with that
  lane's validated managed identity and exact per-operation trust material; and
- `/backups`, read/write only in the storage worker; app, cloud, database, files, logs and
  Beat receive no Local Storage mount.

The app enqueues `reset_incremental_cache` because it has no work mount. That task takes
the same per-node incremental lock as archive/mirror work and uses directory-FD-confined,
no-follow deletion beneath the expected node cache in the files lane. Files run-log
pruning runs in that same private lane; database run-log pruning runs separately in the
database lane, and destination-upload run-log pruning runs in the storage lane. The
externally connected log/notification worker has no staging mount;
request-side code persists a log row and, only after commit, queues its opaque integer ID
so Slack/Telegram I/O remains in the logs role. Custom overrides must preserve these
routing and access boundaries.

Do not mount a tmpfs over `/code/static`; doing so hides the assets embedded in the image.
When running the image without the stock Compose file, reproduce both tmpfs mounts and the
fixed UID/GID exactly. The entrypoint fails closed when `/run/backupsheep` is missing,
symlinked, owned by another identity or not writable.

Python dependencies are resolved from `requirements.lock` in hash-checking mode. Source
distributions are authenticated before build; the builder then creates a second lock over
the exact platform-specific wheels, and the final stage installs that wheelhouse offline
with `--require-hashes`. A changed or incomplete lock fails the build.

Every locally built service family—application, database and egress guard—sets
`pull_policy: never`. Manual deployments must
run `./backupsheep-compose build db app app-egress-guard` at the exact reviewed commit
before `up`; Compose fails instead of pulling a same-named registry image when any reviewed
local build is absent. The verified installer performs the explicit builds automatically.

### Remaining image and bootstrap gates

This release improves secure defaults but is not a claim of full build reproducibility or
complete container isolation:

- A read-only application root limits persistence after application compromise; it does not
  isolate a compromised Docker daemon or host kernel. Required backup clients and provider
  SDKs intentionally retain outbound/network and archive/database parsing capabilities.
  Continue provider and crash-path acceptance against the exact released image.
- The installer is intentionally not a host provisioner: it requires operator-managed Git,
  Docker Engine 28.0.0+ and Compose 2.33.1+, changes no package/service/daemon/firewall or
  kernel setting, verifies an exact immutable commit, refuses root/sudo, and runs as the
  already Docker-authorized unprivileged user. The bundled cloud-init compatibility file is inert. Enterprise
  automation should separately authenticate release provenance and provide the host
  security boundary through reviewed infrastructure code.
- Queue routing is not treated as authorization. The stock model requires per-lane
  RabbitMQ credentials/queue ACLs plus lane-bound signed task envelopes and replay
  tracking. Keep these controls synchronized during upgrades; a shared broker principal,
  broadened ACL, generic worker or unsigned compatibility path would reopen cross-lane
  command relay.
- Python source artifacts and the resulting wheelhouse are hash-locked, but locally built
  wheels and signed APT repository snapshots are not guaranteed to be byte-for-byte
  reproducible across build dates. The application, PostgreSQL and RabbitMQ images are
  rooted in digest-pinned upstream images; runtime Debian packages are exact-version
  selected from signed indexes; and the MySQL client archive is verified with Oracle's
  fingerprint-pinned release key.
  Complete the [dependency reproducibility gate](dependency-security.md) before describing
  the resulting image as reproducible.

## Persistent data and capacity

| Volume | Purpose | Capacity concern |
| --- | --- | --- |
| `pgdata` | Accounts, encrypted credentials, schedules, backup/restore rows, durable execution and activity state | Database growth, transaction health and recovery |
| `rabbitmq_data` | Durable queue messages | Queue backlog and broker disk alarms |
| `database_workdir` | Private database dumps/restores and database run logs | Largest database operation plus reserve |
| `files_workdir` | Private file-source work, website incremental caches and files run logs | Largest full website tree/archive plus persistent caches and reserve |
| `storage_workdir` | Private BSE1 upload/download materialization | Concurrent upload/restore ciphertext plus reserve |
| Database/files/restore transfer volumes | Fenced BSE1 inter-lane handoffs | Concurrent published envelopes, restore handoffs, bytes and inodes |
| `backup_storage` | Storage-only Local Storage BSE1 archives | All retained archives assigned to that destination |

Database and file backups materialize locally before upload. A full website backup can
need the downloaded tree plus its archive. Incremental website mode keeps a per-node cache
between runs. Restore materialization also needs local space; archive member, expansion
ratio, uncompressed-byte and free-space limits are configurable safety controls.

Monitor the filesystem that actually backs each volume, not just the container's overlay
filesystem. Avoid `docker system prune --volumes`: named volumes contain production data.

## Worker sizing and scaling

The default worker concurrency is cloud `4`, database/files `1`, and storage/logs `2`.
Provider API work is primarily I/O-bound; database and file workers consume CPU, memory
and disk. Start conservatively, observe real jobs, then adjust the Compose commands.

On one host, replicas of a lane share only that lane's private volume; source-to-storage
bytes cross only through the fenced BSE1 transfer volumes. Scale only after measuring the
lane's locks, capacity and provider behavior. For example:

```bash
./backupsheep-compose --profile operations up --detach --no-build --no-deps \
  --force-recreate --scale worker-storage=4 \
  storage-egress-guard worker-storage
```

That operation force-recreates the storage namespace pair; drain or reconcile active
storage work before changing the replica count.

Stock Compose is single-host. A separately reviewed multi-host orchestrator must preserve
three private work stores, two source-specific one-way ciphertext transfers, the reverse
lane-fenced restore transfer, lane-specific secret delivery, the PostgreSQL approval
ledger and storage-only Local Storage. Do not replace that topology with one shared
plaintext work filesystem. The repository does not ship a multi-host orchestrator
manifest; validate access, failure and fencing behavior before using such a topology.

Run one Beat service for ordinary maintenance cadence. Scheduled backup occurrences use a
transactional claim, but a singleton scheduler avoids duplicated maintenance dispatch and
unnecessary load.

## Storage protection

Do not make the BackupSheep host the only copy of its own archives. Use multiple independent
destinations where the recovery objective requires it.

Amazon S3 destinations can configure Object Lock, a designated compliance-mode
air-gapped copy, prefix-scoped lifecycle transitions and operator-supplied cost rates.
Those controls use Amazon S3 APIs and guarantees; an S3-compatible endpoint must not be
assumed to provide equivalent immutability.

An Object Lock retention period or legal hold can defer deletion beyond a schedule's
keep-last policy. BackupSheep preserves the catalog entry instead of pretending the locked
version was removed.

## Production acceptance

Do not equate a successful build, migration, health request or provider validation with
recoverability. Before declaring a source protected:

1. run an on-demand backup;
2. confirm the durable execution reaches a terminal success and every intended storage
   copy is complete/verified;
3. restore into a new or disposable target;
4. verify application data, not only provider job status;
5. document the timestamp, source, backup identity, target and verification result;
6. repeat on the cadence defined by the recovery policy.

Use [Observability](observability.md), [Operations](operations.md) and
[Disaster recovery](disaster-recovery.md) as the production runbook set.
