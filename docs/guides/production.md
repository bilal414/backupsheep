# Production deployment

The bundled web service is Gunicorn on plain HTTP port `8000`. A production operator is
responsible for TLS termination, network policy, host maintenance, secrets, capacity,
monitoring and recovery.

## Production checklist

Before making an instance reachable from the internet:

- [ ] install an exact reviewed 40-character commit (the verified installer rejects
      branches, tags and abbreviations);
- [ ] set `BACKUPSHEEP_IMAGE` to the local tag derived from that exact commit so migration,
      web, workers and Beat cannot drift;
- [ ] create/verify the protected `.secrets` files and keep
      `.secrets/django_secret_key` stable;
- [ ] preserve the installer-generated 64-hex `BACKUPSHEEP_INSTALLATION_ID` and verify the
      labeled empty ownership sentinel before reusing a Compose project name;
- [ ] resolve every exact-name Docker network/volume collision; the installer must refuse
      an unlabeled or foreign object rather than adopting it;
- [ ] set a strong `.secrets/db_password` before initializing the database volume;
- [ ] set an independent strong `.secrets/rabbitmq_password` for the dedicated broker
      user/vhost;
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
- [ ] put Local Storage and the work directory on capacity-monitored durable storage;
- [ ] configure transactional email or document host-level password recovery;
- [ ] back up and restore-test the BackupSheep database, configuration and local archives;
- [ ] run a disposable backup and restore rehearsal for every provider you will rely on.

## Network layout

The stock Compose file publishes only `app`:

```text
Internet -> TLS reverse proxy -> app:8000
                              -> role-specific internal bridges -> PostgreSQL
                                                                -> RabbitMQ
                                                                -> workers / Beat
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
./backupsheep-compose up --detach
curl -fsS http://127.0.0.1:8000/healthz/
curl -fsS https://backups.example.com/healthz/
```

If operations were already enabled, review durable queue/recovery state before recreating
workers and Beat explicitly with `./backupsheep-compose --profile operations up --detach`.

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
- Application roles run as fixed UID/GID `10001:10001`, drop all Linux capabilities,
  set `no-new-privileges`, use Docker's init process, disable core dumps and default to
  512 processes per container. The image clears setuid/setgid bits and its entrypoint
  refuses a root or unexpected identity. Where a role requires write access, make the
  bind mount/shared filesystem writable by `10001:10001`; preserve read-only mounts for
  every other role. An arbitrary runtime UID is intentionally not supported.
- Every application-image command passes through that entrypoint. Stock Compose blanks
  dynamic-loader/TLS-key-log variables; the installer rejects them in `.env`; and the
  entrypoint clears shell/Python/loader hooks, fixes executable/import paths and executes
  argv without `eval`. It verifies the runtime boundary and runs `docker_preflight` before
  every web, worker and Beat process, including later automatic restarts. Do not override
  the entrypoint or treat Compose's earlier one-shot result as a permanent attestation.
- PostgreSQL and RabbitMQ use reviewed vendor entrypoints with a narrow bootstrap
  capability set to repair named-volume ownership. Each then drops privilege and execs
  its non-root server as PID 1, without Docker's root-owned init shim. Verify effective
  PID 1 identity and capabilities whenever a pinned vendor image changes.
- Use narrowly scoped provider credentials. Separate source-discovery/snapshot permissions
  from unrelated account administration whenever the provider supports it.
- Protect PostgreSQL backups and `.secrets/django_secret_key` together. Provider
  credentials are encrypted at rest, but the database and encryption material remain
  sensitive.
- Populate SSH host keys only after out-of-band fingerprint verification. Stock Compose
  keeps them in the dedicated `ssh_trust` volume: app read/write, database/files read-only.
  Put an optional unencrypted managed private key in
  `.secrets/ssh_managed_private_key`, mode `0444`, or leave that file empty to disable it.
  The entrypoint validates a non-empty regular key (maximum 64 KiB), copies it into private
  tmpfs at `/run/backupsheep/ssh/managed_private_key` with mode `0600`, and exports that
  runtime path. Never point SSH directly at the mode-`0444` source mount.
- Use token authentication for external API clients and protect tokens as passwords.
  Browser-session API requests use Django CSRF enforcement.
- Browser sessions are HttpOnly, SameSite=Lax, limited to 12 hours, and discarded on
  browser close by default. BackupSheep-generated provider signatures default to five
  minutes and cannot be configured above one hour; generate them only when the user is
  ready to download and avoid putting them in logs or tickets. Provider-issued temporary
  links whose APIs expose no lifetime control retain that provider's documented lifetime.
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
- `/code/_storage`, read/write only in database, files and storage workers; app, cloud,
  logs and Beat receive no staging mount;
- `/var/lib/backupsheep/ssh-trust`, read/write only in app and read-only in database/files;
- `/run/backupsheep/ssh`, private tmpfs populated only in app/database/files when the
  optional managed-key source is non-empty and valid; and
- `/backups`, read/write only in the storage worker and read-only in app, cloud, database
  and files workers; logs and Beat receive no Local Storage mount.

The app enqueues `reset_incremental_cache` because it has no work mount. That task takes
the same per-node incremental lock as archive/mirror work and uses directory-FD-confined,
no-follow deletion beneath the expected node cache. It and on-disk `delete_old_logs` run
in the storage queue. The externally connected log/notification worker has no staging
mount; request-side code persists a log row and, only after commit, queues its opaque
integer ID so Slack/Telegram I/O remains in the logs role. Custom overrides must preserve
these routing and access boundaries.

Do not mount a tmpfs over `/code/static`; doing so hides the assets embedded in the image.
When running the image without the stock Compose file, reproduce both tmpfs mounts and the
fixed UID/GID exactly. The entrypoint fails closed when `/run/backupsheep` is missing,
symlinked, owned by another identity or not writable.

Python dependencies are resolved from `requirements.lock` in hash-checking mode. Source
distributions are authenticated before build; the builder then creates a second lock over
the exact platform-specific wheels, and the final stage installs that wheelhouse offline
with `--require-hashes`. A changed or incomplete lock fails the build.

Every application role and the database set `pull_policy: never`. Manual deployments must
run `./backupsheep-compose build db app` at the exact reviewed commit before `up`; Compose
fails instead of pulling a same-named registry image when either local build is absent.
The verified installer performs both explicit builds automatically.

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
- **High residual risk:** application roles share one RabbitMQ principal/vhost. Queue
  routing and filesystem grants are not authorization; a compromised broker-connected
  role can relay a task or command to a more privileged role's queue. Until per-role
  broker ACLs or authenticated task envelopes exist, isolate the stack, restrict broker
  access and treat this cross-role command-relay path as High.
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
| `backup_workdir` | Active dumps, restore work/logs and website/database incremental caches | Largest concurrent jobs plus caches and reserve |
| `ssh_trust` | Reviewed SSH `known_hosts` shared with database/files readers | Integrity, backup and out-of-band fingerprint review |
| `backup_storage` | Local Storage archives | All retained archives assigned to that destination |

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

On one host, disk-touching workers share `backup_workdir` and can be scaled with Compose.
For example:

```bash
./backupsheep-compose --profile operations up --detach --scale worker-storage=4
```

Across multiple hosts, all processes that touch work files need a shared, correctly
locked network filesystem. They also need consistent `.env`, an explicitly managed trust
store, secure per-host managed-key delivery and Local Storage mounts. The repository does
not ship a multi-host orchestrator manifest;
validate failure and fencing behavior in the target filesystem/orchestrator before using
that topology.

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
