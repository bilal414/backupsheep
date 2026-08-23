# Production deployment

The bundled web service is Gunicorn on plain HTTP port `8000`. A production operator is
responsible for TLS termination, network policy, host maintenance, secrets, capacity,
monitoring and recovery.

## Production checklist

Before making an instance reachable from the internet:

- [ ] use a reviewed release branch/tag or pinned commit;
- [ ] set `BACKUPSHEEP_IMAGE` to the exact reviewed release/revision tag so migration,
      web, workers and Beat cannot drift;
- [ ] replace the sample `DJANGO_SECRET_KEY` and keep the new value stable;
- [ ] set a strong PostgreSQL password before initializing the database volume;
- [ ] keep `DJANGO_DEBUG=false`;
- [ ] set `DJANGO_ALLOWED_HOSTS` to explicit public hosts, never `*`;
- [ ] terminate TLS at a trusted reverse proxy and set `DJANGO_HTTPS=true` only after it
      forwards `X-Forwarded-Proto: https`;
- [ ] set `APP_PROTOCOL=https://` and `APP_DOMAIN` to the real public host;
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
                              -> private Compose network -> PostgreSQL
                                                         -> RabbitMQ
                                                         -> workers / Beat
```

Do not publish the `db` or `rabbitmq` ports. Stock Compose binds app port `8000` to host
loopback; keep `BACKUPSHEEP_BIND_ADDRESS=127.0.0.1` and keep the host/cloud firewall closed
to that port from untrusted networks. If the proxy is another container, connect it to an
explicit reviewed network and avoid a public app-port mapping entirely.

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
docker compose up --detach --remove-orphans
curl -fsS http://127.0.0.1:8000/healthz/
curl -fsS https://backups.example.com/healthz/
```

If `DJANGO_HTTPS=true` is enabled while users still connect over direct HTTP, login can
fail because cookies are Secure and requests redirect to HTTPS.

## Host and container hardening

- Apply operating-system and Docker security updates on a planned cadence.
- Run only the required inbound services. Use SSH keys, disable direct root login where
  appropriate and restrict administrative SSH by source network.
- Keep `.env` mode `0600`; do not commit it, bake it into an image or paste it into an
  issue. The repository's `.dockerignore` excludes `.env`, local environments, VCS data,
  `_storage` and other runtime material from the image build context.
- Application roles run as fixed UID/GID `10001:10001`, drop all Linux capabilities,
  set `no-new-privileges`, use Docker's init process, and default to 512 processes per
  container. Keep bind mounts and shared filesystems writable by that identity.
- Use narrowly scoped provider credentials. Separate source-discovery/snapshot permissions
  from unrelated account administration whenever the provider supports it.
- Protect PostgreSQL backups and `DJANGO_SECRET_KEY` together. Provider credentials are
  encrypted at rest, but the database and encryption material remain sensitive.
- Populate SSH host keys only after out-of-band fingerprint verification. Keep optional
  managed private keys on the shared work volume with mode `0600`.
- Use token authentication for external API clients and protect tokens as passwords.
  Browser-session API requests use Django CSRF enforcement.
- Review the repository's `SECURITY.md` and report vulnerabilities privately through a
  GitHub Security Advisory.

### Remaining image and bootstrap gates

This release improves secure defaults but is not a claim of full build reproducibility or
complete container isolation:

- The application image runs as non-root, but its root filesystem is not read-only.
  Collectstatic, provider SDKs, database clients and large backup/restore tools have varied
  temporary-file behavior; a read-only-root migration needs full provider and crash-path
  acceptance with explicit writable mounts/tmpfs first.
- Stock Compose bounds process counts but does not impose a universal memory or CPU quota.
  Large database dumps, archive compression and restore verification legitimately vary by
  workload; set measured per-role limits in a reviewed deployment override.
- The generic cloud-init example still downloads the installer from mutable `main`, and the
  installer clones a branch/tag rather than verifying a signed release commit. Enterprise
  automation should mirror an approved installer, verify its SHA-256 or signature before
  root execution, and install an approved immutable Git revision/image digest.
- OS packages and Python transitive packages are not fully hash-locked. The image base,
  PostgreSQL and RabbitMQ images are digest-pinned; the MariaDB repository bootstrap is
  checksum-pinned; the MySQL client archive is verified with Oracle's fingerprint-pinned
  release key. Complete the [dependency reproducibility gate](dependency-security.md)
  before describing the resulting image as reproducible.

## Persistent data and capacity

| Volume | Purpose | Capacity concern |
| --- | --- | --- |
| `pgdata` | Accounts, encrypted credentials, schedules, backup/restore rows, durable execution and activity state | Database growth, transaction health and recovery |
| `rabbitmq_data` | Durable queue messages | Queue backlog and broker disk alarms |
| `backup_workdir` | Active dumps, restore work/logs, website incremental cache, SSH trust/key material | Largest concurrent jobs plus caches and reserve |
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
docker compose up --detach --scale worker-storage=4
```

Across multiple hosts, all processes that touch work files need a shared, correctly
locked network filesystem. They also need consistent `.env`, SSH trust/key material and
Local Storage mounts. The repository does not ship a multi-host orchestrator manifest;
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
