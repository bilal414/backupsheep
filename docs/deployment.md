# Production deployment

The bundled stack runs the web app as plain HTTP gunicorn bound to host loopback on port
8000. For an
internet-facing install you must put TLS in front of it and harden the configuration.

## Hardening checklist

Before exposing the instance:

- [ ] **`.secrets/django_secret_key`** — a long random value, not the
      `change-this-key` placeholder, and kept **stable** (rotating it invalidates all
      sessions and makes stored email credentials undecryptable). Keep the direct stock
      `.env` key blank.
- [ ] **`DJANGO_DEBUG=false`** (the default). Never run a public instance with debug on.
- [ ] **`DJANGO_ALLOWED_HOSTS`** — your real hostname(s), not `*`. Comma-separated list ok.
- [ ] **`DJANGO_HTTPS=true`** — once you're serving over TLS (see below). This turns on
      Secure session/CSRF cookies, HSTS, and the HTTP→HTTPS redirect.
- [ ] **`APP_PROTOCOL=https://`** and **`APP_DOMAIN`** set to your public host (these build
      `APP_URL` and `CSRF_TRUSTED_ORIGINS`, and OAuth redirect URIs).
- [ ] Preserve the installer's distinct **database and RabbitMQ bootstrap/lane secret
      files**; never collapse them into one credential or publish either service port.
      Keep direct stock `.env` password keys blank.
- [ ] Configure the required BSE1 AWS KMS key/allowlist and two distinct lane credential
      files. Prove both allowed-lane and denied-cross-lane KMS calls before operations.
- [ ] Preserve the stock integration-credential lane matrix: web receives all families
      needed for setup/OAuth callbacks; cloud only DigitalOcean/OVH; files only Basecamp;
      storage only Dropbox/pCloud/Microsoft/Google; logs only
      Postmark/Mailgun/SES/Slack/Telegram; database, Beat and one-shots receive none. Do
      not defeat the blank-first environment or entrypoint enforcement with overrides.
- [ ] Keep **`BACKUPSHEEP_BIND_ADDRESS=127.0.0.1`** unless an equivalent private network
      boundary has been explicitly reviewed.
- [ ] For an existing RabbitMQ 3.13 volume, complete the documented
      [3.13 -> 4.2 -> 4.3 migration gate](guides/rabbitmq-upgrade.md) before starting the
      pinned 4.3 image.
- [ ] Review [SECURITY.md](../SECURITY.md) for the browser-session/API CSRF note.

## TLS via a reverse proxy

Terminate HTTPS at a proxy in front of the `app` service and forward `X-Forwarded-Proto`.
BackupSheep already sets `SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")`,
so with `DJANGO_HTTPS=true` it will correctly detect HTTPS behind the proxy.

**Caddy** (automatic certificates):

```
backup.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

**nginx** (sketch):

```nginx
server {
    listen 443 ssl;
    server_name backup.example.com;
    # ssl_certificate / ssl_certificate_key ...

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;   # large backups can run long
    }
}
server { listen 80; server_name backup.example.com; return 301 https://$host$request_uri; }
```

Then set `DJANGO_HTTPS=true`, `APP_PROTOCOL=https://`, `APP_DOMAIN=backup.example.com`,
add `backup.example.com` to `DJANGO_ALLOWED_HOSTS`, and force-recreate the existing web
pair with `./backupsheep-compose up --detach --no-build --no-deps --force-recreate
app-egress-guard app`. If operations were already authorized, review queue/recovery state
before recreating all five exact guard/worker pairs and starting Beat separately as shown
in the [egress lifecycle contract](../deploy/egress/README.md#paired-lifecycle-commands).

Long-running core application services, provider workers and Beat use
`restart: unless-stopped`; namespace guards use `restart: "no"`. The wrapper refuses an
independent guard lifecycle command and requires a workload/guard pair to be recreated
together. Before an installer build or migration, `install.sh` removes the complete
container/network topology with ordinary `down` while preserving named volumes; an
operations-only pause explicitly stops workers and Beat and leaves no-secret guards in place.
The installer and wrapper also share an owner-only per-install mutation lock, so parallel
terminals cannot race their guard/one-off inventory; read-only inspection remains concurrent.
Any daemon-triggered application restart still passes through the immutable entrypoint
and reruns deployment preflight, but it cannot restart a guard or prove that the workload
joined the guard's current namespace. After a Docker daemon restart, use the exact paired
recovery command before returning that role to service.

> If you set `DJANGO_HTTPS=true` but serve plain HTTP directly (no TLS), Secure cookies
> will prevent login and the SSL redirect will loop. Only enable it behind real TLS.

Warning-level HTTPS findings from Django's deployment check are expected only while the
service is deliberately bound to loopback and reached through an SSH tunnel. Before any
public exposure, configure the complete HTTPS tuple above and review/resolve every
deployment warning; an error-level preflight pass is not approval for public HTTP.

## Resource & disk planning

Named volumes in the Compose stack:

| Volume | Mounted at | Holds |
|--------|-----------|-------|
| `postgres_data_v1` | `/var/lib/postgresql` (db) | Active PostgreSQL 18.6 Alpine/ICU database bound to its installation/storage witness |
| retired `pgdata` | not mounted | Detached Debian/UID-999 rollback evidence after the explicit logical migration |
| `rabbitmq_data` | `/var/lib/rabbitmq` (RabbitMQ) | Broker metadata and durable queued messages |
| `database_workdir` | `/code/_storage` in `worker-database` only | Private plaintext database dump/restore work and database run logs |
| `files_workdir` | `/code/_storage` in `worker-files` only | Private website/WordPress/Basecamp work, incremental cache and files-lane run logs |
| `storage_workdir` | `/code/_storage` in `worker-storage` only | Private BSE1 materialization, provider transfer work and destination-upload run logs |
| `database_ciphertext_transfer` | `/var/lib/backupsheep/transfer/database` | Database writes a fenced BSE1 handoff; storage receives it read-only |
| `files_ciphertext_transfer` | `/var/lib/backupsheep/transfer/files` | Files writes a fenced BSE1 handoff; storage receives it read-only |
| `restore_ciphertext_transfer` | `/var/lib/backupsheep/restore-transfer` | Storage writes a fenced BSE1 restore handoff; database/files receive only their read-only lane |
| `backup_workdir` | `/volumes/legacy-work` in `staging-provision` only | Legacy shared-volume emptiness evidence; never mounted in a runtime role |
| `staging_layout_witness` | `/var/lib/backupsheep-staging` in `staging-provision` only | Installation-bound v3 layout witness |
| `backup_storage` | `/backups` in `worker-storage` only | BSE1 archives for the **Local Storage** destination; no other runtime role receives the mount |
| `installation_identity` | `/run/backupsheep-installation` (app, read-only) | Empty labeled ownership sentinel; no application or secret data |

Database and website backups are created as plaintext only inside their source lane's
private work volume. The source seals a BSE1 envelope into its own fenced transfer volume;
storage reads that published ciphertext and materializes only BSE1 bytes in its private
work volume. Restore reverses the handoff through the dedicated restore-transfer volume;
database/files never receive `/backups`. Size every lane and transfer filesystem for its
largest concurrent operation. The `worker-database` / `worker-files` workers are CPU/disk
heavy; isolate or scale them per [scaling.md](scaling.md).

The app requests incremental-cache reset through the files queue because it has no staging
mount. Reset uses the same per-node incremental lock as archive/mirror work and
directory-FD-confined, no-follow deletion. Files, database and destination-upload run-log
pruning execute in their respective files/database/storage private-work lanes; the
externally connected notification/log worker receives no staging mount. Notification
creation persists its database row first and,
after commit, queues only the opaque row ID for Slack/Telegram delivery in the logs role.

SSH host-key approvals and their append-only audit are account-scoped PostgreSQL state.
Database/files workers receive only an operation's exact current approval in a transient
mode-`0600` private-runtime file. Optional database and files Ed25519 private keys are
distinct and each mode-`0444` source is mounted only in its matching worker; the app and
other roles receive neither. Managed-key mode is limited to exactly-one-account installs;
multi-account deployments use customer-supplied private keys.

Queue names alone are not authorization. Stock Compose therefore provisions a separate
RabbitMQ principal and fixed queue ACL for every lane, and requires lane-bound signed task
envelopes with replay tracking. Preserve that exact provisioning and never start a generic
worker with broader queues; durable task-specific execution fences are still required for
late-ack crash recovery.

Each Internet-capable role shares only a network namespace with a no-secret egress guard
and retains a private PID namespace. The guard/workload containers are one lifecycle
unit: the wrapper refuses independent guard lifecycle commands, guard restart policy is
`"no"`, and operators recreate the pair together. The guard permits PostgreSQL and
RabbitMQ only as the current exact interface/address/TCP-port tuples on two distinct
directly connected internal bridges; other bridge peers and ports are denied. It refreshes
the two peer sets after Docker DNS changes and fails blocked on absence or ambiguity.
Health requires a successful renewal newer than the kernel lease, not process liveness
alone. Each workload also proves local web/worker readiness and fresh database/broker TCP
connections through the guard's current peer sets; a stranded namespace therefore fails
health.

Generation-2 stock `deny` mode blocks every outward destination. An Internet-dependent
role deliberately fails until it receives the smallest reviewed exact IPv4 `CIDR:port`
or IPv6 `[CIDR]:port` tuples and exact DNS names needed by its configured providers.
`public` is an explicit compatibility risk opt-in that uses ordinary DNS; exact tuples
are special-range exceptions intended only for narrow reviewed private targets. Fixed
`never` destinations and discovered gateways remain blocked; the fixed set includes both
well-known NAT64 prefixes and no tuple can override them. A tuple can override only the
ordinary private/reserved set.

Strict modes redirect Docker-DNS traffic to a loopback-only zero-capability UID-`10021`
parser, which sends only an immutable allowed-name index plus A/AAAA selector to a
distinct zero-capability UID-`10022` forwarder. Only the forwarder constructs canonical
queries and reaches Docker DNS. The complete policy is capped at 66 unique names,
including non-literal DB/broker names; every CNAME target must be listed. Direct external
TCP/UDP 53 is blocked. DNS and exact IP/port grants are independent and provide
transport-level defense in depth only: a shared tenant/resource on the same IP and port
remains reachable. Enterprise operations require dedicated/private endpoints or a
resource-aware proxy. Site-specific NAT64 remains a host/network control.

If you use the Local Storage destination, size `backup_storage` for your full backup
history (every retained backup of every schedule that targets it), and consider
bind-mounting it to dedicated storage — see
[Configuration → Local Storage](configuration.md#local-storage-backup-destination-optional).

## Back up BackupSheep itself

Your BackupSheep PostgreSQL database holds your connections, schedules, and (encrypted)
credentials. Back it up independently (e.g. `pg_dump` of the `db` volume) and store the
complete `.secrets` directory safely — you need the *same* Django key to decrypt restored
email credentials, matching database/broker credentials to recover the stack, and both
source-lane KMS identities plus live allowlisted keys to restore BSE1 artifacts.

## Email

Configure a transactional-email provider (Postmark/Mailgun/SES) so password resets, team
invites, and backup/restore notifications can be delivered. Without one, recover a lost
admin password with
`./backupsheep-compose run --rm --no-deps app python manage.py changepassword <email>`.
