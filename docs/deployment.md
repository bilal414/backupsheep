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
- [ ] A strong **`.secrets/db_password`**, and don't publish the database port.
- [ ] A separate strong **`.secrets/rabbitmq_password`** for the dedicated `backupsheep`
      user/vhost. Keep both direct stock `.env` keys blank.
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
add `backup.example.com` to `DJANGO_ALLOWED_HOSTS`, and run `./backupsheep-compose up -d` for the
core. If operations were already authorized, review queue/recovery state before separately
running `./backupsheep-compose --profile operations up -d`.

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
| `pgdata` | `/var/lib/postgresql` (db) | The PostgreSQL database |
| `rabbitmq_data` | `/var/lib/rabbitmq` (RabbitMQ) | Broker metadata and durable queued messages |
| `backup_workdir` | `/code/_storage` | Read/write in database/files/storage workers; absent from app/cloud/logs/Beat. Holds staged dumps, run logs and website/database incremental caches |
| `ssh_trust` | `/var/lib/backupsheep/ssh-trust` | Reviewed `known_hosts`; read/write in app, read-only in database/files, absent elsewhere |
| `backup_storage` | `/backups` | Read/write in storage; read-only in app/cloud/database/files; absent from logs/Beat. Holds **Local Storage** archives |
| `installation_identity` | `/run/backupsheep-installation` (app, read-only) | Empty labeled ownership sentinel; no application or secret data |

Database and website backups are dumped to the shared `backup_workdir` volume before
upload. Size the host disk for your largest backup's working copy. The
`worker-database` / `worker-files` workers are CPU/disk heavy; isolate or scale them per
[scaling.md](scaling.md).

The app requests incremental-cache reset through the storage queue because it has no
staging mount. Reset uses the same per-node incremental lock as archive/mirror work and
directory-FD-confined, no-follow deletion. On-disk log pruning is also routed to storage;
the externally connected notification/log worker receives no staging mount. Notification
creation persists its database row first and, after commit, queues only the opaque row ID
for Slack/Telegram delivery in the logs role.

The optional `.secrets/ssh_managed_private_key` source is mounted mode `0444` only in
app/database/files. Empty disables it. The entrypoint validates a non-empty unencrypted
key (maximum 64 KiB), copies it into private tmpfs at
`/run/backupsheep/ssh/managed_private_key` with mode `0600`, and exports that runtime path.
Do not point SSH directly at `/run/secrets/ssh_managed_private_key`.

Queue separation is not broker authorization. Stock application roles share a RabbitMQ
principal/vhost, so a compromised connected role can relay a task or command to another
role's queue. Treat this as a High residual risk and keep the broker private until
per-role publish/consume controls or authenticated task envelopes are implemented.

If you use the Local Storage destination, size `backup_storage` for your full backup
history (every retained backup of every schedule that targets it), and consider
bind-mounting it to dedicated storage — see
[Configuration → Local Storage](configuration.md#local-storage-backup-destination-optional).

## Back up BackupSheep itself

Your BackupSheep PostgreSQL database holds your connections, schedules, and (encrypted)
credentials. Back it up independently (e.g. `pg_dump` of the `db` volume) and store the
complete `.secrets` directory safely — you need the *same* Django key to decrypt restored
email credentials and the matching database/broker credentials to recover the stack.

## Email

Configure a transactional-email provider (Postmark/Mailgun/SES) so password resets, team
invites, and backup/restore notifications can be delivered. Without one, recover a lost
admin password with
`./backupsheep-compose run --rm app python manage.py changepassword <email>`.
