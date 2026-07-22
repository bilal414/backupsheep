# Production deployment

The bundled stack runs the web app as plain HTTP gunicorn on port 8000. For an
internet-facing install you must put TLS in front of it and harden the configuration.

## Hardening checklist

Before exposing the instance:

- [ ] **`DJANGO_SECRET_KEY`** — a long random value, not the `change-this-key` placeholder,
      and kept **stable** (rotating it invalidates all sessions and makes stored email
      credentials undecryptable).
- [ ] **`DJANGO_DEBUG=false`** (the default). Never run a public instance with debug on.
- [ ] **`DJANGO_ALLOWED_HOSTS`** — your real hostname(s), not `*`. Comma-separated list ok.
- [ ] **`DJANGO_HTTPS=true`** — once you're serving over TLS (see below). This turns on
      Secure session/CSRF cookies, HSTS, and the HTTP→HTTPS redirect.
- [ ] **`APP_PROTOCOL=https://`** and **`APP_DOMAIN`** set to your public host (these build
      `APP_URL` and `CSRF_TRUSTED_ORIGINS`, and OAuth redirect URIs).
- [ ] A strong **`DB_PASSWORD`**, and don't publish the database port.
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
add `backup.example.com` to `DJANGO_ALLOWED_HOSTS`, and `docker compose up -d`.

> If you set `DJANGO_HTTPS=true` but serve plain HTTP directly (no TLS), Secure cookies
> will prevent login and the SSL redirect will loop. Only enable it behind real TLS.

## Resource & disk planning

Named volumes in the Compose stack:

| Volume | Mounted at | Holds |
|--------|-----------|-------|
| `pgdata` | `/var/lib/postgresql` (db) | The PostgreSQL database |
| `backup_workdir` | `/code/_storage` (workers) | In-progress dumps, run logs, website incremental cache |
| `backup_storage` | `/backups` (app + workers) | Backups stored via the **Local Storage** destination |

Database and website backups are dumped to the shared `backup_workdir` volume before
upload. Size the host disk for your largest backup's working copy. The
`worker-database` / `worker-files` workers are CPU/disk heavy; isolate or scale them per
[scaling.md](scaling.md).

If you use the Local Storage destination, size `backup_storage` for your full backup
history (every retained backup of every schedule that targets it), and consider
bind-mounting it to dedicated storage — see
[Configuration → Local Storage](configuration.md#local-storage-backup-destination-optional).

## Back up BackupSheep itself

Your BackupSheep PostgreSQL database holds your connections, schedules, and (encrypted)
credentials. Back it up independently (e.g. `pg_dump` of the `db` volume) and store
`DJANGO_SECRET_KEY` safely — you need the *same* secret key to decrypt restored email
credentials.

## Email

Configure a transactional-email provider (Postmark/Mailgun/SES) so password resets and
failure notifications can be delivered. Without one, recover a lost admin password with
`docker compose run --rm app python manage.py changepassword <email>`.
