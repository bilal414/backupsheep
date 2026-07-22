# Configuration reference

All configuration is read from environment variables at boot — in the Docker stack, from
the `.env` file (`env_file: .env`). Copy `.env_sample` to `.env` and edit it.

**How keys are read.** Most keys are read directly (the key must *exist* in `.env`, though
its value may be empty); a few have built-in defaults and are fully optional. The simplest
rule: **copy `.env_sample` wholesale and don't delete lines** — leave optional ones blank.
Only `DJANGO_SECRET_KEY` and the `DB_*` connection values need real values to boot.

> Booleans (`DJANGO_DEBUG`, `DJANGO_HTTPS`) are parsed leniently: `true/1/yes/on` ⇒ on,
> anything else ⇒ off.

## Core / Django

| Variable | Required | Default | Purpose |
|----------|:--------:|---------|---------|
| `DJANGO_SECRET_KEY` | ✅ | `change-this-key` (placeholder — **must change**) | Cryptographic signing key; also derives the key that encrypts stored email credentials. Use a long random value and keep it **stable**. |
| `DJANGO_DEBUG` | ✅ | `false` | Django debug mode. **Keep false in production** (debug leaks tracebacks/settings on errors). |
| `DJANGO_ALLOWED_HOSTS` | ✅ | `*` | Allowed Host header(s). Use your real hostname in production; comma-separated list supported. |
| `DJANGO_HTTPS` | optional | `false` | Set `true` when served over TLS to enable Secure cookies, HSTS, and HTTP→HTTPS redirect. See [deployment](deployment.md). |
| `DJANGO_SERVER` | ✅ | `prod` | Environment label, sent to Sentry as the environment tag. |
| `DJANGO_SETTINGS_MODULE` | ✅ | `backupsheep.settings` | Django settings module path. |
| `APP_NAME` | ✅ | `BackupSheep` | Display name (can also be set in the wizard). |
| `APP_DOMAIN` | ✅ | `localhost:8000` | Public host (`host[:port]`); used for `APP_URL` and CSRF trusted origins. |
| `APP_PROTOCOL` | ✅ | `http://` | URL scheme (`http://` or `https://`), combined with `APP_DOMAIN`. |
| `SENTRY_DSN` | optional | empty | Sentry DSN for error/performance monitoring. Leave blank to disable. |
| `BACKUPSHEEP_SECRETS` | optional | unset | Advanced: if set, its JSON value is used as the entire config instead of `.env` (for secret-manager deployments). |

## Database (PostgreSQL)

| Variable | Required | Compose value | Purpose |
|----------|:--------:|---------------|---------|
| `DB_NAME` | ✅ | `backupsheep` | Database name (the `db` service also reads it as `POSTGRES_DB`). |
| `DB_USER` | ✅ | `backupsheep` | Username (`POSTGRES_USER`). |
| `DB_PASSWORD` | ✅ | *(you set it)* | Password (`POSTGRES_PASSWORD`). |
| `DB_HOST` | ✅ | `db` | Host — the Compose service name. |
| `DB_PORT` | ✅ | `5432` | Port. |

## Task queue (Celery / Redis)

| Variable | Required | Default | Purpose |
|----------|:--------:|---------|---------|
| `CELERY_BROKER_URL` | optional | `redis://localhost:6379/0` | Redis broker URL. In the Compose stack set `redis://redis:6379/0`. |
| `LOG_RETENTION_DAYS` | optional | `30` | Days to keep backup run logs on local disk before `delete_old_logs` prunes them. |

## Transactional email

Pick one provider (or none). The wizard can set this per-install; `.env` is the fallback.

| Variable | Purpose |
|----------|---------|
| `EMAIL_PROVIDER` | Default provider: `postmark`, `mailgun`, or `ses`. |
| `POSTMARK_API_KEY`, `POSTMARK_EMAIL`, `POSTMARK_DOMAIN`, `POSTMARK_API_URL` | Postmark settings (`API_URL` defaults to the public host). |
| `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, `MAILGUN_EMAIL`, `MAILGUN_API_URL` | Mailgun settings. |
| `SES_ACCESS_KEY_ID`, `SES_SECRET_ACCESS_KEY`, `SES_REGION_NAME`, `SES_REGION_ENDPOINT` | Amazon SES settings. |

> Without a configured provider, password-reset emails won't send — recover with
> `manage.py changepassword`. See [Troubleshooting](troubleshooting.md).

## Application-log storage (optional)

An S3-compatible bucket BackupSheep can use for application logs etc. (tested with AWS S3
and Cloudflare R2). Optional; backup *run* logs are kept on local disk regardless.

`S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_STORAGE_BUCKET_NAME`, `S3_ENDPOINT_URL`,
`S3_SIGNATURE_VERSION` (`s3v4`).

## Local Storage backup destination (optional)

The **Local Storage** provider keeps backup zips as plain files on this server (no
external bucket). It needs no credentials — only the root directory the files live under.

| Variable | Required | Default | Purpose |
|----------|:--------:|---------|---------|
| `BS_LOCAL_STORAGE_PATH` | optional | `/backups` | Root directory for 'Local Storage' backups. In the Compose stack `/backups` is the `backup_storage` volume, mounted into `app` and the workers. |

To keep backups on a bigger disk or an NFS share, either point
`BS_LOCAL_STORAGE_PATH` at that mount, or bind-mount over `/backups` via
`docker-compose.override.yml`:

```yaml
volumes:
  backup_storage:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /mnt/storage/backupsheep
```

Each Local Storage destination can optionally scope itself to a subdirectory of this
root (the *Path* field in the UI).

## Storage-provider OAuth (only for the providers you use)

Object-storage providers (S3, B2, Wasabi, R2, Spaces, …) need **no** environment config —
you enter their keys in the UI. OAuth-based destinations need an app registered with the
provider and its credentials here:

| Provider | Variables |
|----------|-----------|
| Dropbox | `DROPBOX_APP_KEY`, `DROPBOX_APP_SECRET` |
| Google Drive | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` |
| OneDrive | `MS_CLIENT_ID`, `MS_CLIENT_SECRET_VALUE`, `MS_TENANT_ID`, `MS_OBJECT_ID`, `MS_APPLICATION_ID`, `MS_CLIENT_SECRET_ID` (+ the `MS_OAUTH_*`/`MS_SCOPE`/`MS_GRAPH_ENDPOINT` defaults) |
| pCloud | `PCLOUD_CLIENT_ID`, `PCLOUD_CLIENT_SECRET` (auth/token URLs default to pCloud's public hosts) |

## Backup-source provider endpoints & OAuth (optional)

Cloud-snapshot providers work out of the box with token/key credentials entered in the UI;
these env vars only override the public API hosts or enable OAuth-based connections:

- API host overrides: `DIGITALOCEAN_API`, `HETZNER_API`, `UPCLOUD_API`, `VULTR_API`,
  `GOOGLE_COMPUTE_API`, `GOOGLE_RESOURCE_API`.
- DigitalOcean OAuth (only for OAuth connections, not Personal Access Tokens):
  `DIGITALOCEAN_APP_CLIENT_ID`, `DIGITALOCEAN_APP_CLIENT_SECRET`, `DIGITALOCEAN_TOKEN_URL`.
- Google OAuth refresh: `GOOGLE_OAUTH_TOKEN_URL`.
- OVH Public Cloud (required to back up OVH instances/volumes), per region:
  `OVH_CA_APP_KEY`/`OVH_CA_APP_SECRET`, `OVH_EU_APP_KEY`/`OVH_EU_APP_SECRET`,
  `OVH_US_APP_KEY`/`OVH_US_APP_SECRET`.
- Basecamp source OAuth: `BASECAMP_CLIENT_ID`, `BASECAMP_CLIENT_SECRET` (endpoints default
  to Basecamp's public hosts).

See [Providers](providers.md) for which integrations need what.
