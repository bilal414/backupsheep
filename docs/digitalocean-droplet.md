# DigitalOcean Droplet

BackupSheep runs best on a DigitalOcean Droplet, where its Docker Compose stack can keep
PostgreSQL data, backup working files, and optional Local Storage on durable volumes.

DigitalOcean's App Platform **Deploy to DO** button supports one service, optionally with
one development database. BackupSheep requires a web process, Celery worker, Celery Beat,
PostgreSQL, and a message broker, so App Platform's documented button format cannot deploy
the complete stack.

## Install

1. Create an Ubuntu 22.04+ or Debian 12+ Droplet with at least 2 GB RAM. Attach additional
   block storage first if you plan to retain large backups locally.
2. Allow SSH only from your trusted address. Keep TCP port 8000 closed; the installer
   binds it to loopback for an SSH tunnel. Expose only 80/443 after configuring a reverse
   proxy.
3. SSH into the Droplet and run:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/bilal414/backupsheep/main/install.sh | sudo bash
   ```

4. For a DNS name, pass it to the installer from the start:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/bilal414/backupsheep/main/install.sh | sudo bash -s -- --domain backups.example.com
   ```

The installer creates `/opt/backupsheep`, installs Docker Engine and its Compose plugin,
generates application, database, broker, and onboarding secrets, and starts the complete
stack. When the web service is healthy, it prints an SSH-tunnel command and a trusted-shell
token retrieval command without writing the token itself to install logs.

## Production notes

- Put a TLS-terminating reverse proxy in front of BackupSheep before public use, then set
  `DJANGO_HTTPS=true`, `APP_PROTOCOL=https://`, `APP_DOMAIN`, and
  `DJANGO_ALLOWED_HOSTS` in `/opt/backupsheep/.env`.
- Mount an attached DigitalOcean Block Storage volume over `/backups` if you use **Local
  Storage** as a backup destination. See [Configuration](configuration.md#local-storage-backup-destination-optional).
- Object storage destinations such as DigitalOcean Spaces, S3, B2, or R2 are generally a
  better long-term backup target than the server's local disk.

See the general [installation guide](installation.md) and [production deployment guide](deployment.md)
for operations, upgrades, and TLS examples.
