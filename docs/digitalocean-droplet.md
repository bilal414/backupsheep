# DigitalOcean Droplet

BackupSheep runs best on a DigitalOcean Droplet, where its Docker Compose stack can keep
PostgreSQL data, lane-private backup work, fenced ciphertext handoffs, and optional
storage-only Local Storage on distinct durable volumes.

DigitalOcean's App Platform **Deploy to DO** button supports one service, optionally with
one development database. BackupSheep requires a web process, five isolated Celery worker
lanes, Celery Beat, PostgreSQL, RabbitMQ, private work/transfer boundaries, and per-role
egress guards, so App Platform's documented button format cannot reproduce the reviewed
stock stack.

## Install

1. Create an Ubuntu 22.04+ or Debian 12+ Droplet with at least 2 GB RAM. Attach additional
   block storage first if you plan to retain large backups locally.
2. Allow SSH only from your trusted address. Keep TCP port 8000 closed; the installer
   binds it to loopback for an SSH tunnel. Expose only 80/443 after configuring a reverse
   proxy.
3. Install and secure Git, Docker Engine 28.0.0+ and Docker Compose 2.33.1+ using your
   host-management policy. Grant the intended unprivileged application user access to
   that Docker daemon.
4. As that user, download the installer from the exact reviewed release commit and run
   it without `sudo`:

   ```bash
   COMMIT='<40-character-reviewed-release-commit>'
   curl -fSLo install.sh \
     "https://raw.githubusercontent.com/bilal414/backupsheep/${COMMIT}/install.sh"
   less install.sh
   chmod 700 install.sh
   ./install.sh \
     --ref "${COMMIT}" \
     --install-dir "$HOME/.local/share/backupsheep" \
     --project-name backupsheep \
     --domain backups.example.com
   ```

   The installer generates separate local database/files artifact keyrings. Back up both
   keyrings with the PostgreSQL recovery set before enabling operations.

The installer changes no host settings. It verifies the exact checkout, generates
file-backed application/database/broker/onboarding secrets, builds the reviewed image and
starts only the core stack. When the web service is healthy, it prints an SSH-tunnel and
trusted-shell token retrieval command without writing the token to logs. Provider workers
and Beat remain stopped until the operator reviews recovery/queue state and explicitly
reruns the same exact command (including domain and project) with
`--enable-operations` appended.

## Production notes

- Put a TLS-terminating reverse proxy in front of BackupSheep before public use, then set
  `DJANGO_HTTPS=true`, `APP_PROTOCOL=https://`, `APP_DOMAIN`, and
  `DJANGO_ALLOWED_HOSTS` in the installation `.env`.
- Back the Compose `backup_storage` volume with an attached DigitalOcean Block Storage
  volume if you use **Local Storage**. `/backups` is mounted read/write only in
  `worker-storage`; do not add it to app or another worker. See
  [Configuration](configuration.md#local-storage-backup-destination-optional).
- Object storage destinations such as DigitalOcean Spaces, S3, B2, or R2 are generally a
  better long-term backup target than the server's local disk.

See the general [installation guide](installation.md) and [production deployment guide](deployment.md)
for operations, upgrades, and TLS examples.
