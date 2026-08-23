# Cloud VM deployments

BackupSheep's verified installer works on a Linux VM where the host operator has already
installed and secured Git, Docker Engine 28.0.0+ and Docker Compose 2.33.1+. It changes no
host package, service, daemon, firewall or kernel settings. By default it starts only
PostgreSQL, RabbitMQ, migrations, the security preflight and web console; provider workers
and Beat require a separate explicit opt-in.

This is the recommended deployment path when you need durable Local Storage archives,
large temporary backup files, or separately scalable workers.

## Providers

Use this guide with any provider that can create a supported VM, including:

| Provider | Create | Networking and storage |
|---|---|---|
| AWS EC2 / Lightsail | Ubuntu 22.04+ or Debian 12+ instance | Allow SSH from your IP; expose only 80/443 after configuring a reverse proxy. Keep TCP 8000 closed and attach EBS for Local Storage. |
| Azure Virtual Machines | Ubuntu 22.04+ or Debian 12+ VM | Apply the same rules in the Network Security Group; attach a Managed Disk for Local Storage. |
| Google Compute Engine | Ubuntu 22.04+ or Debian 12+ VM | Add VPC firewall rules only for trusted SSH and the TLS proxy; keep TCP 8000 closed. Use a Persistent Disk for Local Storage. |
| Hetzner Cloud / Vultr / Akamai Connected Cloud (Linode) | Ubuntu 22.04+ or Debian 12+ cloud server | Restrict SSH with the provider firewall; attach block storage if archive retention is local. |
| OVHcloud / Scaleway / UpCloud / Oracle Cloud | Ubuntu 22.04+ or Debian 12+ instance | Open only the required ingress ports and use the provider's block volume for Local Storage. |

Start with at least 2 GB RAM and size disk space for the largest source backup plus its
compressed archive. Use external object storage for a second, off-server copy.

## SSH installation

Create and secure the VM according to your host policy. As the unprivileged user already
authorized to use the intended Docker daemon, download the installer from the exact
reviewed release commit:

```bash
COMMIT='<40-character-reviewed-release-commit>'
curl -fSLo install.sh \
  "https://raw.githubusercontent.com/bilal414/backupsheep/${COMMIT}/install.sh"
less install.sh
chmod 700 install.sh
./install.sh --ref "${COMMIT}" --domain backups.example.com
```

The installer prints an SSH-tunnel command and an explicit trusted-shell command for
retrieving the onboarding token after the health check passes; it does not put the token
in install logs.
For all options, run the script with `--help` or see [installation](installation.md).

## Cloud-init / user data

BackupSheep intentionally no longer provides unattended root cloud-init installation.
The compatibility file at
[deploy/cloud-init/backupsheep.yaml](../deploy/cloud-init/backupsheep.yaml) is inert.
Provision Docker, users, networking and host security using your own reviewed image or
infrastructure code, then run the exact-commit installer as the Docker-authorized user.

After the core passes preflight, retrieve the token explicitly. It is intentionally
absent from installation logs:

```bash
cd "$HOME/.local/share/backupsheep"
./backupsheep-compose ps
cat .secrets/onboarding_token
```

## Before public use

- Restrict SSH to trusted IP addresses.
- Keep TCP 8000 closed publicly. Use an SSH tunnel for initial onboarding.
- Place BackupSheep behind an HTTPS reverse proxy before public use, then set
  `DJANGO_HTTPS=true`, `APP_PROTOCOL=https://`, `APP_DOMAIN`, and
  `DJANGO_ALLOWED_HOSTS` in the installation `.env`.
- If using Local Storage, mount the provider block volume at `/backups` before retaining
  archives there. An external storage destination remains the safer long-term target.

See [production deployment](deployment.md) for TLS and hardening, and
[configuration](configuration.md#local-storage-backup-destination-optional) for persistent
local archive storage.
