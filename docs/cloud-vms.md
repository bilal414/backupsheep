# Cloud VM deployments

BackupSheep's one-command installer works on a fresh **Ubuntu 22.04+** or **Debian 12+**
VM regardless of the cloud provider. It installs Docker Engine and the Compose plugin,
then starts the complete stack: PostgreSQL, **RabbitMQ**, web console, workers, and Celery
Beat.

This is the recommended deployment path when you need durable Local Storage archives,
large temporary backup files, or separately scalable workers.

## Providers

Use this guide with any provider that can create a supported VM, including:

| Provider | Create | Networking and storage |
|---|---|---|
| AWS EC2 / Lightsail | Ubuntu 22.04+ or Debian 12+ instance | Allow SSH from your IP and TCP 8000 temporarily (or only 80/443 behind a reverse proxy); attach EBS for Local Storage. |
| Azure Virtual Machines | Ubuntu 22.04+ or Debian 12+ VM | Apply the same rules in the Network Security Group; attach a Managed Disk for Local Storage. |
| Google Compute Engine | Ubuntu 22.04+ or Debian 12+ VM | Add a VPC firewall rule for the public endpoint; use a Persistent Disk for Local Storage. |
| Hetzner Cloud / Vultr / Akamai Connected Cloud (Linode) | Ubuntu 22.04+ or Debian 12+ cloud server | Restrict SSH with the provider firewall; attach block storage if archive retention is local. |
| OVHcloud / Scaleway / UpCloud / Oracle Cloud | Ubuntu 22.04+ or Debian 12+ instance | Open only the required ingress ports and use the provider's block volume for Local Storage. |

Start with at least 2 GB RAM and size disk space for the largest source backup plus its
compressed archive. Use external object storage for a second, off-server copy.

## SSH installation

Create the VM, connect as an administrator, then run:

```bash
curl -fsSL https://raw.githubusercontent.com/bilal414/backupsheep/main/install.sh | sudo bash
```

If the public hostname is already known, configure it from the first run:

```bash
curl -fsSL https://raw.githubusercontent.com/bilal414/backupsheep/main/install.sh | sudo bash -s -- --domain backups.example.com
```

The installer prints the onboarding URL and private token after the health check passes.
For all options, run the script with `--help` or see [installation](installation.md).

## Cloud-init / user data

For a no-SSH first install, paste
[deploy/cloud-init/backupsheep.yaml](../deploy/cloud-init/backupsheep.yaml) into the
provider's cloud-init, custom-data, or user-data field when creating the VM. Cloud-init
runs it as root, so it must not be prefixed with `sudo`.

To provide a hostname, replace the second `runcmd` entry with:

```yaml
- [bash, /tmp/backupsheep-install.sh, --domain, backups.example.com]
```

After the VM starts, check its console/cloud-init output for the printed onboarding token,
or SSH in and inspect the running stack:

```bash
cd /opt/backupsheep
sudo docker compose ps
```

## Before public use

- Restrict SSH to trusted IP addresses.
- Place BackupSheep behind an HTTPS reverse proxy before public use, then set
  `DJANGO_HTTPS=true`, `APP_PROTOCOL=https://`, `APP_DOMAIN`, and
  `DJANGO_ALLOWED_HOSTS` in `/opt/backupsheep/.env`.
- If using Local Storage, mount the provider block volume at `/backups` before retaining
  archives there. An external storage destination remains the safer long-term target.

See [production deployment](deployment.md) for TLS and hardening, and
[configuration](configuration.md#local-storage-backup-destination-optional) for persistent
local archive storage.
