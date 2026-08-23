# Operator guides

This directory is the canonical, task-oriented documentation for installing and running
the self-hosted BackupSheep control plane. The guides describe the `develop` branch as
implemented in this repository; they do not imply that every provider feature has been
validated against a live production account.

## Start here

1. [Install BackupSheep](installation.md).
2. [Configure the instance](configuration.md).
3. [Complete first-run onboarding](first-run.md).
4. Follow the [production deployment checklist](production.md) before exposing it.

## Run and maintain it

| Guide | Use it for |
| --- | --- |
| [Operations](operations.md) | Daily checks, job control, scaling, retention and safe service intervention |
| [Upgrades](upgrades.md) | Staging, backing up, migrating, verifying and rolling back a release |
| [Disaster recovery](disaster-recovery.md) | Protecting and restoring the BackupSheep control plane itself |
| [Observability](observability.md) | Liveness, dependencies, durable job state, logs, alerts and restore rehearsals |
| [Troubleshooting](troubleshooting.md) | Startup, proxy, worker, backup, restore, source and storage failures |

## Reference material

- [Architecture](../reference/architecture.md)
- [Environment variables](../reference/environment-variables.md)
- [Source and storage provider matrix](../reference/provider-matrix.md)
- [Reference index](../reference/README.md)

## Documentation conventions

Commands assume the repository or install directory is the current directory and use
Docker Compose v2 (`docker compose`). Replace `/opt/backupsheep`, hostnames, account IDs,
resource IDs and backup paths with values you have resolved for the target deployment.

Examples that inspect state are safe to copy. Commands that restore a database, change
provider state, delete data or alter routing are called out at the point of use. Always
capture exact object ownership before a destructive action.

Never paste `.env`, provider responses, signed URLs, credentials, private keys or archive
contents into an issue. Use correlation IDs and the redacted execution status instead.
