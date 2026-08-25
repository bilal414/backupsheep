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
| [PostgreSQL identity generation 2](database-identity-migration.md) | One-time, rollback-gated conversion of a legacy bundled database login into bootstrap, migrator and runtime identities |
| [Disaster recovery](disaster-recovery.md) | Protecting and restoring the BackupSheep control plane itself |
| [Observability](observability.md) | Liveness, dependencies, durable job state, logs, alerts and restore rehearsals |
| [Troubleshooting](troubleshooting.md) | Startup, proxy, worker, backup, restore, source and storage failures |

## Reference material

- [Architecture](../reference/architecture.md)
- [Environment variables](../reference/environment-variables.md)
- [Source and storage provider matrix](../reference/provider-matrix.md)
- [Reference index](../reference/README.md)

## Documentation conventions

Commands assume the repository or install directory is the current directory and require
Docker Engine 28.0.0+ with Docker Compose 2.33.1+ (`docker compose`). Replace
`/opt/backupsheep`, hostnames, account IDs, resource IDs and backup paths with values you
have resolved for the target deployment. Manual deployments explicitly build `app`
because the stock application roles use `pull_policy: never`. Profile-less starts are
core-only; commands that authorize provider workers and Beat include
`--profile operations`.

Deployment commands use the shipped `./backupsheep-compose` wrapper, not raw Compose. It
pins the project directory, `.env` and base model; rejects ambient profile/Bake/orphan and
alternate-settings controls; validates the rendered model; and refuses to auto-load a
`docker-compose.override.yml`. If an installation has an override, inspect its ownership,
permissions, mounts, privileges, networks and complete rendered diff first, then add its
exact path before the Compose command, for example:

```bash
./backupsheep-compose \
  --approved-compose-file "$PWD/docker-compose.override.yml" \
  config --quiet
```

Use that same explicit flag on every later command in the maintenance shell. The only
other accepted extra file is the repository's pinned RabbitMQ compatibility overlay in
its dedicated migration runbook. The verified installer intentionally accepts no local
override at all; use the reviewed manual-deployment path when one is required. The
wrapper also refuses `down`/`rm` volume deletion unless the same command includes its
separate `--allow-data-deletion` wrapper flag; that flag is authorization, not proof that
the selected volumes are disposable.

Examples that inspect state are safe to copy. Commands that restore a database, change
provider state, delete data or alter routing are called out at the point of use. Always
capture exact object ownership before a destructive action.

Never paste `.env`, provider responses, signed URLs, credentials, private keys or archive
contents into an issue. Use correlation IDs and the redacted execution status instead.
