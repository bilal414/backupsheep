# BackupSheep documentation

This is the documentation hub for the current BackupSheep codebase. It separates
day-to-day user guidance, API usage, and operator runbooks from dated engineering test
reports retained elsewhere in `docs/`.

BackupSheep is a self-hosted backup orchestrator. A healthy installation is only the
starting point: validate each integration and storage destination, complete a backup,
and rehearse a restore before relying on it for recovery.

## Enterprise recovery manual

Open the [visual enterprise recovery manual](enterprise/index.html) for the complete,
searchable product guide. It covers architecture, every backup family, storage and
restore behavior, retry/reconciliation policy, API operations, configuration variables,
security boundaries, operational runbooks, edge cases, and evidence requirements.

The manual's API and configuration catalogs are generated from repository sources so
drift can be detected during documentation validation.

## New users

1. [Install BackupSheep](guides/installation.md).
2. [Configure the instance](guides/configuration.md).
3. Complete [first-run setup](guides/first-run.md).
4. Learn the [core concepts](features/core-concepts.md).
5. Follow the [console workflow](features/console-workflows.md) to connect storage and
   a source, create a schedule, and run the first backup.
6. Read the [restore guide](features/restores.md) and rehearse recovery into an isolated
   target.

## Product and feature guides

| Guide | What it covers |
|---|---|
| [Feature overview](features/README.md) | Entry point for all user-facing capabilities. |
| [Core concepts](features/core-concepts.md) | Accounts, connections, nodes, schedules, backups, storage points, and restores. |
| [Console workflows](features/console-workflows.md) | Dashboard and normal setup/management flow. |
| [Backup sources](features/backup-sources.md) | Websites, databases, cloud resources, volumes, and Basecamp. |
| [Storage destinations](features/storage-destinations.md) | Local and cloud destinations, validation, multiple copies, and S3 controls. |
| [Schedules and policies](features/schedules-and-policies.md) | Cron/rate/one-time timing, retention, pause/resume, and on-demand runs. |
| [Executions and history](features/executions-and-history.md) | Durable progress, status, retries, reconciliation, logs, and downloads. |
| [Restores](features/restores.md) | Website/database restore and supported provider recovery workflows. |
| [Notifications](features/notifications.md) | Email, Slack, Telegram, recipient rules, and verification. |
| [Teams, tenancy, and API access](features/teams-tenancy-and-api-access.md) | Accounts, invites, groups, node scope, permissions, MFA, and tokens. |

## API documentation

| Guide | What it covers |
|---|---|
| [REST API overview](api/README.md) | Base URL, scope, formats, security, and quick start. |
| [Authentication](api/authentication.md) | DRF tokens, browser sessions, CSRF, reset endpoints, and account context. |
| [Conventions and safety](api/conventions.md) | CRUD patterns, filters, asynchronous work, idempotency, errors, and mutations. |
| [Common API workflows](api/workflows.md) | Connection-to-backup and restore sequences. |
| [Endpoint reference](api/reference.md) | Human-readable map of every endpoint family. |
| [Bruno collection](../bruno/README.md) | Runnable request for every active API method plus resolver-based coverage validation. |

## Installation and operations

| Guide | What it covers |
|---|---|
| [Operator guide index](guides/README.md) | Recommended lifecycle from installation through recovery. |
| [Installation](guides/installation.md) | Server installer, Compose, and advanced manual processes. |
| [Configuration](guides/configuration.md) | Public URL, database, RabbitMQ, storage paths, secrets, providers, and tuning. |
| [First-run setup](guides/first-run.md) | Secure onboarding and post-setup verification. |
| [Production deployment](guides/production.md) | TLS, reverse proxy, network boundaries, secrets, and go-live checks. |
| [Operations runbook](guides/operations.md) | Routine health checks and safe service management. |
| [Upgrades](guides/upgrades.md) | Preflight, backup, pull/build/migrate, verification, and rollback planning. |
| [Disaster recovery](guides/disaster-recovery.md) | Protect and recover BackupSheep's PostgreSQL, RabbitMQ, work data, and local archives. |
| [Observability](guides/observability.md) | Health, containers, queues, workers, logs, Sentry, and provider evidence. |
| [Troubleshooting](guides/troubleshooting.md) | Symptom-driven diagnosis without masking durable state. |

## Reference

| Reference | Contents |
|---|---|
| [Architecture](reference/architecture.md) | Services, queues, persistence, and backup/restore data flow. |
| [Environment variables](reference/environment-variables.md) | Complete configuration inventory from `.env_sample` and settings. |
| [Provider matrix](reference/provider-matrix.md) | Source/destination coverage, authentication, backup model, restore behavior, and caveats. |

## Deployment-specific guides

The original focused guides remain useful for their specific platform:

- [DigitalOcean Droplet](digitalocean-droplet.md)
- [General cloud VMs](cloud-vms.md)
- [Render](render.md)
- [Heroku](heroku.md)
- [Railway](railway.md)
- [Scaling workers](scaling.md)
- [AWS S3, DynamoDB, and RDS](aws-s3-dynamodb-rds-backups.md)
- [Lightsail bucket replication and database restore](lightsail-bucket-replication-and-database-restore.md)
- [Immutable S3 backups and lifecycle controls](immutable-backups-and-lifecycle.md)

## Engineering evidence and historical reports

Files with names such as `*-test-report.md`, `*-e2e-*.md`, `*-handoff-*.md`,
`*-wrap-up-*.md`, and `*-test-plan.md` record a particular engineering exercise. They
are valuable evidence and maintenance context, but they are not a substitute for the
current user and operator guides above. Provider behavior, deployment state, resource
ownership, and credentials must be revalidated for every real installation.

For the latest documentation/API release evidence and resume point, see
[2026-08-12 — GitHub documentation and Bruno collection](releases/2026-08-12-documentation-and-bruno-handoff.md).

## Project policies

- [Security policy](../SECURITY.md)
- [Contributing](../CONTRIBUTING.md)
- [GNU GPLv3 license](../LICENSE)
