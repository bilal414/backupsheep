# BackupSheep feature guide

This guide describes the features implemented on BackupSheep's `develop`
branch. It is organized around the concepts and workflows visible to people
using or operating the self-hosted console.

## Start here

1. Read [Core concepts](core-concepts.md) to understand accounts,
   connections, nodes, storage destinations, schedules, backups, and restores.
2. Follow [Console workflows](console-workflows.md) for the normal setup,
   monitoring, and troubleshooting flow.
3. Check [Backup sources](backup-sources.md) and
   [Storage destinations](storage-destinations.md) before choosing a design.
4. Configure [Schedules and policies](schedules-and-policies.md).
5. Learn how to read [Executions and history](executions-and-history.md) and
   perform [Restores](restores.md).
6. Configure [Notifications](notifications.md) and, for shared environments,
   [Teams, tenancy, and API access](teams-tenancy-and-api-access.md).

## Feature map

| Area | What BackupSheep implements |
| --- | --- |
| Protected sources | Cloud servers, cloud volumes, provider-managed databases and data services, logical MySQL/MariaDB/PostgreSQL dumps, website files, WordPress, and Basecamp |
| Backup placement | Provider-native snapshots or recovery points for cloud resources; one or more configured storage destinations for locally produced archives |
| Automation | Cron and fixed-rate schedules in the console, one-time schedules through the API, on-demand runs, retention by count, and optional S3-backed air-gapped-copy enforcement |
| Operations | A scoped dashboard, source inventory, run history, durable execution status, retry and reconciliation state, activity logs, cancellation, deletion, and authenticated restore actions where applicable; the rendered transfer surface is not backed by a complete current server action/task |
| Recovery | Tracked website and database restores, provider-native new-resource restores, managed-database forks, and Lightsail bucket-replication restore runs |
| Collaboration | Multi-account membership, Team and Client groups, node visibility rules, group permissions, invitations, account switching, and account-scoped API querysets |
| Notifications | Email plus connected Slack and Telegram channels, with account, node, and membership controls for backup email recipients |

## Important boundaries

- A catalog entry means the integration and its API/task path are implemented.
  It does not certify that every provider region, plan, engine version, or
  credential policy has been tested in your environment.
- Cloud backups remain in the source provider unless a feature explicitly
  describes replication. Website, logical database, WordPress, and Basecamp
  backups are archives uploaded to selected BackupSheep storage destinations.
- Automatic in-console restore is not universal. The exact matrix is documented in
  [Restores](restores.md). Direct browser/ZIP download is disabled for current BSE1
  artifacts, and WordPress/Basecamp do not yet have an authenticated plaintext-export or
  automatic-restore workflow.
- Backup and restore correctness depends on the database, scheduler, workers,
  broker, required command-line clients, configured credentials, and provider
  APIs all being operated correctly.
- Storage-cost numbers are projections calculated from rates entered by the
  operator and BackupSheep's recorded bytes. Provider invoices are authoritative.

## Evidence policy

Each page ends with **Implementation references** linking to the models, views,
tasks, templates, or tests that support its claims. The guide deliberately does
not list seeded-but-unwired Zendesk and Slack backup sources as supported; the
setup page labels both as coming soon. Slack as a notification channel is a
separate, implemented feature.

## Implementation references

- [Console URL map](../../apps/console/urls.py)
- [API v1 URL map](../../apps/api/v1/urls.py)
- [Seeded source and storage catalog](../../apps/_migrations/seed_data/reference_data.json)
- [Setup integration catalog](../../apps/console/_templates/console/setup/1_integration_select.html)
- [Unified account backup inventory](../../apps/console/account/models.py)
