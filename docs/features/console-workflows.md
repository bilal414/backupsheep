# Console workflows

The console is organized around a repeatable path: configure BackupSheep,
connect storage when needed, connect a source, select protected nodes, add a
schedule, monitor executions, and test recovery.

## First-run onboarding

The first-run flow collects application settings, account details, an email
provider, a first source, and storage configuration. After onboarding, the same
source and storage setup tools remain available from the console.

Operators can configure Mailgun, Postmark, or Amazon SES for transactional
email. A self-hosted execution location is also shown when choosing where work
runs; its detected addresses can be used when allowlisting the BackupSheep
worker on protected servers.

## Dashboard

The dashboard is scoped to the current account and the signed-in member's
visible nodes. It shows:

- protected-source and active-schedule counts;
- recent backup runs across all statuses;
- recent failures, including partial and storage-validation failures;
- upcoming schedule occurrences calculated from cron, rate, or one-time data;
- recent activity events;
- latest protected sources.

Storage footprint and projected storage economics are owner-only dashboard
data. The projection shows recorded stored bytes, estimated monthly storage,
and estimated full retrieval cost based on rates entered for each destination.

## Connect storage

Archive-producing sources need at least one storage destination for on-demand
and scheduled backups. In **Add source / integration**, choose a storage
platform, supply its bucket, account, OAuth, or local-path settings, and save.
Validation checks that BackupSheep can reach the configured destination.

Multiple destinations can be selected for one backup. This produces independent
storage-point rows and lets the console distinguish all destinations succeeded,
some succeeded, and none succeeded.

See [Storage destinations](storage-destinations.md) for the full catalog and
Amazon S3 immutability options.

## Connect a source and create nodes

The setup wizard has three steps: choose a provider, connect the account or
service, and select/create source nodes. Provider connections discover eligible
resources. Website, database, and Basecamp setup collects
source-specific choices instead.

The source inventory can be filtered by type, node name, integration name,
status, and execution endpoint. It groups Cloud, Volume, Website, Database, and
SaaS sources without losing the underlying provider identity.

## Work from a node detail page

The node page is the operational center for a protected source. Depending on
the source type and the member's permissions, it provides:

- connection and source metadata;
- source validation;
- pause, resume, modify, and delete actions;
- on-demand backup with optional notes and destination selection;
- schedule creation, editing, manual triggering, pause/resume, and deletion;
- backup history with status, type, size/file information, and actions;
- storage-copy status, delete, and authenticated restore actions where supported;
  compatibility download controls refuse current BSE1 artifacts, and the rendered
  transfer control has no complete current server action/task;
- tracked website, database, managed-database, and native cloud restore state.

## Monitor and respond

The console polls active backup and restore status. It presents a public-safe
phase, progress (when determinate), provider status, next retry, reconciliation
state, and correlation ID. Use the correlation ID when consulting secured
operator diagnostics; raw provider responses and arbitrary exception text are
not returned in the public execution contract.

The **Activity** page complements node history with an account-wide view. It
supports type, node, backup, connection, message, and error filters, paginates
up to 100 events per page, and defaults to newest first. Non-owner members only
see activity tied to nodes in their current visibility scope.

## Manage account settings

Settings pages cover profile, account, password, multifactor authentication,
groups, users, invitations, and notification channels. The account owner can
manage memberships and group assignments. Members with multiple accounts can
switch the current account from their own membership.

## Suggested operating loop

1. Validate every new connection and storage destination.
2. Run an on-demand backup before enabling a schedule.
3. Confirm the backup reaches a terminal status and, for archives, inspect each
   destination copy.
4. Perform a non-production restore rehearsal using the restore behavior for
   that source type.
5. Enable a schedule and an appropriate `keep_last` value.
6. Configure backup failure notifications and inspect the dashboard and
   activity log regularly.
7. Rehearse worker/broker restart recovery and provider credential rotation in
   your own deployment runbook.

## Implementation references

- [Console routes](../../apps/console/urls.py)
- [Dashboard view](../../apps/console/home/views.py)
- [Dashboard template](../../apps/console/_templates/console/home/index.html)
- [Source inventory and detail views](../../apps/console/node/views.py)
- [Source inventory template](../../apps/console/_templates/console/node/index.html)
- [Node detail workflow](../../apps/console/_templates/console/node/detail.html)
- [Setup catalog and wizard entry](../../apps/console/_templates/console/setup/1_integration_select.html)
- [Activity view and filters](../../apps/console/log/views.py)
- [Settings routes](../../apps/console/setting/urls.py)
