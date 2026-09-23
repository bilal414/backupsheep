# Core concepts

BackupSheep separates what is being protected, how it is reached, where an
archive is stored, when work runs, and the resulting execution records. Keeping
those concepts separate makes the console and API easier to reason about.

## Account and current account

An **account** is the top-level tenancy boundary for connections, nodes,
storage, schedules, backups, logs, groups, invitations, and notification
channels. A user can belong to more than one account, but one membership is
marked current. Console and API views use that current account when selecting
data. Switching accounts changes the active scope; it does not move resources
between accounts.

The account's primary membership is the owner. The owner sees all nodes and
bypasses group write-permission checks. Other members receive the union of their
groups' permissions and node visibility.

## Connection

A **connection** stores the credentials and endpoint context used to reach a
provider or service. It belongs to an account and an integration, and may also
be associated with the BackupSheep execution location that will run work.

Examples include a cloud API credential, an SFTP login, a database login, and a
Basecamp OAuth connection. A connection can
expose multiple eligible resources from which nodes are created. Connection
validation tests the configured provider or service before a backup is started.

## Node (protected source)

A **node** is one selected resource to protect. Nodes have five user-visible
categories:

- **Cloud**: a server, instance, provider-managed database, or supported cloud
  data resource.
- **Volume**: an independently discovered block volume or disk.
- **Website**: files and directories reached through FTPS or SFTP; plaintext FTP is
  a default-off legacy compatibility mode.
- **Database**: one or more logical MySQL, MariaDB, or PostgreSQL databases.
- **SaaS**: currently Basecamp.

A node carries its display name, timezone, status, success/failure notification
switches, and provider-specific configuration. Its status can distinguish
active, ready, in progress, retrying, paused, suspended, deletion, and
max-retry states. Pausing a node prevents normal backup initiation without
deleting its history.

## Storage destination

A **storage destination** is an account-owned place for an archive produced by
BackupSheep. It can be local disk, object storage, or a supported drive service.
One website, logical database, or Basecamp backup can be sent to
multiple destinations. Each resulting copy has its own storage-point record and
upload status.

Cloud snapshots and provider recovery points are different: they normally stay
inside the cloud provider and do not use a BackupSheep storage destination.

## Schedule (backup policy)

A **schedule** belongs to one node. It defines when a backup runs and can also
define:

- the storage destinations for archive-producing nodes;
- the number of successful runs to keep;
- whether a selected air-gapped destination must validate before work starts;
- a timezone and operator notes.

Schedules can be active, paused, or pending deletion. A schedule's backups keep
their relationship to it, which is why the API refuses to delete a schedule
that already has backup records and recommends pausing it instead.

## Backup request, backup, and storage point

An accepted **backup request** is a durable dispatch record. On-demand and
scheduled requests are committed before worker publication, giving operators a
queryable accepted state even when the broker is unavailable. An idempotency
key lets repeated delivery converge on the same request.

A concrete **backup** records one run for a source. It has a stable ID, on-demand
or scheduled type, status, timestamps, attempts, notes, size/file counts where
available, and a durable execution ledger. Cloud integrations attach provider
snapshot or recovery-point state. Archive-producing integrations attach one
**storage point** per destination so a run can show complete, partial, or total
upload failure accurately.

BackupSheep prevents a second backup from starting for the same node while an
earlier run is in an active state.

## Restore

A **restore** is its own tracked execution, not a change to the backup record.
Website and database restores select a completed storage point. Native cloud
restores select a completed provider backup and create a new provider target.
Restore records persist progress, safe error codes, retry timing, correlation
IDs, and provider pointers needed for recovery or operator review.

## Activity log

The **activity log** is an account-scoped event stream with these types:
Generic, Node, Connection, Backup, Member, Schedule, Storage, Restore, and Auth.
Events may link back to a node, connection, backup, actor, or error. It is useful
for understanding what changed; the backup and restore execution records remain
the source of truth for run state.

## Implementation references

- [Account, groups, notification recipients, and unified backups](../../apps/console/account/models.py)
- [Connections and service authentication models](../../apps/console/connection/models.py)
- [Nodes and schedules](../../apps/console/node/models.py)
- [Backup status and durable execution contract](../../apps/console/utils/models.py)
- [Backup, storage-point, request, and restore models](../../apps/console/backup/models.py)
- [Storage destination models](../../apps/console/storage/models.py)
- [Durable backup dispatch](../../apps/_tasks/backup_dispatch.py)
- [Activity log model](../../apps/console/log/models.py)
