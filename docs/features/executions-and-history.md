# Executions and history

BackupSheep keeps the accepted request, concrete backup record, durable
execution ledger, destination copies, provider state, and activity events as
separate records. The console combines them into a readable run history without
making Celery's transient task state the source of truth.

## Backup statuses

The public backup lifecycle includes:

- Pending, Started, In Progress, and Retrying;
- Ready for Upload, Upload Validation, Upload In Progress, and Upload Complete;
- Complete and Partial;
- Failed, Max Retries Failed, Upload Failed, Storage Validation Failed, and
  Timeout;
- Cancelled;
- deletion and download transition states.

**Partial** is a usable-but-degraded outcome: at least one requested storage
destination completed and at least one did not. The completed storage-point
rows remain available for download, transfer, or restore.

## Durable execution status

Backup and restore API serializers add a normalized `execution_status` object.
It can expose:

- whether a durable execution row exists;
- correlation ID;
- normalized status and phase;
- a stable, allowlisted error code and message;
- last-error and next-retry timestamps;
- attempt count;
- completed/total/unit progress;
- source-artifact verification summary;
- reconciliation state and reason;
- bounded provider status.

The console turns that data into a badge, phase label, determinate or pulsing
progress bar, retry time, recovery/reconciliation notice, and copyable technical
details. Unknown or sensitive provider fields are not rendered.

## Safe public diagnostics

Provider response bodies, command lines, arbitrary exception strings,
credentials, internal worker ownership, lease tokens, and raw execution metadata
are not part of the public execution contract. Legacy backup serializers return
an empty `metadata` object instead of a provider response. Restore serializers
only expose allowlisted parameters such as restore mode, a locked target
mapping, or the website delete flag.

Use the correlation ID to find the matching secured diagnostics in deployment
logs or error monitoring.

## Node backup history

The node detail page lists backups newest first with their stable backup ID,
created/modified time, type (on-demand or scheduled), schedule information,
status, size/file counts where available, and actions permitted for that source
and status.

Actions include:

- cancel an in-flight backup;
- delete a terminal backup and its unprotected provider/storage copies;
- inspect storage-point status;
- download a completed archive copy;
- transfer a completed archive to another configured destination;
- start a supported restore;
- inspect the execution status and retry/reconciliation information.

Some website/database transfer-log endpoints remain unavailable in the
self-hosted build because the former hosted log bucket is not present. This does
not remove the run's database status, execution status, storage points, or
activity entries.

## Crash and duplicate-delivery behavior

Accepted requests, execution ownership, artifacts, retry timing, and
reconciliation state are stored in the database. Workers use expiring leases
and fencing tokens. A stale worker that has lost its lease is prevented from
persisting a competing state transition. Recovery tasks can resume stale
requests and executions from durable rows.

For provider mutation boundaries, an unknown outcome is not treated as an
ordinary retry. The execution moves into reconciliation, where the provider
adapter looks for an exact marker, request identity, or provider pointer before
deciding whether work can continue. If ownership cannot be proved, the public
state calls for manual review rather than guessing.

These controls reduce duplicate provider operations, but operators should still
test restart, timeout, rate-limit, and lost-response behavior for the exact
providers and versions used by their deployment.

## Activity history

The Activity page records Generic, Node, Connection, Backup, Member, Schedule,
Storage, Restore, and Auth events. Filters cover event type, related node,
backup, connection, message text, and error text. Pages default to 50 entries
and are capped at 100.

Successful logins are recorded for the member's current account. Failed login
attempts are recorded only when the submitted identity can be resolved to an
account; unknown identities have no tenant to receive the event.

Database activity rows older than `LOG_RETENTION_DAYS` are pruned (30 days by
default). Separate file-log maintenance uses the same setting for local run-log
files.

## Implementation references

- [Public backup/restore execution serialization](../../apps/api/v1/backup/serializers.py)
- [Backup execution ledger](../../apps/console/backup/models.py)
- [Backup statuses and fencing helpers](../../apps/console/utils/models.py)
- [Node backup actions](../../apps/api/v1/node/views.py)
- [Node detail execution UI](../../apps/console/_templates/console/node/detail.html)
- [Durable request and execution recovery](../../apps/_tasks/backup_dispatch.py)
- [Activity model, authentication signals, and retention](../../apps/console/log/models.py)
- [Activity page filters and pagination](../../apps/console/log/views.py)
