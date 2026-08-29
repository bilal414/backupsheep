# Schedules and backup policies

A schedule belongs to one node and creates scheduled backup requests through
the database-backed scheduler and dispatch outbox. On-demand backup requests use
the same durable dispatch mechanism but are not schedules.

## Schedule types

| Type | Configuration | Availability |
| --- | --- | --- |
| Fixed rate | A positive interval in minutes, hours, or days | Console and API |
| Cron | Five cron fields plus a timezone | Console and API |
| One-time | A future date/time | API and model; existing one-time schedules are displayed in the console, but the create/edit modal does not offer this type |

The cron expression is validated before save. Rate intervals must be positive.
The timezone is stored with the schedule and is used by the periodic scheduler.

## Destinations by source type

Website, logical database, and Basecamp schedules require at least
one current-account storage destination. Cloud and volume schedules do not take
storage destinations because their snapshots or recovery points stay at the
provider.

The serializer rejects a destination from another account. It also checks node
visibility so a member cannot create a schedule for a node outside their group
scope.

## Retention with `keep_last`

`keep_last` is a count of successful backups created by that schedule:

- leave it empty to keep all successful runs;
- set a positive number to soft-delete the oldest successful runs after a new
  run finalizes;
- both Complete and Partial archive runs count, because each can occupy remote
  destination space;
- provider-native cloud retention deletes old provider snapshots through the
  corresponding adapter;
- archive retention asks each storage point to delete its remote object unless
  it is protected.

Object Lock, a legal hold, `no_delete`, and an air-gapped destination can keep a
remote object beyond the desired `keep_last` count. Provider immutability is the
authoritative minimum retention boundary.

The model contains older policy fields for remote deletion, compression, and
encryption, but the current console does not present them as supported schedule
controls. Do not rely on those fields as an operator-facing feature.

## Required air-gapped copy

For archive-producing nodes, a schedule can require a selected air-gapped copy.
The serializer requires at least one selected destination marked
`is_air_gapped`. At execution time BackupSheep validates the protected
destination before starting source work. If it is absent, paused, or cannot be
validated, the backup is recorded as **Storage Validation Failed** instead of
silently continuing without the required copy.

Currently, the air-gapped designation and its strong configuration checks are
implemented for Amazon S3. See
[Storage destinations](storage-destinations.md#amazon-s3-immutability-and-lifecycle-controls).

## Lifecycle actions

Members with `schedule_changes` can create, edit, pause, resume, manually
trigger, and delete schedules in their visible scope. The account owner bypasses
that group-permission check.

Deleting a schedule removes its periodic task only when it has no attached
backups. If backup history exists, the API returns a conflict and directs the
operator to pause the schedule. This preserves the relationship needed for
history and retention.

A manual schedule trigger carries a caller-supplied request ID. The combination
of schedule and request ID is unique, so replaying the same trigger does not
create another schedule-run record.

## Durable dispatch and overlap control

The scheduler records each occurrence and creates a durable backup request
before publishing work. Recovery tasks republish committed requests that did
not reach a worker. Stable occurrence IDs, request idempotency, and unique
constraints make duplicate scheduler or broker delivery converge on the same
accepted request.

Once execution starts, the node also refuses a new backup while an earlier run
is in an active state. This is per node, not a global concurrency limit.

## Upcoming schedule visibility

The dashboard calculates the next occurrence for active schedules and shows the
earliest five inside the member's visible-node scope. It uses the last periodic
run (or schedule creation) for rate schedules, cron iteration for cron
schedules, and the future timestamp for one-time schedules.

## Implementation references

- [Schedule model and periodic-task mapping](../../apps/console/node/models.py)
- [Schedule validation and destination policy](../../apps/api/v1/schedule/serializers.py)
- [Schedule actions](../../apps/api/v1/schedule/views.py)
- [Console schedule form](../../apps/console/_templates/console/node/detail.html)
- [Database-backed scheduler](../../backupsheep/scheduler.py)
- [Durable request dispatch and recovery](../../apps/_tasks/backup_dispatch.py)
- [Retention and air-gap schedule tests](../../apps/tests/test_scheduling.py)
- [Archive finalization and retention](../../apps/_tasks/integration/storage/tasks.py)
