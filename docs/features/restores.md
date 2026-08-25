# Restores

BackupSheep treats restore as a tracked operation with its own status,
correlation ID, progress, error contract, retry timing, and history. A restore
never changes or consumes the backup record itself.

## Restore matrix

| Source | In-console/API behavior | Existing source changed? |
| --- | --- | --- |
| Website archive | Restores a selected completed copy to the configured server | Files with matching paths can be overwritten; optional exact-mirror deletion can remove remote files absent from the backup |
| Logical MySQL/MariaDB/PostgreSQL archive | Defaults to new, deterministically named database target(s) | No in default fork mode |
| DigitalOcean, AWS EC2/EBS, AWS RDS, Lightsail, Hetzner, Vultr compute/block, UpCloud, Oracle, Google Cloud, OVH CA/EU/US | Creates a new provider resource from a completed snapshot/recovery point | No |
| AWS S3/DynamoDB | Uses AWS Backup recovery metadata and a distinct target bucket/table | No source overwrite; S3 target must be an existing empty versioned bucket |
| Vultr Managed Database | Creates a new managed-database fork | No |
| Lightsail bucket replication | Copies a selected replication run back to a configured target prefix | May write objects under the selected target prefix; tracked separately from node restores |
| WordPress or Basecamp archive | No enterprise recovery action; stock enterprise mode blocks all new protection and backup initiation while retaining existing rows for inspection | Direct BSE1 download is disabled; no automatic restore/authenticated plaintext export exists, and the transfer UI has no complete server action/task. Only explicit non-enterprise `legacy-only` compatibility mode can create a plaintext artifact for the authenticated legacy download action |

Every restore-start action requires a completed/eligible backup or replication
run plus explicit request data. Node restores require the `backup_create` group
permission for non-owner members.

## Website restore

The operator selects one completed storage point and confirms the operation.
The storage worker downloads and validates the BSE1 ciphertext, publishes it through the
files-lane reverse-transfer fence, and the files worker authenticates and decrypts it in
its private work volume before publishing the content through the configured website
connection.

By default, files present in the archive overwrite their matching server paths,
while unrelated server files remain. The optional **Delete files on the server
that are not present in this backup** switch requests an exact mirror and is
destructive. The console displays that warning before submission.

Website restores keep a durable row and recent history. A worker restart can
resume staged/checkpointed work using the existing restore rather than silently
creating a second restore record.

## Logical database restore

The console submits the default **fork** mode. BackupSheep derives and locks a
deterministic target mapping before dispatch, verifies the archive, checks
database privileges, creates new target database(s), and imports the dumps.
The source database and existing data remain unchanged.

Fork restore requires target-creation privileges: PostgreSQL `CREATEDB`, or
appropriate MySQL/MariaDB `CREATE` and `DROP` coverage for the deterministic
target namespace. The public error contract reports missing fork privileges
without exposing database command output.

The API engine also contains an explicit `in_place` mode for callers that
provide and accept its target mapping. It is intentionally not offered by the
current console, whose documented default is the safer fork workflow.

A failed database fork can offer **Resume verification** only when the durable
row contains the exact locked mapping, ownership marker, artifact digest, and
checkpoint evidence needed to re-enter that same operation. It does not start a
new restore request.

## Native cloud and volume restore

The operator chooses a completed provider backup, enters a new target name and
any provider-required parameters, confirms that a new billable resource will be
created, and submits an idempotency key. BackupSheep persists the restore before
worker dispatch. Replaying the same key and payload returns the existing row;
reusing the key for a different payload returns a conflict.

Provider adapters create a new server, volume, image-backed resource, managed
database, bucket recovery, or table recovery. The source and other existing
resources are not modified. Exact target details vary by provider—for example,
Oracle compute requires shape and subnet choices and locks the restore to the
discovered compartment/availability-domain scope.

The console tracks up to five recent native restores and displays provider
status, resource/job IDs, execution phase, retry timing, safe errors, and
correlation ID.

## Unknown outcomes and resume controls

If a provider create request times out or returns an ambiguous result,
BackupSheep keeps the same restore row and reconciles the provider inventory or
known job/resource pointer. It does not automatically issue a second create
unless the provider-specific state machine can prove that is safe.

**Resume verification** is offered only for an existing, proven provider target
or pointer and normally performs read-only polling/reconciliation. One narrow
UpCloud server path can show **Retry same restore** after the prior request was
definitively rejected and a complete inventory scan proves there is no matching
target. Even then it reuses the same durable restore row.

## Restore notifications and activity

Restore started and failed events go to account members eligible for failure
email; completed events go to success recipients. Restore events are also
written to the account Activity log. Public failure messages are categorized
and direct the operator to the correlation ID rather than including arbitrary
provider or command text.

## Before restoring production data

1. Verify that the selected backup and destination copy are complete.
2. Confirm target capacity, region, networking, IAM/database privileges, and
   provider charges.
3. Use a new-resource/fork target whenever the workflow supports it.
4. For a website exact mirror or API `in_place` database restore, take a fresh
   independent backup and review the destructive scope.
5. Test application startup and data integrity on the restored target before a
   cutover.

## Implementation references

- [Website restore API](../../apps/api/v1/backup/website/views.py)
- [Logical database restore API and safe-resume checks](../../apps/api/v1/backup/database/views.py)
- [Native cloud restore API and idempotency](../../apps/api/v1/node/views.py)
- [Restore execution models](../../apps/console/backup/models.py)
- [Restore orchestration and recovery](../../apps/_tasks/integration/restore.py)
- [Website restore engine](../../apps/_tasks/integration/restore_website.py)
- [Database restore engine](../../apps/_tasks/integration/restore_database.py)
- [Restore notification contract](../../apps/_tasks/integration/restore_common.py)
- [Console restore workflows](../../apps/console/_templates/console/node/detail.html)
- [Lightsail bucket replication/restore API](../../apps/api/v1/cloud/lightsail_bucket_replication/views.py)
