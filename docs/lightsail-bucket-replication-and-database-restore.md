# AWS Lightsail bucket replication and managed-database snapshots

This document describes the durable AWS Lightsail integrations added in this change.
The implementation is designed for a worker or broker restart: the database rows are
the source of truth, and a retry resumes the same provider operation or object
transfer instead of starting a second backup.

## Managed Lightsail relational databases

Lightsail relational databases are represented by `CoreLightsail` with
`resource_type=database`. The existing instance/volume endpoint remains instance-only;
managed databases have their own API route:

`/api/v1/clouds/lightsail_database/`

The lifecycle is:

1. Discovery uses paginated `get_relational_databases` calls.
2. Snapshot creation first searches every page of
   `get_relational_database_snapshots` for the exact deterministic BackupSheep name.
   Only when it is absent does it call `create_relational_database_snapshot`.
3. Status polling searches the snapshot catalog and maps `available` to complete and
   provider failure states to failed. Transient lookup failures remain in progress.
4. Restore uses `create_relational_database_from_snapshot`. A concrete availability
   zone and bundle are taken from restore parameters, the snapshot, or the source
   database in that order. Lightsail's regional `all` location is never sent as an
   availability zone.
5. Deletion uses `delete_relational_database_snapshot` and retains the local backup
   row until the provider call succeeds.

The provider calls use the existing encrypted Lightsail connection credentials. No
credential is copied into a backup, restore, manifest, or task payload.

## Lightsail bucket replication

Bucket replication is configured through:

`/api/v1/clouds/lightsail_bucket_replications/`

The definition links one Lightsail connection and source bucket/prefix to an existing
active S3-compatible BackupSheep storage destination. It supports the S3-compatible
storage relations already present in the application, including AWS S3, DigitalOcean
Spaces, Wasabi, Filebase, Backblaze B2, Cloudflare R2, Linode, Vultr, UpCloud, Oracle,
Scaleway, IBM, IONOS, IDrive, Leviia, RackCorp, and Exoscale. Unsupported storage
providers fail explicitly rather than being sent through a potentially incompatible
adapter.

The Lightsail connection credentials must also be authorized for the source bucket's
S3 object actions (`ListObjectsV2`, `ListObjectVersions`, `HeadObject`, `GetObject`,
`PutObject`, multipart upload actions, and `DeleteObject` for delete-marker
replication). A Lightsail control-plane-only policy is not enough; use a bucket access
key or an IAM policy that grants the required bucket/object actions. The `validate`
action checks both clients before a run is dispatched; provider authorization for each
operation is still enforced by the operation itself.

Each run persists:

* one run row keyed by an idempotency key;
* one object row per source key/version/delete marker;
* a short-lived object lease;
* a multipart upload row containing the upload id and completed-part ledger; and
* a manifest object under `.backupsheep/manifests/` in the destination prefix.

When source versions or delete markers are present, the destination bucket must have
native versioning enabled. This prevents an older source version from overwriting a
newer one and preserves delete-marker history. The destination key is otherwise the
configured destination prefix plus the source key relative to the source prefix.

The run endpoints are:

* `POST .../run/` — start or resume one idempotent run;
* `GET .../runs/` — list run status and manifest metadata;
* `GET .../runs/<run_id>/objects/` — inspect per-object progress;
* `POST .../validate/` — validate source and destination access;
* `POST .../restore/` — restore the current destination prefix to the Lightsail
  source bucket, optionally with `restore_prefix` and `target_prefix`; and
* `GET .../restores/` — inspect restore status.

Restore skips manifests, records completed source keys, and owns a restore lease. A
restart therefore resumes the same restore row and does not blindly re-write every
object. Restores are current-state prefix restores; selecting an historical object
version is intentionally not exposed by this endpoint.

## Crash and restart behavior

Celery tasks use late acknowledgement and reject-on-worker-loss where provider
transfers are performed. The API writes a run/restore row and task id before publishing
the message after the transaction commits. If publishing fails, the stale database
row is recovered by the next sweep.

The periodic tasks are:

* `sync_lightsail_bucket_replications` — creates due runs and dispatches them once;
* `resume_lightsail_bucket_replications` — requeues stale replication runs;
* `resume_lightsail_bucket_restores` — requeues stale restore rows; and
* `recover_stale_lightsail_bucket_leases` — releases expired object leases without
  deleting multipart progress.

The recovery task only takes over a stale row or an unclaimed pending row. A healthy
task id or unexpired lease is left alone. Requeued work keeps the same run id,
idempotency key, object state, and multipart upload id.

## Verification matrix

The focused suite is `apps.tests.test_lightsail_relational_database` plus
`apps.tests.test_lightsail_bucket_replication`:

| Case | Coverage | Result |
| --- | --- | --- |
| Managed database discovery | Pagination and normalized name/region/size fields | PASS |
| Snapshot create | Exact snapshot reuse and create-only-when-absent | PASS |
| Snapshot polling | `available`, transient lookup, and provider failure mapping | PASS |
| Database restore | Availability-zone and bundle fallback, accepted operation tracking | PASS |
| Database snapshot deletion | Native relational-database delete API | PASS |
| Version listing | Pagination, versions, and delete markers | PASS |
| Duplicate object delivery | Metadata/ETag identity prevents a second put | PASS |
| Multipart crash recovery | Completed parts resume with the same upload id | PASS |
| Run idempotency | Duplicate delivery produces one object transfer and one manifest | PASS |
| Prefix restore | Current object restore, manifest exclusion, durable completion | PASS |
| API idempotency | Commit-safe enqueue and one task for repeated idempotency keys | PASS |
| Worker recovery | Only stale runs/restores are requeued | PASS |
| Exception recovery | A task exception leaves the run resumable, not terminal | PASS |
| Repository regression | Full Django suite | 359/359 PASS |

Focused test command, after creating the manual Compose configuration and protected
`.secrets` files from the installation guide:

```bash
./backupsheep-compose build db app app-egress-guard rabbitmq
./backupsheep-compose --allow-reviewed-runtime-overrides --profile operations run --rm --no-deps -e DJANGO_SERVER=test --entrypoint python \
  worker-cloud manage.py test \
  apps.tests.test_lightsail_relational_database \
  apps.tests.test_lightsail_bucket_replication --noinput
```

Full regression command:

```bash
./backupsheep-compose --allow-reviewed-runtime-overrides --profile operations run --rm --no-deps -e DJANGO_SERVER=test --entrypoint python \
  worker-cloud manage.py test --noinput
```

## Provider references

* [Lightsail snapshots](https://docs.aws.amazon.com/lightsail/latest/userguide/understanding-snapshots-in-amazon-lightsail.html)
* [Lightsail relational database snapshot API](https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_CreateRelationalDatabaseSnapshot.html)
* [Lightsail restore-from-database-snapshot API](https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_CreateRelationalDatabaseFromSnapshot.html)
* [Amazon S3 versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html)
