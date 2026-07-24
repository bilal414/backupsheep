# Immutable backups, ransomware protection, and storage cost controls

BackupSheep can protect an **Amazon S3** destination with S3 Object Lock, preserve a
designated air-gapped copy, automatically transition older archives to a colder S3
storage class, and project storage costs from rates you supply.

This feature is intentionally conservative: when a backup is protected, BackupSheep
keeps its catalog entry and leaves the remote object restorable. It does not create a
delete marker or pretend that an immutable object was deleted.

## Configure immutable S3 backups

1. Create or choose an Amazon S3 bucket with **Object Lock enabled**. S3 Object Lock
   requires bucket versioning; AWS enables versioning as part of Object Lock.
2. In **Integrations → Amazon S3**, enter the bucket, folder prefix, and credentials.
3. Select an Object Lock mode and a retention period in days.
4. Save and validate the destination. For an Object Lock destination BackupSheep checks
   the bucket's Object Lock configuration without writing a disposable test object that
   could become immutable.

Every new backup uploaded to that destination receives an object-level retention date.
BackupSheep records the S3 object version ID and retention metadata after upload, then
uses that specific version ID when cleanup is allowed. This avoids creating a bare S3
delete marker in a versioned bucket.

Choose the lock mode deliberately:

- **Governance** protects objects unless an actor has the AWS permission to bypass
  governance retention.
- **Compliance** cannot be bypassed before the retention date. Use this for the
  strongest ransomware protection.

An S3 Object Lock legal hold and any unexpired retention date always defer BackupSheep
cleanup. The normal schedule `keep_last` value therefore describes the desired catalog
retention, while S3 Object Lock remains the authoritative minimum retention period.

## Air-gapped copy policy

An air-gapped copy is a separately designated Amazon S3 destination. Enabling it
requires:

- Object Lock **Compliance** mode;
- a positive object-retention period;
- the destination bucket's expected 12-digit AWS account ID; and
- BackupSheep deletion protection (set automatically).

For actual isolation, use a bucket in a separate AWS account with narrowly scoped
credentials and an account/bucket policy that does not allow the production backup
credentials to remove retention or delete versions. The expected owner value pins every
S3 call to that account; it is not a substitute for a separate account or IAM boundary.

On a schedule, enable **Require a selected air-gapped copy for every backup** and select
at least one air-gapped destination. BackupSheep validates it before starting the source
backup. If the protected destination is missing, paused, or cannot validate, it does not
start that scheduled backup.

## Lifecycle tiering

For an Amazon S3 destination, set a non-empty folder prefix, a number of days, and the
target class: Standard-IA, One Zone-IA, Intelligent-Tiering, Glacier Instant Retrieval,
Glacier Flexible Retrieval, or Glacier Deep Archive.

BackupSheep creates one S3 lifecycle rule scoped to that prefix. It reads the bucket's
existing lifecycle configuration, replaces only its own `backupsheep-storage-<id>-lifecycle`
rule, and preserves all other customer-owned rules. Clearing the tiering fields removes
only that BackupSheep rule.

S3 transitions are performed asynchronously by AWS. A lifecycle transition does not
shorten an Object Lock retention period. Archives in Glacier Flexible Retrieval or Deep
Archive may require a restore job before download; BackupSheep requests that restore
when needed.

## Cost projections

Rates are not hard-coded because S3 price varies by region, storage class, agreement,
and transfer/retrieval pattern. For each destination, enter your actual USD rates for:

- standard storage per GiB-month;
- cold storage per GiB-month; and
- retrieval per GiB.

The dashboard shows recorded backup bytes and projected monthly storage cost by both
destination and source. It treats an archive older than the configured lifecycle age as
cold for estimation and also shows the estimated charge for retrieving all currently
recorded data once. Provider invoices remain authoritative.

The REST API exposes the same report at `GET /api/v1/storage/costs/`. S3 lifecycle rules
can be re-applied after an IAM or bucket-policy change with
`POST /api/v1/storage/aws_s3/<storage-id>/sync_lifecycle/`.

## Required S3 access

The S3 principal needs normal object write/read access. Protected and lifecycle-enabled
destinations also need the relevant S3 Object Lock and lifecycle configuration access,
including bucket Object Lock configuration reads, object retention/legal-hold reads,
and lifecycle configuration read/write. It must be able to read object headers to record
the exact uploaded version. Do not grant `s3:BypassGovernanceRetention` unless there is
a specific, reviewed operational reason.

S3-compatible providers are still supported as ordinary backup destinations, but this
implementation uses Amazon S3's Object Lock and lifecycle APIs. Do not assume an
S3-compatible provider offers the same immutability guarantees unless its own
documentation explicitly confirms them.
