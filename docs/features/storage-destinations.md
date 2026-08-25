# Storage destinations

Storage destinations receive authenticated BSE1 ciphertext artifacts produced for
website, logical database, WordPress, and Basecamp nodes. One run can target multiple
destinations; uploads are dispatched independently and finalized only after all accepted
destination states are terminal. Destination workers store ciphertext and do not receive
the source-lane KMS identity needed to decrypt it.

## Destination catalog

The current seeded catalog and API implementation contain 26 destinations.

| Destination | Code | Connection style |
| --- | --- | --- |
| Local Storage | `local` | Disk on the BackupSheep server |
| Amazon S3 | `aws_s3` | AWS S3 API |
| Backblaze B2 | `backblaze_b2` | Object storage |
| Wasabi | `wasabi` | S3-compatible object storage |
| DigitalOcean Spaces | `do_spaces` | S3-compatible object storage |
| Cloudflare R2 | `cloudflare` | S3-compatible object storage |
| Google Cloud Storage | `google_cloud` | Google Cloud credentials/OAuth |
| Azure Blob Storage | `azure` | Azure Blob API |
| Dropbox | `dropbox` | OAuth drive storage |
| Google Drive | `google_drive` | OAuth drive storage |
| Microsoft OneDrive | `onedrive` | OAuth drive storage |
| pCloud | `pcloud` | OAuth drive storage |
| IDrive e2 | `idrive` | S3-compatible object storage |
| IBM Cloud Object Storage | `ibm` | S3-compatible object storage |
| Oracle Object Storage | `oracle` | Object storage |
| Scaleway Object Storage | `scaleway` | S3-compatible object storage |
| Linode Object Storage | `linode` | S3-compatible object storage |
| Vultr Object Storage | `vultr` | S3-compatible object storage |
| UpCloud Object Storage | `upcloud` | S3-compatible object storage |
| Exoscale SOS | `exoscale` | S3-compatible object storage |
| Filebase | `filebase` | S3-compatible object storage |
| IONOS S3 | `ionos` | S3-compatible object storage |
| Leviia | `leviia` | S3-compatible object storage |
| RackCorp | `rackcorp` | S3-compatible object storage |
| Tencent COS | `tencent` | Object storage |
| Alibaba Cloud OSS | `alibaba` | Object storage |

Provider-specific fields vary, but typically include a bucket/container, prefix,
region or endpoint, and credentials. OAuth destinations require the operator to
configure the corresponding application credentials in BackupSheep before
connecting an account.

## Validation and status

A destination can be active, pending, suspended, paused, or pending deletion.
Validation calls the destination-specific adapter. Normal object destinations
generally perform an access/write/read/delete probe. Deletion-protected Amazon
S3 destinations use a bucket/head or Object Lock capability check instead, so
validation does not create an object that BackupSheep cannot clean up.

Storage credentials are write-only in API serializers. Reads expose whether a
credential is configured rather than returning encrypted or decrypted values.

## Multi-destination result rules

For archive-producing backups, BackupSheep creates one storage point per
accepted destination and uploads them in parallel. The final status is:

- **Complete** when every requested destination succeeds;
- **Partial** when at least one destination succeeds and at least one fails;
- **Upload Failed** when no destination succeeds.

An early or duplicated finalizer waits while any destination remains in an
upload state. Partial runs remain usable from their completed storage points and
count toward the schedule's `keep_last` policy.

The console still renders a transfer surface, but the current server has no complete
transfer action/task; do not depend on it. Direct browser/ZIP downloads are disabled for
BSE1 artifacts: BackupSheep does not expose a provider URL or stream Local Storage
ciphertext through the application as if it were a ZIP. Use an authenticated restore, in
which storage publishes a fenced ciphertext handoff to the exact database or files lane
and that source lane authenticates and decrypts it. A completed upload is not a substitute
for a tested restore.

## Local Storage

Local Storage writes BSE1 ciphertext artifacts under `LOCAL_STORAGE_ROOT`. Stock Compose
sets that root to `/backups` and mounts it read/write only in `worker-storage`; app and the
source workers receive no `/backups` mount. Its optional path is a relative subdirectory;
absolute paths and traversal outside the root are rejected. Validation creates the
directory if needed and confirms local write/read/delete behavior. A `no_delete` option
allows BackupSheep records to be removed without deleting the underlying ciphertext
object.

Local Storage is convenient for evaluation and nearby recovery, but it does not
isolate data from failure of the BackupSheep host. Use an independent remote
destination when that failure mode matters.

## Amazon S3 immutability and lifecycle controls

Amazon S3 has additional destination-level controls:

- Object Lock in Governance or Compliance mode with a retention period;
- expected 12-digit bucket-owner verification;
- deletion protection;
- lifecycle transition after a configured age to Standard-IA, One Zone-IA,
  Intelligent-Tiering, Glacier Instant Retrieval, Glacier Flexible Retrieval,
  or Glacier Deep Archive;
- an `is_air_gapped` designation used by schedule policy.

An air-gapped designation requires Compliance mode, a positive retention
period, an expected bucket owner, and deletion protection. BackupSheep enforces
those configuration requirements, but actual isolation also requires an
appropriate separate-account/IAM/bucket-policy design.

Lifecycle management requires a non-empty prefix. BackupSheep owns one rule for
the destination, merges that rule with existing lifecycle configuration, and
leaves unrelated customer rules in place. S3 transitions are asynchronous and
cold classes may need provider-side thawing before download or restore.

## Retention and protected copies

Normal backup deletion and `keep_last` cleanup remove the associated remote
copy when the adapter permits it. An S3 Object Lock retention date or legal hold
can defer cleanup. Air-gapped destinations and destinations marked `no_delete`
are excluded from protected-copy cleanup; BackupSheep preserves their catalog
state so the copy remains discoverable.

## Usage and cost projections

Each destination can store operator-entered USD rates for standard storage,
cold storage, and retrieval per GiB. The owner dashboard and storage-cost API
aggregate successful storage points by destination and source. For a configured
S3 lifecycle age, old recorded bytes are estimated at the cold rate.

These figures are planning estimates. They do not inspect provider invoices,
discounts, minimum storage duration, request charges, taxes, or asynchronous
transition completion.

## Implementation references

- [Seeded destination catalog](../../apps/_migrations/seed_data/reference_data.json)
- [Storage API routes](../../apps/api/v1/storage/urls.py)
- [Storage models, validation, local paths, and cost summary](../../apps/console/storage/models.py)
- [Storage task dispatch and finalization](../../apps/_tasks/integration/storage/tasks.py)
- [S3 serializer policy enforcement](../../apps/api/v1/storage/aws_s3/serializers.py)
- [S3 upload, integrity, and deletion behavior](../../apps/_tasks/integration/storage/aws_s3.py)
- [Protected-copy cleanup task](../../apps/_tasks/helper/maintenance.py)
- [Credential-safe storage serializers](../../apps/api/v1/storage/serializers.py)
