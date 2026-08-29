# Provider and source matrix

This matrix is derived from the integrations, task modules, models, migrations and console
routes on `develop`. “Implemented” means the repository contains an operational path; it
does not certify every provider region, account policy, API version or live restore.

Provider-native backups remain in the provider account. Archive-producing sources write a
validated artifact to one or more configured [storage destinations](#storage-destinations).
All source and destination credentials saved through the console are account-scoped and
encrypted at rest in PostgreSQL.

## Archive-producing sources

| Source | Connection and backup | Restore behavior | Important limits |
| --- | --- | --- | --- |
| Website | Explicit/implicit FTPS or SFTP; selected remote paths; incremental mirror or full collection; ZIP plus file manifest sealed as BSE1 before handoff. Plain FTP is a default-off compatibility mode. | Storage publishes one selected BSE1 copy through the files reverse fence; files authenticates/decrypts and writes it to the configured website target. Overlay is default; optional exact mirror deletes target files absent from backup | SSH host keys are mandatory for SFTP. Server-side tar is an SFTP/SSH optimization, not a fourth protocol, and requires remote shell/tar permission. FTPS certificate verification is on by default. Plain FTP requires `ALLOW_INSECURE_FTP=true` and exposes credentials/data in transit. |
| Database | Direct or SSH-tunneled MySQL, MariaDB and PostgreSQL dumps; optional TLS; selected database; archive sealed as BSE1 | Storage publishes one selected BSE1 copy through the database reverse fence; database authenticates/decrypts. Console restore defaults to a deterministic new-database fork, while the API also has an explicit in-place mode | In-place restore changes target data. Fork restore needs target-creation privileges. Client compatibility, free space, locks and TLS/authentication must be rehearsed. |
| Basecamp | Stock enterprise/BSE1 mode hides the source and refuses new OAuth connections, nodes, schedules, runs, retries and worker replays. Explicit non-enterprise legacy compatibility can package an API snapshot as a plaintext archive | No enterprise automatic restore or authenticated plaintext-export action is implemented; direct BSE1 download is disabled and the transfer UI has no complete server action/task. Legacy compatibility uses the authenticated existing download action | Existing rows stay readable. Do not rely on Basecamp copies for enterprise recoverability until an authenticated BSE1 export/restore path is implemented and rehearsed. Compatibility requires the family flag, `legacy-only`, legacy restore enabled and enterprise mode disabled. |

### Database versions exposed by the model

- MySQL: 5.5, 5.6, 5.7, 8.0 and 8.4.
- MariaDB: 10.1 through 10.11, 11.4 and 11.8 as enumerated choices.
- PostgreSQL: 9 through 18 as enumerated choices.

The image contains Oracle MySQL 8.4 and MariaDB clients plus PostgreSQL clients 14–18.
PostgreSQL selects a compatible installed client where possible; an enumerated old server
version does not mean that the image contains that same old client binary. Verify the
actual server/client pair before relying on it.

### Website modes and authentication

Website authentication supports passwords, customer-supplied private keys and the optional
files-worker managed identity. Database SSH tunnels use the distinct database-worker
identity. In stock Compose, the private halves are
`.secrets/ssh_managed_files_private_key` and
`.secrets/ssh_managed_database_private_key`; each mode-`0444` source is granted only to its
worker lane, validated as Ed25519, and copied to that worker's private tmpfs as mode `0600`.
The app and other roles receive neither private key. Managed identities are available only
while the installation contains exactly one account; creating a second account atomically
disables and fences managed-key connections. Customer-supplied, account-scoped private keys
remain the multi-account option.

Reviewed host keys are account-scoped PostgreSQL approvals with append-only audit events.
For each operation, the worker receives only the exact current approval material in a
transient mode-`0600` private-runtime `known_hosts` file, which is deleted after use. Stock
Compose has no shared SSH-trust volume or global `known_hosts` file.

Incremental mode maintains a persistent per-node cache in the files lane's private
`files_workdir`; full mode
re-collects the selected tree. For eligible SFTP full backups, the server-side-tar path
creates a temporary remote tar over SSH, downloads it over SFTP, inventories it and
creates the final local ZIP. The worker cleans the temporary remote archive, but the
source account must have adequate shell, filesystem and tar permissions.

## Provider-native cloud sources

The general cloud restore model creates a **new** provider target and records the returned
resource ID. It does not overwrite the original. Target names/markers and request
fingerprints are persisted before create calls so an ambiguous response can reconcile to
one owned result or stop for manual review.

| Integration code | Selectable resources and backup form | Restore path in repository | Notes |
| --- | --- | --- | --- |
| `digitalocean` | Droplets and block volumes; provider snapshots | New droplet or volume from snapshot | Personal access token is supported; OAuth requires deployment-level app credentials. |
| `hetzner` | Cloud servers; provider snapshot of the server's primary disk | New server from snapshot | Attached Volumes are not covered by the snapshot and are not modeled as separate Hetzner volume nodes. Networks, firewalls, IPs, load balancers, Storage Boxes and Storage Shares are also outside this backup. |
| `upcloud` | Servers and storage volumes; boot-storage/volume backups | New storage volume or reconstructed server | Server restore persists source configuration, networking and firewall evidence and recreates through a multi-phase state machine. Unsupported/ambiguous topology fails closed. |
| `vultr` | Instances and block storage; provider snapshots | New instance or volume from snapshot | Uses bounded Vultr HTTP timeouts and ownership reconciliation. |
| `vultr` managed database resource | PostgreSQL, MySQL, MariaDB and Valkey provider-managed backup metadata | Forks a new managed database and polls it | Model/task type is `vultr_database`, nested under the Vultr connection. Point-in-time mode is limited to PostgreSQL/MySQL/MariaDB; Valkey uses base-backup fork mode, and unsupported plans fail closed. |
| `oracle` | OCI compute instances, boot volumes and block volumes; custom images or volume backups | New instance, boot volume or block volume | Compartment, availability domain, shape/subnet and exact OCID evidence are validated; ambiguous ownership stops for review. |
| `google_cloud` | Compute Engine instances and persistent disks; machine images or disk snapshots | New instance or disk | Connection carries project and zone; instance image is global while source instance/disk selection is zonal. |
| `ovh_ca`, `ovh_eu`, `ovh_us` | Public Cloud instances and volumes; native snapshots/images | New provider resource from snapshot | Each region uses its matching deployment-level OVH application key/secret plus connection credentials. |
| `aws` | EC2 instances and EBS volumes; AMIs/EBS snapshots | New EC2 instance or EBS volume | `no_reboot` controls EC2 image behavior. Restore persists marker/tag evidence and reconciles exact candidates. |
| `aws` | Versioned S3 buckets and DynamoDB tables through AWS Backup | Restores through an AWS Backup job to a distinct target; S3 requires an existing empty versioned bucket | Backup vault configuration and IAM permissions are required. Source/destination identity checks prevent an unsafe target. |
| `aws_rds` | RDS DB instances; manual DB snapshots | Creates a new DB instance from snapshot and polls to `available` | Target options include class, subnet group, Multi-AZ, public access, security groups, storage type/IOPS/throughput where compatible. |
| `lightsail` | Instances, disks and managed relational databases; native snapshots | New instance, disk or relational database | Provider operations are polled; the source is never overwritten. |
| `lightsail` bucket replication | Lightsail object-storage bucket/prefix copied to a supported destination | Prefix/object-version restore is durably tracked | Separate durable run/object/multipart leases. Destination support is narrower than the general storage list; see below. |

Provider snapshot schedules and on-demand requests use the same durable execution system.
Retention deletes provider-owned backup resources through the provider adapter; where a
delete outcome is ambiguous, preserve the row and reconcile instead of creating another
snapshot or deleting by display name.

### Lightsail bucket-replication destinations

The implementation accepts these destination storage codes:

`aws_s3`, `wasabi`, `do_spaces`, `filebase`, `exoscale`, `backblaze_b2`, `linode`,
`vultr`, `upcloud`, `oracle`, `scaleway`, `cloudflare`, `leviia`, `idrive`, `ionos`,
`rackcorp` and `ibm`.

Local Storage, Azure, Google Cloud Storage and OAuth drive destinations are not accepted
for this lane. Tencent COS and Alibaba OSS use dedicated adapters in the general storage
pipeline but are not accepted by the S3-compatible Lightsail replication adapter.

## Seeded but unavailable source integrations

Zendesk and Slack exist in reference seed data so their tiles and metadata can be shown,
but the setup UI labels both **Coming Soon** and does not provide an operational backup
workflow. Do not advertise them as supported sources. Slack notification delivery is a
separate implemented feature and does not back up a Slack workspace.

## Storage destinations

Archive-producing backups can fan out to multiple destinations. A storage-point row tracks
each copy independently so one destination can retry without losing the source backup's
overall history. Validation commonly performs live list/head and write/read/delete probes;
use a dedicated bucket/container/prefix and least-privilege credentials that permit the
operations BackupSheep actually performs.

| Code | Destination | Credential/API style | Repository-specific notes |
| --- | --- | --- | --- |
| `local` | Local Storage | Mounted filesystem; no provider credential | Root is `BS_LOCAL_STORAGE_PATH` (`/backups` in Compose). It must be durable; stock Compose grants the mount read/write only to `worker-storage` and grants no `/backups` mount to app, cloud, database, files, logs or Beat. |
| `aws_s3` | Amazon S3 | AWS access/secret key, region and bucket | Supports expected bucket owner, version-aware records, lifecycle transition settings and S3 Object Lock retention/legal hold. Presigned archive URLs are compatibility-only for explicitly enabled non-enterprise legacy artifacts; stock BSE1 direct download is refused. |
| `backblaze_b2` | Backblaze B2 | S3-compatible key/secret, endpoint and bucket | Uses S3-compatible multipart upload with provider-specific error normalization. |
| `wasabi` | Wasabi | S3-compatible key/secret, region/endpoint and bucket | Bucket must exist and match the selected service URL/region. |
| `do_spaces` | DigitalOcean Spaces | S3-compatible key/secret, region endpoint and bucket | Uses the regional Spaces endpoint. |
| `cloudflare` | Cloudflare R2 | S3-compatible token pair, account ID and bucket | Endpoint is derived as `<account>.r2.cloudflarestorage.com`. |
| `google_cloud` | Google Cloud Storage | Service-account/project material and bucket | Uses the native Google Cloud Storage adapter, not the Google Drive OAuth app. |
| `azure` | Azure Blob Storage | Azure storage account credential and container | Native Azure adapter; container identity is distinct from S3 buckets. |
| `dropbox` | Dropbox | Per-install OAuth app plus account OAuth grant | Requires `DROPBOX_APP_KEY`/`DROPBOX_APP_SECRET`; uploads are chunked. |
| `google_drive` | Google Drive | Per-install OAuth app plus account OAuth grant | Requires `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`. |
| `onedrive` | Microsoft OneDrive | Microsoft application registration plus account OAuth grant | Requires the `MS_*` OAuth configuration and exact public callback. |
| `pcloud` | pCloud | Per-install OAuth app plus account OAuth grant | Requires `PCLOUD_CLIENT_ID`/`PCLOUD_CLIENT_SECRET`. |
| `idrive` | IDrive e2 | S3-compatible key/secret, endpoint and bucket | Also provides the adapter path used for Hetzner Object Storage-compatible configuration. |
| `ibm` | IBM Cloud Object Storage | S3-compatible credential, endpoint, region and bucket | Configure the exact regional service endpoint. |
| `oracle` | Oracle Object Storage | S3-compatible customer secret, namespace endpoint and bucket | This is destination storage, separate from the OCI compute source integration. |
| `scaleway` | Scaleway Object Storage | S3-compatible key/secret, region endpoint and bucket | Region determines endpoint. |
| `linode` | Linode Object Storage | S3-compatible key/secret, cluster endpoint and bucket | Configure the bucket's cluster endpoint. |
| `vultr` | Vultr Object Storage | S3-compatible key/secret, regional endpoint and bucket | BackupSheep does not create the bucket during validation; use an existing lowercase DNS-safe name. |
| `upcloud` | UpCloud Object Storage | S3-compatible key/secret, endpoint and bucket | Destination storage is separate from UpCloud server/volume snapshots. |
| `exoscale` | Exoscale SOS | S3-compatible key/secret, zone endpoint and bucket | Configure the correct zone. |
| `filebase` | Filebase | S3-compatible key/secret and bucket | Current endpoint is `s3.filebase.io`. |
| `ionos` | IONOS S3 Object Storage | S3-compatible key/secret, endpoint and bucket | Configure the datacenter/region endpoint belonging to the bucket. |
| `leviia` | Leviia object storage | S3-compatible key/secret, endpoint and bucket | Uses the shared verified S3 adapter contract. |
| `rackcorp` | RackCorp object storage | S3-compatible key/secret, endpoint and bucket | Uses the shared verified S3 adapter contract. |
| `tencent` | Tencent Cloud Object Storage | Tencent secret ID/key, region and bucket | Dedicated Tencent adapter; not accepted by Lightsail bucket replication. |
| `alibaba` | Alibaba Cloud OSS | Alibaba access key/secret, endpoint and bucket | Dedicated Alibaba adapter; not accepted by Lightsail bucket replication. |

The application also has optional `S3_*` settings for legacy application-log object
storage. Those variables do not create a backup destination; destinations are configured
and validated through the Storage page/API.

## Destination behavior and immutability

- A successful upload records destination status and provider evidence such as size,
  checksum/ETag or object version where the adapter can prove it.
- Ciphertext transfer/restore uses a concrete storage-point row; losing one copy does not
  implicitly select an unrelated destination. Stock BSE1 direct browser download is
  refused.
- Retention is implemented per backup/destination relationship. A failed delete remains
  visible rather than being silently treated as deleted.
- Amazon S3 Object Lock is the implemented immutable-storage policy surface. Protected
  versions remain cataloged and a Beat task retries eligible deletes after retention or
  legal-hold conditions change.
- Provider-side lifecycle/cold tiers can make an object temporarily unavailable. Restore
  or thaw the object in the storage provider before requesting an authenticated
  BackupSheep restore when the adapter reports cold storage.

## Capability validation checklist

Before declaring a provider ready for an account:

1. create a narrowly scoped credential and record its account/project/region boundary;
2. connect and validate the exact source or destination in the console;
3. run an on-demand backup of a disposable, uniquely marked resource;
4. wait for every required storage copy or provider snapshot to finish;
5. restore to a new disposable target and verify data independently;
6. test retention/delete only against the owned test resource;
7. record correlation IDs and exact provider IDs, then clean up from the ledger.

A passing unit suite or connection test is not a live-provider restore certification.
