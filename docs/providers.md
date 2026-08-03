# Providers

BackupSheep separates **sources** (what you back up) from **storage destinations** (where
offsite backups are stored). Both catalogs are seeded automatically on first install.

## Backup sources

### Cloud server & volume snapshots
Snapshot your instances/volumes through the provider's API. Connect with the provider's
API token/key (entered in the UI); OVH and OAuth-based DigitalOcean connections need app
credentials in `.env` (see [Configuration](configuration.md)).

| Provider | Code |
|----------|------|
| DigitalOcean | `digitalocean` |
| Amazon Web Services — EC2/EBS, S3, DynamoDB | `aws` |
| Amazon Web Services — RDS | `aws_rds` |
| Amazon Lightsail | `lightsail` |
| Hetzner Cloud (server primary disks) | `hetzner` |
| Vultr | `vultr` |
| UpCloud | `upcloud` |
| Oracle Cloud | `oracle` |
| Google Cloud | `google_cloud` |
| OVH Public Cloud — CA / EU / US | `ovh_ca` / `ovh_eu` / `ovh_us` |

### Databases (offsite dumps)
The **Database** source (`database`) dumps and stores your databases offsite:

- **PostgreSQL** — via version-matched `pg_dump` (clients for PG 14–18 ship in the image).
- **MySQL / MariaDB** — MySQL targets use the bundled Oracle MySQL 8.4 client
  (`/opt/mysql/bin`); MariaDB targets use `mariadb-dump` / `mysqldump`.

### Websites / servers (offsite file backups)
The **Website** source (`website`) backs up files from any Linux host over **FTP, FTPS,
SFTP, or SSH** (transfers use `lftp`). Per-connection FTPS TLS verification is supported.
Backups can run in **incremental** mode (after the first run only new/changed files are
downloaded, into a per-node local cache — every backup is still a complete zip) or
**full** mode (re-download everything every run); see
[Usage → Website backup modes](usage.md#website-backup-modes).

### SaaS apps
- **WordPress** (`wordpress`)
- **Basecamp** (`basecamp`) — needs a 37signals OAuth app (`BASECAMP_CLIENT_ID/SECRET`).

> `zendesk` and `slack` rows are seeded but their console tiles are disabled
> in this build; treat them as experimental/not wired.

Hetzner Cloud snapshots/backups cover only a server's primary disk. Attached
Volumes, networks, firewalls, IPs, Load Balancers, Storage Boxes, and Storage
Shares are dependencies to recreate or back up separately; they are not included
in a Hetzner server snapshot. The `hetzner` source currently creates on-demand
server snapshots; it does not import or manage Hetzner's automatic-backup window
configuration. Hetzner Cloud Volumes have no native snapshot API.

## Storage destinations

Connect one or more; a backup can be copied to several at once. **Object-storage**
providers just need an access key, secret, bucket, and (for non-AWS) an endpoint/region,
all entered in the UI. **OAuth** providers (Dropbox, Google Drive, OneDrive, pCloud) need
an app registered with the provider and its credentials in `.env` first. **Local
Storage** needs neither — backups stay on a disk path of the BackupSheep server itself
(`/backups`, overridable via `BS_LOCAL_STORAGE_PATH`).

| Storage | Code | Type |
|---------|------|------|
| Local Storage | `local` | local disk (`BS_LOCAL_STORAGE_PATH`) |
| Amazon S3 | `aws_s3` | object (keys in UI) |
| Backblaze B2 | `backblaze_b2` | object |
| Wasabi | `wasabi` | object |
| Cloudflare R2 | `cloudflare` | object |
| DigitalOcean Spaces | `do_spaces` | object |
| Google Cloud Storage | `google_cloud` | object |
| Azure Blob Storage | `azure` | object |
| IDrive e2 | `idrive` | object |
| Hetzner Object Storage | `idrive` with a Hetzner S3 endpoint | object |
| IBM Cloud Object Storage | `ibm` | object |
| Oracle Object Storage | `oracle` | object |
| Scaleway Object Storage | `scaleway` | object |
| Linode Object Storage | `linode` | object |
| Vultr Object Storage | `vultr` | object |
| UpCloud Object Storage | `upcloud` | object |
| Exoscale SOS | `exoscale` | object |
| Filebase | `filebase` | object |
| IONOS S3 | `ionos` | object |
| Leviia | `leviia` | object |
| RackCorp | `rackcorp` | object |
| Tencent COS | `tencent` | object |
| Alibaba Cloud OSS | `alibaba` | object |
| Dropbox | `dropbox` | OAuth (`DROPBOX_APP_*`) |
| Google Drive | `google_drive` | OAuth (`GOOGLE_CLIENT_*`) |
| Microsoft OneDrive | `onedrive` | OAuth (`MS_*`) |
| pCloud | `pcloud` | OAuth (`PCLOUD_CLIENT_*`) |

OAuth credentials and how to obtain them are listed in
[Configuration → Storage-provider OAuth](configuration.md#storage-provider-oauth-only-for-the-providers-you-use).

Hetzner Object Storage is S3-compatible rather than part of the Hetzner Cloud API.
Use the endpoint-based `idrive` S3 adapter with one of Hetzner's documented
endpoints (`fsn1.your-objectstorage.com`, `nbg1.your-objectstorage.com`, or
`hel1.your-objectstorage.com`), the bucket name, and the Hetzner Object Storage
access/secret key pair. The create-only live test also exercises bucket creation,
object round-tripping, listing, deletion, and exact-prefix cleanup; see
[`docs/hetzner-object-storage-e2e-test-outline.md`](hetzner-object-storage-e2e-test-outline.md).
BackupSheep does not attempt unsupported S3 replication or restore operations
against Hetzner Object Storage; use versioning/Object Lock and an independent
cross-location copy when the retention policy requires it.
