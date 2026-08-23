# Backup sources

BackupSheep supports two backup-placement patterns:

- **Provider-native protection** creates a snapshot, image, recovery point, or
  managed backup inside the connected cloud account.
- **Archive protection** produces a local archive and uploads it to one or more
  configured storage destinations.

The tables below describe implemented routes, models, backup tasks, and console
flows. Provider plan, region, API, and permission limitations still apply.

## Cloud and provider-managed sources

| Provider | Protected resources | Backup placement | Tracked new-resource restore |
| --- | --- | --- | --- |
| DigitalOcean | Droplets and block volumes | Provider snapshots | Yes |
| AWS | EC2 instances and EBS volumes | EC2 images / EBS snapshots | Yes |
| AWS | Versioned S3 buckets and DynamoDB tables | AWS Backup recovery points | Yes |
| AWS RDS | RDS database instances | RDS snapshots | Yes |
| Amazon Lightsail | Instances, disks, and relational databases | Lightsail snapshots | Yes |
| Hetzner Cloud | Servers (primary-disk snapshot) | Provider snapshots | Yes |
| Vultr | Instances and block volumes | Provider snapshots | Yes |
| Vultr Managed Databases | PostgreSQL, MySQL, MariaDB, and Valkey clusters | Provider-managed backup metadata | Yes, as a new managed-database fork where the plan supports it |
| UpCloud | Servers and storage volumes | Provider templates / storage backups | Yes |
| Oracle Cloud | Compute instances and block volumes | Provider images / volume backups | Yes |
| Google Cloud | Compute instances and disks | Machine images / disk snapshots | Yes |
| OVH Public Cloud CA, EU, and US | Instances and volumes | Provider images / snapshots | Yes |

### AWS data resources

S3 and DynamoDB use AWS Backup rather than exporting their data to a
BackupSheep storage destination. An S3 source must have versioning enabled.
The restore workflow uses AWS Backup metadata and requires a new target: an
empty versioned bucket for S3 or a target table for DynamoDB.

### Lightsail variants

Lightsail instances and relational databases are represented as cloud nodes;
disks are volume nodes. Relational database backup and restore use the
Lightsail database API path, while instance/disk resources use snapshot paths.

Lightsail bucket replication is a separate API-operated feature. It copies a
bucket prefix, optionally including versions, into a supported destination,
tracks runs and per-object progress, supports fixed intervals from 1 minute to
7 days, and can copy a completed/failed replication run back to a target
prefix. It is not represented as a normal node schedule in the console.

### Vultr Managed Databases

BackupSheep discovers the engine, region, plan, status, detail, and usage
metadata. PostgreSQL, MySQL, MariaDB, and Valkey are accepted by the managed
database backup path. Point-in-time recovery is limited to PostgreSQL, MySQL,
and MariaDB; Valkey uses the base-backup fork mode. Hobbyist plans are rejected
for user-initiated fork/recovery. BackupSheep observes provider-managed backup
metadata and does not change Vultr's automatic backup schedule.

### Hetzner scope

A Hetzner server snapshot covers the server's primary disk. Attached Volumes
are not offered by Hetzner's snapshot API and are not separate Hetzner volume
nodes in BackupSheep. Networks, firewalls, IPs, load balancers, Storage Boxes,
and Storage Shares are not included in the server snapshot.

## Logical database archives

The Database source supports:

- MySQL;
- MariaDB;
- PostgreSQL.

Connections can be direct or run through SSH, with password, private-key, or
managed-public-key SSH authentication. Database configuration supports SSL,
one database or all databases, discovered database/table selection, stored
routine inclusion, and engine-specific dump options. The worker selects
version-aware database tools from the configured engine/version.

A database run creates a dump archive, validates the source artifact, and
uploads it to every selected storage destination. Restore defaults to a safe,
new database fork; see [Restores](restores.md).

## Website archives

Website connections support FTPS and SFTP. SFTP can use a password,
private key, or BackupSheep-managed public key. FTPS supports explicit TLS and
certificate-verification settings.

Plain FTP is retained only for legacy compatibility and is disabled by default. It
requires `ALLOW_INSECURE_FTP=true`; use it only after accepting that credentials and
backup data are exposed in transit.

A website node can protect selected paths or all paths and define include or
exclude rules using explicit lists, glob patterns, and regular expressions.
Two full-backup methods are modeled: worker-side file collection and a
server-side tar flow. Tar nodes can exclude version-control ignores,
version-control metadata, backup files, or caches.

Incremental mode maintains a per-node source cache so later runs fetch changed
content while still creating a complete archive. Resetting the incremental
cache forces the next run to rebuild it. Operators must budget local worker
disk for staging and the cache.

## WordPress

WordPress uses the BackupSheep WordPress connection/plugin flow and can protect:

- database and files together;
- database only;
- files only.

The resulting archive is uploaded to selected storage destinations. The
console offers download and transfer of completed copies, but it does not expose
an automatic WordPress restore action.

## Basecamp

Basecamp uses OAuth and can protect all projects or a selected project list.
The resulting archive is uploaded to selected storage destinations. Completed
copies can be downloaded or transferred; no automatic Basecamp restore action
is exposed in the node console.

## Not yet wired as backup sources

Zendesk and Slack exist in seed reference data, but the setup catalog marks
their source cards **Coming Soon** and there are no active source/backup routes
for them. They should not be treated as supported backup sources. Slack
notifications are a separate feature.

## Implementation references

- [Cloud source API routes](../../apps/api/v1/cloud/urls.py)
- [Volume source API routes](../../apps/api/v1/volume/urls.py)
- [Backup API routes](../../apps/api/v1/backup/urls.py)
- [Provider and source node models](../../apps/console/node/models.py)
- [Website and database connection models](../../apps/console/connection/models.py)
- [Provider source setup catalog](../../apps/console/_templates/console/setup/1_integration_select.html)
- [AWS S3/DynamoDB implementation](../../apps/console/node/models.py)
- [Vultr managed-database capabilities](../../apps/console/vultr_database.py)
- [Lightsail bucket replication API](../../apps/api/v1/cloud/lightsail_bucket_replication/views.py)
- [Removal of dead source integrations](../../apps/_migrations/0015_remove_dead_integrations.py)
