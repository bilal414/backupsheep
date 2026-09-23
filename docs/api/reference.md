# Endpoint reference

This is the human-oriented route map. The Bruno collection contains one runnable
request for every operation and a generated manifest that is checked against Django's
resolver.

All paths are relative to `/api/v1/`. `{id}` means the account-scoped BackupSheep
object ID, not a provider resource ID.

## Common operation notation

`CRUD` means the router exposes:

- `GET` and `POST` on the collection;
- `GET`, `PUT`, `PATCH`, and `DELETE` on `/{id}/`.

Some permissions or object state can still reject an operation.

## Identity and access

| Resource | Operations and actions |
|---|---|
| `auth/login/` | `POST` login and return the persistent token. |
| `auth/logout/` | `GET` end the browser session; token remains valid. |
| `auth/reset/` | `POST` request reset, `PATCH` complete reset. |
| `check/login/` | `GET` current login/member context. |
| `members/` | CRUD; setup/verify/revoke MFA, switch current account, update membership. |
| `accounts/` | CRUD; leave or remove a membership. |
| `groups/` | CRUD account groups, permissions, and node scope. |
| `invites/` | CRUD; accept, cancel, and resend. |
| `logs/` | Read-only account activity list. |

## Connections

Connection resources store or broker access to source systems. The aggregate
`connections/` resource supports CRUD plus `totals`, `pause`, `resume`, and `validate`.

Provider-specific connection families:

| Family | Extra discovery/actions |
|---|---|
| `connections/aws/` | CRUD, `endpoints`, `regions`, `objects`, `validate`. |
| `connections/aws_rds/` | CRUD, `endpoints`, `regions`, `objects`, `validate`. |
| `connections/lightsail/` | CRUD, `endpoints`, `regions`, `objects`, `validate`. |
| `connections/digitalocean/` | CRUD, `endpoints`, `POST oauth_url`, `objects`, `validate`. |
| `connections/ovh_ca/` | CRUD, `endpoints`, `POST oauth_url`, `objects`, `validate`. |
| `connections/ovh_eu/` | CRUD, `endpoints`, `POST oauth_url`, `objects`, `validate`. |
| `connections/ovh_us/` | CRUD, `endpoints`, `POST oauth_url`, `objects`, `validate`. |
| `connections/vultr/` | CRUD, `endpoints`, `objects`, `validate`. |
| `connections/hetzner/` | CRUD, `endpoints`, `objects`, `validate`. |
| `connections/upcloud/` | CRUD, `endpoints`, `objects`, `validate`. |
| `connections/oracle/` | CRUD, `endpoints`, `objects`, `validate`. |
| `connections/google_cloud/` | CRUD, `endpoints`, `objects`, `validate`. |
| `connections/database/` | CRUD, `endpoints`, `objects`, `update_db_type_and_version`, `validate`. |
| `connections/website/` | CRUD, `endpoints`, `objects`, `validate`. |
| `connections/basecamp/` | CRUD, `endpoints`, `objects`, `validate`. |

## Sources and nodes

The unified `nodes/` resource supports CRUD plus `totals`, `validate`, `pause`,
`resume`, deferred `delete`, `take_snapshot`, `backup_request_status`,
`restore_backup`, `restores`, `resume_restore`, and website `reset_incremental`.

Source families:

| Kind | Families | Common extras |
|---|---|---|
| Databases | `databases/` | CRUD, `connections`, `totals`. |
| Websites | `websites/` | CRUD, `connections`, `totals`. |
| SaaS | `saas/basecamp/` | CRUD, `connections`, `generate_key`, `totals`. |
| Cloud | `clouds/digitalocean/`, `aws/`, `vultr/`, `vultr_database/`, `ovh_ca/`, `ovh_eu/`, `ovh_us/`, `aws_rds/`, `lightsail/`, `lightsail_database/`, `hetzner/`, `upcloud/`, `oracle/`, `google_cloud/` | CRUD, `connections`, `totals`; Vultr servers also expose `automatic-backups`. |
| Volumes | `volumes/digitalocean/`, `aws/`, `vultr/`, `ovh_ca/`, `ovh_eu/`, `ovh_us/`, `lightsail/`, `upcloud/`, `oracle/`, `google_cloud/` | CRUD, `connections`, `totals`. |

### Lightsail bucket replication

`clouds/lightsail_bucket_replications/` exposes CRUD plus:

- `POST /{id}/validate/`
- `POST /{id}/run/`
- `GET /{id}/runs/`
- `GET /{id}/runs/{run_id}/objects/`
- `POST /{id}/restore/`
- `GET /{id}/restores/`

## Storage destinations

The aggregate `storage/` resource is read-oriented and adds `costs`, `validate`,
`pause`, `resume`, and deferred `delete`. `storage/all/` provides a unified read-only
list, detail, and totals view.

All 26 destination families are represented:

| API code | Destination | Common actions |
|---|---|---|
| `aws_s3` | Amazon S3 | CRUD, totals, chart data, regions, validate, lifecycle sync. |
| `do_spaces` | DigitalOcean Spaces | CRUD, totals, chart data, regions, validate. |
| `wasabi` | Wasabi | CRUD, totals, chart data, regions, validate. |
| `dropbox` | Dropbox | CRUD, totals, chart data, validate. |
| `google_drive` | Google Drive | CRUD, totals, chart data, validate. |
| `filebase` | Filebase | CRUD, totals, chart data, regions, validate. |
| `backblaze_b2` | Backblaze B2 | CRUD, totals, chart data, validate. |
| `linode` | Akamai/Linode Object Storage | CRUD, totals, chart data, validate. |
| `exoscale` | Exoscale Object Storage | CRUD, totals, chart data, regions, validate. |
| `vultr` | Vultr Object Storage | CRUD, totals, chart data, validate. |
| `upcloud` | UpCloud Object Storage | CRUD, totals, chart data, validate. |
| `oracle` | Oracle Object Storage | CRUD, totals, chart data, regions, validate. |
| `scaleway` | Scaleway Object Storage | CRUD, totals, chart data, regions, validate. |
| `pcloud` | pCloud | CRUD, totals, chart data, validate. |
| `onedrive` | Microsoft OneDrive | CRUD, totals, chart data, validate. |
| `cloudflare` | Cloudflare R2 | CRUD, totals, chart data, validate. |
| `leviia` | Leviia Object Storage | CRUD, totals, chart data, validate. |
| `google_cloud` | Google Cloud Storage | CRUD, totals, chart data, validate. |
| `azure` | Azure Blob Storage | CRUD, totals, chart data, validate. |
| `idrive` | IDrive e2 | CRUD, totals, chart data, validate. |
| `ionos` | IONOS Object Storage | CRUD, totals, chart data, regions, validate. |
| `alibaba` | Alibaba OSS | CRUD, totals, chart data, regions, validate. |
| `tencent` | Tencent COS | CRUD, totals, chart data, regions, validate. |
| `rackcorp` | RackCorp Object Storage | CRUD, totals, chart data, regions, validate. |
| `ibm` | IBM Cloud Object Storage | CRUD, totals, chart data, regions, validate. |
| `local` | Local or bind-mounted storage | CRUD, validate, file route (BSE1 direct download is refused). |

`highcharts` endpoints return console chart data and are kept for client compatibility;
new automation should prefer resource/status fields unless it specifically needs the
chart series.

## Backups and restores

Every backup family exposes list/create, detail CRUD, and `cancel`. Most expose
`highcharts` for console charts.

| Backup family | Additional actions |
|---|---|
| `backups/database/` | download, transfer log, restore, restore history, resume restore, retry, storage points. |
| `backups/website/` | download, directory tree, transfer log, restore, restore history, retry, storage points. |
| `backups/basecamp/` | download, transfer log, retry, storage points. |
| `backups/vultr_database/` | managed database restore. |
| `backups/digitalocean/` | provider snapshot CRUD, chart data, cancel. |
| `backups/aws/` | provider snapshot CRUD, chart data, cancel. |
| `backups/vultr/` | provider snapshot CRUD, chart data, cancel. |
| `backups/ovh_ca/`, `ovh_eu/`, `ovh_us/` | provider snapshot CRUD, chart data, cancel. |
| `backups/aws_rds/` | provider snapshot CRUD, chart data, cancel. |
| `backups/lightsail/` | provider snapshot CRUD, chart data, cancel. |
| `backups/hetzner/` | provider snapshot CRUD, chart data, cancel. |
| `backups/upcloud/` | provider snapshot CRUD, chart data, cancel. |
| `backups/oracle/` | provider snapshot CRUD, chart data, cancel. |
| `backups/google_cloud/` | provider snapshot CRUD, chart data, cancel. |

The archive-family `download` actions remain routed for API compatibility, but the stock
enterprise pipeline refuses direct download for BSE1 artifacts. The Local Storage file
route likewise returns a conflict for BSE1 rather than exposing ciphertext as a ZIP. Use
the authenticated database/website restore actions; Basecamp currently has no
authenticated BSE1 plaintext-export or automatic-restore action. Stock enterprise mode
therefore omits it from capability/connection choices and returns a generic HTTP `409`
recovery-unavailable refusal at new-connection, node, schedule, on-demand, retry, outbox,
and worker initiation boundaries. Durable outbox rows record
`SOURCE_RECOVERY_UNAVAILABLE`. Read/list and destructive retention operations remain
available for existing rows.

## Schedules, statistics, and notifications

| Resource | Operations and actions |
|---|---|
| `schedules/` | CRUD, `pause`, `resume`, `trigger`. |
| `stats/backups/` | Read-only 30-day backup activity series. |
| `notifications-email/` | CRUD, send verification email. |
| `notifications-slack/` | CRUD, validate. |
| `notifications-telegram/` | CRUD, validate. |

## Utility and callback routes

| Resource | Purpose |
|---|---|
| `utils/test/` | Authenticated API connectivity test. |
| `utils/ssh-host-keys/preview/` | Fetch and fingerprint SSH host keys for review. |
| `utils/ssh-host-keys/approve/` | Record an exact account-scoped SSH host-key approval and append its audit event. |
| `callback/slack/` | Complete Slack authorization. |
| `callback/digitalocean/` | Complete DigitalOcean authorization. |
| `callback/ovh/ca/`, `eu/`, `us/` | Complete regional OVH authorization. |
| `callback/dropbox/` | Complete Dropbox OAuth. |
| `callback/google_drive/` | Complete Google Drive OAuth. |
| `callback/google_cloud/` | Complete Google Cloud authorization. |
| `callback/pcloud/` | Complete pCloud OAuth. |
| `callback/microsoft/` | Complete OneDrive/Microsoft OAuth. |
| `callback/basecamp/` | Complete Basecamp OAuth. |

OAuth callbacks are browser-flow endpoints. Their presence in the Bruno manifest is
for completeness, not an instruction to replay authorization codes manually.
DigitalOcean and OVH authorization starts are POST-only. A cookie-authenticated console
request must carry Django's CSRF token; the POST deliberately replaces any older pending
transaction for that provider. Ordinary console GET rendering reuses a still-live state
bound to the same member and account, including its server-held PKCE verifier, and cannot
silently invalidate an authorization already in flight.
