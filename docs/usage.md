# Using BackupSheep

After [setup](first-run.md) you land on the console dashboard. The typical workflow:

## 1. Add a storage destination

**Storage** → choose a provider → enter its credentials (object-storage: access key,
secret, bucket, endpoint/region; OAuth: connect via the provider). You can add several;
each backup can be pushed to more than one destination. See [Providers](providers.md).

**Local Storage** needs no credentials: backups are kept as plain zip files under the
server's local storage root (`/backups` in the Compose stack — see
[Configuration](configuration.md#local-storage-backup-destination-optional)). The
optional *Path* field scopes the destination to a subdirectory of that root. Downloads
of local backups are streamed through the BackupSheep app itself (no pre-signed URL,
since there is no external provider), so downloading large backups ties up an app
worker for the duration. Deleting a backup normally removes its file from disk; enable
*Keep backups on delete* (`no_delete`) to leave the zips in place and only drop
BackupSheep's record of them.

## 2. Connect a source

**Integrations / Sources** → pick a provider → create a *connection* with its credentials.
A connection exposes the things you can back up (the *nodes*):

- **Cloud** connections list your servers/volumes to snapshot.
- **Website** connections define an FTP/FTPS/SFTP/SSH target and the paths to back up.
- **Database** connections define a database server and which databases to dump.

When the **Backup Server** is *Self-hosted* (this BackupSheep server runs the backups),
its detected public IPv4/IPv6 are shown in the dropdown — add those to your source
servers' firewall allow lists so the backups can connect.

Validate the connection, then select the node(s) you want to protect.

## 3. Schedule backups

For each node, create a **schedule**. Schedules are driven by Celery beat and support
cron, fixed-interval, and one-time runs. You can also trigger a backup on demand.

When a scheduled backup fires:

- **Cloud** snapshots are created through the provider's API (the snapshot lives in your
  cloud account); BackupSheep polls until it's complete.
- **Database / website** backups are dumped locally by a worker, then uploaded to every
  configured storage destination, and the local working copy is cleaned up.

## Website backup modes

Website (file) nodes support two backup modes:

- **Incremental (recommended)** — the first backup downloads everything; later backups
  only download new/changed files over FTP/FTPS/SFTP. A per-node snapshot cache lives in
  `_storage/website_cache/`, but every backup is still a complete, restorable zip. Files
  deleted on the server propagate to the next backup. The cache rebuilds itself
  automatically if connection or path settings change; use the reset action on the node
  page to force a full re-download. The cache needs local disk roughly equal to the site
  size.
- **Full** — re-downloads all files on every backup (the previous behavior).

## 4. Retention

Attach a **retention policy** to keep a chosen number of daily / weekly / monthly backups.
After each run, older backups beyond the policy are pruned automatically (cloud snapshots
are deleted via the provider API; offsite copies are deleted from storage).

## 5. Restore / download

**One-click restores (website + database).** Open the node, find the backup, and click
**Restore**. Pick the storage copy to restore from, confirm, and BackupSheep fetches the
zip and puts the data back:

- **Website** — the files are pushed back onto the server, overwriting files that
  differ. Enable *Delete files on the server that are not present in this backup* for an
  exact-mirror restore. (Incremental nodes need no extra step — the snapshot cache
  re-syncs from the server on the next backup.)
- **Database** — each dump is imported with the native client; databases that no longer
  exist are created automatically. Dumps made without `DROP TABLE` statements
  (`--skip-opt`) may need an empty database to import into.

Restores are tracked runs: the modal shows live status and recent restore history, and a
redacted run log is kept at `_storage/restore_<backup-uuid>.log`. A restore never deletes
or alters the backup itself, and cold (Glacier/Deep Archive) copies must be thawed with
the storage provider first.

**Download instead.** The **Download** button generates a time-limited URL from the
storage destination (Local Storage backups stream through the BackupSheep app), so you
can restore manually: import the SQL dump into your database / extract the files.

- **Cloud snapshots** — restore from the snapshot through your cloud provider (e.g. create
  a new droplet/instance/volume from it), the same as any provider snapshot.

## Notifications

BackupSheep can notify on backup success/failure via email (if an email provider is
configured) and Slack / Telegram. Configure these from the console settings.

## Monitoring runs & logs

Each backup records a status and a run log. Logs are kept on the local `_storage` volume
and pruned after `LOG_RETENTION_DAYS` (default 30) by the daily `delete_old_logs` task.

> **Known limitation:** the per-backup "transfer log" / "directory-tree log" *download*
> buttons are not available in the self-hosted build (they were tied to SaaS-hosted log
> buckets) and return a "not available" message instead. The run status and history in the
> console are unaffected. See [Troubleshooting](troubleshooting.md).
