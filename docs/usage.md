# Using BackupSheep

After [setup](first-run.md) you land on the console dashboard. The typical workflow:

## 1. Add a storage destination

**Storage** → choose a provider → enter its credentials (object-storage: access key,
secret, bucket, endpoint/region; OAuth: connect via the provider). You can add several;
each backup can be pushed to more than one destination. See [Providers](providers.md).

## 2. Connect a source

**Integrations / Sources** → pick a provider → create a *connection* with its credentials.
A connection exposes the things you can back up (the *nodes*):

- **Cloud** connections list your servers/volumes to snapshot.
- **Website** connections define an FTP/FTPS/SFTP/SSH target and the paths to back up.
- **Database** connections define a database server and which databases to dump.

Validate the connection, then select the node(s) you want to protect.

## 3. Schedule backups

For each node, create a **schedule**. Schedules are driven by Celery beat and support
cron, fixed-interval, and one-time runs. You can also trigger a backup on demand.

When a scheduled backup fires:

- **Cloud** snapshots are created through the provider's API (the snapshot lives in your
  cloud account); BackupSheep polls until it's complete.
- **Database / website** backups are dumped locally by a worker, then uploaded to every
  configured storage destination, and the local working copy is cleaned up.

## 4. Retention

Attach a **retention policy** to keep a chosen number of daily / weekly / monthly backups.
After each run, older backups beyond the policy are pruned automatically (cloud snapshots
are deleted via the provider API; offsite copies are deleted from storage).

## 5. Restore / download

- **Offsite backups (database/website)** — download a finished backup from the console; it
  generates a time-limited (pre-signed) URL from the storage destination. Restore by
  importing the dump into your database / extracting the files.
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
