# Using BackupSheep

After [setup](first-run.md) you land on the console dashboard. The typical workflow:

## The dashboard

The console home page is a live overview of the current account:

- **Stat cards** — the headline numbers (nodes, backups, storage, schedules).
- **Storage bars** — per-destination usage at a glance.
- **Recent backups** — the latest finished runs with their status.
- **Failures needing attention** — failed backup runs to look into.
- **Upcoming runs** — what the scheduler fires next.
- **Activity feed** — the newest entries from the [activity log](#activity-log).

The dashboard respects the current account and, for non-owner members, the nodes
assigned to their groups. Its links take you straight to the relevant nodes,
schedules, and filtered activity log.

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

BackupSheep notifies on:

- **Backup succeeded** and **backup failed** (including "couldn't start" and
  "upload to storage failed").
- **Storage validation failed** — a destination failed its pre-backup check.
- **Restore started / completed / failed**.

Who gets what is decided in three layers:

- **Account + node toggles** — the account and each node each have their own
  *notify on success* / *notify on failure* switches; a notification goes out only
  when both allow it.
- **Per-member flags** — every membership has *notify on success* / *notify on
  failure* flags (chosen on the invite, editable later under **Settings → Users**).
  Only active memberships are emailed, and the account owner (primary member) is
  always included — they can't be opted out. Restore emails follow the same flags:
  "completed" goes to the success recipients, "started"/"failed" to the failure
  recipients.
- **Channels** — email is sent through the configured transactional provider
  (Postmark/Mailgun/SES). Under **Settings → Notifications** you can additionally
  connect **Slack** (OAuth with the `incoming-webhook` scope) and **Telegram**
  (a bot token in `.env`, plus the chat ID in the console); every connected
  Slack workspace / Telegram chat then receives the notifications. Each connected
  channel has Validate (sends a test message) and Remove buttons. These channels
  need their app credentials in `.env` (`SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET`,
  `SLACK_TOKEN_URL`, `TELEGRAM_BOT_KEY` — see
  [Configuration](configuration.md#notification-channels-slack--telegram-optional)); email
  notifications work without them.

## Monitoring runs & logs

Each backup records a status and a run log. Logs are kept on the local `_storage` volume
and pruned after `LOG_RETENTION_DAYS` (default 30) by the daily `delete_old_logs` task.

> **Known limitation:** the per-backup "transfer log" / "directory-tree log" *download*
> buttons are not available in the self-hosted build (they were tied to SaaS-hosted log
> buckets) and return a "not available" message instead. The run status and history in the
> console are unaffected. See [Troubleshooting](troubleshooting.md).

## Team accounts, groups & permissions

One BackupSheep account can have many members — your own team, or clients who should
only see their own nodes. Everything lives under **Settings**: **Invites**, **Users**,
and **Groups**.

### Inviting members & clients

**Settings → Invites** → enter first/last name and email, pick the groups the person
will join, set their notification flags, and send. BackupSheep emails a public accept
link (`/invite/<uuid>/`):

- **New users** sign up right on that page (name + password) and land in the console,
  already enrolled.
- **Existing users** log in with the invited email and accept; the new account appears
  in their account switcher and becomes the current one.

Accept links are valid for **7 days**. From the same page, a pending invite can be
**resent** (restarts the 7-day window and re-sends the email) or **cancelled** (the
link stops working immediately). Links that lapse flip to *Expired* automatically, and
only pending invites can be resent or cancelled. The Invites page also lists invites
sent to *your own* email that you haven't accepted yet.

> Without a configured email provider the invite is still created but the email can't
> be delivered — configure one, then use **Resend**. See
> [Troubleshooting](troubleshooting.md#accounts--access).

### Groups & permissions

**Settings → Groups** manages the account's groups. A group has a **type** — **Team**
for staff, **Client** for customers — a name, optional notes, a set of permissions,
and an optional list of nodes it applies to:

- **Node scoping** — a group with **no nodes selected grants access to all nodes**;
  select specific nodes to scope the group to just those.
- **Permissions** — granular switches: `backup_create`, `backup_download`,
  `backup_delete`, `schedule_changes`, `node_changes`, `integration_changes`,
  `storage_changes`, plus notification permissions (`notify_on_success`,
  `notify_on_fail`, `notify_via_email`, `notify_via_slack`, `notify_via_telegram`).
- The **account owner** (the primary member created by the setup wizard) always has
  full access; every other member gets exactly the permissions of the groups they're
  enrolled in.
- A group can't be deleted while it still has members — remove them first.

Manage the members themselves under **Settings → Users**: change which groups a
member belongs to and their per-member notification flags (owner only).

## Activity log

**Logs** in the console sidebar is the account-wide audit trail. Each entry has a
**type** — GENERIC, NODE, CONNECTION, BACKUP, MEMBER, SCHEDULE, STORAGE, RESTORE or
AUTH — a human-readable message, and optional detail (the related node, integration
or backup, an error, the acting user's email). Sign-ins are tracked too: successful
and failed logins are recorded as AUTH entries with the client IP.

The page filters by type, node and integration, and has free-text search over the
message and error fields; node and backup pages deep-link into pre-filtered views.
Entries are kept for `LOG_RETENTION_DAYS` (default 30) and pruned daily at 03:30 by
the `delete_old_db_logs` beat task — see [Scaling](scaling.md#maintenance-tasks).
