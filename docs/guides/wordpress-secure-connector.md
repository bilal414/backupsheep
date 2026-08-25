# WordPress secure connector v2

WordPress backup operations are disabled by default. Do not enable them against the
legacy public plugin: that protocol placed its bearer key in the URL and used GET for
state-changing operations.

The reviewed v2 connector is in
`integrations/wordpress/backupsheep-v2/backupsheep.php`. Build its deterministic ZIP
from an exact reviewed release checkout:

```bash
python3 scripts/build_wordpress_plugin.py --output /tmp/backupsheep.zip
sha256sum /tmp/backupsheep.zip
```

The archive deliberately uses the existing `backupsheep/` WordPress plugin slug. In
the WordPress administrator, install the ZIP and confirm replacement of the old
BackupSheep plugin rather than installing both versions side by side. Confirm that
UpdraftPlus is active, activate **BackupSheep Secure Connector**, and paste a newly
generated integration key under **Settings > BackupSheep**. The plugin never displays
the stored key again.

Rotate the old integration key during this replacement. Remove any legacy plugin copy
or route from caches and deployment artifacts. WordPress still has no authenticated BSE1
export or automatic restore, so stock enterprise mode keeps it unavailable even with the
connector installed. Only a separately reviewed non-enterprise compatibility deployment
may set all four values below:

```dotenv
WORDPRESS_INTEGRATION_ENABLED=true
BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=false
BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE=legacy-only
BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=true
```

That opt-in creates legacy plaintext artifacts for the existing authenticated download
action; it is not an enterprise recovery claim. Existing WordPress records remain visible
when the gate is closed, but new connections, nodes, schedules, runs, retries, outbox
dispatches, and replayed worker tasks are refused.

Recreate the application with `app-egress-guard` as an exact pair. If operations are
already authorized, review durable work and provider side effects, recreate all five
operations guard/worker pairs together, and then start Beat separately; use the exact
[paired lifecycle commands](../../deploy/egress/README.md#paired-lifecycle-commands).
Never recreate an app or worker alone. Validation must return protocol `2` and both
active-plugin checks. A missing protocol marker, redirect, HTTP target, private/metadata
target outside the explicit allowlist, invalid signature, stale timestamp, repeated
nonce, changed body, or changed route fails closed.

Before enabling scheduled WordPress work, inspect the reverse-proxy, CDN, WordPress,
and application logs and prove that neither the integration key nor HTTP Basic password
appears in a URL. Exercise validate, backup, status, file listing, authenticated direct
download, and deletion on disposable data. Every download body is signed with the
backup UUID, and the connector serves only that run's exact UpdraftPlus logfile or
exact UUID-scoped backup file set. There is no v1 compatibility fallback.
