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
or route from caches and deployment artifacts. Then set this installation value:

```dotenv
WORDPRESS_INTEGRATION_ENABLED=true
```

Recreate the BackupSheep application and relevant worker containers. Validation must
return protocol `2` and both active-plugin checks. A missing protocol marker, redirect,
HTTP target, private/metadata target outside the explicit allowlist, invalid signature,
stale timestamp, repeated nonce, changed body, or changed route fails closed.

Before enabling scheduled WordPress work, inspect the reverse-proxy, CDN, WordPress,
and application logs and prove that neither the integration key nor HTTP Basic password
appears in a URL. Exercise validate, backup, status, file listing, authenticated direct
download, and deletion on disposable data. There is no v1 compatibility fallback.
