"""Remove the dead Linode (cloud) and Intercom integrations.

The Linode CLOUD integration (server/volume snapshots) was seeded and advertised but
never implemented -- its model/API scaffolding was empty and has now been removed from
the codebase. The Linode OBJECT STORAGE destination is a separate, working feature and
is intentionally NOT touched (its `linode` core_storage_type row and CoreStorageLinode
stay). The Intercom SaaS integration was likewise dead: its OAuth callback was a broken
copy of the Basecamp one (referencing settings that don't exist) and no backup
implementation ever existed.

This migration, in order:

  1. Data cleanup on EXISTING installs: deletes the seeded `linode` (cloud) and
     `intercom` core_integration rows together with their
     core_connection_location_mtm_integrations links (both FKs are PROTECT, so links
     go first). No-op when the rows are absent; an integration row is also kept if a
     connection somehow references it, to avoid destroying user data. Fresh installs
     never seed these rows anymore (they were removed from reference_data.json). The
     CoreLinodeBackupStatus lookup rows need no explicit delete -- that table is
     dropped by the DeleteModel below.
  2. Removes the never-populated linode_snapshot_count / linode_snapshot_storage
     columns from core_usage_backup.
  3. Drops the dead provider tables: core_linode_backup, core_linode,
     core_auth_linode, core_linode_backup_status, core_contabo (dead copy-paste of the
     DigitalOcean code), and core_intercom. No other model holds an FK to any of
     these, so plain DeleteModel is sufficient.
"""
from django.db import migrations


DEAD_INTEGRATION_CODES = ("linode", "intercom")


def remove_dead_integration_rows(apps, schema_editor):
    CoreIntegration = apps.get_model("apps", "CoreIntegration")
    CoreConnection = apps.get_model("apps", "CoreConnection")
    CoreConnectionLocationIntegration = apps.get_model(
        "apps", "CoreConnectionLocationIntegration"
    )

    for code in DEAD_INTEGRATION_CODES:
        integration = CoreIntegration.objects.filter(code=code).first()
        if integration is None:
            continue
        # core_connection.integration is PROTECT: never strand user connections.
        if CoreConnection.objects.filter(integration=integration).exists():
            continue
        CoreConnectionLocationIntegration.objects.filter(integration=integration).delete()
        integration.delete()


class Migration(migrations.Migration):

    dependencies = [
        ("apps", "0014_update_region_reference_data"),
    ]

    operations = [
        migrations.RunPython(remove_dead_integration_rows, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name="coreusagebackup",
            name="linode_snapshot_count",
        ),
        migrations.RemoveField(
            model_name="coreusagebackup",
            name="linode_snapshot_storage",
        ),
        migrations.DeleteModel(
            name="CoreLinodeBackup",
        ),
        migrations.DeleteModel(
            name="CoreLinode",
        ),
        migrations.DeleteModel(
            name="CoreAuthLinode",
        ),
        migrations.DeleteModel(
            name="CoreLinodeBackupStatus",
        ),
        migrations.DeleteModel(
            name="CoreContabo",
        ),
        migrations.DeleteModel(
            name="CoreIntercom",
        ),
    ]
