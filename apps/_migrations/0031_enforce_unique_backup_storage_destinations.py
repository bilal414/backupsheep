from django.db import migrations, models


class Migration(migrations.Migration):
    """Enforce one durable upload state row per backup destination.

    Duplicate cleanup deliberately lives in 0030. PostgreSQL cannot ALTER one
    of these tables in the same transaction after deleting duplicate rows with
    deferred foreign-key trigger events. Keeping constraint creation in a
    separate atomic migration also makes an interrupted deployment resumable:
    cleanup is durably recorded before any table is altered here.
    """

    dependencies = [
        ("apps", "0030_unique_backup_storage_destinations"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="corewebsitebackupstoragepoints",
            constraint=models.UniqueConstraint(
                fields=("backup", "storage"),
                name="unique_stored_website_backups",
            ),
        ),
        migrations.AddConstraint(
            model_name="corewordpressbackupstoragepoints",
            constraint=models.UniqueConstraint(
                fields=("backup", "storage"),
                name="unique_stored_wordpress_backups",
            ),
        ),
        migrations.AddConstraint(
            model_name="corebasecampbackupstoragepoints",
            constraint=models.UniqueConstraint(
                fields=("backup", "storage"),
                name="unique_stored_basecamp_backups",
            ),
        ),
        migrations.AddConstraint(
            model_name="coredatabasebackupstoragepoints",
            constraint=models.UniqueConstraint(
                fields=("backup", "storage"),
                name="unique_stored_database_backups",
            ),
        ),
    ]
