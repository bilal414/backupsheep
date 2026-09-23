from django.db import migrations
from django.db.models import Count


POINT_MODELS = (
    "CoreWebsiteBackupStoragePoints",
    "CoreWordPressBackupStoragePoints",
    "CoreBasecampBackupStoragePoints",
    "CoreDatabaseBackupStoragePoints",
)


# Prefer the furthest durable lifecycle marker when historical code created more
# than one row for the same logical backup destination. Values are shared by the
# four through models, except that a few numeric gaps differ harmlessly.
STATUS_PRIORITY = {
    7: 100,   # delete completed
    8: 90,    # delete failed
    40: 80,   # transferred
    3: 75,    # upload complete
    2: 60,    # upload in progress
    9: 55,    # upload retry
    1: 50,    # upload ready
    30: 40,   # storage validation failed
    10: 35,   # quota exceeded
    11: 35,   # source file missing
    4: 30,    # upload failed
}


def _status_priority(model_name, status):
    status = int(status)
    if model_name == "CoreDatabaseBackupStoragePoints":
        database_priorities = {
            12: 95,  # delete requested
            13: 85,  # cancelled
            15: 65,  # upload validation
            14: 35,  # upload timeout
        }
        return database_priorities.get(status, STATUS_PRIORITY.get(status, 0))
    local_priorities = {
        5: 95,   # delete requested
        6: 85,   # cancelled
        13: 65,  # upload validation
        12: 35,  # upload timeout
    }
    return local_priorities.get(status, STATUS_PRIORITY.get(status, 0))


def _merge_metadata(rows):
    merged = {}
    for row in rows:
        if isinstance(row.metadata, dict):
            merged.update(row.metadata)
    return merged or None


def collapse_duplicate_destinations(apps, schema_editor):
    for model_name in POINT_MODELS:
        model = apps.get_model("apps", model_name)
        duplicates = (
            model.objects.values("backup_id", "storage_id")
            .annotate(row_count=Count("id"))
            .filter(row_count__gt=1)
            .order_by("backup_id", "storage_id")
        )
        for duplicate in duplicates.iterator(chunk_size=1000):
            rows = list(
                model.objects.filter(
                    backup_id=duplicate["backup_id"],
                    storage_id=duplicate["storage_id"],
                ).order_by("id")
            )
            winner = max(
                rows,
                key=lambda row: (
                    _status_priority(model_name, row.status),
                    bool(row.storage_file_id),
                    bool(row.metadata),
                    row.modified,
                    row.id,
                ),
            )
            winner.upload_attempt_count = max(
                int(row.upload_attempt_count or 0) for row in rows
            )
            winner.metadata = _merge_metadata(rows)
            if not winner.storage_file_id:
                winner.storage_file_id = next(
                    (row.storage_file_id for row in rows if row.storage_file_id),
                    None,
                )
            if not winner.celery_task_id:
                winner.celery_task_id = next(
                    (row.celery_task_id for row in rows if row.celery_task_id),
                    None,
                )
            if not winner.last_error_code:
                winner.last_error_code = next(
                    (row.last_error_code for row in reversed(rows) if row.last_error_code),
                    "",
                )
            if not winner.last_error_message:
                winner.last_error_message = next(
                    (
                        row.last_error_message
                        for row in reversed(rows)
                        if row.last_error_message
                    ),
                    "",
                )
            # A lease belonged to one of the now-collapsed rows. Clear it so the
            # normal recovery sweep can elect one fresh fenced uploader.
            winner.upload_lease_owner = ""
            winner.upload_lease_token = None
            winner.upload_lease_expires_at = None
            winner.upload_heartbeat_at = None
            winner.save()
            model.objects.filter(
                backup_id=duplicate["backup_id"],
                storage_id=duplicate["storage_id"],
            ).exclude(pk=winner.pk).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("apps", "0029_lightsail_bucket_restore_object_ledger"),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name="corewebsitebackupstoragepoints",
            name="unique_stored_website_backups",
        ),
        migrations.RemoveConstraint(
            model_name="corewordpressbackupstoragepoints",
            name="unique_stored_wordpress_backups",
        ),
        migrations.RemoveConstraint(
            model_name="corebasecampbackupstoragepoints",
            name="unique_stored_basecamp_backups",
        ),
        migrations.RemoveConstraint(
            model_name="coredatabasebackupstoragepoints",
            name="unique_stored_database_backups",
        ),
        migrations.RunPython(
            collapse_duplicate_destinations,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
