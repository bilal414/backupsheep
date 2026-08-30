"""Retire the WordPress integration without destroying historical customer data."""

from django.db import migrations


def retire_wordpress_runtime_rows(apps, schema_editor):
    """Disable every dispatch path before removing the models from Django state."""

    CoreConnection = apps.get_model("apps", "CoreConnection")
    CoreIntegration = apps.get_model("apps", "CoreIntegration")
    CoreNode = apps.get_model("apps", "CoreNode")
    CoreSchedule = apps.get_model("apps", "CoreSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    integration_filter = {"integration__code": "wordpress"}
    schedule_ids = list(
        CoreSchedule.objects.filter(
            node__connection__integration__code="wordpress"
        ).values_list("celery_periodic_task_id", flat=True)
    )
    PeriodicTask.objects.filter(pk__in=[pk for pk in schedule_ids if pk]).update(
        enabled=False
    )
    CoreSchedule.objects.filter(
        node__connection__integration__code="wordpress"
    ).update(status=2)
    CoreNode.objects.filter(connection__integration__code="wordpress").update(
        status=6
    )
    CoreConnection.objects.filter(**integration_filter).update(status=4)
    CoreIntegration.objects.filter(code="wordpress").update(enabled=False)


class Migration(migrations.Migration):
    dependencies = [
        ("apps", "0046_core_managed_ssh_operation"),
    ]

    operations = [
        migrations.RunPython(
            retire_wordpress_runtime_rows,
            migrations.RunPython.noop,
        ),
        migrations.SeparateDatabaseAndState(
            # These tables and columns deliberately remain in PostgreSQL. Existing
            # installations retain their records, while the application registry,
            # serializers and workers have no model capable of reading them.
            database_operations=[],
            state_operations=[
                migrations.RemoveField(
                    model_name="corewordpressbackup",
                    name="storage_points",
                ),
                migrations.DeleteModel(name="CoreWordPressBackupStoragePoints"),
                migrations.DeleteModel(name="CoreWordPressBackup"),
                migrations.DeleteModel(name="CoreWordPress"),
                migrations.DeleteModel(name="CoreAuthWordPress"),
                migrations.RemoveField(
                    model_name="corestorage",
                    name="stats_wordpress_count",
                ),
                migrations.RemoveField(
                    model_name="corestorage",
                    name="stats_wordpress_backup_count",
                ),
                migrations.RemoveField(
                    model_name="corestorage",
                    name="stats_wordpress_size",
                ),
                migrations.RemoveField(
                    model_name="corestorage",
                    name="stat_wordpress_size",
                ),
            ],
        ),
    ]
