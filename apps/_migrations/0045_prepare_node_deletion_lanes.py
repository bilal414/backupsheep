from django.db import migrations


DELETE_REQUESTED = 7


def prepare_node_deletion_lanes(apps, _schema_editor):
    """Fence legacy deletion intents before lane-specific workers can resume.

    Older releases let the storage worker delete Beat rows. Generation 3 denies
    every worker access to the scheduler, so the stopped one-shot migrator removes
    those schedules and publishes the existing ``flag_delete_node`` phase witness.
    """

    node_model = apps.get_model("apps", "CoreNode")
    schedule_model = apps.get_model("apps", "CoreSchedule")
    periodic_task_model = apps.get_model("django_celery_beat", "PeriodicTask")

    node_ids = list(
        node_model.objects.filter(status=DELETE_REQUESTED)
        .order_by("pk")
        .values_list("pk", flat=True)
    )
    if not node_ids:
        return

    periodic_task_ids = list(
        schedule_model.objects.filter(node_id__in=node_ids)
        .exclude(celery_periodic_task_id__isnull=True)
        .values_list("celery_periodic_task_id", flat=True)
    )
    schedule_model.objects.filter(node_id__in=node_ids).delete()
    # A malformed legacy database may reuse one PeriodicTask. Never delete it while
    # any surviving schedule still references it.
    periodic_task_model.objects.filter(pk__in=periodic_task_ids).filter(
        schedules__isnull=True
    ).delete()
    node_model.objects.filter(pk__in=node_ids).update(flag_delete_node=True)


class Migration(migrations.Migration):
    dependencies = [
        ("apps", "0044_celery_task_replay"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        migrations.RunPython(
            prepare_node_deletion_lanes,
            reverse_code=migrations.RunPython.noop,
        )
    ]
