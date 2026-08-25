from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("apps", "0043_backup_artifact_encryption")]

    operations = [
        migrations.CreateModel(
            name="CoreCeleryTaskReplay",
            fields=[
                (
                    "execution_key",
                    models.CharField(
                        editable=False,
                        max_length=64,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "envelope_digest",
                    models.CharField(editable=False, max_length=64, unique=True),
                ),
                ("task_id", models.CharField(editable=False, max_length=255)),
                ("task_name", models.CharField(editable=False, max_length=255)),
                ("publisher_lane", models.CharField(editable=False, max_length=16)),
                ("target_lane", models.CharField(editable=False, max_length=16)),
                (
                    "retry_count",
                    models.PositiveIntegerField(default=0, editable=False),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("active", "Active"),
                            ("retry", "Retry published"),
                            ("complete", "Complete"),
                        ],
                        default="active",
                        editable=False,
                        max_length=16,
                    ),
                ),
                ("first_seen_at", models.DateTimeField(auto_now_add=True, editable=False)),
                ("last_seen_at", models.DateTimeField(auto_now=True, editable=False)),
                (
                    "completed_at",
                    models.DateTimeField(blank=True, editable=False, null=True),
                ),
                (
                    "delivery_count",
                    models.PositiveIntegerField(default=1, editable=False),
                ),
            ],
            options={
                "db_table": "backupsheep_celery_task_replay",
                "indexes": [
                    models.Index(
                        fields=["status", "last_seen_at"],
                        name="celery_replay_status_seen",
                    )
                ],
            },
        )
    ]
