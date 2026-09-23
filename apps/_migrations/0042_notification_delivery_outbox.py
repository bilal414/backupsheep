import django.utils.timezone
import model_utils.fields
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("apps", "0041_storage_deletion_lease")]

    operations = [
        migrations.CreateModel(
            name="CoreNotificationDelivery",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "created",
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="created",
                    ),
                ),
                (
                    "modified",
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="modified",
                    ),
                ),
                (
                    "channel_type",
                    models.CharField(
                        choices=[("slack", "Slack"), ("telegram", "Telegram")],
                        max_length=16,
                    ),
                ),
                ("channel_id", models.PositiveBigIntegerField()),
                (
                    "status",
                    models.IntegerField(
                        choices=[
                            (0, "Pending"),
                            (1, "Processing"),
                            (2, "Retry"),
                            (3, "Sent"),
                            (4, "Skipped"),
                        ],
                        default=0,
                    ),
                ),
                ("attempt_count", models.PositiveIntegerField(default=0)),
                (
                    "next_attempt_at",
                    models.DateTimeField(default=django.utils.timezone.now),
                ),
                (
                    "lease_token",
                    models.UUIDField(blank=True, editable=False, null=True),
                ),
                ("lease_expires_at", models.DateTimeField(blank=True, null=True)),
                (
                    "outcome_code",
                    models.CharField(blank=True, default="", max_length=32),
                ),
                (
                    "log",
                    models.ForeignKey(
                        on_delete=models.deletion.CASCADE,
                        related_name="notification_deliveries",
                        to="apps.corelog",
                    ),
                ),
            ],
            options={
                "db_table": "core_notification_delivery",
                "indexes": [
                    models.Index(
                        fields=["status", "next_attempt_at"],
                        name="notification_due_idx",
                    ),
                    models.Index(
                        fields=["status", "lease_expires_at"],
                        name="notification_lease_idx",
                    ),
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("log", "channel_type", "channel_id"),
                        name="unique_log_notification_channel",
                    )
                ],
            },
        )
    ]
