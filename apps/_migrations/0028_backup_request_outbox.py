import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("apps", "0027_restore_execution_leases"),
        ("contenttypes", "0002_remove_content_type_name"),
    ]

    operations = [
        migrations.CreateModel(
            name="CoreBackupRequest",
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
                    "correlation_id",
                    models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
                ),
                ("request_key", models.CharField(max_length=255, unique=True)),
                ("task_id", models.CharField(max_length=255, unique=True)),
                ("task_name", models.CharField(max_length=255)),
                (
                    "trigger",
                    models.CharField(
                        choices=[
                            ("on_demand", "On demand"),
                            ("schedule", "Schedule"),
                            ("retry", "Retry"),
                        ],
                        default="on_demand",
                        max_length=24,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending dispatch"),
                            ("dispatched", "Dispatched"),
                            ("claimed", "Backup created"),
                            ("duplicate", "Duplicate suppressed"),
                            ("cancelled", "Cancelled"),
                            ("manual_review", "Manual review"),
                        ],
                        default="pending",
                        max_length=24,
                    ),
                ),
                ("payload", models.JSONField(blank=True, default=dict)),
                ("backup_object_id", models.PositiveBigIntegerField(blank=True, null=True)),
                ("dispatch_attempt_count", models.PositiveIntegerField(default=0)),
                ("dispatch_lease_owner", models.CharField(blank=True, default="", max_length=255)),
                ("dispatch_lease_token", models.UUIDField(blank=True, editable=False, null=True)),
                ("dispatch_lease_expires_at", models.DateTimeField(blank=True, null=True)),
                ("next_dispatch_at", models.DateTimeField(blank=True, null=True)),
                ("published_at", models.DateTimeField(blank=True, null=True)),
                ("claimed_at", models.DateTimeField(blank=True, null=True)),
                ("last_error_code", models.CharField(blank=True, default="", max_length=64)),
                ("last_error_message", models.TextField(blank=True, default="")),
                (
                    "backup_content_type",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="backupsheep_backup_requests",
                        to="contenttypes.contenttype",
                    ),
                ),
                (
                    "node",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="backup_requests",
                        to="apps.corenode",
                    ),
                ),
                (
                    "requested_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="backup_requests",
                        to="apps.coremember",
                    ),
                ),
                (
                    "schedule",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="backup_requests",
                        to="apps.coreschedule",
                    ),
                ),
            ],
            options={
                "db_table": "core_backup_request",
                "indexes": [
                    models.Index(fields=["status", "next_dispatch_at"], name="backup_request_dispatch_idx"),
                    models.Index(fields=["node", "status"], name="backup_request_node_idx"),
                    models.Index(fields=["dispatch_lease_expires_at"], name="backup_request_lease_idx"),
                ],
            },
        ),
    ]
