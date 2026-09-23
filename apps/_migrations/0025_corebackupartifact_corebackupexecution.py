# Generated for the durable backup execution-state contract.

import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("apps", "0024_vultr_managed_databases"),
        ("contenttypes", "0002_remove_content_type_name"),
    ]

    operations = [
        migrations.CreateModel(
            name="CoreBackupArtifact",
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
                    "uuid",
                    models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
                ),
                ("backup_object_id", models.PositiveBigIntegerField()),
                (
                    "role",
                    models.CharField(
                        choices=[
                            ("source", "Source"),
                            ("archive", "Archive"),
                            ("destination", "Destination"),
                            ("manifest", "Manifest"),
                        ],
                        default="archive",
                        max_length=32,
                    ),
                ),
                ("idempotency_key", models.CharField(max_length=255)),
                ("object_key", models.TextField(blank=True, default="")),
                ("byte_count", models.PositiveBigIntegerField(default=0)),
                (
                    "checksum_algorithm",
                    models.CharField(blank=True, default="", max_length=32),
                ),
                (
                    "checksum_value",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "etag",
                    models.CharField(blank=True, default="", max_length=512),
                ),
                (
                    "version_id",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "multipart_upload_id",
                    models.CharField(blank=True, default="", max_length=512),
                ),
                ("verified_at", models.DateTimeField(blank=True, null=True)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                (
                    "backup_content_type",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="backupsheep_backup_artifacts",
                        to="contenttypes.contenttype",
                    ),
                ),
                (
                    "storage",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="backup_artifacts",
                        to="apps.corestorage",
                    ),
                ),
            ],
            options={
                "db_table": "core_backup_artifact",
                "indexes": [
                    models.Index(
                        fields=["backup_content_type", "backup_object_id"],
                        name="backup_artifact_owner_idx",
                    ),
                    models.Index(
                        fields=["storage", "verified_at"],
                        name="backup_artifact_verify_idx",
                    ),
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=(
                            "backup_content_type",
                            "backup_object_id",
                            "idempotency_key",
                        ),
                        name="unique_backup_artifact_key",
                    )
                ],
            },
        ),
        migrations.CreateModel(
            name="CoreBackupExecution",
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
                ("backup_object_id", models.PositiveBigIntegerField()),
                (
                    "celery_task_id",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "task_name",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "worker_name",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                ("attempt_count", models.PositiveIntegerField(default=0)),
                ("delivery_count", models.PositiveIntegerField(default=0)),
                ("claim_count", models.PositiveIntegerField(default=0)),
                (
                    "phase",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                (
                    "lease_owner",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "lease_token",
                    models.UUIDField(blank=True, editable=False, null=True),
                ),
                ("lease_expires_at", models.DateTimeField(blank=True, null=True)),
                ("heartbeat_at", models.DateTimeField(blank=True, null=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                (
                    "reconciliation_state",
                    models.CharField(
                        choices=[
                            ("none", "None"),
                            ("required", "Required"),
                            ("in_progress", "In Progress"),
                            ("resolved", "Resolved"),
                            ("manual_review", "Manual Review"),
                        ],
                        default="none",
                        max_length=24,
                    ),
                ),
                (
                    "reconciliation_reason",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "reconciliation_metadata",
                    models.JSONField(blank=True, default=dict),
                ),
                (
                    "last_error_code",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                ("last_error_message", models.TextField(blank=True, default="")),
                ("last_error_at", models.DateTimeField(blank=True, null=True)),
                ("next_retry_at", models.DateTimeField(blank=True, null=True)),
                ("progress_completed", models.PositiveBigIntegerField(default=0)),
                (
                    "progress_total",
                    models.PositiveBigIntegerField(blank=True, null=True),
                ),
                (
                    "progress_unit",
                    models.CharField(blank=True, default="", max_length=32),
                ),
                (
                    "provider_operation_id",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "provider_resource_id",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "provider_idempotency_key",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "provider_status",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                ("provider_metadata", models.JSONField(blank=True, default=dict)),
                ("artifact_bytes", models.PositiveBigIntegerField(default=0)),
                (
                    "artifact_checksum_algorithm",
                    models.CharField(blank=True, default="", max_length=32),
                ),
                (
                    "artifact_checksum",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                ("artifact_verified_at", models.DateTimeField(blank=True, null=True)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                (
                    "backup_content_type",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="backupsheep_backup_executions",
                        to="contenttypes.contenttype",
                    ),
                ),
            ],
            options={
                "db_table": "core_backup_execution",
                "indexes": [
                    models.Index(
                        fields=["lease_expires_at"], name="backup_exec_lease_idx"
                    ),
                    models.Index(
                        fields=["reconciliation_state", "next_retry_at"],
                        name="backup_exec_reconcile_idx",
                    ),
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("backup_content_type", "backup_object_id"),
                        name="unique_backup_execution",
                    )
                ],
            },
        ),
    ]
