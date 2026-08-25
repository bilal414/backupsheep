import uuid

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models
import model_utils.fields


class Migration(migrations.Migration):
    dependencies = [("apps", "0045_prepare_node_deletion_lanes")]

    operations = [
        migrations.CreateModel(
            name="CoreManagedSSHOperation",
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
                (
                    "source_lane",
                    models.CharField(
                        choices=[("database", "Database"), ("files", "Files")],
                        editable=False,
                        max_length=16,
                    ),
                ),
                (
                    "operation",
                    models.CharField(
                        choices=[
                            ("validate", "Validate connection"),
                            ("discover", "Discover objects"),
                            ("update_metadata", "Update database metadata"),
                        ],
                        editable=False,
                        max_length=32,
                    ),
                ),
                (
                    "requested_path",
                    models.CharField(blank=True, editable=False, max_length=2048),
                ),
                (
                    "managed_public_key_fingerprint",
                    models.CharField(editable=False, max_length=64),
                ),
                (
                    "connection_config_digest",
                    models.CharField(editable=False, max_length=64),
                ),
                (
                    "celery_task_id",
                    models.UUIDField(editable=False, unique=True),
                ),
                (
                    "idempotency_key",
                    models.CharField(editable=False, max_length=64, unique=True),
                ),
                (
                    "intent_digest",
                    models.CharField(editable=False, max_length=64),
                ),
                ("expires_at", models.DateTimeField(editable=False)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("running", "Running"),
                            ("complete", "Complete"),
                            ("failed", "Failed"),
                            ("expired", "Expired"),
                        ],
                        default="pending",
                        max_length=16,
                    ),
                ),
                ("lease_token", models.UUIDField(blank=True, null=True)),
                ("lease_expires_at", models.DateTimeField(blank=True, null=True)),
                ("attempts", models.PositiveIntegerField(default=0)),
                ("claimed_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("result_payload", models.JSONField(blank=True, default=dict)),
                ("result_digest", models.CharField(blank=True, max_length=64)),
                ("error_payload", models.JSONField(blank=True, default=dict)),
                (
                    "execution_witness_digest",
                    models.CharField(blank=True, max_length=64),
                ),
                (
                    "account",
                    models.ForeignKey(
                        editable=False,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="managed_ssh_operations",
                        to="apps.coreaccount",
                    ),
                ),
                (
                    "connection",
                    models.ForeignKey(
                        editable=False,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="managed_ssh_operations",
                        to="apps.coreconnection",
                    ),
                ),
            ],
            options={
                "db_table": "core_managed_ssh_operation",
                "indexes": [
                    models.Index(
                        fields=["connection", "status"],
                        name="managed_ssh_connection_status",
                    ),
                    models.Index(
                        fields=["status", "expires_at"],
                        name="managed_ssh_status_expiry",
                    ),
                ],
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(source_lane__in=("database", "files")),
                        name="managed_ssh_source_lane_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            operation__in=(
                                "validate",
                                "discover",
                                "update_metadata",
                            )
                        ),
                        name="managed_ssh_operation_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            status__in=(
                                "pending",
                                "running",
                                "complete",
                                "failed",
                                "expired",
                            )
                        ),
                        name="managed_ssh_status_valid",
                    ),
                    models.CheckConstraint(
                        condition=~models.Q(operation="validate")
                        | models.Q(requested_path=""),
                        name="managed_ssh_validate_path_empty",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            managed_public_key_fingerprint__regex="^[0-9a-f]{64}$"
                        )
                        & models.Q(
                            connection_config_digest__regex="^[0-9a-f]{64}$"
                        )
                        & models.Q(idempotency_key__regex="^[0-9a-f]{64}$")
                        & models.Q(intent_digest__regex="^[0-9a-f]{64}$"),
                        name="managed_ssh_intent_digests_valid",
                    ),
                    models.CheckConstraint(
                        condition=~models.Q(
                            status__in=("complete", "failed", "expired")
                        )
                        | models.Q(completed_at__isnull=False),
                        name="managed_ssh_terminal_completed_at",
                    ),
                ],
            },
        )
    ]
