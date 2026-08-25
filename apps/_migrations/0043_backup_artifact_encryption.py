import uuid

import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("apps", "0042_notification_delivery_outbox")]

    operations = [
        migrations.CreateModel(
            name="CoreBackupEncryptionEnvelope",
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
                ("format_version", models.PositiveSmallIntegerField(default=1)),
                (
                    "algorithm",
                    models.CharField(default="AES-256-GCM-SIV", max_length=32),
                ),
                ("chunk_size", models.PositiveIntegerField(default=4194304)),
                ("context_sha256", models.CharField(max_length=64)),
                ("header_sha256", models.CharField(max_length=64)),
                ("plaintext_byte_count", models.PositiveBigIntegerField(default=0)),
                ("plaintext_sha256", models.CharField(max_length=64)),
                (
                    "ciphertext_byte_count",
                    models.PositiveBigIntegerField(default=0),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("active", "Active"),
                            ("manual_review", "Manual review"),
                            ("retired", "Retired"),
                        ],
                        default="pending",
                        max_length=24,
                    ),
                ),
                ("sealed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "execution",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="encryption_envelope",
                        to="apps.corebackupexecution",
                    ),
                ),
            ],
            options={
                "db_table": "core_backup_encryption_envelope",
                "indexes": [
                    models.Index(
                        fields=["status", "sealed_at"],
                        name="backup_envelope_status_idx",
                    )
                ],
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(
                            ("algorithm", "AES-256-GCM-SIV"),
                            ("format_version", 1),
                        ),
                        name="backup_envelope_bse1_algorithm",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            ("chunk_size__gte", 65536),
                            ("chunk_size__lte", 67108864),
                        ),
                        name="backup_envelope_chunk_bounds",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            models.Q(("status", "active"), _negated=True),
                            ("sealed_at__isnull", False),
                            _connector="OR",
                        ),
                        name="active_backup_envelope_is_sealed",
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name="CoreBackupKeyWrap",
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
                ("generation", models.PositiveIntegerField(default=1)),
                (
                    "provider",
                    models.CharField(
                        choices=[
                            ("aws-kms", "AWS KMS"),
                            ("local-development", "Local development"),
                        ],
                        max_length=32,
                    ),
                ),
                ("wrapping_key_id", models.CharField(max_length=2048)),
                (
                    "wrapped_data_key",
                    models.BinaryField(editable=False, max_length=8192),
                ),
                ("wrapped_key_sha256", models.CharField(max_length=64)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("active", "Active"),
                            ("manual_review", "Manual review"),
                            ("retired", "Retired"),
                        ],
                        default="pending",
                        max_length=24,
                    ),
                ),
                ("activated_at", models.DateTimeField(blank=True, null=True)),
                ("retired_at", models.DateTimeField(blank=True, null=True)),
                (
                    "envelope",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="key_wraps",
                        to="apps.corebackupencryptionenvelope",
                    ),
                ),
            ],
            options={
                "db_table": "core_backup_key_wrap",
                "indexes": [
                    models.Index(
                        fields=["provider", "status"],
                        name="backup_key_wrap_state_idx",
                    )
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("envelope", "generation"),
                        name="unique_backup_key_wrap_generation",
                    ),
                    models.UniqueConstraint(
                        condition=models.Q(("status", "active")),
                        fields=("envelope",),
                        name="unique_active_backup_key_wrap",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(("generation__gte", 1)),
                        name="backup_key_wrap_generation_positive",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            models.Q(("status", "active"), _negated=True),
                            ("activated_at__isnull", False),
                            _connector="OR",
                        ),
                        name="active_backup_key_wrap_is_activated",
                    ),
                ],
            },
        ),
        migrations.AddField(
            model_name="corebackupartifact",
            name="artifact_format",
            field=models.CharField(
                choices=[
                    ("legacy_zip", "Legacy ZIP"),
                    ("bse1", "BSE1 encrypted envelope"),
                ],
                default="legacy_zip",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="corebackupartifact",
            name="encryption_envelope",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.RESTRICT,
                related_name="artifacts",
                to="apps.corebackupencryptionenvelope",
            ),
        ),
        migrations.AddConstraint(
            model_name="corebackupartifact",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(
                        ("artifact_format", "legacy_zip"),
                        ("encryption_envelope__isnull", True),
                    ),
                    models.Q(
                        ("artifact_format", "bse1"),
                        ("encryption_envelope__isnull", False),
                    ),
                    _connector="OR",
                ),
                name="backup_artifact_format_envelope",
            ),
        ),
    ]
