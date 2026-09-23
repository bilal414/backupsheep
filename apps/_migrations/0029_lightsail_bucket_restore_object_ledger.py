import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("apps", "0028_backup_request_outbox"),
    ]

    operations = [
        migrations.CreateModel(
            name="CoreLightsailBucketRestoreObject",
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
                ("backup_key_hash", models.CharField(max_length=64)),
                ("backup_key_encrypted", models.TextField()),
                (
                    "backup_version_id",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                ("is_delete_marker", models.BooleanField(default=False)),
                (
                    "backup_etag",
                    models.CharField(blank=True, default="", max_length=512),
                ),
                ("backup_size", models.PositiveBigIntegerField(blank=True, null=True)),
                ("backup_last_modified", models.DateTimeField(blank=True, null=True)),
                ("source_key_hash", models.CharField(max_length=64)),
                ("source_key_encrypted", models.TextField()),
                (
                    "source_version_id",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "source_etag",
                    models.CharField(blank=True, default="", max_length=512),
                ),
                ("target_key_hash", models.CharField(max_length=64)),
                ("target_key_encrypted", models.TextField()),
                (
                    "restored_version_id",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("restoring", "Restoring"),
                            ("complete", "Complete"),
                            ("skipped", "Skipped"),
                            ("failed", "Failed"),
                        ],
                        default="pending",
                        max_length=16,
                    ),
                ),
                ("bytes_restored", models.PositiveBigIntegerField(default=0)),
                ("attempt_count", models.PositiveIntegerField(default=0)),
                ("error", models.TextField(blank=True, default="")),
                (
                    "restore_run",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="object_states",
                        to="apps.corelightsailbucketrestorerun",
                    ),
                ),
                (
                    "source_object",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="restore_objects",
                        to="apps.corelightsailbucketreplicationobject",
                    ),
                ),
            ],
            options={
                "db_table": "core_lightsail_bucket_restore_object",
                "indexes": [
                    models.Index(
                        fields=["restore_run", "status"],
                        name="lightsail_restore_status_idx",
                    ),
                    models.Index(
                        fields=["backup_key_hash", "backup_version_id"],
                        name="lightsail_restore_source_idx",
                    ),
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("restore_run", "backup_key_hash"),
                        name="unique_lightsail_bucket_restore_object_key",
                    ),
                    models.UniqueConstraint(
                        fields=("restore_run", "target_key_hash"),
                        name="unique_lightsail_bucket_restore_target_key",
                    ),
                ],
            },
        ),
    ]
