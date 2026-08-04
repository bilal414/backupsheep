# Generated for the Vultr Managed Database source/backup/fork contract.
import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
import uuid
from django.db import migrations, models


BACKUP_STATUS_CHOICES = [
    (1, "Pending"), (2, "In-Progress"), (3, "Complete"), (4, "Failed"),
    (5, "Retrying"), (6, "Started"), (7, "Max Retries Failed"),
    (8, "Ready For Upload"), (9, "Upload In Progress"), (10, "Upload Complete"),
    (22, "Upload Validation"), (23, "Partial (Some Destinations Failed)"), (11, "Upload Failed"), (12, "Delete REQUESTED"),
    (13, "Delete In-Progress"), (14, "Delete Completed"), (15, "Delete Failed"),
    (20, "Delete Failed (Not Found)"), (16, "Delete Max Retries Failed"),
    (17, "Download In-Progress"), (18, "Download Complete"), (19, "Cancelled"),
    (21, "Timeout"), (30, "Storage Validation Failed"),
]
BACKUP_TYPE_CHOICES = [(1, "On-Demand"), (2, "Scheduled")]


class Migration(migrations.Migration):
    dependencies = [("apps", "0023_vultr_restore_recovery")]

    operations = [
        migrations.CreateModel(
            name="CoreVultrDatabase",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created", model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, editable=False, verbose_name="created")),
                ("modified", model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, editable=False, verbose_name="modified")),
                ("name", models.CharField(max_length=255)),
                ("unique_id", models.CharField(max_length=255)),
                ("engine", models.CharField(default="", max_length=64)),
                ("region", models.CharField(default="", max_length=255)),
                ("plan", models.CharField(default="", max_length=255)),
                ("provider_status", models.CharField(default="", max_length=64)),
                ("notes", models.TextField(blank=True, null=True)),
                ("metadata", models.JSONField(null=True)),
                ("node", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="vultr_database", to="apps.corenode")),
            ],
            options={"db_table": "core_vultr_database"},
        ),
        migrations.CreateModel(
            name="CoreVultrDatabaseBackup",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created", model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, editable=False, verbose_name="created")),
                ("modified", model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, editable=False, verbose_name="modified")),
                ("uuid", models.CharField(editable=False, max_length=1024, null=True)),
                ("celery_task_id", models.CharField(editable=False, max_length=255, null=True)),
                ("name", models.CharField(max_length=255, null=True)),
                ("status", models.IntegerField(choices=BACKUP_STATUS_CHOICES, default=3)),
                ("type", models.IntegerField(choices=BACKUP_TYPE_CHOICES, null=True)),
                ("attempt_no", models.PositiveIntegerField(null=True)),
                ("old_schedule_name", models.CharField(max_length=255, null=True)),
                ("old_schedule_timezone", models.CharField(max_length=255, null=True)),
                ("old_delete_requested", models.BooleanField(null=True)),
                ("old_delete_in_progress", models.BooleanField(default=False)),
                ("old_max_delete_retry", models.BooleanField(default=False)),
                ("completed_on_attempt_no", models.IntegerField(null=True)),
                ("notes", models.TextField(null=True)),
                ("region", models.CharField(max_length=255, null=True)),
                ("unique_id", models.CharField(max_length=255, null=True)),
                ("provider_backup_id", models.CharField(max_length=255, null=True)),
                ("provider_marker", models.CharField(max_length=512, null=True)),
                ("provider_state", models.CharField(default="", max_length=64)),
                ("provider_error_class", models.CharField(default="", max_length=64)),
                ("provider_http_status", models.PositiveIntegerField(null=True)),
                ("size_gigabytes", models.FloatField(null=True)),
                ("metadata", models.JSONField(null=True)),
                ("schedule", models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="vultr_database_backups", to="apps.coreschedule")),
                ("vultr_database", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="backups", to="apps.corevultrdatabase")),
            ],
            options={"db_table": "core_vultr_database_backup"},
        ),
        migrations.AddConstraint(
            model_name="corevultrdatabasebackup",
            constraint=models.UniqueConstraint(condition=models.Q(("provider_marker__isnull", False)), fields=("vultr_database", "provider_marker"), name="unique_vultr_database_provider_marker"),
        ),
        migrations.CreateModel(
            name="CoreVultrDatabaseRestore",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created", model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, editable=False, verbose_name="created")),
                ("modified", model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, editable=False, verbose_name="modified")),
                ("uuid", models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ("name", models.CharField(max_length=255)),
                ("params", models.JSONField(blank=True, null=True)),
                ("resource_id", models.CharField(blank=True, max_length=255, null=True)),
                ("provider_job_id", models.CharField(blank=True, max_length=255, null=True)),
                ("provider_marker", models.CharField(blank=True, max_length=255, null=True)),
                ("provider_status", models.CharField(default="", max_length=64)),
                ("provider_http_status", models.PositiveIntegerField(blank=True, null=True)),
                ("status", models.IntegerField(choices=[(1, "Pending"), (2, "In-Progress"), (3, "Complete"), (4, "Failed"), (5, "Cancelled")], default=1)),
                ("metadata", models.JSONField(blank=True, null=True)),
                ("error", models.TextField(blank=True, null=True)),
                ("celery_task_id", models.CharField(blank=True, max_length=255, null=True)),
                ("backup", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="restores", to="apps.corevultrdatabasebackup")),
            ],
            options={"db_table": "core_vultr_database_restore"},
        ),
    ]
