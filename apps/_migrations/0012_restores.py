"""Restore tracking for website + database backups: CoreWebsiteRestore and
CoreDatabaseRestore (mirrors 0013's CoreCloudRestore for provider snapshots).
"""
import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("apps", "0011_local_storage"),
    ]

    operations = [
        migrations.CreateModel(
            name="CoreWebsiteRestore",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created", model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, editable=False, verbose_name="created")),
                ("modified", model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, editable=False, verbose_name="modified")),
                ("name", models.CharField(max_length=255)),
                ("params", models.JSONField(null=True)),
                ("status", models.IntegerField(choices=[(1, "Pending"), (2, "In-Progress"), (3, "Complete"), (4, "Failed")], default=1)),
                ("error", models.TextField(blank=True, null=True)),
                ("celery_task_id", models.CharField(blank=True, max_length=255, null=True)),
                ("backup", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="restores", to="apps.corewebsitebackup")),
                ("storage_point", models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="restores", to="apps.corewebsitebackupstoragepoints")),
            ],
            options={
                "db_table": "core_website_restore",
            },
        ),
        migrations.CreateModel(
            name="CoreDatabaseRestore",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created", model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, editable=False, verbose_name="created")),
                ("modified", model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, editable=False, verbose_name="modified")),
                ("name", models.CharField(max_length=255)),
                ("params", models.JSONField(null=True)),
                ("status", models.IntegerField(choices=[(1, "Pending"), (2, "In-Progress"), (3, "Complete"), (4, "Failed")], default=1)),
                ("error", models.TextField(blank=True, null=True)),
                ("celery_task_id", models.CharField(blank=True, max_length=255, null=True)),
                ("backup", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="restores", to="apps.coredatabasebackup")),
                ("storage_point", models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="restores", to="apps.coredatabasebackupstoragepoints")),
            ],
            options={
                "db_table": "core_database_restore",
            },
        ),
    ]
