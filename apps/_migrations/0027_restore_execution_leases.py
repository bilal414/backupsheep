import uuid

from django.db import migrations, models


RESTORE_MODELS = (
    "corecloudrestore",
    "coredatabaserestore",
    "corevultrdatabaserestore",
    "corewebsiterestore",
)


def _execution_fields(model_name):
    return [
        migrations.AddField(
            model_name=model_name,
            name="execution_phase",
            field=models.CharField(blank=True, default="pending", max_length=64),
        ),
        migrations.AddField(
            model_name=model_name,
            name="execution_metadata",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name=model_name,
            name="lease_owner",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name=model_name,
            name="lease_token",
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name=model_name,
            name="lease_expires_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name=model_name,
            name="heartbeat_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name=model_name,
            name="attempt_count",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name=model_name,
            name="progress_completed",
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name=model_name,
            name="progress_total",
            field=models.PositiveBigIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name=model_name,
            name="progress_unit",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
        migrations.AddField(
            model_name=model_name,
            name="last_error_code",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name=model_name,
            name="next_retry_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]


def populate_correlation_ids(apps, schema_editor):
    for model_name in (
        "CoreCloudRestore",
        "CoreDatabaseRestore",
        "CoreVultrDatabaseRestore",
        "CoreWebsiteRestore",
    ):
        model = apps.get_model("apps", model_name)
        while True:
            rows = list(
                model.objects.filter(correlation_id__isnull=True)
                .only("pk", "correlation_id")
                .order_by("pk")[:1000]
            )
            if not rows:
                break
            for row in rows:
                row.correlation_id = uuid.uuid4()
            model.objects.bulk_update(rows, ["correlation_id"], batch_size=1000)


class Migration(migrations.Migration):
    dependencies = [
        ("apps", "0026_storage_point_upload_leases"),
    ]

    operations = []
    for _model_name in RESTORE_MODELS:
        operations.append(
            migrations.AddField(
                model_name=_model_name,
                name="correlation_id",
                field=models.UUIDField(blank=True, null=True),
            )
        )
        operations.extend(_execution_fields(_model_name))
    operations.append(migrations.RunPython(populate_correlation_ids, migrations.RunPython.noop))
    for _model_name in RESTORE_MODELS:
        operations.append(
            migrations.AlterField(
                model_name=_model_name,
                name="correlation_id",
                field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
            )
        )
    for _model_name, _prefix in (
        ("corecloudrestore", "cloud_restore"),
        ("corewebsiterestore", "website_restore"),
        ("coredatabaserestore", "database_restore"),
        ("corevultrdatabaserestore", "vultr_db_restore"),
    ):
        operations.extend(
            [
                migrations.AddIndex(
                    model_name=_model_name,
                    index=models.Index(
                        fields=["status", "next_retry_at", "modified"],
                        name=f"{_prefix}_retry_idx",
                    ),
                ),
                migrations.AddIndex(
                    model_name=_model_name,
                    index=models.Index(
                        fields=["status", "lease_expires_at"],
                        name=f"{_prefix}_lease_idx",
                    ),
                ),
            ]
        )
