from django.db import migrations, models


def _storage_point_lease_fields(model_name):
    return [
        migrations.AddField(
            model_name=model_name,
            name="last_error_code",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name=model_name,
            name="last_error_message",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name=model_name,
            name="upload_attempt_count",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name=model_name,
            name="upload_heartbeat_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name=model_name,
            name="upload_lease_expires_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name=model_name,
            name="upload_lease_owner",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name=model_name,
            name="upload_lease_token",
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
    ]


class Migration(migrations.Migration):
    dependencies = [
        ("apps", "0025_corebackupartifact_corebackupexecution"),
    ]

    operations = []
    for _model_name in (
        "corebasecampbackupstoragepoints",
        "coredatabasebackupstoragepoints",
        "corewebsitebackupstoragepoints",
        "corewordpressbackupstoragepoints",
    ):
        operations.extend(_storage_point_lease_fields(_model_name))
