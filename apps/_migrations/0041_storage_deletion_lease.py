import django.utils.timezone
import model_utils.fields
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("apps", "0040_notification_email_verification_issued_at")]

    operations = [
        migrations.CreateModel(
            name="CoreStorageDeletionLease",
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
                    "owner",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "token",
                    models.UUIDField(blank=True, editable=False, null=True),
                ),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                (
                    "storage",
                    models.OneToOneField(
                        on_delete=models.deletion.CASCADE,
                        related_name="deletion_lease",
                        to="apps.corestorage",
                    ),
                ),
            ],
            options={"db_table": "core_storage_deletion_lease"},
        )
    ]
