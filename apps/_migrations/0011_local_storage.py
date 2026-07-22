"""Add the 'Local Storage' backend: CoreStorageLocal (a disk path on this server under
settings.LOCAL_STORAGE_ROOT) plus its core_storage_type catalog row.

The same row is also in seed_data/reference_data.json, so fresh installs get it from
0007's bulk seed and the get_or_create below is a no-op; installs that already ran 0007
pick it up here.
"""
import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
from django.db import migrations, models


def seed_local_storage_type(apps, schema_editor):
    CoreStorageType = apps.get_model("apps", "CoreStorageType")
    CoreStorageType.objects.get_or_create(
        code="local",
        defaults={
            "name": "Local Storage",
            "is_enabled": True,
            "position": 0,
            "description": "Store backups on a local disk path on this BackupSheep server",
            "image": "",
        },
    )


class Migration(migrations.Migration):

    dependencies = [
        ("apps", "0010_corewebsite_incremental"),
    ]

    operations = [
        migrations.CreateModel(
            name="CoreStorageLocal",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created", model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, editable=False, verbose_name="created")),
                ("modified", model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, editable=False, verbose_name="modified")),
                ("path", models.CharField(blank=True, max_length=1024, null=True)),
                ("no_delete", models.BooleanField(null=True)),
                ("storage", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="storage_local", to="apps.corestorage")),
            ],
            options={
                "db_table": "core_storage_local",
            },
        ),
        # Reverse is a no-op: reference data is shared catalog, not user data.
        migrations.RunPython(seed_local_storage_type, migrations.RunPython.noop),
    ]
