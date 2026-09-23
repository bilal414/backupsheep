from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("apps", "0031_enforce_unique_backup_storage_destinations"),
    ]

    operations = [
        migrations.AddField(
            model_name="coreauthupcloud",
            name="api_token",
            field=models.BinaryField(null=True),
        ),
    ]
