from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("apps", "0019_partial_backup_status")]

    operations = [
        migrations.AddField(
            model_name="corelightsail",
            name="resource_type",
            field=models.CharField(
                choices=[
                    ("instance", "Instance"),
                    ("database", "Relational Database"),
                ],
                default="instance",
                max_length=32,
            ),
        ),
    ]
