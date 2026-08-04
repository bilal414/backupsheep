from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("apps", "0022_aws_backup_resources")]

    operations = [
        migrations.AddField(
            model_name="corecloudrestore",
            name="restore_marker",
            field=models.CharField(blank=True, default="", max_length=128),
        ),
        migrations.AddField(
            model_name="corecloudrestore",
            name="request_fingerprint",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="corecloudrestore",
            name="operation_phase",
            field=models.CharField(
                choices=[
                    ("pending", "Pending"),
                    ("reconciling", "Reconciling"),
                    ("create_unknown", "Create outcome unknown"),
                    ("polling", "Polling"),
                    ("complete", "Complete"),
                    ("failed", "Failed"),
                    ("manual_review", "Manual review"),
                ],
                default="pending",
                max_length=32,
            ),
        ),
    ]
