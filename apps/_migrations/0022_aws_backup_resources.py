from django.core.validators import RegexValidator
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("apps", "0021_corelightsailbucketreplication_and_more")]

    operations = [
        migrations.AddField(
            model_name="coreauthaws",
            name="backup_vault_name",
            field=models.CharField(
                default="Default",
                max_length=255,
                validators=[
                    RegexValidator(
                        regex=r"^[A-Za-z0-9_-]{2,50}$",
                        message="AWS Backup vault names must be 2-50 letters, numbers, hyphens, or underscores.",
                    )
                ],
            ),
        ),
        migrations.AddField(
            model_name="coreauthaws",
            name="backup_role_arn",
            field=models.CharField(blank=True, default="", max_length=2048),
        ),
        migrations.AddField(
            model_name="coreaws",
            name="resource_type",
            field=models.CharField(
                choices=[
                    ("instance", "EC2 Instance"),
                    ("volume", "EBS Volume"),
                    ("s3", "S3 Bucket"),
                    ("dynamodb", "DynamoDB Table"),
                ],
                default="instance",
                max_length=32,
            ),
        ),
        migrations.AddField(
            model_name="corecloudrestore",
            name="provider_job_id",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
