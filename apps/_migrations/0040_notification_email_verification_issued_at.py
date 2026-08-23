from django.db import migrations, models
from django.db.models import F


def backfill_verification_issue_time(apps, schema_editor):
    NotificationEmail = apps.get_model("apps", "CoreNotificationEmail")
    # The pre-migration sender called save() when issuing/reissuing a token, so
    # modified is the best available issuance witness for an in-flight digest.
    NotificationEmail.objects.filter(verify_code__isnull=False).update(
        verify_code_created=F("modified")
    )


class Migration(migrations.Migration):
    dependencies = [("apps", "0039_encrypt_wordpress_credentials")]

    operations = [
        migrations.AddField(
            model_name="corenotificationemail",
            name="verify_code_created",
            field=models.DateTimeField(editable=False, null=True),
        ),
        migrations.RunPython(
            backfill_verification_issue_time,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
