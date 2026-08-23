from django.db import migrations


def redact_password_reset_email_logs(apps, schema_editor):
    EmailLog = apps.get_model("apps", "CoreNotificationLogEmail")
    EmailLog.objects.filter(template="password_reset").update(
        context={
            "action_url": "[redacted password reset link]",
            "sensitive_context_redacted": True,
        },
        html_body=None,
        text_body=None,
    )


class Migration(migrations.Migration):
    dependencies = [("apps", "0036_encrypt_slack_notification_secrets")]

    operations = [
        migrations.RunPython(
            redact_password_reset_email_logs,
            reverse_code=migrations.RunPython.noop,
        )
    ]
