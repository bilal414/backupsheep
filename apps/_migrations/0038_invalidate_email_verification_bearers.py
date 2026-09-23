from django.db import migrations


def invalidate_email_verification_bearers(apps, schema_editor):
    NotificationEmail = apps.get_model("apps", "CoreNotificationEmail")
    EmailLog = apps.get_model("apps", "CoreNotificationLogEmail")

    # Historical values were raw, short bearer tokens. They cannot be safely
    # converted to the new keyed digest, so require an explicit resend.
    NotificationEmail.objects.exclude(verify_code__isnull=True).update(
        verify_code=None
    )
    EmailLog.objects.filter(template="verify_email").update(
        context={
            "action_url": "[redacted email verification link]",
            "sensitive_context_redacted": True,
        },
        html_body=None,
        text_body=None,
    )


class Migration(migrations.Migration):
    dependencies = [("apps", "0037_redact_password_reset_email_logs")]

    operations = [
        migrations.RunPython(
            invalidate_email_verification_bearers,
            reverse_code=migrations.RunPython.noop,
        )
    ]
