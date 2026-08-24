from django.db import migrations


def invalidate_plaintext_reset_tokens(apps, schema_editor):
    # Previous releases stored live reset bearer tokens in cleartext. They cannot
    # be safely transformed because doing so would preserve already exposed
    # capabilities, so deployment deliberately invalidates every outstanding link.
    CoreMember = apps.get_model("apps", "CoreMember")
    CoreMember.objects.exclude(password_reset_token__isnull=True).update(
        password_reset_token=None,
        password_reset_token_created=None,
    )


class Migration(migrations.Migration):
    dependencies = [("apps", "0033_coremember_totp_mfa")]

    operations = [
        migrations.RunPython(
            invalidate_plaintext_reset_tokens,
            migrations.RunPython.noop,
        )
    ]
