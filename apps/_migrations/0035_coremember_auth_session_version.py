from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("apps", "0034_invalidate_plaintext_password_reset_tokens")]

    operations = [
        migrations.AddField(
            model_name="coremember",
            name="auth_session_version",
            field=models.PositiveBigIntegerField(default=1, editable=False),
        )
    ]
