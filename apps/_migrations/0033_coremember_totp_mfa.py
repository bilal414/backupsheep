from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("apps", "0032_coreauthupcloud_api_token")]

    operations = [
        migrations.AddField(
            model_name="coremember",
            name="auth_multi_factor_display_name",
            field=models.CharField(blank=True, default="", max_length=128),
        ),
        migrations.AddField(
            model_name="coremember",
            name="auth_multi_factor_enabled_at",
            field=models.DateTimeField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="coremember",
            name="auth_multi_factor_last_counter",
            field=models.BigIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="coremember",
            name="auth_multi_factor_pending_created",
            field=models.DateTimeField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="coremember",
            name="auth_multi_factor_secret",
            field=models.BinaryField(editable=False, null=True),
        ),
    ]
