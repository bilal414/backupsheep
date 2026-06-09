from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('apps', '0011_create_cache_table'),
    ]

    operations = [
        migrations.AddField(
            model_name='coremember',
            name='password_reset_token_created',
            field=models.DateTimeField(blank=True, editable=False, null=True),
        ),
    ]
