# Handwritten: adds CoreWebsite.incremental (mirror into a per-node persistent cache
# instead of re-downloading every file) and renames the BackupType labels.
# NOTE: depends on 0013 (the current leaf) rather than 0009 -- a
# 0010_coreauthwebsite_verify_ssl -> 0013 chain already exists, so hanging this off
# 0009 would leave two leaf nodes and break `migrate`.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('apps', '0013_corecloudrestore'),
    ]

    operations = [
        migrations.AddField(
            model_name='corewebsite',
            name='incremental',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='corewebsite',
            name='backup_type',
            field=models.IntegerField(choices=[(1, 'Full'), (4, 'Full (Server-Side Tar)')], default=1),
        ),
    ]
