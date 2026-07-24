"""Add CoreInvite.expires_at.

Invites are now accepted through a public link (/invite/<uuid>/) and need a bounded
lifetime: new invites default to now + CoreInvite.INVITE_TTL_DAYS (7 days, set in
CoreInvite.save). Existing rows keep NULL, which CoreInvite.is_expired treats as
"never expires" -- they stay acceptable until acted on, and `resend` assigns a fresh
window. Expiry is enforced lazily (CoreInvite.expire_if_needed) at accept time and
when invites are listed; no sweeper task is introduced.
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("apps", "0015_remove_dead_integrations"),
    ]

    operations = [
        migrations.AddField(
            model_name="coreinvite",
            name="expires_at",
            field=models.DateTimeField(null=True),
        ),
    ]
