"""Create the DatabaseCache table used by the default cache backend.

settings.CACHES uses django.core.cache.backends.db.DatabaseCache (LOCATION "core_cache").
`migrate` never creates that table -- only `createcachetable` does -- yet the cache is
exercised at runtime (cache_page on API views, OVH OAuth consumer-key caching, and the
backup-timeout exception path). Without the table those code paths raise
ProgrammingError: relation "core_cache" does not exist. Running createcachetable here
guarantees a fresh install (and the docker `migrate` one-shot) provisions it. Idempotent:
createcachetable skips tables that already exist.
"""
from django.core.management import call_command
from django.db import migrations


def create_cache_table(apps, schema_editor):
    call_command("createcachetable")


class Migration(migrations.Migration):

    dependencies = [
        ("apps", "0010_coreauthwebsite_verify_ssl"),
    ]

    operations = [
        migrations.RunPython(create_cache_table, migrations.RunPython.noop),
    ]
