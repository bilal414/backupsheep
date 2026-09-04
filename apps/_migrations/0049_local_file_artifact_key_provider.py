from django.db import migrations, models


LEGACY_BACKUP_TABLES = (
    "core_website_backup",
    "core_website_backup_mtm_storage_points",
    "core_wordpress_backup",
    "core_wordpress_backup_mtm_storage_points",
    "core_basecamp_backup",
    "core_basecamp_backup_mtm_storage_points",
    "core_database_backup",
    "core_database_backup_mtm_storage_points",
    "core_hosting_backup",
)

_LEGACY_BACKUP_PROBE_SQL_BY_TABLE = {
    "core_website_backup": "SELECT 1 FROM core_website_backup LIMIT 1",
    "core_website_backup_mtm_storage_points": (
        "SELECT 1 FROM core_website_backup_mtm_storage_points LIMIT 1"
    ),
    "core_wordpress_backup": "SELECT 1 FROM core_wordpress_backup LIMIT 1",
    "core_wordpress_backup_mtm_storage_points": (
        "SELECT 1 FROM core_wordpress_backup_mtm_storage_points LIMIT 1"
    ),
    "core_basecamp_backup": "SELECT 1 FROM core_basecamp_backup LIMIT 1",
    "core_basecamp_backup_mtm_storage_points": (
        "SELECT 1 FROM core_basecamp_backup_mtm_storage_points LIMIT 1"
    ),
    "core_database_backup": "SELECT 1 FROM core_database_backup LIMIT 1",
    "core_database_backup_mtm_storage_points": (
        "SELECT 1 FROM core_database_backup_mtm_storage_points LIMIT 1"
    ),
    "core_hosting_backup": "SELECT 1 FROM core_hosting_backup LIMIT 1",
}


def _execute_legacy_backup_probe(cursor, table_name):
    if tuple(_LEGACY_BACKUP_PROBE_SQL_BY_TABLE) != LEGACY_BACKUP_TABLES:
        raise RuntimeError("Legacy backup-table SQL allowlist is out of sync.")
    try:
        statement = _LEGACY_BACKUP_PROBE_SQL_BY_TABLE[table_name]
    except (KeyError, TypeError) as error:
        raise RuntimeError(
            "Refusing an unreviewed legacy backup-table identifier."
        ) from error
    cursor.execute(statement)


def legacy_backup_inventory_exists(schema_editor):
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        present = set(connection.introspection.table_names(cursor))
        for table_name in LEGACY_BACKUP_TABLES:
            if table_name not in present:
                continue
            _execute_legacy_backup_probe(cursor, table_name)
            if cursor.fetchone() is not None:
                return True
    return False


def require_supported_forward_provider(apps, schema_editor):
    key_wrap = apps.get_model("apps", "CoreBackupKeyWrap")
    artifact = apps.get_model("apps", "CoreBackupArtifact")
    existing = key_wrap.objects.count()
    legacy_artifacts = artifact.objects.filter(artifact_format="legacy_zip").exists()
    legacy_backups = legacy_backup_inventory_exists(schema_editor)
    if existing or legacy_artifacts or legacy_backups:
        raise RuntimeError(
            "Transition to the local-file artifact key provider requires zero "
            "existing data-key wraps and zero legacy or unledgered backup, "
            "storage-point, and artifact records; automatic cryptographic "
            "conversion or retirement is intentionally refused."
        )


def require_supported_reverse_provider(apps, schema_editor):
    key_wrap = apps.get_model("apps", "CoreBackupKeyWrap")
    if key_wrap.objects.filter(provider="local-file").exists():
        raise RuntimeError(
            "Cannot reverse the local-file provider migration while local-file wraps exist."
        )


class Migration(migrations.Migration):
    dependencies = [("apps", "0048_detach_retired_wordpress_foreign_keys")]

    operations = [
        migrations.RemoveConstraint(
            model_name="corebackupkeywrap",
            name="backup_key_wrap_provider_valid",
        ),
        migrations.RunPython(
            require_supported_forward_provider,
            require_supported_reverse_provider,
        ),
        migrations.AlterField(
            model_name="corebackupkeywrap",
            name="provider",
            field=models.CharField(
                choices=[
                    ("local-file", "Local file"),
                    ("local-development", "Local development"),
                ],
                max_length=32,
            ),
        ),
        migrations.AddConstraint(
            model_name="corebackupkeywrap",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    provider__in=("local-file", "local-development")
                ),
                name="backup_key_wrap_provider_valid",
            ),
        ),
    ]
