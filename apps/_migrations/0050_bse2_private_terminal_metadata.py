from django.db import migrations, models


def _encryption_rows_exist(apps):
    envelope = apps.get_model("apps", "CoreBackupEncryptionEnvelope")
    key_wrap = apps.get_model("apps", "CoreBackupKeyWrap")
    return envelope.objects.exists() or key_wrap.objects.exists()


def require_empty_forward_encryption_ledger(apps, schema_editor):
    del schema_editor
    if _encryption_rows_exist(apps):
        raise RuntimeError(
            "Transition to the BSE v2 private terminal format requires zero "
            "existing encryption envelopes and zero data-key wraps; automatic "
            "conversion of v1, orphan, pending, or manually inserted rows is "
            "intentionally refused."
        )


def require_empty_reverse_encryption_ledger(apps, schema_editor):
    del schema_editor
    if _encryption_rows_exist(apps):
        raise RuntimeError(
            "Cannot reverse the BSE v2 private terminal migration while any "
            "encryption envelope or data-key wrap exists."
        )


class Migration(migrations.Migration):
    dependencies = [("apps", "0049_local_file_artifact_key_provider")]

    operations = [
        # Keep the data gate ahead of every schema mutation in both directions.
        # The paired no-op at the end runs its reverse gate first on rollback.
        migrations.RunPython(
            require_empty_forward_encryption_ledger,
            migrations.RunPython.noop,
        ),
        migrations.RemoveConstraint(
            model_name="corebackupencryptionenvelope",
            name="backup_envelope_bse1_algorithm",
        ),
        migrations.AlterField(
            model_name="corebackupencryptionenvelope",
            name="format_version",
            field=models.PositiveSmallIntegerField(default=2),
        ),
        migrations.AddConstraint(
            model_name="corebackupencryptionenvelope",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    format_version=2,
                    algorithm="AES-256-GCM-SIV",
                ),
                name="backup_envelope_bse1_algorithm",
            ),
        ),
        migrations.RunPython(
            migrations.RunPython.noop,
            require_empty_reverse_encryption_ledger,
        ),
    ]
