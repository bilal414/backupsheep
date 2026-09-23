import uuid

import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
from django.db import migrations, models


ENCRYPTION_LEDGER_SQL = r"""
CREATE FUNCTION backupsheep_assert_encryption_envelope_state(envelope_pk bigint)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    envelope_state varchar(24);
    envelope_sealed_at timestamptz;
    active_wrap_count bigint;
BEGIN
    SELECT status, sealed_at
      INTO envelope_state, envelope_sealed_at
      FROM core_backup_encryption_envelope
     WHERE id = envelope_pk;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT count(*)
      INTO active_wrap_count
      FROM core_backup_key_wrap
     WHERE envelope_id = envelope_pk AND status = 'active';

    IF envelope_state = 'active' THEN
        IF envelope_sealed_at IS NULL OR active_wrap_count <> 1 THEN
            RAISE EXCEPTION 'active encryption envelope requires one active key wrap'
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF active_wrap_count <> 0 THEN
        RAISE EXCEPTION 'active key wrap requires an active encryption envelope'
            USING ERRCODE = 'check_violation';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM core_backup_artifact
         WHERE encryption_envelope_id = envelope_pk
           AND artifact_format = 'bse1'
    ) AND (envelope_state <> 'active' OR active_wrap_count <> 1) THEN
        RAISE EXCEPTION 'BSE1 artifact requires a restore-ready encryption envelope'
            USING ERRCODE = 'check_violation';
    END IF;
END;
$$;

CREATE FUNCTION backupsheep_envelope_state_constraint()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM backupsheep_assert_encryption_envelope_state(OLD.id);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        PERFORM backupsheep_assert_encryption_envelope_state(NEW.id);
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION backupsheep_key_wrap_state_constraint()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM backupsheep_assert_encryption_envelope_state(OLD.envelope_id);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        PERFORM backupsheep_assert_encryption_envelope_state(NEW.envelope_id);
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION backupsheep_artifact_encryption_constraint()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    artifact_format varchar(24);
    artifact_envelope_id bigint;
    artifact_content_type_id bigint;
    artifact_object_id bigint;
    execution_content_type_id bigint;
    execution_object_id bigint;
    envelope_state varchar(24);
    envelope_sealed_at timestamptz;
    active_wrap_count bigint;
BEGIN
    SELECT current_artifact.artifact_format,
           current_artifact.encryption_envelope_id,
           current_artifact.backup_content_type_id,
           current_artifact.backup_object_id
      INTO artifact_format,
           artifact_envelope_id,
           artifact_content_type_id,
           artifact_object_id
      FROM core_backup_artifact current_artifact
     WHERE current_artifact.id = NEW.id;

    -- A deferred event can survive until after the row was cascade-deleted.
    IF NOT FOUND OR artifact_format <> 'bse1' THEN
        RETURN NULL;
    END IF;

    SELECT execution.backup_content_type_id,
           execution.backup_object_id,
           envelope.status,
           envelope.sealed_at,
           (SELECT count(*)
              FROM core_backup_key_wrap key_wrap
             WHERE key_wrap.envelope_id = envelope.id
               AND key_wrap.status = 'active')
      INTO execution_content_type_id,
           execution_object_id,
           envelope_state,
           envelope_sealed_at,
           active_wrap_count
      FROM core_backup_encryption_envelope envelope
      JOIN core_backup_execution execution ON execution.id = envelope.execution_id
     WHERE envelope.id = artifact_envelope_id;

    IF NOT FOUND
       OR execution_content_type_id IS DISTINCT FROM artifact_content_type_id
       OR execution_object_id IS DISTINCT FROM artifact_object_id
       OR envelope_state <> 'active'
       OR envelope_sealed_at IS NULL
       OR active_wrap_count <> 1 THEN
        RAISE EXCEPTION 'BSE1 artifact ownership or encryption state is invalid'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION backupsheep_envelope_immutable_fields()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.uuid IS DISTINCT FROM OLD.uuid
       OR NEW.execution_id IS DISTINCT FROM OLD.execution_id
       OR NEW.context_canonical_json IS DISTINCT FROM OLD.context_canonical_json
       OR NEW.context_sha256 IS DISTINCT FROM OLD.context_sha256 THEN
        RAISE EXCEPTION 'encryption envelope identity and context are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    -- sealed_at is the one-way publication latch. Checking the latch rather
    -- than OLD.status prevents active -> pending -> mutate status dances.
    IF OLD.sealed_at IS NOT NULL AND (
       NEW.format_version IS DISTINCT FROM OLD.format_version
       OR NEW.algorithm IS DISTINCT FROM OLD.algorithm
       OR NEW.chunk_size IS DISTINCT FROM OLD.chunk_size
       OR NEW.header_sha256 IS DISTINCT FROM OLD.header_sha256
       OR NEW.plaintext_byte_count IS DISTINCT FROM OLD.plaintext_byte_count
       OR NEW.plaintext_sha256 IS DISTINCT FROM OLD.plaintext_sha256
       OR NEW.ciphertext_byte_count IS DISTINCT FROM OLD.ciphertext_byte_count
       OR NEW.sealed_at IS DISTINCT FROM OLD.sealed_at) THEN
        RAISE EXCEPTION 'sealed encryption envelope witnesses are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION backupsheep_key_wrap_immutable_fields()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.uuid IS DISTINCT FROM OLD.uuid
       OR NEW.envelope_id IS DISTINCT FROM OLD.envelope_id
       OR NEW.generation IS DISTINCT FROM OLD.generation THEN
        RAISE EXCEPTION 'key-wrap generation identity is immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    -- activated_at is the one-way custody latch for the same reason.
    IF OLD.activated_at IS NOT NULL AND (
       NEW.provider IS DISTINCT FROM OLD.provider
       OR NEW.wrapping_key_id IS DISTINCT FROM OLD.wrapping_key_id
       OR NEW.wrapped_data_key IS DISTINCT FROM OLD.wrapped_data_key
       OR NEW.wrapped_key_sha256 IS DISTINCT FROM OLD.wrapped_key_sha256
       OR NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
        RAISE EXCEPTION 'activated wrapped-key evidence is immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION backupsheep_execution_encryption_identity_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (NEW.backup_content_type_id IS DISTINCT FROM OLD.backup_content_type_id
        OR NEW.backup_object_id IS DISTINCT FROM OLD.backup_object_id)
       AND EXISTS (
           SELECT 1 FROM core_backup_encryption_envelope
            WHERE execution_id = OLD.id
       ) THEN
        RAISE EXCEPTION 'backup execution identity is immutable after encryption'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER backup_envelope_immutable_fields
BEFORE UPDATE ON core_backup_encryption_envelope
FOR EACH ROW EXECUTE FUNCTION backupsheep_envelope_immutable_fields();

CREATE TRIGGER backup_key_wrap_immutable_fields
BEFORE UPDATE ON core_backup_key_wrap
FOR EACH ROW EXECUTE FUNCTION backupsheep_key_wrap_immutable_fields();

CREATE TRIGGER backup_execution_encryption_identity_immutable
BEFORE UPDATE OF backup_content_type_id, backup_object_id ON core_backup_execution
FOR EACH ROW EXECUTE FUNCTION backupsheep_execution_encryption_identity_immutable();

CREATE CONSTRAINT TRIGGER backup_envelope_state_consistency
AFTER INSERT OR UPDATE OR DELETE ON core_backup_encryption_envelope
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION backupsheep_envelope_state_constraint();

CREATE CONSTRAINT TRIGGER backup_key_wrap_state_consistency
AFTER INSERT OR UPDATE OR DELETE ON core_backup_key_wrap
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION backupsheep_key_wrap_state_constraint();

CREATE CONSTRAINT TRIGGER backup_artifact_encryption_consistency
AFTER INSERT OR UPDATE ON core_backup_artifact
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION backupsheep_artifact_encryption_constraint();
"""


ENCRYPTION_LEDGER_REVERSE_SQL = r"""
DROP TRIGGER IF EXISTS backup_artifact_encryption_consistency ON core_backup_artifact;
DROP TRIGGER IF EXISTS backup_key_wrap_state_consistency ON core_backup_key_wrap;
DROP TRIGGER IF EXISTS backup_envelope_state_consistency ON core_backup_encryption_envelope;
DROP TRIGGER IF EXISTS backup_execution_encryption_identity_immutable ON core_backup_execution;
DROP TRIGGER IF EXISTS backup_key_wrap_immutable_fields ON core_backup_key_wrap;
DROP TRIGGER IF EXISTS backup_envelope_immutable_fields ON core_backup_encryption_envelope;
DROP FUNCTION IF EXISTS backupsheep_execution_encryption_identity_immutable();
DROP FUNCTION IF EXISTS backupsheep_key_wrap_immutable_fields();
DROP FUNCTION IF EXISTS backupsheep_envelope_immutable_fields();
DROP FUNCTION IF EXISTS backupsheep_artifact_encryption_constraint();
DROP FUNCTION IF EXISTS backupsheep_key_wrap_state_constraint();
DROP FUNCTION IF EXISTS backupsheep_envelope_state_constraint();
DROP FUNCTION IF EXISTS backupsheep_assert_encryption_envelope_state(bigint);
"""


class Migration(migrations.Migration):
    dependencies = [("apps", "0042_notification_delivery_outbox")]

    operations = [
        migrations.CreateModel(
            name="CoreBackupEncryptionEnvelope",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "created",
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="created",
                    ),
                ),
                (
                    "modified",
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="modified",
                    ),
                ),
                (
                    "uuid",
                    models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
                ),
                ("format_version", models.PositiveSmallIntegerField(default=1)),
                (
                    "algorithm",
                    models.CharField(default="AES-256-GCM-SIV", max_length=32),
                ),
                ("chunk_size", models.PositiveIntegerField(default=4194304)),
                ("context_canonical_json", models.CharField(max_length=2048)),
                ("context_sha256", models.CharField(max_length=64)),
                ("header_sha256", models.CharField(max_length=64)),
                ("plaintext_byte_count", models.PositiveBigIntegerField(default=0)),
                ("plaintext_sha256", models.CharField(max_length=64)),
                (
                    "ciphertext_byte_count",
                    models.PositiveBigIntegerField(default=0),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("active", "Active"),
                            ("manual_review", "Manual review"),
                            ("retired", "Retired"),
                        ],
                        default="pending",
                        max_length=24,
                    ),
                ),
                ("sealed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "execution",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="encryption_envelope",
                        to="apps.corebackupexecution",
                    ),
                ),
            ],
            options={
                "db_table": "core_backup_encryption_envelope",
                "indexes": [
                    models.Index(
                        fields=["status", "sealed_at"],
                        name="backup_envelope_status_idx",
                    )
                ],
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(
                            ("algorithm", "AES-256-GCM-SIV"),
                            ("format_version", 1),
                        ),
                        name="backup_envelope_bse1_algorithm",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            ("chunk_size__gte", 65536),
                            ("chunk_size__lte", 67108864),
                        ),
                        name="backup_envelope_chunk_bounds",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            models.Q(("status", "active"), _negated=True),
                            ("sealed_at__isnull", False),
                            _connector="OR",
                        ),
                        name="active_backup_envelope_is_sealed",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            (
                                "status__in",
                                ("pending", "active", "manual_review", "retired"),
                            )
                        ),
                        name="backup_envelope_status_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(("context_canonical_json__gt", "")),
                        name="backup_envelope_context_present",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            models.Q(("status", "active"), _negated=True),
                            ("ciphertext_byte_count__gt", 0),
                            _connector="OR",
                        ),
                        name="active_backup_envelope_has_ciphertext",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            ("context_sha256__regex", "^[0-9a-f]{64}$"),
                            ("header_sha256__regex", "^[0-9a-f]{64}$"),
                            ("plaintext_sha256__regex", "^[0-9a-f]{64}$"),
                        ),
                        name="backup_envelope_digests_valid",
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name="CoreBackupKeyWrap",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "created",
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="created",
                    ),
                ),
                (
                    "modified",
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="modified",
                    ),
                ),
                (
                    "uuid",
                    models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
                ),
                ("generation", models.PositiveIntegerField(default=1)),
                (
                    "provider",
                    models.CharField(
                        choices=[
                            ("aws-kms", "AWS KMS"),
                            ("local-development", "Local development"),
                        ],
                        max_length=32,
                    ),
                ),
                ("wrapping_key_id", models.CharField(max_length=2048)),
                (
                    "wrapped_data_key",
                    models.BinaryField(editable=False, max_length=8192),
                ),
                ("wrapped_key_sha256", models.CharField(max_length=64)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("active", "Active"),
                            ("manual_review", "Manual review"),
                            ("retired", "Retired"),
                        ],
                        default="pending",
                        max_length=24,
                    ),
                ),
                ("activated_at", models.DateTimeField(blank=True, null=True)),
                ("retired_at", models.DateTimeField(blank=True, null=True)),
                (
                    "envelope",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="key_wraps",
                        to="apps.corebackupencryptionenvelope",
                    ),
                ),
            ],
            options={
                "db_table": "core_backup_key_wrap",
                "indexes": [
                    models.Index(
                        fields=["provider", "status"],
                        name="backup_key_wrap_state_idx",
                    )
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("envelope", "generation"),
                        name="unique_backup_key_wrap_generation",
                    ),
                    models.UniqueConstraint(
                        condition=models.Q(("status", "active")),
                        fields=("envelope",),
                        name="unique_active_backup_key_wrap",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(("generation__gte", 1)),
                        name="backup_key_wrap_generation_positive",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            models.Q(("status", "active"), _negated=True),
                            ("activated_at__isnull", False),
                            _connector="OR",
                        ),
                        name="active_backup_key_wrap_is_activated",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            (
                                "status__in",
                                ("pending", "active", "manual_review", "retired"),
                            )
                        ),
                        name="backup_key_wrap_status_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            ("provider__in", ("aws-kms", "local-development"))
                        ),
                        name="backup_key_wrap_provider_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            models.Q(("status", "retired"), _negated=True),
                            ("retired_at__isnull", False),
                            _connector="OR",
                        ),
                        name="retired_backup_key_wrap_has_witness",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(("wrapping_key_id__gt", "")),
                        name="backup_key_wrap_key_id_present",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            ("wrapped_key_sha256__regex", "^[0-9a-f]{64}$")
                        ),
                        name="backup_key_wrap_digest_valid",
                    ),
                ],
            },
        ),
        migrations.AddField(
            model_name="corebackupartifact",
            name="artifact_format",
            field=models.CharField(
                choices=[
                    ("legacy_zip", "Legacy ZIP"),
                    ("bse1", "BSE1 encrypted envelope"),
                ],
                default="legacy_zip",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="corebackupartifact",
            name="encryption_envelope",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.RESTRICT,
                related_name="artifacts",
                to="apps.corebackupencryptionenvelope",
            ),
        ),
        migrations.AddConstraint(
            model_name="corebackupartifact",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(
                        ("artifact_format", "legacy_zip"),
                        ("encryption_envelope__isnull", True),
                    ),
                    models.Q(
                        ("artifact_format", "bse1"),
                        ("encryption_envelope__isnull", False),
                    ),
                    _connector="OR",
                ),
                name="backup_artifact_format_envelope",
            ),
        ),
        migrations.RunSQL(
            sql=ENCRYPTION_LEDGER_SQL,
            reverse_sql=ENCRYPTION_LEDGER_REVERSE_SQL,
        ),
    ]
