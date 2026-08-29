"""Apply schema migrations and prove the current artifact-provider transition."""

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from apps.console.backup.models import (
    CoreBackupArtifact,
    CoreBackupKeyWrap,
    CoreBasecampBackup,
    CoreBasecampBackupStoragePoints,
    CoreDatabaseBackup,
    CoreDatabaseBackupStoragePoints,
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
)
from apps._tasks.artifact_deletion import validate_deletion_origin


_BACKUP_FAMILIES = (
    (CoreWebsiteBackup, CoreWebsiteBackupStoragePoints),
    (CoreBasecampBackup, CoreBasecampBackupStoragePoints),
    (CoreDatabaseBackup, CoreDatabaseBackupStoragePoints),
)
_RETIRED_BACKUP_TABLES = (
    "core_wordpress_backup",
    "core_wordpress_backup_mtm_storage_points",
    "core_hosting_backup",
)


def _retired_backup_inventory_exists() -> bool:
    """Return true when retained out-of-state legacy backup rows still exist."""

    with connection.cursor() as cursor:
        present = set(connection.introspection.table_names(cursor))
        for table_name in _RETIRED_BACKUP_TABLES:
            if table_name not in present:
                continue
            cursor.execute(
                f"SELECT 1 FROM {connection.ops.quote_name(table_name)} LIMIT 1"
            )
            if cursor.fetchone() is not None:
                return True
    return False


def _any_backup_inventory_exists() -> bool:
    """Conservatively identify any record that may name a pre-BSE1 archive."""

    return any(
        backup_model.objects.exists() or point_model.objects.exists()
        for backup_model, point_model in _BACKUP_FAMILIES
    ) or _retired_backup_inventory_exists()


def _recoverable_point_statuses(point_model) -> tuple[int, ...]:
    """Unresolved states that require source custody so a worker can reconcile."""

    names = (
        "UPLOAD_IN_PROGRESS",
        "UPLOAD_RETRY",
        "UPLOAD_VALIDATION",
        "STORAGE_VALIDATION_FAILED",
    )
    return tuple(int(getattr(point_model.Status, name)) for name in names)


def _retained_point_statuses(point_model) -> tuple[int, ...]:
    """Committed/deletion states that require an exact verified destination ledger."""

    names = (
        "UPLOAD_COMPLETE",
    )
    return tuple(int(getattr(point_model.Status, name)) for name in names)


def _deletion_point_statuses(point_model) -> tuple[int, ...]:
    return tuple(
        int(getattr(point_model.Status, name))
        for name in ("DELETE_REQUESTED", "DELETE_FAILED")
    )


def _backup_output_statuses(backup_model) -> tuple[int, ...]:
    """Statuses that require committed source custody."""

    names = (
        "COMPLETE",
        "PARTIAL",
        "UPLOAD_IN_PROGRESS",
        "UPLOAD_VALIDATION",
        "UPLOAD_COMPLETE",
    )
    return tuple(int(getattr(backup_model.Status, name)) for name in names)


def _backup_preseal_recovery_statuses(backup_model) -> tuple[int, ...]:
    """Crash gaps that may safely resume with no envelope or a complete one."""

    return tuple(
        int(getattr(backup_model.Status, name))
        for name in ("DOWNLOAD_COMPLETE", "UPLOAD_READY")
    )


def _artifact_has_durable_shape(artifact) -> bool:
    """Require the canonical verified source/destination identity fields."""

    envelope = artifact.encryption_envelope
    if (
        artifact.verified_at is None
        or artifact.byte_count <= 0
        or artifact.byte_count != envelope.ciphertext_byte_count
        or artifact.checksum_algorithm != "sha256"
        or not envelope._valid_sha256(artifact.checksum_value)
        or not artifact.object_key
    ):
        return False
    if artifact.role == CoreBackupArtifact.Role.SOURCE:
        backup = artifact.backup
        expected_name = f"{backup.uuid_str}.bse1" if backup is not None else ""
        return bool(
            artifact.storage_id is None
            and artifact.object_key == expected_name
            and (artifact.metadata or {}).get("transfer_artifact_name")
            == expected_name
        )
    return bool(
        artifact.role
        in {
            CoreBackupArtifact.Role.ARCHIVE,
            CoreBackupArtifact.Role.DESTINATION,
        }
        and artifact.storage_id is not None
    )


def _destination_storage_point(artifact):
    """Resolve one destination artifact to its exact typed storage-point owner."""

    backup = artifact.backup
    for backup_model, point_model in _BACKUP_FAMILIES:
        if not isinstance(backup, backup_model):
            continue
        candidates = list(
            point_model.objects.filter(
                backup_id=backup.pk,
                storage_id=artifact.storage_id,
            ).order_by("pk")[:2]
        )
        return candidates[0] if len(candidates) == 1 else None
    return None


def _destination_matches_source(artifact, source_artifact, storage_point) -> bool:
    """Bind every destination/archive row to its source and storage object."""

    return bool(
        storage_point is not None
        and artifact.object_key == str(storage_point.storage_file_id or "")
        and artifact.encryption_envelope_id
        == source_artifact.encryption_envelope_id
        and artifact.byte_count == source_artifact.byte_count
        and artifact.checksum_algorithm == "sha256"
        and artifact.checksum_value == source_artifact.checksum_value
    )


def _unledgered_backup_inventory_exists() -> bool:
    """Validate BSE1 custody and only require ledgers for output-bearing states."""

    from apps._tasks.artifact_encryption import (
        ArtifactPipelineError,
        _exact_destination_ciphertext_artifact,
        _load_active_source_state,
    )

    artifacts = CoreBackupArtifact.objects.filter(
        artifact_format=CoreBackupArtifact.Format.BSE1
    ).select_related("encryption_envelope__execution", "storage")
    for artifact in artifacts.iterator(chunk_size=500):
        try:
            artifact.validate_encrypted_restore_state()
            if not _artifact_has_durable_shape(artifact):
                return True
            source = _load_active_source_state(artifact.backup, allow_absent=False)
            if artifact.role == CoreBackupArtifact.Role.SOURCE:
                if source.artifact.pk != artifact.pk:
                    return True
            else:
                storage_point = _destination_storage_point(artifact)
                if not _destination_matches_source(
                    artifact,
                    source.artifact,
                    storage_point,
                ):
                    return True
                exact_destination = _exact_destination_ciphertext_artifact(
                    artifact.backup,
                    storage_point,
                    source.artifact,
                )
                if exact_destination.pk != artifact.pk:
                    return True
        except (
            ArtifactPipelineError,
            AttributeError,
            ObjectDoesNotExist,
            ValidationError,
        ):
            return True

    for backup_model, point_model in _BACKUP_FAMILIES:
        successful = backup_model.objects.filter(
            status__in=_backup_output_statuses(backup_model)
        )
        for backup in successful.iterator(chunk_size=250):
            try:
                _load_active_source_state(backup, allow_absent=False)
            except (ArtifactPipelineError, ValidationError):
                return True

        preseal_recovery = backup_model.objects.filter(
            status__in=_backup_preseal_recovery_statuses(backup_model)
        )
        for backup in preseal_recovery.iterator(chunk_size=250):
            try:
                _load_active_source_state(backup, allow_absent=True)
            except (ArtifactPipelineError, ValidationError):
                return True

        recoverable_points = point_model.objects.filter(
            status__in=_recoverable_point_statuses(point_model)
        ).select_related("backup")
        for point in recoverable_points.iterator(chunk_size=250):
            try:
                _load_active_source_state(point.backup, allow_absent=False)
            except (ArtifactPipelineError, ValidationError):
                return True

        retained_points = point_model.objects.filter(
            status__in=_retained_point_statuses(point_model)
        ).select_related("backup")
        for point in retained_points.iterator(chunk_size=250):
            try:
                source = _load_active_source_state(point.backup, allow_absent=False)
                _exact_destination_ciphertext_artifact(
                    point.backup,
                    point,
                    source.artifact,
                )
            except (ArtifactPipelineError, ValidationError):
                return True

        deletion_points = point_model.objects.filter(
            status__in=_deletion_point_statuses(point_model)
        ).select_related("backup")
        for point in deletion_points.iterator(chunk_size=250):
            origin = validate_deletion_origin(point)
            if origin is None:
                return True
            custody, _previous_status = origin
            try:
                source = _load_active_source_state(
                    point.backup,
                    allow_absent=custody == "no-object",
                )
                if custody == "committed-object":
                    _exact_destination_ciphertext_artifact(
                        point.backup,
                        point,
                        source.artifact,
                    )
                elif custody == "ambiguous" and source is None:
                    return True
            except (ArtifactPipelineError, ValidationError):
                return True
    return _retired_backup_inventory_exists()


def verify_artifact_provider_rows(*, generation: str) -> None:
    """Reject incompatible wraps or legacy artifacts using current database state."""

    wraps = CoreBackupKeyWrap.objects.all()
    legacy_artifacts = CoreBackupArtifact.objects.filter(
        artifact_format=CoreBackupArtifact.Format.LEGACY_ZIP
    )
    if generation == "1-pending-empty":
        if (
            wraps.exists()
            or legacy_artifacts.exists()
            or _any_backup_inventory_exists()
        ):
            raise CommandError(
                "Artifact key-provider transition requires zero data-key wraps and "
                "zero legacy or unledgered backup, storage-point, and artifact records."
            )
        return
    if generation != "1":
        raise CommandError("Artifact key-provider generation is not deployable.")
    if wraps.exclude(provider=CoreBackupKeyWrap.Provider.LOCAL_FILE).exists():
        raise CommandError(
            "Production artifact custody contains a non-local-file data-key wrap."
        )
    if legacy_artifacts.exists():
        raise CommandError(
            "Production artifact custody contains a legacy plaintext artifact record."
        )
    if _unledgered_backup_inventory_exists():
        raise CommandError(
            "Production artifact custody contains a backup or storage-point record "
            "without an exact BSE1 artifact ledger."
        )


class Command(BaseCommand):
    help = "Apply migrations, then prove local-file artifact-provider database state."

    def handle(self, *args, **options):
        call_command("migrate", interactive=False, verbosity=options.get("verbosity", 1))
        verify_artifact_provider_rows(
            generation=str(
                getattr(
                    settings,
                    "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION",
                    "",
                )
            )
        )
        self.stdout.write("Artifact key-provider database state verified.")
