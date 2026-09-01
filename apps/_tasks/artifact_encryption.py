"""Fail-closed BSE1 integration for source, storage, and restore workers.

Plaintext ZIPs exist only in a source/restore lane's private work volume.  A
source validates the ZIP before generating a wrapped data key, publishes one BSE1
envelope through the ciphertext fence, and then activates its database ledger
in one transaction.  Storage workers materialize only those ciphertext bytes.
Restore authenticates the full envelope into anonymous private staging before a
ZIP path becomes visible to an extraction engine.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import stat
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from apps.console.backup.models import (
    CoreBackupArtifact,
    CoreBackupEncryptionEnvelope,
    CoreBackupKeyWrap,
)
from backupsheep.artifact_crypto import (
    ArtifactContext,
    EnvelopeExpectation,
    LocalDevelopmentKeyProvider,
    LocalFileKeyProvider,
    WrappedDataKey,
    artifact_provider_policy_witness,
    open_artifact_source,
    read_envelope_header,
    seal_file,
    unseal_file,
)
from backupsheep.artifact_crypto.providers.base import zeroize


_BUFFER_SIZE = 1024 * 1024
_RESTORE_HANDOFF_METADATA_KEY = "local_restore_ciphertext_handoff"


class ArtifactPipelineError(RuntimeError):
    """An encryption or durable-ledger boundary was incomplete or inconsistent."""


@dataclass(frozen=True, slots=True)
class ActiveArtifactState:
    artifact: CoreBackupArtifact
    envelope: CoreBackupEncryptionEnvelope
    key_wrap: CoreBackupKeyWrap
    context: ArtifactContext
    transfer_name: str


@dataclass(frozen=True, slots=True)
class RestoreEncryptionPlan:
    artifact: CoreBackupArtifact
    envelope: CoreBackupEncryptionEnvelope
    context: ArtifactContext
    wrapped_data_key: WrappedDataKey


@dataclass(frozen=True, slots=True)
class StorageArtifactIdentity:
    """The only filename/object identity an adapter may expose for this artifact."""

    identifier: str
    filename: str
    artifact_format: str
    ownership_marker: str
    content_type: str


def local_restore_phase_task_id(restore, phase: str) -> str:
    """Derive the stable Celery id for one restore ciphertext handoff phase."""

    if phase not in {"stage", "cleanup"}:
        raise ArtifactPipelineError("The restore handoff phase is invalid.")
    try:
        correlation_id = str(uuid.UUID(str(restore.correlation_id)))
        model_label = str(restore._meta.label_lower)
        restore_id = int(restore.pk)
    except (AttributeError, TypeError, ValueError):
        raise ArtifactPipelineError(
            "The restore handoff task identity is invalid."
        ) from None
    if not model_label or restore_id <= 0:
        raise ArtifactPipelineError("The restore handoff task identity is invalid.")
    return uuid.uuid5(
        uuid.NAMESPACE_URL,
        "backupsheep:local-restore:"
        f"{phase}:{model_label}:{restore_id}:{correlation_id}",
    ).hex


def restore_ciphertext_handoff_identity(
    restore,
    plan: RestoreEncryptionPlan,
) -> dict[str, object]:
    """Return the exact DB-bound identity for one reverse ciphertext handoff."""

    try:
        handoff_uuid = str(uuid.UUID(str(restore.correlation_id)))
    except (AttributeError, TypeError, ValueError):
        raise ArtifactPipelineError(
            "The restore handoff identifier is invalid."
        ) from None
    model_name = str(getattr(restore._meta, "model_name", ""))
    target_lane = {
        "corewebsiterestore": "files",
        "coredatabaserestore": "database",
    }.get(model_name)
    if target_lane is None or plan.context.lane != target_lane:
        raise ArtifactPipelineError(
            "The restore handoff is bound to the wrong source lane."
        )
    return {
        "handoff_uuid": handoff_uuid,
        "backup_uuid": plan.context.backup_id,
        "target_lane": target_lane,
        "artifact_name": f"{plan.envelope.uuid}.bse1",
        "envelope_id": str(plan.envelope.uuid),
        "context_sha256": plan.envelope.context_sha256,
        "size_bytes": plan.artifact.byte_count,
        "sha256": plan.artifact.checksum_value,
    }


def _handoff_matches(value, expected, *, statuses) -> bool:
    return bool(
        isinstance(value, dict)
        and value.get("status") in statuses
        and all(value.get(key) == expected[key] for key in expected)
    )


def _handoff_timestamp(value, key: str) -> tuple[str, datetime]:
    raw = value.get(key) if isinstance(value, dict) else None
    if not isinstance(raw, str) or not raw or raw != raw.strip():
        raise ArtifactPipelineError(
            f"The restore handoff {key} witness is missing or malformed."
        )
    try:
        parsed = datetime.fromisoformat(raw)
    except (OverflowError, ValueError):
        raise ArtifactPipelineError(
            f"The restore handoff {key} witness is missing or malformed."
        ) from None
    if timezone.is_naive(parsed):
        raise ArtifactPipelineError(
            f"The restore handoff {key} witness is not timezone-aware."
        )
    return raw, parsed


def _terminal_restore_status(restore) -> str:
    if restore.status == restore.Status.COMPLETE:
        return "complete"
    if restore.status == restore.Status.FAILED:
        return "failed"
    raise ArtifactPipelineError("The restore is not in a terminal state.")


def _validate_cleanup_handoff_record(value, expected, terminal_status: str) -> None:
    if terminal_status not in {"complete", "failed"}:
        raise ArtifactPipelineError(
            "The completed restore handoff has an invalid terminal restore state."
        )
    if not _handoff_matches(value, expected, statuses={"cleanup_complete"}):
        raise ArtifactPipelineError(
            "The completed restore handoff evidence conflicts with its ledger."
        )
    if value.get("terminal_restore_status") != terminal_status:
        raise ArtifactPipelineError(
            "The completed restore handoff names a different terminal restore state."
        )
    ready_at, ready_time = _handoff_timestamp(value, "ready_at")
    completed_at, completed_time = _handoff_timestamp(value, "completed_at")
    authenticated_at = value.get("authenticated_at")
    authenticated_time = None
    if authenticated_at is not None:
        authenticated_at, authenticated_time = _handoff_timestamp(
            value, "authenticated_at"
        )
    if terminal_status == "complete" and authenticated_time is None:
        raise ArtifactPipelineError(
            "A completed restore handoff has no authenticated-ciphertext witness."
        )
    if authenticated_time is not None and authenticated_time < ready_time:
        raise ArtifactPipelineError(
            "The restore handoff authentication predates ciphertext readiness."
        )
    if completed_time < (authenticated_time or ready_time):
        raise ArtifactPipelineError(
            "The restore handoff cleanup predates its security witness."
        )
    if completed_time > timezone.now():
        raise ArtifactPipelineError(
            "The restore handoff cleanup witness is in the future."
        )
    allowed = {
        *expected,
        "status",
        "ready_at",
        "completed_at",
        "terminal_restore_status",
    }
    if authenticated_time is not None:
        allowed.add("authenticated_at")
    if set(value) != allowed:
        raise ArtifactPipelineError(
            "The completed restore handoff contains unreviewed evidence fields."
        )
    # Keep the raw values live in this validation path so a future refactor
    # cannot accidentally validate parsed timestamps but copy different bytes.
    if value["ready_at"] != ready_at or value["completed_at"] != completed_at:
        raise ArtifactPipelineError("The restore handoff timestamp witness changed.")
    if authenticated_time is not None and value["authenticated_at"] != authenticated_at:
        raise ArtifactPipelineError("The restore handoff timestamp witness changed.")


def _mode() -> str:
    value = str(
        getattr(settings, "BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE", "legacy-only")
    )
    if value not in {"bse1", "legacy-only"}:
        raise ArtifactPipelineError("The artifact encryption mode is invalid.")
    return value


def _enterprise_mode() -> bool:
    value = getattr(settings, "BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE", False)
    if type(value) is not bool:
        raise ArtifactPipelineError("The enterprise artifact policy is invalid.")
    return value


def _installation_id() -> str:
    value = str(getattr(settings, "BACKUPSHEEP_INSTALLATION_ID", ""))
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ArtifactPipelineError("The installation identity is invalid.")
    return value


def _artifact_context(backup) -> ArtifactContext:
    try:
        node = backup.node
        account = node.connection.account
        lane = "database" if backup._meta.model_name == "coredatabasebackup" else "files"
        return ArtifactContext(
            installation_id=_installation_id(),
            account_id=account.uuid_str,
            node_id=str(node.pk),
            backup_id=str(uuid.UUID(str(backup.uuid_str))),
            backup_model=backup._meta.label_lower,
            lane=lane,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise ArtifactPipelineError(
            "The backup identity cannot be bound to an artifact context."
        ) from error


def _new_envelope_id(backup_id: str) -> uuid.UUID:
    """Generate a v4 object identity that cannot reveal the backup identifier."""

    try:
        backup_uuid = uuid.UUID(str(backup_id))
    except (AttributeError, TypeError, ValueError):
        raise ArtifactPipelineError("The backup identifier is invalid.") from None
    for _attempt in range(4):
        candidate = uuid.uuid4()
        if candidate != backup_uuid:
            return candidate
    raise ArtifactPipelineError(
        "A distinct random encryption envelope identifier could not be generated."
    )


@contextmanager
def _configured_provider():
    provider_name = str(
        getattr(settings, "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER", "")
    )
    if provider_name == "local-file":
        runtime_role = str(os.environ.get("BACKUPSHEEP_RUNTIME_ROLE", ""))
        if runtime_role not in {"database", "files"}:
            raise ArtifactPipelineError(
                "The local-file artifact provider is restricted to a source lane."
            )
        installation_id = _installation_id()
        generation = str(
            getattr(settings, "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION", "")
        )
        witness = str(
            getattr(settings, "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS", "")
        )
        if generation != "1" or not hmac.compare_digest(
            witness,
            artifact_provider_policy_witness(installation_id, "1"),
        ):
            raise ArtifactPipelineError(
                "The local-file artifact provider generation is not sealed to this installation."
            )
        try:
            provider = LocalFileKeyProvider(
                str(
                    getattr(
                        settings,
                        "BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH",
                        "",
                    )
                ),
                lane=runtime_role,
                installation_id=installation_id,
            )
        except Exception as error:
            raise ArtifactPipelineError(
                "The lane-scoped artifact keyring is invalid."
            ) from error
    elif provider_name == "local-development":
        if _enterprise_mode() or str(getattr(settings, "DJANGO_SERVER", "")) == "prod":
            raise ArtifactPipelineError(
                "The local artifact key provider is unavailable in production."
            )
        try:
            decoded = bytearray(
                base64.b64decode(
                    str(
                        getattr(
                            settings,
                            "BACKUPSHEEP_ARTIFACT_LOCAL_WRAPPING_KEY",
                            "",
                        )
                    ),
                    validate=True,
                )
            )
        except (TypeError, ValueError) as error:
            raise ArtifactPipelineError(
                "The local development wrapping key is invalid."
            ) from error
        try:
            provider = LocalDevelopmentKeyProvider(
                decoded,
                key_id=str(
                    getattr(
                        settings,
                        "BACKUPSHEEP_ARTIFACT_LOCAL_KEY_ID",
                        "local-v1",
                    )
                ),
            )
        finally:
            zeroize(decoded)
    else:
        raise ArtifactPipelineError("The artifact key provider is invalid.")
    try:
        yield provider
    finally:
        destroy = getattr(provider, "destroy", None)
        if callable(destroy):
            destroy()


def _file_identity(path_or_file) -> tuple[int, str]:
    digest = hashlib.sha256()
    byte_count = 0
    should_close = not hasattr(path_or_file, "read")
    source = open(path_or_file, "rb") if should_close else path_or_file
    try:
        while True:
            chunk = source.read(_BUFFER_SIZE)
            if not chunk:
                break
            byte_count += len(chunk)
            digest.update(chunk)
    finally:
        if should_close:
            source.close()
    return byte_count, digest.hexdigest()


def _expectation(envelope: CoreBackupEncryptionEnvelope) -> EnvelopeExpectation:
    return EnvelopeExpectation(
        envelope_id=envelope.uuid,
        header_sha256=envelope.header_sha256,
        plaintext_size=envelope.plaintext_byte_count,
        plaintext_sha256=envelope.plaintext_sha256,
    )


def _validate_public_descriptor(
    descriptor, envelope: CoreBackupEncryptionEnvelope
) -> None:
    expected = _expectation(envelope)
    if (
        descriptor.envelope_id != expected.envelope_id
        or descriptor.header_sha256 != expected.header_sha256
        or descriptor.plaintext_size != expected.plaintext_size
        or descriptor.ciphertext_size != envelope.ciphertext_byte_count
        or descriptor.chunk_size != envelope.chunk_size
        or descriptor.version != envelope.format_version
        or descriptor.algorithm != envelope.algorithm
    ):
        raise ArtifactPipelineError(
            "The BSE1 envelope does not match its durable encryption ledger."
        )


def _validate_authenticated_descriptor(
    descriptor, envelope: CoreBackupEncryptionEnvelope
) -> None:
    _validate_public_descriptor(descriptor, envelope)
    if (
        descriptor.plaintext_sha256 != envelope.plaintext_sha256
        or descriptor.context_sha256 != envelope.context_sha256
    ):
        raise ArtifactPipelineError(
            "The authenticated BSE1 metadata does not match its durable encryption ledger."
        )


def _load_active_source_state(backup, *, allow_absent: bool) -> ActiveArtifactState | None:
    execution = backup.get_execution_state(create=False)
    if execution is None:
        if allow_absent:
            return None
        raise ArtifactPipelineError("The backup has no durable execution ledger.")
    envelope = CoreBackupEncryptionEnvelope.objects.filter(execution=execution).first()
    source_rows = list(
        backup.artifact_records.filter(role="source", storage__isnull=True).order_by("pk")
    )
    bse1_rows = [
        row
        for row in source_rows
        if row.artifact_format == CoreBackupArtifact.Format.BSE1
        or row.encryption_envelope_id is not None
    ]
    if envelope is None:
        if bse1_rows:
            raise ArtifactPipelineError(
                "A BSE1 source artifact is missing its encryption envelope."
            )
        if allow_absent:
            return None
        raise ArtifactPipelineError("The backup has no BSE1 encryption envelope.")
    if envelope.status != CoreBackupEncryptionEnvelope.Status.ACTIVE:
        raise ArtifactPipelineError("The backup encryption envelope is not active.")
    try:
        context, key_wrap = envelope.validate_restore_state()
    except ValidationError as error:
        raise ArtifactPipelineError(
            "The backup encryption custody ledger is incomplete."
        ) from error
    if (
        context != _artifact_context(backup)
        or envelope.uuid == uuid.UUID(context.backup_id)
    ):
        raise ArtifactPipelineError(
            "The encryption envelope is bound to a different backup context."
        )
    if len(source_rows) != 1:
        raise ArtifactPipelineError(
            "The backup must have exactly one durable source artifact."
        )
    artifact = source_rows[0]
    transfer_name = f"{envelope.uuid}.bse1"
    if (
        artifact.artifact_format != CoreBackupArtifact.Format.BSE1
        or artifact.encryption_envelope_id != envelope.pk
        or artifact.object_key != transfer_name
        or artifact.byte_count != envelope.ciphertext_byte_count
        or artifact.checksum_algorithm != "sha256"
        or not CoreBackupEncryptionEnvelope._valid_sha256(artifact.checksum_value)
        or artifact.verified_at is None
        or (artifact.metadata or {}).get("transfer_artifact_name") != transfer_name
    ):
        raise ArtifactPipelineError(
            "The BSE1 source artifact ledger is incomplete or inconsistent."
        )
    return ActiveArtifactState(artifact, envelope, key_wrap, context, transfer_name)


def storage_artifact_identity(backup) -> StorageArtifactIdentity:
    """Resolve a destination-safe name from the durable source custody ledger.

    BSE1 writes use only the random envelope UUID. The backup UUID filename is
    retained solely for an explicitly enabled legacy-plaintext operation.
    """

    if callable(getattr(backup, "get_execution_state", None)):
        state = _load_active_source_state(backup, allow_absent=True)
    else:
        state = None
    if state is not None:
        identifier = str(state.envelope.uuid)
        return StorageArtifactIdentity(
            identifier=identifier,
            filename=f"{identifier}.bse1",
            artifact_format=CoreBackupArtifact.Format.BSE1,
            ownership_marker=f"bse2:{identifier}",
            content_type="application/octet-stream",
        )
    if _mode() != "legacy-only" or _enterprise_mode():
        raise ArtifactPipelineError(
            "The storage object identity has no active encrypted source ledger."
        )
    identifier = str(getattr(backup, "uuid_str", "") or "")
    if (
        not identifier
        or len(identifier) > 255
        or identifier in {".", ".."}
        or "\x00" in identifier
        or "/" in identifier
        or "\\" in identifier
    ):
        raise ArtifactPipelineError(
            "The legacy storage object identity is invalid."
        )
    return StorageArtifactIdentity(
        identifier=identifier,
        filename=f"{identifier}.zip",
        artifact_format=CoreBackupArtifact.Format.LEGACY_ZIP,
        ownership_marker=str(
            getattr(backup, "pk", None) or getattr(backup, "id", None) or ""
        ),
        content_type="application/zip",
    )


def validate_storage_object_key(backup, object_key: object) -> StorageArtifactIdentity:
    """Require a new encrypted provider key to end in its opaque BSE1 name."""

    identity = storage_artifact_identity(backup)
    value = str(object_key or "")
    if not value or "\x00" in value or "\\" in value:
        raise ArtifactPipelineError("The storage object key is invalid.")
    basename = value.rstrip("/").rsplit("/", 1)[-1]
    if identity.artifact_format == CoreBackupArtifact.Format.BSE1:
        if basename != identity.filename:
            raise ArtifactPipelineError(
                "The storage object key is not bound to its artifact identity."
            )
        backup_uuid = str(uuid.UUID(str(backup.uuid_str)))
        if backup_uuid in value or value.endswith(".zip"):
            raise ArtifactPipelineError(
                "An encrypted storage object key exposes a private backup identity."
            )
    elif not basename.endswith(".zip"):
        raise ArtifactPipelineError(
            "The legacy storage object key is not a ZIP artifact."
        )
    return identity


def _delete_private_plaintext(archive_path: Path) -> None:
    parent = archive_path.parent
    for path in (
        archive_path,
        parent / f"{archive_path.stem}.manifest.json",
    ):
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ArtifactPipelineError(
                "The private plaintext cleanup target is not a regular file."
            )
        os.unlink(path)
    try:
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass


def _validate_published_source(state: ActiveArtifactState) -> None:
    from backupsheep.staging import create_ciphertext_fence

    fence = create_ciphertext_fence(
        state.context.backup_id,
        installation_id=state.context.installation_id,
    )
    path = fence.path / state.transfer_name
    descriptor = read_envelope_header(path, trusted_source_root=fence.path)
    _validate_public_descriptor(descriptor, state.envelope)
    byte_count, checksum = _file_identity(path)
    if (
        byte_count != state.artifact.byte_count
        or checksum != state.artifact.checksum_value
    ):
        raise ArtifactPipelineError(
            "The published source ciphertext no longer matches its ledger."
        )


def _persist_sealed_source(
    backup,
    sealed,
    ciphertext_path: Path,
    *,
    publish_ciphertext,
) -> CoreBackupArtifact:
    descriptor = sealed.envelope
    byte_count, checksum = _file_identity(ciphertext_path)
    if byte_count != descriptor.ciphertext_size:
        raise ArtifactPipelineError("The published ciphertext size changed.")
    verified_at = timezone.now()
    content_type = ContentType.objects.get_for_model(
        backup, for_concrete_model=False
    )
    transfer_name = ciphertext_path.name
    with transaction.atomic():
        locked_backup = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        execution = locked_backup._locked_execution_state(locked_backup)
        if CoreBackupEncryptionEnvelope.objects.filter(execution=execution).exists():
            raise ArtifactPipelineError(
                "An encryption envelope was published concurrently for this backup."
            )
        envelope = CoreBackupEncryptionEnvelope(
            uuid=descriptor.envelope_id,
            execution=execution,
            format_version=descriptor.version,
            algorithm=descriptor.algorithm,
            chunk_size=descriptor.chunk_size,
            header_sha256=descriptor.header_sha256,
            plaintext_byte_count=descriptor.plaintext_size,
            plaintext_sha256=descriptor.plaintext_sha256,
            ciphertext_byte_count=descriptor.ciphertext_size,
        )
        envelope.set_artifact_context(_artifact_context(locked_backup))
        envelope.full_clean()
        envelope.save()
        wrapped_bytes = bytes(sealed.wrapped_data_key.ciphertext)
        key_wrap = CoreBackupKeyWrap(
            envelope=envelope,
            generation=1,
            provider=sealed.wrapped_data_key.provider_name,
            wrapping_key_id=sealed.wrapped_data_key.wrapping_key_id,
            wrapped_data_key=wrapped_bytes,
            wrapped_key_sha256=hashlib.sha256(wrapped_bytes).hexdigest(),
        )
        key_wrap.full_clean()
        key_wrap.save()

        source_rows = list(
            CoreBackupArtifact.objects.select_for_update()
            .filter(
                backup_content_type=content_type,
                backup_object_id=locked_backup.pk,
                role="source",
                storage__isnull=True,
            )
            .order_by("pk")
        )
        if len(source_rows) > 1:
            raise ArtifactPipelineError(
                "The backup has conflicting source artifact records."
            )
        if source_rows:
            artifact = source_rows[0]
        else:
            material = f"source|source|{transfer_name}"
            artifact = CoreBackupArtifact(
                backup_content_type=content_type,
                backup_object_id=locked_backup.pk,
                role=CoreBackupArtifact.Role.SOURCE,
                idempotency_key=hashlib.sha256(material.encode("utf-8")).hexdigest(),
            )
        artifact.object_key = transfer_name
        artifact.byte_count = byte_count
        artifact.checksum_algorithm = "sha256"
        artifact.checksum_value = checksum
        artifact.verified_at = verified_at
        artifact.metadata = {
            "archive_format": "bse1",
            "plaintext_format": "zip",
            "transfer_artifact_name": transfer_name,
            "verification": "zip_crc_then_bse1_sha256",
        }
        # The deferred PostgreSQL trigger observes only the transaction's final
        # active state.  Keep the row legacy/null until activate_with_key_wrap
        # flips custody and publication together below.
        artifact.artifact_format = CoreBackupArtifact.Format.LEGACY_ZIP
        artifact.encryption_envelope = None
        artifact.full_clean()
        artifact.save()
        execution.artifact_bytes = byte_count
        execution.artifact_checksum_algorithm = "sha256"
        execution.artifact_checksum = checksum
        execution.artifact_verified_at = verified_at
        execution.save(
            update_fields=[
                "artifact_bytes",
                "artifact_checksum_algorithm",
                "artifact_checksum",
                "artifact_verified_at",
                "modified",
            ]
        )
        # The ciphertext identity and context now exist in the same pending DB
        # transaction. Publication changes only the already-validated inode's
        # mode from 0600 to 0640; activation is committed only after it succeeds.
        published = Path(publish_ciphertext())
        if published != ciphertext_path:
            raise ArtifactPipelineError(
                "The ciphertext publisher returned an unexpected artifact path."
            )
        published_metadata = os.lstat(published)
        if (
            not stat.S_ISREG(published_metadata.st_mode)
            or stat.S_ISLNK(published_metadata.st_mode)
            or published_metadata.st_size != byte_count
        ):
            raise ArtifactPipelineError(
                "The ciphertext changed during publication."
            )
        envelope.activate_with_key_wrap(key_wrap, artifacts=(artifact,))
    artifact.refresh_from_db()
    return artifact


def seal_or_validate_source_artifact(backup, archive_path, *, zip_verifier):
    """Return one active BSE1 source artifact, sealing plaintext at most once."""

    from backupsheep.staging import (
        cleanup_ciphertext_fence,
        create_ciphertext_fence,
        private_plaintext_root,
        publish_ciphertext,
        require_transfer_capacity,
    )

    active = _load_active_source_state(backup, allow_absent=True)
    root = private_plaintext_root()
    expected_archive = root / f"{backup.uuid_str}.zip"
    archive = Path(os.path.abspath(os.fspath(archive_path)))
    if archive != expected_archive:
        raise ArtifactPipelineError(
            "The source archive is outside its private plaintext root."
        )
    if active is not None:
        _validate_published_source(active)
        _delete_private_plaintext(archive)
        return active.artifact
    if _mode() != "bse1":
        raise ArtifactPipelineError("BSE1 source sealing is not enabled.")
    try:
        metadata = os.lstat(archive)
    except FileNotFoundError:
        raise FileNotFoundError("The local backup archive is missing.") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_nlink != 1
    ):
        raise ArtifactPipelineError(
            "The local backup archive is not a private regular file."
        )
    # The cheapest validation runs before opening lane root-key material.
    zip_verifier(str(archive))
    plaintext_size, plaintext_sha256 = _file_identity(archive)
    context = _artifact_context(backup)
    chunk_size = getattr(
        settings, "BACKUPSHEEP_ARTIFACT_CHUNK_SIZE", 4 * 1024 * 1024
    )
    chunk_count = (plaintext_size + chunk_size - 1) // chunk_size
    # Reserve the full plaintext payload plus a conservative maximum header and
    # per-record framing before the provider can generate a key or sealing can consume IO.
    require_transfer_capacity(
        required_bytes=plaintext_size + (64 * 1024) + (chunk_count * 64) + 128,
        required_inodes=3,
    )
    fence = create_ciphertext_fence(
        backup.uuid_str,
        installation_id=context.installation_id,
    )
    envelope_id = _new_envelope_id(backup.uuid_str)
    transfer_name = f"{envelope_id}.bse1"
    if any(name != ".backupsheep-ciphertext-fence-v1.json" for name in os.listdir(fence.path)):
        # No database ledger owns this inventory, so it can only be a complete
        # crash orphan.  The staging boundary validates every entry before delete.
        cleanup_ciphertext_fence(
            backup.uuid_str,
            installation_id=context.installation_id,
        )
        fence = create_ciphertext_fence(
            backup.uuid_str,
            installation_id=context.installation_id,
        )
    destination = fence.path / transfer_name
    with _configured_provider() as provider:
        sealed = seal_file(
            archive,
            destination,
            provider=provider,
            context=context,
            enterprise_mode=_enterprise_mode(),
            envelope_id=envelope_id,
            chunk_size=chunk_size,
            trusted_source_root=root,
            trusted_destination_root=fence.path,
        )
    if (
        sealed.envelope.plaintext_size != plaintext_size
        or sealed.envelope.plaintext_sha256 != plaintext_sha256
    ):
        raise ArtifactPipelineError(
            "The source archive changed while its BSE1 envelope was created."
        )
    artifact = _persist_sealed_source(
        backup,
        sealed,
        destination,
        publish_ciphertext=lambda: publish_ciphertext(
            backup.uuid_str,
            transfer_name,
            installation_id=context.installation_id,
        ),
    )
    _delete_private_plaintext(archive)
    return artifact


def _copy_ciphertext_atomically(source, destination: Path, expected) -> None:
    temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.partial"
    descriptor = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        digest = hashlib.sha256()
        byte_count = 0
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            while True:
                chunk = source.read(_BUFFER_SIZE)
                if not chunk:
                    break
                byte_count += len(chunk)
                if byte_count > expected.byte_count:
                    raise ArtifactPipelineError(
                        "The transfer ciphertext exceeds its committed byte count."
                    )
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if (
            byte_count != expected.byte_count
            or digest.hexdigest() != expected.checksum_value
        ):
            raise ArtifactPipelineError(
                "The transfer ciphertext failed its committed SHA-256 check."
            )
        os.replace(temporary, destination)
        directory_fd = os.open(
            destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


@contextmanager
def storage_upload_artifact(backup, *, legacy_verifier):
    """Materialize the exact upload input; BSE1 mode exposes no plaintext."""

    state = _load_active_source_state(backup, allow_absent=True)
    if state is None:
        if _mode() != "legacy-only" or _enterprise_mode():
            raise ArtifactPipelineError(
                "The storage worker requires an active BSE1 source ledger."
            )
        yield legacy_verifier(backup)
        return

    from backupsheep.staging import open_ciphertext, require_private_capacity

    root = require_private_capacity(
        required_bytes=state.artifact.byte_count,
        required_inodes=2,
    )
    object_identity = storage_artifact_identity(backup)
    destination = root / object_identity.filename
    try:
        with open_ciphertext(
            backup.uuid_str,
            state.transfer_name,
            source_lane=state.context.lane,
            installation_id=state.context.installation_id,
        ) as source:
            _copy_ciphertext_atomically(source, destination, state.artifact)
        descriptor = read_envelope_header(destination, trusted_source_root=root)
        _validate_public_descriptor(descriptor, state.envelope)
        yield state.artifact
    finally:
        try:
            metadata = os.lstat(destination)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ArtifactPipelineError(
                    "The storage-private ciphertext path became unsafe."
                )
            os.unlink(destination)


def _storage_point_object_key(stored_backup) -> str:
    object_key = str(stored_backup.storage_file_id or "")
    if not object_key or "\x00" in object_key:
        raise ArtifactPipelineError(
            "The storage adapter did not commit a valid object identity."
        )
    return object_key


def _destination_state_binding(stored_backup, artifact, object_key: str) -> None:
    """Bind provider readback evidence to one storage row and object version."""

    artifact_metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    state_key = str(artifact_metadata.get("storage_metadata_key") or "")
    metadata = stored_backup.metadata if isinstance(stored_backup.metadata, dict) else {}
    state = metadata.get(state_key) if state_key else None
    if not isinstance(state, dict) or not state:
        raise ArtifactPipelineError(
            "The destination artifact has no committed provider readback state."
        )
    if str(state.get("phase") or "").lower() != "committed":
        raise ArtifactPipelineError(
            "The destination provider readback state is not committed."
        )

    state_identities = {
        str(state[field])
        for field in (
            "storage_file_id",
            "object_key",
            "provider_id",
            "path",
            "provider_path",
            "file_id",
            "fileid",
        )
        if state.get(field) not in (None, "")
    }
    if object_key not in state_identities:
        raise ArtifactPipelineError(
            "The destination provider state identifies a different object."
        )

    try:
        state_bytes = int(state.get("size_bytes"))
    except (TypeError, ValueError):
        state_bytes = -1
    state_checksum = str(state.get("sha256") or "").lower()
    if (
        state_bytes != artifact.byte_count
        or state_checksum != artifact.checksum_value.lower()
        or len(state_checksum) != 64
    ):
        raise ArtifactPipelineError(
            "The destination provider state identifies different ciphertext bytes."
        )

    state_etag = str(
        state.get("etag")
        or state.get("content_hash")
        or state.get("provider_hash")
        or ""
    )
    artifact_etag = str(artifact.etag or "")
    if state_etag != artifact_etag:
        raise ArtifactPipelineError(
            "The destination provider ETag does not match its artifact ledger."
        )

    state_version = str(
        state.get("version_id")
        or state.get("generation")
        or state.get("revision")
        or ""
    )
    artifact_version = str(artifact.version_id or "")
    if state_version != artifact_version:
        raise ArtifactPipelineError(
            "The destination provider version does not match its artifact ledger."
        )


def _exact_destination_ciphertext_artifact(
    backup,
    stored_backup,
    source_artifact,
) -> CoreBackupArtifact:
    object_key = _storage_point_object_key(stored_backup)
    candidates = list(
        backup.artifact_records.filter(
            storage_id=stored_backup.storage_id,
            object_key=object_key,
            role__in=("archive", "destination"),
            verified_at__isnull=False,
        ).order_by("pk")
    )
    if len(candidates) != 1:
        raise ArtifactPipelineError(
            "The destination artifact ledger must contain exactly one verified record "
            "for the storage point object."
        )
    candidate = candidates[0]
    if (
        candidate.artifact_format != CoreBackupArtifact.Format.BSE1
        or candidate.encryption_envelope_id
        != source_artifact.encryption_envelope_id
        or candidate.byte_count != source_artifact.byte_count
        or candidate.checksum_algorithm != "sha256"
        or candidate.checksum_value != source_artifact.checksum_value
    ):
        raise ArtifactPipelineError(
            "The destination artifact ledger does not identify the source ciphertext."
        )
    _destination_state_binding(stored_backup, candidate, object_key)
    return candidate


def ensure_destination_ciphertext_ledger(backup, stored_backup, source_artifact) -> None:
    """Require authoritative provider readback for the exact uploaded ciphertext."""

    if source_artifact.artifact_format != CoreBackupArtifact.Format.BSE1:
        return
    stored_backup.refresh_from_db()
    if stored_backup.status != stored_backup.Status.UPLOAD_COMPLETE:
        raise ArtifactPipelineError(
            "The storage adapter did not commit a successful upload state."
        )
    _exact_destination_ciphertext_artifact(
        backup,
        stored_backup,
        source_artifact,
    )


def cleanup_terminal_source_ciphertext(backup, *, expected_lane: str) -> bool:
    """Remove a finalized source fence and persist a crash-safe cleanup witness."""

    if expected_lane not in {"database", "files"}:
        raise ArtifactPipelineError("The ciphertext cleanup lane is invalid.")
    with transaction.atomic():
        locked = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        execution = locked.get_execution_state(create=False)
        if (
            execution is None
            or execution.finished_at is None
            or execution.phase not in {"complete", "failed", "cancelled"}
            or locked.status in locked.ACTIVE_STATUSES
        ):
            raise ArtifactPipelineError(
                "The source ciphertext cannot be cleaned before finalization."
            )
        state = _load_active_source_state(locked, allow_absent=False)
        if state.context.lane != expected_lane:
            raise ArtifactPipelineError(
                "The source ciphertext cleanup was routed to the wrong lane."
            )
        metadata = dict(execution.metadata or {})
        cleanup = metadata.get("artifact_ciphertext_cleanup")
        if isinstance(cleanup, dict) and (
            cleanup.get("status") == "complete"
            and cleanup.get("envelope_id") == str(state.envelope.uuid)
            and cleanup.get("context_sha256") == state.envelope.context_sha256
        ):
            return False
        identity = (
            state.context.installation_id,
            state.context.backup_id,
            state.envelope.uuid,
            state.envelope.context_sha256,
        )

    from backupsheep.staging import cleanup_ciphertext_fence

    removed = cleanup_ciphertext_fence(
        identity[1],
        installation_id=identity[0],
    )

    with transaction.atomic():
        locked = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        execution = locked.get_execution_state(create=False)
        if (
            execution is None
            or execution.finished_at is None
            or execution.phase not in {"complete", "failed", "cancelled"}
            or locked.status in locked.ACTIVE_STATUSES
        ):
            raise ArtifactPipelineError(
                "The backup left its terminal state during ciphertext cleanup."
            )
        state = _load_active_source_state(locked, allow_absent=False)
        current_identity = (
            state.context.installation_id,
            state.context.backup_id,
            state.envelope.uuid,
            state.envelope.context_sha256,
        )
        if current_identity != identity or state.context.lane != expected_lane:
            raise ArtifactPipelineError(
                "The source ciphertext identity changed during cleanup."
            )
        metadata = dict(execution.metadata or {})
        metadata["artifact_ciphertext_cleanup"] = {
            "status": "complete",
            "envelope_id": str(state.envelope.uuid),
            "context_sha256": state.envelope.context_sha256,
            "completed_at": timezone.now().isoformat(),
        }
        execution.metadata = metadata
        execution.save(update_fields=["metadata", "modified"])
    return bool(removed)


def restore_encryption_plan(stored_backup) -> RestoreEncryptionPlan | None:
    """Resolve restore format from durable rows only; never sniff object bytes."""

    backup = stored_backup.backup
    # Some provider adapter tests use deliberately tiny stand-ins with no ORM
    # ledger surface.  They are eligible only for the explicit legacy policy;
    # BSE1/enterprise execution still fails closed rather than inferring bytes.
    if not callable(getattr(backup, "get_execution_state", None)):
        allow_legacy = getattr(
            settings, "BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE", False
        )
        if (
            _mode() == "legacy-only"
            and type(allow_legacy) is bool
            and allow_legacy
            and not _enterprise_mode()
        ):
            return None
        raise ArtifactPipelineError(
            "The selected backup has no durable artifact execution ledger."
        )
    state = _load_active_source_state(backup, allow_absent=True)
    object_key = _storage_point_object_key(stored_backup)
    destination_rows = list(
        backup.artifact_records.filter(
            storage_id=stored_backup.storage_id,
            object_key=object_key,
            role__in=("archive", "destination"),
            verified_at__isnull=False,
        ).order_by("pk")
    )
    if state is None:
        if any(
            row.artifact_format == CoreBackupArtifact.Format.BSE1
            or row.encryption_envelope_id is not None
            for row in destination_rows
        ):
            raise ArtifactPipelineError(
                "The destination BSE1 ledger has no active source envelope."
            )
        allow_legacy = getattr(
            settings, "BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE", False
        )
        if type(allow_legacy) is not bool or not allow_legacy or _enterprise_mode():
            raise ArtifactPipelineError(
                "Legacy plaintext artifact restore is disabled by policy."
            )
        return None
    artifact = _exact_destination_ciphertext_artifact(
        backup,
        stored_backup,
        state.artifact,
    )
    try:
        context, key_wrap = artifact.validate_encrypted_restore_state()
    except ValidationError as error:
        raise ArtifactPipelineError(
            "The selected BSE1 artifact is not restore-ready."
        ) from error
    wrapped = key_wrap.wrapped_data_key
    if isinstance(wrapped, memoryview):
        wrapped = wrapped.tobytes()
    return RestoreEncryptionPlan(
        artifact=artifact,
        envelope=state.envelope,
        context=context,
        wrapped_data_key=WrappedDataKey(
            provider_name=key_wrap.provider,
            wrapping_key_id=key_wrap.wrapping_key_id,
            ciphertext=bytes(wrapped),
        ),
    )


def materialize_local_restore_ciphertext_handoff(restore, *, task_id: str) -> bool:
    """Copy one exact local-storage BSE1 object into the reverse transfer lane."""

    task_id = str(task_id or "")
    if not task_id or len(task_id) > 255:
        raise ArtifactPipelineError("The restore handoff task identity is invalid.")
    now = timezone.now()
    with transaction.atomic():
        locked = restore.__class__.objects.select_for_update().get(pk=restore.pk)
        if locked.status in {locked.Status.COMPLETE, locked.Status.FAILED}:
            raise ArtifactPipelineError(
                "A terminal restore cannot create a ciphertext handoff."
            )
        stored_backup = locked.storage_point
        if (
            stored_backup is None
            or stored_backup.status != stored_backup.Status.UPLOAD_COMPLETE
            or stored_backup.storage.type.code != "local"
        ):
            raise ArtifactPipelineError(
                "The restore does not reference a completed local storage object."
            )
        plan = restore_encryption_plan(stored_backup)
        if plan is None:
            raise ArtifactPipelineError(
                "A plaintext legacy object cannot cross the restore handoff."
            )
        expected = restore_ciphertext_handoff_identity(locked, plan)
        metadata = dict(locked.execution_metadata or {})
        current = metadata.get(_RESTORE_HANDOFF_METADATA_KEY)
        if _handoff_matches(current, expected, statuses={"ready", "authenticated"}):
            return False
        if isinstance(current, dict) and current.get("status") in {
            "ready",
            "authenticated",
        }:
            raise ArtifactPipelineError(
                "The durable restore handoff identity conflicts with this backup."
            )
        lease_expires_at = None
        if isinstance(current, dict):
            try:
                lease_expires_at = datetime.fromisoformat(
                    str(current.get("lease_expires_at") or "")
                )
                if timezone.is_naive(lease_expires_at):
                    lease_expires_at = timezone.make_aware(lease_expires_at)
            except (TypeError, ValueError):
                lease_expires_at = None
        if (
            isinstance(current, dict)
            and current.get("status") == "staging"
            and current.get("task_id") != task_id
            and lease_expires_at is not None
            and lease_expires_at > now
        ):
            raise ArtifactPipelineError(
                "Another storage worker owns the restore handoff staging lease."
            )
        staging = {
            **expected,
            "status": "staging",
            "task_id": task_id,
            "started_at": now.isoformat(),
            "lease_expires_at": (now + timedelta(hours=49)).isoformat(),
        }
        metadata[_RESTORE_HANDOFF_METADATA_KEY] = staging
        locked.execution_metadata = metadata
        locked.save(update_fields=["execution_metadata", "modified"])
        stored_backup_id = stored_backup.pk

    from backupsheep.staging import (
        cleanup_restore_ciphertext_fence,
        create_restore_ciphertext_fence,
        publish_restore_ciphertext,
        require_restore_transfer_capacity,
    )

    require_restore_transfer_capacity(
        required_bytes=int(expected["size_bytes"]),
        required_inodes=3,
    )
    cleanup_restore_ciphertext_fence(
        expected["handoff_uuid"],
        backup_uuid=expected["backup_uuid"],
        target_lane=expected["target_lane"],
        installation_id=plan.context.installation_id,
    )
    fence = create_restore_ciphertext_fence(
        expected["handoff_uuid"],
        backup_uuid=expected["backup_uuid"],
        target_lane=expected["target_lane"],
        installation_id=plan.context.installation_id,
    )
    destination = fence.path / str(expected["artifact_name"])
    local_root = Path(os.path.abspath(os.fspath(settings.LOCAL_STORAGE_ROOT)))
    source_path = Path(
        os.path.abspath(os.fspath(stored_backup.storage_file_id or ""))
    )
    try:
        source_path.relative_to(local_root)
    except ValueError:
        raise ArtifactPipelineError(
            "The local restore ciphertext escapes its storage root."
        ) from None
    with open_artifact_source(
        source_path,
        trusted_source_root=local_root,
    ) as source:
        _copy_ciphertext_atomically(source, destination, plan.artifact)
    descriptor = read_envelope_header(destination, trusted_source_root=fence.path)
    _validate_public_descriptor(descriptor, plan.envelope)
    published = Path(
        publish_restore_ciphertext(
            expected["handoff_uuid"],
            expected["artifact_name"],
            backup_uuid=expected["backup_uuid"],
            target_lane=expected["target_lane"],
            installation_id=plan.context.installation_id,
        )
    )
    if published != destination:
        raise ArtifactPipelineError(
            "The restore ciphertext publisher returned an unexpected path."
        )

    with transaction.atomic():
        locked = restore.__class__.objects.select_for_update().get(pk=restore.pk)
        if locked.status in {locked.Status.COMPLETE, locked.Status.FAILED}:
            raise ArtifactPipelineError(
                "The restore became terminal during ciphertext staging."
            )
        stored_backup = locked.storage_point
        if stored_backup is None or stored_backup.pk != stored_backup_id:
            raise ArtifactPipelineError(
                "The restore storage point changed during ciphertext staging."
            )
        current_plan = restore_encryption_plan(stored_backup)
        if current_plan is None:
            raise ArtifactPipelineError(
                "The restore encryption ledger disappeared during staging."
            )
        current_expected = restore_ciphertext_handoff_identity(
            locked, current_plan
        )
        metadata = dict(locked.execution_metadata or {})
        current = metadata.get(_RESTORE_HANDOFF_METADATA_KEY)
        if current_expected != expected or not _handoff_matches(
            current,
            expected,
            statuses={"staging"},
        ) or current.get("task_id") != task_id:
            raise ArtifactPipelineError(
                "The restore handoff lease or identity changed during staging."
            )
        metadata[_RESTORE_HANDOFF_METADATA_KEY] = {
            **expected,
            "status": "ready",
            "ready_at": timezone.now().isoformat(),
        }
        locked.execution_metadata = metadata
        locked.save(update_fields=["execution_metadata", "modified"])
    return True


def cleanup_terminal_restore_ciphertext_handoff(restore) -> bool:
    """Remove a storage-owned reverse handoff after a terminal restore."""

    source_evidence = None
    terminal_status = ""
    with transaction.atomic():
        locked = restore.__class__.objects.select_for_update().get(pk=restore.pk)
        if locked.status not in {locked.Status.COMPLETE, locked.Status.FAILED}:
            raise ArtifactPipelineError(
                "The restore handoff cannot be cleaned before terminal state."
            )
        stored_backup = locked.storage_point
        if stored_backup is None:
            raise ArtifactPipelineError(
                "The terminal restore no longer identifies its storage point."
            )
        plan = restore_encryption_plan(stored_backup)
        if plan is None:
            raise ArtifactPipelineError(
                "A legacy restore has no encrypted handoff to clean."
            )
        expected = restore_ciphertext_handoff_identity(locked, plan)
        metadata = dict(locked.execution_metadata or {})
        current = metadata.get(_RESTORE_HANDOFF_METADATA_KEY)
        terminal_status = _terminal_restore_status(locked)
        if _handoff_matches(current, expected, statuses={"cleanup_complete"}):
            _validate_cleanup_handoff_record(
                current,
                expected,
                terminal_status,
            )
            return False
        allowed_statuses = (
            {"authenticated"}
            if locked.status == locked.Status.COMPLETE
            else {"ready", "authenticated"}
        )
        if not _handoff_matches(current, expected, statuses=allowed_statuses):
            raise ArtifactPipelineError(
                "The terminal restore handoff witness is incomplete."
            )
        observed_at = timezone.now()
        ready_at, ready_time = _handoff_timestamp(current, "ready_at")
        if ready_time > observed_at:
            raise ArtifactPipelineError(
                "The restore handoff readiness witness is in the future."
            )
        source_evidence = {
            **expected,
            "status": current["status"],
            "ready_at": ready_at,
        }
        if current["status"] == "authenticated":
            authenticated_at, authenticated_time = _handoff_timestamp(
                current, "authenticated_at"
            )
            if authenticated_time < ready_time:
                raise ArtifactPipelineError(
                    "The restore handoff authentication predates ciphertext readiness."
                )
            if authenticated_time > observed_at:
                raise ArtifactPipelineError(
                    "The restore handoff authentication witness is in the future."
                )
            source_evidence["authenticated_at"] = authenticated_at
        elif "authenticated_at" in current:
            raise ArtifactPipelineError(
                "A ready restore handoff contains an uncommitted authentication witness."
            )
        if current != source_evidence:
            raise ArtifactPipelineError(
                "The terminal restore handoff contains unreviewed evidence fields."
            )

    from backupsheep.staging import cleanup_restore_ciphertext_fence

    removed = cleanup_restore_ciphertext_fence(
        expected["handoff_uuid"],
        backup_uuid=expected["backup_uuid"],
        target_lane=expected["target_lane"],
        installation_id=plan.context.installation_id,
    )
    with transaction.atomic():
        locked = restore.__class__.objects.select_for_update().get(pk=restore.pk)
        if locked.status not in {locked.Status.COMPLETE, locked.Status.FAILED}:
            raise ArtifactPipelineError(
                "The restore left terminal state during handoff cleanup."
            )
        stored_backup = locked.storage_point
        current_plan = restore_encryption_plan(stored_backup)
        if current_plan is None:
            raise ArtifactPipelineError(
                "The terminal restore encryption ledger disappeared."
            )
        current_expected = restore_ciphertext_handoff_identity(
            locked, current_plan
        )
        metadata = dict(locked.execution_metadata or {})
        current = metadata.get(_RESTORE_HANDOFF_METADATA_KEY)
        if (
            current_expected != expected
            or _terminal_restore_status(locked) != terminal_status
        ):
            raise ArtifactPipelineError(
                "The restore handoff identity changed during cleanup."
            )
        if _handoff_matches(current, expected, statuses={"cleanup_complete"}):
            _validate_cleanup_handoff_record(
                current,
                expected,
                terminal_status,
            )
            return bool(removed)
        if current != source_evidence:
            raise ArtifactPipelineError(
                "The restore handoff security witness changed during cleanup."
            )
        completed_at = timezone.now()
        _, ready_time = _handoff_timestamp(source_evidence, "ready_at")
        authenticated_time = None
        if "authenticated_at" in source_evidence:
            _, authenticated_time = _handoff_timestamp(
                source_evidence, "authenticated_at"
            )
        if completed_at < (authenticated_time or ready_time):
            raise ArtifactPipelineError(
                "The restore handoff cleanup clock predates its security witness."
            )
        completed_evidence = {
            **expected,
            "status": "cleanup_complete",
            "ready_at": source_evidence["ready_at"],
            "completed_at": completed_at.isoformat(),
            "terminal_restore_status": terminal_status,
        }
        if "authenticated_at" in source_evidence:
            completed_evidence["authenticated_at"] = source_evidence[
                "authenticated_at"
            ]
        _validate_cleanup_handoff_record(
            completed_evidence,
            expected,
            terminal_status,
        )
        metadata[_RESTORE_HANDOFF_METADATA_KEY] = completed_evidence
        locked.execution_metadata = metadata
        locked.save(update_fields=["execution_metadata", "modified"])
    return bool(removed)


def unseal_downloaded_artifact(
    plan: RestoreEncryptionPlan,
    ciphertext_path,
    plaintext_zip_path,
) -> None:
    """Authenticate all ciphertext before atomically exposing the plaintext ZIP."""

    from backupsheep.staging import private_plaintext_root

    root = private_plaintext_root()
    ciphertext = Path(os.path.abspath(os.fspath(ciphertext_path)))
    plaintext = Path(os.path.abspath(os.fspath(plaintext_zip_path)))
    try:
        ciphertext.relative_to(root)
        plaintext.relative_to(root)
    except ValueError:
        raise ArtifactPipelineError(
            "The restore artifact path escapes the private plaintext root."
        ) from None
    descriptor = read_envelope_header(ciphertext, trusted_source_root=root)
    _validate_public_descriptor(descriptor, plan.envelope)
    with _configured_provider() as provider:
        authenticated = unseal_file(
            ciphertext,
            plaintext,
            provider=provider,
            wrapped_data_key=plan.wrapped_data_key,
            context=plan.context,
            expected=_expectation(plan.envelope),
            enterprise_mode=_enterprise_mode(),
            trusted_source_root=root,
            trusted_destination_root=root,
        )
    _validate_authenticated_descriptor(authenticated, plan.envelope)
