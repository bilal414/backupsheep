"""Durable HTTP request identity for logical website/database restores."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass

from django.db import IntegrityError, transaction


class LogicalRestoreRequestConflict(Exception):
    """A request UUID was reused with a different immutable restore body."""


class LogicalRestoreRequestInvalid(Exception):
    """The caller supplied a request identifier that is not a safe UUID."""


class LogicalRestoreActiveExists(Exception):
    """A different nonterminal restore already owns this destination lane."""


class LogicalRestoreStoragePointInvalid(Exception):
    """An explicitly supplied storage point identifier is not a positive int."""


@dataclass(frozen=True)
class LogicalRestoreRequestIdentity:
    correlation_id: uuid.UUID
    recovery_id: str
    key_source: str


def logical_restore_storage_point_id(request_data):
    """Return an optional, strictly typed stored-backup primary key."""

    if "storage_point_id" not in request_data:
        return None
    value = request_data.get("storage_point_id")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise LogicalRestoreStoragePointInvalid
    return value


def logical_restore_request_identity(request_data, *, restore_kind, backup_id):
    """Return one backup-scoped correlation UUID and public recovery UUID.

    Browser-generated UUIDv4 values are safe to expose in the restore ledger.
    Scoping the database correlation UUID to the restore family and backup keeps
    independently generated tenant requests isolated while retaining a unique
    database arbiter for concurrent retries of the same request.

    Missing identifiers retain the legacy API behavior by generating a UUID.
    Such callers still receive the generated recovery identifier in a normal
    response, while clients that need lost-response replay must supply one.
    """

    if "request_id" in request_data:
        raw_request_id = request_data.get("request_id")
        key_source = "body"
    else:
        raw_request_id = str(uuid.uuid4())
        key_source = "generated"

    if not isinstance(raw_request_id, str):
        raise LogicalRestoreRequestInvalid
    try:
        parsed = uuid.UUID(raw_request_id)
    except (AttributeError, TypeError, ValueError):
        raise LogicalRestoreRequestInvalid from None
    if (
        parsed.version != 4
        or parsed.variant != uuid.RFC_4122
        or str(parsed) != raw_request_id
    ):
        raise LogicalRestoreRequestInvalid

    correlation_id = uuid.uuid5(
        uuid.NAMESPACE_URL,
        (
            f"backupsheep:{restore_kind}-restore:"
            f"backup:{int(backup_id)}:{raw_request_id}"
        ),
    )
    return LogicalRestoreRequestIdentity(
        correlation_id=correlation_id,
        recovery_id=raw_request_id,
        key_source=key_source,
    )


def logical_restore_request_metadata(
    identity,
    *,
    restore_kind,
    backup_id,
    storage_point_id,
    options,
):
    """Build the immutable request fingerprint and safe public metadata."""

    payload = {
        "restore_kind": restore_kind,
        "backup_id": int(backup_id),
        "storage_point_id": int(storage_point_id),
        "options": options,
    }
    try:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError):
        raise LogicalRestoreRequestInvalid from None
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return fingerprint, {
        "fingerprint": fingerprint,
        "key_source": identity.key_source,
        "payload_version": 1,
        "recovery_id": identity.recovery_id,
        "restore_kind": restore_kind,
    }


def create_or_replay_logical_restore(
    *,
    restore_model,
    backup,
    storage_point,
    correlation_id,
    request_fingerprint,
    request_metadata,
    create_fields,
):
    """Create exactly one durable row or replay its exact immutable request.

    The unique correlation constraint arbitrates concurrent deliveries.  A
    nested savepoint contains a losing insert's IntegrityError so the winner
    can be locked and compared before this request returns.
    """

    created = False
    with transaction.atomic():
        restore_kind = request_metadata.get("restore_kind")
        if restore_kind not in {"website", "database"}:
            raise ValueError("Unsupported logical restore destination.")
        destination = getattr(backup, restore_kind)
        # Every recovery point for one logical destination takes the same row
        # lock. This closes absent-row races across different backups without a
        # broader node/account state machine or a new schema constraint.
        type(destination).objects.select_for_update().only("pk").get(
            pk=destination.pk
        )
        restore = (
            restore_model.objects.select_for_update()
            .filter(correlation_id=correlation_id)
            .first()
        )
        if restore is None:
            terminal_statuses = {
                restore_model.Status.COMPLETE,
                restore_model.Status.FAILED,
            }
            if (
                restore_model.objects.select_for_update()
                .filter(
                    **{
                        f"backup__{restore_kind}_id": destination.pk,
                    }
                )
                .exclude(status__in=terminal_statuses)
                .exists()
            ):
                raise LogicalRestoreActiveExists
            try:
                with transaction.atomic():
                    restore = restore_model.objects.create(
                        backup=backup,
                        storage_point=storage_point,
                        correlation_id=correlation_id,
                        **create_fields,
                    )
                created = True
            except IntegrityError:
                restore = restore_model.objects.select_for_update().get(
                    correlation_id=correlation_id
                )

        stored_metadata = dict(restore.execution_metadata or {})
        stored_request = dict(stored_metadata.get("api_request") or {})
        stored_fingerprint = str(stored_request.get("fingerprint") or "")
        if (
            restore.backup_id != backup.id
            or restore.storage_point_id != storage_point.id
            or stored_request.get("recovery_id")
            != request_metadata.get("recovery_id")
            or stored_request.get("restore_kind")
            != request_metadata.get("restore_kind")
            or not hmac.compare_digest(
                stored_fingerprint, str(request_fingerprint or "")
            )
        ):
            raise LogicalRestoreRequestConflict

    return restore, created
