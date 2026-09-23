"""Bounded durable custody witness for storage-point deletion recovery."""

from __future__ import annotations

from typing import Literal


DELETION_ORIGIN_KEY = "_artifact_deletion_origin"
DELETION_ORIGIN_VERSION = 1
Custody = Literal["committed-object", "no-object", "ambiguous"]


def _named_statuses(point, names: tuple[str, ...]) -> set[int]:
    return {
        int(value)
        for value in (getattr(point.Status, name, None) for name in names)
        if value is not None
    }


def _pre_provider_empty(point) -> bool:
    metadata = dict(point.metadata) if isinstance(point.metadata, dict) else {}
    metadata.pop(DELETION_ORIGIN_KEY, None)
    deletion_claim = metadata.pop("_deletion_claim", None)
    if metadata:
        return False
    lease_owner = str(getattr(point, "upload_lease_owner", "") or "")
    lease_token = str(getattr(point, "upload_lease_token", "") or "")
    lease_expires_at = getattr(point, "upload_lease_expires_at", None)
    heartbeat = getattr(point, "upload_heartbeat_at", None)
    has_lease = bool(lease_owner or lease_token or lease_expires_at or heartbeat)
    if has_lease:
        if (
            not isinstance(deletion_claim, dict)
            or str(deletion_claim.get("owner") or "") != lease_owner
            or str(deletion_claim.get("token") or "") != lease_token
            or int(getattr(point, "status", -1))
            not in _named_statuses(point, ("DELETE_REQUESTED", "DELETE_FAILED"))
        ):
            return False
    elif deletion_claim is not None:
        return False
    return bool(
        int(getattr(point, "upload_attempt_count", 0) or 0) == 0
        and not str(getattr(point, "storage_file_id", "") or "")
    )


def _deletion_origin_classification(point, previous_status: int) -> tuple[Custody, str]:
    """Classify only evidence whose provider-object meaning is definitive."""

    previous_status = int(previous_status)
    if previous_status in _named_statuses(point, ("UPLOAD_COMPLETE",)):
        return "committed-object", "upload-complete-status"
    # The local-file provider schema migration accepts no historical storage-point
    # rows. In generation 1, CANCELLED is written with a status-only update that
    # preserves provider evidence, while upload claim rejects CANCELLED. Therefore
    # zero attempts plus blank provider/lease state remains a definitive no-boundary
    # fact; any evidence drift invalidates the stored no-object origin below.
    if previous_status in _named_statuses(point, ("UPLOAD_READY", "CANCELLED")):
        if _pre_provider_empty(point):
            return "no-object", "zero-attempt-empty-state"
    return "ambiguous", "ambiguous-status"


def build_deletion_origin(point, previous_status: int) -> dict[str, object]:
    """Create the complete, bounded version-1 deletion-origin witness."""

    previous_status = int(previous_status)
    custody, basis = _deletion_origin_classification(point, previous_status)
    return {
        "version": DELETION_ORIGIN_VERSION,
        "previous_status": previous_status,
        "custody": custody,
        "basis": basis,
    }


def validate_deletion_origin(point) -> tuple[Custody, int] | None:
    """Return a validated origin or None for missing/drifted/foreign metadata."""

    metadata = point.metadata if isinstance(point.metadata, dict) else {}
    origin = metadata.get(DELETION_ORIGIN_KEY)
    if not isinstance(origin, dict) or set(origin) != {
        "version",
        "previous_status",
        "custody",
        "basis",
    }:
        return None
    version = origin["version"]
    previous_status = origin["previous_status"]
    custody = origin["custody"]
    basis = origin["basis"]
    if (
        type(version) is not int
        or type(previous_status) is not int
        or type(custody) is not str
        or type(basis) is not str
    ):
        return None
    if version != DELETION_ORIGIN_VERSION:
        return None
    valid_previous_statuses = {
        int(value) for value in getattr(point.Status, "values", ())
    }
    deletion_statuses = _named_statuses(
        point,
        ("DELETE_REQUESTED", "DELETE_FAILED", "DELETE_COMPLETED"),
    )
    if (
        previous_status not in valid_previous_statuses
        or previous_status in deletion_statuses
    ):
        return None
    expected_custody, expected_basis = _deletion_origin_classification(
        point,
        previous_status,
    )
    if custody != expected_custody or basis != expected_basis:
        return None
    return expected_custody, previous_status
