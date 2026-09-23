"""Exact-row Oracle Cloud acceptance fault injection.

This module is intentionally separate from the provider adapter.  The feature is
disabled in normal settings and, when enabled, requires a complete selector for
one known backup or restore row.  It is suitable for an isolated worker that is
deliberately killed while holding after provider acceptance and before the
adapter persists the provider pointer.
"""

from __future__ import annotations

import hashlib
import json
import time

from django.conf import settings
from django.utils import timezone

from apps._tasks.integration.oracle import OracleProviderError


class OracleAcceptanceFault(OracleProviderError):
    """A deliberate lost-response signal with unknown provider outcome."""

    def __init__(self, message="The Oracle acceptance response was deliberately dropped."):
        super().__init__(
            "PROVIDER_TIMEOUT",
            retryable=True,
            unknown_outcome=True,
        )
        self.acceptance_message = str(message)


def _digest(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _metadata_digest(value):
    return _digest(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    )


def _mode(prefix):
    mode = str(getattr(settings, f"{prefix}_MODE", "") or "").strip().lower()
    if mode not in {"drop_response", "hold"}:
        raise OracleAcceptanceFault("Oracle acceptance fault mode is invalid.")
    return mode


def _matches(prefix, *, marker, row_id, task_id, resource_type):
    return (
        str(getattr(settings, f"{prefix}_MARKER", "") or "") == str(marker)
        and str(getattr(settings, f"{prefix}_ROW_ID", "") or "") == str(row_id)
        and str(getattr(settings, f"{prefix}_TASK_ID", "") or "") == str(task_id)
        and str(getattr(settings, f"{prefix}_RESOURCE_TYPE", "") or "").strip().lower()
        == str(resource_type).strip().lower()
    )


def _fault_record(prefix, *, marker, row_id, task_id, resource_type, token, provider_resource_id, request_metadata):
    return {
        "consumed": True,
        "accepted_response_observed": True,
        "mode": _mode(prefix),
        "row_id": int(row_id),
        "resource_type": str(resource_type)[:64],
        "marker_sha256": _digest(marker),
        "task_id_sha256": _digest(task_id),
        "request_token_sha256": _digest(token),
        "provider_resource_id_sha256": _digest(provider_resource_id),
        "request_metadata_sha256": _metadata_digest(request_metadata),
        "triggered_at": timezone.now().isoformat(),
    }


def _finish(prefix, record, *, sleep_callback=None):
    if record["mode"] == "hold":
        callback = sleep_callback or time.sleep
        callback(
            int(getattr(settings, f"{prefix}_HOLD_SECONDS", 30))
        )
        return True
    raise OracleAcceptanceFault()


def maybe_fault_after_accepted_backup(
    backup,
    *,
    resource_type,
    request_token,
    provider_resource_id,
    request_metadata,
    sleep_callback=None,
):
    """Trigger once after provider acceptance and before backup pointer save."""

    prefix = "ORACLE_BACKUP_ACCEPTANCE_FAULT"
    if not bool(getattr(settings, f"{prefix}_ENABLED", False)):
        return False
    marker = str(getattr(backup, "uuid_str", "") or "")
    task_id = str(getattr(backup, "celery_task_id", "") or "")
    if not _matches(
        prefix,
        marker=marker,
        row_id=getattr(backup, "pk", ""),
        task_id=task_id,
        resource_type=resource_type,
    ):
        return False
    metadata = dict(getattr(backup, "metadata", None) or {})
    existing = metadata.get("_oracle_acceptance_fault")
    if isinstance(existing, dict) and existing.get("consumed") is True:
        return False
    backup.ensure_execution_fence()
    metadata["_oracle_acceptance_fault"] = _fault_record(
        prefix,
        marker=marker,
        row_id=backup.pk,
        task_id=task_id,
        resource_type=resource_type,
        token=request_token,
        provider_resource_id=provider_resource_id,
        request_metadata=request_metadata,
    )
    backup.metadata = metadata
    backup.save(update_fields=["metadata", "modified"])
    return _finish(prefix, metadata["_oracle_acceptance_fault"], sleep_callback=sleep_callback)


def maybe_fault_after_accepted_restore(
    restore,
    *,
    marker,
    resource_type,
    request_token,
    provider_resource_id,
    request_metadata,
    sleep_callback=None,
):
    """Trigger once after provider acceptance and before restore pointer save."""

    prefix = "ORACLE_RESTORE_ACCEPTANCE_FAULT"
    if not bool(getattr(settings, f"{prefix}_ENABLED", False)):
        return False
    task_id = str(getattr(restore, "celery_task_id", "") or "")
    if not _matches(
        prefix,
        marker=marker,
        row_id=getattr(restore, "pk", ""),
        task_id=task_id,
        resource_type=resource_type,
    ):
        return False
    metadata = dict(getattr(restore, "execution_metadata", None) or {})
    existing = metadata.get("oracle_acceptance_fault")
    if isinstance(existing, dict) and existing.get("consumed") is True:
        return False
    restore.assert_live_execution_fence()
    metadata["oracle_acceptance_fault"] = _fault_record(
        prefix,
        marker=marker,
        row_id=restore.pk,
        task_id=task_id,
        resource_type=resource_type,
        token=request_token,
        provider_resource_id=provider_resource_id,
        request_metadata=request_metadata,
    )
    restore.execution_metadata = metadata
    restore.save(update_fields=["execution_metadata", "modified"])
    return _finish(prefix, metadata["oracle_acceptance_fault"], sleep_callback=sleep_callback)
