"""Exact-row AWS restore crash hook used only by live acceptance tests.

Normal workers never enable this hook.  An isolated worker can be configured to
pause one known restore after AWS has returned a job id but before BackupSheep
persists that provider pointer.  Killing that isolated worker proves that the
durable request identity can safely adopt the accepted operation on redelivery.
"""

import hashlib
import json
import time

from django.conf import settings
from django.utils import timezone


class AWSRestoreAcceptanceTimeout(TimeoutError):
    """Represents a deliberately lost accepted response in an acceptance run."""


def _sha256(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _metadata_sha256(metadata):
    encoded = json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def maybe_fault_after_accepted_restore(
    restore,
    *,
    resource_type,
    token,
    request_metadata,
    sleep_callback=None,
):
    """Pause or drop one exact accepted response before provider pointers persist.

    Returns ``False`` when disabled, selectors do not match, or the one-shot
    witness was already consumed.  No raw token, provider response, job id, or
    request metadata is persisted in the acceptance witness.
    """

    if not bool(getattr(settings, "AWS_RESTORE_ACCEPTANCE_FAULT_ENABLED", False)):
        return False

    selected_restore_id = str(
        getattr(settings, "AWS_RESTORE_ACCEPTANCE_FAULT_RESTORE_ID", "") or ""
    )
    selected_correlation_id = str(
        getattr(settings, "AWS_RESTORE_ACCEPTANCE_FAULT_CORRELATION_ID", "") or ""
    ).lower()
    selected_resource_type = str(
        getattr(settings, "AWS_RESTORE_ACCEPTANCE_FAULT_RESOURCE_TYPE", "") or ""
    ).lower()
    actual_correlation_id = str(getattr(restore, "correlation_id", "") or "").lower()
    actual_resource_type = str(resource_type or "").lower()
    if (
        str(getattr(restore, "pk", "") or "") != selected_restore_id
        or actual_correlation_id != selected_correlation_id
        or actual_resource_type != selected_resource_type
    ):
        return False

    execution_metadata = dict(getattr(restore, "execution_metadata", None) or {})
    existing = execution_metadata.get("aws_restore_acceptance_fault")
    if isinstance(existing, dict) and existing.get("consumed") is True:
        return False

    mode = str(
        getattr(settings, "AWS_RESTORE_ACCEPTANCE_FAULT_MODE", "") or ""
    ).lower()
    if mode not in {"drop_response", "hold"}:
        # Settings validates this at process startup. Keep the mutation boundary
        # fail-closed if a test overrides settings dynamically with a bad value.
        raise RuntimeError("AWS restore acceptance fault mode is invalid")

    execution_metadata["aws_restore_acceptance_fault"] = {
        "consumed": True,
        "accepted_response_observed": True,
        "mode": mode,
        "resource_type": actual_resource_type,
        "restore_id": int(restore.pk),
        "correlation_id": actual_correlation_id,
        "attempt_count": int(getattr(restore, "attempt_count", 0) or 0),
        "token_sha256": _sha256(token),
        "request_metadata_sha256": _metadata_sha256(request_metadata),
        "triggered_at": timezone.now().isoformat(),
    }
    restore.execution_metadata = execution_metadata
    restore.save(update_fields=["execution_metadata", "modified"])

    if mode == "hold":
        callback = sleep_callback or time.sleep
        callback(
            int(
                getattr(
                    settings,
                    "AWS_RESTORE_ACCEPTANCE_FAULT_HOLD_SECONDS",
                    30,
                )
            )
        )
        return True

    raise AWSRestoreAcceptanceTimeout(
        "The accepted AWS restore response was deliberately dropped."
    )
