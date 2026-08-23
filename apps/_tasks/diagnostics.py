"""Operator-only Sentry diagnostics correlated to the public execution ledger."""

from __future__ import annotations

import re
import uuid

from sentry_sdk import capture_exception, push_scope


def _safe_correlation(value):
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError):
        return None


def _safe_stage(value):
    value = str(value or "").strip().lower()
    return value if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value) else "unknown"


def _safe_code(value):
    value = str(value or "EXECUTION_ERROR").strip().upper()
    if re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", value):
        return value
    return "EXECUTION_ERROR"


def capture_execution_diagnostic(
    error,
    *,
    correlation_id,
    attempt_no=0,
    stage="unknown",
    code="EXECUTION_ERROR",
):
    """Capture raw exception detail only in Sentry with secret-free lookup tags.

    The exception itself is intentionally never copied to a model, account log,
    notification, API response, or transfer log. Sentry remains the operator-only,
    retention-controlled diagnostic store; the correlation tag joins that private
    event to the public-safe execution record.
    """
    correlation_id = _safe_correlation(correlation_id)
    if correlation_id is None or not isinstance(error, BaseException):
        return None
    try:
        attempt_no = max(0, min(int(attempt_no or 0), 1_000_000))
    except (TypeError, ValueError):
        attempt_no = 0
    with push_scope() as scope:
        scope.set_tag("backupsheep.correlation_id", correlation_id)
        scope.set_tag("backupsheep.attempt", attempt_no)
        scope.set_tag("backupsheep.stage", _safe_stage(stage))
        scope.set_tag("backupsheep.code", _safe_code(code))
        return capture_exception(error)


def capture_backup_diagnostic(error, backup, *, stage="", code=""):
    """Capture one backup error when its durable correlation row exists."""
    try:
        state = backup.get_execution_state(create=False)
    except Exception:
        return None
    if state is None:
        return None
    metadata = state.metadata if isinstance(state.metadata, dict) else {}
    public_stage = str(stage or metadata.get("public_stage") or state.phase or "unknown")
    return capture_execution_diagnostic(
        error,
        correlation_id=state.correlation_id,
        attempt_no=state.attempt_count or getattr(backup, "attempt_no", 0),
        stage=public_stage,
        code=code or state.last_error_code or "EXECUTION_ERROR",
    )
