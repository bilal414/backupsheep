"""Small helpers for bounded, public-safe execution attempt history."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone


PUBLIC_ATTEMPT_HISTORY_KEY = "public_attempt_history"
PUBLIC_ATTEMPT_HISTORY_LIMIT = 20

_STAGE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}")
_CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
_RETRY_DECISIONS = {
    "running",
    "scheduled_retry",
    "retry_not_scheduled",
    "complete",
    "terminal_failure",
    "manual_review",
    "cancelled",
    "lease_lost",
}


def _timestamp(value):
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _correlation(value):
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError):
        return None


def _attempt_number(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if 0 < value <= 1_000_000 else None


def _stage(value):
    value = str(value or "").strip().lower()
    return value if _STAGE_PATTERN.fullmatch(value) else None


def _code(value):
    if value in (None, ""):
        return None
    value = str(value).strip().upper()
    return value if _CODE_PATTERN.fullmatch(value) else None


def _decision(value):
    value = str(value or "").strip().lower()
    return value if value in _RETRY_DECISIONS else None


def _existing_history(metadata):
    raw = metadata.get(PUBLIC_ATTEMPT_HISTORY_KEY)
    if not isinstance(raw, list):
        return []
    history = []
    for item in raw[-PUBLIC_ATTEMPT_HISTORY_LIMIT:]:
        if not isinstance(item, dict):
            continue
        attempt = _attempt_number(item.get("attempt"))
        correlation_id = _correlation(item.get("correlation_id"))
        stage = _stage(item.get("stage"))
        decision = _decision(item.get("retry_decision"))
        started_at = item.get("started_at")
        if not all((attempt, correlation_id, stage, decision, started_at)):
            continue
        record = {
            "attempt": attempt,
            "started_at": str(started_at)[:64],
            "finished_at": (
                str(item.get("finished_at"))[:64]
                if item.get("finished_at")
                else None
            ),
            "stage": stage,
            "code": _code(item.get("code")),
            "retry_decision": decision,
            "correlation_id": correlation_id,
        }
        history.append(record)
    return history[-PUBLIC_ATTEMPT_HISTORY_LIMIT:]


def begin_public_attempt(
    metadata,
    *,
    attempt_no,
    correlation_id,
    stage,
    now=None,
):
    """Start or refresh one still-running attempt without duplicating delivery."""
    values = dict(metadata or {})
    attempt = _attempt_number(attempt_no)
    correlation_id = _correlation(correlation_id)
    stage = _stage(stage) or "preparing"
    if attempt is None or correlation_id is None:
        return values
    history = _existing_history(values)
    if (
        history
        and history[-1]["attempt"] == attempt
        and history[-1]["correlation_id"] == correlation_id
        and history[-1]["finished_at"] is None
    ):
        history[-1]["stage"] = stage
        history[-1]["retry_decision"] = "running"
    else:
        history.append(
            {
                "attempt": attempt,
                "started_at": _timestamp(now),
                "finished_at": None,
                "stage": stage,
                "code": None,
                "retry_decision": "running",
                "correlation_id": correlation_id,
            }
        )
    values[PUBLIC_ATTEMPT_HISTORY_KEY] = history[-PUBLIC_ATTEMPT_HISTORY_LIMIT:]
    return values


def update_public_attempt(
    metadata,
    *,
    attempt_no,
    correlation_id,
    stage=None,
    code=None,
    retry_decision=None,
    now=None,
    finished=False,
):
    """Update the newest matching attempt using only bounded public tokens."""
    values = dict(metadata or {})
    attempt = _attempt_number(attempt_no)
    correlation_id = _correlation(correlation_id)
    if attempt is None or correlation_id is None:
        return values
    history = _existing_history(values)
    index = next(
        (
            position
            for position in range(len(history) - 1, -1, -1)
            if history[position]["attempt"] == attempt
            and history[position]["correlation_id"] == correlation_id
        ),
        None,
    )
    if index is None:
        values = begin_public_attempt(
            values,
            attempt_no=attempt,
            correlation_id=correlation_id,
            stage=stage or "preparing",
            now=now,
        )
        history = _existing_history(values)
        index = len(history) - 1
    record = history[index]
    safe_stage = _stage(stage)
    safe_code = _code(code)
    safe_decision = _decision(retry_decision)
    if safe_stage:
        record["stage"] = safe_stage
    if code is not None:
        record["code"] = safe_code
    if safe_decision:
        record["retry_decision"] = safe_decision
    if finished:
        record["finished_at"] = _timestamp(now)
    values[PUBLIC_ATTEMPT_HISTORY_KEY] = history[-PUBLIC_ATTEMPT_HISTORY_LIMIT:]
    return values
