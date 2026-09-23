"""Small, provider-specific safety helpers for Vultr API calls.

These helpers intentionally do not contain credentials or make requests by
themselves.  Keeping pagination and identity checks here makes it harder for
individual adapters to accidentally fall back to page-based or ID-only
operations.
"""

from django.conf import settings


DEFAULT_VULTR_REQUEST_TIMEOUT = (10, 60)


def vultr_request_timeout():
    """Return a validated ``requests`` connect/read timeout tuple."""
    value = getattr(
        settings,
        "VULTR_REQUEST_TIMEOUT",
        getattr(settings, "VULTR_API_TIMEOUT", DEFAULT_VULTR_REQUEST_TIMEOUT),
    )
    if isinstance(value, (tuple, list)) and len(value) == 2:
        try:
            connect, read = float(value[0]), float(value[1])
            if connect > 0 and read > 0:
                return (connect, read)
        except (TypeError, ValueError):
            pass
    if isinstance(value, (int, float)) and value > 0:
        return float(value)
    return DEFAULT_VULTR_REQUEST_TIMEOUT


def iter_vultr_collection(get, url, *, headers, item_key, params=None, verify=True):
    """Yield every item from a cursor-paginated Vultr collection.

    Vultr's ``meta.links.next`` is the only continuation signal accepted here.
    A repeated or malformed cursor is treated as an incomplete inventory and
    raises instead of silently allowing a duplicate provider create.
    """
    base_params = dict(params or {})
    base_params.setdefault("per_page", 500)
    cursor = None
    seen_cursors = set()

    while True:
        request_params = dict(base_params)
        if cursor is not None:
            request_params["cursor"] = cursor
        response = get(url, headers=headers, params=request_params, verify=verify,
                       timeout=vultr_request_timeout())
        try:
            if response.status_code != 200:
                raise ValueError(
                    f"Vultr collection request failed with status {response.status_code}."
                )
            payload = response.json()
            items = payload.get(item_key)
            if not isinstance(items, list):
                raise ValueError("Vultr collection response did not contain a list of items.")
            for item in items:
                if not isinstance(item, dict):
                    raise ValueError("Vultr collection response contained a malformed item.")
                yield item

            links = (payload.get("meta") or {}).get("links") or {}
            if not isinstance(links, dict):
                raise ValueError("Vultr collection response contained malformed pagination links.")
            next_cursor = links.get("next")
            if next_cursor in (None, ""):
                return
            if not isinstance(next_cursor, str) or not next_cursor.strip():
                raise ValueError("Vultr collection response contained a malformed cursor.")
            if next_cursor in seen_cursors:
                raise ValueError("Vultr collection response repeated a pagination cursor.")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        finally:
            response.close()


def snapshot_matches(snapshot, *, provider_id, source_id, description, source_key):
    """Return whether a snapshot is owned by this exact BackupSheep backup."""
    return (
        isinstance(snapshot, dict)
        and bool(provider_id)
        and bool(source_id)
        and snapshot.get("id") == provider_id
        and snapshot.get("description") == description
        and snapshot.get(source_key) == source_id
    )


VULTR_SNAPSHOT_OWNERSHIP_KEY = "vultr_ownership"


def record_snapshot_ownership(metadata, *, source_id, source_key):
    """Persist the source identity used in a snapshot create request.

    Vultr's instance-snapshot response can omit ``instance_id`` after the
    snapshot becomes complete.  The request identity is therefore retained in
    the durable BackupSheep row so a later worker can reconcile that exact
    provider object without weakening the foreign-source check.
    """
    updated = dict(metadata or {})
    updated[VULTR_SNAPSHOT_OWNERSHIP_KEY] = {
        "source_id": str(source_id),
        "source_key": source_key,
    }
    return updated


def snapshot_matches_with_recorded_source(
    snapshot,
    *,
    provider_id,
    source_id,
    description,
    source_key,
    ownership=None,
):
    """Verify a snapshot, allowing Vultr's documented source omission safely.

    A non-empty provider source must always match exactly.  The fallback is
    allowed only when Vultr omits the source field and the local row contains
    the exact source identity persisted before the provider request.  This is
    deliberately narrower than accepting a description or provider ID alone.
    """
    if snapshot_matches(
        snapshot,
        provider_id=provider_id,
        source_id=source_id,
        description=description,
        source_key=source_key,
    ):
        return True
    if not isinstance(snapshot, dict) or not isinstance(ownership, dict):
        return False
    if not (
        provider_id
        and source_id
        and snapshot.get("id") == provider_id
        and snapshot.get("description") == description
        and snapshot.get(source_key) in (None, "")
    ):
        return False
    return (
        ownership.get("source_key") == source_key
        and str(ownership.get("source_id")) == str(source_id)
    )


def provider_classification(status_code):
    """Map a provider response to a stable, non-sensitive classification."""
    if status_code in (401, 403):
        return "authentication"
    if status_code == 404:
        return "missing"
    if status_code == 429:
        return "rate_limited"
    if status_code is not None and status_code >= 500:
        return "transient_provider_error"
    if status_code is not None and status_code >= 400:
        return "permanent_provider_error"
    return "provider_error"


_VULTR_RESULT_MESSAGES = {
    "provider_terminal_failure": "Vultr reported a terminal snapshot failure.",
    "malformed_provider_state": "Vultr returned an unrecognized snapshot state.",
    "missing_without_ownership_proof": (
        "Unable to prove ownership of the missing Vultr snapshot."
    ),
    "missing_after_ownership_proof": "Vultr snapshot was already absent.",
    "ownership_mismatch": (
        "Vultr snapshot ownership verification failed; refusing the operation."
    ),
    "authentication": "Vultr authentication or authorization failed.",
    "missing": "The Vultr resource was not found.",
    "rate_limited": "Vultr rate-limited the request; BackupSheep will retry.",
    "transient_provider_error": (
        "Vultr is temporarily unavailable; BackupSheep will retry."
    ),
    "transient_client_error": (
        "The Vultr request was interrupted; BackupSheep will reconcile it."
    ),
    "permanent_provider_error": "Vultr rejected the provider operation.",
    "provider_error": "The Vultr provider operation failed.",
}


def record_provider_result(metadata, *, classification, status_code=None, error=None):
    """Return metadata containing only allowlisted provider diagnostics.

    ``error`` remains in the signature for compatibility with older callers but
    is deliberately never stringified. Provider exceptions and HTTP bodies can
    contain bearer tokens, signed URLs, account identifiers, and credentials.
    """
    updated = dict(metadata or {})
    result = {"classification": classification}
    if status_code is not None:
        result["status_code"] = int(status_code)
    safe_message = _VULTR_RESULT_MESSAGES.get(classification)
    if safe_message:
        result["message"] = safe_message
    updated["vultr_last_result"] = result
    return updated


def snapshot_state(snapshot):
    """Normalize Vultr's instance/block snapshot state fields."""
    value = snapshot.get("status")
    if value is None or str(value).strip().lower() in {"", "none", "null", "unknown"}:
        value = snapshot.get("state", "")
    normalized = str(value).strip().lower()
    # A newly accepted Vultr block-snapshot request can briefly return a
    # structurally valid object without either state field.  It is a known
    # asynchronous state, not evidence of a terminal provider failure.
    return normalized if normalized not in {"", "none", "null", "unknown"} else "in_progress"


def is_terminal_snapshot_failure(snapshot):
    return snapshot_state(snapshot) in {
        "failed", "failure", "error", "errored", "cancelled", "canceled",
    }
