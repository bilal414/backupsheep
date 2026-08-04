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


def record_provider_result(metadata, *, classification, status_code=None, error=None):
    """Return metadata with a sanitized provider result for operator visibility."""
    updated = dict(metadata or {})
    result = {"classification": classification}
    if status_code is not None:
        result["status_code"] = int(status_code)
    if error:
        result["error"] = str(error)[:256]
    updated["vultr_last_result"] = result
    return updated


def snapshot_state(snapshot):
    """Normalize Vultr's instance/block snapshot state fields."""
    return str(snapshot.get("status", snapshot.get("state", ""))).lower()


def is_terminal_snapshot_failure(snapshot):
    return snapshot_state(snapshot) in {
        "failed", "failure", "error", "errored", "cancelled", "canceled",
    }
