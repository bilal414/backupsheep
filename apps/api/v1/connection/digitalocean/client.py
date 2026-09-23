"""Bounded, fail-closed helpers for DigitalOcean API reads.

DigitalOcean's v2 collections are page based.  Callers must follow the
provider-supplied ``links.pages.next`` URL and prove that the final item count
matches ``meta.total``; incrementing page numbers from a mutable total can skip
or duplicate resources during reconciliation.

This module deliberately contains no credentials and never logs response
bodies.  The caller supplies an already constructed Authorization header.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit, urlunsplit

from django.conf import settings

from apps.api.v1.utils.http import request_timeout, requests


DIGITALOCEAN_PAGE_SIZE = 200
DIGITALOCEAN_MAX_PAGES = 1000
DIGITALOCEAN_MAX_ITEMS = 200_000


_SAFE_MESSAGES = {
    "PROVIDER_AUTH_FAILED": "DigitalOcean rejected the configured credentials or permissions.",
    "PROVIDER_DUPLICATE_MATCH": "DigitalOcean returned duplicate resources for an exact BackupSheep marker.",
    "PROVIDER_MALFORMED_RESPONSE": "DigitalOcean returned an incomplete or malformed response.",
    "PROVIDER_NOT_FOUND": "DigitalOcean could not find the requested resource.",
    "PROVIDER_OWNERSHIP_MISMATCH": "The DigitalOcean resource did not match the expected source and type.",
    "PROVIDER_RATE_LIMIT": "DigitalOcean rate-limited the request.",
    "PROVIDER_RECONCILIATION_REQUIRED": "The DigitalOcean create outcome could not be reconciled automatically.",
    "PROVIDER_REQUEST_FAILED": "DigitalOcean rejected the request.",
    "PROVIDER_TIMEOUT": "The DigitalOcean request timed out.",
    "PROVIDER_TRANSIENT_OUTAGE": "DigitalOcean is temporarily unavailable.",
}


class DigitalOceanAPIError(RuntimeError):
    """Secret-free provider failure with durable orchestration hints."""

    def __init__(
        self,
        code: str,
        *,
        retryable: bool = False,
        unknown_outcome: bool = False,
        status_code: int | None = None,
    ):
        self.code = str(code)
        self.error_code = self.code
        self.retryable = bool(retryable)
        self.unknown_outcome = bool(unknown_outcome)
        self.status_code = status_code
        super().__init__(_SAFE_MESSAGES.get(self.code, _SAFE_MESSAGES["PROVIDER_REQUEST_FAILED"]))


def _bounded_positive_setting(name: str, default: int, maximum: int) -> int:
    try:
        value = int(getattr(settings, name, default))
    except (TypeError, ValueError):
        value = default
    return min(max(value, 1), maximum)


def _api_base() -> str:
    raw = str(getattr(settings, "DIGITALOCEAN_API", "https://api.digitalocean.com") or "").rstrip("/")
    try:
        parsed = urlsplit(raw)
        has_port = parsed.port is not None
    except ValueError as error:
        raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or has_port
        or parsed.query
        or parsed.fragment
    ):
        raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def digitalocean_api_url(path_or_url: str) -> str:
    """Return a same-origin v2 URL, rejecting credential-exfiltration links."""

    base = _api_base()
    base_parts = urlsplit(base)
    raw = str(path_or_url or "")
    target = urljoin(f"{base}/", raw.lstrip("/")) if not urlsplit(raw).netloc else raw
    try:
        parsed = urlsplit(target)
        has_port = parsed.port is not None
    except ValueError as error:
        raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE") from error
    base_path = base_parts.path.rstrip("/")
    required_prefix = f"{base_path}/v2/" if base_path else "/v2/"
    if (
        parsed.scheme != base_parts.scheme
        or parsed.netloc != base_parts.netloc
        or parsed.username is not None
        or parsed.password is not None
        or has_port
        or parsed.fragment
        or not parsed.path.startswith(required_prefix)
    ):
        raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))


def _response_error(response, *, mutation: bool = False) -> DigitalOceanAPIError | None:
    try:
        status_code = int(response.status_code)
    except (AttributeError, TypeError, ValueError):
        return DigitalOceanAPIError(
            "PROVIDER_MALFORMED_RESPONSE", unknown_outcome=mutation
        )
    if 200 <= status_code < 300:
        return None
    if status_code in {401, 403}:
        return DigitalOceanAPIError("PROVIDER_AUTH_FAILED", status_code=status_code)
    if status_code == 404:
        return DigitalOceanAPIError("PROVIDER_NOT_FOUND", status_code=status_code)
    if status_code == 408:
        return DigitalOceanAPIError(
            "PROVIDER_TIMEOUT",
            retryable=True,
            unknown_outcome=mutation,
            status_code=status_code,
        )
    if status_code == 429:
        return DigitalOceanAPIError(
            "PROVIDER_RATE_LIMIT", retryable=True, status_code=status_code
        )
    if status_code >= 500:
        return DigitalOceanAPIError(
            "PROVIDER_TRANSIENT_OUTAGE",
            retryable=True,
            unknown_outcome=mutation,
            status_code=status_code,
        )
    return DigitalOceanAPIError("PROVIDER_REQUEST_FAILED", status_code=status_code)


def _request_json(method: str, path_or_url: str, *, headers: dict, params=None, json=None):
    mutation = method.upper() not in {"GET", "HEAD", "OPTIONS"}
    try:
        response = requests.request(
            method,
            digitalocean_api_url(path_or_url),
            headers=headers,
            params=params,
            json=json,
            verify=True,
            timeout=request_timeout(),
        )
    except requests.exceptions.Timeout as error:
        raise DigitalOceanAPIError(
            "PROVIDER_TIMEOUT", retryable=True, unknown_outcome=mutation
        ) from error
    except requests.exceptions.RequestException as error:
        raise DigitalOceanAPIError(
            "PROVIDER_TRANSIENT_OUTAGE", retryable=True, unknown_outcome=mutation
        ) from error
    try:
        problem = _response_error(response, mutation=mutation)
        if problem:
            raise problem
        try:
            payload = response.json()
        except (TypeError, ValueError) as error:
            raise DigitalOceanAPIError(
                "PROVIDER_MALFORMED_RESPONSE", unknown_outcome=mutation
            ) from error
        if not isinstance(payload, dict):
            raise DigitalOceanAPIError(
                "PROVIDER_MALFORMED_RESPONSE", unknown_outcome=mutation
            )
        return payload
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


def get_json(path_or_url: str, *, headers: dict, params=None) -> dict:
    return _request_json("GET", path_or_url, headers=headers, params=params)


def iter_collection(
    path: str,
    collection_key: str,
    *,
    headers: dict,
    params: dict | None = None,
) -> list[dict]:
    """Read a complete collection by following validated provider next links."""

    page_limit = _bounded_positive_setting(
        "DIGITALOCEAN_API_MAX_PAGES", DIGITALOCEAN_MAX_PAGES, 10_000
    )
    item_limit = _bounded_positive_setting(
        "DIGITALOCEAN_API_MAX_ITEMS", DIGITALOCEAN_MAX_ITEMS, 2_000_000
    )
    request_params = dict(params or {})
    request_params.setdefault("per_page", DIGITALOCEAN_PAGE_SIZE)
    next_url = digitalocean_api_url(path)
    seen_pages: set[str] = set()
    seen_items: set[str] = set()
    items: list[dict] = []
    expected_total: int | None = None

    for _page_number in range(1, page_limit + 1):
        page_key = next_url
        if request_params:
            page_key = f"{next_url}|{sorted(request_params.items())!r}"
        if page_key in seen_pages:
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
        seen_pages.add(page_key)

        payload = get_json(next_url, headers=headers, params=request_params or None)
        request_params = {}
        page_items = payload.get(collection_key)
        meta = payload.get("meta") or {}
        links = payload.get("links") or {}
        if not isinstance(meta, dict) or not isinstance(links, dict):
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
        try:
            total = int(meta["total"]) if "total" in meta else None
        except (TypeError, ValueError):
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
        if total is not None and total < 0:
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
        if expected_total is None:
            expected_total = total
        elif total is not None and expected_total != total:
            # A catalog changed while reconciliation was running.  Fail closed;
            # creating from a non-atomic inventory could duplicate a snapshot.
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")

        if page_items is None:
            page_items = []
        if not isinstance(page_items, list) or any(
            not isinstance(item, dict) for item in page_items
        ):
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
        for item in page_items:
            item_id = item.get("id")
            if item_id in (None, ""):
                raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
            identity = str(item_id)
            if identity in seen_items:
                raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
            seen_items.add(identity)
            items.append(item)
            if len(items) > item_limit:
                raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")

        pages = links.get("pages") or {}
        if not isinstance(pages, dict):
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
        provider_next = pages.get("next")
        if provider_next:
            next_url = digitalocean_api_url(provider_next)
            continue
        if expected_total is not None and len(items) != expected_total:
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
        return items

    raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")


def find_exact_snapshot(
    *,
    headers: dict,
    marker: str,
    source_id: str,
    resource_type: str,
) -> dict | None:
    """Return one exact snapshot or fail closed on ambiguity/ownership drift."""

    if resource_type not in {"droplet", "volume"}:
        raise DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")
    snapshots = iter_collection(
        "/v2/snapshots",
        "snapshots",
        headers=headers,
        params={"resource_type": resource_type},
    )
    named = [item for item in snapshots if str(item.get("name") or "") == str(marker)]
    exact = [
        item
        for item in named
        if str(item.get("resource_id") or "") == str(source_id)
        and str(item.get("resource_type") or "") == resource_type
    ]
    if len(named) > 1 or len(exact) > 1:
        raise DigitalOceanAPIError("PROVIDER_DUPLICATE_MATCH")
    if named and not exact:
        raise DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")
    return exact[0] if exact else None


def list_eligible_objects(*, headers: dict, object_type: str) -> list[dict]:
    """Return UI discovery objects from a complete, deterministic inventory."""

    mapping = {
        "cloud": ("/v2/droplets", "droplets"),
        "volume": ("/v2/volumes", "volumes"),
    }
    if object_type not in mapping:
        raise ValueError("object_type must be either cloud or volume")
    path, key = mapping[object_type]
    resources = iter_collection(path, key, headers=headers)
    output = []
    for resource in resources:
        item = dict(resource)
        item["_bs_unique_id"] = resource["id"]
        item["_bs_name"] = resource.get("name")
        item["_bs_region"] = (resource.get("region") or {}).get("name")
        item["_bs_size"] = (
            (resource.get("size") or {}).get("disk")
            if object_type == "cloud"
            else resource.get("size_gigabytes")
        )
        output.append(item)
    return sorted(output, key=lambda item: str(item["_bs_unique_id"]))
