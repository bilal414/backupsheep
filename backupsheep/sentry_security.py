"""Privacy boundary for events sent to Sentry.

Sentry is useful for correlating failures, but BackupSheep routinely handles
decrypted provider and database credentials while a backup is running.  This
module deliberately trades some diagnostic detail for a fail-closed telemetry
boundary: request bodies, query strings, cookies, credential-shaped fields,
local variables, and credential-bearing URLs must never leave the process.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import urlsplit, urlunsplit


FILTERED = "[Filtered]"

_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "authorization",
    "cookie",
    "credential",
    "apikey",
    "accesskey",
    "privatekey",
    "consumerkey",
    "webhook",
    "dsn",
)
_BODY_KEYS = {
    "body",
    "form",
    "json",
    "payload",
    "postdata",
    "rawbody",
    "requestbody",
    "vars",
}
_QUERY_KEYS = {"query", "queryparams", "querystring", "searchparams"}
_URL_KEYS = {"url", "uri", "location", "referer", "referrer"}
_URL_PATTERN = re.compile(
    r"(?i)\b(?:https?|postgres(?:ql)?|mysql|mariadb|redis|amqps?|mongodb(?:\+srv)?)"
    r"://[^\s\"'<>]+"
)
_AUTH_PATTERN = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_KEY_VALUE_PATTERN = re.compile(
    r"(?i)\b("
    r"password|passwd|passphrase|secret|token|authorization|cookie|credential|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|consumer[_-]?key|webhook"
    r")\b\s*([:=]\s*|%3[dD])([^\s,;&\"'<>]+)"
)
_TRACE_ID_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
_SPAN_ID_PATTERN = re.compile(r"^[a-fA-F0-9]{16}$")


def _normalized_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def _is_sensitive_key(key: object) -> bool:
    normalized = _normalized_key(key)
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _sanitize_url(value: object) -> str:
    """Keep only a URL's non-secret origin.

    Paths can themselves contain bearer material (reset links and signed object
    URLs), so retaining only scheme, hostname, and a filtered path is safer than
    merely dropping the query string.
    """

    text = str(value)
    try:
        parsed = urlsplit(text)
    except ValueError:
        return FILTERED
    if not parsed.scheme or not parsed.hostname:
        return FILTERED
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        port = ""
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return urlunsplit((parsed.scheme, f"{host}{port}", f"/{FILTERED}", "", ""))


def _scrub_text(value: str) -> str:
    value = _URL_PATTERN.sub(lambda match: _sanitize_url(match.group(0)), value)
    value = _AUTH_PATTERN.sub(lambda match: f"{match.group(1)} {FILTERED}", value)
    return _KEY_VALUE_PATTERN.sub(
        lambda match: f"{match.group(1)}={FILTERED}", value
    )


def _scrub_value(value, *, path=()):
    if isinstance(value, Mapping):
        scrubbed = {}
        parent = _normalized_key(path[-1]) if path else ""
        for key, child in value.items():
            normalized = _normalized_key(key)
            if _is_sensitive_key(key):
                scrubbed[key] = FILTERED
            elif normalized in _BODY_KEYS or normalized in _QUERY_KEYS:
                scrubbed[key] = FILTERED
            elif normalized == "data" and parent == "request":
                scrubbed[key] = FILTERED
            elif normalized in _URL_KEYS or normalized.endswith("url"):
                scrubbed[key] = _sanitize_url(child)
            else:
                scrubbed[key] = _scrub_value(child, path=(*path, key))
        return scrubbed
    if isinstance(value, list):
        return [_scrub_value(item, path=path) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_value(item, path=path) for item in value)
    if isinstance(value, str):
        return _scrub_text(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        # Binary values in an event are not useful enough to justify any chance
        # of shipping a request body or decrypted key material.
        return FILTERED
    return value


def _safe_trace_context(contexts):
    """Retain correlation IDs, but discard arbitrary trace context values."""

    if not isinstance(contexts, Mapping):
        return {}
    source = contexts.get("trace")
    if not isinstance(source, Mapping):
        return {}
    trace = {}
    trace_id = source.get("trace_id")
    span_id = source.get("span_id")
    parent_span_id = source.get("parent_span_id")
    if isinstance(trace_id, str) and _TRACE_ID_PATTERN.fullmatch(trace_id):
        trace["trace_id"] = trace_id
    if isinstance(span_id, str) and _SPAN_ID_PATTERN.fullmatch(span_id):
        trace["span_id"] = span_id
    if isinstance(parent_span_id, str) and _SPAN_ID_PATTERN.fullmatch(parent_span_id):
        trace["parent_span_id"] = parent_span_id
    elif parent_span_id is None:
        trace["parent_span_id"] = None
    return {"trace": trace} if trace else {}


def scrub_sentry_event(event, hint):
    """Sentry hook that returns a credential-safe error or transaction event.

    Some Sentry fields accept arbitrary strings and are populated by framework
    integrations.  Label-based filtering is not sufficient for an exception
    whose message *is* a decrypted secret, so high-risk diagnostic containers
    are removed wholesale.  Correlation IDs and exception types remain useful.
    """

    del hint
    scrubbed = _scrub_value(event)
    if not isinstance(scrubbed, dict):
        return None

    if "message" in scrubbed:
        scrubbed["message"] = FILTERED
    if "logentry" in scrubbed:
        scrubbed["logentry"] = {"message": FILTERED}
    if "transaction" in scrubbed:
        scrubbed["transaction"] = FILTERED

    # These fields are intentionally free-form in the SDK and can contain raw
    # locals, SQL statements, provider responses, request data, or user input.
    scrubbed["extra"] = {}
    scrubbed["breadcrumbs"] = {"values": []}
    scrubbed["spans"] = []
    scrubbed.pop("threads", None)
    scrubbed.pop("debug_meta", None)
    scrubbed.pop("fingerprint", None)
    scrubbed.pop("user", None)

    scrubbed["contexts"] = _safe_trace_context(scrubbed.get("contexts"))

    request = scrubbed.get("request")
    if isinstance(request, dict):
        request["headers"] = {}
        request["cookies"] = FILTERED
        request["query_string"] = FILTERED
        request["data"] = FILTERED
        if "path" in request:
            request["path"] = FILTERED
        if "fragment" in request:
            request["fragment"] = FILTERED
        request.pop("env", None)

    exception = scrubbed.get("exception")
    if isinstance(exception, dict):
        values = exception.get("values")
        if isinstance(values, list):
            for value in values:
                if not isinstance(value, dict):
                    continue
                value["value"] = FILTERED
                stacktrace = value.get("stacktrace")
                if not isinstance(stacktrace, dict):
                    continue
                frames = stacktrace.get("frames")
                if not isinstance(frames, list):
                    continue
                for frame in frames:
                    if isinstance(frame, dict):
                        frame.pop("vars", None)

    return scrubbed
