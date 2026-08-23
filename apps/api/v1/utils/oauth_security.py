"""Shared OAuth authorization-code flow security helpers.

OAuth ``state`` is deliberately stored in the authenticated server-side session
instead of being a signed, self-contained bearer value.  A callback is accepted
only once, for the same provider, member, and current account that initiated it.
PKCE verifiers use the same short-lived session record and never leave the
server.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from urllib.parse import urlsplit, urlunsplit


OAUTH_STATE_SESSION_KEY = "oauth_pending_states_v1"
OAUTH_STATE_TTL_SECONDS = 10 * 60


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def issue_oauth_state(request, *, provider, member, account, use_pkce=False):
    """Issue a session-bound, expiring OAuth state record.

    One pending authorization is retained per provider.  Starting a new flow
    invalidates an older, uncompleted flow for that same provider, while flows
    for other providers remain independent.
    """

    state = secrets.token_urlsafe(32)
    record = {
        "state": state,
        "provider": str(provider),
        "member_id": str(member.pk),
        "account_id": str(account.pk),
        "issued_at": time.time(),
    }
    if use_pkce:
        # token_urlsafe(64) produces an RFC 7636-valid unreserved verifier below
        # the 128-character maximum with substantially more than 256 bits of
        # entropy.
        verifier = secrets.token_urlsafe(64)
        record["code_verifier"] = verifier
        record["code_challenge"] = _pkce_challenge(verifier)

    pending = request.session.get(OAUTH_STATE_SESSION_KEY, {})
    pending = dict(pending) if isinstance(pending, dict) else {}
    pending[str(provider)] = record
    request.session[OAUTH_STATE_SESSION_KEY] = pending
    return dict(record)


def consume_oauth_state(request, *, provider, received_state, member, account):
    """Consume and verify one OAuth state record.

    Consumption happens before validation, so malformed, expired, mismatched,
    and provider-error callbacks cannot be replayed.
    """

    pending = request.session.get(OAUTH_STATE_SESSION_KEY, {})
    pending = dict(pending) if isinstance(pending, dict) else {}
    expected = pending.pop(str(provider), None)
    if pending:
        request.session[OAUTH_STATE_SESSION_KEY] = pending
    else:
        request.session.pop(OAUTH_STATE_SESSION_KEY, None)

    if not isinstance(expected, dict) or not isinstance(received_state, str):
        return None
    expected_state = expected.get("state")
    if not isinstance(expected_state, str):
        return None
    try:
        issued_at = float(expected.get("issued_at"))
    except (TypeError, ValueError):
        return None
    age = time.time() - issued_at
    valid = (
        0 <= age <= OAUTH_STATE_TTL_SECONDS
        and secrets.compare_digest(expected_state, received_state)
        and secrets.compare_digest(str(expected.get("provider")), str(provider))
        and secrets.compare_digest(str(expected.get("member_id")), str(member.pk))
        and secrets.compare_digest(str(expected.get("account_id")), str(account.pk))
    )
    return dict(expected) if valid else None


def validated_https_endpoint(
    value,
    *,
    allowed_hostnames,
    allowed_paths=None,
    allowed_path_prefixes=None,
    allowed_path_suffixes=None,
):
    """Return a normalized allow-listed HTTPS endpoint or ``None``.

    OAuth credentials must never be sent to an arbitrary configurable host.
    Userinfo and token calls also disable redirects at the call site, preventing
    a trusted endpoint from forwarding POST bodies or bearer headers elsewhere.
    """

    if not isinstance(value, str):
        return None
    value = value.strip()
    try:
        parsed = urlsplit(value)
        explicit_port = parsed.port
    except ValueError:
        return None
    hostname = (parsed.hostname or "").lower().rstrip(".")
    allowed = {str(item).lower().rstrip(".") for item in allowed_hostnames}
    if (
        parsed.scheme.lower() != "https"
        or hostname not in allowed
        or parsed.username is not None
        or parsed.password is not None
        or explicit_port is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        return None

    if allowed_paths is not None and parsed.path not in set(allowed_paths):
        return None
    if allowed_path_prefixes is not None and not any(
        parsed.path.startswith(prefix) for prefix in allowed_path_prefixes
    ):
        return None
    if allowed_path_suffixes is not None and not any(
        parsed.path.endswith(suffix) for suffix in allowed_path_suffixes
    ):
        return None

    return urlunsplit(("https", hostname, parsed.path, "", ""))
