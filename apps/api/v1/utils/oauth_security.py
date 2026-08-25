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
    """Explicitly restart a session-bound, expiring OAuth transaction.

    One pending authorization is retained per provider.  Starting a new flow
    invalidates an older, uncompleted flow for that same provider, while flows
    for other providers remain independent.  Callers must only use this
    replacement behavior from an explicit, CSRF-protected user action.  A GET
    page render must use :func:`get_or_issue_oauth_state` instead so it cannot
    invalidate an authorization already in flight.
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


def _state_record_is_reusable(
    record, *, provider, member, account, use_pkce=False, now=None
):
    """Return whether a pending record is safe to reuse for page rendering."""

    if not isinstance(record, dict):
        return False
    state = record.get("state")
    if not isinstance(state, str) or not state:
        return False
    try:
        issued_at = float(record.get("issued_at"))
    except (TypeError, ValueError):
        return False
    age = (time.time() if now is None else now) - issued_at
    if not (
        0 <= age <= OAUTH_STATE_TTL_SECONDS
        and secrets.compare_digest(str(record.get("provider")), str(provider))
        and secrets.compare_digest(str(record.get("member_id")), str(member.pk))
        and secrets.compare_digest(str(record.get("account_id")), str(account.pk))
    ):
        return False

    verifier = record.get("code_verifier")
    challenge = record.get("code_challenge")
    if not use_pkce:
        return verifier is None and challenge is None
    if not isinstance(verifier, str) or not isinstance(challenge, str):
        return False
    try:
        expected_challenge = _pkce_challenge(verifier)
    except (UnicodeEncodeError, ValueError):
        return False
    return secrets.compare_digest(expected_challenge, challenge)


def get_or_issue_oauth_state(
    request,
    *,
    provider,
    member,
    account,
    use_pkce=False,
    legacy_session_key=None,
):
    """Return a matching live transaction without rotating it during a GET.

    A missing, expired, differently-bound, or PKCE-incompatible record is
    replaced.  This makes authenticated console pages idempotent while retaining
    the explicit replacement semantics of :func:`issue_oauth_state` for a real
    restart button or POST endpoint.
    """

    pending = request.session.get(OAUTH_STATE_SESSION_KEY, {})
    pending = dict(pending) if isinstance(pending, dict) else {}
    record = pending.get(str(provider))
    if _state_record_is_reusable(
        record,
        provider=provider,
        member=member,
        account=account,
        use_pkce=use_pkce,
    ):
        if legacy_session_key:
            request.session.pop(legacy_session_key, None)
        return dict(record)

    if legacy_session_key:
        legacy_record = request.session.pop(legacy_session_key, None)
        if isinstance(legacy_record, dict):
            legacy_record = dict(legacy_record)
            legacy_record.setdefault("provider", str(provider))
            if _state_record_is_reusable(
                legacy_record,
                provider=provider,
                member=member,
                account=account,
                use_pkce=use_pkce,
            ):
                pending[str(provider)] = legacy_record
                request.session[OAUTH_STATE_SESSION_KEY] = pending
                return dict(legacy_record)
    return issue_oauth_state(
        request,
        provider=provider,
        member=member,
        account=account,
        use_pkce=use_pkce,
    )


def consume_oauth_state(
    request,
    *,
    provider,
    received_state,
    member,
    account,
    legacy_session_key=None,
):
    """Verify and consume one matching OAuth state record.

    A callback carrying an unknown state must not cancel the user's legitimate
    in-flight authorization.  This matters for cross-site top-level callbacks:
    browsers may attach a SameSite=Lax session cookie even though the sender
    cannot read the pending state.  Once the opaque state itself matches, consume
    the record whether the remaining binding/expiry checks pass or fail so that a
    known stale or misbound value cannot be replayed.
    """

    pending = request.session.get(OAUTH_STATE_SESSION_KEY, {})
    pending = dict(pending) if isinstance(pending, dict) else {}
    provider_key = str(provider)
    expected = pending.get(provider_key)
    using_legacy = False
    if expected is None and legacy_session_key:
        legacy_expected = request.session.get(legacy_session_key)
        if isinstance(legacy_expected, dict):
            expected = dict(legacy_expected)
            expected.setdefault("provider", provider_key)
            using_legacy = True

    if not isinstance(expected, dict) or not isinstance(received_state, str):
        return None
    expected_state = expected.get("state")
    if not isinstance(expected_state, str) or not secrets.compare_digest(
        expected_state, received_state
    ):
        return None

    # Only knowledge of the opaque expected state is allowed to mutate the
    # pending transaction. A current provider record supersedes and retires any
    # legacy record for that provider when it is consumed.
    if using_legacy:
        request.session.pop(legacy_session_key, None)
    else:
        pending.pop(provider_key, None)
        if pending:
            request.session[OAUTH_STATE_SESSION_KEY] = pending
        else:
            request.session.pop(OAUTH_STATE_SESSION_KEY, None)
        if legacy_session_key:
            request.session.pop(legacy_session_key, None)

    try:
        issued_at = float(expected.get("issued_at"))
    except (TypeError, ValueError):
        return None
    age = time.time() - issued_at
    valid = (
        0 <= age <= OAUTH_STATE_TTL_SECONDS
        and secrets.compare_digest(str(expected.get("provider")), provider_key)
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
