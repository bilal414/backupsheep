"""Rate limits for credential- and authenticator-bearing endpoints.

These throttles deliberately do not use DRF's ``AnonRateThrottle``.  An
authenticated browser session or API token must not turn off brute-force and
reset-abuse controls on an authentication endpoint.

Every endpoint has two independent buckets:

* a coarse bucket keyed only by the WSGI server-observed network peer
  (``REMOTE_ADDR``); and
* a tighter bucket keyed by a normalized, keyed digest of the submitted
  identity or the already-authenticated user.

``X-Forwarded-For`` is intentionally ignored.  It is attacker-controlled unless
every route to the application passes through a proxy that overwrites it, which
is not a safe assumption for a reusable self-hosted application.
"""

import ipaddress
import unicodedata

from django.conf import settings
from django.utils.crypto import salted_hmac
from rest_framework.throttling import SimpleRateThrottle


def _keyed_identifier(kind, value):
    """Return a bounded cache-safe digest without persisting identity secrets."""

    normalized = unicodedata.normalize("NFKC", str(value or ""))
    normalized = normalized.strip().casefold()[:1024] or "<missing>"
    return salted_hmac(
        "backupsheep.security-throttle",
        f"{kind}:{normalized}",
    ).hexdigest()


def _canonical_ip(value):
    """Return an IP object for one unambiguous address, otherwise ``None``."""

    if not isinstance(value, str) or "," in value or "%" in value:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _direct_peer(request):
    value = str(request.META.get("REMOTE_ADDR") or "<missing>").strip()
    address = _canonical_ip(value)
    if address is not None:
        return address, address.compressed
    # WSGI servers should supply an IP address. Hashing the bounded raw value
    # fails closed into a stable bucket if a non-standard server does not.
    return None, value[:256].casefold() or "<missing>"


def _configured_trusted_proxy_networks():
    """Parse the already-validated setting, failing closed on any bad entry."""

    networks = []
    for value in getattr(settings, "AUTH_THROTTLE_TRUSTED_PROXY_NETWORKS", ()):
        try:
            networks.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError:
            return ()
    return tuple(networks)


def _server_observed_peer(request):
    """Resolve the non-spoofable peer identity used by coarse auth buckets.

    Direct ``REMOTE_ADDR`` is always the fallback. A deployment may explicitly
    trust exact proxy networks and enable one dedicated client-IP header, but the
    proxy must overwrite that header. Arbitrary forwarding headers are never
    consulted.
    """

    direct_address, direct_value = _direct_peer(request)
    if not getattr(settings, "AUTH_THROTTLE_TRUSTED_PROXY_ENABLED", False):
        return direct_value
    if direct_address is None:
        return direct_value

    networks = _configured_trusted_proxy_networks()
    if not networks or not any(direct_address in network for network in networks):
        return direct_value

    forwarded_address = _canonical_ip(
        request.META.get("HTTP_X_BACKUPSHEEP_CLIENT_IP")
    )
    if forwarded_address is None:
        return direct_value
    return forwarded_address.compressed


def _submitted_value(request, name):
    """Read one field without assuming the JSON root is an object."""

    data = request.data
    getter = getattr(data, "get", None)
    return getter(name) if callable(getter) else None


class _ServerPeerThrottle(SimpleRateThrottle):
    """Apply a throttle to every request from the direct server-observed peer."""

    def get_cache_key(self, request, view):
        ident = _keyed_identifier("peer", _server_observed_peer(request))
        return self.cache_format % {"scope": self.scope, "ident": ident}


class _SubmittedIdentityThrottle(SimpleRateThrottle):
    """Base for a per-submitted-identity bucket that never stores raw values."""

    def identity(self, request):
        raise NotImplementedError

    def get_cache_key(self, request, view):
        kind, value = self.identity(request)
        ident = _keyed_identifier(kind, value)
        return self.cache_format % {"scope": self.scope, "ident": ident}


class LoginRateThrottle(_ServerPeerThrottle):
    """Coarse login spray guard, including authenticated callers."""

    scope = "auth-login-peer"
    rate = "30/minute"


class LoginIdentityRateThrottle(_SubmittedIdentityThrottle):
    """Password and MFA-attempt limit for one normalized submitted email."""

    scope = "auth-login-identity"
    rate = "5/minute"

    def identity(self, request):
        return "login-email", _submitted_value(request, "email")


class PasswordResetRateThrottle(_ServerPeerThrottle):
    """Coarse reset-email/token spray guard, including authenticated callers."""

    scope = "auth-reset-peer"
    rate = "15/minute"


class PasswordResetIdentityRateThrottle(_SubmittedIdentityThrottle):
    """Limit reset POSTs by email and PATCH attempts by reset bearer digest."""

    scope = "auth-reset-identity"
    rate = "3/minute"

    def identity(self, request):
        if request.method.upper() == "PATCH":
            return "reset-token", _submitted_value(request, "password_token")
        return "reset-email", _submitted_value(request, "email")


class MFARateThrottle(_ServerPeerThrottle):
    """Coarse peer guard shared by setup, verification, and revocation."""

    scope = "auth-mfa-peer"
    rate = "30/minute"


class MFAIdentityRateThrottle(_SubmittedIdentityThrottle):
    """Limit all MFA management attempts for the authenticated identity."""

    scope = "auth-mfa-identity"
    rate = "5/minute"

    def identity(self, request):
        user = getattr(request, "user", None)
        return "mfa-user", getattr(user, "pk", None)
