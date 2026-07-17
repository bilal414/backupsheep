"""Rate throttles for unauthenticated, credential-bearing endpoints.

DRF's cache-backed throttle state uses the default cache (the database cache in
this project), so no extra infrastructure is required. Clients are identified by
IP (REMOTE_ADDR). If gunicorn runs behind a reverse proxy, set
REST_FRAMEWORK["NUM_PROXIES"] = 1 so DRF honors X-Forwarded-For — only when
requests can ONLY arrive via that proxy, otherwise the header is spoofable.
"""

from rest_framework.throttling import AnonRateThrottle


class LoginRateThrottle(AnonRateThrottle):
    """Brute-force / credential-stuffing guard for the login endpoint."""

    rate = "5/minute"


class PasswordResetRateThrottle(AnonRateThrottle):
    """Reset-email spam and token-guessing guard for the password reset endpoint."""

    rate = "3/minute"
