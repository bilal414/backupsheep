"""Opportunistic pruning of expired OAuth 2.0 rows from the web lane.

Expired tokens and authorization codes are already rejected at authentication
time; sweeping only keeps the django-oauth-toolkit tables from growing without
bound.  The stock deployment denies every worker lane access to credential
tables, so the sweep runs inside the web service that owns them, gated through
the shared cache so the fleet performs it at most once per interval.
"""

from django.core.cache import cache
from oauth2_provider.models import clear_expired
from sentry_sdk import capture_exception

SWEEP_CACHE_KEY = "backupsheep.oauth2.expired-sweep"
SWEEP_INTERVAL_SECONDS = 60 * 60


def sweep_expired_credentials_if_due():
    """Run the toolkit's ``clear_expired`` at most once per interval.

    Returns ``True`` when this call performed the sweep.  Failures are reported
    and swallowed: token issuance must never depend on maintenance.
    """
    try:
        if not cache.add(SWEEP_CACHE_KEY, "1", timeout=SWEEP_INTERVAL_SECONDS):
            return False
        clear_expired()
        return True
    except Exception as error:  # pragma: no cover - defensive
        capture_exception(error)
        return False
