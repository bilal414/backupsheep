"""Bounded HTTP client used for every direct provider/API request."""

from __future__ import annotations

import math
import requests as _requests
from django.conf import settings
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def _bounded_setting(name, default, maximum):
    try:
        value = float(getattr(settings, name, default))
    except (TypeError, ValueError):
        value = float(default)
    if not math.isfinite(value):
        value = float(default)
    return min(max(value, 0.1), maximum)


def request_timeout():
    """Return a finite connect/read pair for every provider HTTP request."""
    maximum = _bounded_setting("PROVIDER_HTTP_MAX_TIMEOUT", 300.0, 86400.0)
    return (
        _bounded_setting("PROVIDER_HTTP_CONNECT_TIMEOUT", 10.0, maximum),
        _bounded_setting("PROVIDER_HTTP_READ_TIMEOUT", 60.0, maximum),
    )


def _retry_policy(*, allow_mutation_retries=True):
    try:
        retries = int(getattr(settings, "PROVIDER_HTTP_MAX_RETRIES", 4))
    except (TypeError, ValueError):
        retries = 0
    retries = max(0, min(retries, 10_000))
    allowed_methods = {"GET", "HEAD", "OPTIONS"}
    if allow_mutation_retries:
        # Kept as an explicit opt-in for legacy callers/tests.  All
        # BackupSheep-created sessions use the safer default below.
        allowed_methods.update({"DELETE", "PUT"})
    return Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=max(
            0.0, _bounded_setting("PROVIDER_HTTP_BACKOFF_FACTOR", 0.5, 3600.0)
        ),
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(allowed_methods),
        respect_retry_after_header=True,
        raise_on_status=False,
    )


class TimeoutSession(_requests.Session):
    """Requests session with mandatory timeout and safe idempotent retries."""

    def __init__(self, *, allow_mutation_retries=False):
        super().__init__()
        adapter = HTTPAdapter(
            max_retries=_retry_policy(
                allow_mutation_retries=allow_mutation_retries
            )
        )
        self.mount("http://", adapter)
        self.mount("https://", adapter)

    def request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", request_timeout())
        return super().request(method, url, **kwargs)


class RequestsFacade:
    """Drop-in subset of ``requests`` with bounded module-level methods.

    Attribute fallback preserves ``requests.exceptions``, ``RequestException``, and
    other type references used by existing provider adapters.
    """

    Session = TimeoutSession

    def __init__(self):
        self._session = TimeoutSession()

    def request(self, method, url, **kwargs):
        return self._session.request(method, url, **kwargs)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def patch(self, url, **kwargs):
        return self.request("PATCH", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)

    def session(self):
        return TimeoutSession()

    def __getattr__(self, name):
        return getattr(_requests, name)


requests = RequestsFacade()
