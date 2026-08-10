"""Bounded boto/ibm-boto client construction shared by APIs and workers."""

from __future__ import annotations

import boto3
from botocore.config import Config
from django.conf import settings
import math


_DEFAULT_CONNECT_TIMEOUT = 10.0
_DEFAULT_READ_TIMEOUT = 60.0
_DEFAULT_MAX_TIMEOUT = 300.0
_TIMEOUT_FLOOR = 0.1


def _finite_timeout(setting_name, default, maximum):
    try:
        value = float(getattr(settings, setting_name, default))
    except (TypeError, ValueError):
        value = float(default)
    if not math.isfinite(value):
        value = float(default)
    return min(max(value, _TIMEOUT_FLOOR), maximum)


def _timeout_pair():
    try:
        maximum = float(
            getattr(settings, "PROVIDER_HTTP_MAX_TIMEOUT", _DEFAULT_MAX_TIMEOUT)
        )
    except (TypeError, ValueError):
        maximum = _DEFAULT_MAX_TIMEOUT
    if not math.isfinite(maximum) or maximum < _TIMEOUT_FLOOR:
        maximum = _DEFAULT_MAX_TIMEOUT
    return (
        _finite_timeout(
            "PROVIDER_HTTP_CONNECT_TIMEOUT", _DEFAULT_CONNECT_TIMEOUT, maximum
        ),
        _finite_timeout(
            "PROVIDER_HTTP_READ_TIMEOUT", _DEFAULT_READ_TIMEOUT, maximum
        ),
    )


def _configured_retry_count():
    try:
        value = int(getattr(settings, "PROVIDER_HTTP_MAX_RETRIES", 0))
    except (TypeError, ValueError):
        value = 0
    return max(0, min(value, 10_000))


def _configured_pool_size():
    try:
        value = int(getattr(settings, "PROVIDER_HTTP_MAX_POOL_CONNECTIONS", 50))
    except (TypeError, ValueError):
        value = 50
    return max(1, min(value, 10_000))


def provider_boto_config(existing=None, *, allow_retries=False):
    """Apply finite I/O limits and a bounded connection pool.

    Provider-specific settings (for example S3 addressing style or checksum
    behavior) win when an existing ``Config`` is supplied.  SDK retries are
    disabled by default: upload/recovery tasks own retries and have the durable
    provider witnesses needed to distinguish a lost response from a missing
    object.  A caller may explicitly opt into bounded retries for a read-only
    operation.
    """
    connect_timeout, read_timeout = _timeout_pair()
    base = Config(
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        retries={
            "max_attempts": (
                _configured_retry_count() + 1 if allow_retries else 1
            ),
            "mode": "standard",
        },
        tcp_keepalive=True,
        max_pool_connections=_configured_pool_size(),
    )
    merged = base.merge(existing) if existing is not None else base
    # Adapter-local legacy values such as ``connect_timeout=10`` must not hide
    # the centrally configured finite policy.
    merged = merged.merge(
        Config(connect_timeout=connect_timeout, read_timeout=read_timeout)
    )
    if not allow_retries:
        # ``Config.merge`` preserves values from ``existing``.  Retries are the
        # one exception: an adapter's old Config must not silently re-enable
        # transport replay for a mutation.
        merged = merged.merge(
            Config(retries={"max_attempts": 1, "mode": "standard"})
        )
    return merged


def bounded_boto3_client(service_name, *args, **kwargs):
    allow_retries = bool(kwargs.pop("allow_retries", False))
    kwargs["config"] = provider_boto_config(
        kwargs.get("config"), allow_retries=allow_retries
    )
    return boto3.client(service_name, *args, **kwargs)


def bounded_ibm_boto3_client(service_name, *args, **kwargs):
    import ibm_boto3
    from ibm_botocore.client import Config as IBMConfig

    allow_retries = bool(kwargs.pop("allow_retries", False))
    existing = kwargs.get("config")
    connect_timeout, read_timeout = _timeout_pair()
    base = IBMConfig(
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        retries={
            "max_attempts": _configured_retry_count() + 1
            if allow_retries
            else 1,
            "mode": "standard",
        },
        max_pool_connections=_configured_pool_size(),
    )
    merged = base.merge(existing) if existing is not None else base
    merged = merged.merge(
        IBMConfig(connect_timeout=connect_timeout, read_timeout=read_timeout)
    )
    if not allow_retries:
        merged = merged.merge(
            IBMConfig(retries={"max_attempts": 1, "mode": "standard"})
        )
    kwargs["config"] = merged
    return ibm_boto3.client(service_name, *args, **kwargs)
