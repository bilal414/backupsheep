"""Durable S3-compatible replication for Lightsail object-storage buckets.

The module deliberately owns no URL, settings, or migration integration.  The
primary worker can import the task names from here and add this module to its Celery
imports after importing ``apps.console.backup.replication_models`` from the app's
model registry.

There are two layers:

* small, provider-shaped helpers (listing, idempotent copy, multipart resume) that
  are straightforward to exercise with a fake S3 client; and
* database/Celery orchestration that persists the definition, run, object, lease,
  and multipart rows after each remote side effect.

Credentials are always read from the existing encrypted CoreAuthLightsail or
CoreStorage relation fields and decrypted only for construction of a boto3 client.
No credential value is included in returned task data, manifests, or exceptions.
"""

from __future__ import annotations

import hashlib
import json
import errno
import socket
import uuid
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from datetime import timedelta, timezone as datetime_timezone
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

import boto3
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    ConnectionClosedError,
    EndpointConnectionError,
    NoCredentialsError,
    PartialCredentialsError,
    ReadTimeoutError,
)
from celery import current_app
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Sum
from django.utils import timezone
from sentry_sdk import capture_exception

from apps.api.v1.utils.boto import bounded_boto3_client

from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt
from apps.console.backup.replication_models import (
    CoreLightsailBucketReplication,
    CoreLightsailBucketReplicationLease,
    CoreLightsailBucketReplicationMultipart,
    CoreLightsailBucketReplicationObject,
    CoreLightsailBucketReplicationRun,
    CoreLightsailBucketRestoreObject,
    CoreLightsailBucketRestoreRun,
)
from apps.console.storage.models import CoreStorage


DEFAULT_PART_SIZE = 64 * 1024 * 1024
DEFAULT_LEASE_SECONDS = 15 * 60
MANIFEST_DIRECTORY = ".backupsheep/manifests/"


SAFE_FAILURE_CODES = frozenset(
    {
        "LIGHTSAIL_NOT_FOUND",
        "LIGHTSAIL_AUTH_FAILED",
        "LIGHTSAIL_RATE_LIMITED",
        "LIGHTSAIL_TIMEOUT",
        "LIGHTSAIL_TRANSIENT_OUTAGE",
        "LIGHTSAIL_TERMINAL_FAILURE",
        "LIGHTSAIL_INVALID_RESPONSE",
        "LIGHTSAIL_UNSUPPORTED",
        "LIGHTSAIL_DUPLICATE_MATCH",
        "LIGHTSAIL_MUTATION_OUTCOME_UNKNOWN",
        "LIGHTSAIL_LEASE_BUSY",
        "LIGHTSAIL_LEASE_LOST",
        "LIGHTSAIL_STATE_CORRUPT",
        "LIGHTSAIL_WORKER_FAILURE",
    }
)

SAFE_FAILURE_STATUSES = frozenset(
    {
        "not_found",
        "auth_failed",
        "rate_limited",
        "timeout",
        "transient_outage",
        "terminal",
        "invalid_response",
        "unsupported",
        "duplicate_match",
        "unknown_outcome",
        "lease_busy",
        "lease_lost",
        "state_corrupt",
        "worker_failure",
    }
)

SAFE_FAILURE_MESSAGES = {
    "LIGHTSAIL_NOT_FOUND": "The requested Lightsail or destination object was not found.",
    "LIGHTSAIL_AUTH_FAILED": "The provider rejected the configured credentials or permissions.",
    "LIGHTSAIL_RATE_LIMITED": "The provider rate-limited this operation; it will resume automatically.",
    "LIGHTSAIL_TIMEOUT": "The provider did not respond before the configured request or worker timeout.",
    "LIGHTSAIL_TRANSIENT_OUTAGE": "The provider is temporarily unavailable; the operation will resume automatically.",
    "LIGHTSAIL_TERMINAL_FAILURE": "The provider rejected this operation and automatic retry is not safe.",
    "LIGHTSAIL_INVALID_RESPONSE": "The provider returned an invalid response; no unsafe mutation was attempted.",
    "LIGHTSAIL_UNSUPPORTED": "The selected destination is not supported for Lightsail bucket replication.",
    "LIGHTSAIL_DUPLICATE_MATCH": "The provider returned conflicting duplicate object versions; replication stopped for manual review.",
    "LIGHTSAIL_MUTATION_OUTCOME_UNKNOWN": "The provider mutation outcome is unknown; BackupSheep will reconcile it before retrying.",
    "LIGHTSAIL_LEASE_BUSY": "Another worker currently owns this operation; it will resume after the lease expires.",
    "LIGHTSAIL_LEASE_LOST": "This worker lost ownership; the durable operation will resume safely.",
    "LIGHTSAIL_STATE_CORRUPT": "Durable replication state could not be verified; no provider mutation was attempted.",
    "LIGHTSAIL_WORKER_FAILURE": "The backup worker failed safely; secured diagnostics contain the detailed cause.",
}


@dataclass(frozen=True)
class LightsailFailure:
    """The only failure contract allowed into durable state or API responses."""

    code: str
    message: str
    status: str
    retryable: bool
    correlation_id: str
    retry_after_seconds: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        result = {
            "code": self.code,
            "message": self.message,
            "status": self.status,
            "retryable": bool(self.retryable),
            "correlation_id": self.correlation_id,
        }
        if self.retry_after_seconds is not None:
            result["retry_after_seconds"] = int(self.retry_after_seconds)
        return result


class LightsailBucketReplicationError(RuntimeError):
    """Base error for a replication that can be retried from durable state."""

    def __init__(self, message: str = "The Lightsail bucket operation failed safely.", *, failure=None):
        self.failure = failure
        super().__init__(message)


class UnsupportedStorageProvider(LightsailBucketReplicationError, ValueError):
    """Raised when a CoreStorage relation is not S3-compatible for this lane."""


class LeaseUnavailable(LightsailBucketReplicationError):
    """Another worker currently owns the object/restore lease."""


class LeaseLost(LightsailBucketReplicationError):
    """The current worker's lease expired or was recovered by another worker."""


def _correlation_id(value: Optional[str] = None) -> str:
    value = str(value or "").strip()
    return value[:64] if value else uuid.uuid4().hex


def _provider_error_parts(error: BaseException) -> Tuple[str, Optional[int], Dict[str, Any]]:
    if not isinstance(error, ClientError):
        return "", None, {}
    response = error.response if isinstance(error.response, dict) else {}
    details = response.get("Error") if isinstance(response.get("Error"), dict) else {}
    metadata = (
        response.get("ResponseMetadata")
        if isinstance(response.get("ResponseMetadata"), dict)
        else {}
    )
    code = str(details.get("Code") or "").strip().lower()
    status = _safe_int(metadata.get("HTTPStatusCode"))
    headers = metadata.get("HTTPHeaders")
    return code, status, headers if isinstance(headers, dict) else {}


def _retry_after_seconds(error: BaseException, default: Optional[int] = None) -> Optional[int]:
    _code, _status, headers = _provider_error_parts(error)
    value = headers.get("retry-after") or headers.get("Retry-After")
    seconds = _safe_int(value)
    if seconds is None and value:
        try:
            retry_at = parsedate_to_datetime(str(value))
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=datetime_timezone.utc)
            seconds = max(0, int((retry_at - _now()).total_seconds()))
        except (TypeError, ValueError, OverflowError):
            seconds = None
    if seconds is None:
        seconds = _safe_int(getattr(error, "retry_after", None))
    if seconds is None:
        seconds = default
    if seconds is None:
        return None
    return max(1, min(int(seconds), 3600))


def _failure(
    code: str,
    message: str,
    status: str,
    retryable: bool,
    *,
    correlation_id: Optional[str] = None,
    retry_after_seconds: Optional[int] = None,
) -> LightsailFailure:
    if code not in SAFE_FAILURE_CODES or status not in SAFE_FAILURE_STATUSES:
        code = "LIGHTSAIL_WORKER_FAILURE"
        status = "worker_failure"
        message = SAFE_FAILURE_MESSAGES[code]
        retryable = True
    else:
        message = SAFE_FAILURE_MESSAGES[code]
    return LightsailFailure(
        code=code,
        message=message,
        status=status,
        retryable=bool(retryable),
        correlation_id=_correlation_id(correlation_id),
        retry_after_seconds=retry_after_seconds,
    )


def _failure_for(
    error: BaseException,
    *,
    correlation_id: Optional[str] = None,
    unknown_outcome: bool = False,
) -> LightsailFailure:
    """Classify without returning, logging, or persisting provider diagnostics."""

    error_name = error.__class__.__name__
    existing = getattr(error, "failure", None)
    if isinstance(existing, LightsailFailure):
        failure = existing
    elif isinstance(error, LeaseUnavailable):
        failure = _failure(
            "LIGHTSAIL_LEASE_BUSY",
            "Another worker currently owns this operation; it will resume after the lease expires.",
            "lease_busy",
            True,
            correlation_id=correlation_id,
            retry_after_seconds=30,
        )
    elif isinstance(error, LeaseLost):
        failure = _failure(
            "LIGHTSAIL_LEASE_LOST",
            "This worker lost ownership; the durable operation will resume safely.",
            "lease_lost",
            True,
            correlation_id=correlation_id,
            retry_after_seconds=30,
        )
    elif isinstance(error, UnsupportedStorageProvider):
        failure = _failure(
            "LIGHTSAIL_UNSUPPORTED",
            "The selected destination is not supported for Lightsail bucket replication.",
            "unsupported",
            False,
            correlation_id=correlation_id,
        )
    elif isinstance(error, (NoCredentialsError, PartialCredentialsError)):
        failure = _failure(
            "LIGHTSAIL_AUTH_FAILED",
            "The provider credentials are missing or incomplete.",
            "auth_failed",
            False,
            correlation_id=correlation_id,
        )
    elif isinstance(error, (SoftTimeLimitExceeded, TimeoutError, socket.timeout)) or getattr(
        error, "errno", None
    ) == errno.ETIMEDOUT or isinstance(
        error, (ConnectTimeoutError, ReadTimeoutError)
    ) or error_name in {"Timeout", "ReadTimeout", "ConnectTimeout"}:
        failure = _failure(
            "LIGHTSAIL_TIMEOUT",
            "The provider did not respond before the configured request or worker timeout.",
            "timeout",
            True,
            correlation_id=correlation_id,
            retry_after_seconds=_retry_after_seconds(error, 30),
        )
    elif isinstance(error, ClientError):
        code, http_status, _headers = _provider_error_parts(error)
        if code in {
            "404",
            "nosuchkey",
            "nosuchbucket",
            "notfound",
            "notfoundexception",
            "nosuchupload",
        } or http_status == 404:
            failure = _failure(
                "LIGHTSAIL_NOT_FOUND",
                "The requested Lightsail or destination object was not found.",
                "not_found",
                False,
                correlation_id=correlation_id,
            )
        elif code in {
            "401",
            "403",
            "accessdenied",
            "invalidaccesskeyid",
            "signaturedoesnotmatch",
            "invalidtoken",
            "expiredtoken",
            "unauthorized",
        } or http_status in {401, 403}:
            failure = _failure(
                "LIGHTSAIL_AUTH_FAILED",
                "The provider rejected the configured credentials or permissions.",
                "auth_failed",
                False,
                correlation_id=correlation_id,
            )
        elif code in {"requesttimeout", "requesttimeoutexception"} or http_status == 408:
            failure = _failure(
                "LIGHTSAIL_TIMEOUT",
                "The provider did not respond before the configured request or worker timeout.",
                "timeout",
                True,
                correlation_id=correlation_id,
                retry_after_seconds=_retry_after_seconds(error, 30),
            )
        elif code in {
            "429",
            "throttling",
            "throttlingexception",
            "slowdown",
            "toomanyrequests",
            "requestlimitexceeded",
        } or http_status == 429:
            failure = _failure(
                "LIGHTSAIL_RATE_LIMITED",
                "The provider rate-limited this operation; it will resume automatically.",
                "rate_limited",
                True,
                correlation_id=correlation_id,
                retry_after_seconds=_retry_after_seconds(error, 60),
            )
        elif code in {
            "serviceunavailable",
            "internalerror",
            "internalfailure",
            "internalservererror",
            "temporarilyunavailable",
            "slowdown",
        } or http_status in {500, 502, 503, 504}:
            failure = _failure(
                "LIGHTSAIL_TRANSIENT_OUTAGE",
                "The provider is temporarily unavailable; the operation will resume automatically.",
                "transient_outage",
                True,
                correlation_id=correlation_id,
                retry_after_seconds=_retry_after_seconds(error, 60),
            )
        else:
            failure = _failure(
                "LIGHTSAIL_TERMINAL_FAILURE",
                "The provider rejected this operation and automatic retry is not safe.",
                "terminal",
                False,
                correlation_id=correlation_id,
            )
    elif isinstance(error, (EndpointConnectionError, ConnectionClosedError, BotoCoreError, OSError)) or error_name in {
        "ConnectionError",
        "ConnectError",
        "RemoteDisconnected",
    }:
        failure = _failure(
            "LIGHTSAIL_TRANSIENT_OUTAGE",
            "The provider connection failed temporarily; the operation will resume automatically.",
            "transient_outage",
            True,
            correlation_id=correlation_id,
            retry_after_seconds=_retry_after_seconds(error, 60),
        )
    elif isinstance(
        error,
        (AttributeError, IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError),
    ):
        failure = _failure(
            "LIGHTSAIL_INVALID_RESPONSE",
            "The provider returned an invalid response; no unsafe mutation was attempted.",
            "invalid_response",
            False,
            correlation_id=correlation_id,
        )
    else:
        failure = _failure(
            "LIGHTSAIL_WORKER_FAILURE",
            "The backup worker failed safely; secured diagnostics contain the detailed cause.",
            "worker_failure",
            True,
            correlation_id=correlation_id,
            retry_after_seconds=60,
        )

    if unknown_outcome and failure.retryable:
        failure = _failure(
            "LIGHTSAIL_MUTATION_OUTCOME_UNKNOWN",
            "The provider mutation outcome is unknown; BackupSheep will reconcile it before retrying.",
            "unknown_outcome",
            True,
            correlation_id=failure.correlation_id,
            retry_after_seconds=failure.retry_after_seconds or 30,
        )
    return failure


def _duplicate_match_failure(correlation_id: Optional[str] = None) -> LightsailFailure:
    return _failure(
        "LIGHTSAIL_DUPLICATE_MATCH",
        "The provider returned conflicting duplicate object versions; replication stopped for manual review.",
        "duplicate_match",
        False,
        correlation_id=correlation_id,
    )


def _state_corrupt_failure(correlation_id: Optional[str] = None) -> LightsailFailure:
    return _failure(
        "LIGHTSAIL_STATE_CORRUPT",
        "Durable replication state could not be verified; no provider mutation was attempted.",
        "state_corrupt",
        False,
        correlation_id=correlation_id,
    )


def _safe_failure_exception(
    error: BaseException,
    *,
    unknown_outcome: bool = False,
    correlation_id: Optional[str] = None,
) -> LightsailBucketReplicationError:
    capture_exception(getattr(error, "__cause__", None) or error)
    failure = _failure_for(
        error,
        correlation_id=correlation_id,
        unknown_outcome=unknown_outcome,
    )
    return LightsailBucketReplicationError(failure.message, failure=failure)


def _failure_payload(failure: LightsailFailure) -> str:
    return json.dumps(failure.as_dict(), sort_keys=True, separators=(",", ":"))


def safe_failure_details(value: Any, *, fallback_correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """Parse only our safe error envelope; legacy/raw text is never returned."""

    payload = None
    if isinstance(value, dict):
        payload = value
    elif isinstance(value, str) and value:
        try:
            candidate = json.loads(value)
            if isinstance(candidate, dict):
                payload = candidate
        except (TypeError, ValueError):
            payload = None
    if not payload or payload.get("code") not in SAFE_FAILURE_CODES:
        return {
            "code": "LIGHTSAIL_WORKER_FAILURE",
            "message": "The backup worker failed safely; secured diagnostics contain the detailed cause.",
            "status": "worker_failure",
            "retryable": True,
            "correlation_id": _correlation_id(fallback_correlation_id),
        }
    status = payload.get("status")
    if status not in SAFE_FAILURE_STATUSES:
        status = "worker_failure"
    result = {
        "code": str(payload["code"]),
        "message": SAFE_FAILURE_MESSAGES[str(payload["code"])],
        "status": status,
        "retryable": bool(payload.get("retryable")),
        "correlation_id": _correlation_id(payload.get("correlation_id") or fallback_correlation_id),
    }
    retry_after = _safe_int(payload.get("retry_after_seconds"))
    if retry_after is not None:
        result["retry_after_seconds"] = max(1, min(retry_after, 3600))
    return result


def _capture_and_raise_state_error(correlation_id: Optional[str] = None):
    failure = _state_corrupt_failure(correlation_id)
    raise LightsailBucketReplicationError(failure.message, failure=failure)


def _encrypted_state(value: Any, account) -> str:
    try:
        encrypted = bs_encrypt(
            json.dumps(value, sort_keys=True, separators=(",", ":")),
            account.get_encryption_key(),
        )
        if not encrypted:
            _capture_and_raise_state_error()
        return bytes(encrypted).decode("ascii")
    except LightsailBucketReplicationError:
        raise
    except Exception as error:
        raise _safe_failure_exception(error) from error


def _decrypted_state(value: Any, account) -> Dict[str, Any]:
    if not value:
        return {}
    if not isinstance(value, str):
        _capture_and_raise_state_error()
    try:
        plaintext = bs_decrypt(value.encode("ascii"), account.get_encryption_key())
        decoded = json.loads(plaintext or "")
    except Exception as error:
        capture_exception(error)
        _capture_and_raise_state_error()
    if not isinstance(decoded, dict):
        _capture_and_raise_state_error()
    return decoded


def _restore_key_hash(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _encrypt_restore_key(value: str, account) -> str:
    return _encrypted_state({"value": str(value or "")}, account)


def _decrypt_restore_key(value: str, account) -> str:
    decoded = _decrypted_state(value, account)
    plaintext = decoded.get("value")
    if not isinstance(plaintext, str):
        _capture_and_raise_state_error()
    return plaintext


def _load_listing_cursor(run, replication) -> Dict[str, Any]:
    manifest = run.manifest if isinstance(run.manifest, dict) else {}
    return _decrypted_state(manifest.get("_listing_cursor"), replication.account)


def _listing_is_complete(run) -> bool:
    manifest = run.manifest if isinstance(run.manifest, dict) else {}
    return manifest.get("_listing_complete") is True


def _persist_listing_cursor(run, replication, cursor: Dict[str, Any]):
    manifest = dict(run.manifest) if isinstance(run.manifest, dict) else {}
    if cursor:
        manifest["_listing_cursor"] = _encrypted_state(cursor, replication.account)
        manifest["_progress"] = {"phase": "listing"}
        manifest["_listing_complete"] = False
    else:
        manifest.pop("_listing_cursor", None)
        manifest.pop("_progress", None)
        manifest["_listing_complete"] = True
    run.manifest = manifest
    run.save(update_fields=["manifest", "modified"])


# These are the existing relations whose integration uses the S3 protocol and
# boto3-compatible credentials.  Tencent and Alibaba have dedicated SDKs in the
# repository; local, Azure, Google, and OAuth destinations are intentionally rejected
# rather than silently trying a subtly incompatible API.
S3_STORAGE_RELATIONS = {
    "aws_s3": "storage_aws_s3",
    "wasabi": "storage_wasabi",
    "do_spaces": "storage_do_spaces",
    "filebase": "storage_filebase",
    "exoscale": "storage_exoscale",
    "backblaze_b2": "storage_backblaze_b2",
    "linode": "storage_linode",
    "vultr": "storage_vultr",
    "upcloud": "storage_upcloud",
    "oracle": "storage_oracle",
    "scaleway": "storage_scaleway",
    "cloudflare": "storage_cloudflare",
    "leviia": "storage_leviia",
    "idrive": "storage_idrive",
    "ionos": "storage_ionos",
    "rackcorp": "storage_rackcorp",
    "ibm": "storage_ibm",
}


def _setting_int(name: str, default: int) -> int:
    value = getattr(settings, name, default)
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def _now():
    return timezone.now()


def _normalize_prefix(prefix: Optional[str]) -> str:
    value = (prefix or "").strip("/")
    return f"{value}/" if value else ""


def _join_prefix(prefix: Optional[str], key: str) -> str:
    return f"{_normalize_prefix(prefix)}{(key or '').lstrip('/')}"


def _relative_key(key: str, prefix: Optional[str]) -> str:
    normalized = _normalize_prefix(prefix)
    if normalized and key.startswith(normalized):
        return key[len(normalized) :]
    return key


def _as_iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _safe_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _strip_etag(value: Any) -> str:
    return str(value or "").strip('"')


def _is_not_found(error: BaseException) -> bool:
    if isinstance(error, ClientError):
        code = str((error.response.get("Error") or {}).get("Code") or "")
        return code in {
            "404",
            "NoSuchKey",
            "NoSuchBucket",
            "NotFound",
            "NotFoundException",
            "NoSuchUpload",
        }
    return error.__class__.__name__ in {"NoSuchKey", "NotFound", "NoSuchBucket"}


def _version_listing_unsupported(error: BaseException) -> bool:
    if isinstance(error, (NotImplementedError, AttributeError)):
        return True
    if not isinstance(error, ClientError):
        return False
    code = str((error.response.get("Error") or {}).get("Code") or "")
    return code in {
        "NotImplemented",
        "NotImplementedException",
        "InvalidRequest",
        "MethodNotAllowed",
        "501",
    }


def _raw_object_entry(raw: Dict[str, Any], *, delete_marker: bool = False) -> Dict[str, Any]:
    """Normalize one S3 Version or DeleteMarker response item."""

    version_id = raw.get("VersionId") or ""
    # AWS represents the sole unversioned object as the literal string ``null``
    # in some Version APIs. Treat it as unversioned so we do not require a
    # versioned destination for a bucket that has no historical versions.
    if version_id == "null":
        version_id = ""
    return {
        "key": raw.get("Key") or "",
        "version_id": version_id,
        "is_delete_marker": bool(delete_marker),
        "etag": _strip_etag(raw.get("ETag")),
        "size": _safe_int(raw.get("Size")),
        "last_modified": raw.get("LastModified"),
        "last_modified_iso": _as_iso(raw.get("LastModified")),
        "storage_class": raw.get("StorageClass") or "",
        "is_latest": bool(raw.get("IsLatest", True)),
    }


def _entry_identity(entry: Dict[str, Any]) -> Tuple[str, str]:
    return str(entry.get("key") or ""), str(entry.get("version_id") or "")


def _entry_fingerprint(entry: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        bool(entry.get("is_delete_marker")),
        str(entry.get("etag") or ""),
        _safe_int(entry.get("size")),
        str(entry.get("last_modified_iso") or ""),
    )


def _append_unique_entry(
    entries: List[Dict[str, Any]],
    seen: Dict[Tuple[str, str], Tuple[Any, ...]],
    entry: Dict[str, Any],
):
    identity = _entry_identity(entry)
    fingerprint = _entry_fingerprint(entry)
    previous = seen.get(identity)
    if previous is not None:
        if previous != fingerprint:
            failure = _duplicate_match_failure()
            raise LightsailBucketReplicationError(
                failure.message,
                failure=failure,
            )
        return
    seen[identity] = fingerprint
    entries.append(entry)


def _invalid_pagination_error() -> LightsailBucketReplicationError:
    failure = _failure(
        "LIGHTSAIL_INVALID_RESPONSE",
        "The provider returned an invalid pagination cursor; replication stopped safely.",
        "invalid_response",
        False,
    )
    return LightsailBucketReplicationError(failure.message, failure=failure)


def _iter_current_object_pages(
    client,
    bucket_name: str,
    prefix: str = "",
    *,
    cursor_state: Optional[Dict[str, Any]] = None,
) -> Iterator[Tuple[List[Dict[str, Any]], Dict[str, Any]]]:
    """Yield one bounded current-object provider page and its following cursor."""

    state = dict(cursor_state or {})
    if state.get("kind") != "current":
        state = {}
    token = state.get("token") or None
    while True:
        page_entries: List[Dict[str, Any]] = []
        page_seen: Dict[Tuple[str, str], Tuple[Any, ...]] = {}
        kwargs: Dict[str, Any] = {"Bucket": bucket_name}
        if prefix:
            kwargs["Prefix"] = prefix
        if token:
            kwargs["ContinuationToken"] = token
        response = client.list_objects_v2(**kwargs)
        if not isinstance(response, dict):
            raise _invalid_pagination_error()
        for item in response.get("Contents") or []:
            if item.get("Key") is not None:
                entry = _raw_object_entry(item)
                _append_unique_entry(page_entries, page_seen, entry)
        if not response.get("IsTruncated"):
            yield page_entries, {}
            break
        next_token = response.get("NextContinuationToken")
        if not next_token or next_token == token:
            raise _invalid_pagination_error()
        token = next_token
        state = {"kind": "current", "token": str(token)}
        yield page_entries, dict(state)


def iter_source_object_pages(
    client,
    bucket_name: str,
    prefix: str = "",
    include_versions: bool = True,
    *,
    cursor_state: Optional[Dict[str, Any]] = None,
) -> Iterator[Tuple[List[Dict[str, Any]], Dict[str, Any]]]:
    """Yield normalized provider pages without retaining prior pages in memory.

    Version listing uses both ``Versions`` and ``DeleteMarkers`` from each S3 page,
    and paginates with the pair of key/version markers.  Providers that expose only
    the current-object API get an explicit fallback to ``list_objects_v2``; a
    different client error is surfaced so an unavailable bucket is not mistaken for
    an unversioned bucket.
    """

    normalized_prefix = _normalize_prefix(prefix)
    if not include_versions:
        yield from _iter_current_object_pages(
            client,
            bucket_name,
            normalized_prefix,
            cursor_state=cursor_state,
        )
        return

    state = dict(cursor_state or {})
    if state.get("kind") == "current":
        yield from _iter_current_object_pages(
            client,
            bucket_name,
            normalized_prefix,
            cursor_state=state,
        )
        return
    if state.get("kind") != "versions":
        state = {}
    key_marker = state.get("key_marker") or None
    version_id_marker = state.get("version_id_marker") or None
    emitted_page = False
    try:
        while True:
            kwargs: Dict[str, Any] = {"Bucket": bucket_name}
            if normalized_prefix:
                kwargs["Prefix"] = normalized_prefix
            if key_marker:
                kwargs["KeyMarker"] = key_marker
            if version_id_marker:
                kwargs["VersionIdMarker"] = version_id_marker
            response = client.list_object_versions(**kwargs)
            if not isinstance(response, dict):
                raise _invalid_pagination_error()
            page_entries: List[Dict[str, Any]] = []
            page_seen: Dict[Tuple[str, str], Tuple[Any, ...]] = {}
            for item in response.get("Versions") or []:
                if item.get("Key") is not None:
                    entry = _raw_object_entry(item)
                    _append_unique_entry(page_entries, page_seen, entry)
            for item in response.get("DeleteMarkers") or []:
                if item.get("Key") is not None:
                    entry = _raw_object_entry(item, delete_marker=True)
                    _append_unique_entry(page_entries, page_seen, entry)
            if not response.get("IsTruncated"):
                yield page_entries, {}
                break
            next_key = response.get("NextKeyMarker")
            next_version = response.get("NextVersionIdMarker")
            if not next_key and not next_version:
                raise _invalid_pagination_error()
            if (next_key, next_version) == (key_marker, version_id_marker):
                raise _invalid_pagination_error()
            key_marker, version_id_marker = next_key, next_version
            state = {
                "kind": "versions",
                "key_marker": str(key_marker or ""),
                "version_id_marker": str(version_id_marker or ""),
            }
            emitted_page = True
            yield page_entries, dict(state)
    except Exception as error:
        if not _version_listing_unsupported(error):
            raise
        if emitted_page or key_marker or version_id_marker:
            failure = _failure(
                "LIGHTSAIL_UNSUPPORTED",
                "The provider changed pagination capabilities during version listing; replication stopped safely.",
                "unsupported",
                False,
            )
            raise LightsailBucketReplicationError(failure.message, failure=failure) from error
        yield from _iter_current_object_pages(
            client,
            bucket_name,
            normalized_prefix,
            cursor_state={},
        )


def list_source_objects(
    client,
    bucket_name: str,
    prefix: str = "",
    include_versions: bool = True,
    *,
    cursor_state: Optional[Dict[str, Any]] = None,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    page_callback: Optional[Callable[[List[Dict[str, Any]], Dict[str, Any]], None]] = None,
) -> Iterator[Dict[str, Any]]:
    """Stream normalized entries while retaining the focused helper callbacks."""

    for page_entries, next_cursor in iter_source_object_pages(
        client,
        bucket_name,
        prefix,
        include_versions,
        cursor_state=cursor_state,
    ):
        if page_callback:
            page_callback(page_entries, dict(next_cursor))
        if cursor_state is not None:
            cursor_state.clear()
            cursor_state.update(next_cursor)
        if progress_callback:
            progress_callback(dict(next_cursor))
        yield from page_entries


def _source_version_kwargs(entry: Dict[str, Any]) -> Dict[str, Any]:
    version_id = entry.get("version_id")
    return {"VersionId": version_id} if version_id not in (None, "") else {}


def _read_at_most(body, maximum: int) -> bytes:
    """Read exactly up to maximum bytes from a boto3 StreamingBody-like object."""

    chunks = []
    total = 0
    while total < maximum:
        read = getattr(body, "read", None)
        if read is None:
            chunk = body[total:maximum]
        else:
            chunk = read(maximum - total)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _close_body(body):
    close = getattr(body, "close", None)
    if close:
        close()


def _object_identity_metadata(
    entry: Dict[str, Any], metadata_overrides: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    key = str(entry.get("key") or "")
    version_id = str(entry.get("version_id") or "unversioned")
    metadata = {
        "backupsheep-source-key-sha256": hashlib.sha256(key.encode("utf-8")).hexdigest(),
        "backupsheep-source-version": version_id,
        "backupsheep-source-delete-marker": "1" if entry.get("is_delete_marker") else "0",
    }
    if entry.get("etag"):
        metadata["backupsheep-source-etag"] = _strip_etag(entry["etag"])
    if metadata_overrides:
        metadata.update({str(k).lower(): str(v) for k, v in metadata_overrides.items()})
    return metadata


def _head_matches(
    client,
    bucket_name: str,
    destination_key: str,
    expected_metadata: Dict[str, str],
    source_etag: str = "",
    source_size: Optional[int] = None,
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    try:
        response = client.head_object(Bucket=bucket_name, Key=destination_key)
    except Exception as error:
        if _is_not_found(error):
            return False, None
        raise
    raw_metadata = response.get("Metadata") or {}
    metadata = {
        str(key).lower(): str(value)
        for key, value in raw_metadata.items()
    }
    if all(metadata.get(key.lower()) == str(value) for key, value in expected_metadata.items()):
        return True, response
    # Older rows may have been copied before identity metadata was introduced.  A
    # strong ETag+size match is still safe for a normal (single-part) source object,
    # but never override an explicit identity mismatch from a newer run.
    if any(key.lower() in metadata for key in expected_metadata):
        return False, response
    response_etag = _strip_etag(response.get("ETag"))
    if source_etag and response_etag == _strip_etag(source_etag):
        response_size = _safe_int(response.get("ContentLength"))
        if source_size is None or response_size == source_size:
            return True, response
    return False, response


def _destination_not_found(client, bucket_name: str, destination_key: str) -> bool:
    try:
        client.head_object(Bucket=bucket_name, Key=destination_key)
        return False
    except Exception as error:
        if _is_not_found(error):
            return True
        raise


def _response_items(response: Any, name: str) -> List[Dict[str, Any]]:
    if not isinstance(response, dict):
        return []
    items = response.get(name) or []
    return [item for item in items if isinstance(item, dict)]


def _find_multipart_upload(client, bucket_name: str, destination_key: str) -> Optional[str]:
    """Adopt one remote initiation after a lost CreateMultipartUpload response."""

    try:
        response = client.list_multipart_uploads(
            Bucket=bucket_name,
            Prefix=destination_key,
        )
    except Exception as error:
        if _version_listing_unsupported(error) or _is_not_found(error):
            return None
        raise
    matches = [
        item
        for item in _response_items(response, "Uploads")
        if str(item.get("Key") or "") == destination_key and item.get("UploadId")
    ]
    if len(matches) > 1:
        failure = _duplicate_match_failure()
        raise LightsailBucketReplicationError(failure.message, failure=failure)
    return str(matches[0]["UploadId"]) if matches else None


def _find_multipart_part(
    client,
    bucket_name: str,
    destination_key: str,
    upload_id: str,
    part_number: int,
) -> Optional[Dict[str, Any]]:
    """Adopt one remote part after a lost UploadPart response."""

    try:
        response = client.list_parts(
            Bucket=bucket_name,
            Key=destination_key,
            UploadId=upload_id,
        )
    except Exception as error:
        if _version_listing_unsupported(error) or _is_not_found(error):
            return None
        raise
    matches = [
        item
        for item in _response_items(response, "Parts")
        if _safe_int(item.get("PartNumber")) == int(part_number)
    ]
    if len(matches) > 1:
        failure = _duplicate_match_failure()
        raise LightsailBucketReplicationError(failure.message, failure=failure)
    if not matches:
        return None
    part = dict(matches[0])
    part["PartNumber"] = int(part_number)
    part["Size"] = _safe_int(part.get("Size")) or 0
    return part


def _current_delete_marker(client, bucket_name: str, destination_key: str):
    """Return one exact current delete marker, or fail closed on ambiguity."""

    try:
        response = client.list_object_versions(
            Bucket=bucket_name,
            Prefix=destination_key,
        )
    except Exception as error:
        if _version_listing_unsupported(error) or _is_not_found(error):
            return None
        raise
    matches = [
        item
        for item in _response_items(response, "DeleteMarkers")
        if str(item.get("Key") or "") == destination_key
        and item.get("IsLatest")
        and item.get("VersionId")
    ]
    if len(matches) > 1:
        failure = _duplicate_match_failure()
        raise LightsailBucketReplicationError(failure.message, failure=failure)
    return matches[0] if matches else None


def _call_progress_callback(
    callback: Optional[Callable[[Dict[str, Any]], None]], progress: Dict[str, Any]
):
    if callback:
        callback(progress)


def _multipart_copy(
    source_client,
    destination_client,
    source_bucket: str,
    destination_bucket: str,
    entry: Dict[str, Any],
    destination_key: str,
    part_size: int,
    metadata: Dict[str, str],
    multipart_progress: Optional[Dict[str, Any]] = None,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    heartbeat_callback: Optional[Callable[[], None]] = None,
) -> Dict[str, Any]:
    progress = multipart_progress if multipart_progress is not None else {}
    upload_id = progress.get("upload_id") or ""
    resuming = bool(upload_id)
    completed = {
        int(part.get("PartNumber")): dict(part)
        for part in (progress.get("completed_parts") or [])
        if isinstance(part, dict) and part.get("PartNumber") is not None
    }

    if not upload_id:
        try:
            upload_id = _find_multipart_upload(
                destination_client,
                destination_bucket,
                destination_key,
            ) or ""
        except Exception as error:
            # Listing active uploads is a best-effort preflight for providers that
            # do not grant that permission. A conflicting match is never ignored.
            if getattr(getattr(error, "failure", None), "code", "") == "LIGHTSAIL_DUPLICATE_MATCH":
                raise
            upload_id = ""
        if upload_id:
            resuming = True
        else:
            try:
                response = destination_client.create_multipart_upload(
                    Bucket=destination_bucket,
                    Key=destination_key,
                    Metadata=metadata,
                )
            except Exception as error:
                try:
                    upload_id = _find_multipart_upload(
                        destination_client,
                        destination_bucket,
                        destination_key,
                    ) or ""
                except Exception as reconcile_error:
                    raise _safe_failure_exception(
                        reconcile_error,
                        unknown_outcome=True,
                    ) from error
                if not upload_id:
                    raise _safe_failure_exception(error, unknown_outcome=True) from error
            else:
                upload_id = response.get("UploadId") or response.get("upload_id")
                if not upload_id:
                    failure = _failure(
                        "LIGHTSAIL_INVALID_RESPONSE",
                        "The provider did not return a multipart upload identifier.",
                        "invalid_response",
                        False,
                    )
                    raise LightsailBucketReplicationError(failure.message, failure=failure)
        progress["upload_id"] = upload_id
        progress["completed_parts"] = list(completed.values())
        _call_progress_callback(progress_callback, progress)

    source_response = source_client.get_object(
        Bucket=source_bucket,
        Key=entry["key"],
        **_source_version_kwargs(entry),
    )
    body = source_response.get("Body")
    if body is None:
        body = b""
    part_number = 1
    bytes_completed = sum(_safe_int(part.get("Size")) or 0 for part in completed.values())
    try:
        while True:
            chunk = _read_at_most(body, part_size)
            if not chunk:
                break
            if part_number not in completed:
                remote_part = None
                if resuming:
                    try:
                        remote_part = _find_multipart_part(
                            destination_client,
                            destination_bucket,
                            destination_key,
                            upload_id,
                            part_number,
                        )
                    except Exception as error:
                        raise _safe_failure_exception(error, unknown_outcome=True) from error
                if remote_part:
                    completed[part_number] = remote_part
                else:
                    try:
                        upload_response = destination_client.upload_part(
                            Bucket=destination_bucket,
                            Key=destination_key,
                            UploadId=upload_id,
                            PartNumber=part_number,
                            Body=chunk,
                        )
                    except Exception as error:
                        try:
                            remote_part = _find_multipart_part(
                                destination_client,
                                destination_bucket,
                                destination_key,
                                upload_id,
                                part_number,
                            )
                        except Exception as reconcile_error:
                            raise _safe_failure_exception(
                                reconcile_error,
                                unknown_outcome=True,
                            ) from error
                        if not remote_part:
                            raise _safe_failure_exception(error, unknown_outcome=True) from error
                        completed[part_number] = remote_part
                    else:
                        completed[part_number] = {
                            "PartNumber": part_number,
                            "ETag": upload_response.get("ETag")
                            or upload_response.get("etag")
                            or "",
                            "Size": len(chunk),
                        }
                bytes_completed += len(chunk)
                progress["completed_parts"] = [completed[number] for number in sorted(completed)]
                _call_progress_callback(progress_callback, progress)
            if heartbeat_callback:
                heartbeat_callback()
            part_number += 1
            if len(chunk) < part_size:
                break

        parts = [
            {
                key: value
                for key, value in part.items()
                if key in {"PartNumber", "ETag", "ChecksumCRC32", "ChecksumCRC32C", "ChecksumSHA1", "ChecksumSHA256"}
            }
            for _, part in sorted(completed.items())
        ]
        try:
            complete_response = destination_client.complete_multipart_upload(
                Bucket=destination_bucket,
                Key=destination_key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
        except Exception as error:
            # A worker can die after S3 committed CompleteMultipartUpload but before
            # the row was saved.  Verify the durable object before starting over.
            matched, head = _head_matches(
                destination_client,
                destination_bucket,
                destination_key,
                metadata,
                source_etag=entry.get("etag") or "",
                source_size=entry.get("size"),
            )
            if matched:
                complete_response = head or {}
            else:
                raise _safe_failure_exception(error, unknown_outcome=True) from error
    finally:
        _close_body(body)

    progress["completed_parts"] = [completed[number] for number in sorted(completed)]
    progress["completed_at"] = _as_iso(_now())
    _call_progress_callback(progress_callback, progress)
    destination_version_id = (
        complete_response.get("VersionId")
        or complete_response.get("version_id")
        or ""
    )
    return {
        "status": "complete",
        "skipped": False,
        "bytes_transferred": bytes_completed,
        "destination_version_id": destination_version_id,
        "multipart": progress,
    }


def copy_s3_object(
    source_client,
    destination_client,
    source_bucket: str,
    destination_bucket: str,
    entry: Dict[str, Any],
    destination_key: str,
    *,
    part_size: int = DEFAULT_PART_SIZE,
    multipart_progress: Optional[Dict[str, Any]] = None,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    heartbeat_callback: Optional[Callable[[], None]] = None,
    metadata_overrides: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Idempotently copy one source version, resuming multipart progress.

    ``multipart_progress`` and its callback are intentionally plain dictionaries;
    the database orchestration adapts them to CoreLightsailBucketReplicationMultipart
    while focused tests can retain the exact same resume behavior in memory.
    """

    expected_metadata = _object_identity_metadata(entry, metadata_overrides)
    if entry.get("is_delete_marker"):
        # A worker can die after DeleteObject commits. Reconcile the current
        # version before issuing another delete so versioned destinations do not
        # accumulate duplicate delete markers.
        marker = _current_delete_marker(
            destination_client,
            destination_bucket,
            destination_key,
        )
        if marker:
            return {
                "status": "delete_marker_applied",
                "skipped": True,
                "bytes_transferred": 0,
                "destination_version_id": marker.get("VersionId") or "",
            }
        if _destination_not_found(destination_client, destination_bucket, destination_key):
            return {
                "status": "delete_marker_applied",
                "skipped": True,
                "bytes_transferred": 0,
                "destination_version_id": "",
            }
        try:
            response = destination_client.delete_object(
                Bucket=destination_bucket,
                Key=destination_key,
            )
        except Exception as error:
            try:
                marker = _current_delete_marker(
                    destination_client,
                    destination_bucket,
                    destination_key,
                )
            except Exception as reconcile_error:
                raise _safe_failure_exception(
                    reconcile_error,
                    unknown_outcome=True,
                ) from error
            if marker:
                response = marker
            else:
                raise _safe_failure_exception(error, unknown_outcome=True) from error
        return {
            "status": "delete_marker_applied",
            "skipped": False,
            "bytes_transferred": 0,
            "destination_version_id": response.get("VersionId") or "",
        }

    matched, head = _head_matches(
        destination_client,
        destination_bucket,
        destination_key,
        expected_metadata,
        source_etag=entry.get("etag") or "",
        source_size=entry.get("size"),
    )
    if matched:
        return {
            "status": "skipped",
            "skipped": True,
            "bytes_transferred": 0,
            "destination_version_id": (head or {}).get("VersionId") or "",
        }

    size = entry.get("size")
    use_multipart = size is None or int(size) >= max(1, int(part_size))
    if use_multipart:
        return _multipart_copy(
            source_client,
            destination_client,
            source_bucket,
            destination_bucket,
            entry,
            destination_key,
            max(1, int(part_size)),
            expected_metadata,
            multipart_progress=multipart_progress,
            progress_callback=progress_callback,
            heartbeat_callback=heartbeat_callback,
        )

    source_response = source_client.get_object(
        Bucket=source_bucket,
        Key=entry["key"],
        **_source_version_kwargs(entry),
    )
    body = source_response.get("Body")
    if body is None:
        body = b""
    kwargs: Dict[str, Any] = {
        "Bucket": destination_bucket,
        "Key": destination_key,
        "Body": body,
        "Metadata": expected_metadata,
    }
    if size is not None:
        kwargs["ContentLength"] = int(size)
    if source_response.get("ContentType"):
        kwargs["ContentType"] = source_response["ContentType"]
    try:
        response = destination_client.put_object(**kwargs)
    except Exception as error:
        # PUT may have committed before its response was lost. A deterministic
        # metadata/ETag/size match is adopted; otherwise the next attempt receives
        # a durable unknown-outcome classification instead of blindly duplicating.
        try:
            matched, head = _head_matches(
                destination_client,
                destination_bucket,
                destination_key,
                expected_metadata,
                source_etag=entry.get("etag") or "",
                source_size=entry.get("size"),
            )
        except Exception as reconcile_error:
            raise _safe_failure_exception(
                reconcile_error,
                unknown_outcome=True,
            ) from error
        if matched:
            response = head or {}
        else:
            raise _safe_failure_exception(error, unknown_outcome=True) from error
    finally:
        _close_body(body)
    return {
        "status": "complete",
        "skipped": False,
        "bytes_transferred": int(size or source_response.get("ContentLength") or 0),
        "destination_version_id": response.get("VersionId") or "",
    }


def _endpoint_url(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return value if "://" in value else f"https://{value}"


def _validated_endpoint(value: Optional[str]) -> Optional[str]:
    endpoint = _endpoint_url(value)
    if not endpoint:
        return None
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise LightsailBucketReplicationError(
            "The configured provider endpoint is invalid."
        )
    if parsed.username or parsed.password:
        raise LightsailBucketReplicationError(
            "Provider credentials must not be embedded in an endpoint URL."
        )
    return endpoint


def _relation_endpoint(relation) -> Optional[str]:
    endpoint = getattr(relation, "endpoint", None)
    if endpoint:
        return _endpoint_url(endpoint)
    region = getattr(relation, "region", None)
    region_endpoint = getattr(region, "endpoint", None) if region else None
    return _endpoint_url(region_endpoint)


def _s3_client(
    *,
    access_key: str,
    secret_key: str,
    region_name: Optional[str] = None,
    endpoint_url: Optional[str] = None,
):
    kwargs: Dict[str, Any] = {
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
        "config": Config(
            signature_version="s3v4",
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
            retries={"max_attempts": 8, "mode": "standard"},
        ),
    }
    if region_name:
        kwargs["region_name"] = region_name
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    return bounded_boto3_client("s3", **kwargs)


def build_source_client(replication: CoreLightsailBucketReplication):
    """Build a boto3 S3 client from encrypted CoreAuthLightsail credentials."""

    connection = replication.source_connection
    try:
        auth = connection.auth_lightsail
    except Exception as error:
        raise LightsailBucketReplicationError(
            "source connection does not have CoreAuthLightsail credentials"
        ) from error
    account = connection.account
    key = account.get_encryption_key()
    access_key = bs_decrypt(auth.access_key, key)
    secret_key = bs_decrypt(auth.secret_key, key)
    if not access_key or not secret_key:
        raise LightsailBucketReplicationError(
            "source Lightsail credentials are missing or could not be decrypted"
        )
    region = getattr(getattr(auth, "region", None), "code", None)
    endpoint = _validated_endpoint(getattr(replication, "source_endpoint_url", None))
    return _s3_client(
        access_key=access_key,
        secret_key=secret_key,
        region_name=region,
        endpoint_url=endpoint,
    )


def build_destination_client(storage: CoreStorage):
    """Build an S3 client for a supported existing CoreStorage relation.

    The provider code is checked before any relation is touched.  This makes an
    unsupported provider fail clearly instead of accidentally using a similarly
    named credential field with the wrong SDK or endpoint semantics.
    """

    provider_code = getattr(getattr(storage, "type", None), "code", "")
    relation_name = S3_STORAGE_RELATIONS.get(provider_code)
    if not relation_name:
        raise UnsupportedStorageProvider(
            "The selected destination storage provider is not supported for Lightsail bucket replication."
        )
    try:
        relation = getattr(storage, relation_name)
    except Exception as error:
        raise UnsupportedStorageProvider(
            "The selected destination storage provider is missing its configured relation."
        ) from error
    account = storage.account
    key = account.get_encryption_key()
    access_key = bs_decrypt(relation.access_key, key)
    secret_key = bs_decrypt(relation.secret_key, key)
    if not access_key or not secret_key:
        raise LightsailBucketReplicationError(
            "The encrypted destination credentials are missing or could not be decrypted."
        )
    region = getattr(getattr(relation, "region", None), "code", None)
    if provider_code in {"cloudflare", "leviia"}:
        region = "auto"
    endpoint = None if provider_code == "aws_s3" else _relation_endpoint(relation)
    if provider_code == "filebase" and not endpoint:
        endpoint = "https://s3.filebase.io"
    if not endpoint and provider_code != "aws_s3":
        raise UnsupportedStorageProvider(
            "The selected destination storage provider has no usable S3 endpoint."
        )
    return _s3_client(
        access_key=access_key,
        secret_key=secret_key,
        region_name=region,
        endpoint_url=endpoint,
    )


def _destination_relation(storage):
    provider_code = getattr(getattr(storage, "type", None), "code", "")
    relation_name = S3_STORAGE_RELATIONS.get(provider_code)
    if not relation_name:
        # Reuse the same clear rejection text as client construction.
        build_destination_client(storage)
    try:
        return provider_code, getattr(storage, relation_name)
    except Exception as error:
        raise UnsupportedStorageProvider(
            "The selected destination storage provider is missing its configured relation."
        ) from error


def _validate_replication_scope(replication):
    """Reject cross-account or inactive rows before touching either provider."""

    source_connection = replication.source_connection
    destination_storage = replication.destination_storage
    if source_connection.account_id != replication.account_id:
        raise LightsailBucketReplicationError(
            "The Lightsail source connection must belong to the replication account."
        )
    if destination_storage.account_id != replication.account_id:
        raise LightsailBucketReplicationError(
            "The destination storage must belong to the replication account."
        )
    if getattr(source_connection.integration, "code", None) != "lightsail":
        raise LightsailBucketReplicationError(
            "The source connection must use the Lightsail integration."
        )
    if source_connection.status != source_connection.Status.ACTIVE:
        raise LightsailBucketReplicationError(
            "The Lightsail source connection is not active."
        )
    if destination_storage.status != destination_storage.Status.ACTIVE:
        raise LightsailBucketReplicationError(
            "The destination storage is not active."
        )
    _validated_endpoint(getattr(replication, "source_endpoint_url", None))


def _destination_bucket(storage) -> str:
    _, relation = _destination_relation(storage)
    bucket = getattr(relation, "bucket_name", None)
    if not bucket:
        raise LightsailBucketReplicationError("The destination storage bucket is not configured.")
    return bucket


def _destination_key(replication, source_key: str) -> str:
    relative = _relative_key(source_key, replication.source_prefix)
    return _join_prefix(replication.destination_prefix, relative)


def _manifest_key(replication, run) -> str:
    return _join_prefix(
        replication.destination_prefix,
        f"{MANIFEST_DIRECTORY}{run.uuid}.json",
    )


def _write_manifest(destination_client, destination_bucket, manifest_key, run, manifest):
    """Write one deterministic manifest without versioning it on retry."""

    metadata = {
        "backupsheep-manifest": "1",
        "backupsheep-run-id": str(run.uuid),
    }
    try:
        existing = destination_client.head_object(
            Bucket=destination_bucket,
            Key=manifest_key,
        )
        existing_metadata = {
            str(key).lower(): str(value)
            for key, value in (existing.get("Metadata") or {}).items()
        }
        if all(
            existing_metadata.get(key.lower()) == value
            for key, value in metadata.items()
        ):
            return
    except Exception as error:
        if not _is_not_found(error):
            raise
    body = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        destination_client.put_object(
            Bucket=destination_bucket,
            Key=manifest_key,
            Body=body,
            ContentType="application/json",
            Metadata=metadata,
        )
    except Exception as error:
        try:
            existing = destination_client.head_object(
                Bucket=destination_bucket,
                Key=manifest_key,
            )
            existing_metadata = {
                str(key).lower(): str(value)
                for key, value in (existing.get("Metadata") or {}).items()
            }
        except Exception as reconcile_error:
            raise _safe_failure_exception(
                reconcile_error,
                unknown_outcome=True,
            ) from error
        if not all(
            existing_metadata.get(key.lower()) == value
            for key, value in metadata.items()
        ):
            raise _safe_failure_exception(error, unknown_outcome=True) from error


def _require_versioned_destination(
    client,
    bucket_name: str,
    entries: Optional[Iterable[Dict[str, Any]]] = None,
    *,
    required: Optional[bool] = None,
):
    """Fail closed when source history cannot be represented by the destination.

    A plain S3 destination would overwrite older versions under the same key and
    would turn a source delete marker into a destructive delete. Requiring native
    destination versioning keeps the manifest and restore semantics lossless.
    """

    if required is None:
        required = any(
            entry.get("version_id") or entry.get("is_delete_marker")
            for entry in (entries or ())
        )
    if not required:
        return
    try:
        status = (client.get_bucket_versioning(Bucket=bucket_name) or {}).get("Status")
    except Exception as error:
        raise LightsailBucketReplicationError(
            "The destination must support S3 bucket versioning when the source has object versions or delete markers."
        ) from error
    if status != "Enabled":
        raise LightsailBucketReplicationError(
            "Enable versioning on the destination bucket before replicating source object history."
        )


def _run_owner(run, task_id: Optional[str] = None) -> str:
    return str(task_id or getattr(run, "celery_task_id", "") or run.uuid)


def _lease_seconds(replication) -> int:
    value = getattr(replication, "lease_seconds", None)
    return max(1, int(value or _setting_int("LIGHTSAIL_BUCKET_LEASE_SECONDS", DEFAULT_LEASE_SECONDS)))


def _claim_object_lease(object_id: int, owner: str, lease_seconds: int):
    """Atomically claim an object lease, returning a fresh state/token pair."""

    now = _now()
    with transaction.atomic():
        state = CoreLightsailBucketReplicationObject.objects.select_for_update().get(
            pk=object_id
        )
        try:
            lease = CoreLightsailBucketReplicationLease.objects.select_for_update().get(
                object_state_id=state.id
            )
        except CoreLightsailBucketReplicationLease.DoesNotExist:
            lease = CoreLightsailBucketReplicationLease(object_state=state)
        if lease_is_active(lease.expires_at, now):
            return None
        lease.owner = owner
        lease.token = uuid.uuid4()
        lease.acquired_at = now
        lease.heartbeat_at = now
        lease.expires_at = now + timedelta(seconds=lease_seconds)
        lease.attempt_count = int(lease.attempt_count or 0) + 1
        lease.save()
        state.status = CoreLightsailBucketReplicationObject.Status.COPYING
        state.attempt_count = int(state.attempt_count or 0) + 1
        state.error = ""
        state.save()
    return state, lease


def _heartbeat_object_lease(object_id: int, token, lease_seconds: int):
    now = _now()
    updated = CoreLightsailBucketReplicationLease.objects.filter(
        object_state_id=object_id,
        token=token,
        expires_at__gt=now,
    ).update(
        heartbeat_at=now,
        expires_at=now + timedelta(seconds=lease_seconds),
    )
    if not updated:
        raise LeaseLost(f"replication object lease {object_id} is no longer owned")


def _release_object_lease(object_id: int, token):
    CoreLightsailBucketReplicationLease.objects.filter(
        object_state_id=object_id,
        token=token,
    ).update(owner="", expires_at=None, heartbeat_at=_now())


def recover_stale_object_leases(replication_id: Optional[int] = None) -> int:
    """Release expired object leases without touching durable multipart progress."""

    now = _now()
    query = CoreLightsailBucketReplicationLease.objects.filter(expires_at__lte=now)
    if replication_id is not None:
        query = query.filter(object_state__run__replication_id=replication_id)
    recovered = 0
    chunk_size = _setting_int("BACKUP_RECOVERY_BATCH_SIZE", 100)
    for lease_id in query.order_by("id").values_list("id", flat=True).iterator(
        chunk_size=chunk_size
    ):
        with transaction.atomic():
            try:
                lease = CoreLightsailBucketReplicationLease.objects.select_for_update().get(
                    pk=lease_id
                )
            except CoreLightsailBucketReplicationLease.DoesNotExist:
                continue
            if not lease.expires_at or lease.expires_at > _now():
                continue
            state = lease.object_state
            recovery_failure = _failure(
                "LIGHTSAIL_LEASE_LOST",
                SAFE_FAILURE_MESSAGES["LIGHTSAIL_LEASE_LOST"],
                "lease_lost",
                True,
            )
            recovery_error = _failure_payload(recovery_failure)
            if state.status == CoreLightsailBucketReplicationObject.Status.COPYING:
                state.status = CoreLightsailBucketReplicationObject.Status.PENDING
                state.error = recovery_error
                state.save()
            lease.owner = ""
            lease.expires_at = None
            lease.last_error = recovery_error
            lease.save()
            recovered += 1
    return recovered


def _multipart_payload(multipart) -> Dict[str, Any]:
    return {
        "upload_id": multipart.upload_id or "",
        "completed_parts": list(multipart.completed_parts or []),
        "completed_at": _as_iso(multipart.completed_at),
    }


def _persist_multipart_progress(multipart, progress: Dict[str, Any]):
    multipart.upload_id = progress.get("upload_id") or ""
    multipart.completed_parts = list(progress.get("completed_parts") or [])
    completed_at = progress.get("completed_at")
    if completed_at and isinstance(completed_at, str):
        # The completion timestamp is informational; timezone.now avoids depending
        # on a parser for a provider-generated ISO representation.
        multipart.completed_at = _now()
    multipart.save()


def _get_or_create_object_state(run, replication, entry):
    version_id = entry.get("version_id") or ""
    is_delete_marker = bool(entry.get("is_delete_marker"))
    destination_key = _destination_key(replication, entry["key"])
    if CoreLightsailBucketReplicationObject.objects.filter(
        run=run,
        key=entry["key"],
        source_version_id=version_id,
    ).exclude(is_delete_marker=is_delete_marker).exists():
        failure = _duplicate_match_failure()
        raise LightsailBucketReplicationError(failure.message, failure=failure)
    defaults = {
        "source_etag": entry.get("etag") or "",
        "source_size": entry.get("size"),
        "source_last_modified": entry.get("last_modified"),
        "source_metadata": {
            "storage_class": entry.get("storage_class") or "",
            "last_modified": entry.get("last_modified_iso"),
        },
        "destination_key": destination_key,
    }
    try:
        state, created = CoreLightsailBucketReplicationObject.objects.get_or_create(
            run=run,
            key=entry["key"],
            source_version_id=version_id,
            is_delete_marker=is_delete_marker,
            defaults=defaults,
        )
    except IntegrityError:
        state = CoreLightsailBucketReplicationObject.objects.get(
            run=run,
            key=entry["key"],
            source_version_id=version_id,
            is_delete_marker=is_delete_marker,
        )
        created = False
    if not created:
        persisted_fingerprint = (
            _strip_etag(state.source_etag),
            _safe_int(state.source_size),
            _as_iso(state.source_last_modified),
            str(state.destination_key or ""),
        )
        incoming_fingerprint = (
            _strip_etag(defaults["source_etag"]),
            _safe_int(defaults["source_size"]),
            _as_iso(defaults["source_last_modified"]),
            str(defaults["destination_key"] or ""),
        )
        if persisted_fingerprint != incoming_fingerprint:
            failure = _duplicate_match_failure()
            raise LightsailBucketReplicationError(
                failure.message,
                failure=failure,
            )
    return state


def _state_terminal(state) -> bool:
    return state.status in {
        CoreLightsailBucketReplicationObject.Status.COMPLETE,
        CoreLightsailBucketReplicationObject.Status.SKIPPED,
        CoreLightsailBucketReplicationObject.Status.DELETE_MARKER_APPLIED,
    }


def _entry_from_object_state(state) -> Dict[str, Any]:
    metadata = state.source_metadata if isinstance(state.source_metadata, dict) else {}
    return {
        "key": state.key,
        "version_id": state.source_version_id,
        "is_delete_marker": bool(state.is_delete_marker),
        "etag": state.source_etag,
        "size": state.source_size,
        "last_modified": state.source_last_modified,
        "last_modified_iso": metadata.get("last_modified"),
        "storage_class": metadata.get("storage_class") or "",
    }


def _copy_object_state(replication, run, state, entry, source_client, destination_client, owner):
    claim = _claim_object_lease(state.id, owner, _lease_seconds(replication))
    if not claim:
        return {"status": "lease_busy", "skipped": True}
    claimed_state, lease = claim
    multipart = None
    progress_callback = None
    if not entry.get("is_delete_marker") and (
        entry.get("size") is None
        or int(entry.get("size") or 0) >= max(1, int(replication.part_size_bytes or DEFAULT_PART_SIZE))
    ):
        multipart, _ = CoreLightsailBucketReplicationMultipart.objects.get_or_create(
            object_state=claimed_state,
            defaults={
                "part_size_bytes": int(replication.part_size_bytes or DEFAULT_PART_SIZE),
                "source_size": entry.get("size"),
            },
        )
        progress = _multipart_payload(multipart)

        def persist(payload):
            _persist_multipart_progress(multipart, payload)

        progress_callback = persist
    else:
        progress = None

    def heartbeat():
        _heartbeat_object_lease(
            claimed_state.id,
            lease.token,
            _lease_seconds(replication),
        )
        CoreLightsailBucketReplicationRun.objects.filter(
            pk=run.id,
            status=CoreLightsailBucketReplicationRun.Status.RUNNING,
        ).update(modified=_now())

    try:
        result = copy_s3_object(
            source_client,
            destination_client,
            replication.source_bucket_name,
            _destination_bucket(replication.destination_storage),
            entry,
            claimed_state.destination_key,
            part_size=int(replication.part_size_bytes or DEFAULT_PART_SIZE),
            multipart_progress=progress,
            progress_callback=progress_callback,
            heartbeat_callback=heartbeat,
        )
        if not _lease_still_owned(claimed_state.id, lease.token):
            raise LeaseLost(f"replication object lease {claimed_state.id} was recovered")
        claimed_state.destination_version_id = result.get("destination_version_id") or ""
        claimed_state.bytes_transferred = int(result.get("bytes_transferred") or 0)
        if result.get("status") == "delete_marker_applied":
            claimed_state.status = (
                CoreLightsailBucketReplicationObject.Status.DELETE_MARKER_APPLIED
            )
        elif result.get("skipped"):
            claimed_state.status = CoreLightsailBucketReplicationObject.Status.SKIPPED
        else:
            claimed_state.status = CoreLightsailBucketReplicationObject.Status.COMPLETE
        claimed_state.error = ""
        claimed_state.save()
        return result
    except Exception as error:
        # A stale worker must not overwrite the row after recovery/reclaim.  The
        # token check includes the current (unexpired) ownership check here.
        if _lease_still_owned(claimed_state.id, lease.token):
            capture_exception(getattr(error, "__cause__", None) or error)
            failure = _failure_for(error)
            claimed_state.status = CoreLightsailBucketReplicationObject.Status.FAILED
            claimed_state.error = _failure_payload(failure)
            claimed_state.save()
        raise
    finally:
        _release_object_lease(claimed_state.id, lease.token)


def _lease_still_owned(object_id: int, token, allow_expired: bool = False) -> bool:
    query = CoreLightsailBucketReplicationLease.objects.filter(
        object_state_id=object_id, token=token
    )
    if not allow_expired:
        query = query.filter(expires_at__gt=_now())
    return query.exists()


def lease_is_active(expires_at, now=None) -> bool:
    """Return whether a persisted lease still blocks another worker."""

    return bool(expires_at and expires_at > (now or _now()))


def lease_is_stale(expires_at, now=None) -> bool:
    """Small pure predicate used by recovery code and focused unit tests."""

    return not lease_is_active(expires_at, now)


def _run_manifest(run, replication) -> Dict[str, Any]:
    return {
        "schema": 2,
        "run_id": str(run.uuid),
        "include_versions": bool(replication.include_versions),
        "object_count": int(run.object_count or 0),
        "completed_count": int(run.completed_count or 0),
        "failed_count": int(run.failed_count or 0),
        "delete_marker_count": int(run.delete_marker_count or 0),
        "bytes_transferred": int(run.bytes_transferred or 0),
    }


def _refresh_run_progress(run):
    states = run.object_states
    terminal_statuses = {
        CoreLightsailBucketReplicationObject.Status.COMPLETE,
        CoreLightsailBucketReplicationObject.Status.SKIPPED,
        CoreLightsailBucketReplicationObject.Status.DELETE_MARKER_APPLIED,
    }
    run.object_count = states.count()
    run.completed_count = states.filter(status__in=terminal_statuses).count()
    run.failed_count = states.filter(
        status=CoreLightsailBucketReplicationObject.Status.FAILED
    ).count()
    run.delete_marker_count = states.filter(is_delete_marker=True).count()
    run.bytes_transferred = int(
        states.aggregate(total=Sum("bytes_transferred")).get("total") or 0
    )


def _finalize_run(run, replication, destination_client, destination_bucket):
    _refresh_run_progress(run)
    unresolved = run.object_states.filter(
        status__in={
            CoreLightsailBucketReplicationObject.Status.PENDING,
            CoreLightsailBucketReplicationObject.Status.COPYING,
        }
    ).exists()
    failed = bool(run.failed_count)
    manifest = _run_manifest(run, replication)

    if unresolved:
        run.status = CoreLightsailBucketReplicationRun.Status.RUNNING
        run.save(
            update_fields=[
                "object_count",
                "completed_count",
                "failed_count",
                "delete_marker_count",
                "bytes_transferred",
                "status",
                "modified",
            ]
        )
        return _run_result(run)

    run.manifest = manifest
    manifest_key = _manifest_key(replication, run)
    _write_manifest(
        destination_client,
        destination_bucket,
        manifest_key,
        run,
        manifest,
    )
    run.manifest_key = manifest_key
    run.status = (
        CoreLightsailBucketReplicationRun.Status.FAILED
        if failed
        else CoreLightsailBucketReplicationRun.Status.COMPLETE
    )
    run.completed_at = _now()
    run.save()
    replication.last_run = run
    replication.save()
    return _run_result(run)


def _run_result(run) -> Dict[str, Any]:
    result = {
        "run_id": run.id,
        "run_uuid": str(run.uuid),
        "status": run.status,
        "object_count": int(run.object_count or 0),
        "completed_count": int(run.completed_count or 0),
        "failed_count": int(run.failed_count or 0),
        "bytes_transferred": int(run.bytes_transferred or 0),
    }
    if run.error:
        result["error"] = safe_failure_details(run.error, fallback_correlation_id=str(run.uuid))
    return result


def _get_or_create_run(replication, idempotency_key: str, celery_task_id: str = ""):
    defaults = {
        "celery_task_id": celery_task_id,
        "status": CoreLightsailBucketReplicationRun.Status.PENDING,
    }
    try:
        run, _ = CoreLightsailBucketReplicationRun.objects.get_or_create(
            replication=replication,
            idempotency_key=idempotency_key,
            defaults=defaults,
        )
    except IntegrityError:
        run = CoreLightsailBucketReplicationRun.objects.get(
            replication=replication,
            idempotency_key=idempotency_key,
        )
    return run


def _record_replication_failure(
    replication_id: int,
    error: BaseException,
    *,
    run_id: Optional[int] = None,
    idempotency_key: Optional[str] = None,
    celery_task_id: Optional[str] = None,
):
    capture_exception(getattr(error, "__cause__", None) or error)
    failure = _failure_for(error)
    query = CoreLightsailBucketReplicationRun.objects.filter(
        replication_id=replication_id,
        status__in=(
            CoreLightsailBucketReplicationRun.Status.PENDING,
            CoreLightsailBucketReplicationRun.Status.RUNNING,
        ),
    )
    if run_id:
        query = query.filter(pk=run_id)
    elif idempotency_key:
        query = query.filter(idempotency_key=idempotency_key)
    elif celery_task_id:
        query = query.filter(celery_task_id=celery_task_id)
    else:
        latest = query.order_by("-modified").first()
        if latest is None:
            return failure
        query = query.filter(pk=latest.pk)
    update = {
        "status": (
            CoreLightsailBucketReplicationRun.Status.RUNNING
            if failure.retryable
            else CoreLightsailBucketReplicationRun.Status.FAILED
        ),
        "error": _failure_payload(failure),
        "completed_at": None if failure.retryable else _now(),
    }
    query.update(**update)
    return failure


def _recovery_due(row, now, stale_seconds: int) -> bool:
    """Use provider Retry-After when available, otherwise the crash stale window."""

    age = max(0, int((now - row.modified).total_seconds()))
    if row.error:
        details = safe_failure_details(row.error, fallback_correlation_id=str(row.uuid))
        retry_after = _safe_int(details.get("retry_after_seconds"))
        if details.get("retryable") and retry_after is not None:
            return age >= max(1, retry_after)
    return age >= max(1, int(stale_seconds))


def _run_lightsail_bucket_replication(
    replication_id: int,
    *,
    run_id: Optional[int] = None,
    idempotency_key: Optional[str] = None,
    celery_task_id: str = "",
    source_client=None,
    destination_client=None,
) -> Dict[str, Any]:
    """Run/resume a definition; exposed separately for management/API integration."""

    replication = CoreLightsailBucketReplication.objects.select_related(
        "source_connection", "destination_storage"
    ).get(pk=replication_id)
    if not replication.enabled or replication.status != replication.Status.ACTIVE:
        return {"status": "disabled", "replication_id": replication.id}
    _validate_replication_scope(replication)
    if run_id is not None:
        run = CoreLightsailBucketReplicationRun.objects.get(
            pk=run_id, replication_id=replication.id
        )
    else:
        key = idempotency_key or celery_task_id or f"manual:{uuid.uuid4()}"
        run = _get_or_create_run(replication, key, celery_task_id)
    if run.status == CoreLightsailBucketReplicationRun.Status.COMPLETE:
        return _run_result(run)
    if not run.started_at:
        run.started_at = _now()
    run.status = CoreLightsailBucketReplicationRun.Status.RUNNING
    if celery_task_id and not run.celery_task_id:
        run.celery_task_id = celery_task_id
    run.error = ""
    run.save()
    replication.last_run = run
    replication.save()

    recover_stale_object_leases(replication.id)
    source_client = source_client or build_source_client(replication)
    destination_client = destination_client or build_destination_client(
        replication.destination_storage
    )
    destination_bucket = _destination_bucket(replication.destination_storage)
    if not _listing_is_complete(run):
        cursor_state = _load_listing_cursor(run, replication)
        expected_cursor = dict(cursor_state)
        for page_entries, next_cursor in iter_source_object_pages(
            source_client,
            replication.source_bucket_name,
            _normalize_prefix(replication.source_prefix),
            bool(replication.include_versions),
            cursor_state=cursor_state,
        ):
            # The page rows and the cursor that follows them are one commit. A
            # competing redelivery may issue the same read, but only the worker
            # whose expected cursor still matches may advance durable inventory.
            with transaction.atomic():
                checkpoint = CoreLightsailBucketReplicationRun.objects.select_for_update().get(
                    pk=run.id
                )
                current_cursor = _load_listing_cursor(checkpoint, replication)
                if _listing_is_complete(checkpoint) or current_cursor != expected_cursor:
                    run = checkpoint
                    break
                for entry in page_entries:
                    _get_or_create_object_state(checkpoint, replication, entry)
                _persist_listing_cursor(checkpoint, replication, next_cursor)
                run = checkpoint
            expected_cursor = dict(next_cursor)
        run.refresh_from_db()
        if not _listing_is_complete(run):
            _refresh_run_progress(run)
            run.status = CoreLightsailBucketReplicationRun.Status.RUNNING
            run.save(
                update_fields=[
                    "object_count",
                    "completed_count",
                    "failed_count",
                    "delete_marker_count",
                    "bytes_transferred",
                    "status",
                    "modified",
                ]
            )
            return _run_result(run)

    if replication.include_versions:
        requires_versioning = (
            run.object_states.exclude(source_version_id="").exists()
            or run.object_states.filter(is_delete_marker=True).exists()
        )
        _require_versioned_destination(
            destination_client,
            destination_bucket,
            required=requires_versioning,
        )
    owner = _run_owner(run, celery_task_id)
    failure: Optional[LightsailFailure] = None
    lease_busy = False
    chunk_size = _setting_int("LIGHTSAIL_BUCKET_OBJECT_CHUNK_SIZE", 500)
    states = run.object_states.order_by(
        "key",
        "source_last_modified",
        "source_version_id",
        "is_delete_marker",
        "id",
    )
    for state in states.iterator(chunk_size=chunk_size):
        if _state_terminal(state):
            continue
        entry = _entry_from_object_state(state)
        # Keep the run's liveness timestamp current while a large bucket is being
        # walked.  Recovery uses this timestamp to distinguish an active worker
        # from a process that disappeared between object transfers.
        CoreLightsailBucketReplicationRun.objects.filter(
            pk=run.id,
            status=CoreLightsailBucketReplicationRun.Status.RUNNING,
        ).update(modified=_now())
        try:
            result = _copy_object_state(
                replication,
                run,
                state,
                entry,
                source_client,
                destination_client,
                owner,
            )
            if result.get("status") == "lease_busy":
                lease_busy = True
                break
        except Exception as error:
            capture_exception(getattr(error, "__cause__", None) or error)
            failure = _failure_for(error)
            # Versions for one key must reach the destination oldest-first. Stop
            # on the first failed transfer so a later version cannot become current
            # before its predecessor has been durably reconciled.
            break

    if failure:
        _refresh_run_progress(run)
        run.error = _failure_payload(failure)
        run.status = (
            CoreLightsailBucketReplicationRun.Status.RUNNING
            if failure.retryable
            else CoreLightsailBucketReplicationRun.Status.FAILED
        )
        run.completed_at = None if run.status == CoreLightsailBucketReplicationRun.Status.RUNNING else _now()
        run.save()
        return _run_result(run)
    if lease_busy:
        _refresh_run_progress(run)
        run.status = CoreLightsailBucketReplicationRun.Status.RUNNING
        run.save()
        return _run_result(run)
    return _finalize_run(run, replication, destination_client, destination_bucket)


def run_lightsail_bucket_replication(
    replication_id: int,
    *,
    run_id: Optional[int] = None,
    idempotency_key: Optional[str] = None,
    celery_task_id: str = "",
    source_client=None,
    destination_client=None,
) -> Dict[str, Any]:
    """Run/resume a definition while converting top-level failures to safe state."""

    try:
        return _run_lightsail_bucket_replication(
            replication_id,
            run_id=run_id,
            idempotency_key=idempotency_key,
            celery_task_id=celery_task_id,
            source_client=source_client,
            destination_client=destination_client,
        )
    except Exception as error:
        _record_replication_failure(
            replication_id,
            error,
            run_id=run_id,
            idempotency_key=idempotency_key,
            celery_task_id=celery_task_id,
        )
        raise


@current_app.task(
    name="replicate_lightsail_bucket",
    bind=True,
    track_started=True,
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=4,
)
def replicate_lightsail_bucket(
    self,
    replication_id: int,
    run_id: Optional[int] = None,
    idempotency_key: Optional[str] = None,
):
    task_id = str(getattr(getattr(self, "request", None), "id", "") or "")
    try:
        return run_lightsail_bucket_replication(
            replication_id,
            run_id=run_id,
            idempotency_key=idempotency_key,
            celery_task_id=task_id,
        )
    except Exception as error:
        # Leave all object/multipart rows intact.  Late acknowledgement and a
        # follow-up invocation can resume them. Terminal provider failures are
        # marked failed; retryable/transient failures remain RUNNING for recovery.
        _record_replication_failure(
            replication_id,
            error,
            run_id=run_id,
            idempotency_key=idempotency_key,
            celery_task_id=task_id,
        )
        raise


@current_app.task(
    name="recover_stale_lightsail_bucket_leases",
    bind=True,
    track_started=True,
)
def recover_stale_lightsail_bucket_leases(self, replication_id: Optional[int] = None):
    return {
        "replication_id": replication_id,
        "recovered": recover_stale_object_leases(replication_id),
    }


def _claim_restore_lease(restore_run, owner: str, lease_seconds: int):
    now = _now()
    with transaction.atomic():
        row = CoreLightsailBucketRestoreRun.objects.select_for_update().get(
            pk=restore_run.id
        )
        if row.lease_expires_at and row.lease_expires_at > now and row.lease_owner != owner:
            return None
        row.lease_owner = owner
        row.lease_token = uuid.uuid4()
        row.lease_expires_at = now + timedelta(seconds=lease_seconds)
        row.status = CoreLightsailBucketRestoreRun.Status.RUNNING
        row.started_at = row.started_at or now
        row.save()
    return row


def _heartbeat_restore_lease(restore_run, owner: str, token, lease_seconds: int):
    updated = CoreLightsailBucketRestoreRun.objects.filter(
        pk=restore_run.id,
        lease_owner=owner,
        lease_token=token,
        lease_expires_at__gt=_now(),
    ).update(lease_expires_at=_now() + timedelta(seconds=lease_seconds))
    if not updated:
        raise LeaseLost(f"restore run lease {restore_run.id} is no longer owned")


def _release_restore_lease(restore_run, owner: str, token):
    CoreLightsailBucketRestoreRun.objects.filter(
        pk=restore_run.id,
        lease_owner=owner,
        lease_token=token,
    ).update(lease_owner="", lease_expires_at=None)


def _restore_lease_still_owned(restore_run, owner: str, token) -> bool:
    return CoreLightsailBucketRestoreRun.objects.filter(
        pk=restore_run.id,
        lease_owner=owner,
        lease_token=token,
        lease_expires_at__gt=_now(),
    ).exists()


def _raise_restore_duplicate_match():
    failure = _duplicate_match_failure()
    raise LightsailBucketReplicationError(failure.message, failure=failure)


def _verify_exact_restore_delete_marker(
    client,
    bucket_name: str,
    key: str,
    version_id: str,
    last_modified: Any,
):
    matches = 0
    for page_entries, _next_cursor in iter_source_object_pages(
        client,
        bucket_name,
        key,
        True,
    ):
        for entry in page_entries:
            if (
                entry.get("key") == key
                and entry.get("version_id") == version_id
                and entry.get("is_delete_marker")
            ):
                if _as_iso(entry.get("last_modified")) != _as_iso(last_modified):
                    _raise_restore_duplicate_match()
                matches += 1
                if matches > 1:
                    _raise_restore_duplicate_match()
    if matches != 1:
        failure = _failure(
            "LIGHTSAIL_NOT_FOUND",
            SAFE_FAILURE_MESSAGES["LIGHTSAIL_NOT_FOUND"],
            "not_found",
            False,
        )
        raise LightsailBucketReplicationError(failure.message, failure=failure)


def _verify_restore_backup_object(
    client,
    bucket_name: str,
    *,
    backup_key: str,
    backup_version_id: str,
    is_delete_marker: bool,
    backup_etag: str,
    backup_size: Optional[int],
    backup_last_modified: Any,
    source_key: str,
    source_version_id: str,
    source_etag: str,
) -> Optional[Dict[str, Any]]:
    if is_delete_marker:
        _verify_exact_restore_delete_marker(
            client,
            bucket_name,
            backup_key,
            backup_version_id,
            backup_last_modified,
        )
        return None

    kwargs: Dict[str, Any] = {"Bucket": bucket_name, "Key": backup_key}
    if backup_version_id:
        kwargs["VersionId"] = backup_version_id
    response = client.head_object(**kwargs)
    if not isinstance(response, dict):
        failure = _failure(
            "LIGHTSAIL_INVALID_RESPONSE",
            SAFE_FAILURE_MESSAGES["LIGHTSAIL_INVALID_RESPONSE"],
            "invalid_response",
            False,
        )
        raise LightsailBucketReplicationError(failure.message, failure=failure)
    response_version = str(response.get("VersionId") or "")
    if backup_version_id and response_version and response_version != backup_version_id:
        _raise_restore_duplicate_match()
    if backup_etag and _strip_etag(response.get("ETag")) != _strip_etag(backup_etag):
        _raise_restore_duplicate_match()
    if _safe_int(response.get("ContentLength")) != _safe_int(backup_size):
        _raise_restore_duplicate_match()
    if _as_iso(response.get("LastModified")) != _as_iso(backup_last_modified):
        _raise_restore_duplicate_match()

    expected_metadata = _object_identity_metadata(
        {
            "key": source_key,
            "version_id": source_version_id,
            "is_delete_marker": False,
            "etag": source_etag,
        }
    )
    actual_metadata = {
        str(key).lower(): str(value)
        for key, value in (response.get("Metadata") or {}).items()
    }
    if not all(
        actual_metadata.get(key.lower()) == str(value)
        for key, value in expected_metadata.items()
    ):
        _raise_restore_duplicate_match()
    return response


def restore_s3_object(
    destination_client,
    source_client,
    destination_bucket: str,
    source_bucket: str,
    destination_key: str,
    source_key: str,
    *,
    restore_id: str,
    backup_version_id: str = "",
    is_delete_marker: bool = False,
    backup_etag: str = "",
    backup_size: Optional[int] = None,
    backup_last_modified: Any = None,
    original_source_key: str = "",
    original_source_version_id: str = "",
    original_source_etag: str = "",
    heartbeat_callback: Optional[Callable[[], None]] = None,
) -> Dict[str, Any]:
    """Restore one exact, ownership-verified backup version idempotently."""

    source_head = _verify_restore_backup_object(
        destination_client,
        destination_bucket,
        backup_key=destination_key,
        backup_version_id=backup_version_id,
        is_delete_marker=is_delete_marker,
        backup_etag=backup_etag,
        backup_size=backup_size,
        backup_last_modified=backup_last_modified,
        source_key=original_source_key,
        source_version_id=original_source_version_id,
        source_etag=original_source_etag,
    )
    entry = {
        "key": destination_key,
        "version_id": backup_version_id,
        "is_delete_marker": bool(is_delete_marker),
        "etag": _strip_etag((source_head or {}).get("ETag")),
        "size": _safe_int((source_head or {}).get("ContentLength")),
    }
    # The restore identity is distinct from replication identity: a later restore
    # intentionally overwrites a source object when its restore id differs.
    overrides = {
        "backupsheep-restore-id": restore_id,
        "backupsheep-restore-source-key": hashlib.sha256(
            destination_key.encode("utf-8")
        ).hexdigest(),
    }
    return copy_s3_object(
        destination_client,
        source_client,
        destination_bucket,
        source_bucket,
        entry,
        source_key,
        part_size=DEFAULT_PART_SIZE,
        metadata_overrides=overrides,
        heartbeat_callback=heartbeat_callback,
    )


def _get_or_create_restore_run(
    replication,
    idempotency_key: str,
    source_run_id: Optional[int],
    restore_prefix: str,
    target_prefix: str,
    celery_task_id: str,
):
    defaults = {
        "source_run_id": source_run_id,
        "restore_prefix": restore_prefix,
        "target_prefix": target_prefix,
        "destination_prefix": _join_prefix(replication.destination_prefix, restore_prefix),
        "celery_task_id": celery_task_id,
    }
    try:
        row, created = CoreLightsailBucketRestoreRun.objects.get_or_create(
            replication=replication,
            idempotency_key=idempotency_key,
            defaults=defaults,
        )
    except IntegrityError:
        row = CoreLightsailBucketRestoreRun.objects.get(
            replication=replication,
            idempotency_key=idempotency_key,
        )
        created = False
    if not created:
        existing = (
            row.source_run_id,
            row.restore_prefix,
            row.target_prefix,
            row.destination_prefix,
        )
        requested = (
            source_run_id,
            restore_prefix,
            target_prefix,
            defaults["destination_prefix"],
        )
        if existing != requested:
            _raise_restore_duplicate_match()
    return row


def _source_object_for_restore(source_run, entry):
    expected_statuses = (
        {CoreLightsailBucketReplicationObject.Status.DELETE_MARKER_APPLIED}
        if entry.get("is_delete_marker")
        else {
            CoreLightsailBucketReplicationObject.Status.COMPLETE,
            CoreLightsailBucketReplicationObject.Status.SKIPPED,
        }
    )
    matches = list(
        source_run.object_states.filter(
            destination_key=entry.get("key") or "",
            destination_version_id=entry.get("version_id") or "",
            is_delete_marker=bool(entry.get("is_delete_marker")),
            status__in=expected_statuses,
        ).order_by("id")[:2]
    )
    if len(matches) != 1:
        _raise_restore_duplicate_match()
    return matches[0]


def _prepare_restore_object(
    replication,
    source_run,
    entry: Dict[str, Any],
    destination_client,
    destination_bucket: str,
    destination_prefix: str,
    target_prefix: str,
) -> Dict[str, Any]:
    source_state = _source_object_for_restore(source_run, entry)
    if _destination_key(replication, source_state.key) != entry.get("key"):
        _raise_restore_duplicate_match()

    backup_etag = entry.get("etag") or ""
    backup_size = entry.get("size")
    backup_last_modified = entry.get("last_modified")
    if not entry.get("is_delete_marker"):
        head = _verify_restore_backup_object(
            destination_client,
            destination_bucket,
            backup_key=entry.get("key") or "",
            backup_version_id=entry.get("version_id") or "",
            is_delete_marker=False,
            backup_etag=backup_etag,
            backup_size=backup_size,
            backup_last_modified=backup_last_modified,
            source_key=source_state.key,
            source_version_id=source_state.source_version_id,
            source_etag=source_state.source_etag,
        )
        backup_etag = _strip_etag((head or {}).get("ETag"))
        backup_size = _safe_int((head or {}).get("ContentLength"))
        backup_last_modified = (head or {}).get("LastModified")

    relative = _relative_key(entry.get("key") or "", destination_prefix)
    return {
        "source_object": source_state,
        "backup_version_id": entry.get("version_id") or "",
        "is_delete_marker": bool(entry.get("is_delete_marker")),
        "backup_etag": backup_etag,
        "backup_size": backup_size,
        "backup_last_modified": backup_last_modified,
        "_source_key": source_state.key,
        "source_version_id": source_state.source_version_id,
        "source_etag": source_state.source_etag,
        "_target_key": _join_prefix(target_prefix, relative),
    }


def _get_or_create_restore_object_state(
    restore_run,
    replication,
    backup_key: str,
    defaults,
):
    source_key = defaults.get("_source_key") or ""
    target_key = defaults.get("_target_key") or ""
    backup_key_hash = _restore_key_hash(backup_key)
    target_key_hash = _restore_key_hash(target_key)
    if CoreLightsailBucketRestoreObject.objects.filter(
        restore_run=restore_run,
        target_key_hash=target_key_hash,
    ).exclude(backup_key_hash=backup_key_hash).exists():
        _raise_restore_duplicate_match()
    persisted_defaults = {
        key: value for key, value in defaults.items() if not key.startswith("_")
    }
    persisted_defaults.update(
        {
            "backup_key_encrypted": _encrypt_restore_key(
                backup_key,
                replication.account,
            ),
            "source_key_hash": _restore_key_hash(source_key),
            "source_key_encrypted": _encrypt_restore_key(
                source_key,
                replication.account,
            ),
            "target_key_hash": target_key_hash,
            "target_key_encrypted": _encrypt_restore_key(
                target_key,
                replication.account,
            ),
        }
    )
    try:
        state, created = CoreLightsailBucketRestoreObject.objects.get_or_create(
            restore_run=restore_run,
            backup_key_hash=backup_key_hash,
            defaults=persisted_defaults,
        )
    except IntegrityError:
        try:
            state = CoreLightsailBucketRestoreObject.objects.get(
                restore_run=restore_run,
                backup_key_hash=backup_key_hash,
            )
        except CoreLightsailBucketRestoreObject.DoesNotExist:
            _raise_restore_duplicate_match()
        created = False
    if not created:
        persisted_backup_key = _decrypt_restore_key(
            state.backup_key_encrypted,
            replication.account,
        )
        persisted_source_key = _decrypt_restore_key(
            state.source_key_encrypted,
            replication.account,
        )
        persisted_target_key = _decrypt_restore_key(
            state.target_key_encrypted,
            replication.account,
        )
        persisted_fingerprint = (
            state.source_object_id,
            persisted_backup_key,
            state.backup_version_id,
            bool(state.is_delete_marker),
            _strip_etag(state.backup_etag),
            _safe_int(state.backup_size),
            _as_iso(state.backup_last_modified),
            persisted_source_key,
            state.source_version_id,
            _strip_etag(state.source_etag),
            persisted_target_key,
        )
        incoming_fingerprint = (
            getattr(defaults.get("source_object"), "id", None),
            backup_key,
            defaults.get("backup_version_id") or "",
            bool(defaults.get("is_delete_marker")),
            _strip_etag(defaults.get("backup_etag")),
            _safe_int(defaults.get("backup_size")),
            _as_iso(defaults.get("backup_last_modified")),
            source_key,
            defaults.get("source_version_id") or "",
            _strip_etag(defaults.get("source_etag")),
            target_key,
        )
        if persisted_fingerprint != incoming_fingerprint:
            _raise_restore_duplicate_match()
    return state


def _refresh_restore_progress(row):
    states = row.object_states
    row.object_count = states.count()
    row.completed_count = states.filter(
        status=CoreLightsailBucketRestoreObject.Status.COMPLETE
    ).count()
    row.skipped_count = states.filter(
        status=CoreLightsailBucketRestoreObject.Status.SKIPPED
    ).count()
    row.failed_count = states.filter(
        status=CoreLightsailBucketRestoreObject.Status.FAILED
    ).count()
    row.bytes_restored = int(
        states.aggregate(total=Sum("bytes_restored")).get("total") or 0
    )


def _restore_manifest(row) -> Dict[str, Any]:
    return {
        "schema": 2,
        "restore_id": str(row.uuid),
        "_listing_complete": True,
        "object_count": int(row.object_count or 0),
        "completed_count": int(row.completed_count or 0),
        "skipped_count": int(row.skipped_count or 0),
        "failed_count": int(row.failed_count or 0),
        "bytes_restored": int(row.bytes_restored or 0),
    }


def _restore_result(row) -> Dict[str, Any]:
    result = {
        "restore_id": row.id,
        "restore_uuid": str(row.uuid),
        "status": row.status,
        "object_count": int(row.object_count or 0),
        "completed_count": int(row.completed_count or 0),
        "skipped_count": int(row.skipped_count or 0),
        "failed_count": int(row.failed_count or 0),
        "bytes_restored": int(row.bytes_restored or 0),
    }
    if row.error:
        result["error"] = safe_failure_details(
            row.error,
            fallback_correlation_id=str(row.uuid),
        )
    return result


def _record_restore_failure(
    replication_id: int,
    error: BaseException,
    *,
    restore_id: Optional[int] = None,
    idempotency_key: Optional[str] = None,
    celery_task_id: Optional[str] = None,
):
    capture_exception(getattr(error, "__cause__", None) or error)
    failure = _failure_for(error)
    query = CoreLightsailBucketRestoreRun.objects.filter(
        replication_id=replication_id,
        status__in=(
            CoreLightsailBucketRestoreRun.Status.PENDING,
            CoreLightsailBucketRestoreRun.Status.RUNNING,
        ),
    )
    if restore_id:
        query = query.filter(pk=restore_id)
    elif idempotency_key:
        query = query.filter(idempotency_key=idempotency_key)
    elif celery_task_id:
        query = query.filter(celery_task_id=celery_task_id)
    else:
        latest = query.order_by("-modified").first()
        if latest is None:
            return failure
        query = query.filter(pk=latest.pk)
    query.update(
        status=(
            CoreLightsailBucketRestoreRun.Status.RUNNING
            if failure.retryable
            else CoreLightsailBucketRestoreRun.Status.FAILED
        ),
        error=_failure_payload(failure),
        completed_at=None if failure.retryable else _now(),
    )
    return failure


def _run_lightsail_bucket_prefix_restore(
    replication_id: int,
    *,
    restore_id: Optional[int] = None,
    source_run_id: Optional[int] = None,
    restore_prefix: str = "",
    target_prefix: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    celery_task_id: str = "",
    source_client=None,
    destination_client=None,
) -> Dict[str, Any]:
    """Restore a destination prefix to Lightsail, safely resumable/idempotent."""

    replication = CoreLightsailBucketReplication.objects.select_related(
        "source_connection", "destination_storage", "last_run"
    ).get(pk=replication_id)
    _validate_replication_scope(replication)
    if restore_id is not None:
        row = CoreLightsailBucketRestoreRun.objects.select_related("source_run").get(
            pk=restore_id, replication_id=replication.id
        )
        if source_run_id is not None and row.source_run_id != source_run_id:
            _raise_restore_duplicate_match()
        normalized_restore_prefix = row.restore_prefix
        normalized_target_prefix = row.target_prefix
    else:
        normalized_restore_prefix = _normalize_prefix(restore_prefix)
        if target_prefix is None:
            normalized_target_prefix = _join_prefix(
                replication.source_prefix,
                _relative_key(normalized_restore_prefix, ""),
            )
        else:
            normalized_target_prefix = _normalize_prefix(target_prefix)
        effective_source_run_id = source_run_id or replication.last_run_id
        if effective_source_run_id is None:
            failure = _failure(
                "LIGHTSAIL_STATE_CORRUPT",
                "A completed replication inventory is required before restore.",
                "state_corrupt",
                False,
            )
            raise LightsailBucketReplicationError(failure.message, failure=failure)
        key = idempotency_key or celery_task_id or f"manual-restore:{uuid.uuid4()}"
        row = _get_or_create_restore_run(
            replication,
            key,
            effective_source_run_id,
            normalized_restore_prefix,
            normalized_target_prefix,
            celery_task_id,
        )
        row = CoreLightsailBucketRestoreRun.objects.select_related("source_run").get(
            pk=row.id
        )
    source_run = row.source_run
    if (
        source_run is None
        or source_run.replication_id != replication.id
        or source_run.status
        not in {
            CoreLightsailBucketReplicationRun.Status.COMPLETE,
            CoreLightsailBucketReplicationRun.Status.FAILED,
        }
    ):
        failure = _failure(
            "LIGHTSAIL_STATE_CORRUPT",
            "A completed replication inventory is required before restore.",
            "state_corrupt",
            False,
        )
        raise LightsailBucketReplicationError(failure.message, failure=failure)
    if row.status == CoreLightsailBucketRestoreRun.Status.COMPLETE:
        return _restore_result(row)
    owner = celery_task_id or str(row.uuid)
    claimed = _claim_restore_lease(row, owner, _lease_seconds(replication))
    if not claimed:
        return _restore_result(row)
    row = claimed
    token = row.lease_token
    try:
        source_client = source_client or build_source_client(replication)
        destination_client = destination_client or build_destination_client(
            replication.destination_storage
        )
        source_bucket = replication.source_bucket_name
        destination_bucket = _destination_bucket(replication.destination_storage)
        destination_prefix = _join_prefix(
            replication.destination_prefix,
            normalized_restore_prefix,
        )
        if row.destination_prefix != destination_prefix:
            _raise_restore_duplicate_match()
        manifest_prefix = _join_prefix(replication.destination_prefix, MANIFEST_DIRECTORY)
        if not _listing_is_complete(row):
            cursor_state = _load_listing_cursor(row, replication)
            expected_cursor = dict(cursor_state)
            for page_entries, next_cursor in iter_source_object_pages(
                destination_client,
                destination_bucket,
                destination_prefix,
                True,
                cursor_state=cursor_state,
            ):
                prepared = []
                for entry in page_entries:
                    if not entry.get("is_latest", True):
                        continue
                    if (entry.get("key") or "").startswith(manifest_prefix):
                        continue
                    defaults = _prepare_restore_object(
                        replication,
                        source_run,
                        entry,
                        destination_client,
                        destination_bucket,
                        destination_prefix,
                        normalized_target_prefix,
                    )
                    prepared.append((entry.get("key") or "", defaults))
                with transaction.atomic():
                    checkpoint = CoreLightsailBucketRestoreRun.objects.select_for_update().get(
                        pk=row.id
                    )
                    current_cursor = _load_listing_cursor(checkpoint, replication)
                    if _listing_is_complete(checkpoint) or current_cursor != expected_cursor:
                        row = checkpoint
                        break
                    for backup_key, defaults in prepared:
                        _get_or_create_restore_object_state(
                            checkpoint,
                            replication,
                            backup_key,
                            defaults,
                        )
                    _persist_listing_cursor(checkpoint, replication, next_cursor)
                    row = checkpoint
                expected_cursor = dict(next_cursor)
            row.refresh_from_db()
            if not _listing_is_complete(row):
                _refresh_restore_progress(row)
                row.status = CoreLightsailBucketRestoreRun.Status.RUNNING
                row.save()
                return _restore_result(row)

        summary_failure: Optional[LightsailFailure] = None
        all_failures_retryable = True
        chunk_size = _setting_int("LIGHTSAIL_BUCKET_OBJECT_CHUNK_SIZE", 500)
        states = row.object_states.order_by("backup_key_hash", "id")
        for state in states.iterator(chunk_size=chunk_size):
            if state.status in {
                CoreLightsailBucketRestoreObject.Status.COMPLETE,
                CoreLightsailBucketRestoreObject.Status.SKIPPED,
            }:
                continue
            _heartbeat_restore_lease(
                row,
                owner,
                token,
                _lease_seconds(replication),
            )
            state.status = CoreLightsailBucketRestoreObject.Status.RESTORING
            state.attempt_count = int(state.attempt_count or 0) + 1
            state.error = ""
            state.save(update_fields=["status", "attempt_count", "error", "modified"])
            try:
                backup_key = _decrypt_restore_key(
                    state.backup_key_encrypted,
                    replication.account,
                )
                original_source_key = _decrypt_restore_key(
                    state.source_key_encrypted,
                    replication.account,
                )
                target_key = _decrypt_restore_key(
                    state.target_key_encrypted,
                    replication.account,
                )
                result = restore_s3_object(
                    destination_client,
                    source_client,
                    destination_bucket,
                    source_bucket,
                    backup_key,
                    target_key,
                    restore_id=str(row.uuid),
                    backup_version_id=state.backup_version_id,
                    is_delete_marker=state.is_delete_marker,
                    backup_etag=state.backup_etag,
                    backup_size=state.backup_size,
                    backup_last_modified=state.backup_last_modified,
                    original_source_key=original_source_key,
                    original_source_version_id=state.source_version_id,
                    original_source_etag=state.source_etag,
                    heartbeat_callback=lambda: _heartbeat_restore_lease(
                        row,
                        owner,
                        token,
                        _lease_seconds(replication),
                    ),
                )
                if not _restore_lease_still_owned(row, owner, token):
                    raise LeaseLost("The restore worker lease was recovered.")
                state.restored_version_id = result.get("destination_version_id") or ""
                state.bytes_restored = int(result.get("bytes_transferred") or 0)
                if result.get("skipped"):
                    state.status = CoreLightsailBucketRestoreObject.Status.SKIPPED
                else:
                    state.status = CoreLightsailBucketRestoreObject.Status.COMPLETE
                state.error = ""
                state.save()
                _heartbeat_restore_lease(
                    row,
                    owner,
                    token,
                    _lease_seconds(replication),
                )
            except Exception as error:
                if isinstance(error, LeaseLost) or not _restore_lease_still_owned(
                    row, owner, token
                ):
                    raise
                capture_exception(getattr(error, "__cause__", None) or error)
                failure = _failure_for(error)
                state.status = CoreLightsailBucketRestoreObject.Status.FAILED
                state.error = _failure_payload(failure)
                state.save(update_fields=["status", "error", "modified"])
                summary_failure = failure
                all_failures_retryable = all_failures_retryable and failure.retryable
                break

        _refresh_restore_progress(row)
        row.manifest = _restore_manifest(row)
        if summary_failure:
            row.error = _failure_payload(summary_failure)
            row.status = (
                CoreLightsailBucketRestoreRun.Status.RUNNING
                if all_failures_retryable
                else CoreLightsailBucketRestoreRun.Status.FAILED
            )
            row.completed_at = None if row.status == CoreLightsailBucketRestoreRun.Status.RUNNING else _now()
        elif row.object_states.filter(
            status__in={
                CoreLightsailBucketRestoreObject.Status.PENDING,
                CoreLightsailBucketRestoreObject.Status.RESTORING,
                CoreLightsailBucketRestoreObject.Status.FAILED,
            }
        ).exists():
            row.error = ""
            row.status = CoreLightsailBucketRestoreRun.Status.RUNNING
            row.completed_at = None
        else:
            row.error = ""
            row.status = CoreLightsailBucketRestoreRun.Status.COMPLETE
            row.completed_at = _now()
        row.save()
        return _restore_result(row)
    finally:
        _release_restore_lease(row, owner, token)


def run_lightsail_bucket_prefix_restore(
    replication_id: int,
    *,
    restore_id: Optional[int] = None,
    source_run_id: Optional[int] = None,
    restore_prefix: str = "",
    target_prefix: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    celery_task_id: str = "",
    source_client=None,
    destination_client=None,
) -> Dict[str, Any]:
    """Restore a destination prefix while preserving a safe resumable state."""

    try:
        return _run_lightsail_bucket_prefix_restore(
            replication_id,
            restore_id=restore_id,
            source_run_id=source_run_id,
            restore_prefix=restore_prefix,
            target_prefix=target_prefix,
            idempotency_key=idempotency_key,
            celery_task_id=celery_task_id,
            source_client=source_client,
            destination_client=destination_client,
        )
    except Exception as error:
        _record_restore_failure(
            replication_id,
            error,
            restore_id=restore_id,
            idempotency_key=idempotency_key,
            celery_task_id=celery_task_id,
        )
        raise


@current_app.task(
    name="restore_lightsail_bucket_prefix",
    bind=True,
    track_started=True,
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=4,
)
def restore_lightsail_bucket_prefix(
    self,
    replication_id: int,
    restore_id: Optional[int] = None,
    source_run_id: Optional[int] = None,
    restore_prefix: str = "",
    target_prefix: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    prefix: Optional[str] = None,
):
    # ``prefix`` is a small compatibility affordance for API callers that name the
    # source selection simply "prefix".
    if prefix is not None and not restore_prefix:
        restore_prefix = prefix
    task_id = str(getattr(getattr(self, "request", None), "id", "") or "")
    return run_lightsail_bucket_prefix_restore(
        replication_id,
        restore_id=restore_id,
        source_run_id=source_run_id,
        restore_prefix=restore_prefix,
        target_prefix=target_prefix,
        idempotency_key=idempotency_key,
        celery_task_id=task_id,
    )


@current_app.task(
    name="sync_lightsail_bucket_replications",
    bind=True,
    ignore_result=True,
)
def sync_lightsail_bucket_replications(self):
    """Start due bucket runs and recover fresh PENDING rows.

    The database row is created before the Celery message is published. If beat or
    the broker disappears in that gap, the next beat/recovery pass sees the same
    PENDING run and publishes it instead of creating a second run.
    """

    now = _now()
    stale_seconds = _setting_int(
        "LIGHTSAIL_BUCKET_RUN_STALE_SECONDS", DEFAULT_LEASE_SECONDS
    )
    dispatch = []
    queryset = CoreLightsailBucketReplication.objects.filter(
        enabled=True,
        status=CoreLightsailBucketReplication.Status.ACTIVE,
    ).order_by("next_run_at", "id")
    for replication_id in queryset.values_list("id", flat=True):
        with transaction.atomic():
            replication = CoreLightsailBucketReplication.objects.select_for_update().get(
                pk=replication_id
            )
            if not replication.enabled or replication.status != replication.Status.ACTIVE:
                continue
            active = replication.runs.filter(
                status__in=(
                    CoreLightsailBucketReplicationRun.Status.PENDING,
                    CoreLightsailBucketReplicationRun.Status.RUNNING,
                )
            ).order_by("-created").first()
            should_dispatch = False
            if active is not None:
                # A PENDING row without a task id is the broker-gap recovery case.
                # RUNNING rows are only re-enqueued after their stale window; the
                # per-object lease still prevents duplicate provider transfers.
                should_dispatch = (
                    not active.celery_task_id
                    or _recovery_due(active, now, stale_seconds)
                )
                run = active
            elif replication.next_run_at is None or replication.next_run_at <= now:
                key = f"scheduled:{now.strftime('%Y%m%d%H%M')}"
                run = _get_or_create_run(replication, key)
                should_dispatch = True
                replication.next_run_at = now + timedelta(
                    minutes=max(1, int(replication.interval_minutes or 60))
                )
                replication.save(update_fields=["next_run_at", "modified"])
            else:
                continue
            if should_dispatch:
                task_id = f"sync-lightsail-bucket-{run.id}-{uuid.uuid4().hex}"
                run.celery_task_id = task_id
                run.save(update_fields=["celery_task_id", "modified"])
                dispatch.append(
                    (replication.id, run.id, run.idempotency_key, task_id)
                )

    for replication_id, run_id, idempotency_key, task_id in dispatch:
        replicate_lightsail_bucket.apply_async(
            task_id=task_id,
            kwargs={
                "replication_id": replication_id,
                "run_id": run_id,
                "idempotency_key": idempotency_key,
            }
        )
    return {"dispatched": len(dispatch)}


@current_app.task(
    name="resume_lightsail_bucket_replications",
    bind=True,
    ignore_result=True,
)
def resume_lightsail_bucket_replications(self):
    """Requeue stale runs after a worker/server restart.

    Object and multipart rows are deliberately left untouched: the next worker
    takes over only expired object leases and resumes the recorded upload parts.
    """

    runs = CoreLightsailBucketReplicationRun.objects.filter(
        status__in=(
            CoreLightsailBucketReplicationRun.Status.PENDING,
            CoreLightsailBucketReplicationRun.Status.RUNNING,
        )
    )
    dispatch = []
    now = _now()
    stale_seconds = _setting_int(
        "LIGHTSAIL_BUCKET_RUN_STALE_SECONDS", DEFAULT_LEASE_SECONDS
    )
    batch_size = _setting_int("BACKUP_RECOVERY_BATCH_SIZE", 100)
    for run_id in runs.order_by("modified").values_list("id", flat=True)[: batch_size * 4]:
        with transaction.atomic():
            run = CoreLightsailBucketReplicationRun.objects.select_for_update().select_related(
                "replication"
            ).get(pk=run_id)
            if run.status not in (
                CoreLightsailBucketReplicationRun.Status.PENDING,
                CoreLightsailBucketReplicationRun.Status.RUNNING,
            ):
                continue
            if run.celery_task_id and not _recovery_due(run, now, stale_seconds):
                continue
            recover_stale_object_leases(run.replication_id)
            task_id = f"recover-lightsail-bucket-{run.id}-{uuid.uuid4().hex}"
            run.celery_task_id = task_id
            run.save(update_fields=["celery_task_id", "modified"])
            dispatch.append(
                (run.replication_id, run.id, run.idempotency_key, task_id)
            )
    for replication_id, run_id, idempotency_key, task_id in dispatch:
        replicate_lightsail_bucket.apply_async(
            task_id=task_id,
            kwargs={
                "replication_id": replication_id,
                "run_id": run_id,
                "idempotency_key": idempotency_key,
            },
        )
    return {"dispatched": len(dispatch)}


@current_app.task(
    name="resume_lightsail_bucket_restores",
    bind=True,
    ignore_result=True,
)
def resume_lightsail_bucket_restores(self):
    """Requeue bucket restores whose worker/ETA message disappeared.

    Restore rows have their own lease and per-object child ledger. Recovery only
    hands off an expired lease (or a never-claimed pending row), so an active
    restore cannot produce a second source write.
    """

    now = _now()
    stale_seconds = _setting_int(
        "LIGHTSAIL_BUCKET_RUN_STALE_SECONDS", DEFAULT_LEASE_SECONDS
    )
    rows = CoreLightsailBucketRestoreRun.objects.filter(
        status__in=(
            CoreLightsailBucketRestoreRun.Status.PENDING,
            CoreLightsailBucketRestoreRun.Status.RUNNING,
        )
    )
    dispatch = []
    batch_size = _setting_int("BACKUP_RECOVERY_BATCH_SIZE", 100)
    for restore_id in rows.order_by("modified").values_list("id", flat=True)[
        : batch_size * 4
    ]:
        with transaction.atomic():
            row = CoreLightsailBucketRestoreRun.objects.select_for_update().get(
                pk=restore_id
            )
            if row.status not in (
                CoreLightsailBucketRestoreRun.Status.PENDING,
                CoreLightsailBucketRestoreRun.Status.RUNNING,
            ):
                continue
            if row.lease_expires_at and row.lease_expires_at > _now():
                continue
            if row.celery_task_id and not _recovery_due(row, now, stale_seconds):
                continue
            task_id = f"recover-lightsail-bucket-restore-{row.id}-{uuid.uuid4().hex}"
            row.celery_task_id = task_id
            row.save(update_fields=["celery_task_id", "modified"])
            dispatch.append(
                (
                    row.replication_id,
                    row.id,
                    row.source_run_id,
                    row.restore_prefix,
                    row.target_prefix,
                    row.idempotency_key,
                    task_id,
                )
            )
    for (
        replication_id,
        restore_id,
        source_run_id,
        restore_prefix,
        target_prefix,
        idempotency_key,
        task_id,
    ) in dispatch:
        restore_lightsail_bucket_replication.apply_async(
            task_id=task_id,
            kwargs={
                "replication_id": replication_id,
                "restore_id": restore_id,
                "source_run_id": source_run_id,
                "restore_prefix": restore_prefix,
                "target_prefix": target_prefix,
                "idempotency_key": idempotency_key,
            },
        )
    return {"dispatched": len(dispatch)}


@current_app.task(
    name="start_lightsail_bucket_replication",
    bind=True,
    track_started=True,
    acks_late=True,
    reject_on_worker_lost=True,
)
def start_lightsail_bucket_replication(
    self, replication_id: int, run_id: Optional[int] = None, idempotency_key: Optional[str] = None
):
    """Public task spelling for API/manual callers; all work stays idempotent."""

    task_id = str(getattr(getattr(self, "request", None), "id", "") or "")
    return run_lightsail_bucket_replication(
        replication_id,
        run_id=run_id,
        idempotency_key=idempotency_key,
        celery_task_id=task_id,
    )


@current_app.task(
    name="finalize_lightsail_bucket_replication",
    bind=True,
    ignore_result=True,
)
def finalize_lightsail_bucket_replication(
    self, replication_id: int, run_id: int, idempotency_key: Optional[str] = None
):
    """Resume the run so its durable object rows are finalized and manifested."""

    return run_lightsail_bucket_replication(
        replication_id,
        run_id=run_id,
        idempotency_key=idempotency_key,
        celery_task_id=str(getattr(getattr(self, "request", None), "id", "") or ""),
    )


@current_app.task(
    name="restore_lightsail_bucket_replication",
    bind=True,
    track_started=True,
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=4,
)
def restore_lightsail_bucket_replication(
    self,
    replication_id: int,
    restore_id: Optional[int] = None,
    source_run_id: Optional[int] = None,
    restore_prefix: str = "",
    target_prefix: Optional[str] = None,
    idempotency_key: Optional[str] = None,
):
    """Stable public task spelling for prefix restores."""

    return run_lightsail_bucket_prefix_restore(
        replication_id,
        restore_id=restore_id,
        source_run_id=source_run_id,
        restore_prefix=restore_prefix,
        target_prefix=target_prefix,
        idempotency_key=idempotency_key,
        celery_task_id=str(getattr(getattr(self, "request", None), "id", "") or ""),
    )


# Alternate public spellings keep integration code explicit without registering a
# second Celery task that could execute the same run twice.
backup_lightsail_bucket = replicate_lightsail_bucket
restore_lightsail_bucket = restore_lightsail_bucket_prefix
recover_stale_lightsail_bucket_replication = recover_stale_lightsail_bucket_leases


__all__ = [
    "LightsailBucketReplicationError",
    "UnsupportedStorageProvider",
    "LeaseUnavailable",
    "LeaseLost",
    "S3_STORAGE_RELATIONS",
    "list_source_objects",
    "copy_s3_object",
    "restore_s3_object",
    "build_source_client",
    "build_destination_client",
    "lease_is_active",
    "lease_is_stale",
    "recover_stale_object_leases",
    "run_lightsail_bucket_replication",
    "replicate_lightsail_bucket",
    "sync_lightsail_bucket_replications",
    "resume_lightsail_bucket_replications",
    "resume_lightsail_bucket_restores",
    "recover_stale_lightsail_bucket_leases",
    "run_lightsail_bucket_prefix_restore",
    "restore_lightsail_bucket_prefix",
    "backup_lightsail_bucket",
    "restore_lightsail_bucket",
    "recover_stale_lightsail_bucket_replication",
]
