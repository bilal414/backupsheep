"""Crash-safe, resumable uploads for S3 and compatible object stores."""

from __future__ import annotations

import base64
import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone as datetime_timezone
from typing import Dict, Optional

from botocore.exceptions import (
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
    ResponseStreamingError,
)
from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps._tasks.artifact_encryption import validate_storage_object_key


SHA256_METADATA = "backupsheep-sha256"
SIZE_METADATA = "backupsheep-bytes"
ARTIFACT_METADATA = "backupsheep-artifact-id"
LEGACY_BACKUP_METADATA = "backupsheep-backup-id"
# Compatibility export for legacy tests/callers. New encrypted writes select the
# artifact marker explicitly through ``_ownership_metadata_key``.
BACKUP_METADATA = LEGACY_BACKUP_METADATA
MULTIPART_METADATA = "backupsheep-multipart-id"
S3_MIN_MULTIPART_PART_SIZE = 5 * 1024 * 1024
S3_MAX_MULTIPART_PART_SIZE = 5 * 1024 ** 3
S3_MAX_OBJECT_SIZE = 5 * 1024 ** 4
S3_MULTIPART_ALIGNMENT = 1024 * 1024
NOT_FOUND_CODES = {"404", "NoSuchKey", "NotFound", "NoSuchBucket"}
NO_UPLOAD_CODES = {"NoSuchUpload", "404", "NotFound"}
_ALLOWED_UPLOAD_EXTRA_ARGS = frozenset(
    {
        "ExpectedBucketOwner",
        "ObjectLockMode",
        "ObjectLockRetainUntilDate",
        "StorageClass",
    }
)


def _ownership_metadata_key(ownership_marker):
    return (
        ARTIFACT_METADATA
        if str(ownership_marker or "").startswith("bse2:")
        else LEGACY_BACKUP_METADATA
    )

_AUTH_CODES = {
    "accessdenied",
    "allaccessdisabled",
    "accountproblem",
    "expiredtoken",
    "expiredtokenexception",
    "invalidaccesskeyid",
    "invalidclienttokenid",
    "invalidsecuritytoken",
    "invalidtoken",
    "signaturedoesnotmatch",
    "unauthorized",
}
_NOT_FOUND_CODES_LOWER = {code.lower() for code in NOT_FOUND_CODES}
_RATE_LIMIT_CODES = {
    "ratelimitexceeded",
    "requestlimitexceeded",
    "slowdown",
    "throttling",
    "throttlingexception",
    "toomanyrequests",
    "toomanyrequestsexception",
}
_VALIDATION_CODES = {
    "invalidargument",
    "invalidpart",
    "invalidpartorder",
    "invalidrequest",
    "malformedxml",
    "missingrequiredparameter",
    "nosuchbucket",
    "nosuchkey",
    "nosuchupload",
    "notfound",
    "preconditionfailed",
}
_AMBIGUOUS_CODES = {
    "gatewaytimeout",
    "internalerror",
    "internalfailure",
    "requesttimeout",
    "serviceunavailable",
}
_AMBIGUOUS_EXCEPTIONS = (
    ConnectionError,
    TimeoutError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
    ResponseStreamingError,
)


def _bounded_setting(name, default, *, maximum):
    try:
        value = int(getattr(settings, name, default))
    except (TypeError, ValueError):
        value = default
    return max(1, min(value, maximum))


def _reconciliation_max_pages():
    return _bounded_setting("S3_RECONCILIATION_MAX_PAGES", 32, maximum=100)


def _reconciliation_max_items():
    return _bounded_setting("S3_RECONCILIATION_MAX_ITEMS", 1000, maximum=10000)


def _reconciliation_page_size():
    return _bounded_setting("S3_RECONCILIATION_PAGE_SIZE", 1000, maximum=1000)


def _reconciliation_max_parts():
    return _bounded_setting("S3_RECONCILIATION_MAX_PARTS", 10000, maximum=10000)


def _reconciliation_clock_skew_seconds():
    return _bounded_setting("S3_RECONCILIATION_CLOCK_SKEW_SECONDS", 300, maximum=3600)


def _outcome_reconciliation_max_checks():
    return _bounded_setting("S3_OUTCOME_RECONCILIATION_MAX_CHECKS", 12, maximum=96)


def _outcome_reconciliation_retry_after():
    return _bounded_setting(
        "S3_OUTCOME_RECONCILIATION_RETRY_AFTER_SECONDS", 60, maximum=3600
    )


def _multipart_checkpoint_parts():
    return _bounded_setting("S3_MULTIPART_CHECKPOINT_PARTS", 16, maximum=1000)


def _multipart_hash_chunk_bytes():
    return _bounded_setting(
        "S3_MULTIPART_HASH_CHUNK_BYTES", 1024 * 1024, maximum=8 * 1024 * 1024
    )


def _multipart_no_progress_seconds():
    return _bounded_setting(
        "S3_MULTIPART_NO_PROGRESS_SECONDS", 3600, maximum=7 * 24 * 3600
    )


def _multipart_no_progress_retry_after():
    return _bounded_setting(
        "S3_MULTIPART_NO_PROGRESS_RETRY_AFTER_SECONDS", 300, maximum=3600
    )


def _multipart_cleanup_retry_after():
    return _bounded_setting(
        "S3_MULTIPART_CLEANUP_RETRY_AFTER_SECONDS", 300, maximum=3600
    )


class S3ObjectIntegrityError(RuntimeError):
    pass


class S3UploadReconciliationRequired(RuntimeError):
    outcome_kind = "ambiguous"


class S3MalformedMultipartInventory(S3UploadReconciliationRequired):
    """The provider definitively returned an unusable inventory shape."""

    outcome_kind = "definitive"


class S3UploadOutcomePending(S3UploadReconciliationRequired):
    """A provider mutation may have succeeded but is not visible yet."""

    error_code = "STORAGE_RECONCILIATION_PENDING"
    code = error_code
    retryable = True
    outcome_kind = "ambiguous"

    def __init__(self, message, *, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after or _outcome_reconciliation_retry_after()


class S3UploadStalled(S3UploadOutcomePending):
    """The exact multipart upload made no provider-visible progress in time."""

    error_code = "STORAGE_STALLED"
    code = error_code


# A descriptive compatibility alias for callers that use reconciliation wording.
S3UploadReconciliationPending = S3UploadOutcomePending


class S3UploadInventoryFailure(RuntimeError):
    """A definitive inventory read failure after an ambiguous provider mutation."""

    outcome_kind = "ambiguous"
    retryable = False

    def __init__(self, message, *, error_code):
        super().__init__(message)
        self.error_code = str(error_code)
        self.code = self.error_code


class S3MultipartCleanupNotEligible(S3UploadReconciliationRequired):
    """The durable/provider evidence is insufficient for an automatic abort."""

    retryable = False
    error_code = "STORAGE_MULTIPART_CLEANUP_NOT_ELIGIBLE"
    code = error_code


class S3MultipartCleanupPending(S3UploadOutcomePending):
    """An exact-owned abort was issued but provider absence is not proven yet."""

    error_code = "STORAGE_MULTIPART_CLEANUP_PENDING"
    code = error_code

    def __init__(self, message="Multipart cleanup is pending provider visibility."):
        super().__init__(message, retry_after=_multipart_cleanup_retry_after())


class _BoundedPartBody:
    """Seekable view of one file range without materialising the part in memory."""

    def __init__(self, source, offset, size):
        self._source = source
        self._offset = int(offset)
        self._size = int(size)
        self._position = 0
        self._source.seek(self._offset)

    def __len__(self):
        return self._size

    def readable(self):
        return True

    def seekable(self):
        return True

    def close(self):
        # Botocore may close request bodies after a call. The shared source file
        # belongs to the outer upload loop and must remain available for later parts.
        return None

    def tell(self):
        return self._position

    def seek(self, offset, whence=os.SEEK_SET):
        offset = int(offset)
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self._position + offset
        elif whence == os.SEEK_END:
            position = self._size + offset
        else:
            raise ValueError("Unsupported seek mode for multipart body.")
        if position < 0 or position > self._size:
            raise ValueError("Multipart body seek is outside the bounded part.")
        self._source.seek(self._offset + position)
        self._position = position
        return self._position

    def read(self, size=-1):
        remaining = self._size - self._position
        if remaining <= 0:
            return b""
        if size is None or int(size) < 0:
            amount = remaining
        else:
            amount = min(int(size), remaining)
        payload = self._source.read(amount)
        self._position += len(payload)
        return payload


def _hash_file_range(source, offset, size):
    digest = hashlib.sha256()
    remaining = int(size)
    source.seek(int(offset))
    chunk_size = _multipart_hash_chunk_bytes()
    while remaining:
        payload = source.read(min(chunk_size, remaining))
        if not payload:
            raise S3ObjectIntegrityError(
                "The local backup ended while a multipart part was hashed."
            )
        digest.update(payload)
        remaining -= len(payload)
    return base64.b64encode(digest.digest()).decode("ascii")


def _validated_multipart_geometry(size_bytes, part_size_bytes, *, state=False):
    error_class = S3UploadReconciliationRequired if state else S3ObjectIntegrityError
    try:
        size_bytes = int(size_bytes)
        part_size_bytes = int(part_size_bytes)
    except (TypeError, ValueError) as error:
        raise error_class("Multipart upload geometry is malformed.") from error
    if size_bytes < 1 or size_bytes > S3_MAX_OBJECT_SIZE:
        raise error_class("Object size is outside the supported S3 multipart range.")
    if not S3_MIN_MULTIPART_PART_SIZE <= part_size_bytes <= S3_MAX_MULTIPART_PART_SIZE:
        raise error_class("Multipart part size is outside the supported S3 range.")
    total_parts = (size_bytes + part_size_bytes - 1) // part_size_bytes
    if total_parts > _reconciliation_max_parts():
        raise error_class(
            "Multipart geometry exceeds the bounded provider inventory limit."
        )
    return part_size_bytes


def _multipart_part_size(size_bytes):
    """Choose bounded geometry before creating a new multipart upload."""
    try:
        configured_minimum = int(
            getattr(settings, "S3_MULTIPART_PART_SIZE_BYTES", 8 * 1024 * 1024)
        )
    except (TypeError, ValueError):
        configured_minimum = 8 * 1024 * 1024
    configured_minimum = max(S3_MIN_MULTIPART_PART_SIZE, configured_minimum)
    target_parts = min(
        _bounded_setting("S3_MULTIPART_TARGET_PARTS", 8000, maximum=10000),
        _reconciliation_max_parts(),
    )
    required_size = (int(size_bytes) + target_parts - 1) // target_parts
    aligned_size = (
        (required_size + S3_MULTIPART_ALIGNMENT - 1)
        // S3_MULTIPART_ALIGNMENT
        * S3_MULTIPART_ALIGNMENT
    )
    return _validated_multipart_geometry(
        size_bytes,
        max(configured_minimum, aligned_size),
    )


def _legacy_multipart_part_size(size_bytes, remote_parts):
    """Recover immutable geometry for uploads created before it was persisted."""
    remote_sizes = []
    for part in remote_parts:
        try:
            part_size = int(part.get("Size"))
        except (AttributeError, TypeError, ValueError):
            continue
        if part_size > 0:
            remote_sizes.append(part_size)
    if remote_sizes and max(remote_sizes) >= S3_MIN_MULTIPART_PART_SIZE:
        candidate = max(remote_sizes)
    else:
        try:
            candidate = int(
                getattr(
                    settings,
                    "S3_MULTIPART_PART_SIZE_BYTES",
                    8 * 1024 * 1024,
                )
            )
        except (TypeError, ValueError):
            candidate = 8 * 1024 * 1024
        candidate = max(S3_MIN_MULTIPART_PART_SIZE, candidate)
    return _validated_multipart_geometry(size_bytes, candidate, state=True)


def _exception_chain(error):
    current = error
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = getattr(current, "__cause__", None) or getattr(
            current, "__context__", None
        )


def _error_code(error):
    if isinstance(error, ClientError):
        return str((error.response or {}).get("Error", {}).get("Code", ""))
    return ""


def _error_status(error):
    if not isinstance(error, ClientError):
        return None
    response = error.response or {}
    response_metadata = response.get("ResponseMetadata") or {}
    status = response_metadata.get("HTTPStatusCode")
    if isinstance(status, str) and status.isdigit():
        status = int(status)
    return status if isinstance(status, int) else None


def _provider_retry_after(error):
    for current in _exception_chain(error):
        if not isinstance(current, ClientError):
            continue
        metadata = (current.response or {}).get("ResponseMetadata") or {}
        headers = metadata.get("HTTPHeaders") or {}
        if not isinstance(headers, dict):
            continue
        for name, value in headers.items():
            if str(name).lower() != "retry-after":
                continue
            try:
                return max(1, min(int(value), 86400))
            except (TypeError, ValueError):
                return None
    return None


def _inventory_failure_code(error):
    for current in _exception_chain(error):
        if not isinstance(current, ClientError):
            continue
        code = _error_code(current).strip().lower()
        status = _error_status(current)
        if code in _AUTH_CODES or status in {401, 403}:
            return "STORAGE_AUTH_FAILED"
        if code in _NOT_FOUND_CODES_LOWER or status == 404:
            return "STORAGE_DESTINATION_NOT_FOUND"
        return "PROVIDER_MALFORMED_RESPONSE"
    return "PROVIDER_MALFORMED_RESPONSE"


def _create_error_kind(error):
    """Classify create failures before considering multipart adoption.

    A definitive provider response means the create request was rejected and
    inventory must not be used as a side channel for adoption. A rate-limit
    response is also a known provider response and is returned unchanged so the
    normal retry/error mapping remains intact. Only transport failures and
    explicitly ambiguous 5xx responses may enter reconciliation.
    """

    chain = tuple(_exception_chain(error))
    for current in chain:
        explicit_kind = getattr(current, "outcome_kind", None)
        if explicit_kind in {"ambiguous", "definitive", "rate_limit"}:
            return explicit_kind
    for current in chain:
        if not isinstance(current, ClientError):
            continue
        code = _error_code(current).strip().lower()
        status = _error_status(current)
        if code in _RATE_LIMIT_CODES or status == 429:
            return "rate_limit"
        if (
            code in _AUTH_CODES
            or code in _NOT_FOUND_CODES_LOWER
            or code in _VALIDATION_CODES
            or status in {400, 401, 403, 404, 409, 422}
        ):
            return "definitive"
        if code in _AMBIGUOUS_CODES or status in {408, 425}:
            return "ambiguous"
        if status is not None and 500 <= status <= 599:
            return "ambiguous"
        return "definitive"
    if any(isinstance(current, _AMBIGUOUS_EXCEPTIONS) for current in chain):
        return "ambiguous"
    return "definitive"


def file_identity(path):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return {
        "sha256": digest.hexdigest(),
        "sha256_base64": base64.b64encode(digest.digest()).decode("ascii"),
        "size_bytes": size,
    }


def _state(stored_backup, metadata_key):
    metadata = dict(stored_backup.metadata or {})
    state = dict(metadata.get(metadata_key) or {})
    return metadata, state


def _bind_exact_bucket(state, bucket):
    bucket = str(bucket or "")
    if not bucket or bucket != bucket.strip():
        raise S3UploadReconciliationRequired(
            "Object storage has no valid exact bucket binding."
        )
    if "bucket" not in state:
        if state:
            return bucket, True
        state["bucket"] = bucket
        return bucket, False
    bound_bucket = state.get("bucket")
    if not isinstance(bound_bucket, str) or not bound_bucket:
        raise S3UploadReconciliationRequired(
            "The durable object bucket binding is malformed."
        )
    if bound_bucket != bucket:
        raise S3UploadReconciliationRequired(
            "The configured object storage bucket differs from the durable upload binding."
        )
    return bucket, False


def _bind_exact_storage_context(stored_backup, state, expected_owner=None):
    """Bind one upload to the owning account, storage row, and bucket owner."""

    storage = getattr(stored_backup, "storage", None)
    account_id = getattr(storage, "account_id", None)
    storage_id = getattr(stored_backup, "storage_id", None)
    if storage_id is None:
        storage_id = getattr(storage, "id", None)
    if account_id is None or storage_id is None:
        raise S3UploadReconciliationRequired(
            "Object storage upload has no exact account and storage binding."
        )
    expected = {
        "account_id": str(account_id),
        "storage_id": str(storage_id),
        "expected_bucket_owner": str(expected_owner or ""),
    }
    for field, value in expected.items():
        if field in state and str(state.get(field)) != value:
            raise S3UploadReconciliationRequired(
                "The configured storage context differs from the durable upload binding."
            )
        state[field] = value
    return expected


def _save_state(stored_backup, metadata_key, state, *, status=None):
    metadata = dict(stored_backup.metadata or {})
    metadata[metadata_key] = state
    stored_backup.metadata = metadata
    fields = ["metadata", "modified"]
    if status is not None:
        stored_backup.status = status
        fields.insert(0, "status")
    if state.get("object_key"):
        stored_backup.storage_file_id = state["object_key"]
        fields.insert(0, "storage_file_id")
    stored_backup.save(update_fields=list(dict.fromkeys(fields)))


def _new_outcome_intent(key, identity, ownership_marker, **extra):
    intent = {
        "complete": True,
        "object_key": key,
        "sha256": identity["sha256"],
        "size_bytes": identity["size_bytes"],
        "ownership_marker": str(ownership_marker),
        "operation_marker": uuid.uuid4().hex,
        "operation_started_at": timezone.now().isoformat(),
        "reconciliation_checks": 0,
    }
    intent.update(extra)
    return intent


def _require_exact_outcome_intent(
    intent,
    *,
    key,
    identity,
    ownership_marker,
    upload_id=None,
):
    if not isinstance(intent, dict) or not intent.get("complete"):
        raise S3UploadReconciliationRequired(
            "Upload outcome reconciliation has no complete durable intent."
        )
    expected = {
        "object_key": key,
        "sha256": identity["sha256"],
        "size_bytes": identity["size_bytes"],
        "ownership_marker": str(ownership_marker),
    }
    for field, value in expected.items():
        observed = intent.get(field)
        if field == "size_bytes":
            try:
                observed = int(observed)
            except (TypeError, ValueError):
                observed = None
        if observed != value:
            raise S3UploadReconciliationRequired(
                "The durable upload intent does not match the exact backup object."
            )
    operation_marker = str(intent.get("operation_marker") or "").strip()
    if not operation_marker:
        raise S3UploadReconciliationRequired(
            "The durable upload intent has no operation identity."
        )
    _upload_time(intent.get("operation_started_at"))
    if upload_id is not None and str(intent.get("upload_id") or "") != str(upload_id):
        raise S3UploadReconciliationRequired(
            "The durable completion intent belongs to a different multipart upload."
        )
    try:
        checks = int(intent.get("reconciliation_checks") or 0)
    except (TypeError, ValueError) as error:
        raise S3UploadReconciliationRequired(
            "The durable upload intent has malformed reconciliation progress."
        ) from error
    if checks < 0:
        raise S3UploadReconciliationRequired(
            "The durable upload intent has malformed reconciliation progress."
        )
    return checks


def _persist_and_raise_outcome_pending(
    stored_backup,
    metadata_key,
    state,
    record,
    *,
    pending_phase,
    exhausted_phase,
    pending_message,
    exhausted_message,
    cause=None,
):
    try:
        checks = int(record.get("reconciliation_checks") or 0)
    except (TypeError, ValueError) as error:
        raise S3UploadReconciliationRequired(
            "Upload reconciliation progress is malformed."
        ) from error
    if checks < 0:
        raise S3UploadReconciliationRequired(
            "Upload reconciliation progress is malformed."
        )
    checks += 1
    record["reconciliation_checks"] = checks
    record["last_checked_at"] = timezone.now().isoformat()
    exhausted = checks >= _outcome_reconciliation_max_checks()
    state["phase"] = exhausted_phase if exhausted else pending_phase
    _save_state(stored_backup, metadata_key, state)
    if exhausted:
        error = S3UploadReconciliationRequired(exhausted_message)
    else:
        error = S3UploadOutcomePending(
            pending_message,
            retry_after=getattr(cause, "retry_after", None),
        )
    if cause is not None:
        raise error from cause
    raise error


def _head(client, bucket, key, expected_owner=None, version_id=None):
    args = {"Bucket": bucket, "Key": key}
    if expected_owner:
        args["ExpectedBucketOwner"] = expected_owner
    if version_id and version_id != "null":
        args["VersionId"] = version_id
    return client.head_object(**args)


def _metadata_value(head, name):
    metadata = head.get("Metadata") or {}
    return next(
        (str(value) for key, value in metadata.items() if key.lower() == name.lower()),
        None,
    )


def _normalise_version_id(version_id):
    if version_id is None or str(version_id).lower() == "null":
        return ""
    return str(version_id)


def _require_exact_version(head, version_id):
    expected = _normalise_version_id(version_id)
    actual = _normalise_version_id(head.get("VersionId"))
    if actual != expected:
        raise S3ObjectIntegrityError(
            "Object storage returned a different version for this backup object."
        )


def _stream_remote_identity(client, bucket, key, expected_owner=None, version_id=None):
    args = {"Bucket": bucket, "Key": key}
    if expected_owner:
        args["ExpectedBucketOwner"] = expected_owner
    if version_id and version_id != "null":
        args["VersionId"] = version_id
    response = client.get_object(**args)
    body = response["Body"]
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    finally:
        close = getattr(body, "close", None)
        if close:
            close()
    return digest.hexdigest(), size


def verified_head(
    client,
    bucket,
    key,
    identity,
    *,
    expected_owner=None,
    expected_ownership_marker=None,
    version_id=None,
    version_id_known=False,
    stream_if_metadata_missing=True,
):
    if expected_ownership_marker is None:
        raise S3ObjectIntegrityError(
            "Object ownership cannot be verified without a BackupSheep marker."
        )
    try:
        head = _head(client, bucket, key, expected_owner, version_id)
    except ClientError as error:
        if _error_code(error) in NOT_FOUND_CODES:
            return None
        raise
    artifact_marker = _metadata_value(head, ARTIFACT_METADATA)
    legacy_marker = _metadata_value(head, LEGACY_BACKUP_METADATA)
    if str(expected_ownership_marker).startswith("bse2:"):
        if legacy_marker is not None or _metadata_value(head, "backup") is not None:
            raise S3ObjectIntegrityError(
                "Object storage returned ambiguous legacy and encrypted ownership markers."
            )
        marker = artifact_marker
    else:
        marker = legacy_marker
    if marker != str(expected_ownership_marker):
        raise S3ObjectIntegrityError(
            "Object storage returned an object owned by a different backup."
        )
    if version_id_known:
        _require_exact_version(head, version_id)
    if int(head.get("ContentLength", -1)) != identity["size_bytes"]:
        return None
    remote_sha256 = _metadata_value(head, SHA256_METADATA)
    remote_bytes = _metadata_value(head, SIZE_METADATA)
    if remote_bytes is not None and int(remote_bytes) != identity["size_bytes"]:
        return None
    if remote_sha256 is not None:
        return head if remote_sha256 == identity["sha256"] else None
    if not stream_if_metadata_missing:
        return None
    sha256, size = _stream_remote_identity(
        client, bucket, key, expected_owner, version_id
    )
    if sha256 != identity["sha256"] or size != identity["size_bytes"]:
        return None
    return head


def _list_exact_uploads(client, bucket, key, expected_owner=None):
    args = {
        "Bucket": bucket,
        "Prefix": key,
        "MaxUploads": _reconciliation_page_size(),
    }
    if expected_owner:
        args["ExpectedBucketOwner"] = expected_owner
    uploads = []
    key_marker = None
    upload_marker = None
    page_count = 0
    max_pages = _reconciliation_max_pages()
    max_items = _reconciliation_max_items()
    while True:
        page_count += 1
        if page_count > max_pages:
            raise S3UploadReconciliationRequired(
                "Object storage multipart inventory exceeded the reconciliation page limit."
            )
        page_args = dict(args)
        if key_marker:
            page_args["KeyMarker"] = key_marker
        if upload_marker:
            page_args["UploadIdMarker"] = upload_marker
        payload = client.list_multipart_uploads(**page_args)
        if not isinstance(payload, dict):
            raise S3MalformedMultipartInventory(
                "Object storage returned a malformed multipart inventory page."
            )
        page_uploads = payload.get("Uploads")
        if page_uploads is None:
            page_uploads = []
        if not isinstance(page_uploads, list):
            raise S3MalformedMultipartInventory(
                "Object storage returned a malformed multipart inventory collection."
            )
        for item in page_uploads:
            if not isinstance(item, dict):
                raise S3MalformedMultipartInventory(
                    "Object storage returned a malformed multipart upload."
                )
            item_key = item.get("Key")
            if not isinstance(item_key, str):
                raise S3MalformedMultipartInventory(
                    "Object storage returned a multipart upload without an object key."
                )
            upload_id = item.get("UploadId")
            if not isinstance(upload_id, str) or not upload_id.strip():
                raise S3MalformedMultipartInventory(
                    "Object storage returned a multipart upload without an upload identity."
                )
            if item_key == key:
                uploads.append(item)
        if len(uploads) > max_items:
            raise S3UploadReconciliationRequired(
                "Object storage multipart inventory exceeded the reconciliation item limit."
            )
        if not payload.get("IsTruncated"):
            break
        next_key = payload.get("NextKeyMarker")
        next_upload = payload.get("NextUploadIdMarker")
        if (
            not isinstance(next_key, str)
            or not next_key
            or (next_upload is not None and not isinstance(next_upload, str))
            or (next_key, next_upload) == (key_marker, upload_marker)
        ):
            raise S3MalformedMultipartInventory(
                "Object storage returned a non-advancing multipart cursor."
            )
        key_marker, upload_marker = next_key, next_upload
    return uploads


def _list_parts(client, bucket, key, upload_id, expected_owner=None):
    args = {
        "Bucket": bucket,
        "Key": key,
        "UploadId": upload_id,
        "MaxParts": _reconciliation_page_size(),
    }
    if expected_owner:
        args["ExpectedBucketOwner"] = expected_owner
    parts = []
    seen_part_numbers = set()
    marker = 0
    page_count = 0
    max_pages = _reconciliation_max_pages()
    max_parts = _reconciliation_max_parts()
    while True:
        page_count += 1
        if page_count > max_pages:
            raise S3UploadReconciliationRequired(
                "Object storage multipart parts exceeded the reconciliation page limit."
            )
        payload = client.list_parts(**args, PartNumberMarker=marker)
        if not isinstance(payload, dict):
            raise S3UploadReconciliationRequired(
                "Object storage returned a malformed multipart parts page."
            )
        page_parts = payload.get("Parts")
        if page_parts is None:
            page_parts = []
        elif not isinstance(page_parts, list):
            raise S3UploadReconciliationRequired(
                "Object storage returned a malformed multipart parts collection."
            )
        previous_number = marker
        for raw_part in page_parts:
            if not isinstance(raw_part, dict):
                raise S3UploadReconciliationRequired(
                    "Object storage returned a malformed multipart part."
                )
            try:
                part_number = int(raw_part.get("PartNumber"))
            except (TypeError, ValueError) as error:
                raise S3UploadReconciliationRequired(
                    "Object storage returned a multipart part without a valid number."
                ) from error
            etag = raw_part.get("ETag")
            if (
                part_number <= previous_number
                or part_number > max_parts
                or part_number in seen_part_numbers
                or not isinstance(etag, str)
                or not etag.strip()
            ):
                raise S3UploadReconciliationRequired(
                    "Object storage returned an invalid or repeated multipart part."
                )
            if raw_part.get("Size") is not None:
                try:
                    if int(raw_part["Size"]) < 0:
                        raise ValueError
                except (TypeError, ValueError) as error:
                    raise S3UploadReconciliationRequired(
                        "Object storage returned an invalid multipart part size."
                    ) from error
            part = dict(raw_part)
            part["PartNumber"] = part_number
            parts.append(part)
            seen_part_numbers.add(part_number)
            previous_number = part_number
        if len(parts) > max_parts:
            raise S3UploadReconciliationRequired(
                "Object storage multipart parts exceeded the reconciliation item limit."
            )
        if not payload.get("IsTruncated"):
            return parts
        try:
            next_marker = int(payload["NextPartNumberMarker"])
        except (KeyError, TypeError, ValueError) as error:
            raise S3UploadReconciliationRequired(
                "Object storage returned a malformed multipart part cursor."
            ) from error
        if next_marker <= marker or (
            page_parts and next_marker < previous_number
        ):
            raise S3UploadReconciliationRequired(
                "Object storage returned a non-advancing part cursor."
            )
        marker = next_marker


def _multipart_inventory_witness(parts):
    witness = hashlib.sha256()
    for part in parts:
        try:
            number = int(part["PartNumber"])
            size = int(part["Size"])
        except (KeyError, TypeError, ValueError) as error:
            raise S3MalformedMultipartInventory(
                "Object storage returned incomplete multipart cleanup evidence."
            ) from error
        etag = str(part.get("ETag") or "")
        checksum = str(part.get("ChecksumSHA256") or "")
        witness.update(
            f"{number}\0{size}\0{etag}\0{checksum}\n".encode("utf-8")
        )
    return witness.hexdigest()


def _cleanup_terminal_statuses(stored_backup):
    names = (
        "UPLOAD_FAILED",
        "UPLOAD_FAILED_STORAGE_LIMIT",
        "UPLOAD_FAILED_FILE_NOT_FOUND",
        "UPLOAD_TIME_LIMIT_REACHED",
        "STORAGE_VALIDATION_FAILED",
        "CANCELLED",
    )
    return {
        value
        for value in (getattr(stored_backup.Status, name, None) for name in names)
        if value is not None
    }


def _cleanup_not_eligible(message):
    raise S3MultipartCleanupNotEligible(message)


def _require_cleanup_bindings(
    stored_backup,
    state,
    multipart,
    *,
    bucket,
    expected_owner,
):
    if stored_backup.status not in _cleanup_terminal_statuses(stored_backup):
        _cleanup_not_eligible(
            "Multipart cleanup requires a terminal failed or cancelled storage point."
        )

    storage = getattr(stored_backup, "storage", None)
    current_account_id = getattr(storage, "account_id", None)
    current_storage_id = getattr(stored_backup, "storage_id", None)
    if current_storage_id is None:
        current_storage_id = getattr(storage, "id", None)
    expected_bindings = {
        "account_id": current_account_id,
        "storage_id": current_storage_id,
        "bucket": bucket,
        "expected_bucket_owner": str(expected_owner or ""),
    }
    for field, expected in expected_bindings.items():
        observed = state.get(field)
        if expected is None or observed is None or str(observed) != str(expected):
            _cleanup_not_eligible(
                "Multipart cleanup storage ownership is not bound exactly."
            )

    key = state.get("object_key")
    upload_id = multipart.get("upload_id")
    operation_marker = multipart.get("operation_marker")
    if (
        not isinstance(key, str)
        or not key
        or str(getattr(stored_backup, "storage_file_id", "") or "") != key
        or not isinstance(upload_id, str)
        or not upload_id.strip()
        or not isinstance(operation_marker, str)
        or not operation_marker.strip()
    ):
        _cleanup_not_eligible(
            "Multipart cleanup has no exact object, upload, and operation identity."
        )
    expected_ownership_marker = validate_storage_object_key(
        stored_backup.backup, key
    ).ownership_marker
    if str(state.get("ownership_marker") or "") != expected_ownership_marker:
        _cleanup_not_eligible(
            "Multipart cleanup belongs to a different backup ownership marker."
        )

    phase = str(state.get("phase") or "")
    unsafe_phases = {
        "committed",
        "verifying",
        "creating_multipart",
        "multipart_create_reconciliation_exhausted",
        "multipart_complete_outcome_unknown",
        "multipart_complete_reconciliation_exhausted",
    }
    if (
        phase in unsafe_phases
        or phase.startswith("put_")
        or dict(multipart.get("complete_intent") or {}).get("complete")
    ):
        _cleanup_not_eligible(
            "Multipart completion may have crossed its provider mutation boundary."
        )

    baseline = multipart.get("create_baseline")
    proof = multipart.get("creation_proof")
    if not isinstance(baseline, dict) or not baseline.get("complete"):
        _cleanup_not_eligible(
            "Multipart cleanup has no complete pre-create inventory boundary."
        )
    if baseline.get("object_key") != key:
        _cleanup_not_eligible(
            "Multipart cleanup baseline belongs to a different object."
        )
    operation_started_at = _upload_time(baseline.get("operation_started_at"))
    preexisting = {
        str(value) for value in baseline.get("preexisting_upload_ids") or []
    }
    if upload_id in preexisting:
        _cleanup_not_eligible(
            "Multipart cleanup upload predates the owned creation boundary."
        )

    if (
        not isinstance(proof, dict)
        or proof.get("version") != 1
        or proof.get("result") not in {"provider_response", "baseline_adoption"}
        or str(proof.get("upload_id") or "") != upload_id
        or str(proof.get("operation_marker") or "") != operation_marker
    ):
        _cleanup_not_eligible(
            "Multipart cleanup has no exact durable creation witness."
        )
    _upload_time(proof.get("recorded_at"))
    return key, upload_id, operation_marker, baseline, operation_started_at


def _require_owned_cleanup_upload(
    upload,
    *,
    key,
    upload_id,
    baseline,
    operation_started_at,
):
    if upload.get("Key") != key or str(upload.get("UploadId") or "") != upload_id:
        _cleanup_not_eligible(
            "Multipart inventory does not contain the exact owned upload."
        )
    initiated = _upload_time(upload.get("Initiated"))
    skew = timedelta(seconds=_reconciliation_clock_skew_seconds())
    now = timezone.now().astimezone(datetime_timezone.utc)
    if initiated < operation_started_at - skew or initiated > now + skew:
        _cleanup_not_eligible(
            "Multipart upload falls outside the durable creation time boundary."
        )

    owner_id = _upload_identity(upload, "Owner")
    initiator_id = _upload_identity(upload, "Initiator")
    for observed, baseline_key in (
        (owner_id, "owner_ids"),
        (initiator_id, "initiator_ids"),
    ):
        expected = [str(value) for value in baseline.get(baseline_key) or []]
        if expected and (len(expected) != 1 or observed != expected[0]):
            _cleanup_not_eligible(
                "Multipart upload provider identity differs from the durable baseline."
            )
    return initiated, owner_id, initiator_id


def _head_absent_for_cleanup(client, bucket, key, expected_owner, stored_backup):
    _ensure_upload_fence(stored_backup)
    try:
        head = _head(client, bucket, key, expected_owner)
    except ClientError as error:
        if _error_code(error) in NOT_FOUND_CODES:
            return True
        raise
    if head is not None:
        return False
    return True


def _fresh_cleanup_inventory(client, bucket, key, expected_owner, stored_backup):
    _ensure_upload_fence(stored_backup)
    return _list_exact_uploads(client, bucket, key, expected_owner)


def _complete_multipart_cleanup(
    stored_backup,
    metadata_key,
    state,
    cleanup,
    *,
    result,
):
    cleanup.update(
        {
            "phase": "complete",
            "result": result,
            "completed_at": timezone.now().isoformat(),
        }
    )
    state["multipart_cleanup"] = cleanup
    _save_state(stored_backup, metadata_key, state)
    return cleanup


def _cleanup_inventory_witness(uploads):
    witness = hashlib.sha256()
    for upload in uploads:
        owner = upload.get("Owner")
        initiator = upload.get("Initiator")
        owner_id = owner.get("ID") if isinstance(owner, dict) else "<malformed>"
        initiator_id = (
            initiator.get("ID")
            if isinstance(initiator, dict)
            else "<malformed>"
        )
        witness.update(
            (
                f"{upload.get('Key')}\0{upload.get('UploadId')}\0"
                f"{upload.get('Initiated')}\0"
                f"{owner_id}\0{initiator_id}\n"
            ).encode("utf-8")
        )
    return witness.hexdigest()


def _record_blocked_multipart_cleanup(
    stored_backup,
    metadata_key,
    state,
    *,
    reason,
    uploads=None,
):
    previous = dict(state.get("multipart_cleanup") or {})
    try:
        observation_count = int(previous.get("observation_count") or 0) + 1
    except (TypeError, ValueError):
        observation_count = 1
    observation = {
        "result": str(reason),
        "checked_at": timezone.now().isoformat(),
    }
    if uploads is not None:
        observation["exact_inventory_count"] = len(uploads)
        observation["exact_inventory_sha256"] = _cleanup_inventory_witness(
            uploads
        )
    if previous.get("phase") == "abort_outcome_unknown":
        previous["observation_count"] = observation_count
        previous["last_observation"] = observation
        state["multipart_cleanup"] = previous
        _save_state(stored_backup, metadata_key, state)
        return previous
    cleanup = {
        "version": 1,
        "phase": "blocked",
        "result": str(reason),
        "observation_count": observation_count,
        "last_checked_at": observation["checked_at"],
    }
    if uploads is not None:
        cleanup["exact_inventory_count"] = observation[
            "exact_inventory_count"
        ]
        cleanup["exact_inventory_sha256"] = observation[
            "exact_inventory_sha256"
        ]
    state["multipart_cleanup"] = cleanup
    _save_state(stored_backup, metadata_key, state)
    return cleanup


def cleanup_owned_multipart_upload(
    stored_backup,
    *,
    client,
    bucket,
    metadata_key="s3_object",
    expected_owner=None,
):
    """Abort only one terminal upload whose exact ownership is durably proven."""

    _metadata, state = _state(stored_backup, metadata_key)
    multipart = dict(state.get("multipart") or {})
    key, upload_id, operation_marker, baseline, operation_started_at = (
        _require_cleanup_bindings(
            stored_backup,
            state,
            multipart,
            bucket=bucket,
            expected_owner=expected_owner,
        )
    )
    cleanup = dict(state.get("multipart_cleanup") or {})
    if cleanup.get("phase") == "complete":
        return cleanup
    if cleanup.get("phase") == "abort_rejected":
        _cleanup_not_eligible(
            "A definitive multipart abort rejection requires manual review."
        )

    if not _head_absent_for_cleanup(
        client, bucket, key, expected_owner, stored_backup
    ):
        _record_blocked_multipart_cleanup(
            stored_backup,
            metadata_key,
            state,
            reason="object_present",
        )
        _cleanup_not_eligible(
            "An object exists at the exact multipart key; automatic abort was stopped."
        )
    try:
        uploads = _fresh_cleanup_inventory(
            client, bucket, key, expected_owner, stored_backup
        )
    except S3MalformedMultipartInventory:
        _record_blocked_multipart_cleanup(
            stored_backup,
            metadata_key,
            state,
            reason="malformed_inventory",
        )
        raise

    existing_intent = dict(cleanup.get("intent") or {})
    if cleanup.get("phase") == "abort_outcome_unknown":
        expected_intent = {
            "account_id": str(state["account_id"]),
            "storage_id": str(state["storage_id"]),
            "bucket": bucket,
            "object_key": key,
            "upload_id": upload_id,
            "ownership_marker": str(state["ownership_marker"]),
            "operation_marker": operation_marker,
        }
        if not existing_intent.get("complete") or any(
            str(existing_intent.get(field) or "") != str(value)
            for field, value in expected_intent.items()
        ):
            _cleanup_not_eligible(
                "Multipart abort reconciliation has no exact durable intent."
            )
        if not uploads:
            return _complete_multipart_cleanup(
                stored_backup,
                metadata_key,
                state,
                cleanup,
                result="abort_reconciled",
            )
        if len(uploads) == 1 and str(uploads[0].get("UploadId") or "") == upload_id:
            cleanup["last_checked_at"] = timezone.now().isoformat()
            state["multipart_cleanup"] = cleanup
            _save_state(stored_backup, metadata_key, state)
            raise S3MultipartCleanupPending()
        cleanup["last_checked_at"] = timezone.now().isoformat()
        state["multipart_cleanup"] = cleanup
        _save_state(stored_backup, metadata_key, state)
        raise S3MultipartCleanupPending(
            "Multipart abort remains outcome-unknown because exact-key inventory changed."
        )

    if not uploads:
        try:
            second_inventory = _fresh_cleanup_inventory(
                client, bucket, key, expected_owner, stored_backup
            )
        except S3MalformedMultipartInventory:
            _record_blocked_multipart_cleanup(
                stored_backup,
                metadata_key,
                state,
                reason="malformed_inventory",
            )
            raise
        if second_inventory:
            _record_blocked_multipart_cleanup(
                stored_backup,
                metadata_key,
                state,
                reason="inventory_changed",
                uploads=second_inventory,
            )
            _cleanup_not_eligible(
                "Multipart inventory changed while proving prior provider absence."
            )
        cleanup = {
            "version": 1,
            "phase": "complete",
            "result": "already_absent",
            "completed_at": timezone.now().isoformat(),
        }
        state["multipart_cleanup"] = cleanup
        _save_state(stored_backup, metadata_key, state)
        return cleanup
    if len(uploads) != 1:
        _record_blocked_multipart_cleanup(
            stored_backup,
            metadata_key,
            state,
            reason="exact_inventory_not_unique",
            uploads=uploads,
        )
        _cleanup_not_eligible(
            "Exact-key multipart inventory is foreign or ambiguous; no upload was aborted."
        )

    try:
        initiated, owner_id, initiator_id = _require_owned_cleanup_upload(
            uploads[0],
            key=key,
            upload_id=upload_id,
            baseline=baseline,
            operation_started_at=operation_started_at,
        )
    except S3UploadReconciliationRequired:
        _record_blocked_multipart_cleanup(
            stored_backup,
            metadata_key,
            state,
            reason="provider_ownership_mismatch",
            uploads=uploads,
        )
        raise
    _ensure_upload_fence(stored_backup)
    try:
        parts = _list_parts(client, bucket, key, upload_id, expected_owner)
        part_inventory_sha256 = _multipart_inventory_witness(parts)
    except S3UploadReconciliationRequired:
        _record_blocked_multipart_cleanup(
            stored_backup,
            metadata_key,
            state,
            reason="malformed_part_inventory",
            uploads=uploads,
        )
        raise
    intent = {
        "complete": True,
        "account_id": str(state["account_id"]),
        "storage_id": str(state["storage_id"]),
        "bucket": bucket,
        "expected_bucket_owner": str(expected_owner or ""),
        "object_key": key,
        "upload_id": upload_id,
        "ownership_marker": str(state["ownership_marker"]),
        "operation_marker": operation_marker,
        "initiated_at": initiated.isoformat(),
        "owner_id": owner_id,
        "initiator_id": initiator_id,
        "part_count": len(parts),
        "part_inventory_sha256": part_inventory_sha256,
        "recorded_at": timezone.now().isoformat(),
    }
    cleanup = {
        "version": 1,
        "phase": "abort_outcome_unknown",
        "intent": intent,
        "abort_attempts": 1,
    }
    state["multipart_cleanup"] = cleanup
    _save_state(stored_backup, metadata_key, state)

    abort_args = {"Bucket": bucket, "Key": key, "UploadId": upload_id}
    if expected_owner:
        abort_args["ExpectedBucketOwner"] = expected_owner
    abort_error = None
    try:
        _ensure_upload_fence(stored_backup)
        client.abort_multipart_upload(**abort_args)
    except Exception as error:
        abort_error = error
        if (
            not (isinstance(error, ClientError) and _error_code(error) in NO_UPLOAD_CODES)
            and _create_error_kind(error) != "ambiguous"
        ):
            cleanup.update(
                {
                    "phase": "abort_rejected",
                    "result": "definitive_rejection",
                    "provider_code": _error_code(error),
                    "http_status": _error_status(error),
                    "last_checked_at": timezone.now().isoformat(),
                }
            )
            state["multipart_cleanup"] = cleanup
            _save_state(stored_backup, metadata_key, state)
            raise S3MultipartCleanupNotEligible(
                "Object storage definitively rejected the exact multipart abort."
            ) from error

    remaining = _fresh_cleanup_inventory(
        client, bucket, key, expected_owner, stored_backup
    )
    if not remaining:
        return _complete_multipart_cleanup(
            stored_backup,
            metadata_key,
            state,
            cleanup,
            result="abort_reconciled" if abort_error else "aborted",
        )
    cleanup["last_checked_at"] = timezone.now().isoformat()
    state["multipart_cleanup"] = cleanup
    _save_state(stored_backup, metadata_key, state)
    raise S3MultipartCleanupPending()


def _completion_parts(remote_parts, *, size_bytes, part_size):
    """Validate one exact provider inventory and return its completion payload."""
    total_parts = (int(size_bytes) + int(part_size) - 1) // int(part_size)
    if len(remote_parts) != total_parts:
        raise S3UploadReconciliationRequired(
            "Object storage did not return the complete multipart inventory."
        )
    completed = []
    witness = hashlib.sha256()
    for expected_number, remote in enumerate(remote_parts, start=1):
        try:
            number = int(remote.get("PartNumber"))
            observed_size = int(remote["Size"])
        except (KeyError, TypeError, ValueError) as error:
            raise S3UploadReconciliationRequired(
                "Object storage returned incomplete multipart completion metadata."
            ) from error
        expected_size = min(
            int(part_size),
            int(size_bytes) - ((expected_number - 1) * int(part_size)),
        )
        if number != expected_number or observed_size != expected_size:
            raise S3UploadReconciliationRequired(
                "Object storage multipart inventory does not match the exact object geometry."
            )
        etag = str(remote.get("ETag") or "")
        checksum = str(remote.get("ChecksumSHA256") or "")
        witness.update(
            f"{number}\0{observed_size}\0{etag}\0{checksum}\n".encode("utf-8")
        )
        part = {"PartNumber": number, "ETag": etag}
        if checksum:
            part["ChecksumSHA256"] = checksum
        completed.append(part)
    return completed, witness.hexdigest()


def _checkpoint_multipart_progress(
    stored_backup,
    metadata_key,
    state,
    multipart,
    *,
    completed_parts,
    total_parts,
    uploaded_bytes,
    total_bytes,
):
    previous = dict(multipart.get("progress") or {})
    try:
        previous_parts = int(previous.get("completed_parts") or 0)
        previous_bytes = int(previous.get("uploaded_bytes") or 0)
    except (TypeError, ValueError):
        previous_parts = previous_bytes = 0
    progress = {
        "completed_parts": int(completed_parts),
        "total_parts": int(total_parts),
        "uploaded_bytes": int(uploaded_bytes),
        "total_bytes": int(total_bytes),
        "updated_at": timezone.now().isoformat(),
    }
    if int(completed_parts) > previous_parts or int(uploaded_bytes) > previous_bytes:
        progress["last_progress_at"] = progress["updated_at"]
        progress["window_started_at"] = progress["updated_at"]
    elif previous.get("last_progress_at"):
        progress["last_progress_at"] = previous["last_progress_at"]
        if previous.get("window_started_at"):
            progress["window_started_at"] = previous["window_started_at"]
    if previous.get("no_progress_count"):
        progress["no_progress_count"] = previous["no_progress_count"]
    multipart.pop("parts", None)
    multipart["progress"] = progress
    state["multipart"] = multipart
    _save_state(stored_backup, metadata_key, state)


def _contiguous_remote_progress(remote_parts, *, size_bytes, part_size):
    completed = 0
    uploaded_bytes = 0
    for expected_number, remote in enumerate(remote_parts, start=1):
        try:
            number = int(remote.get("PartNumber"))
            observed_size = int(remote["Size"])
        except (KeyError, TypeError, ValueError):
            break
        expected_size = min(
            int(part_size),
            int(size_bytes) - ((expected_number - 1) * int(part_size)),
        )
        if number != expected_number or observed_size != expected_size:
            break
        completed = expected_number
        uploaded_bytes += observed_size
    return completed, uploaded_bytes


def _maybe_pause_stalled_multipart(
    stored_backup,
    metadata_key,
    state,
    multipart,
    *,
    provider_parts,
    provider_bytes,
    total_parts,
    total_bytes,
):
    progress = dict(multipart.get("progress") or {})
    try:
        durable_parts = int(progress.get("completed_parts") or 0)
        durable_bytes = int(progress.get("uploaded_bytes") or 0)
    except (TypeError, ValueError) as error:
        raise S3UploadReconciliationRequired(
            "Multipart upload progress is malformed."
        ) from error
    if (
        durable_parts < 0
        or durable_parts > int(total_parts)
        or durable_bytes < 0
        or durable_bytes > int(total_bytes)
    ):
        raise S3UploadReconciliationRequired(
            "Multipart upload progress is outside the exact object bounds."
        )
    if provider_parts > durable_parts or provider_bytes > durable_bytes:
        _checkpoint_multipart_progress(
            stored_backup,
            metadata_key,
            state,
            multipart,
            completed_parts=provider_parts,
            total_parts=total_parts,
            uploaded_bytes=provider_bytes,
            total_bytes=total_bytes,
        )
        return
    if provider_parts >= total_parts:
        return
    started_at = progress.get("window_started_at") or progress.get(
        "last_progress_at"
    )
    if not started_at:
        return
    parsed = parse_datetime(str(started_at))
    if parsed is None or timezone.is_naive(parsed):
        raise S3UploadReconciliationRequired(
            "Multipart upload progress has an invalid no-progress timestamp."
        )
    now = timezone.now()
    if (now - parsed).total_seconds() < _multipart_no_progress_seconds():
        return
    try:
        notices = int(progress.get("no_progress_count") or 0) + 1
    except (TypeError, ValueError) as error:
        raise S3UploadReconciliationRequired(
            "Multipart upload no-progress state is malformed."
        ) from error
    progress.update(
        {
            "completed_parts": durable_parts,
            "total_parts": int(total_parts),
            "uploaded_bytes": durable_bytes,
            "total_bytes": int(total_bytes),
            "updated_at": now.isoformat(),
            "window_started_at": now.isoformat(),
            "no_progress_count": notices,
            "last_no_progress_at": now.isoformat(),
        }
    )
    multipart["progress"] = progress
    state.update({"phase": "multipart_no_progress", "multipart": multipart})
    _save_state(stored_backup, metadata_key, state)
    raise S3UploadStalled(
        "Multipart upload made no provider-visible progress within the bounded window.",
        retry_after=_multipart_no_progress_retry_after(),
    )


def _ensure_upload_fence(stored_backup):
    ensure = getattr(stored_backup, "ensure_upload_fence", None)
    if callable(ensure):
        ensure()


def _upload_identity(upload, field):
    value = upload.get(field)
    if value is None:
        return ""
    if not isinstance(value, dict):
        raise S3UploadReconciliationRequired(
            "Object storage returned malformed multipart ownership identity."
        )
    identity = value.get("ID")
    if identity is None:
        return ""
    identity = str(identity).strip()
    if not identity:
        raise S3UploadReconciliationRequired(
            "Object storage returned an empty multipart ownership identity."
        )
    return identity


def _upload_time(value):
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = parse_datetime(value)
    else:
        parsed = None
    if parsed is None or timezone.is_naive(parsed):
        raise S3UploadReconciliationRequired(
            "Object storage did not return a trustworthy multipart initiation time."
        )
    return parsed.astimezone(datetime_timezone.utc)


def _inventory_baseline(uploads, key, operation_started_at):
    upload_ids = []
    owner_ids = set()
    initiator_ids = set()
    for upload in uploads:
        if upload.get("Key") != key:
            raise S3UploadReconciliationRequired(
                "Object storage returned a multipart upload outside the exact object key."
            )
        upload_id = str(upload.get("UploadId") or "").strip()
        if not upload_id:
            raise S3UploadReconciliationRequired(
                "Object storage returned a multipart upload without an upload identity."
            )
        upload_ids.append(upload_id)
        owner_id = _upload_identity(upload, "Owner")
        initiator_id = _upload_identity(upload, "Initiator")
        if owner_id:
            owner_ids.add(owner_id)
        if initiator_id:
            initiator_ids.add(initiator_id)
    return {
        "complete": True,
        "object_key": key,
        "operation_started_at": operation_started_at,
        "preexisting_upload_ids": sorted(set(upload_ids)),
        "owner_ids": sorted(owner_ids),
        "initiator_ids": sorted(initiator_ids),
    }


def _prepare_multipart_baseline(
    stored_backup,
    metadata_key,
    state,
    multipart,
    client,
    bucket,
    key,
    expected_owner,
):
    baseline = dict(multipart.get("create_baseline") or {})
    if baseline.get("complete"):
        if baseline.get("object_key") != key:
            raise S3UploadReconciliationRequired(
                "The durable multipart baseline belongs to a different object key."
            )
        _upload_time(baseline.get("operation_started_at"))
        return baseline

    if state.get("phase") == "creating_multipart":
        raise S3UploadReconciliationRequired(
            "Multipart creation may have started without a complete durable inventory baseline."
        )

    operation_started_at = baseline.get("operation_started_at")
    if operation_started_at:
        _upload_time(operation_started_at)
    else:
        operation_started_at = timezone.now().isoformat()
    baseline = {
        "complete": False,
        "object_key": key,
        "operation_started_at": operation_started_at,
    }
    multipart["create_baseline"] = baseline
    state.update({"phase": "inventorying_multipart", "multipart": multipart})
    _save_state(stored_backup, metadata_key, state)

    uploads = _list_exact_uploads(client, bucket, key, expected_owner)
    baseline = _inventory_baseline(uploads, key, operation_started_at)
    multipart["create_baseline"] = baseline
    state.update({"phase": "multipart_baseline_ready", "multipart": multipart})
    _save_state(stored_backup, metadata_key, state)
    return baseline


def _adopt_new_multipart_upload(
    client,
    bucket,
    key,
    baseline,
    *,
    expected_owner=None,
):
    if not baseline.get("complete") or baseline.get("object_key") != key:
        raise S3UploadReconciliationRequired(
            "Multipart creation cannot be reconciled without an exact durable baseline."
        )
    preexisting = {
        str(upload_id) for upload_id in baseline.get("preexisting_upload_ids") or []
    }
    uploads = _list_exact_uploads(client, bucket, key, expected_owner)
    candidates = []
    for upload in uploads:
        upload_id = str(upload.get("UploadId") or "").strip()
        if not upload_id:
            raise S3UploadReconciliationRequired(
                "Object storage returned a multipart upload without an upload identity."
            )
        if upload_id not in preexisting:
            candidates.append(upload)
    if not candidates:
        raise S3UploadOutcomePending(
            "The multipart creation outcome is still pending provider inventory visibility."
        )
    if len(candidates) > 1:
        raise S3UploadReconciliationRequired(
            "Multiple new unfinished uploads appeared after the durable baseline; "
            "automatic adoption was stopped."
        )

    candidate = candidates[0]
    if candidate.get("Key") != key:
        raise S3UploadReconciliationRequired(
            "The new unfinished upload does not match the exact object key."
        )
    initiated = _upload_time(candidate.get("Initiated"))
    boundary = _upload_time(baseline.get("operation_started_at"))
    skew = timedelta(seconds=_reconciliation_clock_skew_seconds())
    now = timezone.now().astimezone(datetime_timezone.utc)
    if initiated < boundary - skew or initiated > now + skew:
        raise S3UploadReconciliationRequired(
            "The new unfinished upload falls outside the durable operation time boundary."
        )

    owner_id = _upload_identity(candidate, "Owner")
    initiator_id = _upload_identity(candidate, "Initiator")
    for field, observed, baseline_key in (
        ("owner", owner_id, "owner_ids"),
        ("initiator", initiator_id, "initiator_ids"),
    ):
        expected_ids = [str(value) for value in baseline.get(baseline_key) or []]
        if expected_ids and (len(expected_ids) != 1 or observed != expected_ids[0]):
            raise S3UploadReconciliationRequired(
                f"The new unfinished upload has a different provider {field} identity."
            )

    return str(candidate["UploadId"]), {
        "adopted_after_ambiguous_create": True,
        "upload_id": str(candidate["UploadId"]),
        "initiated_at": initiated.isoformat(),
        "owner_id": owner_id,
        "initiator_id": initiator_id,
    }


def _raise_post_create_inventory_failure(error):
    kind = _create_error_kind(error)
    if kind in {"ambiguous", "rate_limit"}:
        raise S3UploadOutcomePending(
            "Multipart creation remains outcome-unknown while provider inventory is unavailable.",
            retry_after=_provider_retry_after(error),
        ) from error
    raise S3UploadInventoryFailure(
        "Multipart inventory was definitively rejected after an ambiguous create; "
        "the durable create boundary remains reconciliation-only.",
        error_code=_inventory_failure_code(error),
    ) from error


def _create_or_adopt_multipart(
    client,
    bucket,
    key,
    create_args,
    *,
    expected_owner=None,
    expected_ownership_marker=None,
    expected_multipart_marker=None,
    baseline=None,
    reconcile_only=False,
):
    if not expected_ownership_marker or not expected_multipart_marker:
        raise S3UploadReconciliationRequired(
            "Multipart adoption requires durable BackupSheep ownership markers."
        )
    create_args = dict(create_args)
    metadata = dict(create_args.get("Metadata") or {})
    metadata[_ownership_metadata_key(expected_ownership_marker)] = str(
        expected_ownership_marker
    )
    metadata[MULTIPART_METADATA] = str(expected_multipart_marker)
    create_args["Metadata"] = metadata
    if expected_owner:
        create_args.setdefault("ExpectedBucketOwner", expected_owner)
    if reconcile_only:
        return _adopt_new_multipart_upload(
            client,
            bucket,
            key,
            baseline or {},
            expected_owner=expected_owner,
        )
    ambiguous_error = None
    try:
        response = client.create_multipart_upload(
            Bucket=bucket,
            Key=key,
            **create_args,
        )
    except Exception as error:
        if _create_error_kind(error) != "ambiguous":
            raise
        ambiguous_error = error
    else:
        upload_id = response.get("UploadId") if isinstance(response, dict) else None
        if isinstance(upload_id, str) and upload_id.strip():
            return upload_id.strip(), None
        # A successful status without the provider upload pointer cannot prove
        # whether creation was accepted. Reconcile against the pre-create
        # boundary exactly as for a lost transport response.

    try:
        return _adopt_new_multipart_upload(
            client,
            bucket,
            key,
            baseline or {},
            expected_owner=expected_owner,
        )
    except S3MalformedMultipartInventory as inventory_error:
        _raise_post_create_inventory_failure(inventory_error)
    except S3UploadReconciliationRequired as reconciliation_error:
        if ambiguous_error is not None:
            raise reconciliation_error from ambiguous_error
        raise
    except Exception as inventory_error:
        _raise_post_create_inventory_failure(inventory_error)


def _record_definitive_multipart_rejection(
    stored_backup,
    metadata_key,
    state,
    multipart,
    baseline,
    error,
):
    kind = _create_error_kind(error)
    state["multipart_create_rejection"] = {
        "result": "definitive_rejection",
        "kind": kind,
        "provider_code": _error_code(error),
        "http_status": _error_status(error),
        "retryable": kind == "rate_limit",
        "recorded_at": timezone.now().isoformat(),
        "operation_marker": multipart.get("operation_marker"),
        "create_baseline": dict(baseline),
    }
    # Preserve the rejected attempt and its complete boundary above, while
    # retiring only active create-attempt fields. A subsequent delivery must
    # inventory again and establish a fresh boundary before another mutation.
    reset_multipart = dict(multipart)
    reset_multipart.pop("operation_marker", None)
    reset_multipart.pop("create_baseline", None)
    reset_multipart.pop("upload_id", None)
    reset_multipart.pop("parts", None)
    state.update(
        {
            "phase": "multipart_create_rejected",
            "multipart": reset_multipart,
        }
    )
    _save_state(stored_backup, metadata_key, state)


def _persist_multipart_create_pending(
    stored_backup,
    metadata_key,
    state,
    multipart,
    baseline,
    error,
):
    baseline = dict(baseline)
    baseline.setdefault("first_pending_at", timezone.now().isoformat())
    multipart["create_baseline"] = baseline
    state["multipart"] = multipart
    _persist_and_raise_outcome_pending(
        stored_backup,
        metadata_key,
        state,
        baseline,
        pending_phase="creating_multipart",
        exhausted_phase="multipart_create_reconciliation_exhausted",
        pending_message=(
            "The multipart creation outcome is pending provider inventory visibility."
        ),
        exhausted_message=(
            "Multipart creation remained invisible beyond the bounded reconciliation window; "
            "automatic writes were stopped safely."
        ),
        cause=error,
    )


def _record_definitive_put_rejection(
    stored_backup,
    metadata_key,
    state,
    intent,
    error,
):
    kind = _create_error_kind(error)
    state["put_rejection"] = {
        "result": "definitive_rejection",
        "kind": kind,
        "provider_code": _error_code(error),
        "http_status": _error_status(error),
        "retryable": kind == "rate_limit",
        "recorded_at": timezone.now().isoformat(),
        "intent": dict(intent),
    }
    state.pop("put_intent", None)
    state["phase"] = "put_rejected"
    _save_state(stored_backup, metadata_key, state)


def _persist_put_pending(
    stored_backup,
    metadata_key,
    state,
    intent,
    error=None,
):
    intent = dict(intent)
    intent.setdefault("first_pending_at", timezone.now().isoformat())
    state["put_intent"] = intent
    _persist_and_raise_outcome_pending(
        stored_backup,
        metadata_key,
        state,
        intent,
        pending_phase="put_outcome_unknown",
        exhausted_phase="put_reconciliation_exhausted",
        pending_message=(
            "The object upload outcome is pending exact provider visibility."
        ),
        exhausted_message=(
            "The object upload remained invisible beyond the bounded reconciliation window; "
            "automatic writes were stopped safely."
        ),
        cause=error,
    )


def _record_definitive_multipart_completion_rejection(
    stored_backup,
    metadata_key,
    state,
    multipart,
    intent,
    error,
):
    kind = _create_error_kind(error)
    state["multipart_complete_rejection"] = {
        "result": "definitive_rejection",
        "kind": kind,
        "provider_code": _error_code(error),
        "http_status": _error_status(error),
        "retryable": kind == "rate_limit",
        "recorded_at": timezone.now().isoformat(),
        "intent": dict(intent),
    }
    multipart = dict(multipart)
    multipart.pop("complete_intent", None)
    state.update(
        {
            "phase": "multipart_complete_rejected",
            "multipart": multipart,
        }
    )
    _save_state(stored_backup, metadata_key, state)


def _persist_multipart_completion_pending(
    stored_backup,
    metadata_key,
    state,
    multipart,
    intent,
    error=None,
):
    intent = dict(intent)
    intent.setdefault("first_pending_at", timezone.now().isoformat())
    multipart["complete_intent"] = intent
    state["multipart"] = multipart
    _persist_and_raise_outcome_pending(
        stored_backup,
        metadata_key,
        state,
        intent,
        pending_phase="multipart_complete_outcome_unknown",
        exhausted_phase="multipart_complete_reconciliation_exhausted",
        pending_message=(
            "Multipart completion is pending exact object visibility."
        ),
        exhausted_message=(
            "Multipart completion remained invisible beyond the bounded reconciliation "
            "window; automatic writes were stopped safely."
        ),
        cause=error,
    )


def _multipart_upload(
    stored_backup,
    metadata_key,
    client,
    bucket,
    key,
    local_path,
    identity,
    create_args,
    *,
    expected_owner=None,
    supports_checksum=False,
):
    create_args = dict(create_args)
    if supports_checksum:
        create_args.setdefault("ChecksumAlgorithm", "SHA256")
    metadata, state = _state(stored_backup, metadata_key)
    if state.get("phase") in {
        "multipart_create_reconciliation_exhausted",
        "multipart_complete_reconciliation_exhausted",
    }:
        raise S3UploadReconciliationRequired(
            "Multipart upload reconciliation already exhausted its bounded window; "
            "automatic writes remain stopped."
        )
    multipart = dict(state.get("multipart") or {})
    upload_id = multipart.get("upload_id")
    persisted_part_size = multipart.get("part_size_bytes")
    part_size = (
        _validated_multipart_geometry(
            identity["size_bytes"], persisted_part_size, state=True
        )
        if persisted_part_size is not None
        else None
    )
    if state.get("phase") == "multipart_complete_outcome_unknown":
        if not upload_id:
            raise S3UploadReconciliationRequired(
                "Multipart completion outcome is unknown without a durable upload identity."
            )
        intent = dict(multipart.get("complete_intent") or {})
        _require_exact_outcome_intent(
            intent,
            key=key,
            identity=identity,
            ownership_marker=state["ownership_marker"],
            upload_id=upload_id,
        )
        # upload_verified_s3 already performed the only safe operation for this
        # delivery: an exact HEAD. Never inspect/recreate the upload after the
        # completion mutation may have reached the provider.
        _persist_multipart_completion_pending(
            stored_backup,
            metadata_key,
            state,
            multipart,
            intent,
        )
    if upload_id:
        try:
            remote_parts = _list_parts(
                client, bucket, key, upload_id, expected_owner
            )
        except ClientError as error:
            if _error_code(error) not in NO_UPLOAD_CODES:
                raise
            if state.get("phase") == "multipart_complete_rejected":
                raise S3UploadReconciliationRequired(
                    "The rejected multipart completion no longer has a provider upload; "
                    "automatic recreation was stopped safely."
                ) from error
            # NoSuchUpload cannot distinguish expiry/abort from an accepted
            # completion whose object is not visible yet. Fence this legacy or
            # mid-upload ambiguity into bounded HEAD-only reconciliation.
            missing_intent = dict(multipart.get("complete_intent") or {})
            if not missing_intent.get("complete"):
                legacy_parts = list(multipart.get("parts") or [])
                missing_intent = _new_outcome_intent(
                    key,
                    identity,
                    state["ownership_marker"],
                    upload_id=str(upload_id),
                    part_count=int(
                        dict(multipart.get("progress") or {}).get(
                            "completed_parts", len(legacy_parts)
                        )
                        or 0
                    ),
                    inferred_from_missing_upload=True,
                )
            _require_exact_outcome_intent(
                missing_intent,
                key=key,
                identity=identity,
                ownership_marker=state["ownership_marker"],
                upload_id=upload_id,
            )
            _persist_multipart_completion_pending(
                stored_backup,
                metadata_key,
                state,
                multipart,
                missing_intent,
                error,
            )
    else:
        remote_parts = []

    if not upload_id:
        multipart = dict(multipart)
        if part_size is None:
            part_size = _multipart_part_size(identity["size_bytes"])
            multipart["part_size_bytes"] = part_size
        multipart.setdefault("operation_marker", uuid.uuid4().hex)
        existing_baseline = dict(multipart.get("create_baseline") or {})
        reconcile_only = (
            state.get("phase") == "creating_multipart"
            and existing_baseline.get("complete")
        )
        baseline = _prepare_multipart_baseline(
            stored_backup,
            metadata_key,
            state,
            multipart,
            client,
            bucket,
            key,
            expected_owner,
        )
        state["multipart"] = multipart
        state["phase"] = "creating_multipart"
        _save_state(stored_backup, metadata_key, state)
        try:
            upload_id, adoption = _create_or_adopt_multipart(
                client,
                bucket,
                key,
                create_args,
                expected_owner=expected_owner,
                expected_ownership_marker=state["ownership_marker"],
                expected_multipart_marker=multipart["operation_marker"],
                baseline=baseline,
                reconcile_only=reconcile_only,
            )
        except S3UploadOutcomePending as error:
            _persist_multipart_create_pending(
                stored_backup,
                metadata_key,
                state,
                multipart,
                baseline,
                error,
            )
        except S3UploadReconciliationRequired:
            # Duplicate, foreign, stale, malformed-cursor, and other unsafe
            # reconciliation results remain manual-review terminal states.
            raise
        except Exception as error:
            if not reconcile_only and _create_error_kind(error) != "ambiguous":
                _record_definitive_multipart_rejection(
                    stored_backup,
                    metadata_key,
                    state,
                    multipart,
                    baseline,
                    error,
                )
            raise
        multipart = {
            **multipart,
            "upload_id": upload_id,
            "creation_proof": {
                "version": 1,
                "result": (
                    "baseline_adoption" if adoption else "provider_response"
                ),
                "upload_id": str(upload_id),
                "operation_marker": multipart["operation_marker"],
                "recorded_at": timezone.now().isoformat(),
            },
        }
        multipart.pop("parts", None)
        if adoption:
            state["multipart_reconciliation"] = adoption
        state.update({"phase": "uploading", "multipart": multipart})
        _save_state(stored_backup, metadata_key, state)
        remote_parts = _list_parts(client, bucket, key, upload_id, expected_owner)

    if part_size is None:
        part_size = _legacy_multipart_part_size(
            identity["size_bytes"], remote_parts
        )
        multipart["part_size_bytes"] = part_size
        state["multipart"] = multipart
        _save_state(stored_backup, metadata_key, state)
    elif multipart.get("parts"):
        # Migrate pre-bounded progress state after exact provider inventory is
        # available. Provider state, not the legacy JSON ETag list, is authoritative.
        multipart.pop("parts", None)
        state["multipart"] = multipart
        _save_state(stored_backup, metadata_key, state)
    remote_by_number = {int(part["PartNumber"]): part for part in remote_parts}
    total_parts = (identity["size_bytes"] + part_size - 1) // part_size
    provider_parts, provider_bytes = _contiguous_remote_progress(
        remote_parts,
        size_bytes=identity["size_bytes"],
        part_size=part_size,
    )
    _maybe_pause_stalled_multipart(
        stored_backup,
        metadata_key,
        state,
        multipart,
        provider_parts=provider_parts,
        provider_bytes=provider_bytes,
        total_parts=total_parts,
        total_bytes=identity["size_bytes"],
    )
    if state.get("phase") != "uploading":
        state["phase"] = "uploading"
        state["multipart"] = multipart
        _save_state(stored_backup, metadata_key, state)
    checkpoint_parts = _multipart_checkpoint_parts()
    checkpoint_due = False
    processed_bytes = 0
    with open(local_path, "rb") as source:
        for number in range(1, total_parts + 1):
            offset = (number - 1) * part_size
            expected_size = min(
                part_size, identity["size_bytes"] - offset
            )
            remote = remote_by_number.get(number)
            try:
                remote_size = int(remote["Size"]) if remote else None
            except (KeyError, TypeError, ValueError):
                remote_size = None
            if remote_size != expected_size:
                part_checksum = (
                    _hash_file_range(source, offset, expected_size)
                    if supports_checksum
                    else None
                )
                upload_args = {
                    "Bucket": bucket,
                    "Key": key,
                    "UploadId": upload_id,
                    "PartNumber": number,
                    "Body": _BoundedPartBody(source, offset, expected_size),
                }
                if supports_checksum:
                    upload_args["ChecksumSHA256"] = part_checksum
                if expected_owner:
                    upload_args["ExpectedBucketOwner"] = expected_owner
                _ensure_upload_fence(stored_backup)
                response = client.upload_part(**upload_args)
                if not isinstance(response, dict) or not str(
                    response.get("ETag") or ""
                ).strip():
                    raise S3UploadReconciliationRequired(
                        "Object storage did not return a valid uploaded-part identity."
                    )
            processed_bytes += expected_size
            checkpoint_due = checkpoint_due or number % checkpoint_parts == 0
            if checkpoint_due:
                _checkpoint_multipart_progress(
                    stored_backup,
                    metadata_key,
                    state,
                    multipart,
                    completed_parts=number,
                    total_parts=total_parts,
                    uploaded_bytes=processed_bytes,
                    total_bytes=identity["size_bytes"],
                )
                checkpoint_due = False

    progress = dict(multipart.get("progress") or {})
    if (
        int(progress.get("completed_parts") or 0) != total_parts
        or int(progress.get("uploaded_bytes") or 0) != identity["size_bytes"]
    ):
        _checkpoint_multipart_progress(
            stored_backup,
            metadata_key,
            state,
            multipart,
            completed_parts=total_parts,
            total_parts=total_parts,
            uploaded_bytes=identity["size_bytes"],
            total_bytes=identity["size_bytes"],
        )

    # Completion is based only on one fresh, ordered provider inventory. The
    # durable row stores a bounded witness, never the growing ETag collection.
    final_remote_parts = _list_parts(
        client, bucket, key, upload_id, expected_owner
    )
    completed, part_inventory_sha256 = _completion_parts(
        final_remote_parts,
        size_bytes=identity["size_bytes"],
        part_size=part_size,
    )

    complete_args = {
        "Bucket": bucket,
        "Key": key,
        "UploadId": upload_id,
        "MultipartUpload": {"Parts": completed},
    }
    if expected_owner:
        complete_args["ExpectedBucketOwner"] = expected_owner

    complete_intent = _new_outcome_intent(
        key,
        identity,
        state["ownership_marker"],
        upload_id=str(upload_id),
        part_count=len(completed),
        uploaded_bytes=identity["size_bytes"],
        part_inventory_sha256=part_inventory_sha256,
    )
    multipart["complete_intent"] = complete_intent
    state.update(
        {
            "phase": "multipart_complete_outcome_unknown",
            "multipart": multipart,
        }
    )
    _save_state(stored_backup, metadata_key, state)
    try:
        _ensure_upload_fence(stored_backup)
        client.complete_multipart_upload(**complete_args)
    except Exception as error:
        if _create_error_kind(error) != "ambiguous":
            _record_definitive_multipart_completion_rejection(
                stored_backup,
                metadata_key,
                state,
                multipart,
                complete_intent,
                error,
            )
            raise
        head = verified_head(
            client,
            bucket,
            key,
            identity,
            expected_owner=expected_owner,
            expected_ownership_marker=state["ownership_marker"],
        )
        if head is None:
            _persist_multipart_completion_pending(
                stored_backup,
                metadata_key,
                state,
                multipart,
                complete_intent,
                error,
            )
    else:
        head = verified_head(
            client,
            bucket,
            key,
            identity,
            expected_owner=expected_owner,
            expected_ownership_marker=state["ownership_marker"],
        )
        if head is None:
            _persist_multipart_completion_pending(
                stored_backup,
                metadata_key,
                state,
                multipart,
                complete_intent,
            )
    state["phase"] = "verifying"
    _save_state(stored_backup, metadata_key, state)
    return head


def upload_verified_s3(
    stored_backup,
    *,
    client,
    bucket,
    key,
    local_path,
    metadata_key="s3_object",
    expected_owner=None,
    extra_args: Optional[Dict] = None,
    supports_checksum=False,
):
    """Upload/adopt one deterministic object and persist its verified identity.

    The function returns only after a provider HEAD proves the exact byte count and
    SHA-256. Large objects persist multipart upload IDs and each accepted part so a
    worker crash can continue rather than starting another upload.
    """

    artifact_identity = validate_storage_object_key(stored_backup.backup, key)
    if os.path.basename(os.fspath(local_path)) != artifact_identity.filename:
        raise S3ObjectIntegrityError(
            "The local upload path is not bound to its artifact identity."
        )
    identity = file_identity(local_path)
    metadata, state = _state(stored_backup, metadata_key)
    state_was_empty = not state
    bucket, legacy_bucket_unbound = _bind_exact_bucket(state, bucket)
    _bind_exact_storage_context(stored_backup, state, expected_owner)
    previous_sha256 = state.get("sha256")
    previous_size = state.get("size_bytes")
    if previous_sha256 and previous_sha256 != identity["sha256"]:
        raise S3ObjectIntegrityError(
            "The local backup changed after this upload operation started."
        )
    if previous_size is not None and int(previous_size) != identity["size_bytes"]:
        raise S3ObjectIntegrityError(
            "The local backup size changed after this upload operation started."
        )
    # A retry must continue the exact object selected by the first attempt. This
    # also preserves restorable objects created by older BackupSheep versions whose
    # prefix policy differed from the current storage configuration.
    key = state.get("object_key") or stored_backup.storage_file_id or key
    artifact_identity = validate_storage_object_key(stored_backup.backup, key)
    expected_ownership_marker = artifact_identity.ownership_marker
    persisted_marker = str(state.get("ownership_marker") or "")
    if not state_was_empty and persisted_marker != expected_ownership_marker:
        raise S3ObjectIntegrityError(
            "The durable object state belongs to a different backup."
        )

    head = None
    if legacy_bucket_unbound:
        if (
            str(state.get("phase") or "").lower() != "committed"
            or not state.get("object_key")
            or previous_sha256 != identity["sha256"]
            or previous_size is None
            or "version_id" not in state
            or str(state.get("checksum_algorithm") or "sha256").lower()
            != "sha256"
        ):
            raise S3UploadReconciliationRequired(
                "Legacy upload state cannot prove a committed read-only object; "
                "automatic provider writes were stopped safely."
            )
        state["version_id"] = _normalise_version_id(state.get("version_id"))
        head = verified_head(
            client,
            bucket,
            key,
            identity,
            expected_owner=expected_owner,
            expected_ownership_marker=expected_ownership_marker,
            version_id=state["version_id"],
            version_id_known=True,
        )
        if head is None:
            raise S3UploadReconciliationRequired(
                "The legacy committed object could not be proven in the configured bucket; "
                "automatic provider writes were stopped safely."
            )
        # This is the only legacy adoption mutation: persist the bucket after an
        # exact authenticated read. No provider write is permitted before proof.
        state["bucket"] = bucket

    state.update(
        {
            "object_key": key,
            "sha256": identity["sha256"],
            "size_bytes": identity["size_bytes"],
            "checksum_algorithm": "sha256",
            "ownership_marker": expected_ownership_marker,
        }
    )
    _save_state(stored_backup, metadata_key, state)

    version_id_known = "version_id" in state
    if version_id_known:
        state["version_id"] = _normalise_version_id(state.get("version_id"))

    if head is None:
        head = verified_head(
            client,
            bucket,
            key,
            identity,
            expected_owner=expected_owner,
            expected_ownership_marker=expected_ownership_marker,
            version_id=state.get("version_id"),
            version_id_known=version_id_known,
        )
    if head is None:
        phase = state.get("phase")
        if phase == "committed":
            raise S3ObjectIntegrityError(
                "The committed object version is no longer available from storage."
            )
        if phase == "verifying":
            put_intent = dict(state.get("put_intent") or {})
            multipart = dict(state.get("multipart") or {})
            complete_intent = dict(multipart.get("complete_intent") or {})
            if put_intent.get("complete") and complete_intent.get("complete"):
                raise S3UploadReconciliationRequired(
                    "Conflicting durable upload intents require manual review."
                )
            if put_intent.get("complete"):
                _require_exact_outcome_intent(
                    put_intent,
                    key=key,
                    identity=identity,
                    ownership_marker=expected_ownership_marker,
                )
                _persist_put_pending(
                    stored_backup,
                    metadata_key,
                    state,
                    put_intent,
                )
            if complete_intent.get("complete"):
                upload_id = multipart.get("upload_id")
                if not upload_id:
                    raise S3UploadReconciliationRequired(
                        "Multipart verification lost its durable upload identity."
                    )
                _require_exact_outcome_intent(
                    complete_intent,
                    key=key,
                    identity=identity,
                    ownership_marker=expected_ownership_marker,
                    upload_id=upload_id,
                )
                _persist_multipart_completion_pending(
                    stored_backup,
                    metadata_key,
                    state,
                    multipart,
                    complete_intent,
                )
            raise S3UploadReconciliationRequired(
                "Object verification has no durable provider mutation intent; "
                "automatic writes were stopped safely."
            )
        if phase == "uploading" and not state.get("multipart"):
            # Older single-part state did not fence the PUT boundary. Repeating
            # it cannot be proven safe in a versioned bucket.
            raise S3UploadReconciliationRequired(
                "A legacy single-part upload may have reached storage without a "
                "durable intent; automatic replay was stopped safely."
            )

        args = dict(extra_args or {})
        unexpected_args = set(args) - _ALLOWED_UPLOAD_EXTRA_ARGS
        if unexpected_args:
            raise S3ObjectIntegrityError(
                "The object upload contains unsupported provider-visible arguments."
            )
        user_metadata = {
            SHA256_METADATA: identity["sha256"],
            SIZE_METADATA: str(identity["size_bytes"]),
            _ownership_metadata_key(
                expected_ownership_marker
            ): expected_ownership_marker,
        }
        args["ContentType"] = artifact_identity.content_type
        args["Metadata"] = user_metadata
        threshold = int(
            getattr(settings, "S3_MULTIPART_THRESHOLD_BYTES", 8 * 1024 * 1024)
        )
        durable_put = bool(state.get("put_intent")) or str(phase or "").startswith(
            "put_"
        )
        durable_multipart = bool(state.get("multipart")) or str(
            phase or ""
        ).startswith("multipart_")
        if durable_put and durable_multipart:
            raise S3UploadReconciliationRequired(
                "Conflicting single-part and multipart state requires manual review."
            )
        use_multipart = (
            durable_multipart
            if durable_multipart or durable_put
            else identity["size_bytes"] >= threshold
        )
        if use_multipart:
            head = _multipart_upload(
                stored_backup,
                metadata_key,
                client,
                bucket,
                key,
                local_path,
                identity,
                args,
                expected_owner=expected_owner,
                supports_checksum=supports_checksum,
            )
            _, state = _state(stored_backup, metadata_key)
        else:
            put_args = {"Bucket": bucket, "Key": key, **args}
            if expected_owner:
                put_args["ExpectedBucketOwner"] = expected_owner
            if supports_checksum:
                put_args["ChecksumSHA256"] = identity["sha256_base64"]
            if state.get("phase") == "put_reconciliation_exhausted":
                raise S3UploadReconciliationRequired(
                    "Object upload reconciliation already exhausted its bounded window; "
                    "automatic writes remain stopped."
                )
            if state.get("phase") == "put_outcome_unknown":
                put_intent = dict(state.get("put_intent") or {})
                _require_exact_outcome_intent(
                    put_intent,
                    key=key,
                    identity=identity,
                    ownership_marker=expected_ownership_marker,
                )
                # The initial exact HEAD for this delivery missed. The durable
                # intent fences the provider mutation, so this delivery may only
                # report pending visibility and must never issue another PUT.
                _persist_put_pending(
                    stored_backup,
                    metadata_key,
                    state,
                    put_intent,
                )

            put_intent = _new_outcome_intent(
                key,
                identity,
                expected_ownership_marker,
            )
            state["put_intent"] = put_intent
            state["phase"] = "put_outcome_unknown"
            _save_state(stored_backup, metadata_key, state)
            try:
                with open(local_path, "rb") as source:
                    client.put_object(Body=source, **put_args)
            except Exception as error:
                if _create_error_kind(error) != "ambiguous":
                    _record_definitive_put_rejection(
                        stored_backup,
                        metadata_key,
                        state,
                        put_intent,
                        error,
                    )
                    raise
                head = verified_head(
                    client,
                    bucket,
                    key,
                    identity,
                    expected_owner=expected_owner,
                    expected_ownership_marker=expected_ownership_marker,
                )
                if head is None:
                    _persist_put_pending(
                        stored_backup,
                        metadata_key,
                        state,
                        put_intent,
                        error,
                    )
            else:
                head = verified_head(
                    client,
                    bucket,
                    key,
                    identity,
                    expected_owner=expected_owner,
                    expected_ownership_marker=expected_ownership_marker,
                )
                if head is None:
                    _persist_put_pending(
                        stored_backup,
                        metadata_key,
                        state,
                        put_intent,
                    )

        state["phase"] = "verifying"
        _save_state(
            stored_backup,
            metadata_key,
            state,
            status=stored_backup.Status.UPLOAD_VALIDATION,
        )
        if head is None:
            head = verified_head(
                client,
                bucket,
                key,
                identity,
                expected_owner=expected_owner,
                expected_ownership_marker=expected_ownership_marker,
            )
    if head is None:
        raise S3ObjectIntegrityError(
            "Object storage did not return a verified copy of the uploaded backup."
        )

    state.update(
        {
            "phase": "committed",
            "etag": head.get("ETag"),
            # S3-compatible providers commonly omit VersionId when bucket
            # versioning is unavailable. Persist one canonical explicit
            # unavailable value so reconciliation never flips between null and
            # an empty string across worker retries.
            "version_id": str(head.get("VersionId") or ""),
            "provider_checksum_sha256": head.get("ChecksumSHA256"),
        }
    )
    state.pop("multipart", None)
    state.pop("put_intent", None)
    _save_state(
        stored_backup,
        metadata_key,
        state,
        status=stored_backup.Status.UPLOAD_VALIDATION,
    )
    stored_backup.backup.record_artifact_integrity(
        role="destination",
        object_key=key,
        byte_count=identity["size_bytes"],
        storage=stored_backup.storage,
        checksum_algorithm="sha256",
        checksum_value=identity["sha256"],
        etag=head.get("ETag") or "",
        version_id=head.get("VersionId") or "",
        verified_at=timezone.now(),
        metadata={
            "provider_checksum_sha256": head.get("ChecksumSHA256"),
            "storage_metadata_key": metadata_key,
        },
    )
    _save_state(
        stored_backup,
        metadata_key,
        state,
        status=stored_backup.Status.UPLOAD_COMPLETE,
    )
    return state
