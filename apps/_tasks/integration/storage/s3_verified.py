"""Crash-safe, resumable uploads for S3 and compatible object stores."""

from __future__ import annotations

import base64
import hashlib
import math
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


SHA256_METADATA = "backupsheep-sha256"
SIZE_METADATA = "backupsheep-bytes"
BACKUP_METADATA = "backupsheep-backup-id"
MULTIPART_METADATA = "backupsheep-multipart-id"
NOT_FOUND_CODES = {"404", "NoSuchKey", "NotFound", "NoSuchBucket"}
NO_UPLOAD_CODES = {"NoSuchUpload", "404", "NotFound"}

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


class S3ObjectIntegrityError(RuntimeError):
    pass


class S3UploadReconciliationRequired(RuntimeError):
    outcome_kind = "ambiguous"


class S3UploadOutcomePending(S3UploadReconciliationRequired):
    """A provider mutation may have succeeded but is not visible yet."""

    error_code = "STORAGE_RECONCILIATION_PENDING"
    code = error_code
    retryable = True
    outcome_kind = "ambiguous"

    def __init__(self, message, *, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after or _outcome_reconciliation_retry_after()


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
    marker = _metadata_value(head, BACKUP_METADATA)
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
        uploads.extend(
            item for item in (payload.get("Uploads") or []) if item.get("Key") == key
        )
        if len(uploads) > max_items:
            raise S3UploadReconciliationRequired(
                "Object storage multipart inventory exceeded the reconciliation item limit."
            )
        if not payload.get("IsTruncated"):
            break
        next_key = payload.get("NextKeyMarker")
        next_upload = payload.get("NextUploadIdMarker")
        if (next_key, next_upload) == (key_marker, upload_marker):
            raise S3UploadReconciliationRequired(
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
    marker = 0
    max_parts = _reconciliation_max_parts()
    while True:
        payload = client.list_parts(**args, PartNumberMarker=marker)
        parts.extend(payload.get("Parts") or [])
        if len(parts) > max_parts:
            raise S3UploadReconciliationRequired(
                "Object storage multipart parts exceeded the reconciliation item limit."
            )
        if not payload.get("IsTruncated"):
            return parts
        next_marker = int(payload.get("NextPartNumberMarker") or 0)
        if next_marker <= marker:
            raise S3UploadReconciliationRequired(
                "Object storage returned a non-advancing part cursor."
            )
        marker = next_marker


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
    metadata[BACKUP_METADATA] = str(expected_ownership_marker)
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
                missing_intent = _new_outcome_intent(
                    key,
                    identity,
                    state["ownership_marker"],
                    upload_id=str(upload_id),
                    parts=[dict(part) for part in multipart.get("parts") or []],
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
            "parts": [],
        }
        if adoption:
            state["multipart_reconciliation"] = adoption
        state.update({"phase": "uploading", "multipart": multipart})
        _save_state(stored_backup, metadata_key, state)
        remote_parts = _list_parts(client, bucket, key, upload_id, expected_owner)

    part_size = max(
        5 * 1024 * 1024,
        int(getattr(settings, "S3_MULTIPART_PART_SIZE_BYTES", 8 * 1024 * 1024)),
    )
    remote_by_number = {int(part["PartNumber"]): part for part in remote_parts}
    total_parts = int(math.ceil(identity["size_bytes"] / part_size))
    completed = []
    with open(local_path, "rb") as source:
        for number in range(1, total_parts + 1):
            expected_size = min(
                part_size, identity["size_bytes"] - ((number - 1) * part_size)
            )
            remote = remote_by_number.get(number)
            if remote and int(remote.get("Size", expected_size)) == expected_size:
                completed_part = {
                    "PartNumber": number,
                    "ETag": remote["ETag"],
                }
                if remote.get("ChecksumSHA256"):
                    completed_part["ChecksumSHA256"] = remote["ChecksumSHA256"]
                completed.append(completed_part)
                continue
            source.seek((number - 1) * part_size)
            body = source.read(expected_size)
            part_checksum = base64.b64encode(
                hashlib.sha256(body).digest()
            ).decode("ascii")
            upload_args = {
                "Bucket": bucket,
                "Key": key,
                "UploadId": upload_id,
                "PartNumber": number,
                "Body": body,
            }
            if supports_checksum:
                upload_args["ChecksumSHA256"] = part_checksum
            if expected_owner:
                upload_args["ExpectedBucketOwner"] = expected_owner
            response = client.upload_part(**upload_args)
            completed_part = {
                "PartNumber": number,
                "ETag": response["ETag"],
            }
            if response.get("ChecksumSHA256"):
                completed_part["ChecksumSHA256"] = response["ChecksumSHA256"]
            completed.append(completed_part)
            multipart["parts"] = completed
            multipart["uploaded_bytes"] = min(
                number * part_size, identity["size_bytes"]
            )
            state["multipart"] = multipart
            _save_state(stored_backup, metadata_key, state)

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
        parts=[dict(part) for part in completed],
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

    identity = file_identity(local_path)
    metadata, state = _state(stored_backup, metadata_key)
    state_was_empty = not state
    bucket, legacy_bucket_unbound = _bind_exact_bucket(state, bucket)
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
    expected_ownership_marker = str(stored_backup.backup_id)
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
        user_metadata = {
            str(k): str(v) for k, v in dict(args.pop("Metadata", {}) or {}).items()
        }
        user_metadata.update(
            {
                SHA256_METADATA: identity["sha256"],
                SIZE_METADATA: str(identity["size_bytes"]),
                BACKUP_METADATA: str(stored_backup.backup_id),
            }
        )
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
