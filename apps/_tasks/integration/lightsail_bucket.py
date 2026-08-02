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
import uuid
from datetime import timedelta
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from celery import current_app
from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.console.backup.replication_models import (
    CoreLightsailBucketReplication,
    CoreLightsailBucketReplicationLease,
    CoreLightsailBucketReplicationMultipart,
    CoreLightsailBucketReplicationObject,
    CoreLightsailBucketReplicationRun,
    CoreLightsailBucketRestoreRun,
)
from apps.console.storage.models import CoreStorage


DEFAULT_PART_SIZE = 64 * 1024 * 1024
DEFAULT_LEASE_SECONDS = 15 * 60
MANIFEST_DIRECTORY = ".backupsheep/manifests/"


class LightsailBucketReplicationError(RuntimeError):
    """Base error for a replication that can be retried from durable state."""


class UnsupportedStorageProvider(LightsailBucketReplicationError, ValueError):
    """Raised when a CoreStorage relation is not S3-compatible for this lane."""


class LeaseUnavailable(LightsailBucketReplicationError):
    """Another worker currently owns the object/restore lease."""


class LeaseLost(LightsailBucketReplicationError):
    """The current worker's lease expired or was recovered by another worker."""


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
    }


def _list_current_objects(client, bucket_name: str, prefix: str = "") -> List[Dict[str, Any]]:
    """List current objects using list_objects_v2 with durable pagination."""

    entries: List[Dict[str, Any]] = []
    token = None
    while True:
        kwargs: Dict[str, Any] = {"Bucket": bucket_name}
        if prefix:
            kwargs["Prefix"] = prefix
        if token:
            kwargs["ContinuationToken"] = token
        response = client.list_objects_v2(**kwargs)
        entries.extend(
            _raw_object_entry(item)
            for item in (response.get("Contents") or [])
            if item.get("Key") is not None
        )
        if not response.get("IsTruncated"):
            break
        next_token = response.get("NextContinuationToken")
        if not next_token or next_token == token:
            break
        token = next_token
    return entries


def list_source_objects(
    client,
    bucket_name: str,
    prefix: str = "",
    include_versions: bool = True,
) -> List[Dict[str, Any]]:
    """Return normalized source rows, preserving versions and delete markers.

    Version listing uses both ``Versions`` and ``DeleteMarkers`` from each S3 page,
    and paginates with the pair of key/version markers.  Providers that expose only
    the current-object API get an explicit fallback to ``list_objects_v2``; a
    different client error is surfaced so an unavailable bucket is not mistaken for
    an unversioned bucket.
    """

    normalized_prefix = _normalize_prefix(prefix)
    if not include_versions:
        return _list_current_objects(client, bucket_name, normalized_prefix)

    entries: List[Dict[str, Any]] = []
    key_marker = None
    version_id_marker = None
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
            entries.extend(
                _raw_object_entry(item)
                for item in (response.get("Versions") or [])
                if item.get("Key") is not None
            )
            entries.extend(
                _raw_object_entry(item, delete_marker=True)
                for item in (response.get("DeleteMarkers") or [])
                if item.get("Key") is not None
            )
            if not response.get("IsTruncated"):
                break
            next_key = response.get("NextKeyMarker")
            next_version = response.get("NextVersionIdMarker")
            if not next_key and not next_version:
                break
            if (next_key, next_version) == (key_marker, version_id_marker):
                break
            key_marker, version_id_marker = next_key, next_version
    except Exception as error:
        if not _version_listing_unsupported(error):
            raise
        return _list_current_objects(client, bucket_name, normalized_prefix)

    # list_object_versions returns newest versions first for a key on AWS.  Keeping
    # the provider order here is useful to callers that need the raw chronology;
    # transfer orchestration applies _transfer_order so older versions reach the
    # destination before newer versions.
    seen = set()
    unique_entries = []
    for entry in entries:
        identity = (
            entry["key"],
            entry["version_id"],
            bool(entry["is_delete_marker"]),
        )
        if identity in seen:
            continue
        seen.add(identity)
        unique_entries.append(entry)
    return unique_entries


def _transfer_order(entries: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Order versions oldest-first so the final destination state is correct."""

    def sort_key(item):
        timestamp = item.get("last_modified")
        if timestamp is None:
            timestamp_key = (0, 0.0)
        elif hasattr(timestamp, "timestamp"):
            timestamp_key = (1, timestamp.timestamp())
        else:
            timestamp_key = (2, str(timestamp))
        return (
            item.get("key") or "",
            timestamp_key,
            item.get("version_id") or "",
            1 if item.get("is_delete_marker") else 0,
        )

    return sorted(entries, key=sort_key)


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
    completed = {
        int(part.get("PartNumber")): dict(part)
        for part in (progress.get("completed_parts") or [])
        if isinstance(part, dict) and part.get("PartNumber") is not None
    }

    if not upload_id:
        response = destination_client.create_multipart_upload(
            Bucket=destination_bucket,
            Key=destination_key,
            Metadata=metadata,
        )
        upload_id = response.get("UploadId") or response.get("upload_id")
        if not upload_id:
            raise LightsailBucketReplicationError(
                f"destination did not return a multipart upload id for {destination_key}"
            )
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
                upload_response = destination_client.upload_part(
                    Bucket=destination_bucket,
                    Key=destination_key,
                    UploadId=upload_id,
                    PartNumber=part_number,
                    Body=chunk,
                )
                completed[part_number] = {
                    "PartNumber": part_number,
                    "ETag": upload_response.get("ETag") or upload_response.get("etag") or "",
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
                raise error
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
        # A current 404 means the delete marker is already the visible destination
        # state (or the bucket is unversioned), so a duplicate delivery is harmless.
        if _destination_not_found(destination_client, destination_bucket, destination_key):
            return {
                "status": "delete_marker_applied",
                "skipped": True,
                "bytes_transferred": 0,
                "destination_version_id": "",
            }
        response = destination_client.delete_object(
            Bucket=destination_bucket,
            Key=destination_key,
        )
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
    return boto3.client("s3", **kwargs)


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
    endpoint = _endpoint_url(getattr(replication, "source_endpoint_url", None))
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
        supported = ", ".join(sorted(S3_STORAGE_RELATIONS))
        raise UnsupportedStorageProvider(
            f"storage provider '{provider_code or 'unknown'}' is not supported for "
            f"Lightsail bucket replication; supported S3-compatible providers: {supported}"
        )
    try:
        relation = getattr(storage, relation_name)
    except Exception as error:
        raise UnsupportedStorageProvider(
            f"storage provider '{provider_code}' is missing relation '{relation_name}'"
        ) from error
    account = storage.account
    key = account.get_encryption_key()
    access_key = bs_decrypt(relation.access_key, key)
    secret_key = bs_decrypt(relation.secret_key, key)
    if not access_key or not secret_key:
        raise LightsailBucketReplicationError(
            f"encrypted credentials for storage provider '{provider_code}' are missing "
            "or could not be decrypted"
        )
    region = getattr(getattr(relation, "region", None), "code", None)
    if provider_code in {"cloudflare", "leviia"}:
        region = "auto"
    endpoint = None if provider_code == "aws_s3" else _relation_endpoint(relation)
    if provider_code == "filebase" and not endpoint:
        endpoint = "https://s3.filebase.io"
    if not endpoint and provider_code != "aws_s3":
        raise UnsupportedStorageProvider(
            f"storage provider '{provider_code}' has no usable S3 endpoint"
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
            f"storage provider '{provider_code}' is missing relation '{relation_name}'"
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


def _destination_bucket(storage) -> str:
    _, relation = _destination_relation(storage)
    bucket = getattr(relation, "bucket_name", None)
    if not bucket:
        raise LightsailBucketReplicationError("destination S3 bucket name is empty")
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
    destination_client.put_object(
        Bucket=destination_bucket,
        Key=manifest_key,
        Body=json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        ContentType="application/json",
        Metadata=metadata,
    )


def _require_versioned_destination(client, bucket_name: str, entries: Iterable[Dict[str, Any]]):
    """Fail closed when source history cannot be represented by the destination.

    A plain S3 destination would overwrite older versions under the same key and
    would turn a source delete marker into a destructive delete. Requiring native
    destination versioning keeps the manifest and restore semantics lossless.
    """

    if not any(entry.get("version_id") or entry.get("is_delete_marker") for entry in entries):
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
    for lease_id in list(query.values_list("id", flat=True)):
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
            if state.status == CoreLightsailBucketReplicationObject.Status.COPYING:
                state.status = CoreLightsailBucketReplicationObject.Status.PENDING
                state.error = "stale transfer lease recovered"
                state.save()
            lease.owner = ""
            lease.expires_at = None
            lease.last_error = "stale transfer lease recovered"
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
    if not created and state.status in {
        CoreLightsailBucketReplicationObject.Status.PENDING,
        CoreLightsailBucketReplicationObject.Status.FAILED,
    }:
        changed = False
        for field, value in defaults.items():
            if getattr(state, field) != value:
                setattr(state, field, value)
                changed = True
        if changed:
            state.save()
    return state


def _state_terminal(state) -> bool:
    return state.status in {
        CoreLightsailBucketReplicationObject.Status.COMPLETE,
        CoreLightsailBucketReplicationObject.Status.SKIPPED,
        CoreLightsailBucketReplicationObject.Status.DELETE_MARKER_APPLIED,
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
            claimed_state.status = CoreLightsailBucketReplicationObject.Status.FAILED
            claimed_state.error = str(error)[:10000]
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
    states = list(run.object_states.order_by("key", "source_version_id", "id"))
    objects = [
        {
            "key": state.key,
            "version_id": state.source_version_id,
            "is_delete_marker": bool(state.is_delete_marker),
            "etag": state.source_etag,
            "size": state.source_size,
            "destination_key": state.destination_key,
            "destination_version_id": state.destination_version_id,
            "status": state.status,
            "bytes_transferred": state.bytes_transferred,
        }
        for state in states
    ]
    return {
        "schema": 1,
        "run_id": str(run.uuid),
        "replication_id": replication.id,
        "source_bucket": replication.source_bucket_name,
        "source_prefix": replication.source_prefix or "",
        "destination_storage_id": replication.destination_storage_id,
        "destination_prefix": replication.destination_prefix or "",
        "include_versions": bool(replication.include_versions),
        "object_count": len(objects),
        "objects": objects,
    }


def _finalize_run(run, replication, destination_client, destination_bucket):
    states = list(run.object_states.all())
    completed = [state for state in states if state.status in {
        CoreLightsailBucketReplicationObject.Status.COMPLETE,
        CoreLightsailBucketReplicationObject.Status.SKIPPED,
        CoreLightsailBucketReplicationObject.Status.DELETE_MARKER_APPLIED,
    }]
    failed = [
        state
        for state in states
        if state.status == CoreLightsailBucketReplicationObject.Status.FAILED
    ]
    unresolved = [
        state
        for state in states
        if state.status in {
            CoreLightsailBucketReplicationObject.Status.PENDING,
            CoreLightsailBucketReplicationObject.Status.COPYING,
        }
    ]
    manifest = _run_manifest(run, replication)
    run.object_count = len(states)
    run.completed_count = len(completed)
    run.failed_count = len(failed)
    run.delete_marker_count = sum(1 for state in states if state.is_delete_marker)
    run.bytes_transferred = sum(int(state.bytes_transferred or 0) for state in states)
    run.manifest = manifest

    if unresolved:
        run.status = CoreLightsailBucketReplicationRun.Status.RUNNING
        run.save()
        return _run_result(run)

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
    return {
        "run_id": run.id,
        "run_uuid": str(run.uuid),
        "status": run.status,
        "object_count": int(run.object_count or 0),
        "completed_count": int(run.completed_count or 0),
        "failed_count": int(run.failed_count or 0),
        "bytes_transferred": int(run.bytes_transferred or 0),
        "manifest_key": run.manifest_key or "",
    }


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


def run_lightsail_bucket_replication(
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
    entries = _transfer_order(
        list_source_objects(
            source_client,
            replication.source_bucket_name,
            _normalize_prefix(replication.source_prefix),
            bool(replication.include_versions),
        )
    )
    if replication.include_versions:
        _require_versioned_destination(destination_client, destination_bucket, entries)
    owner = _run_owner(run, celery_task_id)
    errors = []
    for entry in entries:
        state = _get_or_create_object_state(run, replication, entry)
        if _state_terminal(state):
            continue
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
                continue
        except Exception as error:
            errors.append(f"{entry.get('key')}: {error}")

    result = _finalize_run(run, replication, destination_client, destination_bucket)
    if errors:
        run.error = "\n".join(errors)[:20000]
        run.save(update_fields=["error", "modified"])
        result["error"] = run.error
    return result


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
        # follow-up invocation can resume them.  Keep the run non-terminal so a
        # broker/worker recovery pass can retry the same durable rows instead of
        # creating a fresh upload.
        run_query = CoreLightsailBucketReplicationRun.objects.filter(
            replication_id=replication_id,
        )
        if run_id:
            run_query = run_query.filter(pk=run_id)
        elif idempotency_key:
            run_query = run_query.filter(idempotency_key=idempotency_key)
        elif task_id:
            run_query = run_query.filter(celery_task_id=task_id)
        if run_id or idempotency_key or task_id:
            run_query.update(
                status=CoreLightsailBucketReplicationRun.Status.RUNNING,
                error=str(error)[:20000],
                completed_at=None,
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


def restore_s3_object(
    destination_client,
    source_client,
    destination_bucket: str,
    source_bucket: str,
    destination_key: str,
    source_key: str,
    *,
    restore_id: str,
) -> Dict[str, Any]:
    """Copy one destination object back to a Lightsail source key idempotently."""

    source_head = destination_client.head_object(
        Bucket=destination_bucket,
        Key=destination_key,
    )
    entry = {
        "key": destination_key,
        "version_id": "",
        "is_delete_marker": False,
        "etag": _strip_etag(source_head.get("ETag")),
        "size": _safe_int(source_head.get("ContentLength")),
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
        row, _ = CoreLightsailBucketRestoreRun.objects.get_or_create(
            replication=replication,
            idempotency_key=idempotency_key,
            defaults=defaults,
        )
    except IntegrityError:
        row = CoreLightsailBucketRestoreRun.objects.get(
            replication=replication,
            idempotency_key=idempotency_key,
        )
    return row


def _restore_result(row) -> Dict[str, Any]:
    return {
        "restore_id": row.id,
        "restore_uuid": str(row.uuid),
        "status": row.status,
        "object_count": int(row.object_count or 0),
        "completed_count": int(row.completed_count or 0),
        "skipped_count": int(row.skipped_count or 0),
        "failed_count": int(row.failed_count or 0),
        "bytes_restored": int(row.bytes_restored or 0),
    }


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
    """Restore a destination prefix to Lightsail, safely resumable/idempotent."""

    replication = CoreLightsailBucketReplication.objects.select_related(
        "source_connection", "destination_storage"
    ).get(pk=replication_id)
    _validate_replication_scope(replication)
    normalized_restore_prefix = _normalize_prefix(restore_prefix)
    if target_prefix is None:
        normalized_target_prefix = _join_prefix(
            replication.source_prefix,
            _relative_key(normalized_restore_prefix, ""),
        )
    else:
        normalized_target_prefix = _normalize_prefix(target_prefix)
    if restore_id is not None:
        row = CoreLightsailBucketRestoreRun.objects.get(
            pk=restore_id, replication_id=replication.id
        )
    else:
        key = idempotency_key or celery_task_id or f"manual-restore:{uuid.uuid4()}"
        row = _get_or_create_restore_run(
            replication,
            key,
            source_run_id,
            normalized_restore_prefix,
            normalized_target_prefix,
            celery_task_id,
        )
    if row.status == CoreLightsailBucketRestoreRun.Status.COMPLETE:
        return _restore_result(row)
    owner = celery_task_id or str(row.uuid)
    claimed = _claim_restore_lease(row, owner, _lease_seconds(replication))
    if not claimed:
        return _restore_result(row)
    row = claimed
    source_client = source_client or build_source_client(replication)
    destination_client = destination_client or build_destination_client(
        replication.destination_storage
    )
    source_bucket = replication.source_bucket_name
    destination_bucket = _destination_bucket(replication.destination_storage)
    destination_prefix = _join_prefix(replication.destination_prefix, normalized_restore_prefix)
    entries = _list_current_objects(destination_client, destination_bucket, destination_prefix)
    manifest_prefix = _join_prefix(replication.destination_prefix, MANIFEST_DIRECTORY)
    entries = [
        entry
        for entry in entries
        if not entry["key"].startswith(manifest_prefix)
    ]
    completed_keys = set(row.completed_objects or [])
    errors = []
    row.object_count = len(entries)
    row.restore_prefix = normalized_restore_prefix
    row.target_prefix = normalized_target_prefix
    row.destination_prefix = destination_prefix
    row.save()
    token = row.lease_token
    try:
        for entry in entries:
            destination_key = entry["key"]
            relative = _relative_key(destination_key, destination_prefix)
            source_key = _join_prefix(normalized_target_prefix, relative)
            if source_key in completed_keys:
                row.skipped_count = int(row.skipped_count or 0) + 1
                continue
            try:
                result = restore_s3_object(
                    destination_client,
                    source_client,
                    destination_bucket,
                    source_bucket,
                    destination_key,
                    source_key,
                    restore_id=str(row.uuid),
                )
                completed_keys.add(source_key)
                row.completed_objects = sorted(completed_keys)
                if result.get("skipped"):
                    row.skipped_count = int(row.skipped_count or 0) + 1
                else:
                    row.completed_count = int(row.completed_count or 0) + 1
                    row.bytes_restored = int(row.bytes_restored or 0) + int(
                        result.get("bytes_transferred") or 0
                    )
                row.save()
                _heartbeat_restore_lease(
                    row,
                    owner,
                    token,
                    _lease_seconds(replication),
                )
            except Exception as error:
                row.failed_count = int(row.failed_count or 0) + 1
                errors.append(f"{destination_key}: {error}")
        row.manifest = {
            "schema": 1,
            "restore_id": str(row.uuid),
            "source_bucket": source_bucket,
            "destination_bucket": destination_bucket,
            "destination_prefix": destination_prefix,
            "target_prefix": normalized_target_prefix,
            "objects": sorted(completed_keys),
        }
        row.error = "\n".join(errors)[:20000]
        row.status = (
            CoreLightsailBucketRestoreRun.Status.FAILED
            if errors
            else CoreLightsailBucketRestoreRun.Status.COMPLETE
        )
        row.completed_at = _now()
        row.save()
        return _restore_result(row)
    finally:
        _release_restore_lease(row, owner, token)


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

    from django.db.models import Q

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
                age = (now - active.modified).total_seconds()
                # A PENDING row without a task id is the broker-gap recovery case.
                # RUNNING rows are only re-enqueued after their stale window; the
                # per-object lease still prevents duplicate provider transfers.
                should_dispatch = (
                    not active.celery_task_id
                    or age >= stale_seconds
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

    from django.db.models import Q

    cutoff = _now() - timedelta(
        seconds=_setting_int(
            "LIGHTSAIL_BUCKET_RUN_STALE_SECONDS", DEFAULT_LEASE_SECONDS
        )
    )
    runs = CoreLightsailBucketReplicationRun.objects.filter(
        status__in=(
            CoreLightsailBucketReplicationRun.Status.PENDING,
            CoreLightsailBucketReplicationRun.Status.RUNNING,
        )
    ).filter(
        Q(status=CoreLightsailBucketReplicationRun.Status.PENDING, celery_task_id="")
        | Q(modified__lt=cutoff)
    )
    dispatch = []
    for run_id in runs.order_by("modified").values_list("id", flat=True)[: _setting_int("BACKUP_RECOVERY_BATCH_SIZE", 100)]:
        with transaction.atomic():
            run = CoreLightsailBucketReplicationRun.objects.select_for_update().select_related(
                "replication"
            ).get(pk=run_id)
            if run.status not in (
                CoreLightsailBucketReplicationRun.Status.PENDING,
                CoreLightsailBucketReplicationRun.Status.RUNNING,
            ):
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

    Restore rows have their own lease and completed-object ledger.  Recovery only
    hands off an expired lease (or a never-claimed pending row), so an active
    restore cannot produce a second source write.
    """

    from django.db.models import Q

    now = _now()
    cutoff = now - timedelta(
        seconds=_setting_int(
            "LIGHTSAIL_BUCKET_RUN_STALE_SECONDS", DEFAULT_LEASE_SECONDS
        )
    )
    stale = Q(modified__lt=cutoff) & (
        Q(lease_expires_at__isnull=True) | Q(lease_expires_at__lte=now)
    )
    rows = CoreLightsailBucketRestoreRun.objects.filter(
        status__in=(
            CoreLightsailBucketRestoreRun.Status.PENDING,
            CoreLightsailBucketRestoreRun.Status.RUNNING,
        )
    ).filter(
        Q(status=CoreLightsailBucketRestoreRun.Status.PENDING, celery_task_id="")
        | stale
    )
    dispatch = []
    for restore_id in rows.order_by("modified").values_list("id", flat=True)[
        : _setting_int("BACKUP_RECOVERY_BATCH_SIZE", 100)
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
