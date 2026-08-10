"""Crash-safe, resumable uploads for S3 and compatible object stores."""

from __future__ import annotations

import base64
import hashlib
import math
import os
from typing import Dict, Optional

from botocore.exceptions import ClientError
from django.conf import settings
from django.utils import timezone


SHA256_METADATA = "backupsheep-sha256"
SIZE_METADATA = "backupsheep-bytes"
BACKUP_METADATA = "backupsheep-backup-id"
NOT_FOUND_CODES = {"404", "NoSuchKey", "NotFound", "NoSuchBucket"}
NO_UPLOAD_CODES = {"NoSuchUpload", "404", "NotFound"}


class S3ObjectIntegrityError(RuntimeError):
    pass


class S3UploadReconciliationRequired(RuntimeError):
    pass


def _error_code(error):
    if isinstance(error, ClientError):
        return str((error.response or {}).get("Error", {}).get("Code", ""))
    return ""


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
    version_id=None,
    stream_if_metadata_missing=True,
):
    try:
        head = _head(client, bucket, key, expected_owner, version_id)
    except ClientError as error:
        if _error_code(error) in NOT_FOUND_CODES:
            return None
        raise
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
    args = {"Bucket": bucket, "Prefix": key}
    if expected_owner:
        args["ExpectedBucketOwner"] = expected_owner
    uploads = []
    key_marker = None
    upload_marker = None
    while True:
        page_args = dict(args)
        if key_marker:
            page_args["KeyMarker"] = key_marker
        if upload_marker:
            page_args["UploadIdMarker"] = upload_marker
        payload = client.list_multipart_uploads(**page_args)
        uploads.extend(
            item for item in (payload.get("Uploads") or []) if item.get("Key") == key
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
    args = {"Bucket": bucket, "Key": key, "UploadId": upload_id}
    if expected_owner:
        args["ExpectedBucketOwner"] = expected_owner
    parts = []
    marker = 0
    while True:
        payload = client.list_parts(**args, PartNumberMarker=marker)
        parts.extend(payload.get("Parts") or [])
        if not payload.get("IsTruncated"):
            return parts
        next_marker = int(payload.get("NextPartNumberMarker") or 0)
        if next_marker <= marker:
            raise S3UploadReconciliationRequired(
                "Object storage returned a non-advancing part cursor."
            )
        marker = next_marker


def _create_or_adopt_multipart(
    client,
    bucket,
    key,
    create_args,
    *,
    expected_owner=None,
):
    try:
        response = client.create_multipart_upload(
            Bucket=bucket,
            Key=key,
            **create_args,
        )
        return response["UploadId"]
    except Exception:
        uploads = _list_exact_uploads(client, bucket, key, expected_owner)
        if len(uploads) == 1:
            return uploads[0]["UploadId"]
        if len(uploads) > 1:
            raise S3UploadReconciliationRequired(
                "Multiple unfinished uploads match this backup object; automatic creation was stopped."
            )
        raise


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
    multipart = dict(state.get("multipart") or {})
    upload_id = multipart.get("upload_id")
    if upload_id:
        try:
            remote_parts = _list_parts(
                client, bucket, key, upload_id, expected_owner
            )
        except ClientError as error:
            if _error_code(error) not in NO_UPLOAD_CODES:
                raise
            upload_id = None
            remote_parts = []
    else:
        remote_parts = []

    if not upload_id:
        state["phase"] = "creating_multipart"
        _save_state(stored_backup, metadata_key, state)
        upload_id = _create_or_adopt_multipart(
            client,
            bucket,
            key,
            create_args,
            expected_owner=expected_owner,
        )
        multipart = {"upload_id": upload_id, "parts": []}
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
    try:
        client.complete_multipart_upload(**complete_args)
    except Exception:
        head = verified_head(
            client,
            bucket,
            key,
            identity,
            expected_owner=expected_owner,
        )
        if head is None:
            raise
    state["phase"] = "verifying"
    state.pop("multipart", None)
    _save_state(stored_backup, metadata_key, state)


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
    state.update(
        {
            "object_key": key,
            "sha256": identity["sha256"],
            "size_bytes": identity["size_bytes"],
            "checksum_algorithm": "sha256",
        }
    )
    _save_state(stored_backup, metadata_key, state)

    head = verified_head(
        client,
        bucket,
        key,
        identity,
        expected_owner=expected_owner,
        version_id=state.get("version_id"),
    )
    if head is None:
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
        if identity["size_bytes"] >= threshold:
            _multipart_upload(
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
        else:
            put_args = {"Bucket": bucket, "Key": key, **args}
            if expected_owner:
                put_args["ExpectedBucketOwner"] = expected_owner
            if supports_checksum:
                put_args["ChecksumSHA256"] = identity["sha256_base64"]
            state["phase"] = "uploading"
            _save_state(stored_backup, metadata_key, state)
            try:
                with open(local_path, "rb") as source:
                    client.put_object(Body=source, **put_args)
            except Exception:
                head = verified_head(
                    client,
                    bucket,
                    key,
                    identity,
                    expected_owner=expected_owner,
                )
                if head is None:
                    raise

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
            )
    if head is None:
        raise S3ObjectIntegrityError(
            "Object storage did not return a verified copy of the uploaded backup."
        )

    state.update(
        {
            "phase": "committed",
            "etag": head.get("ETag"),
            "version_id": head.get("VersionId"),
            "provider_checksum_sha256": head.get("ChecksumSHA256"),
        }
    )
    state.pop("multipart", None)
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
