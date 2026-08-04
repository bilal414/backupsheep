import hashlib

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from apps._tasks.exceptions import StorageVultrUploadFailedError
from apps.api.v1.utils.api_helpers import bs_decrypt


VULTR_OBJECT_METADATA_KEY = "vultr_s3_object"
VULTR_SHA256_HEADER = "backupsheep-sha256"
_NOT_FOUND_CODES = {"404", "NoSuchKey", "NotFound", "NoSuchBucket"}


def _hash_stream(stream):
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _head_object(client, bucket, key, version_id=None):
    args = {"Bucket": bucket, "Key": key}
    if version_id and version_id != "null":
        args["VersionId"] = version_id
    return client.head_object(**args)


def _metadata_value(response, name):
    metadata = response.get("Metadata") or {}
    name = name.lower()
    return next(
        (str(value) for key, value in metadata.items() if key.lower() == name),
        None,
    )


def _object_matches(client, bucket, key, expected, *, persisted=None):
    """Verify one exact object without treating ETag as a content checksum.

    The custom SHA-256 metadata is preferred. If a compatible S3 provider does not
    preserve user metadata, the object body is streamed through SHA-256 instead.
    """
    persisted = persisted or {}
    try:
        head = _head_object(client, bucket, key, persisted.get("version_id"))
    except ClientError as exc:
        code = str((exc.response or {}).get("Error", {}).get("Code", ""))
        if code in _NOT_FOUND_CODES:
            return None
        raise

    if int(head.get("ContentLength", -1)) != expected["size_bytes"]:
        return None

    expected_etag = persisted.get("etag")
    if expected_etag and head.get("ETag") != expected_etag:
        return None

    remote_sha256 = _metadata_value(head, VULTR_SHA256_HEADER)
    if remote_sha256:
        if remote_sha256 != expected["sha256"]:
            return None
    else:
        response = client.get_object(
            **{
                "Bucket": bucket,
                "Key": key,
                **(
                    {"VersionId": persisted["version_id"]}
                    if persisted.get("version_id") and persisted["version_id"] != "null"
                    else {}
                ),
            }
        )
        body = response["Body"]
        try:
            remote_sha256, remote_size = _hash_stream(body)
        finally:
            close = getattr(body, "close", None)
            if close:
                close()
        if remote_size != expected["size_bytes"] or remote_sha256 != expected["sha256"]:
            return None

    return head


def _s3_client(storage, encryption_key):
    vultr = storage.storage_vultr
    return boto3.client(
        "s3",
        aws_access_key_id=bs_decrypt(vultr.access_key, encryption_key),
        aws_secret_access_key=bs_decrypt(vultr.secret_key, encryption_key),
        endpoint_url=f"https://{vultr.endpoint}",
        config=Config(
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 5, "mode": "standard"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )


def _persist_upload(stored_backup, file_key, expected, head):
    metadata = dict(stored_backup.metadata or {})
    metadata[VULTR_OBJECT_METADATA_KEY] = {
        "object_key": file_key,
        "sha256": expected["sha256"],
        "size_bytes": expected["size_bytes"],
        # ETag is retained as provider identity metadata only. It is not used as
        # a content hash because multipart ETags are not MD5 checksums.
        "etag": head.get("ETag"),
        "version_id": head.get("VersionId"),
    }
    stored_backup.storage_file_id = file_key
    stored_backup.metadata = metadata
    stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
    stored_backup.save()


def storage_vultr(stored_backup):
    try:
        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        encryption_key = storage.account.get_encryption_key()
        vultr = storage.storage_vultr

        file_name = f"{stored_backup.backup.uuid}.zip"
        prefix = vultr.prefix or ""
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        file_key = prefix + file_name

        # Hash the exact stream that will be uploaded. This keeps memory bounded
        # and gives retries a deterministic content identity.
        with open(local_zip, "rb") as file_obj:
            sha256, size_bytes = _hash_stream(file_obj)
            expected = {"sha256": sha256, "size_bytes": size_bytes}
            file_obj.seek(0)

            client = _s3_client(storage, encryption_key)
            stored_metadata = dict((stored_backup.metadata or {}).get(VULTR_OBJECT_METADATA_KEY) or {})
            persisted_key = stored_metadata.get("object_key") or stored_backup.storage_file_id
            candidate_key = persisted_key or file_key

            # The deterministic key preflight also adopts an object from the
            # crash window where S3 accepted the upload but the DB save did not.
            head = _object_matches(
                client,
                vultr.bucket_name,
                candidate_key,
                expected,
                persisted=stored_metadata,
            )
            if head is not None:
                _persist_upload(stored_backup, candidate_key, expected, head)
                return

            file_obj.seek(0)
            client.upload_fileobj(
                file_obj,
                vultr.bucket_name,
                candidate_key,
                ExtraArgs={"Metadata": {VULTR_SHA256_HEADER: sha256}},
            )

        # Verify durability and capture provider-assigned identity only after the
        # upload has completed. A failed verification remains an upload failure.
        head = _object_matches(
            client,
            vultr.bucket_name,
            candidate_key,
            expected,
        )
        if head is None:
            raise ValueError("Vultr Object Storage integrity verification failed")
        _persist_upload(stored_backup, candidate_key, expected, head)
    except FileNotFoundError:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as exc:
        raise StorageVultrUploadFailedError(
            stored_backup.backup.uuid_str,
            stored_backup.backup.attempt_no,
            stored_backup.backup.type,
            str(exc),
        )
