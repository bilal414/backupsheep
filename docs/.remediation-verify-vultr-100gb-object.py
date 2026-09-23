import hashlib
import json
import os
import time

from apps._tasks.integration.storage.vultr import _s3_client
from apps.console.backup.models import CoreWebsiteBackupStoragePoints


point = CoreWebsiteBackupStoragePoints.objects.get(pk=44)
state = ((point.metadata or {}).get("vultr_s3_object") or {})
assert point.backup_id == 42
assert point.storage_id == 11
assert point.status == point.Status.UPLOAD_COMPLETE
assert point.upload_attempt_count == 2
assert state.get("phase") == "committed"

expected_size = 107421554763
expected_sha256 = "71ec61b44453a81201295bcb2f480c74b653f18333319821857cab74ba0775d1"
bucket = "bs-remed-0d08dcf-100gb-20260819"
key = (
    "bs-remed-20260818-0d08dcf/100gb/"
    "bs-bs-remed-20260818-0d08dcf-n101-b42-100gb.zip"
)
assert state.get("bucket") == bucket
assert state.get("object_key") == key
assert state.get("size_bytes") == expected_size
assert state.get("sha256") == expected_sha256


def digest_stream(chunks):
    digest = hashlib.sha256()
    byte_count = 0
    for chunk in chunks:
        if not chunk:
            continue
        digest.update(chunk)
        byte_count += len(chunk)
    return byte_count, digest.hexdigest()


local_path = f"_storage/{point.backup.uuid_str}.zip"
assert os.path.isfile(local_path)
started = time.monotonic()
with open(local_path, "rb") as source:
    local_size, local_sha256 = digest_stream(
        iter(lambda: source.read(8 * 1024 * 1024), b"")
    )
local_elapsed = time.monotonic() - started
assert local_size == expected_size
assert local_sha256 == expected_sha256

storage = point.storage
client = _s3_client(storage, storage.account.get_encryption_key())
head_before = client.head_object(Bucket=bucket, Key=key)
assert head_before.get("ContentLength") == expected_size
assert (head_before.get("Metadata") or {}).get("backupsheep-sha256") == expected_sha256

started = time.monotonic()
response = client.get_object(Bucket=bucket, Key=key)
body = response["Body"]
try:
    remote_size, remote_sha256 = digest_stream(
        body.iter_chunks(chunk_size=8 * 1024 * 1024)
    )
finally:
    body.close()
remote_elapsed = time.monotonic() - started
assert remote_size == expected_size
assert remote_sha256 == expected_sha256

head_after = client.head_object(Bucket=bucket, Key=key)
objects = client.list_objects_v2(Bucket=bucket, Prefix=key).get("Contents") or []
uploads = client.list_multipart_uploads(Bucket=bucket, Prefix=key).get("Uploads") or []
assert head_after.get("ContentLength") == expected_size
assert len(objects) == 1
assert objects[0].get("Key") == key
assert not uploads

print(
    json.dumps(
        {
            "result": "PASS",
            "point_id": point.id,
            "backup_id": point.backup_id,
            "attempt_count": point.upload_attempt_count,
            "bucket": bucket,
            "key": key,
            "size_bytes": expected_size,
            "local_sha256": local_sha256,
            "remote_sha256": remote_sha256,
            "local_elapsed_seconds": round(local_elapsed, 3),
            "remote_elapsed_seconds": round(remote_elapsed, 3),
            "etag": head_after.get("ETag"),
            "metadata": head_after.get("Metadata"),
            "object_count": len(objects),
            "unfinished_multipart_count": len(uploads),
        },
        sort_keys=True,
    )
)
