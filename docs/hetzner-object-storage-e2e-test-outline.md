# Hetzner Object Storage E2E test outline

This outline accompanies
[`scripts/hetzner_object_storage_e2e.py`](../scripts/hetzner_object_storage_e2e.py).
Hetzner Object Storage is S3-compatible, so BackupSheep integrates it through
the existing endpoint-based `idrive` storage adapter. It is a storage
destination for file/database backup artifacts, not a native Hetzner Cloud
server snapshot source.

## Safety contract

1. The first operation is a read-only bucket inventory against the selected
   Object Storage endpoint. A random exact bucket-name collision aborts before
   mutation.
2. The harness creates one lower-case bucket with a random `bs-e2e-` name and
   writes only objects under its own `backupsheep-e2e/` or run-prefix path.
3. The ownership marker contains the exact run prefix. Cleanup requires that
   marker, or a successful create attempt plus an exact collision-free bucket
   name when a failure occurs before the marker can be written.
4. Cleanup rejects unexpected object keys and then deletes only the exact test
   bucket. It waits for the exact bucket name to disappear before reporting
   success.

## Test matrix

| ID | Case | Evidence | Expected result |
| --- | --- | --- | --- |
| HOS-01 | Credential and bucket preflight | Read-only `ListBuckets` inventory | Fail before writes on bad credentials or exact collision |
| HOS-02 | Bucket lifecycle | `CreateBucket`, post-create `HeadBucket` | Temporary bucket becomes readable |
| HOS-03 | BackupSheep adapter validation | Existing `CoreStorageIDrive.validate()` performs upload, reload, presigned GET, and delete | PASS |
| HOS-04 | Object write/read | `PutObject` and `GetObject` for marker and payload | Exact bytes round-trip |
| HOS-05 | Object listing | `ListObjectsV2` | Both owned keys are listed |
| HOS-06 | Object deletion | `DeleteObject` and `HeadObject` | Deleted payload returns 404 |
| HOS-07 | Prefix-scoped cleanup | Ownership proof, object deletion, bucket deletion, absence verification | No exact test bucket remains |

## Recorded live run

The final run completed successfully on 2026-08-03 against
`https://fsn1.your-objectstorage.com` (`fsn1`). Run prefix and bucket were
`bs-e2e-260803131612-ccdd21`; HOS-01 through HOS-07 passed and cleanup
reported no remaining exact bucket. The endpoint inventory contained one
pre-existing bucket; it did not match the random prefix and was not read,
changed, or deleted beyond the account-level bucket listing required for the
collision check.

## Deliberate non-coverage

- Hetzner does not provide a native Object Storage replication or restore API;
  cross-location copies must be implemented as independent S3 object copies.
- The harness does not enable or change versioning/Object Lock on any bucket.
- No existing bucket or object is modified. The harness only creates and
  removes its exact temporary bucket.

Run from the application environment with credentials injected outside the
repository:

```bash
HETZNER_S3_ACCESS_KEY=' supplied outside the repository ' \
HETZNER_S3_SECRET_KEY=' supplied outside the repository ' \
HETZNER_S3_ENDPOINT=https://fsn1.your-objectstorage.com \
HETZNER_S3_REGION=fsn1 \
python scripts/hetzner_object_storage_e2e.py
```
