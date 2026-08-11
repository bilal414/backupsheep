"""Create-only Hetzner Object Storage E2E test for BackupSheep.

The application already supports S3-compatible destinations through the
``idrive`` storage adapter. This harness proves that adapter against one
temporary Hetzner Object Storage bucket. Cleanup requires both the exact
provider marker and a fsynced durable ledger entry.

Required environment variables:

    HETZNER_S3_ACCESS_KEY
    HETZNER_S3_SECRET_KEY
    BACKUPSHEEP_E2E_RUN_ID
    BACKUPSHEEP_E2E_LEDGER_PATH

Optional environment variables:

    HETZNER_S3_ENDPOINT  # defaults to https://fsn1.your-objectstorage.com
    HETZNER_S3_REGION    # defaults to fsn1
    BACKUPSHEEP_E2E_APPLY=YES    # opt in to provider writes
    BACKUPSHEEP_E2E_CLEANUP=YES  # separately opt in to verified cleanup

The access and secret keys are process inputs only. They are never included in
the report, application rows, or exception output.
"""

import hashlib
import json
import os
import re
import sys
import time
from urllib.parse import urlsplit

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import django


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backupsheep.settings")

from scripts.live_e2e_ledger import (  # noqa: E402
    DurableMutationIntentStore,
    DurableResourceLedger,
    bounded_error,
    provider_error_class,
    require_run_id,
)


class HarnessError(RuntimeError):
    """A clear, actionable harness failure."""


class AmbiguousMutation(HarnessError):
    provider_code = "PROVIDER_AMBIGUOUS"


MAX_PROVIDER_PAGES = 1000
MAX_PROVIDER_ITEMS = 10000


def _redact(value, secrets_to_redact):
    text = bounded_error(value, secrets_to_redact)
    for secret in secrets_to_redact:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


OBJECT_STORAGE_REGION_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _validate_object_storage_endpoint(endpoint, region):
    """Accept only a region-rooted Hetzner Object Storage HTTPS endpoint."""
    endpoint = str(endpoint or "")
    region = str(region or "")
    if not OBJECT_STORAGE_REGION_RE.fullmatch(region):
        raise HarnessError(
            "HETZNER_S3_REGION must be a lowercase documented Hetzner region"
        )
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except (TypeError, ValueError) as error:
        raise HarnessError(
            "HETZNER_S3_ENDPOINT must be exactly "
            "https://<region>.your-objectstorage.com"
        ) from error
    expected_netloc = f"{region}.your-objectstorage.com"
    expected_endpoint = f"https://{expected_netloc}"
    if (
        endpoint != expected_endpoint
        or parsed.scheme != "https"
        or parsed.netloc != expected_netloc
        or parsed.hostname != expected_netloc
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise HarnessError(
            "HETZNER_S3_ENDPOINT must be exactly "
            "https://<region>.your-objectstorage.com and match HETZNER_S3_REGION"
        )
    return endpoint, region


class ObjectStorageHarness:
    MARKER_KEY = "backupsheep-e2e/ownership.json"
    OBJECT_KEY = "backupsheep-e2e/payload.txt"

    def __init__(self, access_key, secret_key):
        endpoint = os.environ.get(
            "HETZNER_S3_ENDPOINT", "https://fsn1.your-objectstorage.com"
        )
        region = os.environ.get("HETZNER_S3_REGION", "fsn1")
        self.endpoint, self.region = _validate_object_storage_endpoint(
            endpoint, region
        )
        self.access_key = access_key
        self.secret_key = secret_key
        self.prefix = require_run_id(os.environ.get("BACKUPSHEEP_E2E_RUN_ID"))
        self.bucket = self.prefix
        self.marker_body = json.dumps(
            {"owner": "BackupSheep", "prefix": self.prefix},
            sort_keys=True,
        ).encode()
        self.payload_body = (
            f"BackupSheep Hetzner Object Storage E2E {self.prefix}\n"
        ).encode()
        self.apply = os.environ.get("BACKUPSHEEP_E2E_APPLY") == "YES"
        self.cleanup_enabled = os.environ.get("BACKUPSHEEP_E2E_CLEANUP") == "YES"
        scope = (
            f"{self.endpoint}:{self.region}:"
            f"{hashlib.sha256(access_key.encode()).hexdigest()[:16]}"
        )
        self.ledger = DurableResourceLedger(
            os.environ.get("BACKUPSHEEP_E2E_LEDGER_PATH"),
            provider="hetzner_object_storage",
            run_id=self.prefix,
            scope=scope,
        )
        self.intents = DurableMutationIntentStore(
            os.environ.get("BACKUPSHEEP_E2E_LEDGER_PATH"),
            provider="hetzner_object_storage",
            run_id=self.prefix,
            scope=scope,
            suffix=".object-storage-intents.json",
        )
        self.report = {
            "prefix": self.prefix,
            "bucket": self.bucket,
            "endpoint": self.endpoint,
            "region": self.region,
            "tests": {},
            "cleanup": {"status": "NOT_RUN", "errors": []},
        }
        self.client = boto3.client(
            "s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=self.region,
            config=Config(
                signature_version="s3v4",
                connect_timeout=10,
                read_timeout=60,
                retries={"total_max_attempts": 1, "mode": "standard"},
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

    def _safe_error(self, error):
        return f"{provider_error_class(error)}: {_redact(error, (self.access_key, self.secret_key))}"

    def _preflight_cleanup(self):
        if self.cleanup_enabled and not self.apply:
            raise HarnessError(
                "Cleanup is a provider write and requires both "
                "BACKUPSHEEP_E2E_APPLY=YES and BACKUPSHEEP_E2E_CLEANUP=YES"
            )

    def preflight(self):
        """Validate local mutation gates before any provider operation."""
        self._preflight_cleanup()

    def list_bucket_names(self):
        response = self.client.list_buckets()
        buckets = response.get("Buckets")
        if not isinstance(buckets, list):
            raise HarnessError("Object Storage returned a malformed bucket inventory")
        if len(buckets) > MAX_PROVIDER_ITEMS:
            raise HarnessError("Object Storage bucket inventory exceeded the bounded item limit")
        names = []
        for bucket in buckets:
            if not isinstance(bucket, dict) or not bucket.get("Name"):
                raise HarnessError("Object Storage returned a malformed bucket identity")
            names.append(str(bucket["Name"]))
        return names

    def baseline(self):
        names = self.list_bucket_names()
        self.report["baseline"] = {
            "bucket_count": len(names),
            "exact_prefix_collision": self.bucket in names,
        }
        if self.bucket in names:
            entry = self.ledger.get("bucket", self.bucket)
            if not entry or not self.ledger.cleanup_eligible("bucket", self.bucket):
                raise HarnessError(
                    f"Unique Object Storage bucket collision detected: {self.bucket}"
                )
            if not self._marker_is_owned():
                raise HarnessError(
                    "The ledgered Object Storage bucket failed its exact ownership read-back"
                )
            self.report["baseline"]["ledgered_bucket_adoption"] = True

    def create_bucket(self):
        entry = self.ledger.get("bucket", self.bucket)
        if entry and self.ledger.cleanup_eligible("bucket", self.bucket):
            if not self._marker_is_owned():
                raise HarnessError(
                    "The ledgered Object Storage bucket failed its exact ownership read-back"
                )
            self.report["tests"]["bucket create"] = {
                "status": "ADOPTED",
                "bucket": self.bucket,
            }
            return

        pending_key = "create:bucket"
        pending = self.intents.get(pending_key)
        if pending:
            errors = self._reconcile_pending_intents()
            if errors:
                raise HarnessError("; ".join(errors))
            entry = self.ledger.get("bucket", self.bucket)
            if entry and self.ledger.cleanup_eligible("bucket", self.bucket):
                return self.create_bucket()
            if self.intents.get(pending_key):
                raise AmbiguousMutation(
                    "Object Storage bucket create remains pending; no duplicate create issued"
                )

        self.intents.put(
            pending_key,
            {
                "marker": self.bucket,
                "kind": "bucket",
                "name": self.bucket,
                "operation": "create_bucket",
                "mutation_state": "request_started",
                "expected_marker_key": self.MARKER_KEY,
                "expected_marker_sha256": hashlib.sha256(self.marker_body).hexdigest(),
                "endpoint": self.endpoint,
                "region": self.region,
            },
        )
        # Hetzner's S3 endpoint accepts the standard regional location
        # constraint. A single create request is deliberate: on an ambiguous
        # response cleanup adopts the exact bucket only after marker validation.
        try:
            self.client.create_bucket(
                Bucket=self.bucket,
                CreateBucketConfiguration={"LocationConstraint": self.region},
            )
        except Exception as error:
            self.intents.update(
                pending_key,
                mutation_state="outcome_unknown",
                last_error_code=provider_error_class(error),
            )
            raise AmbiguousMutation(
                "Object Storage bucket create outcome is unknown; no retry issued"
            ) from error
        self.intents.update(
            pending_key,
            provider_id=self.bucket,
            mutation_state="accepted",
        )
        # Object Storage can briefly return NoSuchBucket immediately after a
        # successful CreateBucket response. Wait for the exact bucket to become
        # readable before using it; this is also the first post-create ownership
        # check used by cleanup after an ambiguous create response.
        started = time.monotonic()
        while True:
            try:
                self.client.head_bucket(Bucket=self.bucket)
                break
            except ClientError as error:
                status = (error.response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
                if status != 404:
                    self.intents.update(
                        pending_key,
                        last_read_error_code=provider_error_class(error),
                    )
                    raise
                if time.monotonic() - started > 60:
                    raise AmbiguousMutation(
                        "Object Storage accepted bucket creation but exact read-back timed out"
                    )
                time.sleep(3)
        self.report["tests"]["bucket create"] = {"status": "PASS"}

    def verify_backupsheep_storage_adapter(self):
        """Exercise the same validation path used by the storage API/UI."""
        from apps.console.storage.models import CoreStorageIDrive

        storage = CoreStorageIDrive()
        valid = storage.validate(
            {
                "access_key": self.access_key,
                "secret_key": self.secret_key,
                "endpoint": self.endpoint,
                "bucket_name": self.bucket,
                "prefix": f"{self.prefix}/adapter",
                "no_delete": False,
            },
            raise_exp=True,
        )
        if not valid:
            raise HarnessError("BackupSheep S3-compatible storage validation returned false")
        self.report["tests"]["backupsheep idrive adapter validation"] = {
            "status": "PASS",
            "adapter": "idrive",
        }

    def put_and_get(self):
        marker_put = self.client.put_object(
            Bucket=self.bucket,
            Key=self.MARKER_KEY,
            Body=self.marker_body,
            ContentType="application/json",
        )
        payload_put = self.client.put_object(
            Bucket=self.bucket,
            Key=self.OBJECT_KEY,
            Body=self.payload_body,
            ContentType="text/plain",
        )
        marker = self.client.get_object(Bucket=self.bucket, Key=self.MARKER_KEY)
        marker_body = marker["Body"].read()
        if marker_body != self.marker_body:
            raise HarnessError("Object Storage ownership marker read-back failed")
        marker_metadata = self._object_metadata(
            self.MARKER_KEY, self.marker_body, marker_put
        )
        payload_metadata = self._object_metadata(
            self.OBJECT_KEY, self.payload_body, payload_put
        )
        # Only this confirmed read-back makes the exact bucket cleanup-eligible.
        self.ledger.record(
            kind="bucket",
            resource_id=self.bucket,
            name=self.bucket,
            ownership={
                "marker_key": self.MARKER_KEY,
                "marker_sha256": hashlib.sha256(self.marker_body).hexdigest(),
                "endpoint": self.endpoint,
                "region": self.region,
                "objects": {
                    self.MARKER_KEY: marker_metadata,
                    self.OBJECT_KEY: payload_metadata,
                },
            },
        )
        pending_key = "create:bucket"
        if self.intents.get(pending_key):
            self.intents.update(
                pending_key,
                mutation_state="ledgered",
                objects={
                    self.MARKER_KEY: marker_metadata,
                    self.OBJECT_KEY: payload_metadata,
                },
            )
            self.intents.clear(pending_key)
        payload = self.client.get_object(Bucket=self.bucket, Key=self.OBJECT_KEY)
        payload_body = payload["Body"].read()
        if payload_body != self.payload_body:
            raise HarnessError("Object Storage returned content different from uploaded bytes")
        self.report["tests"]["put/get objects"] = {
            "status": "PASS",
            "keys": [self.MARKER_KEY, self.OBJECT_KEY],
            "objects": {
                self.MARKER_KEY: marker_metadata,
                self.OBJECT_KEY: payload_metadata,
            },
        }

    def _object_metadata(self, key, expected_body, put_response):
        try:
            head = self.client.head_object(Bucket=self.bucket, Key=key)
        except Exception as error:
            raise HarnessError(
                f"Object Storage metadata read-back failed for {key}: {self._safe_error(error)}"
            ) from error
        try:
            byte_count = int(head.get("ContentLength"))
        except (TypeError, ValueError) as error:
            raise HarnessError(f"Object Storage returned no byte count for {key}") from error
        if byte_count != len(expected_body):
            raise HarnessError(f"Object Storage byte count mismatch for {key}")
        etag = str(head.get("ETag") or put_response.get("ETag") or "").strip('"')
        if not etag:
            raise HarnessError(f"Object Storage returned no ETag for {key}")
        return {
            "checksum_sha256": hashlib.sha256(expected_body).hexdigest(),
            "byte_count": byte_count,
            "etag": etag,
            "version_id": head.get("VersionId") or put_response.get("VersionId"),
        }

    def verify_listing(self):
        listed = self._list_objects()
        keys = sorted(item.get("Key") for item in listed)
        expected = sorted([self.MARKER_KEY, self.OBJECT_KEY])
        if not set(expected).issubset(set(keys)):
            raise HarnessError(f"Object listing missed owned test keys: {keys!r}")
        self.report["tests"]["list objects"] = {"status": "PASS", "keys": keys}

    def delete_object_and_verify(self):
        self.client.delete_object(Bucket=self.bucket, Key=self.OBJECT_KEY)
        started = time.monotonic()
        while True:
            try:
                self.client.head_object(Bucket=self.bucket, Key=self.OBJECT_KEY)
            except ClientError as error:
                status = (error.response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
                if status == 404:
                    break
                raise
            if time.monotonic() - started > 30:
                raise HarnessError("Deleted Object Storage object was still readable")
            time.sleep(2)
        self.report["tests"]["delete object"] = {"status": "PASS"}

    def _marker_is_owned(self):
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=self.MARKER_KEY)
        except ClientError as error:
            status = (error.response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
            if status == 404:
                return False
            raise
        return response["Body"].read() == self.marker_body

    def _reconcile_pending_intents(self):
        """Adopt only an exact marked bucket or prove a prepared create absent."""
        errors = []
        for key, intent in self.intents.pending().items():
            if intent.get("kind") != "bucket" or intent.get("name") != self.bucket:
                errors.append(f"{key}: unsupported pending Object Storage intent")
                continue
            try:
                names = self.list_bucket_names()
            except Exception as error:
                errors.append(f"{key}: bucket inventory failed: {self._safe_error(error)}")
                continue
            if self.bucket not in names:
                if str(intent.get("mutation_state") or "prepared") == "prepared":
                    self.intents.clear(key)
                else:
                    errors.append(
                        f"{key}: accepted or ambiguous bucket create has no exact provider match"
                    )
                continue
            try:
                marker_owned = self._marker_is_owned()
            except Exception as error:
                errors.append(f"{key}: exact bucket marker read failed: {self._safe_error(error)}")
                continue
            if not marker_owned:
                errors.append(
                    f"{key}: exact bucket exists but its immutable ownership marker does not match"
                )
                continue
            self.ledger.record(
                kind="bucket",
                resource_id=self.bucket,
                name=self.bucket,
                ownership={
                    "marker_key": self.MARKER_KEY,
                    "marker_sha256": hashlib.sha256(self.marker_body).hexdigest(),
                    "endpoint": self.endpoint,
                    "region": self.region,
                },
            )
            self.intents.update(
                key,
                provider_id=self.bucket,
                mutation_state="ledgered",
            )
            self.intents.clear(key)
        return errors

    def _list_objects(self):
        objects = []
        token = None
        seen_tokens = set()
        for _ in range(MAX_PROVIDER_PAGES):
            params = {"Bucket": self.bucket, "MaxKeys": 1000}
            if token:
                params["ContinuationToken"] = token
            response = self.client.list_objects_v2(**params)
            page = response.get("Contents")
            if not isinstance(page, list):
                raise HarnessError("Object Storage returned a malformed object page")
            objects.extend(page)
            if len(objects) > MAX_PROVIDER_ITEMS:
                raise HarnessError("Object Storage pagination exceeded the bounded item limit")
            if "IsTruncated" not in response or not isinstance(response["IsTruncated"], bool):
                raise HarnessError("Object Storage omitted the required truncation metadata")
            if not response["IsTruncated"]:
                return objects
            token = response.get("NextContinuationToken")
            if not isinstance(token, str) or not token or token in seen_tokens:
                raise HarnessError("Object Storage returned a truncated listing without a continuation token")
            seen_tokens.add(token)
        raise HarnessError("Object Storage pagination exceeded the bounded page limit")

    def cleanup(self):
        errors = []
        if not self.cleanup_enabled:
            self.report["cleanup"] = {
                "status": "NOT_REQUESTED",
                "errors": [],
                "bucket": self.bucket,
            }
            return
        if not self.apply:
            self.report["cleanup"] = {
                "status": "REFUSED",
                "errors": [
                    "Cleanup is a provider write and requires both "
                    "BACKUPSHEEP_E2E_APPLY=YES and BACKUPSHEEP_E2E_CLEANUP=YES"
                ],
                "bucket": self.bucket,
            }
            return
        pending_errors = self._reconcile_pending_intents()
        if pending_errors:
            self.report["cleanup"] = {
                "status": "MANUAL_REVIEW",
                "errors": [
                    bounded_error(error, (self.access_key, self.secret_key))
                    for error in pending_errors
                ],
                "bucket": self.bucket,
            }
            return
        ledger_entry = self.ledger.get("bucket", self.bucket)
        if not ledger_entry or not self.ledger.cleanup_eligible("bucket", self.bucket):
            self.report["cleanup"] = {
                "status": "MANUAL_REVIEW",
                "errors": [
                    "refused bucket cleanup: no durable confirmed ownership ledger entry"
                ],
                "bucket": self.bucket,
            }
            return
        try:
            names = self.list_bucket_names()
            bucket_present = self.bucket in names
        except Exception as error:
            errors.append(f"list buckets during cleanup: {self._safe_error(error)}")
            bucket_present = False

        if bucket_present:
            marker_owned = self._marker_is_owned()
            if not marker_owned:
                errors.append(
                    "refused bucket cleanup: exact BackupSheep ownership marker is missing"
                )
            else:
                try:
                    listed = self._list_objects()
                    allowed = {
                        self.MARKER_KEY,
                        self.OBJECT_KEY,
                    }
                    allowed_prefix = f"{self.prefix}/"
                    unknown = [
                        item.get("Key")
                        for item in listed
                        if not (
                            item.get("Key") in allowed
                            or item.get("Key", "").startswith(allowed_prefix)
                        )
                    ]
                    if unknown:
                        errors.append(
                            "refused bucket cleanup: unexpected object keys found: "
                            + repr(unknown)
                        )
                    else:
                        objects = [{"Key": item["Key"]} for item in listed]
                        if objects:
                            self.client.delete_objects(
                                Bucket=self.bucket,
                                Delete={"Objects": objects, "Quiet": True},
                            )
                        self.client.delete_bucket(Bucket=self.bucket)
                except Exception as error:
                    errors.append(f"delete owned bucket: {self._safe_error(error)}")

        # Require the exact bucket name to disappear before declaring cleanup
        # green. This is scoped to the random name, never a broad bucket purge.
        if not errors:
            started = time.monotonic()
            while True:
                try:
                    try:
                        self.client.head_bucket(Bucket=self.bucket)
                    except ClientError as error:
                        status = (error.response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
                        if status == 404:
                            break
                        raise
                    if self.bucket not in self.list_bucket_names():
                        break
                except Exception as error:
                    errors.append(f"verify bucket cleanup: {self._safe_error(error)}")
                    break
                if time.monotonic() - started > 120:
                    errors.append(f"bucket remained after cleanup: {self.bucket}")
                    break
                time.sleep(5)

        self.report["cleanup"] = {
            "status": "PASS" if not errors else "FAIL",
            "errors": errors,
            "bucket": self.bucket,
        }
        self.ledger.mark_cleanup(
            "bucket",
            self.bucket,
            state="deleted" if not errors else "failed",
            error="; ".join(errors),
        )

    def run(self):
        try:
            self.preflight()
            self.baseline()
            if not self.apply:
                self.report["status"] = "PREFLIGHT_PASS"
                self.report["mode"] = "read_only"
                return 0
            self.create_bucket()
            self.verify_backupsheep_storage_adapter()
            self.put_and_get()
            self.verify_listing()
            self.delete_object_and_verify()
            self.report["status"] = "PASS"
        except Exception as error:
            self.report["status"] = "FAIL"
            self.report["error"] = self._safe_error(error)
        finally:
            self.cleanup()
            print(json.dumps(self.report, indent=2, sort_keys=True, default=str))
        cleanup_ok = self.report["cleanup"]["status"] in {"PASS", "NOT_REQUESTED"}
        return 0 if self.report.get("status") == "PASS" and cleanup_ok else 1


def main():
    required = (
        "HETZNER_S3_ACCESS_KEY",
        "HETZNER_S3_SECRET_KEY",
        "BACKUPSHEEP_E2E_RUN_ID",
        "BACKUPSHEEP_E2E_LEDGER_PATH",
    )
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        print(
            json.dumps(
                {
                    "status": "FAIL",
                    "error": "Missing required environment variables: " + ", ".join(missing),
                },
                indent=2,
            )
        )
        return 1
    django.setup()
    return ObjectStorageHarness(
        os.environ["HETZNER_S3_ACCESS_KEY"], os.environ["HETZNER_S3_SECRET_KEY"]
    ).run()


if __name__ == "__main__":
    sys.exit(main())
