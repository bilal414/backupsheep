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
import sys
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import django


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backupsheep.settings")

from scripts.live_e2e_ledger import (  # noqa: E402
    DurableResourceLedger,
    require_run_id,
)


class HarnessError(RuntimeError):
    """A clear, actionable harness failure."""


def _redact(value, secrets_to_redact):
    text = str(value)
    for secret in secrets_to_redact:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


class ObjectStorageHarness:
    MARKER_KEY = "backupsheep-e2e/ownership.json"
    OBJECT_KEY = "backupsheep-e2e/payload.txt"

    def __init__(self, access_key, secret_key):
        self.access_key = access_key
        self.secret_key = secret_key
        self.endpoint = os.environ.get(
            "HETZNER_S3_ENDPOINT", "https://fsn1.your-objectstorage.com"
        ).rstrip("/")
        self.region = os.environ.get("HETZNER_S3_REGION", "fsn1")
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
        return _redact(error, (self.access_key, self.secret_key))

    def list_bucket_names(self):
        response = self.client.list_buckets()
        return [bucket.get("Name") for bucket in response.get("Buckets", [])]

    def baseline(self):
        names = self.list_bucket_names()
        self.report["baseline"] = {
            "bucket_count": len(names),
            "exact_prefix_collision": self.bucket in names,
        }
        if self.bucket in names:
            raise HarnessError(
                f"Unique Object Storage bucket collision detected: {self.bucket}"
            )

    def create_bucket(self):
        # Hetzner's S3 endpoint accepts the standard regional location
        # constraint. A single create request is deliberate: on an ambiguous
        # response cleanup adopts the exact bucket only after marker validation.
        self.client.create_bucket(
            Bucket=self.bucket,
            CreateBucketConfiguration={"LocationConstraint": self.region},
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
                    raise
                if time.monotonic() - started > 60:
                    raise HarnessError("Created Object Storage bucket did not become readable")
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
        self.client.put_object(
            Bucket=self.bucket,
            Key=self.MARKER_KEY,
            Body=self.marker_body,
            ContentType="application/json",
        )
        self.client.put_object(
            Bucket=self.bucket,
            Key=self.OBJECT_KEY,
            Body=self.payload_body,
            ContentType="text/plain",
        )
        marker = self.client.get_object(Bucket=self.bucket, Key=self.MARKER_KEY)
        marker_body = marker["Body"].read()
        if marker_body != self.marker_body:
            raise HarnessError("Object Storage ownership marker read-back failed")
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
            },
        )
        payload = self.client.get_object(Bucket=self.bucket, Key=self.OBJECT_KEY)
        payload_body = payload["Body"].read()
        if marker_body != self.marker_body or payload_body != self.payload_body:
            raise HarnessError("Object Storage returned content different from uploaded bytes")
        self.report["tests"]["put/get objects"] = {
            "status": "PASS",
            "keys": [self.MARKER_KEY, self.OBJECT_KEY],
        }

    def verify_listing(self):
        listed = self.client.list_objects_v2(Bucket=self.bucket).get("Contents", [])
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
        except ClientError:
            return False
        return response["Body"].read() == self.marker_body

    def _list_objects(self):
        objects = []
        token = None
        while True:
            params = {"Bucket": self.bucket}
            if token:
                params["ContinuationToken"] = token
            response = self.client.list_objects_v2(**params)
            objects.extend(response.get("Contents", []))
            if not response.get("IsTruncated"):
                return objects
            token = response.get("NextContinuationToken")
            if not token:
                raise HarnessError("Object Storage returned a truncated listing without a continuation token")

    def cleanup(self):
        errors = []
        if not self.cleanup_enabled:
            self.report["cleanup"] = {
                "status": "NOT_REQUESTED",
                "errors": [],
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
