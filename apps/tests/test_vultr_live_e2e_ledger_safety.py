import hashlib
import os
import tempfile
from io import BytesIO
from unittest import TestCase, mock

import requests

from scripts.live_e2e_ledger import DurableResourceLedger, LedgerError
from scripts.vultr_live_e2e import (
    AmbiguousMutation,
    HarnessError,
    LiveVultrHarness,
    MutationIntentStore,
    ProviderNotFound,
    ProviderTransientFailure,
    _validate_vultr_api_base,
    _validate_vultr_object_storage_hostname,
    _request_fingerprint,
    _retry_after_seconds,
)


RUN_ID = "bs-e2e-vultr-safety"


class _FakeResponse:
    def __init__(self, status_code=200, payload=None, body=b"{}", headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.content = body
        self.text = body.decode("utf-8", errors="replace")
        self.headers = dict(headers or {})
        self.closed = False

    def json(self):
        return self._payload

    def close(self):
        self.closed = True


class _S3NotFoundError(Exception):
    response = {
        "Error": {"Code": "404"},
        "ResponseMetadata": {"HTTPStatusCode": 404},
    }


class _FakeSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return _FakeResponse(payload={"account": {}})


class _SequenceSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if not self.responses:
            raise AssertionError("unexpected extra request")
        return self.responses.pop(0)


class _FakeS3BucketClient:
    def __init__(self, bucket, marker_key, marker_body):
        self.bucket = bucket
        self.marker_key = marker_key
        self.marker_body = marker_body
        self.created_buckets = []
        self.put_objects = []

    def list_buckets(self):
        return {"Buckets": [{"Name": self.bucket}]}

    def head_object(self, *, Bucket, Key, **kwargs):
        if (Bucket, Key) != (self.bucket, self.marker_key):
            raise AssertionError("unexpected object")
        return {"ETag": '"marker-etag"', "VersionId": "marker-version"}

    def get_object(self, *, Bucket, Key, **kwargs):
        if (Bucket, Key) != (self.bucket, self.marker_key):
            raise AssertionError("unexpected object")
        return {"Body": BytesIO(self.marker_body)}

    def create_bucket(self, **kwargs):
        self.created_buckets.append(kwargs)

    def put_object(self, **kwargs):
        self.put_objects.append(kwargs)


class _FakeS3CleanupClient:
    def __init__(self, marker_body):
        self.marker_body = marker_body
        self.deleted_objects = []
        self.deleted_buckets = []

    def head_bucket(self, *, Bucket):
        return {}

    def head_object(self, *, Bucket, Key, **kwargs):
        return {"ContentLength": len(self.marker_body), "VersionId": None}

    def get_object(self, *, Bucket, Key, **kwargs):
        return {"Body": BytesIO(self.marker_body)}

    def delete_object(self, *, Bucket, Key, **kwargs):
        self.deleted_objects.append((Bucket, Key, kwargs.get("VersionId")))

    def list_objects_v2(self, *, Bucket, **kwargs):
        if kwargs.get("ContinuationToken") == "objects-page-2":
            return {"Contents": [{"Key": "external-owner/object.txt"}]}
        return {
            "Contents": [{"Key": f"{RUN_ID}/ownership.json"}],
            "IsTruncated": True,
            "NextContinuationToken": "objects-page-2",
        }

    def list_object_versions(self, *, Bucket, **kwargs):
        if kwargs.get("KeyMarker") == "versions-page-2":
            return {
                "Versions": [
                    {
                        "Key": "external-owner/object.txt",
                        "VersionId": "external-version",
                    }
                ],
                "DeleteMarkers": [],
            }
        return {
            "Versions": [{"Key": f"{RUN_ID}/ownership.json", "VersionId": "null"}],
            "DeleteMarkers": [],
            "IsTruncated": True,
            "NextKeyMarker": "versions-page-2",
            "NextVersionIdMarker": "version-cursor",
        }

    def delete_bucket(self, *, Bucket):
        self.deleted_buckets.append(Bucket)


class _OwnedS3CleanupClient:
    def __init__(self, objects):
        self.objects = {key: dict(value) for key, value in objects.items()}
        self.deleted_objects = []
        self.deleted_buckets = []
        self.head_bucket_calls = 0

    def head_bucket(self, *, Bucket):
        self.head_bucket_calls += 1
        if Bucket in self.deleted_buckets:
            raise _S3NotFoundError("bucket absent")
        return {}

    def head_object(self, *, Bucket, Key, **kwargs):
        if Key not in self.objects:
            raise _S3NotFoundError("object absent")
        value = self.objects[Key]
        return {
            "ContentLength": len(value["body"]),
            "ETag": value.get("etag"),
            "VersionId": value.get("version_id"),
        }

    def get_object(self, *, Bucket, Key, **kwargs):
        return {"Body": BytesIO(self.objects[Key]["body"])}

    def list_objects_v2(self, *, Bucket, **kwargs):
        return {"Contents": [{"Key": key} for key in sorted(self.objects)]}

    def list_object_versions(self, *, Bucket, **kwargs):
        return {
            "Versions": [
                {
                    "Key": key,
                    "VersionId": value.get("version_id") or "null",
                }
                for key, value in sorted(self.objects.items())
            ],
            "DeleteMarkers": [],
        }

    def delete_object(self, *, Bucket, Key, **kwargs):
        self.deleted_objects.append((Bucket, Key, kwargs.get("VersionId")))
        self.objects.pop(Key)

    def delete_bucket(self, *, Bucket):
        self.deleted_buckets.append(Bucket)


class _EventuallyConsistentObjectClient:
    def __init__(self, *, bucket, key, body, version_id, visible_reads_after_delete=1):
        self.bucket = bucket
        self.key = key
        self.body = body
        self.version_id = version_id
        self.visible_reads_after_delete = visible_reads_after_delete
        self.delete_calls = []
        self.head_calls = 0
        self.deleted = False

    def delete_object(self, *, Bucket, Key, **kwargs):
        self.delete_calls.append((Bucket, Key, kwargs.get("VersionId")))
        self.deleted = True

    def head_object(self, *, Bucket, Key, **kwargs):
        self.head_calls += 1
        if self.deleted and self.visible_reads_after_delete > 0:
            self.visible_reads_after_delete -= 1
            return {
                "ContentLength": len(self.body),
                "ETag": '"etag"',
                "VersionId": self.version_id,
            }
        if self.deleted:
            raise _S3NotFoundError("version absent")
        return {
            "ContentLength": len(self.body),
            "ETag": '"etag"',
            "VersionId": self.version_id,
        }


class _EventuallyConsistentBucketClient:
    def __init__(self, *, visible_reads_after_delete=1):
        self.visible_reads_after_delete = visible_reads_after_delete
        self.delete_calls = []
        self.head_calls = 0
        self.deleted = False

    def head_bucket(self, *, Bucket):
        self.head_calls += 1
        if self.deleted and self.visible_reads_after_delete > 0:
            self.visible_reads_after_delete -= 1
            return {}
        if self.deleted:
            raise _S3NotFoundError("bucket absent")
        return {}

    def delete_bucket(self, *, Bucket):
        self.delete_calls.append(Bucket)
        self.deleted = True


class _UploadRecoveryS3Client:
    def __init__(self, objects):
        self.objects = {key: dict(value) for key, value in objects.items()}
        self.put_calls = []

    def list_objects_v2(self, *, Bucket, **kwargs):
        return {"Contents": [{"Key": key} for key in sorted(self.objects)]}

    def list_object_versions(self, *, Bucket, **kwargs):
        return {
            "Versions": [
                {"Key": key, "VersionId": value.get("version_id") or "null"}
                for key, value in sorted(self.objects.items())
            ],
            "DeleteMarkers": [],
            "IsTruncated": False,
        }

    def head_object(self, *, Bucket, Key, **kwargs):
        value = self.objects[Key]
        return {
            "ContentLength": len(value["body"]),
            "ETag": value.get("etag") or '"etag"',
            "VersionId": value.get("version_id") or "null",
        }

    def get_object(self, *, Bucket, Key, **kwargs):
        return {"Body": BytesIO(self.objects[Key]["body"])}

    def put_object(self, **kwargs):
        self.put_calls.append(kwargs)


class VultrLiveE2ELedgerSafetyTests(TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.ledger_path = os.path.join(self.temporary.name, "vultr.json")

    def _harness(self, *, apply=True, cleanup=False):
        harness = LiveVultrHarness.__new__(LiveVultrHarness)
        harness.prefix = RUN_ID
        harness.token = "unit-test-token"
        harness.api_base = "https://api.vultr.com/v2"
        harness.timeout = (10, 60)
        harness.apply = apply
        harness.cleanup_requested = cleanup
        harness.ledger = DurableResourceLedger(
            self.ledger_path,
            provider="vultr",
            run_id=RUN_ID,
            scope="unit-test-scope",
        )
        harness.intents = MutationIntentStore(
            self.ledger_path,
            run_id=RUN_ID,
            scope="unit-test-scope",
        )
        harness.created = {
            "instances": [],
            "snapshots": [],
            "blocks": [],
            "block_snapshots": [],
            "databases": [],
            "object_storages": [],
            "object_buckets": [],
            "object_keys": [],
        }
        harness.report = {
            "ledger": [],
            "tests": {},
            "cleanup": {"status": "NOT_RUN", "errors": []},
        }
        harness.account = None
        harness.member = None
        harness.user = None
        harness.local_ids = {}
        harness.object_client = None
        harness.object_credentials = {}
        return harness

    @staticmethod
    def _intent(marker, operation, *, request=None, kind=""):
        request = request or {
            "resource_type": "test",
            "marker": marker,
            "operation": operation,
        }
        return {
            "marker": marker,
            "operation": operation,
            "kind": kind,
            "role": operation,
            "request": request,
            "fingerprint": _request_fingerprint(request),
        }

    @staticmethod
    def _provider_resource_args(candidate, *, create=None):
        marker = f"{RUN_ID}-source-instance"
        return {
            "kind": "instance",
            "role": "source-instance",
            "marker": marker,
            "name": marker,
            "cache_key": "instances",
            "candidates": lambda: [candidate],
            "readback": lambda resource_id: candidate
            if resource_id == candidate.get("id")
            else None,
            "create": create or (lambda: {"instance": {"id": "must-not-create"}}),
            "id_from_response": lambda payload: (payload.get("instance") or {}).get("id"),
            "ownership": lambda item: {
                "label": f"{RUN_ID}-source-instance",
                "hostname": f"{RUN_ID}-source",
                "tags": [RUN_ID],
                "region": "ewr",
                "plan": "vc2-1c-1gb",
                "os_id": 2284,
            },
            "request": {
                "resource_type": "instance",
                "region": "ewr",
                "plan": "vc2-1c-1gb",
                "os_id": 2284,
                "label": f"{RUN_ID}-source-instance",
                "hostname": f"{RUN_ID}-source",
                "tags": [RUN_ID],
                "backups": "disabled",
            },
        }

    def _record_object_cleanup_resources(self, harness, objects):
        bucket = f"{RUN_ID}-bucket"
        marker_key = f"{RUN_ID}/ownership.json"
        marker_body = harness._object_marker_body(RUN_ID)
        object_storage = {
            "id": "os-owned",
            "label": f"{RUN_ID}-object-storage",
            "region": "ewr",
            "s3_hostname": "ewr1.vultrobjects.com",
        }
        harness.ledger.record(
            kind="object_storage",
            resource_id="os-owned",
            name=object_storage["label"],
            ownership={
                "run_id": RUN_ID,
                "role": "object-storage",
                "request_fingerprint": "a" * 64,
                "label": object_storage["label"],
                "region": "ewr",
                "s3_hostname": "ewr1.vultrobjects.com",
            },
        )
        harness.ledger.record(
            kind="object_bucket",
            resource_id=bucket,
            name=bucket,
            ownership={
                "run_id": RUN_ID,
                "role": "object-bucket",
                "request_fingerprint": "a" * 64,
                "bucket": bucket,
                "marker_key": marker_key,
                "marker_sha256": hashlib.sha256(marker_body).hexdigest(),
            },
        )
        for key, value in objects.items():
            role = "object-bucket-marker" if key == marker_key else "object-key"
            harness.ledger.record(
                kind="object_key",
                resource_id=f"{bucket}/{key}",
                name=key,
                ownership={
                    "run_id": RUN_ID,
                    "role": role,
                    "request_fingerprint": "a" * 64,
                    "bucket": bucket,
                    "key": key,
                    "etag": value.get("etag") or "",
                    "version_id": value.get("version_id") or "",
                    "sha256": hashlib.sha256(value["body"]).hexdigest(),
                    "size_bytes": len(value["body"]),
                },
                source_witness=bucket,
            )
        harness._read_detail = lambda path, key: object_storage
        return bucket, marker_key, marker_body, object_storage

    def test_api_base_is_exact_and_non_redirectable(self):
        self.assertEqual(
            _validate_vultr_api_base("https://api.vultr.com/v2"),
            "https://api.vultr.com/v2",
        )
        for value in (
            "http://api.vultr.com/v2",
            "https://api.vultr.com/v2/",
            "https://api.vultr.com/v1",
            "https://api.vultr.com/v2?next=evil",
            "https://api.vultr.com/v2#fragment",
            "https://user:pass@api.vultr.com/v2",
            "https://api.vultr.com:443/v2",
            "https://evil.example/v2",
        ):
            with self.subTest(value=value):
                with self.assertRaises(HarnessError):
                    _validate_vultr_api_base(value)

    def test_object_storage_hostname_is_https_only_and_vultr_owned(self):
        self.assertEqual(
            _validate_vultr_object_storage_hostname("ewr1.vultrobjects.com"),
            "ewr1.vultrobjects.com",
        )
        for value in (
            "https://ewr1.vultrobjects.com",
            "ewr1.vultrobjects.com:443",
            "ewr1.vultrobjects.com/path",
            "ewr1.vultrobjects.com?redirect=1",
            "user@ewr1.vultrobjects.com",
            "ewr1.other.example",
            "10.0.0.1",
            "a.b.vultrobjects.com",
            "ewr1.vultrobjects.com.",
        ):
            with self.subTest(value=value):
                with self.assertRaises(HarnessError):
                    _validate_vultr_object_storage_hostname(value)

    def test_untrusted_object_storage_hostname_is_rejected_before_client_credentials(self):
        harness = self._harness()
        with self.assertRaises(HarnessError):
            harness._object_client(
                {
                    "s3_hostname": "attacker.example",
                    "s3_access_key": "would-not-be-used",
                    "s3_secret_key": "would-not-be-used",
                }
            )
        self.assertEqual(harness.object_credentials, {})

    def test_request_uses_bounded_timeout_and_exact_api_origin(self):
        harness = self._harness()
        harness.session = _FakeSession()
        result = harness.request("GET", "/account")
        self.assertEqual(result, {"account": {}})
        self.assertEqual(len(harness.session.calls), 1)
        method, url, kwargs = harness.session.calls[0]
        self.assertEqual((method, url), ("GET", "https://api.vultr.com/v2/account"))
        self.assertEqual(kwargs["timeout"], (10, 60))
        self.assertFalse(kwargs["allow_redirects"])

    def test_get_retries_rate_limit_and_transient_failures_with_retry_after(self):
        harness = self._harness()
        responses = [
            _FakeResponse(status_code=429, headers={"Retry-After": "7"}),
            _FakeResponse(status_code=503),
            _FakeResponse(payload={"account": {"id": "owned"}}),
        ]
        harness.session = _SequenceSession(responses)
        with mock.patch("scripts.vultr_live_e2e.time.sleep") as sleep:
            result = harness.request("GET", "/account")

        self.assertEqual(result, {"account": {"id": "owned"}})
        self.assertEqual(len(harness.session.calls), 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [7, 6])
        self.assertTrue(all(response.closed for response in responses))

    def test_get_retry_is_bounded_and_closes_every_response(self):
        harness = self._harness()
        responses = [_FakeResponse(status_code=503) for _ in range(8)]
        harness.session = _SequenceSession(responses)
        with mock.patch("scripts.vultr_live_e2e.time.sleep") as sleep:
            with self.assertRaises(HarnessError):
                harness.request("GET", "/instances")

        self.assertEqual(len(harness.session.calls), 8)
        self.assertEqual(sleep.call_count, 7)
        self.assertTrue(all(response.closed for response in responses))

    def test_write_response_is_never_retried_and_is_closed(self):
        harness = self._harness()
        first = _FakeResponse(status_code=503)
        unused = _FakeResponse(status_code=201, payload={"instance": {"id": "i-two"}})
        harness.session = _SequenceSession([first, unused])
        with mock.patch("scripts.vultr_live_e2e.time.sleep") as sleep:
            with self.assertRaises(HarnessError):
                harness.request("POST", "/instances", expected=(201,), body={"label": "x"})

        self.assertEqual(len(harness.session.calls), 1)
        self.assertTrue(first.closed)
        self.assertFalse(unused.closed)
        sleep.assert_not_called()

    def test_request_exposes_provider_404_as_a_distinct_outcome(self):
        harness = self._harness()

        class NotFoundSession:
            def request(self, method, url, **kwargs):
                return _FakeResponse(status_code=404, body=b"{}")

        harness.session = NotFoundSession()
        with self.assertRaises(ProviderNotFound):
            harness.request("GET", "/instances/i-missing")

    def test_lost_create_response_is_adopted_after_restart_without_second_create(self):
        state = {}
        create_calls = []

        first = self._harness()

        def create_once():
            create_calls.append("create")
            state["resource"] = {
                "id": "i-owned",
                "label": f"{RUN_ID}-source-instance",
                "hostname": f"{RUN_ID}-source",
                "tags": [RUN_ID],
                "region": "ewr",
                "plan": "vc2-1c-1gb",
                "os_id": 2284,
            }
            raise requests.Timeout("simulated lost response")

        common = {
            "kind": "instance",
            "role": "source-instance",
            "marker": f"{RUN_ID}-source-instance",
            "name": f"{RUN_ID}-source-instance",
            "cache_key": "instances",
            "candidates": lambda: [state["resource"]] if state else [],
            "readback": lambda resource_id: (
                state.get("resource")
                if state.get("resource", {}).get("id") == resource_id
                else None
            ),
            "create": create_once,
            "id_from_response": lambda payload: (payload.get("instance") or {}).get("id"),
            "ownership": lambda item: {
                "label": f"{RUN_ID}-source-instance",
                "hostname": f"{RUN_ID}-source",
                "tags": [RUN_ID],
                "region": "ewr",
                "plan": "vc2-1c-1gb",
                "os_id": 2284,
            },
            "request": {
                "resource_type": "instance",
                "region": "ewr",
                "plan": "vc2-1c-1gb",
                "os_id": 2284,
                "label": f"{RUN_ID}-source-instance",
                "hostname": f"{RUN_ID}-source",
                "tags": [RUN_ID],
                "backups": "disabled",
            },
        }
        with self.assertRaises(AmbiguousMutation):
            first._ensure_provider_resource(**common)
        self.assertEqual(create_calls, ["create"])
        self.assertIsNotNone(first.intents.get("source-instance"))

        resumed = self._harness()
        resource_id, resource = resumed._ensure_provider_resource(**common)
        self.assertEqual(resource_id, "i-owned")
        self.assertEqual(resource["id"], "i-owned")
        self.assertEqual(create_calls, ["create"])
        self.assertIsNone(resumed.intents.get("source-instance"))
        self.assertEqual(resumed.ledger.get("instance", "i-owned")["ownership"]["run_id"], RUN_ID)

    def test_successful_create_is_verified_and_ledgered_before_intent_is_cleared(self):
        candidate = {
            "id": "i-created",
            "label": f"{RUN_ID}-source-instance",
            "hostname": f"{RUN_ID}-source",
            "tags": [RUN_ID],
            "region": "ewr",
            "plan": "vc2-1c-1gb",
            "os_id": 2284,
        }
        harness = self._harness()
        args = self._provider_resource_args(
            candidate,
            create=lambda: {"instance": {"id": candidate["id"]}},
        )
        args["candidates"] = lambda: []

        resource_id, resource = harness._ensure_provider_resource(**args)

        self.assertEqual(resource_id, candidate["id"])
        self.assertEqual(resource, candidate)
        entry = harness.ledger.get("instance", candidate["id"])
        self.assertEqual(
            entry["ownership"]["request_fingerprint"],
            _request_fingerprint(args["request"]),
        )
        self.assertIsNone(harness.intents.get(args["role"]))

    def test_pending_provider_reconciliation_adopts_exact_match_with_request_witness(self):
        harness = self._harness()
        candidate = {
            "id": "i-adopted",
            "label": f"{RUN_ID}-source-instance",
            "hostname": f"{RUN_ID}-source",
            "tags": [RUN_ID],
            "region": "ewr",
            "plan": "vc2-1c-1gb",
            "os_id": 2284,
        }
        args = self._provider_resource_args(candidate)
        intent = self._intent(
            args["marker"],
            args["role"],
            request=args["request"],
            kind=args["kind"],
        )
        harness.intents.set(args["role"], intent)
        harness.collection = lambda path, item_key: [candidate]
        harness._read_detail = lambda path, key: candidate

        state = harness._reconcile_pending_provider_intent(args["role"], intent)

        self.assertEqual(state, "adopted")
        adopted = harness.ledger.get("instance", "i-adopted")
        self.assertEqual(adopted["ownership"]["request_fingerprint"], _request_fingerprint(args["request"]))
        self.assertIsNone(harness.intents.get(args["role"]))

    def test_empty_provider_inventory_keeps_unknown_create_intent_durable(self):
        harness = self._harness()
        args = self._provider_resource_args(
            {
                "id": "not-visible-yet",
                "label": f"{RUN_ID}-source-instance",
                "hostname": f"{RUN_ID}-source",
                "tags": [RUN_ID],
                "region": "ewr",
                "plan": "vc2-1c-1gb",
                "os_id": 2284,
            }
        )
        intent = self._intent(
            args["marker"],
            args["role"],
            request=args["request"],
            kind=args["kind"],
        )
        harness.intents.set(args["role"], intent)
        harness.collection = lambda path, item_key: []

        self.assertEqual(
            harness._reconcile_pending_provider_intent(args["role"], intent),
            "unresolved",
        )
        self.assertEqual(harness.intents.get(args["role"]), intent)
        self.assertEqual(harness.ledger.entries(), [])

    def test_empty_inventory_stops_cleanup_and_local_graph_deletion(self):
        harness = self._harness(apply=True, cleanup=True)
        args = self._provider_resource_args(
            {
                "id": "accepted-but-hidden",
                "label": f"{RUN_ID}-source-instance",
                "hostname": f"{RUN_ID}-source",
                "tags": [RUN_ID],
                "region": "ewr",
                "plan": "vc2-1c-1gb",
                "os_id": 2284,
            }
        )
        intent = self._intent(
            args["marker"],
            args["role"],
            request=args["request"],
            kind=args["kind"],
        )
        harness.intents.set(args["role"], intent)
        harness.collection = lambda path, item_key: []

        class LocalRecord:
            def __init__(self):
                self.delete_calls = 0

            def delete(self):
                self.delete_calls += 1

        harness.account = LocalRecord()
        harness.member = LocalRecord()
        harness.user = LocalRecord()
        harness.cleanup()

        self.assertEqual(harness.report["cleanup"]["status"], "FAIL")
        self.assertEqual(harness.account.delete_calls, 0)
        self.assertEqual(harness.member.delete_calls, 0)
        self.assertEqual(harness.user.delete_calls, 0)
        self.assertIsNotNone(harness.intents.get(args["role"]))

    def test_provider_marker_collision_without_intent_is_not_adopted(self):
        harness = self._harness()
        candidate = {
            "id": "i-collision",
            "label": f"{RUN_ID}-source-instance",
            "hostname": f"{RUN_ID}-source",
            "tags": [RUN_ID],
            "region": "ewr",
            "plan": "vc2-1c-1gb",
        }
        create_calls = []
        args = self._provider_resource_args(
            candidate, create=lambda: create_calls.append("must-not-run")
        )

        with self.assertRaisesRegex(HarnessError, "without an exact pending intent"):
            harness._ensure_provider_resource(**args)

        self.assertEqual(create_calls, [])
        self.assertEqual(harness.ledger.entries(), [])

    def test_provider_marker_collision_rejects_mismatched_intent_witness(self):
        candidate = {
            "id": "i-collision",
            "label": f"{RUN_ID}-source-instance",
            "hostname": f"{RUN_ID}-source",
            "tags": [RUN_ID],
            "region": "ewr",
            "plan": "vc2-1c-1gb",
        }
        for intent in (
            {"marker": "different-marker", "operation": "source-instance"},
            {
                "marker": f"{RUN_ID}-source-instance",
                "operation": "different-operation",
            },
        ):
            with self.subTest(intent=intent):
                harness = self._harness()
                harness.intents.set(
                    "source-instance",
                    self._intent(intent["marker"], intent["operation"]),
                )
                with self.assertRaisesRegex(HarnessError, "different marker or operation"):
                    harness._ensure_provider_resource(
                        **self._provider_resource_args(candidate)
                    )
                self.assertEqual(harness.ledger.entries(), [])
                harness.intents.clear("source-instance")

    def test_adapter_marker_collision_without_intent_is_not_adopted(self):
        harness = self._harness()
        marker = f"{RUN_ID}-snapshot"
        candidate = {"id": "snap-collision", "description": marker}

        with self.assertRaisesRegex(HarnessError, "without an exact pending intent"):
            harness._prepare_adapter_resource(
                kind="snapshot",
                role="instance-snapshot",
                marker=marker,
                name=marker,
                candidates=lambda: [candidate],
                readback=lambda resource_id: candidate,
                ownership=lambda item: {"description": marker},
                request={
                    "resource_type": "instance_snapshot",
                    "description": marker,
                    "source_instance_id": "i-source",
                },
            )

        self.assertEqual(harness.ledger.entries(), [])

    def test_adapter_marker_collision_rejects_mismatched_intent_witness(self):
        marker = f"{RUN_ID}-snapshot"
        candidate = {"id": "snap-collision", "description": marker}
        for intent in (
            {"marker": "different-marker", "operation": "instance-snapshot"},
            {"marker": marker, "operation": "different-operation"},
        ):
            with self.subTest(intent=intent):
                harness = self._harness()
                harness.intents.set(
                    "instance-snapshot",
                    self._intent(intent["marker"], intent["operation"]),
                )
                with self.assertRaisesRegex(HarnessError, "different marker or operation"):
                    harness._prepare_adapter_resource(
                        kind="snapshot",
                        role="instance-snapshot",
                        marker=marker,
                        name=marker,
                        candidates=lambda: [candidate],
                        readback=lambda resource_id: candidate,
                        ownership=lambda item: {"description": marker},
                        request={
                            "resource_type": "instance_snapshot",
                            "description": marker,
                            "source_instance_id": "i-source",
                        },
                    )
                self.assertEqual(harness.ledger.entries(), [])
                harness.intents.clear("instance-snapshot")

    def test_pending_intent_without_unique_match_stops_without_retry(self):
        harness = self._harness()
        harness.intents.set(
            "source-instance",
            self._intent(f"{RUN_ID}-source-instance", "source-instance"),
        )
        create_calls = []
        with self.assertRaises(HarnessError):
            harness._ensure_provider_resource(
                kind="instance",
                role="source-instance",
                marker=f"{RUN_ID}-source-instance",
                name=f"{RUN_ID}-source-instance",
                cache_key="instances",
                candidates=lambda: [],
                readback=lambda resource_id: None,
                create=lambda: create_calls.append("must-not-run"),
                id_from_response=lambda payload: "",
                ownership=lambda item: {"label": f"{RUN_ID}-source-instance"},
                request={
                    "resource_type": "instance",
                    "region": "ewr",
                    "plan": "vc2-1c-1gb",
                    "os_id": 2284,
                    "label": f"{RUN_ID}-source-instance",
                    "hostname": f"{RUN_ID}-source",
                    "tags": [RUN_ID],
                    "backups": "disabled",
                },
            )
        self.assertEqual(create_calls, [])

    def test_empty_object_inventory_keeps_upload_intent_durable(self):
        harness = self._harness()
        bucket = f"{RUN_ID}-bucket"
        marker_key = f"{RUN_ID}/ownership.json"
        marker_body = harness._object_marker_body(RUN_ID)
        self._record_object_cleanup_resources(
            harness,
            {
                marker_key: {
                    "body": marker_body,
                    "etag": '"marker-etag"',
                    "version_id": "marker-version",
                }
            },
        )
        key = f"{RUN_ID}/not-visible-yet.zip"
        payload = b"accepted but eventually consistent"
        request = {
            "resource_type": "object_upload",
            "bucket": bucket,
            "key": key,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
            "marker_key": marker_key,
        }
        intent = self._intent(
            key,
            "Object Storage backup upload",
            request=request,
            kind="object_key",
        )
        harness.intents.set("object-key", intent)
        client = _UploadRecoveryS3Client(
            {
                marker_key: {
                    "body": marker_body,
                    "etag": '"marker-etag"',
                    "version_id": "marker-version",
                }
            }
        )

        self.assertEqual(
            harness._reconcile_pending_object_intent(client, "object-key", intent),
            "unresolved",
        )
        self.assertEqual(harness.intents.get("object-key"), intent)
        self.assertEqual(client.put_calls, [])

    def test_empty_bucket_inventory_keeps_bucket_and_marker_intents_durable(self):
        class EmptyBucketClient:
            def list_buckets(self):
                return {"Buckets": []}

        bucket = f"{RUN_ID}-empty-bucket"
        marker_key = f"{RUN_ID}/ownership.json"
        marker_hash = hashlib.sha256(
            LiveVultrHarness._object_marker_body(RUN_ID)
        ).hexdigest()
        cases = (
            (
                "object-bucket",
                bucket,
                "Object Storage bucket create",
                {
                    "resource_type": "object_bucket",
                    "bucket": bucket,
                    "object_storage_id": "",
                    "marker_key": marker_key,
                    "marker_sha256": marker_hash,
                },
            ),
            (
                "object-bucket-marker",
                marker_key,
                "Object Storage ownership marker",
                {
                    "resource_type": "object_marker",
                    "bucket": bucket,
                    "key": marker_key,
                    "sha256": marker_hash,
                    "size_bytes": len(
                        LiveVultrHarness._object_marker_body(RUN_ID)
                    ),
                },
            ),
        )
        for key, marker, operation, request in cases:
            with self.subTest(key=key):
                harness = self._harness()
                intent = self._intent(
                    marker,
                    operation,
                    request=request,
                    kind="object_bucket" if key == "object-bucket" else "object_key",
                )
                harness.intents.set(key, intent)

                self.assertEqual(
                    harness._reconcile_pending_object_intent(
                        EmptyBucketClient(), key, intent
                    ),
                    "unresolved",
                )
                self.assertEqual(harness.intents.get(key), intent)

    def test_duplicate_provider_matches_are_rejected_before_create(self):
        harness = self._harness()
        candidates = [
            {"id": "i-one", "label": f"{RUN_ID}-source-instance", "tags": [RUN_ID]},
            {"id": "i-two", "label": f"{RUN_ID}-source-instance", "tags": [RUN_ID]},
        ]
        create_calls = []
        with self.assertRaises(HarnessError):
            harness._ensure_provider_resource(
                kind="instance",
                role="source-instance",
                marker=f"{RUN_ID}-source-instance",
                name=f"{RUN_ID}-source-instance",
                cache_key="instances",
                candidates=lambda: candidates,
                readback=lambda resource_id: next(
                    item for item in candidates if item["id"] == resource_id
                ),
                create=lambda: create_calls.append("must-not-run"),
                id_from_response=lambda payload: "",
                ownership=lambda item: {
                    "label": f"{RUN_ID}-source-instance",
                    "tags": [RUN_ID],
                },
                request={
                    "resource_type": "instance",
                    "region": "ewr",
                    "plan": "vc2-1c-1gb",
                    "os_id": 2284,
                    "label": f"{RUN_ID}-source-instance",
                    "hostname": f"{RUN_ID}-source",
                    "tags": [RUN_ID],
                    "backups": "disabled",
                },
            )
        self.assertEqual(create_calls, [])
        self.assertEqual(harness.ledger.entries(), [])

    def test_existing_marked_bucket_without_intents_is_not_adopted(self):
        harness = self._harness()
        bucket = f"{RUN_ID}-bucket"
        marker_key = f"{RUN_ID}/ownership.json"
        marker_body = harness._object_marker_body(RUN_ID)
        client = _FakeS3BucketClient(bucket, marker_key, marker_body)

        with self.assertRaisesRegex(HarnessError, "without an exact pending intent"):
            harness._ensure_object_bucket(client, bucket)

        self.assertEqual(client.created_buckets, [])
        self.assertEqual(client.put_objects, [])
        self.assertEqual(harness.ledger.entries(), [])

    def test_existing_marked_bucket_rejects_mismatched_intent(self):
        harness = self._harness()
        bucket = f"{RUN_ID}-bucket"
        marker_key = f"{RUN_ID}/ownership.json"
        marker_body = harness._object_marker_body(RUN_ID)
        client = _FakeS3BucketClient(bucket, marker_key, marker_body)
        harness.intents.set(
            "object-bucket",
            self._intent(
                bucket,
                "Object Storage bucket create",
                request={
                    "resource_type": "object_bucket",
                    "bucket": bucket,
                    "object_storage_id": "",
                    "marker_key": marker_key,
                    "marker_sha256": hashlib.sha256(marker_body).hexdigest(),
                },
            ),
        )
        harness.intents.set(
            "object-bucket-marker",
            self._intent(
                marker_key,
                "different-operation",
                request={"resource_type": "wrong-marker", "key": marker_key},
            ),
        )

        with self.assertRaisesRegex(HarnessError, "different marker or operation"):
            harness._ensure_object_bucket(client, bucket)

        self.assertEqual(client.put_objects, [])
        self.assertEqual(harness.ledger.entries(), [])

    def test_existing_marked_bucket_with_exact_intents_is_recovered(self):
        harness = self._harness()
        bucket = f"{RUN_ID}-bucket"
        marker_key = f"{RUN_ID}/ownership.json"
        marker_body = harness._object_marker_body(RUN_ID)
        client = _FakeS3BucketClient(bucket, marker_key, marker_body)
        harness.intents.set(
            "object-bucket",
            self._intent(
                bucket,
                "Object Storage bucket create",
                request={
                    "resource_type": "object_bucket",
                    "bucket": bucket,
                    "object_storage_id": "",
                    "marker_key": marker_key,
                    "marker_sha256": hashlib.sha256(marker_body).hexdigest(),
                },
            ),
        )
        harness.intents.set(
            "object-bucket-marker",
            self._intent(
                marker_key,
                "Object Storage ownership marker",
                request={
                    "resource_type": "object_marker",
                    "bucket": bucket,
                    "key": marker_key,
                    "sha256": hashlib.sha256(marker_body).hexdigest(),
                    "size_bytes": len(marker_body),
                },
            ),
        )

        self.assertEqual(harness._ensure_object_bucket(client, bucket), bucket)

        marker_entry = harness.ledger.get("object_key", f"{bucket}/{marker_key}")
        self.assertEqual(marker_entry["ownership"]["etag"], '"marker-etag"')
        self.assertEqual(marker_entry["ownership"]["version_id"], "marker-version")
        self.assertIsNotNone(harness.ledger.get("object_bucket", bucket))
        self.assertIsNone(harness.intents.get("object-bucket"))
        self.assertIsNone(harness.intents.get("object-bucket-marker"))

    def test_pending_upload_recovery_runs_verified_adapter_before_completion(self):
        harness = self._harness()
        bucket = f"{RUN_ID}-bucket"
        key = f"{RUN_ID}/{RUN_ID}-file-backup.zip"
        payload = b"verified upload recovery"
        expected_hash = hashlib.sha256(payload).hexdigest()
        marker_key = f"{RUN_ID}/ownership.json"
        marker_body = harness._object_marker_body(RUN_ID)
        self._record_object_cleanup_resources(
            harness,
            {
                marker_key: {
                    "body": marker_body,
                    "etag": '"marker-etag"',
                    "version_id": "marker-version",
                },
            },
        )
        harness.intents.set(
            "object-key",
            self._intent(
                key,
                "Object Storage backup upload",
                request={
                    "resource_type": "object_upload",
                    "bucket": bucket,
                    "key": key,
                    "sha256": expected_hash,
                    "size_bytes": len(payload),
                    "marker_key": f"{RUN_ID}/ownership.json",
                },
            ),
        )

        class FakePoint:
            class Status:
                UPLOAD_READY = "UPLOAD_READY"
                UPLOAD_COMPLETE = "UPLOAD_COMPLETE"

            storage_file_id = ""
            status = Status.UPLOAD_READY
            metadata = {}

            def __init__(self):
                self.saved_fields = []
                self.metadata = {}

            def save(self, *, update_fields):
                self.saved_fields.append(tuple(update_fields))

            def refresh_from_db(self):
                return None

        point = FakePoint()
        client = _UploadRecoveryS3Client(
            {
                marker_key: {
                    "body": marker_body,
                    "etag": '"marker-etag"',
                    "version_id": "marker-version",
                },
                key: {
                    "body": payload,
                    "etag": '"verified-etag"',
                    "version_id": "version-7",
                },
            }
        )
        harness.object_client = client
        with mock.patch("scripts.vultr_live_e2e.storage_vultr") as adapter:
            entry, metadata, observed_hash = harness._run_verified_object_upload(
                point,
                bucket=bucket,
                expected_key=key,
                content=payload,
            )

        self.assertIsNotNone(entry)
        self.assertEqual(observed_hash, expected_hash)
        self.assertEqual(metadata["etag"], '"verified-etag"')
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)
        self.assertEqual(client.put_calls, [])
        adapter.assert_not_called()
        self.assertIsNotNone(harness.ledger.get("object_key", f"{bucket}/{key}"))

    def test_pending_upload_with_mismatched_witness_never_runs_adapter(self):
        harness = self._harness()
        key = f"{RUN_ID}/backup.zip"
        harness.intents.set(
            "object-key",
            self._intent(
                "different-key",
                "Object Storage backup upload",
                request={"resource_type": "different-upload", "key": "different-key"},
            ),
        )
        point = mock.Mock()
        point.storage_file_id = ""

        with mock.patch("scripts.vultr_live_e2e.storage_vultr") as adapter:
            with self.assertRaisesRegex(HarnessError, "different marker or operation"):
                harness._run_verified_object_upload(
                    point,
                    bucket=f"{RUN_ID}-bucket",
                    expected_key=key,
                    content=b"payload",
                )

        adapter.assert_not_called()

    def test_object_key_replay_intent_is_adopted_from_exact_ledger_identity(self):
        harness = self._harness()
        bucket = f"{RUN_ID}-bucket"
        marker_key = f"{RUN_ID}/ownership.json"
        key = f"{RUN_ID}/fixture.zip"
        marker_body = harness._object_marker_body(RUN_ID)
        payload = b"replay identity"
        payload_hash = hashlib.sha256(payload).hexdigest()
        self._record_object_cleanup_resources(
            harness,
            {
                marker_key: {
                    "body": marker_body,
                    "etag": '"marker-etag"',
                    "version_id": "marker-version",
                }
            },
        )
        request = {
            "resource_type": "object_upload",
            "bucket": bucket,
            "key": key,
            "sha256": payload_hash,
            "size_bytes": len(payload),
            "marker_key": marker_key,
        }
        harness.ledger.record(
            kind="object_key",
            resource_id=f"{bucket}/{key}",
            name=key,
            ownership={
                "run_id": RUN_ID,
                "role": "object-key",
                "request_fingerprint": _request_fingerprint(request),
                "bucket": bucket,
                "key": key,
                "etag": '"replay-etag"',
                "version_id": "replay-version",
                "sha256": payload_hash,
                "size_bytes": len(payload),
            },
            source_witness=bucket,
        )
        intent = self._intent(
            key,
            "Object Storage backup replay",
            request=request,
            kind="object_key",
        )
        harness.intents.set("object-key-replay", intent)
        client = _UploadRecoveryS3Client(
            {
                marker_key: {
                    "body": marker_body,
                    "etag": '"marker-etag"',
                    "version_id": "marker-version",
                },
                key: {
                    "body": payload,
                    "etag": '"replay-etag"',
                    "version_id": "replay-version",
                },
            }
        )

        self.assertEqual(
            harness._reconcile_pending_object_intent(
                client, "object-key-replay", intent
            ),
            "adopted",
        )
        self.assertIsNone(harness.intents.get("object-key-replay"))
        self.assertIsNotNone(harness.ledger.get("object_key", f"{bucket}/{key}"))

    def test_explicit_run_id_is_required_and_never_generated(self):
        with self.assertRaisesRegex(LedgerError, "BACKUPSHEEP_E2E_RUN_ID"):
            LiveVultrHarness._explicit_run_id({})
        self.assertEqual(
            LiveVultrHarness._explicit_run_id(
                {"BACKUPSHEEP_E2E_RUN_ID": RUN_ID}
            ),
            RUN_ID,
        )

    def test_cleanup_requires_both_mutation_and_cleanup_gates_without_provider_call(self):
        harness = self._harness(apply=False, cleanup=True)
        with self.assertRaises(HarnessError):
            harness.cleanup()
        self.assertEqual(harness.report["cleanup"]["status"], "NOT_RUN")

    def test_cleanup_without_cleanup_gate_is_read_only(self):
        harness = self._harness(apply=True, cleanup=False)
        harness.cleanup()
        self.assertEqual(harness.report["cleanup"]["status"], "NOT_REQUESTED")

    def test_cleanup_refuses_mismatched_exact_id_without_delete(self):
        harness = self._harness(apply=True, cleanup=True)

        class LocalRecord:
            def __init__(self, record_id):
                self.id = record_id
                self.delete_calls = 0

            def delete(self):
                self.delete_calls += 1

        harness.account = LocalRecord(101)
        harness.member = LocalRecord(102)
        harness.user = LocalRecord(103)
        harness.ledger.record(
            kind="instance",
            resource_id="i-owned",
            name=f"{RUN_ID}-source-instance",
            ownership={
                "run_id": RUN_ID,
                "role": "source-instance",
                "request_fingerprint": "a" * 64,
                "label": f"{RUN_ID}-source-instance",
                "hostname": f"{RUN_ID}-source",
                "tags": [RUN_ID],
                "region": "ewr",
                "plan": "vc2-1c-1gb",
            },
        )
        delete_calls = []
        harness._read_detail = lambda path, key: {
            "id": "i-external",
            "label": "someone-else",
            "hostname": "someone-else",
            "tags": [],
        }
        harness.request = lambda method, path, **kwargs: delete_calls.append((method, path))
        harness.cleanup()
        self.assertEqual(delete_calls, [])
        self.assertEqual(harness.report["cleanup"]["status"], "FAIL")
        self.assertEqual(
            harness.ledger.get("instance", "i-owned")["cleanup_state"],
            "manual_review",
        )
        self.assertEqual(harness.account.delete_calls, 0)
        self.assertEqual(harness.member.delete_calls, 0)
        self.assertEqual(harness.user.delete_calls, 0)
        self.assertTrue(harness.report["cleanup"]["local_graph_retained"])

    def test_provider_delete_waits_for_absence_before_clearing_intent(self):
        harness = self._harness(apply=True, cleanup=True)
        resource = {
            "id": "i-delete",
            "label": f"{RUN_ID}-source-instance",
            "hostname": f"{RUN_ID}-source",
            "tags": [RUN_ID],
            "region": "ewr",
            "plan": "vc2-1c-1gb",
            "os_id": 2284,
        }
        entry = harness.ledger.record(
            kind="instance",
            resource_id="i-delete",
            name=resource["label"],
            ownership={
                "run_id": RUN_ID,
                "role": "source-instance",
                "request_fingerprint": "a" * 64,
                "label": resource["label"],
                "hostname": resource["hostname"],
                "tags": [RUN_ID],
                "region": "ewr",
                "plan": "vc2-1c-1gb",
                "os_id": 2284,
            },
        )
        reads = mock.Mock(side_effect=[resource, resource, None])
        deletes = []
        harness._read_detail = reads
        harness.request = lambda method, path, **kwargs: deletes.append(
            (method, path)
        )
        errors = []
        with mock.patch("scripts.vultr_live_e2e.time.sleep"):
            harness._cleanup_provider_entry(
                entry,
                path_template="/instances/{resource_id}",
                response_key="instance",
                errors=errors,
            )

        self.assertEqual(errors, [])
        self.assertEqual(deletes, [("DELETE", "/instances/i-delete")])
        self.assertEqual(reads.call_count, 3)
        self.assertIsNone(harness.intents.get("cleanup:instance:i-delete"))
        self.assertEqual(
            harness.ledger.get("instance", "i-delete")["cleanup_state"],
            "deleted",
        )

    def test_provider_delete_timeout_retains_intent_and_cleanup_authority(self):
        harness = self._harness(apply=True, cleanup=True)
        resource = {
            "id": "i-timeout",
            "label": f"{RUN_ID}-source-instance",
            "hostname": f"{RUN_ID}-source",
            "tags": [RUN_ID],
            "region": "ewr",
            "plan": "vc2-1c-1gb",
            "os_id": 2284,
        }
        entry = harness.ledger.record(
            kind="instance",
            resource_id="i-timeout",
            name=resource["label"],
            ownership={
                "run_id": RUN_ID,
                "role": "source-instance",
                "request_fingerprint": "a" * 64,
                "label": resource["label"],
                "hostname": resource["hostname"],
                "tags": [RUN_ID],
                "region": "ewr",
                "plan": "vc2-1c-1gb",
                "os_id": 2284,
            },
        )
        harness._read_detail = lambda path, key: resource
        deletes = []
        harness.request = lambda method, path, **kwargs: deletes.append(
            (method, path)
        )
        harness._wait_for_provider_absence = mock.Mock(
            side_effect=ProviderTransientFailure("simulated timeout")
        )
        errors = []
        harness._cleanup_provider_entry(
            entry,
            path_template="/instances/{resource_id}",
            response_key="instance",
            errors=errors,
        )

        self.assertEqual(deletes, [("DELETE", "/instances/i-timeout")])
        self.assertTrue(errors)
        self.assertIsNotNone(harness.intents.get("cleanup:instance:i-timeout"))
        self.assertEqual(
            harness.ledger.get("instance", "i-timeout")["cleanup_state"],
            "failed",
        )

    def test_object_version_delete_waits_for_exact_absence_before_finalizing(self):
        harness = self._harness(apply=True, cleanup=True)
        bucket = f"{RUN_ID}-bucket"
        key = f"{RUN_ID}/fixture.zip"
        body = b"versioned fixture"
        entry = harness.ledger.record(
            kind="object_key",
            resource_id=f"{bucket}/{key}",
            name=key,
            ownership={
                "run_id": RUN_ID,
                "role": "object-key",
                "request_fingerprint": "a" * 64,
                "bucket": bucket,
                "key": key,
                "etag": '"etag"',
                "version_id": "version-1",
                "sha256": hashlib.sha256(body).hexdigest(),
                "size_bytes": len(body),
            },
            source_witness=bucket,
        )
        client = _EventuallyConsistentObjectClient(
            bucket=bucket,
            key=key,
            body=body,
            version_id="version-1",
            visible_reads_after_delete=1,
        )
        with mock.patch("scripts.vultr_live_e2e.time.sleep"):
            harness._delete_ledgered_object(client, bucket, entry)

        self.assertEqual(client.delete_calls, [(bucket, key, "version-1")])
        self.assertEqual(client.head_calls, 2)
        self.assertIsNone(
            harness.intents.get(f"cleanup:object_key:{bucket}/{key}")
        )
        self.assertEqual(
            harness.ledger.get("object_key", f"{bucket}/{key}")["cleanup_state"],
            "deleted",
        )

    def test_object_bucket_delete_waits_for_absence_before_finalizing(self):
        harness = self._harness(apply=True, cleanup=True)
        bucket = f"{RUN_ID}-bucket"
        entry = harness.ledger.record(
            kind="object_bucket",
            resource_id=bucket,
            name=bucket,
            ownership={
                "run_id": RUN_ID,
                "role": "object-bucket",
                "request_fingerprint": "a" * 64,
                "bucket": bucket,
                "marker_key": f"{RUN_ID}/ownership.json",
                "marker_sha256": hashlib.sha256(
                    harness._object_marker_body(RUN_ID)
                ).hexdigest(),
            },
        )
        cleanup_key = f"cleanup:object_bucket:{bucket}"
        harness._prepare_cleanup_intent(
            cleanup_key,
            bucket,
            "Object Storage bucket delete",
            harness._delete_request_for_entry(entry),
            kind="object_bucket",
        )
        client = _EventuallyConsistentBucketClient(visible_reads_after_delete=1)
        intent = harness.intents.get(cleanup_key)
        with mock.patch("scripts.vultr_live_e2e.time.sleep"):
            state = harness._reconcile_pending_delete_intent(
                client,
                cleanup_key,
                intent,
            )

        self.assertEqual(state, "cleaned")
        self.assertEqual(client.delete_calls, [bucket])
        self.assertEqual(client.head_calls, 3)
        self.assertIsNone(harness.intents.get(cleanup_key))
        self.assertEqual(
            harness.ledger.get("object_bucket", bucket)["cleanup_state"],
            "deleted",
        )

    def test_cleanup_rejects_subscription_mismatch_before_s3_credentials_are_used(self):
        harness = self._harness(apply=True, cleanup=True)
        harness.ledger.record(
            kind="object_storage",
            resource_id="os-owned",
            name=f"{RUN_ID}-object-storage",
            ownership={
                "run_id": RUN_ID,
                "role": "object-storage",
                "request_fingerprint": "a" * 64,
                "label": f"{RUN_ID}-object-storage",
                "region": "ewr",
                "s3_hostname": "ewr1.vultrobjects.com",
            },
        )
        harness._read_detail = lambda path, key: {
            "id": "os-owned",
            "label": "someone-else",
            "region": "ewr",
            "s3_hostname": "ewr1.vultrobjects.com",
            "s3_access_key": "must-not-be-used",
            "s3_secret_key": "must-not-be-used",
        }

        with mock.patch.object(harness, "_object_client") as object_client:
            with self.assertRaisesRegex(HarnessError, "exact ownership read-back"):
                harness._object_client_for_cleanup()

        object_client.assert_not_called()
        self.assertEqual(harness.object_credentials, {})

    def test_cleanup_never_deletes_unknown_object_keys(self):
        harness = self._harness(apply=True, cleanup=True)
        bucket = f"{RUN_ID}-bucket"
        marker_key = f"{RUN_ID}/ownership.json"
        marker_body = harness._object_marker_body(RUN_ID)
        object_storage = {
            "id": "os-owned",
            "label": f"{RUN_ID}-object-storage",
            "region": "ewr",
            "s3_hostname": "ewr1.vultrobjects.com",
        }
        harness.ledger.record(
            kind="object_storage",
            resource_id="os-owned",
            name=object_storage["label"],
            ownership={
                "run_id": RUN_ID,
                "role": "object-storage",
                "request_fingerprint": "a" * 64,
                "label": object_storage["label"],
                "region": "ewr",
                "s3_hostname": "ewr1.vultrobjects.com",
            },
        )
        harness.ledger.record(
            kind="object_bucket",
            resource_id=bucket,
            name=bucket,
            ownership={
                "run_id": RUN_ID,
                "role": "object-bucket",
                "request_fingerprint": "a" * 64,
                "bucket": bucket,
                "marker_key": marker_key,
                "marker_sha256": hashlib.sha256(marker_body).hexdigest(),
            },
        )
        harness.ledger.record(
            kind="object_key",
            resource_id=f"{bucket}/{marker_key}",
            name=marker_key,
            ownership={
                "run_id": RUN_ID,
                "role": "object-bucket-marker",
                "request_fingerprint": "a" * 64,
                "bucket": bucket,
                "key": marker_key,
                "sha256": hashlib.sha256(marker_body).hexdigest(),
                "size_bytes": len(marker_body),
            },
            source_witness=bucket,
        )
        client = _FakeS3CleanupClient(marker_body)
        harness.object_client = client
        harness._read_detail = lambda path, key: object_storage
        harness.cleanup()
        self.assertEqual(client.deleted_objects, [])
        self.assertEqual(client.deleted_buckets, [])
        self.assertIn("unknown resources", " ".join(harness.report["cleanup"]["errors"]))
        self.assertEqual(
            harness.ledger.get("object_key", f"{bucket}/{marker_key}")["cleanup_state"],
            "eligible",
        )
        self.assertEqual(
            harness.ledger.get("object_bucket", bucket)["cleanup_state"],
            "manual_review",
        )
        self.assertEqual(
            harness.ledger.get("object_storage", "os-owned")["cleanup_state"],
            "eligible",
        )

    def test_cleanup_rejects_unknown_historical_version_before_any_delete(self):
        harness = self._harness(apply=True, cleanup=True)
        marker_key = f"{RUN_ID}/ownership.json"
        marker_body = harness._object_marker_body(RUN_ID)
        objects = {
            marker_key: {
                "body": marker_body,
                "etag": '"marker-etag"',
                "version_id": "marker-current",
            }
        }
        bucket, _, _, _ = self._record_object_cleanup_resources(harness, objects)
        client = _OwnedS3CleanupClient(objects)
        client.list_object_versions = lambda **kwargs: {
            "Versions": [
                {"Key": marker_key, "VersionId": "marker-current"},
                {"Key": marker_key, "VersionId": "marker-old"},
            ],
            "DeleteMarkers": [],
        }
        harness.object_client = client

        harness.cleanup()

        self.assertEqual(client.deleted_objects, [])
        self.assertEqual(client.deleted_buckets, [])
        self.assertEqual(
            harness.ledger.get("object_bucket", bucket)["cleanup_state"],
            "manual_review",
        )
        self.assertIn("unknown resources", " ".join(harness.report["cleanup"]["errors"]))

    def test_safe_object_cleanup_deletes_marker_last_then_bucket_and_subscription(self):
        harness = self._harness(apply=True, cleanup=True)
        marker_key = f"{RUN_ID}/ownership.json"
        data_key = f"{RUN_ID}/backup.zip"
        marker_body = harness._object_marker_body(RUN_ID)
        objects = {
            marker_key: {
                "body": marker_body,
                "etag": '"marker-etag"',
                "version_id": "marker-version",
            },
            data_key: {
                "body": b"owned backup payload",
                "etag": '"data-etag"',
                "version_id": "data-version",
            },
        }
        bucket, _, _, object_storage = self._record_object_cleanup_resources(
            harness, objects
        )
        client = _OwnedS3CleanupClient(objects)
        provider_deletes = []
        harness.object_client = client
        provider_present = {"value": True}

        def read_detail(path, key):
            if path == "/object-storage/os-owned" and not provider_present["value"]:
                return None
            return object_storage

        def request(method, path, **kwargs):
            provider_deletes.append((method, path))
            if method == "DELETE" and path == "/object-storage/os-owned":
                provider_present["value"] = False

        harness._read_detail = read_detail
        harness.request = request

        harness.cleanup()

        self.assertEqual(
            client.deleted_objects,
            [
                (bucket, data_key, "data-version"),
                (bucket, marker_key, "marker-version"),
            ],
        )
        self.assertEqual(client.deleted_buckets, [bucket])
        self.assertEqual(
            provider_deletes,
            [("DELETE", "/object-storage/os-owned")],
        )
        self.assertEqual(client.head_bucket_calls, 2)
        self.assertEqual(harness.report["cleanup"]["status"], "PASS")

    def test_object_inventory_rejects_repeated_cursor_with_a_bounded_read(self):
        class RepeatedCursorClient:
            def __init__(self):
                self.calls = 0

            def list_objects_v2(self, **kwargs):
                self.calls += 1
                return {
                    "Contents": [{"Key": f"key-{self.calls}"}],
                    "IsTruncated": True,
                    "NextContinuationToken": "same-token",
                }

        client = RepeatedCursorClient()
        with self.assertRaisesRegex(HarnessError, "repeated or missing"):
            LiveVultrHarness._bounded_object_inventory(client, "bucket")
        self.assertEqual(client.calls, 2)

    def test_collection_rejects_duplicate_ids_across_cursor_pages(self):
        harness = self._harness()
        pages = iter(
            [
                {"instances": [{"id": "i-one"}], "meta": {"links": {"next": "cursor-1"}}},
                {"instances": [{"id": "i-one"}], "meta": {"links": {}}},
            ]
        )
        harness.request = lambda method, path, **kwargs: next(pages)
        with self.assertRaises(HarnessError):
            harness.collection("/instances", "instances")

    def test_collection_accepts_complete_total_only_provider_response(self):
        harness = self._harness()
        harness.request = lambda method, path, **kwargs: {
            "databases": [{"id": "db-one"}],
            "meta": {"total": 1},
        }

        self.assertEqual(
            harness.collection("/databases", "databases"),
            [{"id": "db-one"}],
        )

    def test_collection_rejects_partial_total_without_cursor(self):
        harness = self._harness()
        harness.request = lambda method, path, **kwargs: {
            "databases": [{"id": "db-one"}],
            "meta": {"total": 2},
        }

        with self.assertRaisesRegex(HarnessError, "without a continuation cursor"):
            harness.collection("/databases", "databases")

    def test_object_storage_ownership_accepts_omitted_tier_but_not_mismatch(self):
        harness = self._harness()
        harness.object_tier_id = 2
        harness.object_cluster_id = 2
        resource = {
            "id": "object-one",
            "label": f"{RUN_ID}-object-storage",
            "region": "ewr",
            "cluster_id": 2,
            "tier_id": None,
            "s3_hostname": "ewr1.vultrobjects.com",
        }

        proof = harness._object_storage_ownership(resource)

        self.assertNotIn("tier_id", proof)
        self.assertEqual(proof["cluster_id"], 2)
        resource["tier_id"] = 3
        with self.assertRaisesRegex(HarnessError, "different tier"):
            harness._object_storage_ownership(resource)

    def test_provider_ownership_normalizes_only_region_case(self):
        harness = self._harness()
        resource = {
            "id": "database-one",
            "label": f"{RUN_ID}-database",
            "region": "EWR",
            "plan": "database-plan",
            "database_engine": "pg",
            "database_engine_version": "16",
        }
        entry = {
            "resource_id": "database-one",
            "ownership": {
                "request_fingerprint": "a" * 64,
                "label": f"{RUN_ID}-database",
                "region": "ewr",
                "plan": "database-plan",
                "database_engine": "pg",
                "database_engine_version": "16",
            },
        }

        self.assertTrue(harness._resource_matches_entry(resource, entry))
        harness._assert_poll_ownership(
            resource,
            provider_id="database-one",
            expected={"region": "ewr", "plan": "database-plan"},
        )
        resource["plan"] = "different-plan"
        self.assertFalse(harness._resource_matches_entry(resource, entry))

    def test_failed_live_case_is_recorded_and_fails_closed(self):
        harness = self._harness()

        with self.assertRaisesRegex(HarnessError, "VUL-TEST"):
            harness.record_test("VUL-TEST", "FAIL", reason="identity mismatch")

        self.assertEqual(harness.report["tests"]["VUL-TEST"]["status"], "FAIL")

    def test_database_cleanup_422_requires_complete_zero_match_inventory(self):
        harness = self._harness()
        harness.session = _SequenceSession(
            [
                _FakeResponse(status_code=422, payload={"error": "deleting"}),
                _FakeResponse(payload={"databases": [], "meta": {"total": 0}}),
            ]
        )
        entry = {"kind": "database", "resource_id": "database-one"}

        self.assertIsNone(
            harness._read_cleanup_resource(
                entry, "/databases/database-one", "database"
            )
        )
        self.assertEqual(len(harness.session.calls), 2)

    def test_database_cleanup_422_returns_exact_inventory_match(self):
        database = {
            "id": "database-one",
            "label": f"{RUN_ID}-database",
            "region": "EWR",
        }
        harness = self._harness()
        harness.session = _SequenceSession(
            [
                _FakeResponse(status_code=422, payload={"error": "deleting"}),
                _FakeResponse(
                    payload={"databases": [database], "meta": {"total": 1}}
                ),
            ]
        )

        self.assertEqual(
            harness._read_cleanup_resource(
                {"kind": "database", "resource_id": "database-one"},
                "/databases/database-one",
                "database",
            ),
            database,
        )

    def test_restore_block_cleanup_accepts_only_ledgered_omitted_snapshot(self):
        harness = self._harness()
        resource = {
            "id": "block-one",
            "label": "backupsheep-restore-41",
            "region": "ewr",
            "size_gb": 10,
            "snapshot_id": "",
        }
        entry = {
            "resource_id": "block-one",
            "source_witness": "snapshot-one",
            "ownership": {
                "request_fingerprint": "a" * 64,
                "role": "restore-block",
                "label": "backupsheep-restore-41",
                "region": "ewr",
                "size_gb": 10,
                "snapshot_id": "snapshot-one",
            },
        }

        self.assertTrue(harness._resource_matches_entry(resource, entry))
        entry["source_witness"] = "different-snapshot"
        self.assertFalse(harness._resource_matches_entry(resource, entry))
        entry["source_witness"] = "snapshot-one"
        resource["snapshot_id"] = "different-snapshot"
        self.assertFalse(harness._resource_matches_entry(resource, entry))
