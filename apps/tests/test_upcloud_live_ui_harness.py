"""Offline safety acceptance tests for the UpCloud live UI harness."""

from __future__ import annotations

import io
import json
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from copy import deepcopy
from pathlib import Path
from unittest import mock

import requests
from django.test import SimpleTestCase

from scripts import upcloud_live_ui_e2e as live_harness


class Body:
    def __init__(self, payload: bytes):
        self._stream = io.BytesIO(payload)
        self.closed = False

    def read(self, size=-1):
        return self._stream.read(size)

    def close(self):
        self.closed = True
        self._stream.close()


class Response:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self.payload = payload if payload is not None else {}
        self.closed = False

    def json(self):
        return self.payload

    def close(self):
        self.closed = True


class S3Failure(Exception):
    def __init__(self, status=None, code="ProviderFailure"):
        super().__init__(code)
        self.response = {
            "Error": {"Code": code},
            "ResponseMetadata": {},
        }
        if status is not None:
            self.response["ResponseMetadata"]["HTTPStatusCode"] = status


def service(run_id, service_id="service-uuid", region="europe-1"):
    names = live_harness._resource_names(run_id)
    return {
        "uuid": service_id,
        "name": names["service"],
        "region": region,
        "configured_status": "started",
        "operational_state": "running",
        "termination_protection": False,
        "labels": live_harness._labels(run_id),
        "networks": [
            {
                "name": names["network"],
                "type": "public",
                "family": "IPv4",
            }
        ],
        "endpoints": [
            {
                "domain_name": "safe1.upcloudobjects.com",
                "type": "public",
                "mode": "api",
            }
        ],
    }


class UpCloudLiveUIHarnessSafetyTests(SimpleTestCase):
    run_id = "bs-e2e-upcloud-offline"
    account = "allowed-account"
    region = "europe-1"

    def setUp(self):
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def config(self, *, apply=False, cleanup=False):
        return live_harness.HarnessConfig(
            run_id=self.run_id,
            ledger_path=self.root / "ledger.json",
            account=self.account,
            region=self.region,
            runtime_path=self.root / "runtime.json",
            apply=apply,
            cleanup=cleanup,
        )

    def harness(self, *, apply=False, cleanup=False, control=None, s3_factory=None):
        return live_harness.UpCloudLiveHarness(
            self.config(apply=apply, cleanup=cleanup),
            environment={"UPCLOUD_API_TOKEN": "TOKEN-CANARY"},
            control=control or mock.Mock(),
            s3_factory=s3_factory,
            sleeper=lambda _seconds: None,
        )

    def seed_service(self, harness):
        harness.account = self.account
        value = service(self.run_id, region=self.region)
        harness._record_service(value, harness._service_request())
        return value

    def seed_bucket(self, harness, value):
        request = harness._bucket_request()
        harness._record_bucket(
            value["uuid"], {"name": harness.names["bucket"]}, request
        )

    def seed_user_policy_key(self, harness, value, *, key_id="KEY-CANARY"):
        user = {
            "username": harness.names["username"],
            "arn": f"urn:ecs:iam::test:user/{harness.names['username']}",
        }
        harness._record_user(
            value["uuid"], user, {"username": harness.names["username"]}
        )
        request = harness._policy_request()
        harness._record_policy(
            value["uuid"],
            harness.names["username"],
            {"name": harness.names["policy"], "document": request["document"]},
            request,
        )
        harness._record_access_key(
            value["uuid"],
            harness.names["username"],
            {"access_key_id": key_id, "status": "Active"},
        )
        return user

    def write_runtime(self, harness, value, *, key_id="KEY-CANARY"):
        payload = harness._runtime_payload(
            service=value,
            access_key=key_id,
            secret_key="SECRET-CANARY",
        )
        live_harness._write_runtime_secret(harness.config.runtime_path, payload)
        return payload

    def arm_bucket_for_manifest(self, harness, value, runtime):
        harness.ledger.record(
            kind="mos_bucket_configuration",
            resource_id=f"{value['uuid']}:{runtime['bucket_name']}:versioning",
            name=runtime["bucket_name"],
            ownership={
                "account": self.account,
                "run_id": self.run_id,
                "service_uuid": value["uuid"],
                "bucket": runtime["bucket_name"],
                "versioning": "Enabled",
            },
            source_witness=value["uuid"],
        )

    def _assert_manifest_envelope_rejected_before_provider(
        self, manifest, message
    ):
        harness = self.harness(apply=True)
        manifest_path = self.root / "invalid-envelope.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with mock.patch.object(harness, "verify_account") as verify_account, \
            mock.patch.object(harness, "_service_read") as service_read, \
            mock.patch.object(harness, "_s3") as s3, \
            mock.patch.object(harness, "_s3_inventory") as inventory, \
            self.assertRaisesRegex(live_harness.HarnessError, message):
            harness.verify_ui_objects(str(manifest_path), maximum_bytes=1024)

        verify_account.assert_not_called()
        service_read.assert_not_called()
        s3.assert_not_called()
        inventory.assert_not_called()

    def test_ui_manifest_requires_json_object_before_provider_inventory(self):
        self._assert_manifest_envelope_rejected_before_provider(
            [], r"JSON object"
        )

    def test_ui_manifest_rejects_wrong_schema_before_provider_inventory(self):
        self._assert_manifest_envelope_rejected_before_provider(
            {"schema": 2, "run_id": self.run_id, "objects": []},
            r"schema must be 1",
        )

    def test_ui_manifest_rejects_missing_schema_before_provider_inventory(self):
        self._assert_manifest_envelope_rejected_before_provider(
            {"run_id": self.run_id, "objects": []}, r"schema must be 1"
        )

    def test_ui_manifest_rejects_wrong_run_id_before_provider_inventory(self):
        self._assert_manifest_envelope_rejected_before_provider(
            {"schema": 1, "run_id": "another-run", "objects": []},
            r"run_id does not match",
        )

    def test_ui_manifest_rejects_missing_run_id_before_provider_inventory(self):
        self._assert_manifest_envelope_rejected_before_provider(
            {"schema": 1, "objects": []}, r"run_id does not match"
        )

    def test_plan_is_offline_and_never_reads_or_prints_token(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            live_harness,
            "UpCloudControlPlane",
            side_effect=AssertionError("must stay offline"),
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            result = live_harness.main(
                ["plan"], environment={"UPCLOUD_API_TOKEN": "TOKEN-CANARY"}
            )

        self.assertEqual(result, 0)
        self.assertIn('"network_calls": false', stdout.getvalue())
        self.assertNotIn("TOKEN-CANARY", stdout.getvalue() + stderr.getvalue())

    def test_setup_and_cleanup_require_independent_explicit_gates(self):
        control = mock.Mock()
        with self.assertRaises(live_harness.HarnessError):
            self.harness(apply=False, control=control).setup_object_storage()
        control.request.assert_not_called()

        with self.assertRaises(live_harness.HarnessError):
            self.harness(
                apply=True, cleanup=False, control=control
            ).cleanup_object_storage(maximum_bytes=1024)
        control.request.assert_not_called()

    def test_waiter_accepts_current_documented_setup_states(self):
        harness = self.harness(apply=True)
        transitional = service(self.run_id, region=self.region)
        transitional["operational_state"] = "setup-public-endpoint"
        ready = service(self.run_id, region=self.region)
        with mock.patch.object(
            harness,
            "_service_read",
            side_effect=[
                live_harness.ProviderUnavailable("temporary"),
                transitional,
                ready,
            ],
        ) as read:
            result = harness.wait_service_ready(transitional)
        self.assertEqual(result["operational_state"], "running")
        self.assertEqual(read.call_count, 3)

    def test_runtime_secret_is_mode_0600_and_ledger_never_contains_credentials(self):
        harness = self.harness(apply=True)
        value = self.seed_service(harness)
        self.seed_user_policy_key(harness, value)
        payload = self.write_runtime(harness, value)

        self.assertEqual(
            oct(harness.config.runtime_path.stat().st_mode & 0o777), "0o600"
        )
        self.assertEqual(
            live_harness._read_runtime_secret(harness.config.runtime_path), payload
        )
        ledger = harness.config.ledger_path.read_text(encoding="utf-8")
        self.assertNotIn("KEY-CANARY", ledger)
        self.assertNotIn("SECRET-CANARY", ledger)
        self.assertIn(live_harness._hash("KEY-CANARY"), ledger)

    def test_runtime_secret_inside_unignored_worktree_location_is_refused(self):
        unsafe = live_harness.ROOT / "runtime-secret-canary.json"
        with self.assertRaises(live_harness.HarnessError):
            live_harness._write_runtime_secret(
                unsafe,
                {
                    field: "value"
                    for field in live_harness.RUNTIME_FIELDS
                },
            )
        self.assertFalse(unsafe.exists())

    def test_policy_is_prefix_and_bucket_scoped_without_wildcard_resources(self):
        names = live_harness._resource_names(self.run_id)
        policy = live_harness._policy_document(names["bucket"], names["prefix"])
        statements = policy["Statement"]

        self.assertTrue(statements)
        self.assertNotIn("*", [statement["Resource"] for statement in statements])
        self.assertTrue(
            all(
                statement["Resource"].startswith(
                    f"arn:aws:s3:::{names['bucket']}"
                )
                for statement in statements
            )
        )
        self.assertTrue(
            all(
                action.startswith("s3:") and action != "s3:*"
                for statement in statements
                for action in statement["Action"]
            )
        )
        inventory = next(
            statement
            for statement in statements
            if statement["Sid"] == "BackupSheepBoundedInventory"
        )
        self.assertEqual(
            inventory["Condition"]["StringLike"]["s3:prefix"],
            [names["prefix"], f"{names['prefix']}*"],
        )
        request = self.harness()._policy_request()
        self.assertEqual(json.loads(request["document"]), policy)
        self.assertTrue(request["document"].startswith("{"))

    def test_control_plane_uses_timeout_no_redirects_and_redacts_lost_response(self):
        response = Response(200, {"account": {"username": self.account}})
        session = mock.Mock()
        session.request.return_value = response
        control = live_harness.UpCloudControlPlane(
            "TOKEN-CANARY", session=session
        )

        self.assertEqual(
            control.request("GET", "/account"),
            {"account": {"username": self.account}},
        )
        self.assertEqual(session.request.call_args.kwargs["timeout"], (10.0, 60.0))
        self.assertFalse(session.request.call_args.kwargs["allow_redirects"])
        self.assertTrue(response.closed)

        session.request.side_effect = requests.Timeout("TOKEN-CANARY")
        with self.assertRaises(live_harness.AmbiguousMutation) as raised:
            control.request("POST", "/object-storage-2", mutation=True)
        self.assertNotIn("TOKEN-CANARY", str(raised.exception))

    def test_control_plane_exposes_only_bounded_provider_error_code(self):
        response = Response(
            400,
            {
                "error": {
                    "error_code": "UNKNOWN_ATTRIBUTE",
                    "error_message": (
                        "Unknown attribute boot_disk. SECRET-CANARY provider diagnostic"
                    ),
                }
            },
        )
        session = mock.Mock()
        session.request.return_value = response
        control = live_harness.UpCloudControlPlane(
            "TOKEN-CANARY", session=session
        )

        with self.assertRaises(live_harness.HarnessError) as raised:
            control.request("POST", "/server", mutation=True)

        self.assertIn("UNKNOWN_ATTRIBUTE:BOOT_DISK", str(raised.exception))
        self.assertNotIn("SECRET-CANARY", str(raised.exception))
        self.assertNotIn("TOKEN-CANARY", str(raised.exception))
        self.assertTrue(response.closed)

    def test_provider_firewall_inventory_rejects_empty_chain(self):
        harness = self.harness(apply=True)
        harness.control.request.return_value = {
            "firewall_rules": {"firewall_rule": []}
        }
        with self.assertRaisesRegex(live_harness.HarnessError, r"empty firewall"):
            harness._provider_firewall_inventory(
                "11111111-1111-4111-8111-111111111111"
            )

    def test_empty_chain_is_not_evidence_of_default_drop(self):
        default_drop = live_harness._normalize_firewall_rule(
            {"direction": "in", "action": "drop"}
        )
        self.assertFalse(
            live_harness.UpCloudLiveHarness._provider_firewall_is_default_drop(
                {"rules": []}
            )
        )
        self.assertTrue(
            live_harness.UpCloudLiveHarness._provider_firewall_is_default_drop(
                {"rules": [default_drop]}
            )
        )

    def test_source_server_request_omits_public_interface_until_firewall_is_verified(self):
        harness = self.harness(apply=True)
        request = harness._source_server_request(
            "11111111-1111-4111-8111-111111111111", "ssh-rsa PUBLIC"
        )
        interfaces = request["server"]["networking"]["interfaces"]["interface"]
        self.assertEqual([interface["type"] for interface in interfaces], ["utility"])

    def test_public_ip_assignment_waits_for_firewall_stabilization_without_duplicate_post(self):
        harness = self.harness(apply=True)
        server_id = "11111111-1111-4111-8111-111111111111"
        utility = {
            "uuid": server_id,
            "networking": {
                "interfaces": {
                    "interface": [
                        {
                            "index": 1,
                            "type": "utility",
                            "ip_addresses": {
                                "ip_address": [{"family": "IPv4"}]
                            },
                        }
                    ]
                }
            },
        }
        public = deepcopy(utility)
        public["networking"]["interfaces"]["interface"].append(
            {
                "index": 2,
                "type": "public",
                "ip_addresses": {"ip_address": [{"family": "IPv4"}]},
            }
        )
        base = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
        harness.clock = lambda: base
        harness._server_read = mock.Mock(return_value=utility)
        harness._control_mutation = mock.Mock()
        verified_at = base.isoformat()

        with self.assertRaisesRegex(
            live_harness.HarnessError, r"120-second stabilization window"
        ):
            harness._ensure_provider_public_ip_families(
                server_id,
                ("IPv4",),
                firewall_verified_at=verified_at,
            )
        harness._control_mutation.assert_not_called()

        harness.clock = lambda: datetime(2026, 8, 12, 12, 2, tzinfo=timezone.utc)
        harness._server_read = mock.Mock(side_effect=[utility, public, public])
        result = harness._ensure_provider_public_ip_families(
            server_id,
            ("IPv4",),
            firewall_verified_at=verified_at,
        )
        self.assertEqual(result, public)
        harness._control_mutation.assert_called_once()
        self.assertEqual(harness._control_mutation.call_args.args[:3], (
            "compute_source_public_ip:11111111-1111-4111-8111-111111111111:0:IPv4",
            "POST",
            "/ip_address",
        ))

    def test_definite_mutation_rejection_clears_intent_but_lost_response_keeps_it(self):
        harness = self.harness(apply=True)
        intent_key = "mutation-canary"
        intent = {
            "marker": self.run_id,
            "kind": "canary",
            "name": "canary",
            "operation": "create",
        }
        harness.intents.put(intent_key, intent)
        harness.intents.update(intent_key, request_boundary_crossed=True)
        harness.control.request.side_effect = live_harness.HarnessError(
            "definite rejection", definitive_rejection=True
        )
        with self.assertRaises(live_harness.HarnessError):
            harness._control_mutation(intent_key, "POST", "/object-storage-2")
        self.assertIsNone(harness.intents.get(intent_key))

        harness.intents.put(intent_key, intent)
        harness.intents.update(intent_key, request_boundary_crossed=True)
        harness.control.request.side_effect = live_harness.AmbiguousMutation(
            "lost response"
        )
        with self.assertRaises(live_harness.AmbiguousMutation):
            harness._control_mutation(intent_key, "POST", "/object-storage-2")
        self.assertTrue(
            harness.intents.get(intent_key)["request_boundary_crossed"]
        )

    def test_control_mutation_definitive_4xx_categories_clear_only_their_intent(self):
        for status in (400, 403, 404, 429):
            with self.subTest(status=status):
                response = Response(status, {"error": {"error_code": "DENIED"}})
                session = mock.Mock()
                session.request.return_value = response
                control = live_harness.UpCloudControlPlane(
                    "TOKEN-CANARY", session=session
                )
                harness = self.harness(apply=True, control=control)
                intent_key = f"control-{status}"
                harness.intents.put(
                    intent_key,
                    {
                        "marker": self.run_id,
                        "kind": "canary",
                        "name": "canary",
                        "operation": "create",
                    },
                )
                harness.intents.update(intent_key, request_boundary_crossed=True)
                with self.assertRaises(live_harness.HarnessError) as raised:
                    harness._control_mutation(
                        intent_key, "POST", "/object-storage-2"
                    )
                self.assertNotIsInstance(
                    raised.exception, live_harness.AmbiguousMutation
                )
                self.assertIsNone(harness.intents.get(intent_key))

    def test_control_mutation_transient_and_unknown_categories_retain_intent(self):
        cases = (
            (408, "REQUEST_TIMEOUT"),
            (500, "SERVER_ERROR"),
            (504, "GATEWAY_TIMEOUT"),
        )
        for status, code in cases:
            with self.subTest(status=status):
                session = mock.Mock()
                session.request.return_value = Response(
                    status, {"error": {"error_code": code}}
                )
                control = live_harness.UpCloudControlPlane(
                    "TOKEN-CANARY", session=session
                )
                harness = self.harness(apply=True, control=control)
                intent_key = f"control-{status}"
                harness.intents.put(
                    intent_key,
                    {
                        "marker": self.run_id,
                        "kind": "canary",
                        "name": "canary",
                        "operation": "create",
                    },
                )
                harness.intents.update(intent_key, request_boundary_crossed=True)
                with self.assertRaises(live_harness.AmbiguousMutation):
                    harness._control_mutation(
                        intent_key, "POST", "/object-storage-2"
                    )
                self.assertIsNotNone(harness.intents.get(intent_key))

        session = mock.Mock()
        session.request.return_value = Response(302, {})
        control = live_harness.UpCloudControlPlane("TOKEN-CANARY", session=session)
        harness = self.harness(apply=True, control=control)
        intent_key = "control-unknown"
        harness.intents.put(
            intent_key,
            {
                "marker": self.run_id,
                "kind": "canary",
                "name": "canary",
                "operation": "create",
            },
        )
        harness.intents.update(intent_key, request_boundary_crossed=True)
        with self.assertRaises(live_harness.AmbiguousMutation):
            harness._control_mutation(intent_key, "POST", "/object-storage-2")
        self.assertIsNotNone(harness.intents.get(intent_key))

    def test_s3_mutation_definitive_4xx_categories_clear_only_their_intent(self):
        for status, code in (
            (400, "InvalidRequest"),
            (403, "AccessDenied"),
            (404, "NoSuchBucket"),
            (429, "SlowDown"),
        ):
            with self.subTest(status=status):
                harness = self.harness(apply=True)
                intent_key = f"s3-{status}"
                harness.intents.put(
                    intent_key,
                    {
                        "marker": self.run_id,
                        "kind": "canary",
                        "name": "canary",
                        "operation": "put-object",
                    },
                )
                harness.intents.update(intent_key, request_boundary_crossed=True)

                def fail(status=status, code=code):
                    raise S3Failure(status, code)

                with self.assertRaises(live_harness.HarnessError) as raised:
                    harness._s3_mutation(intent_key, fail)
                self.assertNotIsInstance(
                    raised.exception, live_harness.AmbiguousMutation
                )
                self.assertIsNone(harness.intents.get(intent_key))

    def test_s3_mutation_transient_and_unknown_categories_retain_intent(self):
        cases = (
            ("408", lambda: S3Failure(408, "RequestTimeout")),
            ("500", lambda: S3Failure(500, "InternalError")),
            ("504", lambda: S3Failure(504, "ServiceUnavailable")),
            ("timeout", lambda: requests.Timeout("lost response")),
            ("connection", lambda: requests.ConnectionError("lost response")),
            ("unknown", lambda: ValueError("unclassified SDK failure")),
        )
        for label, failure in cases:
            with self.subTest(category=label):
                harness = self.harness(apply=True)
                intent_key = f"s3-{label}"
                harness.intents.put(
                    intent_key,
                    {
                        "marker": self.run_id,
                        "kind": "canary",
                        "name": "canary",
                        "operation": "put-object",
                    },
                )
                harness.intents.update(intent_key, request_boundary_crossed=True)

                def fail(failure=failure):
                    error = failure()
                    raise error

                with self.assertRaises(live_harness.AmbiguousMutation):
                    harness._s3_mutation(intent_key, fail)
                self.assertIsNotNone(harness.intents.get(intent_key))

    def test_lost_access_key_secret_is_adopted_for_cleanup_without_second_post(self):
        harness = self.harness(apply=True)
        harness.account = self.account
        value = service(self.run_id, region=self.region)
        intent_key = "mos_access_key_create"
        harness.intents.put(
            intent_key,
            {
                "marker": self.run_id,
                "kind": "mos_access_key",
                "name": "run-owned-access-key",
                "operation": "create",
                "service_uuid": value["uuid"],
                "username": harness.names["username"],
                "preflight_absent": True,
            },
        )
        harness.intents.update(intent_key, request_boundary_crossed=True)
        key = {"access_key_id": "LOST-KEY-CANARY", "status": "Active"}

        with mock.patch.object(
            harness, "_access_keys", return_value=[key]
        ), mock.patch.object(
            harness, "_access_key_read", return_value=key
        ), self.assertRaises(live_harness.SecretUnavailable):
            harness.ensure_access_key(
                value, {"username": harness.names["username"]}
            )

        entry = harness._one_active("mos_access_key")
        self.assertEqual(
            entry["resource_id"], live_harness._hash("LOST-KEY-CANARY")
        )
        serialized = harness.config.ledger_path.read_text(encoding="utf-8")
        self.assertNotIn("LOST-KEY-CANARY", serialized)
        harness.control.request.assert_not_called()

    def test_s3_inventory_scopes_first_and_later_pages_to_exact_run_prefix(self):
        harness = self.harness(apply=True)
        client = mock.Mock()
        bucket = harness.names["bucket"]
        prefix = harness.names["prefix"]
        first_key = f"{prefix}first.zip"
        second_key = f"{prefix}second.zip"
        upload_key = f"{prefix}pending.zip"
        client.list_object_versions.side_effect = [
            {
                "Versions": [{"Key": first_key, "VersionId": "version-1"}],
                "DeleteMarkers": [],
                "IsTruncated": True,
                "NextKeyMarker": first_key,
                "NextVersionIdMarker": "version-1",
            },
            {
                "Versions": [{"Key": second_key, "VersionId": "version-2"}],
                "DeleteMarkers": [],
                "IsTruncated": False,
            },
        ]
        client.list_objects_v2.side_effect = [
            {
                "Contents": [{"Key": first_key}],
                "IsTruncated": True,
                "NextContinuationToken": "object-page-2",
            },
            {"Contents": [{"Key": second_key}], "IsTruncated": False},
        ]
        client.list_multipart_uploads.side_effect = [
            {
                "Uploads": [{"Key": upload_key, "UploadId": "upload-1"}],
                "IsTruncated": True,
                "NextKeyMarker": upload_key,
                "NextUploadIdMarker": "upload-1",
            },
            {"Uploads": [], "IsTruncated": False},
        ]

        result = harness._s3_inventory(client, bucket, prefix)

        self.assertEqual(len(result["versions"]), 2)
        self.assertEqual(len(result["objects"]), 2)
        self.assertEqual(len(result["multipart_uploads"]), 1)
        self.assertEqual(
            client.list_object_versions.call_args_list,
            [
                mock.call(Bucket=bucket, Prefix=prefix),
                mock.call(
                    Bucket=bucket,
                    Prefix=prefix,
                    KeyMarker=first_key,
                    VersionIdMarker="version-1",
                ),
            ],
        )
        self.assertEqual(
            client.list_objects_v2.call_args_list,
            [
                mock.call(Bucket=bucket, Prefix=prefix),
                mock.call(
                    Bucket=bucket,
                    Prefix=prefix,
                    ContinuationToken="object-page-2",
                ),
            ],
        )
        self.assertEqual(
            client.list_multipart_uploads.call_args_list,
            [
                mock.call(Bucket=bucket, Prefix=prefix),
                mock.call(
                    Bucket=bucket,
                    Prefix=prefix,
                    KeyMarker=upload_key,
                    UploadIdMarker="upload-1",
                ),
            ],
        )

    def test_s3_inventory_rejects_invalid_prefix_before_s3_reads(self):
        harness = self.harness(apply=True)
        expected = harness.names["prefix"]
        invalid_prefixes = {
            "empty": "",
            "wrong": f"{expected}nested/",
            "cross-run": "backupsheep-e2e/another-run/",
        }
        for label, prefix in invalid_prefixes.items():
            with self.subTest(prefix=label):
                client = mock.Mock()
                with self.assertRaisesRegex(
                    live_harness.HarnessError, r"exact active BackupSheep run prefix"
                ):
                    harness._s3_inventory(client, harness.names["bucket"], prefix)

                client.list_object_versions.assert_not_called()
                client.list_objects_v2.assert_not_called()
                client.list_multipart_uploads.assert_not_called()

    def test_arm_refuses_nonempty_bucket_before_enabling_versioning(self):
        harness = self.harness(apply=True)
        value = self.seed_service(harness)
        self.seed_bucket(harness, value)
        self.seed_user_policy_key(harness, value)
        self.write_runtime(harness, value)
        client = mock.Mock()
        foreign = {
            "versions": [{"Key": "foreign", "VersionId": "v1"}],
            "delete_markers": [],
            "objects": [{"Key": "foreign"}],
            "multipart_uploads": [],
        }

        with mock.patch.object(harness, "verify_account", return_value=self.account), \
            mock.patch.object(harness, "_service_read", return_value=value), \
            mock.patch.object(harness, "_s3", return_value=(client, self.write_runtime(harness, value))), \
            mock.patch.object(harness, "_s3_inventory", return_value=foreign), \
            self.assertRaises(live_harness.InventoryNotEmpty):
            harness.arm_object_storage()

        client.put_bucket_versioning.assert_not_called()

    def test_cleanup_refuses_unledgered_object_before_any_delete(self):
        harness = self.harness(apply=True, cleanup=True)
        harness.account = self.account
        client = mock.Mock()
        foreign = {
            "versions": [{"Key": "foreign", "VersionId": "v1"}],
            "delete_markers": [],
            "objects": [{"Key": "foreign"}],
            "multipart_uploads": [],
        }
        with mock.patch.object(
            harness, "_s3_inventory", return_value=foreign
        ), self.assertRaises(live_harness.InventoryNotEmpty):
            harness._delete_bucket_contents(
                client,
                harness.names["bucket"],
                harness.names["prefix"],
                maximum_bytes=1024,
            )

        client.delete_object.assert_not_called()
        client.abort_multipart_upload.assert_not_called()

    def test_verified_ui_object_requires_exact_metadata_bytes_and_version(self):
        harness = self.harness(apply=True)
        value = self.seed_service(harness)
        self.seed_bucket(harness, value)
        self.seed_user_policy_key(harness, value)
        runtime = self.write_runtime(harness, value)
        harness.ledger.record(
            kind="mos_bucket_configuration",
            resource_id=f"{value['uuid']}:{runtime['bucket_name']}:versioning",
            name=runtime["bucket_name"],
            ownership={
                "account": self.account,
                "run_id": self.run_id,
                "service_uuid": value["uuid"],
                "bucket": runtime["bucket_name"],
                "versioning": "Enabled",
                "request_fingerprint": "f" * 64,
            },
            source_witness=f"{value['uuid']}:{runtime['bucket_name']}",
        )
        backup_id = "123"
        backup_uuid = "11111111-1111-4111-8111-111111111111"
        payload = b"deterministic-backup-bytes\x00\xff"
        sha256 = live_harness.hashlib.sha256(payload).hexdigest()
        key = f"{runtime['prefix']}{backup_uuid}.zip"
        version_id = "version-1"
        etag = "etag-1"
        metadata = {
            "backupsheep-sha256": sha256,
            "backupsheep-bytes": str(len(payload)),
            "backupsheep-backup-id": backup_id,
        }
        client = mock.Mock()
        client.head_object.return_value = {
            "ContentLength": len(payload),
            "ETag": f'"{etag}"',
            "VersionId": version_id,
            "Metadata": metadata,
        }
        body = Body(payload)
        client.get_object.return_value = {"Body": body}
        manifest = {
            "schema": 1,
            "run_id": self.run_id,
            "objects": [
                {
                    "kind": "website",
                    "backup_id": backup_id,
                    "backup_uuid": backup_uuid,
                    "object_key": key,
                    "sha256": sha256,
                    "byte_count": len(payload),
                    "etag": etag,
                    "version_id": version_id,
                }
            ]
        }
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        inventory = {
            "versions": [{"Key": key, "VersionId": version_id}],
            "delete_markers": [],
            "objects": [{"Key": key}],
            "multipart_uploads": [],
        }

        with mock.patch.object(harness, "verify_account", return_value=self.account), \
            mock.patch.object(harness, "_service_read", return_value=value), \
            mock.patch.object(harness, "_s3", return_value=(client, runtime)), \
            mock.patch.object(harness, "_s3_inventory", return_value=inventory):
            result = harness.verify_ui_objects(
                str(manifest_path), maximum_bytes=1024
            )

        self.assertEqual(result["status"], "verified")
        self.assertTrue(body.closed)
        entry = harness._one_active("mos_ui_website_object")
        self.assertEqual(entry["ownership"]["version_id"], version_id)
        self.assertEqual(entry["ownership"]["sha256"], sha256)
        self.assertEqual(entry["ownership"]["byte_count"], len(payload))
        self.assertEqual(entry["ownership"]["etag"], etag)

    def test_duplicate_ui_object_versions_fail_closed_without_ledger_adoption(self):
        harness = self.harness(apply=True)
        value = self.seed_service(harness)
        self.seed_user_policy_key(harness, value)
        runtime = self.write_runtime(harness, value)
        harness.ledger.record(
            kind="mos_bucket_configuration",
            resource_id=f"{value['uuid']}:{runtime['bucket_name']}:versioning",
            name=runtime["bucket_name"],
            ownership={
                "account": self.account,
                "run_id": self.run_id,
                "service_uuid": value["uuid"],
                "bucket": runtime["bucket_name"],
                "versioning": "Enabled",
            },
            source_witness=value["uuid"],
        )
        backup_id = "124"
        backup_uuid = "22222222-2222-4222-8222-222222222222"
        key = f"{runtime['prefix']}{backup_uuid}.zip"
        manifest_path = self.root / "duplicate.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "run_id": self.run_id,
                    "objects": [
                        {
                            "kind": "database",
                            "backup_id": backup_id,
                            "backup_uuid": backup_uuid,
                            "object_key": key,
                            "sha256": "a" * 64,
                            "byte_count": 1,
                            "etag": "etag",
                            "version_id": "v2",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        inventory = {
            "versions": [
                {"Key": key, "VersionId": "v1"},
                {"Key": key, "VersionId": "v2"},
            ],
            "delete_markers": [],
            "objects": [{"Key": key}],
            "multipart_uploads": [],
        }

        with mock.patch.object(harness, "verify_account", return_value=self.account), \
            mock.patch.object(harness, "_service_read", return_value=value), \
            mock.patch.object(harness, "_s3", return_value=(mock.Mock(), runtime)), \
            mock.patch.object(harness, "_s3_inventory", return_value=inventory), \
            self.assertRaises(live_harness.HarnessError):
            harness.verify_ui_objects(str(manifest_path), maximum_bytes=1024)

        self.assertIsNone(harness._one_active("mos_ui_database_object"))

    def test_ui_manifest_rejects_object_key_that_uses_numeric_row_id(self):
        harness = self.harness(apply=True)
        value = self.seed_service(harness)
        self.seed_bucket(harness, value)
        self.seed_user_policy_key(harness, value)
        runtime = self.write_runtime(harness, value)
        self.arm_bucket_for_manifest(harness, value, runtime)
        backup_uuid = "33333333-3333-4333-8333-333333333333"
        manifest_path = self.root / "wrong-key.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "run_id": self.run_id,
                    "objects": [
                        {
                            "kind": "website",
                            "backup_id": "125",
                            "backup_uuid": backup_uuid,
                            "object_key": f"{runtime['prefix']}125.zip",
                            "sha256": "a" * 64,
                            "byte_count": 1,
                            "etag": "etag",
                            "version_id": "v1",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        with mock.patch.object(harness, "verify_account", return_value=self.account), \
            mock.patch.object(harness, "_service_read", return_value=value), \
            mock.patch.object(harness, "_s3", return_value=(mock.Mock(), runtime)), \
            mock.patch.object(harness, "_s3_inventory") as inventory, \
            self.assertRaises(live_harness.HarnessError):
            harness.verify_ui_objects(str(manifest_path), maximum_bytes=1024)

        inventory.assert_not_called()

    def test_ui_manifest_rejects_duplicate_manifest_keys(self):
        harness = self.harness(apply=True)
        value = self.seed_service(harness)
        self.seed_bucket(harness, value)
        self.seed_user_policy_key(harness, value)
        runtime = self.write_runtime(harness, value)
        self.arm_bucket_for_manifest(harness, value, runtime)
        backup_uuid = "44444444-4444-4444-8444-444444444444"
        key = f"{runtime['prefix']}{backup_uuid}.zip"
        row = {
            "kind": "database",
            "backup_id": "126",
            "backup_uuid": backup_uuid,
            "object_key": key,
            "sha256": "a" * 64,
            "byte_count": 1,
            "etag": "etag",
            "version_id": "v1",
        }
        duplicate = dict(row)
        duplicate["backup_id"] = "127"
        manifest_path = self.root / "duplicate-manifest.json"
        manifest_path.write_text(
            json.dumps(
                {"schema": 1, "run_id": self.run_id, "objects": [row, duplicate]}
            ),
            encoding="utf-8",
        )
        with mock.patch.object(harness, "verify_account", return_value=self.account), \
            mock.patch.object(harness, "_service_read", return_value=value), \
            mock.patch.object(harness, "_s3", return_value=(mock.Mock(), runtime)), \
            mock.patch.object(harness, "_s3_inventory") as inventory, \
            self.assertRaises(live_harness.HarnessError):
            harness.verify_ui_objects(str(manifest_path), maximum_bytes=1024)

        inventory.assert_called_once()

    def test_ui_manifest_rejects_sensitive_keys(self):
        harness = self.harness(apply=True)
        value = self.seed_service(harness)
        self.seed_bucket(harness, value)
        self.seed_user_policy_key(harness, value)
        runtime = self.write_runtime(harness, value)
        self.arm_bucket_for_manifest(harness, value, runtime)
        manifest_path = self.root / "sensitive.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "run_id": self.run_id,
                    "objects": [
                        {
                            "kind": "website",
                            "backup_id": "128",
                            "backup_uuid": "55555555-5555-4555-8555-555555555555",
                            "object_key": "outside",
                            "api_token": "TOKEN-CANARY",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        with mock.patch.object(harness, "verify_account", return_value=self.account), \
            mock.patch.object(harness, "_service_read", return_value=value), \
            mock.patch.object(harness, "_s3", return_value=(mock.Mock(), runtime)), \
            self.assertRaises(live_harness.HarnessError):
            harness.verify_ui_objects(str(manifest_path), maximum_bytes=1024)
