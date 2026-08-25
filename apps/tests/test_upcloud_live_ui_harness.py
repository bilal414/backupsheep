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

    def provider_scaffolding(self, harness, *, key_id="KEY-CANARY"):
        policy_request = harness._policy_request()
        return {
            "network": {
                "name": harness.names["network"],
                "type": "public",
                "family": "IPv4",
            },
            "user": {
                "username": harness.names["username"],
                "arn": f"urn:ecs:iam::test:user/{harness.names['username']}",
            },
            "policy": {
                "name": harness.names["policy"],
                "document": policy_request["document"],
            },
            "key": {"access_key_id": key_id, "status": "Active"},
        }

    def write_runtime(self, harness, value, *, key_id="KEY-CANARY"):
        payload = harness._runtime_payload(
            service=value,
            access_key=key_id,
            secret_key="SECRET-CANARY",
        )
        live_harness._write_runtime_secret(harness.config.runtime_path, payload)
        return payload

    def arm_bucket_for_manifest(self, harness, value, runtime):
        request = {"bucket": runtime["bucket_name"], "status": "Enabled"}
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
                "provenance": "intent_applied",
                "request_fingerprint": live_harness._fingerprint(request),
            },
            source_witness=f"{value['uuid']}:{runtime['bucket_name']}",
        )

    @staticmethod
    def object_row(*, kind, backup_id, backup_uuid, object_key, **overrides):
        row = {
            "kind": kind,
            "backup_id": backup_id,
            "backup_uuid": backup_uuid,
            "storage_point_id": 201,
            "storage_id": 202,
            "artifact_id": 203,
            "artifact_status": "verified",
            "object_key": object_key,
            "sha256": "a" * 64,
            "byte_count": 1,
            "etag": "etag",
            "version_id": "v1",
        }
        row.update(overrides)
        return row

    def write_generation(self, object_manifest, *, name="generation"):
        rows = {row["kind"]: row for row in object_manifest["objects"]}
        generation = self.root / name
        generation.mkdir(mode=0o700)
        compute = {
            "schema": 1,
            "run_id": self.run_id,
            "volume": {
                "node_id": 1,
                "backup_id": 2,
                "restore_id": 3,
                "source_resource_id": "01a00000-0000-4000-8000-000000000001",
                "backup_resource_id": "01a00000-0000-4000-8000-000000000002",
                "backup_marker": "volume-backup-marker",
                "restore_resource_id": "01a00000-0000-4000-8000-000000000003",
                "restore_marker": "backupsheep-upcloud-volume-restore",
            },
            "server": {
                "node_id": 4,
                "backup_id": 5,
                "restore_id": 6,
                "source_resource_id": "00a00000-0000-4000-8000-000000000001",
                "backup_resource_id": "01a00000-0000-4000-8000-000000000004",
                "backup_marker": "server-backup-marker",
                "restore_storage_id": "01a00000-0000-4000-8000-000000000005",
                "restore_storage_marker": "backupsheep-upcloud-storage-restore",
                "restore_server_id": "00a00000-0000-4000-8000-000000000006",
                "restore_server_marker": "backupsheep-upcloud-server-restore",
                "restore_hostname": "bs-upcloud-restore",
            },
        }
        workload = {
            "schema": 1,
            "run_id": self.run_id,
            "website": {
                "node_id": 7,
                "backup_id": rows["website"]["backup_id"],
                "restore_id": 8,
                "restore_path": f"/srv/backupsheep-e2e/{self.run_id}",
            },
            "postgresql": {
                "node_id": 9,
                "backup_id": rows["database"]["backup_id"],
                "restore_id": 10,
                "restore_database": "bs_restore_database",
            },
        }
        payloads = {"compute": compute, "workload": workload, "object": object_manifest}
        filenames = {
            "compute": "upcloud-compute-manifest.json",
            "workload": "upcloud-workload-manifest.json",
            "object": "upcloud-object-manifest.json",
        }
        encoded = {}
        for kind, payload in payloads.items():
            body = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            path = generation / filenames[kind]
            path.write_bytes(body)
            path.chmod(0o600)
            encoded[kind] = body

        def binding(row):
            identity = {
                "artifact_id": row["artifact_id"],
                "byte_count": row["byte_count"],
                "sha256": row["sha256"],
                "etag": row["etag"],
                "version_id": row["version_id"],
            }
            return {
                **identity,
                "binding_sha256": live_harness._artifact_binding_digest(identity),
            }

        marker = {
            "schema": 1,
            "kind": "upcloud_manifest_generation_ownership",
            "provider": "upcloud",
            "integration_code": "upcloud",
            "run_id": self.run_id,
            "disposition": "EXCLUSIVE_COMPLETE_GENERATION",
            "manifests": {
                kind: {
                    "filename": filenames[kind],
                    "sha256": live_harness.hashlib.sha256(body).hexdigest(),
                    "byte_count": len(body),
                }
                for kind, body in encoded.items()
            },
            "storage_id": rows["website"]["storage_id"],
            "rows": {
                "volume_node_id": 1,
                "volume_backup_id": 2,
                "volume_restore_id": 3,
                "server_node_id": 4,
                "server_backup_id": 5,
                "server_restore_id": 6,
                "website_node_id": 7,
                "website_backup_id": rows["website"]["backup_id"],
                "website_restore_id": 8,
                "database_node_id": 9,
                "database_backup_id": rows["database"]["backup_id"],
                "database_restore_id": 10,
                "website_storage_point_id": rows["website"]["storage_point_id"],
                "database_storage_point_id": rows["database"]["storage_point_id"],
                "website_artifact_id": rows["website"]["artifact_id"],
                "database_artifact_id": rows["database"]["artifact_id"],
            },
            "artifact_bindings": {
                "website": binding(rows["website"]),
                "database": binding(rows["database"]),
            },
        }
        marker_path = generation / live_harness.UPCLOUD_GENERATION_MARKER
        marker_path.write_bytes(
            (json.dumps(marker, indent=2, sort_keys=True) + "\n").encode()
        )
        marker_path.chmod(0o600)
        return generation

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
            self.assertRaisesRegex(
                live_harness.HarnessError, r"complete new generation directory"
            ):
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
            r"schema must be integer 1",
        )

    def test_ui_manifest_rejects_missing_schema_before_provider_inventory(self):
        self._assert_manifest_envelope_rejected_before_provider(
            {"run_id": self.run_id, "objects": []}, r"unknown or missing fields"
        )

    def test_ui_manifest_rejects_wrong_run_id_before_provider_inventory(self):
        self._assert_manifest_envelope_rejected_before_provider(
            {"schema": 1, "run_id": "another-run", "objects": []},
            r"run_id does not match",
        )

    def test_ui_manifest_rejects_missing_run_id_before_provider_inventory(self):
        self._assert_manifest_envelope_rejected_before_provider(
            {"schema": 1, "objects": []}, r"unknown or missing fields"
        )

    def test_ui_manifest_requires_exactly_one_website_and_database_before_provider(self):
        cases = {
            "missing_database": [{"kind": "website"}],
            "missing_website": [{"kind": "database"}],
            "duplicate_website": [
                {"kind": "website"},
                {"kind": "website"},
            ],
            "duplicate_database": [
                {"kind": "database"},
                {"kind": "database"},
            ],
            "extra_kind": [
                {"kind": "website"},
                {"kind": "database"},
                {"kind": "volume"},
            ],
        }
        for label, rows in cases.items():
            with self.subTest(case=label):
                self._assert_manifest_envelope_rejected_before_provider(
                    {"schema": 1, "run_id": self.run_id, "objects": rows},
                    r"exactly one website and one database",
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

    def test_main_refuses_secret_bearing_results_before_writing_output(self):
        cases = {
            "sensitive_key": {
                "status": "ready",
                "secret_key": "SECRET-CANARY",
            },
            "registered_secret_value": {
                "status": "ready",
                "diagnostic": "SECRET-CANARY",
            },
            "api_token_value": {
                "status": "ready",
                "diagnostic": "TOKEN-CANARY",
            },
            "generic_token_key": {
                "status": "ready",
                "token": "UNREGISTERED-CANARY",
            },
            "camel_case_api_key": {
                "status": "ready",
                "apiKey": "CAMEL-CANARY",
            },
            "compact_access_key": {
                "status": "ready",
                "accesskey": "COMPACT-CANARY",
            },
            "generic_key": {
                "status": "ready",
                "key": "UNREGISTERED-GENERIC-CANARY",
            },
            "generic_auth": {
                "status": "ready",
                "auth": "UNREGISTERED-GENERIC-CANARY",
            },
            "generic_session": {
                "status": "ready",
                "session": "UNREGISTERED-GENERIC-CANARY",
            },
            "generic_jwt": {
                "status": "ready",
                "jwt": "UNREGISTERED-GENERIC-CANARY",
            },
            "generic_ticket": {
                "status": "ready",
                "ticket": "UNREGISTERED-GENERIC-CANARY",
            },
            **{
                f"composite_{index}": {
                    "status": "ready",
                    key: "UNREGISTERED-COMPOSITE-CANARY",
                }
                for index, key in enumerate(
                    (
                        "auth_key",
                        "authkey",
                        "session_key",
                        "sessionKey",
                        "jwt_key",
                        "ticket_key",
                        "oauth_code",
                        "signing_key",
                        "encryption_key",
                        "key_material",
                        "key_value",
                    )
                )
            },
            **{
                f"credential_family_{index}": {
                    "status": "ready",
                    key: "UNREGISTERED-FAMILY-CANARY",
                }
                for index, key in enumerate(
                    (
                        "session_cookie",
                        "sessioncookie",
                        "auth_cookie",
                        "client_key",
                        "consumer_key",
                        "master_key",
                        "ssh_key",
                        "otp",
                        "one_time_code",
                        "verification_code",
                        "refresh_code",
                        "signed_cookie",
                        "oauth_verifier",
                        "oauth_state",
                    )
                )
            },
            "nested_credential_family": {
                "status": "ready",
                "result": {
                    "details": {
                        "session_cookie": "NESTED-FAMILY-CANARY",
                    }
                },
            },
            "list_credential_family": {
                "status": "ready",
                "items": [
                    {
                        "details": {
                            "client_key": "LIST-FAMILY-CANARY",
                        }
                    }
                ],
            },
            "private_key": {
                "status": "ready",
                "private_key": "UNREGISTERED-PRIVATE-CANARY",
            },
            "private_key_material_in_path_field": {
                "status": "ready",
                "ssh_private_key_file": "UNREGISTERED-PRIVATE-CANARY",
            },
            "secret_in_url_query": {
                "status": "ready",
                "next_url": "https://provider.invalid/callback?token=QUERY-CANARY",
            },
            "secret_in_percent_encoded_url_query": {
                "status": "ready",
                "next_url": (
                    "https://provider.invalid/callback?secret%255Fkey=ENCODED-CANARY"
                ),
            },
            "secret_in_url_fragment": {
                "status": "ready",
                "next_url": "https://provider.invalid/callback#accessKey=FRAGMENT-CANARY",
            },
            "signature_in_url_query": {
                "status": "ready",
                "next_url": "https://provider.invalid/callback?sig=SIGNATURE-CANARY",
            },
            "standalone_bearer_value": {
                "status": "ready",
                "diagnostic": "Bearer STANDALONE-BEARER-CANARY",
            },
            "url_userinfo": {
                "status": "ready",
                "next_url": "https://USERINFO-CANARY@provider.invalid/callback",
            },
            "secret_query_in_allowed_path_field": {
                "status": "ready",
                "ssh_private_key_file": (
                    "/protected/runtime.json?token=PATH-QUERY-CANARY"
                ),
            },
            "noncanonical_allowed_path_field": {
                "status": "ready",
                "credentials_file": "/protected/../runtime.json",
            },
            "double_anchor_allowed_path_field": {
                "status": "ready",
                "credentials_file": "//protected/runtime.json",
            },
            "registered_secret_as_key": {
                "status": "ready",
                "OPAQUE-CANARY": "value",
            },
        }
        for label, payload in cases.items():
            stdout = io.StringIO()
            stderr = io.StringIO()
            harness = mock.Mock()
            harness._output_secret_values = {"SECRET-CANARY", "OPAQUE-CANARY"}
            # Keep the command envelope valid so each case must reach the
            # recursive key/text/registered-value boundary. A sparse or extra-key
            # result would be rejected by the envelope before proving the
            # credential detector that this regression test targets.
            harness.setup_object_storage.return_value = {
                "status": "ready_for_ui_storage_configuration",
                "service_uuid": "11111111-1111-4111-8111-111111111111",
                "bucket_name": "public-bucket",
                "endpoint": payload,
                "prefix": "backupsheep-e2e/run/",
                "credentials_file": "/protected/runtime.json",
                "versioning": "not_enabled_until_arm_object_storage",
                "ui_no_delete": False,
            }
            with self.subTest(case=label), mock.patch.object(
                live_harness.HarnessConfig,
                "from_environment",
                return_value=self.config(apply=True),
            ), mock.patch.object(
                live_harness, "UpCloudLiveHarness", return_value=harness
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                result = live_harness.main(
                    ["setup-object-storage"],
                    environment={"UPCLOUD_API_TOKEN": "TOKEN-CANARY"},
                )

            output = stdout.getvalue() + stderr.getvalue()
            self.assertEqual(result, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("refused a diagnostic or result", stderr.getvalue())
            self.assertNotIn("TOKEN-CANARY", output)
            self.assertNotIn("SECRET-CANARY", output)
            self.assertNotIn("UNREGISTERED-CANARY", output)
            self.assertNotIn("UNREGISTERED-PRIVATE-CANARY", output)
            self.assertNotIn("OPAQUE-CANARY", output)
            self.assertNotIn("CAMEL-CANARY", output)
            self.assertNotIn("COMPACT-CANARY", output)
            self.assertNotIn("UNREGISTERED-GENERIC-CANARY", output)
            self.assertNotIn("UNREGISTERED-COMPOSITE-CANARY", output)
            self.assertNotIn("UNREGISTERED-FAMILY-CANARY", output)
            self.assertNotIn("NESTED-FAMILY-CANARY", output)
            self.assertNotIn("LIST-FAMILY-CANARY", output)
            self.assertNotIn("QUERY-CANARY", output)
            self.assertNotIn("ENCODED-CANARY", output)
            self.assertNotIn("FRAGMENT-CANARY", output)
            self.assertNotIn("SIGNATURE-CANARY", output)
            self.assertNotIn("STANDALONE-BEARER-CANARY", output)
            self.assertNotIn("USERINFO-CANARY", output)
            self.assertNotIn("PATH-QUERY-CANARY", output)

    def test_main_never_renders_provider_diagnostics(self):
        cases = {
            "safe": (
                live_harness.HarnessError("The exact service ownership changed."),
                "refused a diagnostic or result",
            ),
            "api_token": (
                live_harness.HarnessError("Provider rejected TOKEN-CANARY."),
                "refused a diagnostic or result",
            ),
            "credential_assignment": (
                live_harness.HarnessError("password=SECRET-CANARY"),
                "refused a diagnostic or result",
            ),
            "secret_crossing_diagnostic_bound": (
                live_harness.HarnessError("x" * 496 + "TOKEN-CANARY"),
                "refused a diagnostic or result",
            ),
            "authorization_bearer": (
                live_harness.HarnessError(
                    "Authorization Bearer UNREGISTERED-BEARER-CANARY"
                ),
                "refused a diagnostic or result",
            ),
            "authorization_basic": (
                live_harness.HarnessError(
                    "Authorization: Basic UNREGISTERED-BASIC-CANARY"
                ),
                "refused a diagnostic or result",
            ),
            "standalone_bearer": (
                live_harness.HarnessError(
                    "Bearer STANDALONE-BEARER-CANARY"
                ),
                "refused a diagnostic or result",
            ),
            "percent_encoded_query_secret": (
                live_harness.HarnessError(
                    "https://provider.invalid/error?secret%255Fkey=ENCODED-CANARY"
                ),
                "refused a diagnostic or result",
            ),
            "url_userinfo": (
                live_harness.HarnessError(
                    "https://USERINFO-CANARY@provider.invalid/error"
                ),
                "refused a diagnostic or result",
            ),
            "safe_url_diagnostic": (
                live_harness.HarnessError(
                    "https://provider.invalid/status?request_id=abc#summary"
                ),
                "refused a diagnostic or result",
            ),
        }
        for label, (error, expected) in cases.items():
            stdout = io.StringIO()
            stderr = io.StringIO()
            harness = mock.Mock()
            harness._output_secret_values = {"SECRET-CANARY"}
            harness.setup_object_storage.side_effect = error
            with self.subTest(case=label), mock.patch.object(
                live_harness.HarnessConfig,
                "from_environment",
                return_value=self.config(apply=True),
            ), mock.patch.object(
                live_harness, "UpCloudLiveHarness", return_value=harness
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                result = live_harness.main(
                    ["setup-object-storage"],
                    environment={"UPCLOUD_API_TOKEN": "TOKEN-CANARY"},
                )

            output = stdout.getvalue() + stderr.getvalue()
            self.assertEqual(result, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(
                stderr.getvalue(),
                "ERROR: The UpCloud harness refused a diagnostic or result "
                "containing credentials.\n",
            )
            self.assertIn(expected, stderr.getvalue())
            self.assertNotIn("The exact service ownership changed.", output)
            self.assertNotIn("provider.invalid/status", output)
            self.assertNotIn("TOKEN-CANARY", output)
            self.assertNotIn("SECRET-CANARY", output)
            self.assertNotIn("UNREGISTERED-", output)
            self.assertNotIn("STANDALONE-BEARER-CANARY", output)
            self.assertNotIn("ENCODED-CANARY", output)
            self.assertNotIn("USERINFO-CANARY", output)

    def test_main_prints_safe_result_with_protected_file_diagnostic(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        harness = mock.Mock()
        harness._output_secret_values = {"SECRET-CANARY"}
        harness.setup_object_storage.return_value = {
            "status": "ready_for_ui_storage_configuration",
            "service_uuid": "11111111-1111-4111-8111-111111111111",
            "bucket_name": "public-bucket",
            "endpoint": "https://public.example.invalid",
            "prefix": "backupsheep-e2e/run/",
            "credentials_file": "/protected/runtime.json",
            "versioning": "not_enabled_until_arm_object_storage",
            "ui_no_delete": False,
        }
        with mock.patch.object(
            live_harness.HarnessConfig,
            "from_environment",
            return_value=self.config(apply=True),
        ), mock.patch.object(
            live_harness, "UpCloudLiveHarness", return_value=harness
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            result = live_harness.main(
                ["setup-object-storage"],
                environment={"UPCLOUD_API_TOKEN": "TOKEN-CANARY"},
            )

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {
                "status": "ready_for_ui_storage_configuration",
                "service_uuid": "11111111-1111-4111-8111-111111111111",
                "bucket_name": "public-bucket",
                "endpoint": "https://public.example.invalid",
                "prefix": "backupsheep-e2e/run/",
                "credentials_file": "/protected/runtime.json",
                "versioning": "not_enabled_until_arm_object_storage",
                "ui_no_delete": False,
            },
        )

    def test_main_refuses_unknown_or_incomplete_public_output_envelope(self):
        valid = {
            "status": "ready_for_ui_storage_configuration",
            "service_uuid": "11111111-1111-4111-8111-111111111111",
            "bucket_name": "public-bucket",
            "endpoint": "https://public.example.invalid",
            "prefix": "backupsheep-e2e/run/",
            "credentials_file": "/protected/runtime.json",
            "versioning": "not_enabled_until_arm_object_storage",
            "ui_no_delete": False,
        }
        cases = {
            "unknown_neutral_field": {**valid, "diagnostic": "safe"},
            "missing_field": {
                key: value
                for key, value in valid.items()
                if key != "service_uuid"
            },
        }
        for label, payload in cases.items():
            stdout = io.StringIO()
            stderr = io.StringIO()
            harness = mock.Mock()
            harness._output_secret_values = set()
            harness.setup_object_storage.return_value = payload
            with self.subTest(case=label), mock.patch.object(
                live_harness.HarnessConfig,
                "from_environment",
                return_value=self.config(apply=True),
            ), mock.patch.object(
                live_harness, "UpCloudLiveHarness", return_value=harness
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                result = live_harness.main(
                    ["setup-object-storage"],
                    environment={"UPCLOUD_API_TOKEN": "TOKEN-CANARY"},
                )

            self.assertEqual(result, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(
                stderr.getvalue(),
                "ERROR: The UpCloud harness refused a diagnostic or result "
                "containing credentials.\n",
            )

    def test_public_output_filter_couples_cleanup_shape_to_status(self):
        full_result = {
            "status": "completed",
            "service_uuid": "11111111-1111-4111-8111-111111111111",
            "data_cleanup": "completed",
            "credential_service_scaffolding": (
                live_harness.USER_RETAINED_BY_INSTRUCTION
            ),
            "retained_by_instruction": {},
        }
        valid = (
            {"status": "nothing_to_cleanup"},
            full_result,
        )
        for payload in valid:
            stdout = io.StringIO()
            with self.subTest(valid=payload["status"]), redirect_stdout(stdout):
                live_harness._emit_public_json(
                    payload, command="cleanup-object-storage"
                )
            self.assertEqual(json.loads(stdout.getvalue()), payload)

        invalid = (
            {"status": "completed"},
            {**full_result, "status": "nothing_to_cleanup"},
        )
        for payload in invalid:
            stdout = io.StringIO()
            with self.subTest(invalid=payload["status"]), self.assertRaisesRegex(
                live_harness.HarnessError,
                "refused a diagnostic or result",
            ), redirect_stdout(stdout):
                live_harness._emit_public_json(
                    payload, command="cleanup-object-storage"
                )
            self.assertEqual(stdout.getvalue(), "")

    def test_output_filter_rejects_every_credential_family_recursively(self):
        names = (
            "key",
            "auth",
            "session",
            "sessionid",
            "jwt",
            "ticket",
            "auth_key",
            "authkey",
            "session_key",
            "sessionKey",
            "jwt_key",
            "ticket_key",
            "oauth_code",
            "signing_key",
            "encryption_key",
            "key_material",
            "key_value",
            "session_cookie",
            "sessioncookie",
            "auth_cookie",
            "client_key",
            "consumer_key",
            "master_key",
            "ssh_key",
            "otp",
            "one_time_code",
            "verification_code",
            "refresh_code",
            "signed_cookie",
            "oauth_verifier",
            "oauth_state",
        )
        for name in names:
            with self.subTest(name=name):
                self.assertTrue(live_harness._output_name_is_sensitive(name))
        self.assertTrue(
            live_harness._contains_sensitive_output_key(
                {"result": {"details": {"session_cookie": "CANARY"}}}
            )
        )
        self.assertTrue(
            live_harness._contains_sensitive_output_key(
                {"items": [{"details": {"client_key": "CANARY"}}]}
            )
        )

    def test_public_output_filter_accepts_reviewed_key_metadata(self):
        payload = {
            "status": "verified",
            "objects": [
                {
                    "object_key": "backupsheep-e2e/run/backup.zip",
                    "key_fingerprints": ["a" * 64, "b" * 64],
                    "public_key_sha256": "c" * 64,
                }
            ],
        }
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            live_harness._emit_public_json(
                payload, command="verify-object-storage"
            )
        self.assertEqual(json.loads(stdout.getvalue()), payload)

    def test_main_rejects_malformed_public_key_metadata_exceptions(self):
        cases = {
            "object_key": {"object_key": "/unsafe/absolute.zip"},
            "key_fingerprints": {"key_fingerprints": ["NOT-A-FINGERPRINT"]},
            "public_key_sha256": {"public_key_sha256": "NOT-A-DIGEST"},
        }
        for label, payload in cases.items():
            stdout = io.StringIO()
            with self.subTest(case=label), self.assertRaisesRegex(
                live_harness.HarnessError,
                "refused a diagnostic or result",
            ), redirect_stdout(stdout):
                live_harness._emit_public_json(
                    {
                        "status": "verified",
                        "objects": [payload],
                    },
                    command="verify-object-storage",
                )
            self.assertEqual(stdout.getvalue(), "")

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
        self.arm_bucket_for_manifest(harness, value, runtime)
        witnesses = [
            {
                "kind": "website",
                "backup_id": 123,
                "backup_uuid": "backup-live_2026.08:15",
                "payload": b"deterministic-website-backup-bytes\x00\xff",
                "version_id": "version-website",
                "etag": "etag-website",
            },
            {
                "kind": "database",
                "backup_id": 124,
                "backup_uuid": "database-live_2026.08:15",
                "payload": b"deterministic-database-backup-bytes\x00\xff",
                "version_id": "version-database",
                "etag": "etag-database",
            },
        ]
        for witness in witnesses:
            witness["sha256"] = live_harness.hashlib.sha256(
                witness["payload"]
            ).hexdigest()
            witness["key"] = (
                f"{runtime['prefix']}{witness['backup_uuid']}.zip"
            )
        client = mock.Mock()
        client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        client.head_object.side_effect = [
            {
                "ContentLength": len(witness["payload"]),
                "ETag": f'"{witness["etag"]}"',
                "VersionId": witness["version_id"],
                "Metadata": {
                    "backupsheep-sha256": witness["sha256"],
                    "backupsheep-bytes": str(len(witness["payload"])),
                    "backupsheep-backup-id": str(witness["backup_id"]),
                },
            }
            for witness in witnesses
        ]
        bodies = [Body(witness["payload"]) for witness in witnesses]
        client.get_object.side_effect = [{"Body": body} for body in bodies]
        manifest = {
            "schema": 1,
            "run_id": self.run_id,
            "objects": [
                self.object_row(
                    kind=witness["kind"],
                    backup_id=witness["backup_id"],
                    backup_uuid=witness["backup_uuid"],
                    object_key=witness["key"],
                    sha256=witness["sha256"],
                    byte_count=len(witness["payload"]),
                    etag=witness["etag"],
                    version_id=witness["version_id"],
                )
                for witness in witnesses
            ]
        }
        generation_path = self.write_generation(manifest)
        inventory = {
            "versions": [
                {"Key": witness["key"], "VersionId": witness["version_id"]}
                for witness in witnesses
            ],
            "delete_markers": [],
            "objects": [{"Key": witness["key"]} for witness in witnesses],
            "multipart_uploads": [],
        }

        with mock.patch.object(harness, "verify_account", return_value=self.account), \
            mock.patch.object(harness, "_service_read", return_value=value), \
            mock.patch.object(harness, "_s3", return_value=(client, runtime)), \
            mock.patch.object(harness, "_s3_inventory", return_value=inventory):
            result = harness.verify_ui_objects(
                str(generation_path), maximum_bytes=1024
            )

        self.assertEqual(result["status"], "verified")
        self.assertTrue(all(body.closed for body in bodies))
        entry = harness._one_active("mos_ui_website_object")
        self.assertEqual(entry["ownership"]["version_id"], "version-website")
        self.assertEqual(entry["ownership"]["sha256"], witnesses[0]["sha256"])
        self.assertEqual(
            entry["ownership"]["byte_count"], len(witnesses[0]["payload"])
        )
        self.assertEqual(entry["ownership"]["etag"], "etag-website")
        bindings = harness._active_entries("mos_ui_object_binding")
        self.assertEqual(len(bindings), 2)
        self.assertTrue(
            all(row["ownership"]["storage_point_id"] == 201 for row in bindings)
        )
        self.assertTrue(
            all(
                row["ownership"]["artifact_status"] == "verified"
                for row in bindings
            )
        )
        self.assertTrue(
            all(
                row["ownership"]["generation_marker_sha256"]
                == live_harness.hashlib.sha256(
                    (generation_path / live_harness.UPCLOUD_GENERATION_MARKER).read_bytes()
                ).hexdigest()
                for row in bindings
            )
        )

    def test_tampered_and_swapped_generations_fail_before_provider_reads(self):
        manifest = {
            "schema": 1,
            "run_id": self.run_id,
            "objects": [
                self.object_row(
                    kind="website",
                    backup_id=123,
                    backup_uuid="website-generation-2026.08:15",
                    object_key="backupsheep-e2e/website-generation-2026.08:15.zip",
                ),
                self.object_row(
                    kind="database",
                    backup_id=124,
                    backup_uuid="database-generation-2026.08:15",
                    object_key="backupsheep-e2e/database-generation-2026.08:15.zip",
                ),
            ],
        }
        tampered = self.write_generation(manifest, name="tampered-generation")
        marker_path = tampered / live_harness.UPCLOUD_GENERATION_MARKER
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        marker["artifact_bindings"]["website"]["sha256"] = "f" * 64
        marker_path.write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n")
        marker_path.chmod(0o600)

        swapped_manifest = deepcopy(manifest)
        swapped_manifest["objects"][0]["version_id"] = "version-swapped"
        swapped = self.write_generation(swapped_manifest, name="swapped-generation")
        original = self.write_generation(manifest, name="original-generation")
        swapped_object = swapped / "upcloud-object-manifest.json"
        original_object = original / "upcloud-object-manifest.json"
        original_object.write_bytes(swapped_object.read_bytes())
        original_object.chmod(0o600)

        for generation in (tampered, original):
            harness = self.harness(apply=True)
            with self.subTest(generation=generation), \
                mock.patch.object(harness, "verify_account") as verify_account, \
                mock.patch.object(harness, "_service_read") as service_read, \
                mock.patch.object(harness, "_s3") as s3, \
                mock.patch.object(harness, "_s3_inventory") as inventory, \
                self.assertRaises(live_harness.HarnessError):
                harness.verify_ui_objects(str(generation), maximum_bytes=1024)
            verify_account.assert_not_called()
            service_read.assert_not_called()
            s3.assert_not_called()
            inventory.assert_not_called()

    def test_backup_object_identifier_accepts_real_strings_and_rejects_path_escape(self):
        self.assertEqual(
            live_harness._safe_backup_object_id("backup-live_2026.08:15"),
            "backup-live_2026.08:15",
        )
        for value in ("../escape", "a/b", "a\\b", ".", "a..b", "bad\nvalue", ""):
            with self.subTest(value=value), self.assertRaises(live_harness.HarnessError):
                live_harness._safe_backup_object_id(value)

    def test_manifest_rejects_duplicate_json_key_and_boolean_schema_before_provider(self):
        harness = self.harness(apply=True)
        duplicate = self.root / "duplicate-key.json"
        duplicate.write_text(
            '{"schema":1,"schema":1,"run_id":"%s","objects":[]}' % self.run_id,
            encoding="utf-8",
        )
        boolean = self.root / "boolean-schema.json"
        boolean.write_text(
            json.dumps({"schema": True, "run_id": self.run_id, "objects": []}),
            encoding="utf-8",
        )
        for path in (duplicate, boolean):
            with self.subTest(path=path), mock.patch.object(
                harness, "verify_account"
            ) as provider, self.assertRaises(live_harness.HarnessError):
                harness.verify_ui_objects(str(path), maximum_bytes=1024)
            provider.assert_not_called()

    def test_reconcile_object_storage_adopts_observed_configuration_with_fresh_versioning(self):
        harness = self.harness(apply=False)
        value = self.seed_service(harness)
        self.seed_bucket(harness, value)
        self.seed_user_policy_key(harness, value)
        runtime = self.write_runtime(harness, value)
        client = mock.Mock()
        client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        with mock.patch.object(harness, "verify_account", return_value=self.account), \
            mock.patch.object(harness, "_service_read", return_value=value), \
            mock.patch.object(harness, "_buckets", return_value=[{"name": runtime["bucket_name"]}]), \
            mock.patch.object(harness, "_s3", return_value=(client, runtime)), \
            mock.patch.object(
                harness,
                "_s3_inventory",
                return_value={"versions": [], "delete_markers": [], "objects": [], "multipart_uploads": []},
            ):
            result = harness.reconcile_object_storage_evidence()
        self.assertEqual(result["configuration_provenance"], "observed_existing")
        self.assertEqual(result["bucket_name"], harness.names["bucket"])
        self.assertEqual(result["prefix"], harness.names["prefix"])
        config = harness._one_active("mos_bucket_configuration")
        self.assertEqual(config["ownership"]["request_fingerprint"], "")
        self.assertEqual(config["ownership"]["versioning"], "Enabled")

    def test_reconcile_object_storage_rejects_duplicate_ownership_marker_versions(self):
        harness = self.harness(apply=False)
        value = self.seed_service(harness)
        self.seed_bucket(harness, value)
        self.seed_user_policy_key(harness, value)
        runtime = self.write_runtime(harness, value)
        key = harness._ownership_marker_contract(
            runtime["bucket_name"], runtime["prefix"]
        )["key"]
        client = mock.Mock()
        client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        inventory = {
            "versions": [{"Key": key, "VersionId": "v1"}, {"Key": key, "VersionId": "v2"}],
            "delete_markers": [],
            "objects": [{"Key": key}],
            "multipart_uploads": [],
        }
        with mock.patch.object(harness, "verify_account", return_value=self.account), \
            mock.patch.object(harness, "_service_read", return_value=value), \
            mock.patch.object(harness, "_buckets", return_value=[{"name": runtime["bucket_name"]}]), \
            mock.patch.object(harness, "_s3", return_value=(client, runtime)), \
            mock.patch.object(harness, "_s3_inventory", return_value=inventory), \
            self.assertRaises(live_harness.HarnessError):
            harness.reconcile_object_storage_evidence()
        self.assertIsNone(harness._one_active("mos_bucket_configuration"))

    def test_crossed_object_delete_adopts_exact_absence_without_replay(self):
        harness = self.harness(apply=True, cleanup=True)
        key = f"{harness.names['prefix']}backup-live.zip"
        entry = harness._record_object(
            kind="mos_ui_website_object",
            bucket=harness.names["bucket"],
            key=key,
            version_id="v1",
            sha256="a" * 64,
            byte_count=1,
            etag="etag",
            backup_id="1",
            backup_uuid="backup-live",
            metadata={},
        )
        intent_key = f"cleanup:{entry['kind']}:{entry['resource_id']}"
        harness.intents.put(
            intent_key,
            {"marker": self.run_id, "kind": entry["kind"], "name": key, "operation": "delete-version"},
        )
        harness.intents.update(intent_key, request_boundary_crossed=True)
        empty = {"versions": [], "delete_markers": [], "objects": [], "multipart_uploads": []}
        client = mock.Mock()
        with mock.patch.object(harness, "_s3_inventory", return_value=empty):
            harness._delete_bucket_contents(
                client, harness.names["bucket"], harness.names["prefix"], maximum_bytes=1024
            )
        client.delete_object.assert_not_called()
        self.assertEqual(harness.ledger.get(entry["kind"], entry["resource_id"])["cleanup_state"], "deleted")

    def test_object_cleanup_evidence_gate_stops_before_mutation(self):
        harness = self.harness(apply=True, cleanup=True)
        value = self.seed_service(harness)
        with mock.patch.object(harness, "verify_account", return_value=self.account), \
            mock.patch.object(harness, "_service_read", return_value=value), \
            mock.patch.object(harness, "_control_mutation") as mutation, \
            self.assertRaises(live_harness.HarnessError):
            harness.cleanup_object_storage(maximum_bytes=1024, require_evidence=True)
        mutation.assert_not_called()

    def test_object_cleanup_preserves_credentials_service_and_runtime_bytes(self):
        harness = self.harness(apply=True, cleanup=True)
        value = self.seed_service(harness)
        self.seed_bucket(harness, value)
        self.seed_user_policy_key(harness, value)
        runtime = self.write_runtime(harness, value)
        before = harness.config.runtime_path.read_bytes()
        provider = self.provider_scaffolding(harness)
        client = mock.Mock()

        with mock.patch.object(
            harness, "verify_account", return_value=self.account
        ), mock.patch.object(
            harness, "_service_read", return_value=value
        ), mock.patch.object(
            harness,
            "_buckets",
            side_effect=[
                [{"name": harness.names["bucket"]}],
                [],
                [],
            ],
        ), mock.patch.object(
            harness, "_users", return_value=[provider["user"]]
        ), mock.patch.object(
            harness, "_user_read", return_value=provider["user"]
        ), mock.patch.object(
            harness, "_inline_policies", return_value=[provider["policy"]]
        ), mock.patch.object(
            harness, "_policy_read", return_value=provider["policy"]
        ), mock.patch.object(
            harness, "_access_keys", return_value=[provider["key"]]
        ), mock.patch.object(
            harness, "_access_key_read", return_value=provider["key"]
        ), mock.patch.object(
            harness, "_s3", return_value=(client, runtime)
        ), mock.patch.object(
            harness, "_delete_bucket_contents"
        ) as delete_contents, mock.patch.object(
            harness, "_control_mutation"
        ) as mutation:
            harness.control.request.return_value = [provider["network"]]
            result = harness.cleanup_object_storage(maximum_bytes=1024)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["data_cleanup"], "terminal")
        self.assertEqual(
            result["credential_service_scaffolding"],
            live_harness.USER_RETAINED_BY_INSTRUCTION,
        )
        self.assertEqual(harness.config.runtime_path.read_bytes(), before)
        with self.assertRaisesRegex(
            live_harness.HarnessError, r"Only the separate compute runtime"
        ):
            live_harness._remove_compute_runtime_secret(
                harness.config.runtime_path
            )
        self.assertEqual(harness.config.runtime_path.read_bytes(), before)
        delete_contents.assert_called_once()
        self.assertEqual(mutation.call_count, 1)
        self.assertEqual(mutation.call_args.args[0], "cleanup:mos-bucket")
        self.assertEqual(mutation.call_args.args[1], "DELETE")
        self.assertIn("/buckets/", mutation.call_args.args[2])
        self.assertFalse(
            any(
                call.args and call.args[0] == "DELETE"
                for call in harness.control.request.call_args_list
            )
        )
        for kind in live_harness.MOS_RETAINED_PROVIDER_KINDS:
            rows = harness._active_entries(kind)
            self.assertEqual(len(rows), 1, kind)
            self.assertEqual(rows[0]["cleanup_state"], "eligible")
        receipt_kinds = {
            row["ownership"]["retained_kind"]
            for row in harness._active_entries(
                live_harness.MOS_RETENTION_RECEIPT_KIND
            )
        }
        self.assertEqual(receipt_kinds, live_harness.MOS_RETAINED_KINDS)
        self.assertIn(
            live_harness.UPCLOUD_ACCOUNT_TOKEN_KIND,
            {row["kind"] for row in result["retained_by_instruction"]},
        )

    def test_retained_mos_delete_kinds_are_blocked_before_any_endpoint(self):
        harness = self.harness(apply=True, cleanup=True)
        for kind in (
            "mos_access_key",
            "mos_user",
            "mos_service",
            "mos_inline_policy",
            "mos_network",
        ):
            with self.subTest(kind=kind), mock.patch.object(
                harness, "_control_mutation"
            ) as mutation, self.assertRaisesRegex(
                live_harness.HarnessError, r"retained by user instruction"
            ):
                harness._control_delete(
                    intent_key=f"cleanup:{kind}",
                    kind=kind,
                    entry={"resource_id": f"{kind}-id", "name": kind},
                    path=f"/forbidden/{kind}",
                    verify_absent=lambda: False,
                )
            mutation.assert_not_called()
        harness.control.request.assert_not_called()

    def test_object_cleanup_preservation_gate_is_default_on_and_cannot_disable(self):
        args = live_harness.build_parser().parse_args(["cleanup-object-storage"])
        self.assertIs(args.preserve_credentials, True)
        harness = self.harness(apply=True, cleanup=True)
        with mock.patch.object(harness, "verify_account") as verify_account, \
            self.assertRaisesRegex(
                live_harness.HarnessError, r"preservation is mandatory"
            ):
            harness.cleanup_object_storage(
                maximum_bytes=1024, preserve_credentials=False
            )
        verify_account.assert_not_called()

    def test_missing_retained_service_never_removes_runtime_or_marks_credentials(self):
        harness = self.harness(apply=True, cleanup=True)
        value = self.seed_service(harness)
        self.seed_user_policy_key(harness, value)
        self.write_runtime(harness, value)
        before = harness.config.runtime_path.read_bytes()
        with mock.patch.object(
            harness, "verify_account", return_value=self.account
        ), mock.patch.object(
            harness, "_service_read", return_value=None
        ), mock.patch.object(
            harness, "_control_mutation"
        ) as mutation, self.assertRaisesRegex(
            live_harness.HarnessError, r"user-retained MOS service is absent"
        ):
            harness.cleanup_object_storage(maximum_bytes=1024)
        mutation.assert_not_called()
        self.assertEqual(harness.config.runtime_path.read_bytes(), before)
        self.assertEqual(
            harness._one_active("mos_service")["cleanup_state"], "eligible"
        )
        self.assertEqual(
            harness._one_active("mos_access_key")["cleanup_state"], "eligible"
        )

    def test_after_inventory_accepts_complete_nonempty_retained_mos_graph(self):
        harness = self.harness(apply=False)
        value = self.seed_service(harness)
        self.seed_user_policy_key(harness, value)
        self.write_runtime(harness, value)
        provider = self.provider_scaffolding(harness)
        harness.control.request.return_value = [provider["network"]]
        with mock.patch.object(
            harness, "_users", return_value=[provider["user"]]
        ), mock.patch.object(
            harness, "_user_read", return_value=provider["user"]
        ), mock.patch.object(
            harness, "_inline_policies", return_value=[provider["policy"]]
        ), mock.patch.object(
            harness, "_policy_read", return_value=provider["policy"]
        ), mock.patch.object(
            harness, "_access_keys", return_value=[provider["key"]]
        ), mock.patch.object(
            harness, "_access_key_read", return_value=provider["key"]
        ):
            harness._validate_and_receipt_retained_mos_scaffolding(
                harness._one_active("mos_service"), value
            )

            with mock.patch.object(
                harness, "verify_account", return_value=self.account
            ), mock.patch.object(
                harness, "_compute_inventory", return_value=[]
            ), mock.patch.object(
                harness, "_ip_inventory", return_value=[]
            ), mock.patch.object(
                harness, "_offset_list", return_value=[value]
            ), mock.patch.object(
                harness, "_service_read", return_value=value
            ), mock.patch.object(
                harness, "_buckets", return_value=[]
            ):
                result = harness.inventory(phase="after")

        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["exact_run"]["mos_services"], [value["uuid"]])
        graph = result["exact_run"]["mos_graph"][0]
        self.assertTrue(graph["retention_verified"])
        self.assertTrue(graph["protected_runtime_file_verified"])
        self.assertEqual(
            graph["disposition"],
            live_harness.USER_RETAINED_BY_INSTRUCTION,
        )

    def test_read_only_after_inventory_proves_no_exact_run_graph(self):
        harness = self.harness(apply=False)
        with mock.patch.object(harness, "verify_account", return_value=self.account), \
            mock.patch.object(harness, "_compute_inventory", return_value=[]), \
            mock.patch.object(harness, "_ip_inventory", return_value=[]), \
            mock.patch.object(harness, "_offset_list", return_value=[]):
            result = harness.inventory(phase="after")
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["exact_run"]["servers"], [])

    def test_final_inventory_rejects_exact_run_orphan(self):
        harness = self.harness(apply=False)
        summary = {
            "uuid": "11111111-1111-4111-8111-111111111111",
            "title": harness.names["source_server"],
            "labels": live_harness._labels(self.run_id),
        }
        exact = {
            **summary,
            "storage_devices": {"storage_device": []},
            "ip_addresses": {"ip_address": []},
        }
        with mock.patch.object(harness, "verify_account", return_value=self.account), \
            mock.patch.object(harness, "_compute_inventory", side_effect=[[summary], [], []]), \
            mock.patch.object(harness, "_server_read", return_value=exact), \
            mock.patch.object(harness, "_ip_inventory", return_value=[]), \
            mock.patch.object(harness, "_offset_list", return_value=[]), \
            self.assertRaises(live_harness.HarnessError):
            harness.inventory(phase="after")

    def test_empty_object_cleanup_is_idempotent(self):
        harness = self.harness(apply=True, cleanup=True)
        with mock.patch.object(harness, "verify_account", return_value=self.account):
            first = harness.cleanup_object_storage(maximum_bytes=1024)
            second = harness.cleanup_object_storage(maximum_bytes=1024)
        self.assertEqual(first, {"status": "nothing_to_cleanup"})
        self.assertEqual(second, first)
        harness.control.request.assert_not_called()

    def test_duplicate_ui_object_versions_fail_closed_without_ledger_adoption(self):
        harness = self.harness(apply=True)
        value = self.seed_service(harness)
        self.seed_user_policy_key(harness, value)
        runtime = self.write_runtime(harness, value)
        self.seed_bucket(harness, value)
        self.arm_bucket_for_manifest(harness, value, runtime)
        backup_id = 124
        backup_uuid = "22222222-2222-4222-8222-222222222222"
        key = f"{runtime['prefix']}{backup_uuid}.zip"
        manifest_path = self.root / "duplicate.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "run_id": self.run_id,
                    "objects": [
                        self.object_row(
                            kind="database",
                            backup_id=backup_id,
                            backup_uuid=backup_uuid,
                            object_key=key,
                            version_id="v2",
                        ),
                        self.object_row(
                            kind="website",
                            backup_id=125,
                            backup_uuid="website-companion-2026.08.15",
                            object_key=(
                                f"{runtime['prefix']}website-companion-2026.08.15.zip"
                            ),
                        ),
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
            mock.patch.object(
                harness,
                "_s3",
                return_value=(
                    mock.Mock(
                        get_bucket_versioning=mock.Mock(return_value={"Status": "Enabled"})
                    ),
                    runtime,
                ),
            ), \
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
                        self.object_row(
                            kind="website",
                            backup_id=125,
                            backup_uuid=backup_uuid,
                            object_key=f"{runtime['prefix']}125.zip",
                        ),
                        self.object_row(
                            kind="database",
                            backup_id=126,
                            backup_uuid="database-companion-2026.08.15",
                            object_key=(
                                f"{runtime['prefix']}database-companion-2026.08.15.zip"
                            ),
                        ),
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
        row = self.object_row(
            kind="database",
            backup_id=126,
            backup_uuid=backup_uuid,
            object_key=key,
        )
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

        inventory.assert_not_called()

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
