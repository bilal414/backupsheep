"""Local-only safety tests for the Hetzner live E2E harnesses.

These tests deliberately use fake credentials and mocked client factories. No
provider or network calls are permitted; an invalid endpoint must fail before
the requests or boto3 client can receive credentials.
"""

import os
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from scripts import hetzner_cloud_e2e as cloud_e2e
from scripts import hetzner_object_storage_e2e as object_storage_e2e
from scripts import hetzner_web_database_fixture_e2e as fixture_e2e


RUN_ID = "bs-e2e-20260810-endpoint-safety"


class HetznerE2EEndpointSafetyTests(TestCase):
    def _common_env(self, ledger_path, **overrides):
        values = {
            "BACKUPSHEEP_E2E_RUN_ID": RUN_ID,
            "BACKUPSHEEP_E2E_LEDGER_PATH": str(ledger_path),
            "BACKUPSHEEP_E2E_APPLY": "NO",
            "BACKUPSHEEP_E2E_CLEANUP": "YES",
            "HETZNER_E2E_API": "https://api.hetzner.cloud",
            "HETZNER_E2E_SERVER_TYPE": "cx23",
            "HETZNER_E2E_LOCATION": "fsn1",
            "HETZNER_E2E_IMAGE": "ubuntu-24.04",
            "HETZNER_S3_ENDPOINT": "https://fsn1.your-objectstorage.com",
            "HETZNER_S3_REGION": "fsn1",
        }
        values.update(overrides)
        return values

    def test_cloud_api_rejects_alternate_endpoints_before_session_receives_token(self):
        invalid_endpoints = (
            "http://api.hetzner.cloud",
            "https://evil.example",
            "https://api.hetzner.cloud:443",
            "https://api.hetzner.cloud/",
            "https://api.hetzner.cloud/v1",
            "https://api.hetzner.cloud?redirect=1",
            "https://api.hetzner.cloud#fragment",
            "https://user:secret@api.hetzner.cloud",
        )
        with mock.patch.object(cloud_e2e.requests, "Session") as session_factory:
            for endpoint in invalid_endpoints:
                with self.subTest(endpoint=endpoint), tempfile.TemporaryDirectory() as directory:
                    environment = self._common_env(
                        Path(directory) / "ledger.json", HETZNER_E2E_API=endpoint
                    )
                    with mock.patch.dict(os.environ, environment, clear=False):
                        with self.assertRaises(cloud_e2e.HarnessError):
                            cloud_e2e.HetznerHarness("fake-cloud-token")
        session_factory.assert_not_called()

    def test_fixture_api_rejects_alternate_endpoints_before_session_receives_token(self):
        invalid_endpoints = (
            "http://api.hetzner.cloud",
            "https://evil.example",
            "https://api.hetzner.cloud:443",
            "https://api.hetzner.cloud/",
            "https://api.hetzner.cloud/v1",
            "https://api.hetzner.cloud?redirect=1",
            "https://api.hetzner.cloud#fragment",
            "https://user:secret@api.hetzner.cloud",
        )
        with mock.patch.object(fixture_e2e.requests, "Session") as session_factory:
            for endpoint in invalid_endpoints:
                with self.subTest(endpoint=endpoint), tempfile.TemporaryDirectory() as directory:
                    environment = self._common_env(
                        Path(directory) / "ledger.json", HETZNER_E2E_API=endpoint
                    )
                    with mock.patch.dict(os.environ, environment, clear=False):
                        with self.assertRaises(fixture_e2e.HarnessError):
                            fixture_e2e.HetznerFixtureHarness("fake-fixture-token")
        session_factory.assert_not_called()

    def test_object_storage_rejects_alternate_endpoints_before_boto3_receives_keys(self):
        invalid_endpoints = (
            "http://fsn1.your-objectstorage.com",
            "https://evil.your-objectstorage.com",
            "https://fsn1.your-objectstorage.com:443",
            "https://fsn1.your-objectstorage.com/",
            "https://fsn1.your-objectstorage.com/bucket",
            "https://fsn1.your-objectstorage.com?redirect=1",
            "https://fsn1.your-objectstorage.com#fragment",
            "https://user:secret@fsn1.your-objectstorage.com",
            "https://storage.fsn1.your-objectstorage.com",
        )
        with mock.patch.object(object_storage_e2e.boto3, "client") as client_factory:
            for endpoint in invalid_endpoints:
                with self.subTest(endpoint=endpoint), tempfile.TemporaryDirectory() as directory:
                    environment = self._common_env(
                        Path(directory) / "ledger.json",
                        HETZNER_S3_ENDPOINT=endpoint,
                        HETZNER_S3_REGION="fsn1",
                    )
                    with mock.patch.dict(os.environ, environment, clear=False):
                        with self.assertRaises(object_storage_e2e.HarnessError):
                            object_storage_e2e.ObjectStorageHarness(
                                "fake-storage-access", "fake-storage-secret"
                            )
        client_factory.assert_not_called()

    def test_object_storage_requires_region_and_hostname_consistency(self):
        invalid = (
            ("https://fsn1.your-objectstorage.com", "nbg1"),
            ("https://nbg1.your-objectstorage.com", "FSN1"),
            ("https://nbg1.your-objectstorage.com", "nbg1/"),
            ("https://nbg1.other-objectstorage.com", "nbg1"),
        )
        for endpoint, region in invalid:
            with self.subTest(endpoint=endpoint, region=region):
                with self.assertRaises(object_storage_e2e.HarnessError):
                    object_storage_e2e._validate_object_storage_endpoint(endpoint, region)

        self.assertEqual(
            object_storage_e2e._validate_object_storage_endpoint(
                "https://fsn1.your-objectstorage.com", "fsn1"
            ),
            ("https://fsn1.your-objectstorage.com", "fsn1"),
        )

    def test_cleanup_without_apply_performs_zero_delete_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            environment = self._common_env(ledger_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                cloud = cloud_e2e.HetznerHarness("fake-cloud-token")
                with mock.patch.object(
                    cloud, "_delete_owned_server"
                ) as delete_server, mock.patch.object(
                    cloud, "_delete_owned_snapshot"
                ) as delete_snapshot, mock.patch.object(
                    cloud, "_wait_until_owned_resources_absent"
                ) as wait_absent:
                    cloud.cleanup()
                delete_server.assert_not_called()
                delete_snapshot.assert_not_called()
                wait_absent.assert_not_called()
                self.assertEqual(cloud.report["cleanup"]["status"], "REFUSED")

        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            environment = self._common_env(ledger_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                fixture = fixture_e2e.HetznerFixtureHarness("fake-fixture-token")
                with mock.patch.object(fixture.ledger, "entries") as entries, mock.patch.object(
                    fixture, "_delete_entry"
                ) as delete_entry:
                    fixture.cleanup()
                entries.assert_not_called()
                delete_entry.assert_not_called()
                self.assertEqual(fixture.report["cleanup"]["status"], "REFUSED")

        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            environment = self._common_env(ledger_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                client = mock.Mock()
                with mock.patch.object(object_storage_e2e.boto3, "client", return_value=client):
                    storage = object_storage_e2e.ObjectStorageHarness(
                        "fake-storage-access", "fake-storage-secret"
                    )
                storage.cleanup()
                client.delete_object.assert_not_called()
                client.delete_objects.assert_not_called()
                client.delete_bucket.assert_not_called()
                self.assertEqual(storage.report["cleanup"]["status"], "REFUSED")

    def test_run_rejects_cleanup_without_apply_before_provider_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            environment = self._common_env(ledger_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                cloud = cloud_e2e.HetznerHarness("fake-cloud-token")
                with mock.patch.object(cloud, "baseline") as baseline:
                    result = cloud.run()
                baseline.assert_not_called()
                self.assertEqual(result, 1)
                self.assertEqual(cloud.report["cleanup"]["status"], "REFUSED")

        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            environment = self._common_env(ledger_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                fixture = fixture_e2e.HetznerFixtureHarness("fake-fixture-token")
                with mock.patch.object(fixture, "baseline") as baseline:
                    result = fixture.run()
                baseline.assert_not_called()
                self.assertEqual(result, 1)
                self.assertEqual(fixture.report["cleanup"]["status"], "REFUSED")

        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            environment = self._common_env(ledger_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                client = mock.Mock()
                with mock.patch.object(object_storage_e2e.boto3, "client", return_value=client):
                    storage = object_storage_e2e.ObjectStorageHarness(
                        "fake-storage-access", "fake-storage-secret"
                    )
                result = storage.run()
                self.assertEqual(result, 1)
                client.list_buckets.assert_not_called()
                self.assertEqual(storage.report["cleanup"]["status"], "REFUSED")

    def test_object_storage_cleanup_reconciles_pending_create_before_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            environment = self._common_env(
                ledger_path,
                BACKUPSHEEP_E2E_APPLY="YES",
                BACKUPSHEEP_E2E_CLEANUP="YES",
            )
            client = mock.Mock()
            with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
                object_storage_e2e.boto3, "client", return_value=client
            ):
                storage = object_storage_e2e.ObjectStorageHarness(
                    "fake-storage-access", "fake-storage-secret"
                )
            with mock.patch.object(
                storage,
                "_reconcile_pending_intents",
                return_value=["ambiguous pending create"],
            ), mock.patch.object(storage.ledger, "get") as ledger_get:
                storage.cleanup()

            ledger_get.assert_not_called()
            client.delete_objects.assert_not_called()
            client.delete_bucket.assert_not_called()
            self.assertEqual(storage.report["cleanup"]["status"], "MANUAL_REVIEW")
