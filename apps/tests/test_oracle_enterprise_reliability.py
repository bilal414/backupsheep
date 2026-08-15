"""Offline acceptance tests for Oracle Cloud backup and restore safety."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from types import SimpleNamespace
from threading import Barrier, Event
from unittest import mock
from uuid import uuid4

import oci
from django.db import close_old_connections
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.utils import timezone
from rest_framework import serializers

from apps._tasks.integration.oracle import (
    ORACLE_BACKUP_TAG,
    ORACLE_KIND_TAG,
    ORACLE_REQUEST_TAG,
    ORACLE_RESTORE_ORIGIN_TAG,
    ORACLE_RESTORE_SOURCE_TAG,
    ORACLE_RESTORE_TAG,
    ORACLE_SOURCE_TAG,
    OracleBackupWitness,
    OracleProviderError,
    OracleComputeAdapter,
    OracleRestoreAdapter,
    OracleVolumeAdapter,
    _oracle_delete_absence,
    _persist_oracle_delete_state,
    classify_oracle_error,
    discover_exact_oracle_object,
    discover_oracle_objects,
    iter_oracle_pages,
    oracle_retry_token,
)
from apps._tasks.integration.storage.oracle import (
    _s3_client,
    oracle_object_endpoint,
)
from apps._tasks.helper import tasks as helper_tasks
from apps.api.v1.cloud.oracle.serializers import CoreCloudOracleWriteSerializer
from apps.api.v1.volume.oracle.serializers import CoreVolumeOracleWriteSerializer
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import (
    CoreBackupExecution,
    CoreCloudRestore,
    CoreOracleBackup,
)
from apps.console.connection.models import CoreAuthOracle, CoreConnection, CoreIntegration
from apps.console.node.models import CoreNode, CoreOracle
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


def response(data=None, *, status=200, next_page=None, headers=None):
    return SimpleNamespace(
        status=status,
        data=data,
        opc_next_page=next_page,
        headers=headers or {},
    )


def model(**values):
    return SimpleNamespace(**values)


class OracleProviderPrimitiveTests(SimpleTestCase):
    def test_error_classification_is_explicit_and_secret_free(self):
        cases = (
            (oci.exceptions.ServiceError(401, "NotAuthenticated", {}, "secret"), "PROVIDER_AUTH_FAILED", False),
            (oci.exceptions.ServiceError(404, "NotFound", {}, "secret"), "PROVIDER_NOT_FOUND", False),
            (oci.exceptions.ServiceError(400, "LimitExceeded", {}, "secret"), "QUOTA_EXCEEDED", False),
            (oci.exceptions.ServiceError(429, "TooManyRequests", {"retry-after": "17"}, "secret"), "PROVIDER_RATE_LIMIT", True),
            (oci.exceptions.ServiceError(503, "ServiceUnavailable", {}, "secret"), "PROVIDER_TRANSIENT_OUTAGE", True),
            (oci.exceptions.RequestException("provider-secret"), "PROVIDER_TRANSIENT_OUTAGE", True),
        )
        for error, code, retryable in cases:
            with self.subTest(code=code):
                classified = classify_oracle_error(error, mutation=True)
                self.assertEqual(classified.code, code)
                self.assertEqual(classified.retryable, retryable)
                self.assertNotIn("secret", str(classified))
        rate_limit = classify_oracle_error(cases[3][0], mutation=True)
        self.assertEqual(rate_limit.retry_after, 17)
        self.assertTrue(rate_limit.unknown_outcome)

        ambiguous = classify_oracle_error(
            oci.exceptions.ServiceError(
                404, "NotAuthorizedOrNotFound", {}, "provider-secret"
            )
        )
        self.assertEqual(ambiguous.code, "PROVIDER_NOT_FOUND_OR_UNAUTHORIZED")
        self.assertNotEqual(ambiguous.code, "PROVIDER_NOT_FOUND")

    def test_retry_token_is_stable_bounded_and_opaque(self):
        marker = "customer-visible-marker-with-sensitive-context"
        first = oracle_retry_token(marker)
        self.assertEqual(first, oracle_retry_token(marker))
        self.assertLessEqual(len(first), 64)
        self.assertNotIn(marker, first)
        self.assertNotEqual(first, oracle_retry_token(marker + "-other"))

    def test_object_storage_uses_canonical_path_style_sigv4_endpoint(self):
        provider = SimpleNamespace(
            namespace="safe_namespace",
            region=SimpleNamespace(code="us-chicago-1"),
            access_key=b"encrypted-access",
            secret_key=b"encrypted-secret",
        )
        with mock.patch(
            "apps._tasks.integration.storage.oracle.bs_decrypt",
            return_value="secret",
        ), mock.patch(
            "apps.api.v1.utils.boto.boto3.client"
        ) as constructor:
            _s3_client(provider, "encryption-key")
        kwargs = constructor.call_args.kwargs
        self.assertEqual(
            kwargs["endpoint_url"],
            "https://safe_namespace.compat.objectstorage.us-chicago-1.oraclecloud.com",
        )
        self.assertEqual(kwargs["config"].signature_version, "s3v4")
        self.assertEqual(kwargs["config"].s3["addressing_style"], "path")
        with self.assertRaises(ValueError):
            oracle_object_endpoint("bad/namespace", "us-chicago-1")

    def test_cursor_pagination_consumes_every_page(self):
        listing = mock.Mock(
            side_effect=[
                response([{"id": "one"}], next_page="cursor-2"),
                response([{"id": "two"}]),
            ]
        )
        self.assertEqual(
            list(iter_oracle_pages(listing, compartment_id="root")),
            [{"id": "one"}, {"id": "two"}],
        )
        self.assertNotIn("page", listing.call_args_list[0].kwargs)
        self.assertEqual(listing.call_args_list[1].kwargs["page"], "cursor-2")

    def test_repeated_cursor_and_inventory_bounds_fail_closed(self):
        repeated = mock.Mock(
            side_effect=[
                response([], next_page="same"),
                response([], next_page="same"),
            ]
        )
        with self.assertRaisesRegex(OracleProviderError, "invalid response"):
            list(iter_oracle_pages(repeated, compartment_id="root"))

        too_many = mock.Mock(return_value=response([{"id": 1}, {"id": 2}]))
        with self.assertRaises(OracleProviderError):
            list(iter_oracle_pages(too_many, max_items=1))

    @override_settings(
        PROVIDER_HTTP_CONNECT_TIMEOUT=3,
        PROVIDER_HTTP_READ_TIMEOUT=11,
    )
    @mock.patch("oci.core.BlockstorageClient")
    def test_volume_adapter_constructs_bounded_no_retry_client(self, constructor):
        node = SimpleNamespace(
            type=CoreNode.Type.VOLUME,
            connection=SimpleNamespace(
                auth_oracle=SimpleNamespace(
                    get_client=lambda: {"region": "us-test-1"},
                    get_verified_client=lambda: {"region": "us-test-1"},
                )
            ),
        )
        integration = SimpleNamespace(
            node=node,
            unique_id="ocid1.volume.test.source",
            metadata={"_bs_vol_type": "block"},
        )
        adapter = OracleVolumeAdapter(integration)
        self.assertIs(adapter.client, constructor.return_value)
        kwargs = constructor.call_args.kwargs
        self.assertEqual(kwargs["timeout"], (3.0, 11.0))
        self.assertIsInstance(kwargs["retry_strategy"], oci.retry.NoneRetryStrategy)


class OracleEnterpriseReliabilityTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.connection = factories.make_connection(
            self.account, self.member, code="oracle"
        )
        CoreAuthOracle.objects.create(
            connection=self.connection,
            user="ocid1.user.test.backupsheep",
            fingerprint="aa:bb:cc",
            tenancy="ocid1.tenancy.test.backupsheep",
            region="us-chicago-1",
            private_key=bs_encrypt(
                "offline-private-key", self.account.get_encryption_key()
            ),
            profile="DEFAULT",
        )
        self.node = CoreNode.objects.create(
            connection=self.connection,
            type=CoreNode.Type.VOLUME,
            name="oracle-source-volume",
            added_by=self.member,
        )
        self.integration = CoreOracle.objects.create(
            node=self.node,
            name="oracle-source-volume",
            unique_id="ocid1.volume.test.source",
            metadata={
                "_bs_vol_type": "block",
                "_bs_availability_domain": "AD-1",
            },
        )

    def _backup(self, marker="bs-oracle-volume-n1-b1"):
        return self.integration.backups.create(
            uuid=marker,
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
            celery_task_id=f"task-{uuid4().hex}",
        )

    @staticmethod
    def _source_volume():
        return model(
            id="ocid1.volume.test.source",
            display_name="source-volume",
            compartment_id="ocid1.compartment.test.backupsheep",
            availability_domain="AD-1",
            lifecycle_state="AVAILABLE",
            size_in_gbs=50,
            freeform_tags={},
            source_details=None,
        )

    @staticmethod
    def _backup_resource(marker, *, resource_id="ocid1.volumebackup.test.one"):
        token = oracle_retry_token(marker)
        return model(
            id=resource_id,
            display_name=marker,
            compartment_id="ocid1.compartment.test.backupsheep",
            volume_id="ocid1.volume.test.source",
            lifecycle_state="CREATING",
            size_in_gbs=50,
            freeform_tags={
                ORACLE_BACKUP_TAG: marker,
                ORACLE_SOURCE_TAG: "ocid1.volume.test.source",
                ORACLE_KIND_TAG: "block",
                ORACLE_REQUEST_TAG: token,
            },
            source_details=None,
        )

    def _volume_client(self):
        client = mock.MagicMock()
        client.get_volume.return_value = response(self._source_volume())
        client.list_volume_backups.return_value = response([])
        return client

    def _compute_fixture(self):
        node = CoreNode.objects.create(
            connection=self.connection,
            type=CoreNode.Type.CLOUD,
            name="oracle-source-instance",
            added_by=self.member,
        )
        integration = CoreOracle.objects.create(
            node=node,
            name="oracle-source-instance",
            unique_id="ocid1.instance.test.source",
            metadata={
                "_bs_compartment_id": "ocid1.compartment.test.backupsheep",
                "_bs_availability_domain": "AD-1",
                "_bs_shape": "VM.Standard.E2.1.Micro",
            },
        )
        backup = integration.backups.create(
            uuid="bs-oracle-compute-n1-b1",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
            celery_task_id=f"task-{uuid4().hex}",
        )
        return node, integration, backup

    def _boot_fixture(self):
        node = CoreNode.objects.create(
            connection=self.connection,
            type=CoreNode.Type.VOLUME,
            name="oracle-source-boot-volume",
            added_by=self.member,
        )
        integration = CoreOracle.objects.create(
            node=node,
            name="oracle-source-boot-volume",
            unique_id="ocid1.bootvolume.test.source",
            metadata={
                "_bs_vol_type": "boot",
                "_bs_availability_domain": "AD-1",
            },
        )
        backup = integration.backups.create(
            uuid="bs-oracle-boot-n1-b1",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
            celery_task_id=f"task-{uuid4().hex}",
        )
        return node, integration, backup

    @staticmethod
    def _compute_source():
        return model(
            id="ocid1.instance.test.source",
            display_name="source-instance",
            compartment_id="ocid1.compartment.test.backupsheep",
            availability_domain="AD-1",
            lifecycle_state="RUNNING",
            freeform_tags={},
            source_details=model(image_id="ocid1.image.test.base"),
        )

    @staticmethod
    def _compute_image(marker, *, resource_id="ocid1.image.test.backup"):
        return model(
            id=resource_id,
            display_name=marker,
            compartment_id="ocid1.compartment.test.backupsheep",
            lifecycle_state="CREATING",
            size_in_mbs=1024,
            freeform_tags={
                ORACLE_BACKUP_TAG: marker,
                ORACLE_SOURCE_TAG: "ocid1.instance.test.source",
                ORACLE_KIND_TAG: "compute_image",
                ORACLE_REQUEST_TAG: oracle_retry_token(marker),
            },
            source_details=None,
        )

    def _run_shared_oracle_create_and_poll(
        self, backup, adapter, resource, make_available
    ):
        """Exercise the Celery create boundary before the adapter poller."""

        with mock.patch.object(helper_tasks.current_app, "send_task") as resume:
            result = helper_tasks.run_provider_create(
                backup,
                backup.celery_task_id,
                adapter.create_or_adopt_backup,
            )

        self.assertIsNotNone(result)
        backup.refresh_from_db()
        execution = backup.get_execution_state(create=False)
        expected_token = oracle_retry_token(backup.uuid_str)
        self.assertEqual(execution.provider_idempotency_key, expected_token)
        self.assertNotEqual(
            execution.provider_idempotency_key,
            backup.uuid_str,
        )
        resume.assert_not_called()

        make_available(resource)
        self.assertEqual(adapter.poll_backup(backup), UtilBackup.Status.COMPLETE)
        execution.refresh_from_db()
        self.assertNotEqual(
            execution.last_error_code,
            "PROVIDER_RECONCILIATION_REQUIRED",
        )

    def test_shared_create_preserves_compute_retry_token_for_polling(self):
        _node, integration, backup = self._compute_fixture()
        client = mock.MagicMock()
        client.get_instance.return_value = response(self._compute_source())
        client.list_images.return_value = response([])
        image = self._compute_image(backup.uuid_str)
        client.create_image.return_value = response(image, status=202)
        adapter = OracleComputeAdapter(integration, client=client)
        client.get_image.return_value = response(image)

        self._run_shared_oracle_create_and_poll(
            backup,
            adapter,
            image,
            lambda resource: setattr(resource, "lifecycle_state", "AVAILABLE"),
        )
        client.create_image.assert_called_once()

    def test_shared_create_preserves_boot_volume_retry_token_for_polling(self):
        _node, integration, backup = self._boot_fixture()
        client = mock.MagicMock()
        source = model(
            id=integration.unique_id,
            display_name="source-boot-volume",
            compartment_id="ocid1.compartment.test.backupsheep",
            availability_domain="AD-1",
            lifecycle_state="AVAILABLE",
            size_in_gbs=50,
            freeform_tags={},
            source_details=None,
        )
        token = oracle_retry_token(backup.uuid_str)
        boot_backup = model(
            id="ocid1.bootvolumebackup.test.shared-create",
            display_name=backup.uuid_str,
            compartment_id=source.compartment_id,
            boot_volume_id=integration.unique_id,
            lifecycle_state="CREATING",
            size_in_gbs=50,
            freeform_tags={
                ORACLE_BACKUP_TAG: backup.uuid_str,
                ORACLE_SOURCE_TAG: integration.unique_id,
                ORACLE_KIND_TAG: "boot",
                ORACLE_REQUEST_TAG: token,
            },
            source_details=None,
        )
        client.get_boot_volume.return_value = response(source)
        client.list_boot_volume_backups.return_value = response([])
        client.create_boot_volume_backup.return_value = response(
            boot_backup, status=202
        )
        client.get_boot_volume_backup.return_value = response(boot_backup)
        adapter = OracleVolumeAdapter(integration, client=client)

        self._run_shared_oracle_create_and_poll(
            backup,
            adapter,
            boot_backup,
            lambda resource: setattr(resource, "lifecycle_state", "AVAILABLE"),
        )
        client.create_boot_volume_backup.assert_called_once()

    def test_shared_create_preserves_block_volume_retry_token_for_polling(self):
        backup = self._backup()
        client = self._volume_client()
        volume_backup = self._backup_resource(
            backup.uuid_str,
            resource_id="ocid1.volumebackup.test.shared-create",
        )
        client.create_volume_backup.return_value = response(
            volume_backup, status=202
        )
        client.get_volume_backup.return_value = response(volume_backup)
        adapter = OracleVolumeAdapter(self.integration, client=client)

        self._run_shared_oracle_create_and_poll(
            backup,
            adapter,
            volume_backup,
            lambda resource: setattr(resource, "lifecycle_state", "AVAILABLE"),
        )
        client.create_volume_backup.assert_called_once()

    def test_volume_create_persists_exact_provider_identity_before_polling(self):
        backup = self._backup()
        client = self._volume_client()
        created = self._backup_resource(backup.uuid_str)
        client.create_volume_backup.return_value = response(created, status=202)

        OracleVolumeAdapter(self.integration, client=client).create_or_adopt_backup(
            backup
        )

        backup.refresh_from_db()
        execution = backup.get_execution_state(create=False)
        self.assertEqual(backup.unique_id, created.id)
        self.assertEqual(execution.provider_resource_id, created.id)
        self.assertEqual(
            execution.provider_idempotency_key, oracle_retry_token(backup.uuid_str)
        )
        self.assertEqual(
            execution.provider_metadata["witness"]["source_id"],
            self.integration.unique_id,
        )
        kwargs = client.create_volume_backup.call_args.kwargs
        self.assertEqual(kwargs["opc_retry_token"], oracle_retry_token(backup.uuid_str))
        details = kwargs["create_volume_backup_details"]
        self.assertEqual(details.volume_id, self.integration.unique_id)
        self.assertEqual(details.freeform_tags[ORACLE_SOURCE_TAG], self.integration.unique_id)

    def test_lost_create_response_adopts_one_exact_match_without_duplicate(self):
        backup = self._backup()
        client = self._volume_client()
        candidate = self._backup_resource(backup.uuid_str)
        client.list_volume_backups.side_effect = [
            response([]),
            response([candidate]),
        ]
        client.create_volume_backup.side_effect = oci.exceptions.RequestException(
            "provider-secret-canary"
        )

        OracleVolumeAdapter(self.integration, client=client).create_or_adopt_backup(
            backup
        )

        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, candidate.id)
        client.create_volume_backup.assert_called_once()
        execution = backup.get_execution_state(create=False)
        self.assertTrue(execution.provider_metadata["adopted"])
        self.assertNotIn("provider-secret-canary", repr(execution.provider_metadata))
        self.assertNotIn("provider-secret-canary", execution.last_error_message)

    def test_accepted_create_without_body_reconciles_before_any_replay(self):
        backup = self._backup()
        client = self._volume_client()
        candidate = self._backup_resource(backup.uuid_str)
        client.list_volume_backups.side_effect = [
            response([]),
            response([candidate]),
        ]
        client.create_volume_backup.return_value = response(None, status=202)

        OracleVolumeAdapter(self.integration, client=client).create_or_adopt_backup(
            backup
        )

        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, candidate.id)
        self.assertTrue(
            backup.get_execution_state(create=False).provider_metadata["adopted"]
        )
        client.create_volume_backup.assert_called_once()

    @override_settings(ORACLE_RETRY_TOKEN_REPLAY_SECONDS=1)
    def test_expired_native_retry_token_requires_manual_reconciliation(self):
        backup = self._backup()
        client = self._volume_client()
        adapter = OracleVolumeAdapter(self.integration, client=client)
        witness = adapter.witness(backup, vars(self._source_volume()))
        backup.record_provider_reference(
            idempotency_key=witness.request_token,
            provider_status="create_intent",
            metadata={
                "provider": "oracle",
                "witness": witness.as_dict(),
                "create_attempted": True,
                "outcome_unknown": True,
                "mutation_started_at": (
                    timezone.now() - timedelta(minutes=5)
                ).isoformat(),
            },
        )

        with self.assertRaises(OracleProviderError) as raised:
            adapter.create_or_adopt_backup(backup)

        self.assertEqual(
            raised.exception.code, "PROVIDER_RECONCILIATION_REQUIRED"
        )
        client.create_volume_backup.assert_not_called()

    def test_duplicate_or_foreign_matches_fail_closed_before_create(self):
        for resources, expected_code in (
            (
                [
                    self._backup_resource("marker", resource_id="one"),
                    self._backup_resource("marker", resource_id="two"),
                ],
                "PROVIDER_DUPLICATE_MATCH",
            ),
            (
                [
                    model(
                        **{
                            **vars(self._backup_resource("marker")),
                            "freeform_tags": {ORACLE_BACKUP_TAG: "foreign"},
                        }
                    )
                ],
                "PROVIDER_OWNERSHIP_MISMATCH",
            ),
            (
                [
                    model(
                        **{
                            **vars(self._backup_resource("marker")),
                            "volume_id": None,
                        }
                    )
                ],
                "PROVIDER_OWNERSHIP_MISMATCH",
            ),
        ):
            with self.subTest(expected_code=expected_code):
                backup = self._backup("marker")
                client = self._volume_client()
                client.list_volume_backups.return_value = response(resources)
                with self.assertRaises(OracleProviderError) as raised:
                    OracleVolumeAdapter(
                        self.integration, client=client
                    ).create_or_adopt_backup(backup)
                self.assertEqual(raised.exception.code, expected_code)
                client.create_volume_backup.assert_not_called()

    def test_delete_verifies_provider_tags_and_source_before_mutation(self):
        backup = self._backup()
        client = self._volume_client()
        candidate = self._backup_resource(backup.uuid_str)
        client.create_volume_backup.return_value = response(candidate, status=202)
        adapter = OracleVolumeAdapter(self.integration, client=client)
        adapter.create_or_adopt_backup(backup)
        client.get_volume_backup.return_value = response(
            model(
                **{
                    **vars(candidate),
                    "freeform_tags": {ORACLE_BACKUP_TAG: "foreign"},
                }
            )
        )

        with self.assertRaises(OracleProviderError) as raised:
            adapter.delete_backup(backup)

        self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")
        client.delete_volume_backup.assert_not_called()

    def test_volume_poll_distinguishes_rate_limit_from_not_found(self):
        backup, _candidate = self._committed_backup()
        client = self._volume_client()
        adapter = OracleVolumeAdapter(self.integration, client=client)
        client.get_volume_backup.side_effect = oci.exceptions.ServiceError(
            429, "TooManyRequests", {"retry-after": "9"}, "provider-secret"
        )

        self.assertEqual(adapter.poll_backup(backup), UtilBackup.Status.IN_PROGRESS)
        execution = backup.get_execution_state(create=False)
        self.assertEqual(execution.last_error_code, "PROVIDER_RATE_LIMIT")
        self.assertIsNotNone(execution.next_retry_at)

        client.get_volume_backup.side_effect = oci.exceptions.ServiceError(
            404, "NotFound", {}, "provider-secret"
        )
        self.assertEqual(adapter.poll_backup(backup), UtilBackup.Status.FAILED)
        execution.refresh_from_db()
        self.assertEqual(execution.last_error_code, "PROVIDER_NOT_FOUND")

    def test_volume_poll_fails_closed_when_durable_pointer_drifts(self):
        backup, _candidate = self._committed_backup()
        execution = backup.get_execution_state(create=False)
        execution.provider_resource_id = "ocid1.volumebackup.test.drifted"
        execution.save(update_fields=["provider_resource_id", "modified"])
        client = self._volume_client()

        result = OracleVolumeAdapter(self.integration, client=client).poll_backup(
            backup
        )

        self.assertEqual(result, UtilBackup.Status.FAILED)
        execution.refresh_from_db()
        self.assertEqual(
            execution.last_error_code, "PROVIDER_RECONCILIATION_REQUIRED"
        )
        self.assertEqual(
            execution.reconciliation_state,
            CoreBackupExecution.ReconciliationState.REQUIRED,
        )
        self.assertEqual(
            execution.reconciliation_reason, "provider_reconciliation_required"
        )
        self.assertEqual(
            execution.reconciliation_metadata["source"], "provider_outcome"
        )
        self.assertEqual(
            execution.reconciliation_metadata["error_code"],
            "PROVIDER_RECONCILIATION_REQUIRED",
        )
        self.assertEqual(execution.reconciliation_metadata["provider"], "oracle")
        self.assertEqual(
            execution.reconciliation_metadata["resource_id"],
            backup.unique_id,
        )
        client.get_volume_backup.assert_not_called()

    def test_compute_image_create_status_and_delete_use_exact_durable_identity(self):
        _node, integration, backup = self._compute_fixture()
        client = mock.MagicMock()
        client.get_instance.return_value = response(self._compute_source())
        client.list_images.return_value = response([])
        image = self._compute_image(backup.uuid_str)
        client.create_image.return_value = response(image, status=202)
        adapter = OracleComputeAdapter(integration, client=client)

        adapter.create_or_adopt_backup(backup)

        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, image.id)
        execution = backup.get_execution_state(create=False)
        self.assertEqual(execution.provider_resource_id, image.id)
        self.assertEqual(
            client.create_image.call_args.kwargs["opc_retry_token"],
            oracle_retry_token(backup.uuid_str),
        )

        available = model(**{**vars(image), "lifecycle_state": "AVAILABLE"})
        client.get_image.return_value = response(available)
        self.assertEqual(adapter.poll_backup(backup), UtilBackup.Status.COMPLETE)
        client.delete_image.return_value = response(status=204)
        self.assertEqual(
            adapter.delete_backup(backup), UtilBackup.Status.IN_PROGRESS
        )
        client.delete_image.assert_called_once_with(image_id=image.id)
        execution.refresh_from_db()
        self.assertEqual(
            execution.provider_metadata["oracle_delete"]["phase"],
            "delete_accepted",
        )
        self.assertFalse(
            execution.provider_metadata["oracle_delete"]["absence_verified"]
        )

        client.get_image.side_effect = oci.exceptions.ServiceError(
            404, "NotFound", {}, "provider-secret"
        )
        self.assertEqual(adapter.delete_backup(backup), "already_absent")
        client.delete_image.assert_called_once_with(image_id=image.id)
        execution.refresh_from_db()
        self.assertEqual(
            execution.provider_metadata["oracle_delete"]["phase"],
            "absence_verified",
        )

    def test_lost_compute_delete_response_reconciles_without_duplicate(self):
        _node, integration, backup = self._compute_fixture()
        client = mock.MagicMock()
        client.get_instance.return_value = response(self._compute_source())
        client.list_images.return_value = response([])
        image = self._compute_image(backup.uuid_str)
        client.create_image.return_value = response(image, status=202)
        adapter = OracleComputeAdapter(integration, client=client)
        adapter.create_or_adopt_backup(backup)

        client.get_image.return_value = response(
            model(**{**vars(image), "lifecycle_state": "AVAILABLE"})
        )
        client.delete_image.side_effect = oci.exceptions.RequestException(
            "provider-secret-canary"
        )
        with self.assertRaises(OracleProviderError) as raised:
            adapter.delete_backup(backup)
        self.assertEqual(raised.exception.code, "PROVIDER_TRANSIENT_OUTAGE")

        execution = backup.get_execution_state(create=False)
        self.assertEqual(
            execution.provider_metadata["oracle_delete"]["phase"],
            "delete_requested",
        )
        client.get_image.side_effect = oci.exceptions.ServiceError(
            404, "NotFound", {}, "provider-secret"
        )
        self.assertEqual(adapter.delete_backup(backup), "already_absent")
        client.delete_image.assert_called_once_with(image_id=image.id)

    def test_volume_delete_acceptance_waits_for_absence_and_never_replays(self):
        backup, candidate = self._committed_backup()
        client = self._volume_client()
        candidate.lifecycle_state = "AVAILABLE"
        client.get_volume_backup.side_effect = [
            response(candidate),
            response(candidate),
            oci.exceptions.ServiceError(404, "NotFound", {}, "provider-secret"),
        ]
        client.delete_volume_backup.return_value = response(status=202)
        adapter = OracleVolumeAdapter(self.integration, client=client)

        self.assertEqual(
            adapter.delete_backup(backup), UtilBackup.Status.IN_PROGRESS
        )
        self.assertEqual(
            adapter.delete_backup(backup), UtilBackup.Status.IN_PROGRESS
        )
        self.assertEqual(adapter.delete_backup(backup), "already_absent")
        client.delete_volume_backup.assert_called_once_with(
            volume_backup_id=backup.unique_id
        )

    def _delete_pending_backup(self):
        backup = self._backup(marker=f"bs-oracle-delete-{uuid4().hex}")
        backup.unique_id = "ocid1.volumebackup.test.pending"
        backup.status = UtilBackup.Status.DELETE_IN_PROGRESS
        backup.save(update_fields=["unique_id", "status", "modified"])
        return backup

    def test_oracle_delete_task_requeues_async_acceptance_with_durable_lease(self):
        backup = self._delete_pending_backup()
        with mock.patch.object(
            CoreOracleBackup, "soft_delete", return_value=False
        ) as soft_delete, mock.patch.object(
            helper_tasks.reconcile_oracle_backup_deletion, "apply_async"
        ) as schedule:
            helper_tasks.reconcile_oracle_backup_deletion.apply(
                args=[backup.id], task_id="oracle-delete-worker"
            )

        soft_delete.assert_called_once_with(
            enqueue_reconciliation=False,
            execution_owner="oracle-delete-worker",
            execution_token=mock.ANY,
        )
        schedule.assert_called_once_with(args=[backup.id], countdown=120)
        backup.refresh_from_db()
        state = backup.get_execution_state(create=False)
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_IN_PROGRESS)
        self.assertFalse(state.lease_owner)
        self.assertIsNone(state.lease_token)
        self.assertIsNotNone(state.next_retry_at)

    def test_oracle_delete_task_does_not_run_while_another_worker_holds_lease(self):
        backup = self._delete_pending_backup()
        from apps._tasks.integration.oracle import (
            claim_oracle_delete_reconciliation,
            release_oracle_delete_reconciliation,
        )

        claimed = claim_oracle_delete_reconciliation(
            backup, "oracle-delete-owner", lease_seconds=300
        )
        self.assertIsNotNone(claimed)
        with mock.patch.object(CoreOracleBackup, "soft_delete") as soft_delete:
            helper_tasks.reconcile_oracle_backup_deletion.apply(
                args=[backup.id], task_id="oracle-delete-duplicate"
            )
        soft_delete.assert_not_called()
        release_oracle_delete_reconciliation(
            backup, "oracle-delete-owner", claimed[1]
        )

    def test_oracle_delete_beat_sweep_republishes_expired_worker_lease(self):
        backup = self._delete_pending_backup()
        state = backup.get_execution_state(create=True)
        state.lease_owner = "crashed-oracle-worker"
        state.lease_token = uuid4()
        state.lease_expires_at = timezone.now() - timedelta(seconds=1)
        state.save(
            update_fields=[
                "lease_owner",
                "lease_token",
                "lease_expires_at",
                "modified",
            ]
        )

        with mock.patch.object(
            helper_tasks.reconcile_oracle_backup_deletion, "apply_async"
        ) as schedule:
            helper_tasks.reconcile_oracle_backup_deletions.apply()

        schedule.assert_called_once_with(args=[backup.id], countdown=0)

    def test_cloud_poll_delivery_routes_oracle_delete_to_reconciler(self):
        backup = self._delete_pending_backup()
        with mock.patch.object(
            CoreOracleBackup, "_enqueue_delete_reconciliation"
        ) as enqueue, mock.patch.object(CoreOracleBackup, "poll_status") as poll:
            helper_tasks.poll_cloud_backup.apply(
                args=[self.node.id, backup.id], task_id="stale-cloud-poll"
            )

        enqueue.assert_called_once_with()
        poll.assert_not_called()

    def test_cleanup_task_leaves_oracle_delete_in_progress_to_dedicated_reconciler(self):
        backup = self._delete_pending_backup()
        with mock.patch.object(
            CoreOracleBackup, "soft_delete", return_value=False
        ) as soft_delete, mock.patch.object(
            helper_tasks.reconcile_oracle_backup_deletion, "apply_async"
        ) as schedule:
            helper_tasks.clean_delete_failed_backups.apply()

        soft_delete.assert_not_called()
        schedule.assert_not_called()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_IN_PROGRESS)

    def test_node_delete_routes_oracle_delete_in_progress_to_reconciler(self):
        backup = self._delete_pending_backup()
        self.node.status = CoreNode.Status.DELETE_REQUESTED
        self.node.save(update_fields=["status", "modified"])

        class RetrySignal(Exception):
            pass

        with mock.patch.object(
            CoreOracleBackup, "soft_delete"
        ) as soft_delete, mock.patch.object(
            helper_tasks.reconcile_oracle_backup_deletion, "apply_async"
        ) as schedule:
            with self.assertRaises(RetrySignal):
                with mock.patch.object(
                    helper_tasks.node_delete_requested,
                    "retry",
                    side_effect=RetrySignal,
                ):
                    helper_tasks.node_delete_requested.run(self.node.id)

        soft_delete.assert_not_called()
        schedule.assert_called_once_with(args=[backup.id], countdown=0)
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_IN_PROGRESS)

    def test_lost_compute_image_response_adopts_exact_image_without_duplicate(self):
        _node, integration, backup = self._compute_fixture()
        client = mock.MagicMock()
        client.get_instance.return_value = response(self._compute_source())
        image = self._compute_image(backup.uuid_str)
        client.list_images.side_effect = [response([]), response([image])]
        client.create_image.side_effect = oci.exceptions.RequestException(
            "provider-secret-canary"
        )

        OracleComputeAdapter(integration, client=client).create_or_adopt_backup(backup)

        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, image.id)
        client.create_image.assert_called_once()
        execution = backup.get_execution_state(create=False)
        self.assertTrue(execution.provider_metadata["adopted"])
        self.assertNotIn("provider-secret-canary", repr(execution.provider_metadata))

    def test_accepted_compute_image_without_body_reconciles_before_replay(self):
        _node, integration, backup = self._compute_fixture()
        client = mock.MagicMock()
        client.get_instance.return_value = response(self._compute_source())
        image = self._compute_image(backup.uuid_str)
        client.list_images.side_effect = [response([]), response([image])]
        client.create_image.return_value = response(None, status=202)

        OracleComputeAdapter(integration, client=client).create_or_adopt_backup(
            backup
        )

        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, image.id)
        self.assertTrue(
            backup.get_execution_state(create=False).provider_metadata["adopted"]
        )
        client.create_image.assert_called_once()

    def test_compute_restore_launches_new_instance_with_owned_vnic_and_retry_token(self):
        node, integration, backup = self._compute_fixture()
        client = mock.MagicMock()
        client.get_instance.return_value = response(self._compute_source())
        client.list_images.return_value = response([])
        image = self._compute_image(backup.uuid_str)
        client.create_image.return_value = response(image, status=202)
        OracleComputeAdapter(integration, client=client).create_or_adopt_backup(backup)
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["status", "modified"])
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="bs-oracle-compute-restored",
            params={
                "compartment_id": "ocid1.compartment.test.backupsheep",
                "availability_domain": "AD-1",
                "shape": "VM.Standard.E2.1.Micro",
                "subnet_id": "ocid1.subnet.test.backupsheep",
                "assign_public_ip": True,
            },
        )
        token = uuid4()
        restore.lease_owner = "oracle-compute-restore-test"
        restore.lease_token = token
        restore.lease_expires_at = timezone.now() + timedelta(minutes=5)
        restore.save(
            update_fields=["lease_owner", "lease_token", "lease_expires_at", "modified"]
        )
        restore.bind_execution_fence("oracle-compute-restore-test", token)
        client.get_image.return_value = response(
            model(**{**vars(image), "lifecycle_state": "AVAILABLE"})
        )
        client.list_instances.return_value = response([])

        def launch(**_kwargs):
            restore.refresh_from_db()
            witness = restore.params["_bs_oracle_restore"]
            return response(
                model(
                    id="ocid1.instance.test.restored",
                    display_name=restore.name,
                    compartment_id=witness["compartment_id"],
                    availability_domain=witness["availability_domain"],
                    lifecycle_state="PROVISIONING",
                    freeform_tags={
                        ORACLE_RESTORE_TAG: witness["marker"],
                        ORACLE_RESTORE_SOURCE_TAG: image.id,
                        ORACLE_RESTORE_ORIGIN_TAG: integration.unique_id,
                        ORACLE_KIND_TAG: "instance",
                        ORACLE_REQUEST_TAG: witness["request_token"],
                    },
                    source_details=model(image_id=image.id),
                ),
                status=202,
            )

        client.launch_instance.side_effect = launch
        result = OracleRestoreAdapter(
            integration,
            compute_client=client,
        ).restore_snapshot(backup, restore)

        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "ocid1.instance.test.restored")
        kwargs = client.launch_instance.call_args.kwargs
        witness = restore.params["_bs_oracle_restore"]
        self.assertEqual(kwargs["opc_retry_token"], witness["request_token"])
        details = kwargs["launch_instance_details"]
        self.assertEqual(details.source_details.image_id, image.id)
        self.assertEqual(details.create_vnic_details.subnet_id, "ocid1.subnet.test.backupsheep")
        self.assertTrue(details.create_vnic_details.assign_public_ip)
        self.assertEqual(
            details.create_vnic_details.freeform_tags[ORACLE_RESTORE_TAG],
            witness["marker"],
        )

        client.get_instance.return_value = response(
            model(
                id=restore.resource_id,
                display_name=restore.name,
                compartment_id=witness["compartment_id"],
                availability_domain=witness["availability_domain"],
                lifecycle_state="RUNNING",
                freeform_tags={
                    ORACLE_RESTORE_TAG: witness["marker"],
                    ORACLE_RESTORE_SOURCE_TAG: image.id,
                    ORACLE_RESTORE_ORIGIN_TAG: integration.unique_id,
                    ORACLE_KIND_TAG: "instance",
                    ORACLE_REQUEST_TAG: witness["request_token"],
                },
                image_id=image.id,
                source_details=None,
            )
        )
        self.assertEqual(
            OracleRestoreAdapter(
                integration,
                compute_client=client,
            ).check_restore(restore),
            CoreCloudRestore.Status.COMPLETE,
        )
        restore.refresh_from_db()
        self.assertEqual(restore.params["_bs_provider_status"], "RUNNING")

    def test_boot_volume_backup_and_fork_restore_use_current_source_details(self):
        node, integration, backup = self._boot_fixture()
        client = mock.MagicMock()
        source = model(
            id=integration.unique_id,
            display_name=integration.name,
            compartment_id="ocid1.compartment.test.backupsheep",
            availability_domain="AD-1",
            lifecycle_state="AVAILABLE",
            size_in_gbs=50,
            freeform_tags={},
            source_details=model(image_id="ocid1.image.test.base"),
        )
        provider_backup = model(
            id="ocid1.bootvolumebackup.test.one",
            display_name=backup.uuid_str,
            compartment_id="ocid1.compartment.test.backupsheep",
            boot_volume_id=integration.unique_id,
            lifecycle_state="CREATING",
            size_in_gbs=50,
            freeform_tags={
                ORACLE_BACKUP_TAG: backup.uuid_str,
                ORACLE_SOURCE_TAG: integration.unique_id,
                ORACLE_KIND_TAG: "boot",
                ORACLE_REQUEST_TAG: oracle_retry_token(backup.uuid_str),
            },
            source_details=None,
        )
        client.get_boot_volume.return_value = response(source)
        client.list_boot_volume_backups.return_value = response([])
        client.create_boot_volume_backup.return_value = response(
            provider_backup, status=202
        )
        OracleVolumeAdapter(integration, client=client).create_or_adopt_backup(backup)
        details = client.create_boot_volume_backup.call_args.kwargs[
            "create_boot_volume_backup_details"
        ]
        self.assertEqual(details.boot_volume_id, integration.unique_id)
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["status", "modified"])
        provider_backup.lifecycle_state = "AVAILABLE"

        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="bs-oracle-boot-restored",
            params={
                "compartment_id": "ocid1.compartment.test.backupsheep",
                "availability_domain": "AD-1",
            },
        )
        token = uuid4()
        restore.lease_owner = "oracle-boot-restore-test"
        restore.lease_token = token
        restore.lease_expires_at = timezone.now() + timedelta(minutes=5)
        restore.save(
            update_fields=["lease_owner", "lease_token", "lease_expires_at", "modified"]
        )
        restore.bind_execution_fence("oracle-boot-restore-test", token)
        client.get_boot_volume_backup.return_value = response(provider_backup)
        client.list_boot_volumes.return_value = response([])

        def create(**_kwargs):
            restore.refresh_from_db()
            witness = restore.params["_bs_oracle_restore"]
            return response(
                model(
                    id="ocid1.bootvolume.test.restored",
                    display_name=restore.name,
                    compartment_id=witness["compartment_id"],
                    availability_domain=witness["availability_domain"],
                    lifecycle_state="PROVISIONING",
                    freeform_tags={
                        ORACLE_RESTORE_TAG: witness["marker"],
                        ORACLE_RESTORE_SOURCE_TAG: provider_backup.id,
                        ORACLE_RESTORE_ORIGIN_TAG: integration.unique_id,
                        ORACLE_KIND_TAG: "boot_volume",
                        ORACLE_REQUEST_TAG: witness["request_token"],
                    },
                    # OCI boot volumes retain the original image id in
                    # addition to the exact boot-backup source_details id.
                    # Ownership must bind to the latter for this target type.
                    image_id="ocid1.image.test.base",
                    source_details=model(id=provider_backup.id),
                ),
                status=202,
            )

        client.create_boot_volume.side_effect = create
        result = OracleRestoreAdapter(
            integration,
            block_storage_client=client,
        ).restore_snapshot(backup, restore)

        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
        restore_details = client.create_boot_volume.call_args.kwargs[
            "create_boot_volume_details"
        ]
        self.assertEqual(restore_details.source_details.id, provider_backup.id)
        self.assertNotIn(
            "display_name", client.list_boot_volumes.call_args.kwargs
        )
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "ocid1.bootvolume.test.restored")

    def _committed_backup(self):
        backup = self._backup()
        client = self._volume_client()
        candidate = self._backup_resource(backup.uuid_str)
        client.create_volume_backup.return_value = response(candidate, status=202)
        OracleVolumeAdapter(self.integration, client=client).create_or_adopt_backup(
            backup
        )
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["status", "modified"])
        candidate.lifecycle_state = "AVAILABLE"
        return backup, candidate

    @staticmethod
    def _restore_target(restore, backup, *, resource_id="ocid1.volume.test.restore"):
        params = restore.params or {}
        witness = params["_bs_oracle_restore"]
        return model(
            id=resource_id,
            display_name=restore.name,
            compartment_id=witness["compartment_id"],
            availability_domain=witness["availability_domain"],
            lifecycle_state="PROVISIONING",
            freeform_tags={
                ORACLE_RESTORE_TAG: witness["marker"],
                ORACLE_RESTORE_SOURCE_TAG: str(backup.unique_id),
                ORACLE_RESTORE_ORIGIN_TAG: "ocid1.volume.test.source",
                ORACLE_KIND_TAG: "volume",
                ORACLE_REQUEST_TAG: witness["request_token"],
            },
            source_details=model(volume_backup_id=str(backup.unique_id)),
        )

    def _restore(self, backup):
        restore = CoreCloudRestore.objects.create(
            node=self.node,
            backup_id=backup.id,
            name="bs-oracle-restored-volume",
            params={
                "compartment_id": "ocid1.compartment.test.backupsheep",
                "availability_domain": "AD-1",
            },
        )
        token = uuid4()
        restore.lease_owner = "oracle-restore-test"
        restore.lease_token = token
        restore.lease_expires_at = timezone.now() + timedelta(minutes=5)
        restore.save(
            update_fields=[
                "lease_owner",
                "lease_token",
                "lease_expires_at",
                "modified",
            ]
        )
        restore.bind_execution_fence("oracle-restore-test", token)
        return restore

    def test_restore_create_persists_pointer_and_native_retry_token(self):
        backup, source_backup = self._committed_backup()
        restore = self._restore(backup)
        client = self._volume_client()
        client.get_volume_backup.return_value = response(source_backup)
        client.list_volumes.return_value = response([])

        def create(**_kwargs):
            restore.refresh_from_db()
            return response(self._restore_target(restore, backup), status=202)

        client.create_volume.side_effect = create
        result = OracleRestoreAdapter(
            self.integration, block_storage_client=client
        ).restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.resource_id, "ocid1.volume.test.restore")
        self.assertEqual(restore.operation_phase, restore.OperationPhase.POLLING)
        witness = restore.params["_bs_oracle_restore"]
        self.assertEqual(
            client.create_volume.call_args.kwargs["opc_retry_token"],
            witness["request_token"],
        )
        details = client.create_volume.call_args.kwargs["create_volume_details"]
        self.assertEqual(details.source_details.id, str(backup.unique_id))
        self.assertIsNone(details.volume_backup_id)
        self.assertFalse(restore.params["_bs_create_outcome_unknown"])

    def test_restore_lost_response_is_adopted_on_redelivery_without_second_create(self):
        backup, source_backup = self._committed_backup()
        restore = self._restore(backup)
        client = self._volume_client()
        client.get_volume_backup.return_value = response(source_backup)
        client.list_volumes.return_value = response([])
        client.create_volume.side_effect = oci.exceptions.RequestException(
            "provider-secret-canary"
        )
        adapter = OracleRestoreAdapter(
            self.integration, block_storage_client=client
        )

        first = adapter.restore_snapshot(backup, restore)
        restore.refresh_from_db()
        self.assertEqual(first, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertTrue(restore.params["_bs_create_outcome_unknown"])
        self.assertIsNone(restore.resource_id)

        candidate = self._restore_target(restore, backup)
        client.list_volumes.return_value = response([candidate])
        restore.bind_execution_fence("oracle-restore-test", restore.lease_token)
        second = adapter.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(second, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.resource_id, candidate.id)
        client.create_volume.assert_called_once()
        self.assertNotIn("provider-secret-canary", restore.error or "")

    def test_restore_replays_same_native_token_when_unknown_target_is_not_visible(self):
        backup, source_backup = self._committed_backup()
        restore = self._restore(backup)
        client = self._volume_client()
        client.get_volume_backup.return_value = response(source_backup)
        client.list_volumes.return_value = response([])
        client.create_volume.side_effect = oci.exceptions.RequestException(
            "provider-secret-canary"
        )
        adapter = OracleRestoreAdapter(
            self.integration, block_storage_client=client
        )

        self.assertEqual(
            adapter.restore_snapshot(backup, restore),
            CoreCloudRestore.Status.IN_PROGRESS,
        )
        first_token = client.create_volume.call_args.kwargs["opc_retry_token"]
        restore.refresh_from_db()
        restore.bind_execution_fence("oracle-restore-test", restore.lease_token)

        def replay(**_kwargs):
            restore.refresh_from_db()
            return response(self._restore_target(restore, backup), status=202)

        client.create_volume.side_effect = replay
        self.assertEqual(
            adapter.restore_snapshot(backup, restore),
            CoreCloudRestore.Status.IN_PROGRESS,
        )

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "ocid1.volume.test.restore")
        self.assertEqual(client.create_volume.call_count, 2)
        self.assertEqual(
            client.create_volume.call_args.kwargs["opc_retry_token"], first_token
        )

    def test_restore_source_transient_is_retryable_without_false_unknown_mutation(self):
        backup, source_backup = self._committed_backup()
        restore = self._restore(backup)
        client = self._volume_client()
        client.get_volume_backup.side_effect = [
            oci.exceptions.ServiceError(
                503, "ServiceUnavailable", {}, "provider-secret-canary"
            ),
            response(source_backup),
        ]
        client.list_volumes.return_value = response([])

        adapter = OracleRestoreAdapter(
            self.integration, block_storage_client=client
        )
        first = adapter.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(first, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertFalse(restore.params["_bs_create_outcome_unknown"])
        self.assertNotIn("_bs_mutation_started_at", restore.params)
        self.assertEqual(
            restore.params["_bs_last_error_category"], "retryable_preflight"
        )
        client.create_volume.assert_not_called()

        def create(**_kwargs):
            restore.refresh_from_db()
            return response(self._restore_target(restore, backup), status=202)

        client.create_volume.side_effect = create
        restore.bind_execution_fence("oracle-restore-test", restore.lease_token)
        second = adapter.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(second, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.resource_id, "ocid1.volume.test.restore")
        client.create_volume.assert_called_once()

    def test_restore_duplicate_matches_fail_manual_review_without_create(self):
        backup, source_backup = self._committed_backup()
        restore = self._restore(backup)
        client = self._volume_client()
        client.get_volume_backup.return_value = response(source_backup)

        def listing(**_kwargs):
            restore.refresh_from_db()
            first = self._restore_target(restore, backup, resource_id="one")
            second = self._restore_target(restore, backup, resource_id="two")
            return response([first, second])

        client.list_volumes.side_effect = listing
        result = OracleRestoreAdapter(
            self.integration, block_storage_client=client
        ).restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(result, CoreCloudRestore.Status.FAILED)
        self.assertEqual(restore.operation_phase, restore.OperationPhase.MANUAL_REVIEW)
        self.assertEqual(restore.last_error_code, "PROVIDER_DUPLICATE_MATCH")
        client.create_volume.assert_not_called()

    def test_restore_poll_404_is_bounded_reconciliation_not_false_progress(self):
        backup, source_backup = self._committed_backup()
        restore = self._restore(backup)
        client = self._volume_client()
        client.get_volume_backup.return_value = response(source_backup)
        client.list_volumes.return_value = response([])

        def create(**_kwargs):
            restore.refresh_from_db()
            return response(self._restore_target(restore, backup), status=202)

        client.create_volume.side_effect = create
        adapter = OracleRestoreAdapter(
            self.integration, block_storage_client=client
        )
        adapter.restore_snapshot(backup, restore)
        client.get_volume.side_effect = oci.exceptions.ServiceError(
            404, "NotFound", {}, "provider-secret-canary"
        )
        restore.refresh_from_db()
        restore.bind_execution_fence("oracle-restore-test", restore.lease_token)

        result = adapter.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.operation_phase, restore.OperationPhase.RECONCILING)
        reconciliation = restore.params["_bs_restore_reconciliation"]
        self.assertEqual(reconciliation["missing_target_observations"], 1)
        self.assertNotIn("provider-secret-canary", restore.error)

    def test_discovery_lists_compute_and_volume_resources_without_sdk_auto_pagination(self):
        auth = SimpleNamespace(
            tenancy="ocid1.tenancy.test.backupsheep",
            get_client=lambda: {"region": "us-chicago-1"},
            get_verified_client=lambda: {"region": "us-chicago-1"},
        )
        identity = mock.MagicMock()
        identity.list_compartments.return_value = response(
            [
                model(
                    id="ocid1.compartment.test.child",
                    lifecycle_state="ACTIVE",
                )
            ]
        )
        compute = mock.MagicMock()
        compute.list_instances.side_effect = [
            response([]),
            response(
                [
                    model(
                        id="ocid1.instance.test.one",
                        display_name="server-one",
                        lifecycle_state="RUNNING",
                        availability_domain="AD-1",
                        shape="VM.Standard.E2.1.Micro",
                        compartment_id="ocid1.compartment.test.child",
                        freeform_tags={},
                        source_details=None,
                    )
                ]
            ),
        ]
        block = mock.MagicMock()

        objects = discover_oracle_objects(
            auth,
            "cloud",
            identity_client=identity,
            compute_client=compute,
            block_storage_client=block,
        )

        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0]["_bs_unique_id"], "ocid1.instance.test.one")
        self.assertEqual(compute.list_instances.call_count, 2)
        for call in compute.list_instances.call_args_list:
            self.assertIn("limit", call.kwargs)
            self.assertNotIn("page", call.kwargs)

    def test_exact_discovery_uses_direct_ocid_get_and_tenancy_compartment_proof(self):
        auth = SimpleNamespace(
            tenancy="ocid1.tenancy.test.backupsheep",
            get_client=lambda: {"region": "us-chicago-1"},
            get_verified_client=lambda: {"region": "us-chicago-1"},
        )
        identity = mock.MagicMock()
        identity.list_compartments.return_value = response(
            [
                model(
                    id="ocid1.compartment.test.child",
                    lifecycle_state="ACTIVE",
                )
            ]
        )
        compute = mock.MagicMock()
        compute.get_instance.return_value = response(
            model(
                id="ocid1.instance.test.one",
                display_name="server-one",
                lifecycle_state="RUNNING",
                availability_domain="AD-1",
                shape="VM.Standard.E2.1.Micro",
                compartment_id="ocid1.compartment.test.child",
                freeform_tags={},
                source_details=None,
            )
        )

        item = discover_exact_oracle_object(
            auth,
            "cloud",
            "ocid1.instance.test.one",
            identity_client=identity,
            compute_client=compute,
        )

        self.assertEqual(item["_bs_unique_id"], "ocid1.instance.test.one")
        compute.get_instance.assert_called_once_with(
            instance_id="ocid1.instance.test.one"
        )
        compute.list_instances.assert_not_called()

        compute.get_instance.return_value = response(
            model(
                id="ocid1.instance.test.foreign",
                display_name="foreign-server",
                lifecycle_state="RUNNING",
                availability_domain="AD-1",
                shape="VM.Standard.E2.1.Micro",
                compartment_id="ocid1.compartment.test.foreign",
                freeform_tags={},
                source_details=None,
            )
        )
        with self.assertRaises(OracleProviderError) as raised:
            discover_exact_oracle_object(
                auth,
                "cloud",
                "ocid1.instance.test.foreign",
                identity_client=identity,
                compute_client=compute,
            )
        self.assertEqual(
            raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH"
        )

    def test_oracle_link_serializers_replace_untrusted_fields_with_provider_data(self):
        cases = (
            (
                CoreCloudOracleWriteSerializer,
                "cloud",
                "ocid1.instance.test.ui",
                {
                    "id": "ocid1.instance.test.ui",
                    "_bs_unique_id": "ocid1.instance.test.ui",
                    "_bs_name": "provider-server",
                    "_bs_resource_type": "cloud",
                    "_bs_compartment_id": "ocid1.compartment.test.backupsheep",
                    "_bs_availability_domain": "AD-1",
                    "_bs_lifecycle_state": "RUNNING",
                    "_bs_region": "AD-1",
                    "_bs_shape": "VM.Standard.E2.1.Micro",
                    "_bs_size": None,
                },
            ),
            (
                CoreVolumeOracleWriteSerializer,
                "volume",
                "ocid1.volume.test.ui",
                {
                    "id": "ocid1.volume.test.ui",
                    "_bs_unique_id": "ocid1.volume.test.ui",
                    "_bs_name": "provider-volume",
                    "_bs_resource_type": "volume",
                    "_bs_compartment_id": "ocid1.compartment.test.backupsheep",
                    "_bs_availability_domain": "AD-1",
                    "_bs_lifecycle_state": "AVAILABLE",
                    "_bs_region": "AD-1",
                    "_bs_vol_type": "block",
                    "_bs_size": 50,
                },
            ),
        )
        for serializer_class, object_type, resource_id, provider in cases:
            with self.subTest(object_type=object_type), mock.patch(
                f"{serializer_class.__module__}.discover_exact_oracle_object",
                return_value=provider,
            ) as discovery:
                data = {
                    "node": {
                        "connection": self.connection,
                        "name": "untrusted-node-name",
                    },
                    "unique_id": resource_id,
                    "name": "untrusted-name",
                    "metadata": {"untrusted": True},
                }

                validated = serializer_class().validate(data)

                discovery.assert_called_once_with(
                    self.connection.auth_oracle, object_type, resource_id
                )
                self.assertEqual(validated["unique_id"], provider["_bs_unique_id"])
                self.assertEqual(validated["name"], provider["_bs_name"])
                self.assertEqual(validated["node"]["name"], provider["_bs_name"])
                self.assertEqual(validated["metadata"], provider)

    def test_oracle_link_serializers_reject_a_non_oracle_connection(self):
        connection = factories.make_connection(
            self.account, self.member, code="digitalocean"
        )
        for serializer_class, resource_id in (
            (CoreCloudOracleWriteSerializer, "ocid1.instance.test.ui"),
            (CoreVolumeOracleWriteSerializer, "ocid1.volume.test.ui"),
        ):
            with self.subTest(serializer=serializer_class.__name__):
                with self.assertRaises(serializers.ValidationError):
                    serializer_class().validate(
                        {
                            "node": {"connection": connection},
                            "unique_id": resource_id,
                        }
                    )

    def test_oracle_link_serializers_reject_account_wide_duplicate_ids(self):
        other_connection = factories.make_connection(
            self.account, self.member, code="oracle", name="Oracle duplicate connection"
        )
        cases = (
            (
                CoreCloudOracleWriteSerializer,
                CoreNode.Type.CLOUD,
                "ocid1.instance.test.account-duplicate",
                "This Oracle Cloud server is already linked.",
                "cloud",
            ),
            (
                CoreVolumeOracleWriteSerializer,
                CoreNode.Type.VOLUME,
                "ocid1.volume.test.account-duplicate",
                "This Oracle Cloud volume is already linked.",
                "volume",
            ),
        )
        for serializer_class, node_type, resource_id, message, object_type in cases:
            with self.subTest(object_type=object_type):
                duplicate_node = CoreNode.objects.create(
                    connection=other_connection,
                    type=node_type,
                    name=f"duplicate-{object_type}",
                    added_by=self.member,
                )
                CoreOracle.objects.create(
                    node=duplicate_node,
                    name=f"duplicate-{object_type}",
                    unique_id=resource_id,
                    metadata={"_bs_resource_type": object_type},
                )
                provider = {
                    "_bs_unique_id": resource_id,
                    "_bs_name": f"provider-{object_type}",
                    "_bs_resource_type": object_type,
                }
                with mock.patch(
                    f"{serializer_class.__module__}.discover_exact_oracle_object",
                    return_value=provider,
                ):
                    with self.assertRaises(serializers.ValidationError) as raised:
                        serializer_class().validate(
                            {
                                "node": {"connection": self.connection},
                                "unique_id": resource_id,
                            }
                        )
                self.assertIn(message, str(raised.exception))


class OracleSerializerConcurrencyTests(TransactionTestCase):
    """Account locking elects one Oracle resource link across connections."""

    def setUp(self):
        super().setUp()
        CoreIntegration.objects.get_or_create(
            code="oracle",
            defaults={"name": "Oracle Cloud", "type": CoreIntegration.Type.CLOUD},
        )

    def test_cloud_and_volume_creates_are_account_wide_and_concurrency_safe(self):
        account, member, _user = factories.make_account()
        connections = [
            factories.make_connection(
                account, member, code="oracle", name=f"Oracle race {index}"
            )
            for index in (1, 2)
        ]
        cases = (
            (CoreCloudOracleWriteSerializer, CoreNode.Type.CLOUD, "cloud"),
            (CoreVolumeOracleWriteSerializer, CoreNode.Type.VOLUME, "volume"),
        )

        for serializer_class, node_type, object_type in cases:
            resource_id = f"ocid1.{object_type}.test.concurrent"
            barrier = Barrier(2)
            results = []
            errors = []

            def create_link(connection_id, index):
                close_old_connections()
                try:
                    connection = CoreConnection.objects.get(pk=connection_id)
                    barrier.wait(timeout=10)
                    serializer_class().create(
                        {
                            "node": {
                                "connection": connection,
                                "type": node_type,
                                "name": f"race-{object_type}-{index}",
                            },
                            "unique_id": resource_id,
                            "name": f"race-{object_type}",
                            "metadata": {"_bs_resource_type": object_type},
                        }
                    )
                    results.append("created")
                except serializers.ValidationError:
                    results.append("duplicate")
                except Exception as error:
                    errors.append(error)
                finally:
                    close_old_connections()

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(create_link, connection.id, index)
                    for index, connection in enumerate(connections, start=1)
                ]
                for future in futures:
                    future.result(timeout=30)

            self.assertFalse(errors, errors)
            self.assertEqual(results.count("created"), 1)
            self.assertEqual(results.count("duplicate"), 1)
            self.assertEqual(
                CoreOracle.objects.filter(
                    node__connection__account=account,
                    node__connection__integration__code="oracle",
                    unique_id=resource_id,
                ).count(),
                1,
            )


class OracleDeleteCleanupRoutingConcurrencyTests(TransactionTestCase):
    """The legacy cleaner and Oracle reconciler must have disjoint ownership."""

    def setUp(self):
        super().setUp()
        CoreIntegration.objects.get_or_create(
            code="oracle",
            defaults={"name": "Oracle Cloud", "type": CoreIntegration.Type.CLOUD},
        )
        account, member, _user = factories.make_account()
        connection = factories.make_connection(
            account, member, code="oracle", name="Oracle cleanup race"
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.VOLUME,
            name="oracle-cleanup-race-node",
            added_by=member,
        )
        integration = CoreOracle.objects.create(
            node=node,
            name="oracle-cleanup-race-node",
            unique_id="ocid1.volume.test.cleanup-race-source",
            metadata={"_bs_vol_type": "block"},
        )
        self.backup = integration.backups.create(
            uuid=f"bs-oracle-cleanup-race-{uuid4().hex}",
            unique_id="ocid1.volumebackup.test.cleanup-race",
            status=UtilBackup.Status.DELETE_IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
            celery_task_id=f"task-{uuid4().hex}",
        )
        state = self.backup.get_execution_state(create=True)
        state.lease_owner = "crashed-oracle-worker"
        state.lease_token = uuid4()
        state.lease_expires_at = timezone.now() - timedelta(seconds=1)
        state.save(
            update_fields=[
                "lease_owner",
                "lease_token",
                "lease_expires_at",
                "modified",
            ]
        )

    @staticmethod
    def _run_task(task):
        close_old_connections()
        try:
            task.apply()
        finally:
            close_old_connections()

    def test_cleanup_and_beat_sweep_cannot_call_unfenced_soft_delete_concurrently(self):
        with mock.patch.object(
            CoreOracleBackup, "soft_delete"
        ) as soft_delete, mock.patch.object(
            helper_tasks.reconcile_oracle_backup_deletion, "apply_async"
        ) as schedule:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(
                        self._run_task, helper_tasks.clean_delete_failed_backups
                    ),
                    executor.submit(
                        self._run_task,
                        helper_tasks.reconcile_oracle_backup_deletions,
                    ),
                ]
                for future in futures:
                    future.result(timeout=30)

        soft_delete.assert_not_called()
        schedule.assert_called_once_with(args=[self.backup.pk], countdown=0)
        self.backup.refresh_from_db()
        self.assertEqual(
            self.backup.status, UtilBackup.Status.DELETE_IN_PROGRESS
        )

    def test_initial_api_delete_and_reconciler_cannot_regress_absence_checkpoint(self):
        backup = self.backup
        backup.status = UtilBackup.Status.DELETE_REQUESTED
        backup.save(update_fields=["status", "modified"])
        witness = OracleBackupWitness(
            marker=backup.uuid_str,
            source_id="ocid1.volume.test.cleanup-race-source",
            volume_type="block",
            compartment_id="ocid1.compartment.test",
            request_token=oracle_retry_token(backup.uuid_str),
        )
        execution = backup.get_execution_state(create=False)
        execution.provider_resource_id = backup.unique_id
        execution.provider_idempotency_key = witness.request_token
        execution.provider_metadata = {"witness": witness.as_dict()}
        execution.lease_owner = ""
        execution.lease_token = None
        execution.lease_expires_at = None
        execution.next_retry_at = None
        execution.save()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_REQUESTED)
        execution.refresh_from_db()
        self.assertFalse(execution.lease_is_active())
        self.assertIsNone(execution.next_retry_at)
        self.assertEqual(
            backup.status, UtilBackup.Status.DELETE_REQUESTED
        )

        api_entered = Event()
        api_release = Event()
        errors = []
        calls = []

        def api_delete(claimed):
            calls.append(
                (
                    "api",
                    getattr(claimed, "_required_backup_lease_owner", ""),
                    getattr(claimed, "_required_backup_lease_token", ""),
                )
            )
            try:
                _persist_oracle_delete_state(
                    claimed,
                    {
                        "phase": "delete_accepted",
                        "delete_started": True,
                        "delete_completed": False,
                        "absence_verified": False,
                        "ownership_verified": True,
                    },
                    witness,
                    claimed.unique_id,
                )
            except Exception as error:
                errors.append(error)
                raise
            api_entered.set()
            if not api_release.wait(timeout=10):
                raise AssertionError("API delete test worker was not released")
            return UtilBackup.Status.IN_PROGRESS

        def reconciler_delete(claimed):
            calls.append(
                (
                    "reconciler",
                    getattr(claimed, "_required_backup_lease_owner", ""),
                    getattr(claimed, "_required_backup_lease_token", ""),
                )
            )
            current = claimed.get_execution_state(create=False)
            delete_state = dict(
                (current.provider_metadata or {}).get("oracle_delete") or {}
            )
            _oracle_delete_absence(
                claimed, delete_state, witness, claimed.unique_id
            )
            return "already_absent"

        adapter = mock.Mock()

        def dispatch_delete(claimed):
            return (
                api_delete(claimed)
                if len(calls) == 0
                else reconciler_delete(claimed)
            )

        adapter.delete_backup.side_effect = dispatch_delete

        def run_api_delete():
            close_old_connections()
            try:
                results = CoreOracleBackup.objects.get(pk=backup.pk).soft_delete()
                return results
            except Exception as error:
                errors.append(error)
                raise
            finally:
                close_old_connections()

        with mock.patch(
            "apps._tasks.integration.oracle.oracle_backup_adapter",
            return_value=adapter,
        ), mock.patch.object(
            CoreOracleBackup, "_enqueue_delete_reconciliation"
        ) as enqueue:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(run_api_delete)
                if not api_entered.wait(timeout=10):
                    future.result(timeout=30)
                    self.fail("API delete did not reach the adapter")

                # The API has committed its initial lease and is blocked inside
                # the adapter. A concurrent reconciler must be a read-only no-op.
                helper_tasks.reconcile_oracle_backup_deletion.apply(
                    args=[backup.pk], task_id="oracle-reconciler-race"
                )
                self.assertEqual(len(calls), 1)
                api_release.set()
                self.assertFalse(future.result(timeout=30))

            backup.refresh_from_db()
            self.assertFalse(errors, errors)
            self.assertEqual(backup.status, UtilBackup.Status.DELETE_IN_PROGRESS)
            execution = backup.get_execution_state(create=False)
            self.assertEqual(
                execution.provider_metadata["oracle_delete"]["phase"],
                "delete_accepted",
            )
            self.assertFalse(
                execution.provider_metadata["oracle_delete"]["absence_verified"]
            )
            self.assertFalse(execution.lease_owner)
            self.assertIsNone(execution.lease_token)
            enqueue.assert_called_once_with()

            # The next fenced reconciliation proves absence and completes the row.
            helper_tasks.reconcile_oracle_backup_deletion.apply(
                args=[backup.pk], task_id="oracle-reconciler-absence"
            )

        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], "api")
        self.assertEqual(calls[1][0], "reconciler")
        self.assertTrue(calls[0][1] and calls[0][2])
        self.assertTrue(calls[1][1] and calls[1][2])
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_COMPLETED)
        execution = backup.get_execution_state(create=False)
        self.assertEqual(
            execution.provider_metadata["oracle_delete"]["phase"],
            "absence_verified",
        )
        self.assertTrue(
            execution.provider_metadata["oracle_delete"]["absence_verified"]
        )
        self.assertFalse(execution.lease_owner)
        self.assertIsNone(execution.lease_token)

        stale = CoreOracleBackup.objects.get(pk=backup.pk)
        stale.bind_execution_fence(calls[0][1], calls[0][2])
        with self.assertRaises(OracleProviderError) as raised:
            _persist_oracle_delete_state(
                stale,
                {"phase": "delete_reconciling", "delete_started": True},
                witness,
                stale.unique_id,
            )
        self.assertEqual(raised.exception.code, "WORKER_LEASE_LOST")
        execution.refresh_from_db()
        self.assertEqual(
            execution.provider_metadata["oracle_delete"]["phase"],
            "absence_verified",
        )
