"""Offline UpCloud backup and storage reliability acceptance tests."""

from unittest import mock

import requests as raw_requests
from django.test import SimpleTestCase
from rest_framework.test import APIClient

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.integration.storage.upcloud import (
    _s3_client,
    normalize_upcloud_endpoint,
)
from apps._tasks.integration.upcloud import (
    backup_upcloud,
    classify_upcloud_response,
    create_upcloud_snapshot,
    list_upcloud_storages,
)
from apps.api.v1.storage.upcloud.serializers import (
    CoreStorageUpCloudWriteSerializer,
)
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.api.v1.utils.http import request_timeout
from apps.console.backup.models import CoreBackupExecution
from apps.console.connection.models import CoreAuthUpCloud, CoreIntegration
from apps.console.node.models import CoreNode, CoreUpCloud, _BackupProviderError
from apps.console.setting.models import CoreSiteSettings
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


class Response:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers = headers or {}

    def json(self):
        return self._payload


def storage(
    resource_id,
    *,
    storage_type="normal",
    title="storage",
    origin=None,
    zone="us-chi1",
    state="online",
):
    value = {
        "uuid": resource_id,
        "type": storage_type,
        "title": title,
        "zone": zone,
        "state": state,
        "size": 10,
    }
    if origin is not None:
        value["origin"] = origin
    return value


def page(items):
    return {"storages": {"storage": items}}


class UpCloudEnterpriseReliabilityTests(BaseTestCase):
    def _backup(self):
        CoreIntegration.objects.get_or_create(
            code="upcloud",
            defaults={"type": CoreIntegration.Type.CLOUD, "enabled": True},
        )
        connection = factories.make_connection(
            self.account, self.member, code="upcloud"
        )
        CoreAuthUpCloud.objects.create(
            connection=connection,
            username=bs_encrypt(
                "test-user", self.account.get_encryption_key()
            ),
            password=bs_encrypt(
                "test-password", self.account.get_encryption_key()
            ),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.VOLUME,
            name="upcloud-source",
            added_by=self.member,
        )
        integration = CoreUpCloud.objects.create(
            node=node,
            name="upcloud-source",
            unique_id="source-1",
            metadata={"_bs_zone": "us-chi1"},
        )
        backup = integration.backups.create(
            uuid="upcloud-enterprise-backup-1",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
            celery_task_id="task-upcloud-enterprise",
        )
        return integration, backup

    def test_offset_inventory_is_complete_bounded_and_timed(self):
        responses = [
            Response(
                200,
                page(
                    [
                        storage("normal-1"),
                        storage("normal-2"),
                    ]
                ),
                {"Upcloud-Total-Count": "3"},
            ),
            Response(
                200,
                page([storage("normal-3")]),
                {"upcloud-total-count": "3"},
            ),
        ]
        stats = {}
        with mock.patch(
            "apps._tasks.integration.upcloud.requests.get",
            side_effect=responses,
        ) as get:
            result = list_upcloud_storages(
                object(),
                storage_type="normal",
                stats=stats,
                page_limit=2,
            )

        self.assertEqual([item["uuid"] for item in result], [
            "normal-1",
            "normal-2",
            "normal-3",
        ])
        self.assertEqual(
            [call.kwargs["params"]["offset"] for call in get.call_args_list],
            [0, 2],
        )
        self.assertTrue(
            all(
                call.kwargs["timeout"] == request_timeout()
                for call in get.call_args_list
            )
        )
        self.assertEqual(
            stats,
            {
                "page_count": 2,
                "item_count": 3,
                "last_offset": 2,
                "scan_complete": True,
            },
        )

    def test_celery_task_routes_create_through_upcloud_adapter(self):
        integration, backup = self._backup()
        with mock.patch.object(
            CoreNode, "backup_initiate", return_value=backup
        ), mock.patch.object(
            CoreNode, "validate", return_value=True
        ), mock.patch.object(
            integration.node.connection.__class__,
            "validate",
            return_value=True,
        ), mock.patch(
            "apps._tasks.helper.tasks.run_provider_create",
            return_value=backup,
        ) as run_create, mock.patch(
            "apps._tasks.helper.tasks.poll_cloud_backup.apply_async"
        ) as poll:
            backup_upcloud.apply(
                kwargs={"node_id": integration.node_id},
                task_id="upcloud-task-route-test",
            ).get(propagate=True)

        run_create.assert_called_once()
        self.assertEqual(run_create.call_args.args[:2], (
            backup,
            "upcloud-task-route-test",
        ))
        self.assertIs(run_create.call_args.args[2], create_upcloud_snapshot)
        poll.assert_called_once_with(
            args=[integration.node_id, backup.id], countdown=60
        )

    def test_ui_discovery_without_object_type_uses_complete_scanner(self):
        integration, _backup = self._backup()
        site_settings = CoreSiteSettings.load()
        site_settings.setup_completed = True
        site_settings.save()
        OnboardingMiddleware._completed = False
        client = APIClient()
        client.force_authenticate(user=self.user)
        discovered = {
            "uuid": "server-ui-1",
            "title": "UI server source",
            "zone": "fi-hel1",
            "state": "started",
        }
        with mock.patch(
            "apps.api.v1.connection.upcloud.views.list_upcloud_servers",
            return_value=[discovered],
        ) as scanner, mock.patch(
            "apps.api.v1.connection.upcloud.views.list_upcloud_storages"
        ) as volume_scanner, mock.patch.object(
            CoreAuthUpCloud, "get_verified_client", return_value=object()
        ) as verifier:
            response = client.get(
                f"/api/v1/connections/upcloud/{integration.node.connection_id}/objects/"
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["_bs_unique_id"], "server-ui-1")
        self.assertEqual(response.json()[0]["_bs_name"], "UI server source")
        self.assertEqual(response.json()[0]["_bs_region"], "fi-hel1")
        self.assertEqual(response.json()[0]["_bs_resource_type"], "cloud")
        scanner.assert_called_once_with(mock.ANY)
        verifier.assert_called_once()
        volume_scanner.assert_not_called()

    def test_ui_discovery_never_returns_provider_exception_text(self):
        integration, _backup = self._backup()
        site_settings = CoreSiteSettings.load()
        site_settings.setup_completed = True
        site_settings.save()
        OnboardingMiddleware._completed = False
        client = APIClient()
        client.force_authenticate(user=self.user)
        with mock.patch.object(
            CoreAuthUpCloud, "get_verified_client", return_value=object()
        ), mock.patch(
            "apps.api.v1.connection.upcloud.views.list_upcloud_servers",
            side_effect=RuntimeError("provider-secret-canary"),
        ):
            response = client.get(
                f"/api/v1/connections/upcloud/{integration.node.connection_id}/objects/"
            )

        self.assertGreaterEqual(response.status_code, 400)
        self.assertNotIn("provider-secret-canary", response.content.decode())
        self.assertIn("CONNECTION_VALIDATION_FAILED", response.content.decode())

    def test_repeated_or_over_bound_inventory_fails_closed(self):
        repeated = Response(
            200,
            page([storage("normal-1"), storage("normal-2")]),
        )
        with mock.patch(
            "apps._tasks.integration.upcloud.requests.get",
            side_effect=[repeated, repeated],
        ):
            with self.assertRaises(_BackupProviderError) as raised:
                list_upcloud_storages(
                    object(),
                    storage_type="normal",
                    page_limit=2,
                    max_pages=2,
                )
        self.assertEqual(raised.exception.code, "PROVIDER_MALFORMED_RESPONSE")
        self.assertTrue(raised.exception.manual_review)

        with mock.patch(
            "apps._tasks.integration.upcloud.requests.get",
            return_value=Response(
                200,
                page([storage("normal-1"), storage("normal-2")]),
            ),
        ):
            with self.assertRaises(_BackupProviderError) as raised:
                list_upcloud_storages(
                    object(),
                    storage_type="normal",
                    page_limit=2,
                    max_pages=1,
                )
        self.assertEqual(
            raised.exception.code, "PROVIDER_RECONCILIATION_REQUIRED"
        )

    def test_lost_create_response_is_adopted_without_duplicate_post(self):
        integration, backup = self._backup()
        source = Response(200, {"storage": storage("source-1")})
        empty = Response(200, page([]))
        auth_type = integration.node.connection.auth_upcloud.__class__

        with mock.patch.object(
            auth_type, "get_verified_client", return_value=object()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get",
            side_effect=[source, empty],
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post",
            side_effect=raw_requests.Timeout("provider-secret-canary"),
        ):
            with self.assertRaises(NodeBackupFailedError):
                create_upcloud_snapshot(backup)

        backup.refresh_from_db()
        execution = backup.get_execution_state()
        self.assertEqual(execution.last_error_code, "PROVIDER_TIMEOUT")
        self.assertEqual(
            execution.reconciliation_state,
            CoreBackupExecution.ReconciliationState.REQUIRED,
        )
        self.assertTrue(execution.provider_metadata["create_attempted"])
        self.assertTrue(execution.provider_metadata["outcome_unknown"])
        self.assertNotIn("provider-secret-canary", str(execution.provider_metadata))

        adopted = storage(
            "backup-1",
            storage_type="backup",
            title=backup.uuid_str,
            origin="source-1",
            state="backuping",
        )
        with mock.patch.object(
            auth_type, "get_verified_client", return_value=object()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get",
            side_effect=[source, Response(200, page([adopted]))],
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post"
        ) as post:
            create_upcloud_snapshot(backup)

        post.assert_not_called()
        backup.refresh_from_db()
        execution = backup.get_execution_state()
        self.assertEqual(backup.unique_id, "backup-1")
        self.assertEqual(execution.provider_resource_id, "backup-1")
        self.assertEqual(
            execution.reconciliation_state,
            CoreBackupExecution.ReconciliationState.RESOLVED,
        )
        self.assertFalse(execution.provider_metadata["outcome_unknown"])

    def test_duplicate_or_foreign_marker_never_reaches_create(self):
        for resources, expected in (
            (
                [
                    storage(
                        "backup-1",
                        storage_type="backup",
                        title="upcloud-enterprise-backup-1",
                        origin="source-1",
                    ),
                    storage(
                        "backup-2",
                        storage_type="backup",
                        title="upcloud-enterprise-backup-1",
                        origin="source-1",
                    ),
                ],
                "PROVIDER_DUPLICATE_MATCH",
            ),
            (
                [
                    storage(
                        "backup-foreign",
                        storage_type="backup",
                        title="upcloud-enterprise-backup-1",
                        origin="foreign-source",
                    )
                ],
                "PROVIDER_OWNERSHIP_MISMATCH",
            ),
        ):
            with self.subTest(expected=expected):
                integration, backup = self._backup()
                auth_type = integration.node.connection.auth_upcloud.__class__
                responses = [
                    Response(200, {"storage": storage("source-1")}),
                    Response(200, page(resources)),
                ]
                with mock.patch.object(
                    auth_type, "get_verified_client", return_value=object()
                ), mock.patch(
                    "apps._tasks.integration.upcloud.requests.get",
                    side_effect=responses,
                ), mock.patch(
                    "apps._tasks.integration.upcloud.requests.post"
                ) as post:
                    with self.assertRaises(NodeBackupFailedError):
                        create_upcloud_snapshot(backup)
                post.assert_not_called()
                backup.refresh_from_db()
                self.assertEqual(
                    backup.get_execution_state().last_error_code, expected
                )

    def test_unknown_zero_match_retries_are_bounded_without_second_post(self):
        integration, backup = self._backup()
        state = backup.get_execution_state(create=True)
        state.provider_metadata = {
            "create_attempted": True,
            "outcome_unknown": True,
        }
        state.save(update_fields=["provider_metadata", "modified"])
        auth_type = integration.node.connection.auth_upcloud.__class__

        for expected_count, expected_code in (
            (1, "PROVIDER_CREATE_OUTCOME_UNKNOWN"),
            (2, "PROVIDER_CREATE_OUTCOME_UNKNOWN"),
            (3, "PROVIDER_RECONCILIATION_REQUIRED"),
        ):
            backup.refresh_from_db()
            with mock.patch.object(
                auth_type, "get_verified_client", return_value=object()
            ), mock.patch(
                "apps._tasks.integration.upcloud.requests.get",
                side_effect=[
                    Response(200, {"storage": storage("source-1")}),
                    Response(200, page([])),
                ],
            ), mock.patch(
                "apps._tasks.integration.upcloud.requests.post"
            ) as post:
                with self.assertRaises(NodeBackupFailedError):
                    create_upcloud_snapshot(backup)
            post.assert_not_called()
            backup.refresh_from_db()
            execution = backup.get_execution_state()
            self.assertEqual(execution.last_error_code, expected_code)
            self.assertEqual(
                execution.provider_metadata[
                    "zero_match_reconciliation_count"
                ],
                expected_count,
            )

        self.assertEqual(
            execution.reconciliation_state,
            CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
        )

    def test_success_persists_exact_resource_before_return(self):
        integration, backup = self._backup()
        created = storage(
            "backup-created",
            storage_type="backup",
            title=backup.uuid_str,
            origin="source-1",
            state="backuping",
        )
        auth_type = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_type, "get_verified_client", return_value=object()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get",
            side_effect=[
                Response(200, {"storage": storage("source-1")}),
                Response(200, page([])),
            ],
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post",
            return_value=Response(201, {"storage": created}),
        ) as post:
            result = create_upcloud_snapshot(backup)

        self.assertEqual(result, "backup-created")
        self.assertEqual(post.call_count, 1)
        self.assertEqual(post.call_args.kwargs["timeout"], request_timeout())
        backup.refresh_from_db()
        execution = backup.get_execution_state()
        self.assertEqual(backup.unique_id, "backup-created")
        self.assertEqual(execution.provider_resource_id, "backup-created")
        self.assertEqual(execution.provider_idempotency_key, backup.uuid_str)
        self.assertTrue(backup.metadata["_bs_ownership_verified"])

    def test_definitive_rate_limit_does_not_leave_unknown_outcome(self):
        integration, backup = self._backup()
        auth_type = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_type, "get_verified_client", return_value=object()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get",
            side_effect=[
                Response(200, {"storage": storage("source-1")}),
                Response(200, page([])),
            ],
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post",
            return_value=Response(
                429,
                {
                    "error": {
                        "error_code": "RATE_LIMIT_EXCEEDED",
                        "error_message": "provider-secret-canary",
                    }
                },
            ),
        ):
            with self.assertRaises(NodeBackupFailedError):
                create_upcloud_snapshot(backup)

        backup.refresh_from_db()
        execution = backup.get_execution_state()
        self.assertEqual(execution.last_error_code, "PROVIDER_RATE_LIMIT")
        self.assertFalse(execution.provider_metadata["create_attempted"])
        self.assertFalse(execution.provider_metadata["outcome_unknown"])
        self.assertNotIn("provider-secret-canary", str(execution.provider_metadata))

    def test_credential_decode_failure_is_terminal_without_provider_io(self):
        integration, backup = self._backup()
        auth_type = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_type,
            "get_verified_client",
            side_effect=ValueError("credential-secret-canary"),
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get"
        ) as get, mock.patch(
            "apps._tasks.integration.upcloud.requests.post"
        ) as post:
            with self.assertRaises(NodeBackupFailedError):
                create_upcloud_snapshot(backup)

        get.assert_not_called()
        post.assert_not_called()
        backup.refresh_from_db()
        execution = backup.get_execution_state()
        self.assertEqual(execution.last_error_code, "PROVIDER_AUTH_FAILED")
        self.assertFalse(execution.provider_metadata["outcome_unknown"])
        self.assertNotIn(
            "credential-secret-canary", str(execution.provider_metadata)
        )

    def test_upcloud_error_categories_are_distinct_and_secret_free(self):
        cases = (
            (401, "AUTHENTICATION_FAILED", "PROVIDER_AUTH_FAILED", False),
            (404, "STORAGE_NOT_FOUND", "PROVIDER_NOT_FOUND", False),
            (429, "RATE_LIMIT_EXCEEDED", "PROVIDER_RATE_LIMIT", False),
            (402, "INSUFFICIENT_CREDIT", "QUOTA_EXCEEDED", False),
            (403, "MAXIOPS_STORAGE_LIMIT_REACHED", "QUOTA_EXCEEDED", False),
            (409, "STORAGE_OPERATION_IN_PROGRESS", "PROVIDER_CONFLICT", False),
            (504, "GATEWAY_TIMEOUT", "PROVIDER_TIMEOUT", True),
            (503, "MAINTENANCE", "PROVIDER_TRANSIENT_OUTAGE", True),
            (422, "INVALID_REQUEST", "PROVIDER_REQUEST_FAILED", False),
        )
        for status, machine_code, expected, unknown in cases:
            with self.subTest(status=status, machine_code=machine_code):
                error = classify_upcloud_response(
                    Response(
                        status,
                        {
                            "error": {
                                "error_code": machine_code,
                                "error_message": "provider-secret-canary",
                            }
                        },
                    ),
                    mutation=True,
                )
                self.assertEqual(error.code, expected)
                self.assertEqual(error.unknown_outcome, unknown)
                self.assertNotIn("provider-secret-canary", str(error))


class UpCloudObjectStorageBoundaryTests(SimpleTestCase):
    def test_endpoint_accepts_only_upcloud_managed_https_hosts(self):
        self.assertEqual(
            normalize_upcloud_endpoint(" AbCd1.UpCloudObjects.com. "),
            "abcd1.upcloudobjects.com",
        )
        self.assertEqual(
            normalize_upcloud_endpoint("mud5q-private.upcloudobjects.com"),
            "mud5q-private.upcloudobjects.com",
        )
        for endpoint in (
            "",
            "https://abcd1.upcloudobjects.com",
            "abcd1.upcloudobjects.com/path",
            "abcd1.upcloudobjects.com:443",
            "upcloudobjects.com",
            "abcd1.upcloudobjects.com.attacker.example",
            "127.0.0.1",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ValueError):
                    normalize_upcloud_endpoint(endpoint)

    def test_storage_serializer_rejects_foreign_endpoint_before_provider_io(self):
        serializer = CoreStorageUpCloudWriteSerializer(
            data={
                "access_key": "access",
                "secret_key": "secret",
                "bucket_name": "bucket",
                "prefix": "backups",
                "endpoint": "metadata.internal.example",
            },
            context={"encryption_key": b"test-key"},
        )
        with mock.patch(
            "apps.api.v1.storage.upcloud.serializers.CoreStorageUpCloud.validate"
        ) as provider_validate:
            self.assertFalse(serializer.is_valid())
        provider_validate.assert_not_called()
        self.assertNotIn("metadata.internal.example", str(serializer.errors))

    def test_persisted_foreign_endpoint_is_rejected_before_credentials_are_used(self):
        storage = mock.Mock(
            endpoint="metadata.internal.example",
            access_key=b"encrypted-access",
            secret_key=b"encrypted-secret",
        )
        with mock.patch(
            "apps._tasks.integration.storage.upcloud.bounded_boto3_client"
        ) as client:
            with self.assertRaises(ValueError):
                _s3_client(storage, b"encryption-key")
        client.assert_not_called()
