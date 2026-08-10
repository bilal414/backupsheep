"""Crash-safe backup-request outbox and duplicate-dispatch contract tests.

These tests intentionally exercise the durable request row independently from
Celery's result backend.  A broker publish can be lost, repeated, or observed
by a worker before the publisher updates the row; the database state and the
stable task id are the recovery boundary in each case.
"""

import json
import threading
import uuid
from datetime import timedelta
from unittest import mock

from django.contrib.contenttypes.models import ContentType
from django.db import close_old_connections
from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps._tasks import backup_dispatch
from apps._tasks.helper import tasks as helper_tasks
from apps._tasks.integration.digitalocean import backup_digitalocean
from apps.console.backup.models import (
    CoreBackupRequest,
    CoreDigitalOceanBackup,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreConnectionLocation,
    CoreIntegration,
)
from apps.console.node.models import CoreDigitalOcean, CoreNode
from apps.console.setting.models import CoreSiteSettings
from apps.console.storage.models import CoreStorageType
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


class BackupRequestTestMixin:
    @staticmethod
    def _ensure_factory_reference_data():
        # These are normally supplied by reference-data migrations.  A
        # TransactionTestCase flushes them under --keepdb, so keep this module
        # runnable on its own and repeatable without modifying shared fixtures.
        CoreIntegration.objects.get_or_create(
            code="website",
            defaults={"name": "Website", "type": CoreIntegration.Type.WEBSITE},
        )
        CoreIntegration.objects.get_or_create(
            code="digitalocean",
            defaults={"name": "DigitalOcean", "type": CoreIntegration.Type.CLOUD},
        )
        CoreConnectionLocation.objects.get_or_create(
            code="test-loc",
            defaults={"name": "Test location", "queue": "test"},
        )
        CoreStorageType.objects.get_or_create(
            code="aws_s3",
            defaults={"name": "Amazon S3", "is_enabled": True},
        )

    def setUp(self):
        super().setUp()
        self._ensure_factory_reference_data()

    def _request(
        self,
        *,
        node=None,
        idempotency_key=None,
        broker_side_effect=None,
        storage_ids=None,
    ):
        node = node or factories.make_website_node(self.account, self.member)
        key = idempotency_key or uuid.uuid4().hex
        with mock.patch.object(
            backup_dispatch.current_app,
            "send_task",
            side_effect=broker_side_effect,
        ) as send_task, mock.patch.object(backup_dispatch, "capture_exception"):
            request = backup_dispatch.create_backup_request(
                node=node,
                storage_ids=storage_ids,
                requested_by=self.member,
                trigger=CoreBackupRequest.Trigger.ON_DEMAND,
                idempotency_key=key,
            )
        return request, send_task

    @staticmethod
    def _direct_request(node, *, task_id=None, status=None, next_dispatch_at=None):
        task_id = task_id or uuid.uuid4().hex
        return CoreBackupRequest.objects.create(
            request_key=f"test-request-{uuid.uuid4().hex}",
            task_id=task_id,
            task_name=node.backup_task_name(),
            node=node,
            status=status or CoreBackupRequest.Status.PENDING,
            payload={"node_id": node.id, "storage_ids": [], "resume": True},
            next_dispatch_at=(
                next_dispatch_at
                if next_dispatch_at is not None
                else timezone.now() - timedelta(seconds=1)
            ),
        )


class BackupRequestOutboxTests(BackupRequestTestMixin, BaseTestCase):
    def test_broker_failure_commits_safe_pending_state_without_exception_text(self):
        raw_secret = "amqp://backup-user:broker-secret-canary@rabbitmq/vhost"

        def fail_publish(*_args, **_kwargs):
            raise ValueError(raw_secret)

        request, send_task = self._request(broker_side_effect=fail_publish)
        request.refresh_from_db()

        self.assertEqual(request.status, CoreBackupRequest.Status.PENDING)
        self.assertEqual(request.dispatch_attempt_count, 1)
        self.assertEqual(request.last_error_code, "BROKER_PUBLISH_FAILED")
        self.assertIn("could not be published", request.last_error_message)
        self.assertNotIn("broker-secret-canary", request.last_error_message)
        self.assertNotIn("broker-secret-canary", json.dumps(request.payload))
        self.assertIsNone(request.published_at)
        send_task.assert_called_once()

    def test_unrecognized_publish_exception_remains_conservative(self):
        node = factories.make_website_node(self.account, self.member)
        with mock.patch.object(
            backup_dispatch.current_app,
            "send_task",
            side_effect=RuntimeError("broker wrapper outcome unknown"),
        ), mock.patch.object(backup_dispatch, "capture_exception"):
            request = backup_dispatch.create_backup_request(
                node=node,
                requested_by=self.member,
                idempotency_key="unknown-publish-outcome",
            )

        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.DISPATCHED)
        self.assertEqual(request.last_error_code, "BROKER_PUBLISH_AMBIGUOUS")
        self.assertGreater(
            (request.next_dispatch_at - timezone.now()).total_seconds(), 120
        )

    def test_successful_confirmed_dispatch_persists_delivery_and_clears_lease(self):
        request, send_task = self._request(
            idempotency_key="confirmed-dispatch",
            storage_ids=[3, "4", -1, "not-an-id", 3],
        )
        request.refresh_from_db()

        self.assertEqual(request.status, CoreBackupRequest.Status.DISPATCHED)
        self.assertEqual(request.dispatch_attempt_count, 1)
        self.assertIsNotNone(request.published_at)
        self.assertEqual(request.dispatch_lease_owner, "")
        self.assertIsNone(request.dispatch_lease_token)
        self.assertIsNone(request.dispatch_lease_expires_at)
        self.assertEqual(request.payload["storage_ids"], [3, 4])

        send_task.assert_called_once()
        args, kwargs = send_task.call_args
        self.assertEqual(args, (request.task_name,))
        self.assertEqual(kwargs["task_id"], request.task_id)
        self.assertEqual(kwargs["kwargs"]["node_id"], request.node_id)
        self.assertTrue(kwargs["kwargs"]["resume"])
        self.assertEqual(kwargs["delivery_mode"], 2)
        self.assertTrue(kwargs["mandatory"])
        self.assertTrue(kwargs["retry"])

    def test_post_publish_success_update_loss_keeps_conservative_claim_timeout(self):
        node = factories.make_website_node(self.account, self.member)
        with mock.patch.object(
            backup_dispatch.current_app, "send_task"
        ) as send_task, mock.patch.object(
            backup_dispatch,
            "_persist_confirmed_dispatch",
            side_effect=RuntimeError("process died before success update"),
        ):
            with self.assertRaises(RuntimeError):
                backup_dispatch.publish_backup_request(
                    self._direct_request(node).pk
                )

        request = CoreBackupRequest.objects.get(node=node)
        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.DISPATCHED)
        self.assertEqual(request.last_error_code, "BROKER_PUBLISH_AMBIGUOUS")
        self.assertIn("safely queued", request.last_error_message)
        self.assertIsNone(request.published_at)
        self.assertGreater(
            (request.next_dispatch_at - timezone.now()).total_seconds(), 120
        )
        self.assertIsNotNone(request.dispatch_lease_token)
        send_task.assert_called_once()

        # Even after the publisher lease expires, the recovery sweep must wait
        # for the claim timeout because RabbitMQ may already hold the message.
        CoreBackupRequest.objects.filter(pk=request.pk).update(
            dispatch_lease_expires_at=timezone.now() - timedelta(seconds=1),
        )
        with mock.patch.object(
            backup_dispatch.current_app, "send_task"
        ) as recovery_send:
            helper_tasks.resume_pending_backup_requests.apply()
        recovery_send.assert_not_called()
        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.DISPATCHED)

    def test_same_idempotency_key_returns_one_request_and_stable_task_id(self):
        node = factories.make_website_node(self.account, self.member)
        with mock.patch.object(
            backup_dispatch.current_app, "send_task"
        ) as send_task, mock.patch.object(backup_dispatch, "capture_exception"):
            first = backup_dispatch.create_backup_request(
                node=node,
                storage_ids=[11],
                requested_by=self.member,
                idempotency_key="same-client-request",
            )
            second = backup_dispatch.create_backup_request(
                node=node,
                storage_ids=[99],
                requested_by=self.member,
                idempotency_key="same-client-request",
            )

        self.assertEqual(first.pk, second.pk)
        self.assertEqual(first.correlation_id, second.correlation_id)
        self.assertEqual(first.task_id, second.task_id)
        self.assertEqual(
            CoreBackupRequest.objects.filter(node=node).count(),
            1,
        )
        self.assertEqual(send_task.call_count, 1)
        self.assertEqual(
            [call.kwargs["task_id"] for call in send_task.call_args_list],
            [first.task_id],
        )

    def test_lost_publish_response_waits_for_claim_timeout_then_retries_same_task_id(self):
        node = factories.make_website_node(self.account, self.member)
        with mock.patch.object(
            backup_dispatch.current_app,
            "send_task",
            side_effect=ConnectionError("lost broker response: secret-canary"),
        ), mock.patch.object(backup_dispatch, "capture_exception"):
            request = backup_dispatch.create_backup_request(
                node=node,
                requested_by=self.member,
                idempotency_key="lost-response",
            )
        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.DISPATCHED)
        self.assertEqual(request.last_error_code, "BROKER_PUBLISH_AMBIGUOUS")
        self.assertIsNone(request.published_at)
        self.assertGreater(
            (request.next_dispatch_at - timezone.now()).total_seconds(), 120
        )

        with mock.patch.object(
            backup_dispatch.current_app, "send_task"
        ) as send_task:
            # A replay of the same idempotency key cannot force an ambiguous
            # delivery onto the broker before the claim timeout.
            replay = backup_dispatch.create_backup_request(
                node=node,
                requested_by=self.member,
                idempotency_key="lost-response",
            )
            self.assertEqual(replay.pk, request.pk)
            send_task.assert_not_called()

            CoreBackupRequest.objects.filter(pk=request.pk).update(
                next_dispatch_at=timezone.now() - timedelta(seconds=1),
            )
            self.assertTrue(backup_dispatch.publish_backup_request(request.pk))

        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.DISPATCHED)
        self.assertIsNotNone(request.published_at)
        send_task.assert_called_once()
        self.assertEqual(send_task.call_args.kwargs["task_id"], request.task_id)
        self.assertNotIn("secret-canary", request.last_error_message)

    @override_settings(
        BACKUP_REQUEST_RETRY_SECONDS=10,
        BACKUP_REQUEST_RETRY_MAX_SECONDS=25,
        BACKUP_REQUEST_CLAIM_TIMEOUT_SECONDS=120,
        BACKUP_REQUEST_CLAIM_TIMEOUT_MAX_SECONDS=300,
    )
    def test_confirmed_publish_uses_bounded_exponential_claim_timeout(self):
        node = factories.make_website_node(self.account, self.member)
        with mock.patch.object(
            backup_dispatch.current_app, "send_task"
        ) as send_task:
            request = backup_dispatch.create_backup_request(
                node=node,
                requested_by=self.member,
                idempotency_key="delayed-worker-claim",
            )
            request.refresh_from_db()
            first_delay = (
                request.next_dispatch_at - request.published_at
            ).total_seconds()
            self.assertGreaterEqual(first_delay, 119)

            # A one-minute beat tick must not republish a task that is merely
            # waiting in a broker queue for a slow worker.
            helper_tasks.resume_pending_backup_requests.apply()
            send_task.assert_called_once()

            CoreBackupRequest.objects.filter(pk=request.pk).update(
                next_dispatch_at=timezone.now() - timedelta(seconds=1),
            )
            helper_tasks.resume_pending_backup_requests.apply()
            self.assertEqual(send_task.call_count, 2)
            request.refresh_from_db()
            second_delay = (
                request.next_dispatch_at - timezone.now()
            ).total_seconds()
            self.assertGreaterEqual(second_delay, 239)

            # The cap is also respected after repeated lost claims.
            CoreBackupRequest.objects.filter(pk=request.pk).update(
                next_dispatch_at=timezone.now() - timedelta(seconds=1),
            )
            helper_tasks.resume_pending_backup_requests.apply()
            self.assertEqual(send_task.call_count, 3)
            request.refresh_from_db()
            capped_delay = (
                request.next_dispatch_at - timezone.now()
            ).total_seconds()
            self.assertGreaterEqual(capped_delay, 299)
            self.assertEqual(
                [call.kwargs["task_id"] for call in send_task.call_args_list],
                [request.task_id] * 3,
            )

    @override_settings(
        BACKUP_REQUEST_RETRY_SECONDS=10,
        BACKUP_REQUEST_RETRY_MAX_SECONDS=25,
    )
    def test_failed_publish_uses_short_bounded_retry_and_replay_does_not_force_it(self):
        node = factories.make_website_node(self.account, self.member)
        with mock.patch.object(
            backup_dispatch.current_app,
            "send_task",
            side_effect=ValueError("definite publish failure"),
        ) as send_task:
            request = backup_dispatch.create_backup_request(
                node=node,
                requested_by=self.member,
                idempotency_key="failed-publish-backoff",
            )
            request.refresh_from_db()
            self.assertEqual(request.status, CoreBackupRequest.Status.PENDING)
            self.assertEqual(request.last_error_code, "BROKER_PUBLISH_FAILED")
            self.assertGreater(
                (request.next_dispatch_at - timezone.now()).total_seconds(), 8
            )

            backup_dispatch.create_backup_request(
                node=node,
                requested_by=self.member,
                idempotency_key="failed-publish-backoff",
            )
            send_task.assert_called_once()

            CoreBackupRequest.objects.filter(pk=request.pk).update(
                next_dispatch_at=timezone.now() - timedelta(seconds=1),
            )
            helper_tasks.resume_pending_backup_requests.apply()
            request.refresh_from_db()
            self.assertEqual(send_task.call_count, 2)
            self.assertGreater(
                (request.next_dispatch_at - timezone.now()).total_seconds(), 18
            )

            CoreBackupRequest.objects.filter(pk=request.pk).update(
                next_dispatch_at=timezone.now() - timedelta(seconds=1),
            )
            helper_tasks.resume_pending_backup_requests.apply()
            request.refresh_from_db()
            self.assertEqual(send_task.call_count, 3)
            self.assertGreaterEqual(
                (request.next_dispatch_at - timezone.now()).total_seconds(), 24
            )

    def test_ineligible_confirmed_request_is_cancelled_without_republish(self):
        node = factories.make_website_node(self.account, self.member)
        with mock.patch.object(
            backup_dispatch.current_app, "send_task"
        ) as send_task:
            request = backup_dispatch.create_backup_request(
                node=node,
                requested_by=self.member,
                idempotency_key="source-paused-after-acceptance",
            )
            request.refresh_from_db()
            self.assertEqual(request.status, CoreBackupRequest.Status.DISPATCHED)
            self.assertEqual(send_task.call_count, 1)

            # The confirmed claim timeout is deliberately still in the future;
            # recovery must nevertheless notice that the task can no longer run.
            node.status = CoreNode.Status.PAUSED
            node.save(update_fields=["status", "modified"])
            helper_tasks.resume_pending_backup_requests.apply()

        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.CANCELLED)
        self.assertEqual(request.last_error_code, "REQUEST_INELIGIBLE")
        self.assertIn("cancelled", request.last_error_message)
        self.assertIsNone(request.next_dispatch_at)
        self.assertEqual(send_task.call_count, 1)

    def test_ineligible_connection_and_account_requests_are_cancelled_centrally(self):
        for field in ("connection", "account"):
            with self.subTest(field=field):
                account, member, _ = factories.make_account()
                node = factories.make_website_node(account, member)
                with mock.patch.object(
                    backup_dispatch.current_app, "send_task"
                ) as send_task:
                    request = backup_dispatch.create_backup_request(
                        node=node,
                        requested_by=member,
                        idempotency_key=f"{field}-ineligible",
                    )
                    if field == "connection":
                        node.connection.status = node.connection.Status.PAUSED
                        node.connection.save(
                            update_fields=["status", "modified"]
                        )
                    else:
                        node.connection.account.status = (
                            node.connection.account.Status.DELETE_REQUESTED
                        )
                        node.connection.account.save(
                            update_fields=["status", "modified"]
                        )
                    helper_tasks.resume_pending_backup_requests.apply()

                request.refresh_from_db()
                self.assertEqual(
                    request.status, CoreBackupRequest.Status.CANCELLED
                )
                self.assertEqual(send_task.call_count, 1)

    def test_live_dispatch_lease_blocks_republication_but_stale_lease_is_reclaimed(self):
        node = factories.make_website_node(self.account, self.member)
        token = uuid.uuid4()
        request = self._direct_request(node)
        CoreBackupRequest.objects.filter(pk=request.pk).update(
            dispatch_lease_owner="live-dispatcher",
            dispatch_lease_token=token,
            dispatch_lease_expires_at=timezone.now() + timedelta(minutes=5),
        )

        with mock.patch.object(backup_dispatch.current_app, "send_task") as send_task:
            self.assertFalse(
                backup_dispatch.publish_backup_request(request.pk, force=True)
            )
            send_task.assert_not_called()

        CoreBackupRequest.objects.filter(pk=request.pk).update(
            dispatch_lease_expires_at=timezone.now() - timedelta(seconds=1),
            next_dispatch_at=timezone.now() - timedelta(seconds=1),
        )
        with mock.patch.object(backup_dispatch.current_app, "send_task") as send_task:
            self.assertTrue(backup_dispatch.publish_backup_request(request.pk))
            send_task.assert_called_once()

        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.DISPATCHED)
        self.assertEqual(request.dispatch_attempt_count, 1)

    def test_recovery_sweep_republishes_due_request_with_original_task_id(self):
        node = factories.make_website_node(self.account, self.member)
        request = self._direct_request(node)

        with mock.patch.object(backup_dispatch.current_app, "send_task") as send_task:
            helper_tasks.resume_pending_backup_requests.apply()
            request.refresh_from_db()
            self.assertEqual(request.status, CoreBackupRequest.Status.DISPATCHED)
            self.assertEqual(send_task.call_count, 1)
            first_task_id = send_task.call_args.kwargs["task_id"]

            # A later recovery cycle may need to republish after a worker dies
            # after broker acceptance. It must still use the same Celery id.
            CoreBackupRequest.objects.filter(pk=request.pk).update(
                next_dispatch_at=timezone.now() - timedelta(seconds=1),
            )
            helper_tasks.resume_pending_backup_requests.apply()

        request.refresh_from_db()
        self.assertEqual(send_task.call_count, 2)
        self.assertEqual(
            [call.kwargs["task_id"] for call in send_task.call_args_list],
            [first_task_id, first_task_id],
        )
        self.assertEqual(request.task_id, first_task_id)

    def test_late_publisher_cannot_regress_claimed_request_to_dispatched(self):
        node = factories.make_cloud_node(self.account, self.member)
        request = self._direct_request(node)
        created_backup = {}

        def worker_claims_before_publisher_persists(*_args, **kwargs):
            backup = CoreDigitalOceanBackup.objects.create(
                digitalocean=node.digitalocean,
                status=UtilBackup.Status.IN_PROGRESS,
                celery_task_id=kwargs["task_id"],
            )
            created_backup["backup"] = backup
            self.assertEqual(
                CoreBackupRequest.link_backup(
                    task_id=kwargs["task_id"],
                    node=node,
                    backup=backup,
                ),
                1,
            )

        with mock.patch.object(
            backup_dispatch.current_app,
            "send_task",
            side_effect=worker_claims_before_publisher_persists,
        ):
            self.assertTrue(backup_dispatch.publish_backup_request(request.pk))

        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.CLAIMED)
        self.assertEqual(request.backup_object_id, created_backup["backup"].pk)
        self.assertEqual(request.backup_content_type, ContentType.objects.get_for_model(
            created_backup["backup"], for_concrete_model=False
        ))
        self.assertIsNone(request.published_at)
        self.assertIsNone(request.next_dispatch_at)

    def test_backup_request_linking_is_node_scoped_and_persists_generic_backup(self):
        node = factories.make_cloud_node(self.account, self.member)
        other_node = factories.make_cloud_node(self.account, self.member)
        request = self._direct_request(node, task_id="link-task")
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id="link-task",
        )
        wrong_backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=other_node.digitalocean,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id="wrong-link-task",
        )

        self.assertEqual(
            CoreBackupRequest.link_backup(
                task_id="link-task", node=other_node, backup=wrong_backup
            ),
            0,
        )
        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.PENDING)

        self.assertEqual(
            CoreBackupRequest.link_backup(
                task_id="link-task", node=node, backup=backup
            ),
            1,
        )
        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.CLAIMED)
        self.assertEqual(request.backup, backup)
        self.assertEqual(request.backup_object_id, backup.pk)

    def test_backup_initiate_reuses_task_backup_and_outbox_links_it_once(self):
        node = factories.make_cloud_node(self.account, self.member)
        request = self._direct_request(node, task_id="stable-node-task")

        first = node.backup_initiate(
            "stable-node-task", UtilBackup.Type.ON_DEMAND, 1, None, None, None
        )
        second = node.backup_initiate(
            "stable-node-task", UtilBackup.Type.ON_DEMAND, 2, None, None, None
        )

        self.assertIsNotNone(first)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(
            CoreDigitalOceanBackup.objects.filter(
                digitalocean=node.digitalocean
            ).count(),
            1,
        )
        self.assertEqual(
            CoreBackupRequest.link_backup(
                task_id=request.task_id, node=node, backup=first
            ),
            1,
        )
        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.CLAIMED)
        self.assertEqual(request.backup_object_id, first.pk)

    def test_same_and_different_task_deliveries_make_at_most_one_provider_create(self):
        node = factories.make_cloud_node(self.account, self.member)
        task_kwargs = {
            "node_id": node.id,
            "schedule_id": None,
            "storage_ids": None,
            "notes": None,
        }

        def provider_create(backup):
            backup.action_id = "provider-action-once"
            backup.unique_id = "provider-snapshot-once"
            backup.save(update_fields=["action_id", "unique_id", "modified"])

        with mock.patch.object(CoreConnection, "validate", return_value=True), \
                mock.patch.object(CoreNode, "validate", return_value=True), \
                mock.patch.object(CoreDigitalOcean, "create_snapshot", side_effect=provider_create) as create_snapshot, \
                mock.patch.object(helper_tasks.poll_cloud_backup, "apply_async"):
            backup_digitalocean.apply(kwargs=task_kwargs, task_id="same-provider-task")
            backup_digitalocean.apply(kwargs=task_kwargs, task_id="same-provider-task")
            backup_digitalocean.apply(kwargs=task_kwargs, task_id="different-provider-task")

        self.assertEqual(create_snapshot.call_count, 1)
        self.assertEqual(
            CoreDigitalOceanBackup.objects.filter(
                digitalocean=node.digitalocean
            ).count(),
            1,
        )
        backup = CoreDigitalOceanBackup.objects.get(digitalocean=node.digitalocean)
        self.assertEqual(backup.celery_task_id, "same-provider-task")
        self.assertEqual(backup.unique_id, "provider-snapshot-once")


class BackupRequestApiTests(BackupRequestTestMixin, BaseTestCase):
    def setUp(self):
        super().setUp()
        site_settings = CoreSiteSettings.load()
        site_settings.setup_completed = True
        site_settings.save(update_fields=["setup_completed", "modified"])
        OnboardingMiddleware._completed = False
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.node = factories.make_website_node(self.account, self.member)
        self.storage = factories.make_storage(self.account, self.member)

    def test_take_snapshot_and_status_endpoint_return_durable_request(self):
        with mock.patch.object(backup_dispatch.current_app, "send_task") as send_task:
            response = self.client.post(
                f"/api/v1/nodes/{self.node.id}/take_snapshot/",
                {
                    "storage_point_ids": [self.storage.id],
                    "notes": "operator note",
                },
                format="json",
                HTTP_IDEMPOTENCY_KEY="api-idempotency-key",
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        body = response.json()["backup_request"]
        self.assertEqual(body["status"], CoreBackupRequest.Status.DISPATCHED)
        self.assertEqual(body["backup_id"], None)
        request_id = body["request_id"]
        request = CoreBackupRequest.objects.get(correlation_id=request_id)
        self.assertEqual(request.node_id, self.node.id)
        send_task.assert_called_once()

        status_response = self.client.get(
            f"/api/v1/nodes/{self.node.id}/backup_request_status/",
            {"request_id": request_id},
        )
        self.assertEqual(status_response.status_code, status.HTTP_200_OK)
        self.assertEqual(status_response.json()["request_id"], request_id)
        self.assertEqual(
            status_response.json()["status"], CoreBackupRequest.Status.DISPATCHED
        )

    def test_take_snapshot_idempotency_reuses_request_and_task_id(self):
        payload = {"storage_point_ids": [self.storage.id]}
        with mock.patch.object(backup_dispatch.current_app, "send_task") as send_task:
            first = self.client.post(
                f"/api/v1/nodes/{self.node.id}/take_snapshot/",
                payload,
                format="json",
                HTTP_IDEMPOTENCY_KEY="repeat-api-request",
            )
            second = self.client.post(
                f"/api/v1/nodes/{self.node.id}/take_snapshot/",
                payload,
                format="json",
                HTTP_IDEMPOTENCY_KEY="repeat-api-request",
            )

        self.assertEqual(first.status_code, status.HTTP_201_CREATED)
        self.assertEqual(second.status_code, status.HTTP_201_CREATED)
        first_request = first.json()["backup_request"]
        second_request = second.json()["backup_request"]
        self.assertEqual(first_request["request_id"], second_request["request_id"])
        request = CoreBackupRequest.objects.get(correlation_id=first_request["request_id"])
        self.assertEqual(request.task_id, send_task.call_args.kwargs["task_id"])
        self.assertEqual(
            CoreBackupRequest.objects.filter(node=self.node).count(),
            1,
        )
        self.assertEqual(send_task.call_count, 1)

    def test_status_endpoint_scopes_by_node_and_account(self):
        same_account_other_node = factories.make_website_node(
            self.account, self.member
        )
        same_account_request = self._direct_request(same_account_other_node)
        same_node_response = self.client.get(
            f"/api/v1/nodes/{self.node.id}/backup_request_status/",
            {"request_id": str(same_account_request.correlation_id)},
        )
        self.assertEqual(same_node_response.status_code, status.HTTP_404_NOT_FOUND)

        other_account, other_member, _ = factories.make_account()
        foreign_node = factories.make_website_node(other_account, other_member)
        foreign_request = self._direct_request(foreign_node)
        foreign_response = self.client.get(
            f"/api/v1/nodes/{foreign_node.id}/backup_request_status/",
            {"request_id": str(foreign_request.correlation_id)},
        )
        self.assertEqual(foreign_response.status_code, status.HTTP_404_NOT_FOUND)


class ConcurrentBackupRequestRecoveryTests(
    BackupRequestTestMixin, TransactionTestCase
):
    def setUp(self):
        super().setUp()
        self.account, self.member, self.user = factories.make_account()

    def _fixture_teardown(self):
        super()._fixture_teardown()
        # TransactionTestCase.flush removes migration-seeded reference rows even
        # with --keepdb. Leave the focused test database ready for the next test
        # module while keeping all created account/node data isolated.
        self._ensure_factory_reference_data()

    def test_concurrent_recovery_elects_one_live_dispatch_lease(self):
        node = factories.make_website_node(self.account, self.member)
        request = self._direct_request(node)
        first_publisher_entered = threading.Event()
        allow_first_publisher_to_finish = threading.Event()
        published_task_ids = []
        results = []
        errors = []
        result_lock = threading.Lock()

        def broker_publish(*_args, **kwargs):
            with result_lock:
                published_task_ids.append(kwargs["task_id"])
            first_publisher_entered.set()
            if not allow_first_publisher_to_finish.wait(timeout=10):
                raise RuntimeError("test publisher did not get released")

        def recover():
            try:
                result = backup_dispatch.publish_backup_request(request.pk)
                with result_lock:
                    results.append(result)
            except Exception as error:  # pragma: no cover - asserted below
                with result_lock:
                    errors.append(error)
            finally:
                close_old_connections()

        with mock.patch.object(
            backup_dispatch.current_app,
            "send_task",
            side_effect=broker_publish,
        ):
            first = threading.Thread(target=recover)
            first.start()
            self.assertTrue(first_publisher_entered.wait(timeout=10))

            second = threading.Thread(target=recover)
            second.start()
            second.join(timeout=10)
            self.assertFalse(second.is_alive(), "second recovery deadlocked")

            allow_first_publisher_to_finish.set()
            first.join(timeout=10)
            self.assertFalse(first.is_alive(), "first recovery deadlocked")

        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(published_task_ids, [request.task_id])
        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.DISPATCHED)
        self.assertEqual(request.dispatch_attempt_count, 1)
