import threading
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from django.db import close_old_connections
from django.test import TransactionTestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.api.v1.node.views import CoreNodeView
from apps.console.backup.models import CoreCloudRestore
from apps.console.connection.models import CoreIntegration
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


def _completed_cloud_backup(node, unique_id="provider-snapshot-1"):
    return node.digitalocean.backups.create(
        status=UtilBackup.Status.COMPLETE,
        type=UtilBackup.Type.ON_DEMAND,
        unique_id=unique_id,
    )


class _CloudRestoreRequestMixin:
    def _post(self, node, payload, *, idempotency_key=None):
        view = CoreNodeView.as_view({"post": "restore_backup"})
        request_kwargs = {}
        if idempotency_key is not None:
            request_kwargs["HTTP_IDEMPOTENCY_KEY"] = idempotency_key
        request = APIRequestFactory().post(
            f"/api/v1/nodes/{node.id}/restore_backup/",
            payload,
            format="json",
            **request_kwargs,
        )
        force_authenticate(request, user=self.user)
        return view(request, pk=node.id)

    @staticmethod
    def _payload(backup, **overrides):
        payload = {
            "backup_id": backup.id,
            "name": "restored-server",
            "params": {},
            "confirm": True,
        }
        payload.update(overrides)
        return payload


class _CloudRestoreTransactionMixin:
    def setUp(self):
        super().setUp()
        CoreIntegration.objects.get_or_create(
            code="digitalocean",
            defaults={
                "name": "DigitalOcean",
                "type": CoreIntegration.Type.CLOUD,
            },
        )

    def _fixture_teardown(self):
        super()._fixture_teardown()
        # TransactionTestCase.flush removes migration-seeded integrations;
        # restore the one needed by the next focused test class.
        CoreIntegration.objects.get_or_create(
            code="digitalocean",
            defaults={
                "name": "DigitalOcean",
                "type": CoreIntegration.Type.CLOUD,
            },
        )


class CloudRestoreRequestIdempotencyTests(
    _CloudRestoreRequestMixin, BaseTestCase
):
    def test_confirmation_is_required_before_a_restore_row_is_created(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = _completed_cloud_backup(node)

        response = self._post(
            node,
            {
                "backup_id": backup.id,
                "name": "restored-server",
                "params": {},
            },
            idempotency_key="confirmation-required",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(CoreCloudRestore.objects.count(), 0)

    def test_confirmation_must_be_the_explicit_boolean_true(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = _completed_cloud_backup(node)

        response = self._post(
            node,
            self._payload(backup, confirm=1),
            idempotency_key="non-boolean-confirmation",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(CoreCloudRestore.objects.count(), 0)

    def test_empty_header_does_not_fall_back_to_body_request_id(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = _completed_cloud_backup(node)

        response = self._post(
            node,
            self._payload(backup, request_id="body-key-must-not-win"),
            idempotency_key="",
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(CoreCloudRestore.objects.count(), 0)

    def test_same_key_reuses_one_restore_and_one_dispatch(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = _completed_cloud_backup(node)
        payload = self._payload(backup)

        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as dispatch:
            with self.captureOnCommitCallbacks(execute=True):
                first = self._post(
                    node, payload, idempotency_key="lost-http-response"
                )
            with self.captureOnCommitCallbacks(execute=True):
                replay = self._post(
                    node, payload, idempotency_key="lost-http-response"
                )

        self.assertEqual(first.status_code, 201)
        self.assertEqual(replay.status_code, 200)
        self.assertFalse(first.data["idempotent_replay"])
        self.assertTrue(replay.data["idempotent_replay"])
        self.assertEqual(first.data["id"], replay.data["id"])
        self.assertEqual(CoreCloudRestore.objects.filter(node=node).count(), 1)
        restore = CoreCloudRestore.objects.get(node=node)
        self.assertEqual(first.data["correlation_id"], str(restore.correlation_id))
        self.assertTrue(restore.celery_task_id.startswith("cloud-restore-"))
        self.assertEqual(
            len(
                restore.execution_metadata["api_request"][
                    "idempotency_key_sha256"
                ]
            ),
            64,
        )
        # Provider adapters own request_fingerprint; HTTP idempotency has a
        # separate immutable fingerprint so the two crash-recovery layers do
        # not overwrite each other.
        self.assertEqual(restore.request_fingerprint, "")
        self.assertNotIn("lost-http-response", str(first.data))
        dispatch.assert_called_once_with(
            task_id=restore.celery_task_id,
            kwargs={
                "node_id": node.id,
                "backup_id": backup.id,
                "restore_id": restore.id,
            },
        )

    def test_replay_survives_provider_fingerprint_and_internal_param_updates(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = _completed_cloud_backup(node)
        payload = self._payload(backup, params={"region": "test"})

        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as dispatch:
            with self.captureOnCommitCallbacks(execute=True):
                first = self._post(
                    node,
                    payload,
                    idempotency_key="provider-prepared-replay",
                )

        restore = CoreCloudRestore.objects.get(pk=first.data["id"])
        restore.request_fingerprint = "f" * 64
        restore.params = {
            "region": "test",
            "_bs_provider_name": "provider-owned-marker",
            "_backupsheep_restore": {"source_id": "snapshot-1"},
        }
        restore.save(update_fields=["request_fingerprint", "params", "modified"])

        replay = self._post(
            node,
            payload,
            idempotency_key="provider-prepared-replay",
        )

        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.data["idempotent_replay"])
        self.assertEqual(replay.data["id"], restore.id)
        self.assertEqual(CoreCloudRestore.objects.filter(node=node).count(), 1)
        dispatch.assert_called_once()

    def test_body_request_id_is_an_idempotency_key(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = _completed_cloud_backup(node)
        payload = self._payload(backup, request_id="browser-request-42")

        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as dispatch:
            with self.captureOnCommitCallbacks(execute=True):
                first = self._post(node, payload)
            with self.captureOnCommitCallbacks(execute=True):
                second = self._post(node, payload)

        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.data["correlation_id"], second.data["correlation_id"])
        self.assertEqual(CoreCloudRestore.objects.count(), 1)
        dispatch.assert_called_once()

    def test_backup_name_and_params_are_normalized_before_fingerprinting(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = _completed_cloud_backup(node)

        first_payload = self._payload(
            backup,
            backup_id=str(backup.id),
            name="  restored-server  ",
            params={"region": "test", "size": "small"},
        )
        replay_payload = self._payload(
            backup,
            name="restored-server",
            params={"size": "small", "region": "test"},
        )

        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as dispatch:
            with self.captureOnCommitCallbacks(execute=True):
                first = self._post(
                    node, first_payload, idempotency_key="normalized-request"
                )
            with self.captureOnCommitCallbacks(execute=True):
                replay = self._post(
                    node, replay_payload, idempotency_key="normalized-request"
                )

        self.assertEqual(first.status_code, 201)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(first.data["id"], replay.data["id"])
        restore = CoreCloudRestore.objects.get(node=node)
        self.assertEqual(restore.name, "restored-server")
        self.assertEqual(restore.params, {"region": "test", "size": "small"})
        dispatch.assert_called_once()

    def test_header_key_precedes_body_request_id(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = _completed_cloud_backup(node)
        first_payload = self._payload(backup, request_id="body-key-one")
        replay_payload = self._payload(backup, request_id="body-key-two")

        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as dispatch:
            with self.captureOnCommitCallbacks(execute=True):
                first = self._post(
                    node, first_payload, idempotency_key="header-key"
                )
            with self.captureOnCommitCallbacks(execute=True):
                replay = self._post(
                    node, replay_payload, idempotency_key="header-key"
                )
            with self.captureOnCommitCallbacks(execute=True):
                body_only = self._post(node, first_payload)

        self.assertEqual(first.status_code, 201)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(body_only.status_code, 201)
        self.assertEqual(first.data["id"], replay.data["id"])
        self.assertNotEqual(first.data["id"], body_only.data["id"])
        self.assertEqual(CoreCloudRestore.objects.filter(node=node).count(), 2)
        self.assertEqual(dispatch.call_count, 2)

    def test_reusing_key_for_different_request_fails_closed(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = _completed_cloud_backup(node)

        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as dispatch:
            with self.captureOnCommitCallbacks(execute=True):
                first = self._post(
                    node,
                    self._payload(backup),
                    idempotency_key="immutable-request",
                )
            conflict = self._post(
                node,
                self._payload(backup, name="different-target"),
                idempotency_key="immutable-request",
            )

        self.assertEqual(first.status_code, 201)
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.data["code"], "restore_idempotency_conflict")
        self.assertEqual(CoreCloudRestore.objects.count(), 1)
        dispatch.assert_called_once()

    def test_unsafe_request_values_are_rejected_before_persistence(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = _completed_cloud_backup(node)
        unsafe_payloads = (
            self._payload(backup, backup_id=True),
            self._payload(backup, name=["not-a-name"]),
            self._payload(backup, params=[]),
            self._payload(backup, params={"_bs_provider_name": "forged"}),
        )

        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as dispatch:
            for index, payload in enumerate(unsafe_payloads):
                response = self._post(
                    node,
                    payload,
                    idempotency_key=f"unsafe-request-{index}",
                )
                self.assertEqual(response.status_code, 503)

        self.assertEqual(CoreCloudRestore.objects.count(), 0)
        dispatch.assert_not_called()

    def test_oversized_deep_or_excessive_params_are_rejected(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = _completed_cloud_backup(node)
        deeply_nested = {}
        cursor = deeply_nested
        for _ in range(20):
            cursor["child"] = {}
            cursor = cursor["child"]
        unsafe_params = (
            deeply_nested,
            {"value": "x" * (64 * 1024)},
            {"items": list(range(1001))},
        )

        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as dispatch:
            for index, params in enumerate(unsafe_params):
                response = self._post(
                    node,
                    self._payload(backup, params=params),
                    idempotency_key=f"bounded-params-{index}",
                )
                self.assertEqual(response.status_code, 503)

        self.assertEqual(CoreCloudRestore.objects.count(), 0)
        dispatch.assert_not_called()

    def test_same_key_with_a_different_backup_or_params_conflicts(self):
        node = factories.make_cloud_node(self.account, self.member)
        first_backup = _completed_cloud_backup(node, "provider-snapshot-first")
        second_backup = _completed_cloud_backup(node, "provider-snapshot-second")

        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as dispatch:
            with self.captureOnCommitCallbacks(execute=True):
                first = self._post(
                    node,
                    self._payload(
                        first_backup,
                        params={"size": "small", "region": "test"},
                    ),
                    idempotency_key="immutable-payload",
                )
            conflict = self._post(
                node,
                self._payload(
                    second_backup,
                    params={"region": "test", "size": "large"},
                ),
                idempotency_key="immutable-payload",
            )

        self.assertEqual(first.status_code, 201)
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.data["code"], "restore_idempotency_conflict")
        self.assertEqual(CoreCloudRestore.objects.filter(node=node).count(), 1)
        dispatch.assert_called_once()

    def test_same_key_is_scoped_to_the_node(self):
        first_node = factories.make_cloud_node(self.account, self.member)
        second_node = factories.make_cloud_node(self.account, self.member)
        first_backup = _completed_cloud_backup(first_node, "provider-snapshot-one")
        second_backup = _completed_cloud_backup(second_node, "provider-snapshot-two")

        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as dispatch:
            with self.captureOnCommitCallbacks(execute=True):
                first = self._post(
                    first_node,
                    self._payload(first_backup),
                    idempotency_key="same-key-on-two-nodes",
                )
            with self.captureOnCommitCallbacks(execute=True):
                second = self._post(
                    second_node,
                    self._payload(second_backup),
                    idempotency_key="same-key-on-two-nodes",
                )

        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 201)
        self.assertNotEqual(first.data["id"], second.data["id"])
        self.assertNotEqual(
            first.data["correlation_id"], second.data["correlation_id"]
        )
        self.assertEqual(CoreCloudRestore.objects.count(), 2)
        self.assertEqual(dispatch.call_count, 2)


class CloudRestoreBrokerFailureTests(
    _CloudRestoreRequestMixin,
    _CloudRestoreTransactionMixin,
    TransactionTestCase,
):
    def setUp(self):
        super().setUp()
        self.account, self.member, self.user = factories.make_account()

    def test_publish_failure_keeps_recoverable_row_and_redacts_broker_error(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = _completed_cloud_backup(node)
        payload = self._payload(backup)

        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async",
            side_effect=RuntimeError(
                "amqp://broker-user:SUPER-SECRET@10.0.0.4/vhost"
            ),
        ):
            response = self._post(
                node, payload, idempotency_key="broker-ack-lost"
            )

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("SUPER-SECRET", str(response.data))
        self.assertNotIn("10.0.0.4", str(response.data))
        restore = CoreCloudRestore.objects.get(node=node)
        self.assertEqual(restore.status, CoreCloudRestore.Status.PENDING)
        self.assertTrue(restore.celery_task_id.startswith("cloud-restore-"))
        self.assertEqual(restore.execution_phase, "pending")

        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as replay_dispatch:
            replay = self._post(
                node, payload, idempotency_key="broker-ack-lost"
            )

        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.data["idempotent_replay"])
        self.assertEqual(CoreCloudRestore.objects.filter(node=node).count(), 1)
        # Recovery Beat, not an HTTP replay, owns redelivery after the durable
        # task boundary is recorded. This prevents click storms from flooding
        # the broker while still recovering a lost publish.
        replay_dispatch.assert_not_called()


class CloudRestoreConcurrentRequestTests(
    _CloudRestoreRequestMixin,
    _CloudRestoreTransactionMixin,
    TransactionTestCase,
):
    reset_sequences = True

    def setUp(self):
        super().setUp()
        self.account, self.member, self.user = factories.make_account()

    def test_concurrent_same_key_creates_one_row_and_one_publish(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = _completed_cloud_backup(node)
        payload = self._payload(backup)
        start = threading.Barrier(2)

        def submit():
            close_old_connections()
            try:
                start.wait(timeout=10)
                return self._post(
                    node,
                    payload,
                    idempotency_key="concurrent-restore-key",
                )
            finally:
                close_old_connections()

        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as dispatch:
            with ThreadPoolExecutor(max_workers=2) as executor:
                responses = list(executor.map(lambda _value: submit(), (1, 2)))

        self.assertEqual(
            sorted(response.status_code for response in responses), [200, 201]
        )
        self.assertEqual(CoreCloudRestore.objects.filter(node=node).count(), 1)
        self.assertEqual(responses[0].data["id"], responses[1].data["id"])
        self.assertEqual(
            responses[0].data["correlation_id"],
            responses[1].data["correlation_id"],
        )
        dispatch.assert_called_once()
