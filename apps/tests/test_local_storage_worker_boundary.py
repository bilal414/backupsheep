import hashlib
import os
import tempfile
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.db import close_old_connections, connection
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps._tasks.integration.storage.tasks import (
    _claim_backup_deletion,
    _claim_storage_point_delete,
    _delete_backup_requested_id,
    _delete_storage_requested_id,
    resume_requested_storage_deletions,
    _validate_local_storage_id,
)
from apps._tasks.helper.tasks import (
    _delete_requested_node,
    resume_requested_local_node_deletions,
)
from apps.api.v1.backup.mixins import VisibleNodeBackupMixin
from apps.api.v1.node.views import CoreNodeView
from apps.api.v1.storage.local.views import CoreStorageLocalView
from apps.api.v1.storage.views import CoreStorageView
from apps.api.v1.storage.local.serializers import CoreStorageLocalWriteSerializer
from apps.console.backup.models import (
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
)
from apps.console.connection.models import CoreConnectionLocation, CoreIntegration
from apps.console.storage.models import CoreStorage, CoreStorageLocal, CoreStorageType
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class _SimulatedWorkerCrash(BaseException):
    """Escape the task's normal Exception handler like a killed worker process."""


def _local_storage(account, member, *, status=CoreStorage.Status.ACTIVE, path=None, no_delete=None):
    storage = CoreStorage.objects.create(
        account=account,
        type=CoreStorageType.objects.get(code="local"),
        name=f"local-{uuid.uuid4().hex}",
        added_by=member,
        status=status,
    )
    CoreStorageLocal.objects.create(
        storage=storage, path=path, no_delete=no_delete
    )
    return storage


def _website_point(member, storage, *, storage_file_id=None, metadata=None):
    node = factories.make_website_node(storage.account, member)
    backup = CoreWebsiteBackup.objects.create(
        website=node.website,
        uuid=f"worker-boundary-{uuid.uuid4().hex}",
        status=UtilBackup.Status.COMPLETE,
        type=UtilBackup.Type.ON_DEMAND,
        metadata={},
    )
    point = CoreWebsiteBackupStoragePoints.objects.create(
        backup=backup,
        storage=storage,
        status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
        storage_file_id=storage_file_id,
        metadata=metadata or {},
    )
    return backup, point


class LocalStorageWorkerBoundaryTests(BaseTestCase):
    def test_api_serializer_validation_never_writes_local_storage(self):
        with tempfile.TemporaryDirectory() as root, override_settings(
            LOCAL_STORAGE_ROOT=root
        ):
            serializer = CoreStorageLocalWriteSerializer(
                data={"path": "tenant/backups", "no_delete": False}
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            self.assertFalse(os.path.exists(os.path.join(root, "tenant")))

    def test_id_only_worker_validation_transitions_pending_to_active_once(self):
        with tempfile.TemporaryDirectory() as root, override_settings(
            LOCAL_STORAGE_ROOT=root
        ):
            storage = _local_storage(
                self.account,
                self.member,
                status=CoreStorage.Status.PENDING,
                path="tenant/backups",
            )
            self.assertEqual(
                _validate_local_storage_id(storage.pk), {"result": "valid"}
            )
            storage.refresh_from_db()
            self.assertEqual(storage.status, CoreStorage.Status.ACTIVE)
            self.assertTrue(os.path.isdir(os.path.join(root, "tenant", "backups")))

            with mock.patch.object(
                CoreStorageLocal, "probe_filesystem", side_effect=AssertionError
            ):
                self.assertEqual(
                    _validate_local_storage_id(storage.pk),
                    {"result": "not_pending"},
                )

    def test_worker_rejects_path_payload_instead_of_treating_it_as_an_id(self):
        with tempfile.TemporaryDirectory() as root, override_settings(
            LOCAL_STORAGE_ROOT=root
        ):
            self.assertEqual(
                _validate_local_storage_id("../tenant"),
                {"result": "invalid_id"},
            )
            self.assertEqual(os.listdir(root), [])

    def test_node_delete_recovery_republishes_database_ids_only(self):
        node = factories.make_website_node(self.account, self.member)
        node.status = node.Status.DELETE_REQUESTED
        node.flag_delete_node = True
        node.save(update_fields=["status", "flag_delete_node", "modified"])

        with mock.patch(
            "apps._tasks.helper.tasks.delete_local_node_requested.apply_async"
        ) as publish:
            self.assertEqual(resume_requested_local_node_deletions(), [node.pk])

        publish.assert_called_once_with(args=[node.pk])

    def test_storage_delete_recovery_republishes_allowlisted_ids_only(self):
        storage = _local_storage(self.account, self.member)
        backup, _point = _website_point(self.member, storage)
        backup.status = UtilBackup.Status.DELETE_REQUESTED
        backup.metadata = {
            "_deletion_request": {
                "previous_status": int(UtilBackup.Status.COMPLETE)
            }
        }
        backup.save(update_fields=["status", "metadata", "modified"])
        storage.status = CoreStorage.Status.DELETE_REQUESTED
        storage.save(update_fields=["status", "modified"])

        with mock.patch(
            "apps._tasks.integration.storage.tasks.delete_backup_requested.apply_async"
        ) as publish_backup, mock.patch(
            "apps._tasks.integration.storage.tasks.delete_storage_requested.apply_async"
        ) as publish_storage:
            result = resume_requested_storage_deletions()

        self.assertEqual(
            result,
            {
                "backup_requests": [("website", backup.pk)],
                "storage_ids": [storage.pk],
            },
        )
        publish_backup.assert_called_once_with(args=["website", backup.pk])
        publish_storage.assert_called_once_with(args=[storage.pk])

    def test_delete_requested_rows_are_not_interactively_mutable(self):
        storage = _local_storage(self.account, self.member)
        storage.status = CoreStorage.Status.DELETE_REQUESTED
        storage.save(update_fields=["status", "modified"])
        request = SimpleNamespace(user=SimpleNamespace(member=self.member))

        for view_class in (CoreStorageLocalView, CoreStorageView):
            with self.subTest(view=view_class.__name__):
                view = view_class()
                view.request = request
                self.assertFalse(view.get_queryset().filter(pk=storage.pk).exists())

        node = factories.make_website_node(self.account, self.member)
        node.status = node.Status.DELETE_REQUESTED
        node.save(update_fields=["status", "modified"])
        node_view = CoreNodeView()
        node_view.request = request
        self.assertFalse(node_view.get_queryset().filter(pk=node.pk).exists())

    def test_node_delete_protected_backup_restores_visible_paused_node(self):
        storage = _local_storage(self.account, self.member, no_delete=True)
        backup, _point = _website_point(
            self.member, storage, storage_file_id="/backups/protected.zip"
        )
        node = backup.website.node
        node.status = node.Status.DELETE_REQUESTED
        node.flag_delete_node = True
        node.save(update_fields=["status", "flag_delete_node", "modified"])

        self.assertEqual(
            _delete_requested_node(node.pk, "local"),
            {"result": "protected", "node_id": node.pk},
        )
        node.refresh_from_db()
        backup.refresh_from_db()
        self.assertEqual(node.status, node.Status.PAUSED)
        self.assertEqual(backup.status, UtilBackup.Status.COMPLETE)
        self.assertEqual(
            backup.metadata["_deletion_request"]["state"],
            "deferred_protected",
        )
        self.assertFalse(node.flag_delete_node)

    def test_local_and_cloud_node_delete_lanes_cannot_adopt_each_other(self):
        node = factories.make_website_node(self.account, self.member)
        node.status = node.Status.DELETE_REQUESTED
        node.flag_delete_node = True
        node.save(update_fields=["status", "flag_delete_node", "modified"])

        with self.assertRaisesRegex(RuntimeError, "local deletion lane"):
            _delete_requested_node(node.pk, "cloud")

    def test_api_prepares_schedule_cleanup_before_publishing_local_delete(self):
        from django_celery_beat.models import PeriodicTask

        node = factories.make_website_node(self.account, self.member)
        schedule = factories.make_schedule(node, self.member)
        schedule.schedule_create()
        periodic_task_id = schedule.celery_periodic_task_id
        view = CoreNodeView()
        view.get_object = lambda: node
        request = SimpleNamespace(user=self.user)

        with mock.patch(
            "apps.api.v1.node.views.delete_local_node_requested.apply_async"
        ) as publish, mock.patch(
            "apps.api.v1.node.views._log_activity"
        ), self.captureOnCommitCallbacks(execute=True):
            response = view.delete(request, pk=node.pk)

        self.assertEqual(response.status_code, 202)
        node.refresh_from_db()
        self.assertEqual(node.status, node.Status.DELETE_REQUESTED)
        self.assertTrue(node.flag_delete_node)
        self.assertFalse(node.schedules.exists())
        self.assertFalse(PeriodicTask.objects.filter(pk=periodic_task_id).exists())
        publish.assert_called_once_with(args=[node.pk])

    def test_api_delete_is_durable_async_and_broker_payload_is_id_only(self):
        storage = _local_storage(self.account, self.member)
        backup, _point = _website_point(self.member, storage)
        view = VisibleNodeBackupMixin()
        view.backup_model = CoreWebsiteBackup
        view.backup_delete_model_key = "website"

        with mock.patch(
            "apps.api.v1.backup.mixins.delete_backup_requested.apply_async"
        ) as publish, self.captureOnCommitCallbacks(execute=True):
            response = view.request_backup_delete(backup)

        self.assertEqual(response.status_code, 202)
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_REQUESTED)
        self.assertEqual(
            backup.metadata["_deletion_request"]["previous_status"],
            int(UtilBackup.Status.COMPLETE),
        )
        publish.assert_called_once_with(args=["website", backup.pk])

    def test_protected_delete_restores_visible_state_and_stops_recovery(self):
        storage = _local_storage(self.account, self.member, no_delete=True)
        backup, point = _website_point(
            self.member, storage, storage_file_id="/backups/protected.zip"
        )
        backup.status = UtilBackup.Status.DELETE_REQUESTED
        backup.metadata = {
            "_deletion_request": {
                "previous_status": int(UtilBackup.Status.COMPLETE)
            }
        }
        backup.save(update_fields=["status", "metadata", "modified"])

        self.assertEqual(
            _delete_backup_requested_id("website", backup.pk),
            {"result": "protected"},
        )
        backup.refresh_from_db()
        point.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.COMPLETE)
        self.assertEqual(
            backup.metadata["_deletion_request"]["state"],
            "deferred_protected",
        )
        self.assertIn("deletion_protection", point.metadata)

        with mock.patch.object(
            CoreWebsiteBackupStoragePoints,
            "soft_delete",
            side_effect=AssertionError("protected delete must not be swept"),
        ):
            self.assertEqual(
                _delete_backup_requested_id("website", backup.pk),
                {"result": "not_requested"},
            )

    def test_local_delete_derives_path_from_persisted_point_and_verifies_bytes(self):
        with tempfile.TemporaryDirectory() as root, override_settings(
            LOCAL_STORAGE_ROOT=root
        ):
            storage = _local_storage(self.account, self.member)
            backup, point = _website_point(self.member, storage)
            payload = b"owned-local-backup"
            target = os.path.join(root, f"{backup.uuid_str}.zip")
            with open(target, "wb") as output:
                output.write(payload)
            point.storage_file_id = target
            point.metadata = {
                "local_object": {
                    "object_key": os.path.basename(target),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                    "checksum_algorithm": "sha256",
                }
            }
            point.save(update_fields=["storage_file_id", "metadata", "modified"])
            backup.status = UtilBackup.Status.DELETE_REQUESTED
            backup.metadata = {
                "_deletion_request": {
                    "previous_status": int(UtilBackup.Status.COMPLETE)
                }
            }
            backup.save(update_fields=["status", "metadata", "modified"])

            self.assertEqual(
                _delete_backup_requested_id("website", backup.pk),
                {"result": "deleted"},
            )
            self.assertFalse(os.path.exists(target))
            backup.refresh_from_db()
            self.assertEqual(backup.status, UtilBackup.Status.DELETE_COMPLETED)


class LocalStorageDeleteConcurrencyTests(TransactionTestCase):
    def setUp(self):
        # TransactionTestCase flushes rows between methods. Seed only the
        # reference records this concurrency fixture needs instead of relying
        # on serialized_rollback, which conflicts with other transactional
        # suites that also restore Django's content types.
        CoreStorageType.objects.get_or_create(
            code="local",
            defaults={"name": "Local", "is_enabled": True},
        )
        CoreIntegration.objects.get_or_create(
            code="website",
            defaults={"name": "Website", "type": CoreIntegration.Type.WEBSITE},
        )
        self.account, self.member, _user = factories.make_account()
        self.storage = _local_storage(self.account, self.member)
        CoreConnectionLocation.objects.get_or_create(
            code="test-loc", defaults={"id": 999999}
        )
        self.backup, self.point = _website_point(self.member, self.storage)
        self.backup.status = UtilBackup.Status.DELETE_REQUESTED
        self.backup.metadata = {
            "_deletion_request": {
                "previous_status": int(UtilBackup.Status.COMPLETE)
            }
        }
        self.backup.save(update_fields=["status", "metadata", "modified"])

    def test_duplicate_delivery_observes_committed_claim_and_mutates_once(self):
        entered = threading.Event()
        release = threading.Event()
        call_count = 0
        count_lock = threading.Lock()

        def controlled_delete(point):
            nonlocal call_count
            with count_lock:
                call_count += 1
            entered.set()
            self.assertTrue(release.wait(timeout=10))
            point.status = point.Status.DELETE_COMPLETED
            point.save(update_fields=["status", "modified"])
            return True

        def invoke():
            close_old_connections()
            try:
                return _delete_backup_requested_id("website", self.backup.pk)
            finally:
                close_old_connections()

        with mock.patch.object(
            CoreWebsiteBackupStoragePoints,
            "soft_delete",
            autospec=True,
            side_effect=controlled_delete,
        ), ThreadPoolExecutor(max_workers=2) as pool:
            winner = pool.submit(invoke)
            self.assertTrue(entered.wait(timeout=10))
            duplicate = pool.submit(invoke)
            duplicate_result = duplicate.result(timeout=10)
            with count_lock:
                self.assertEqual(call_count, 1)
            release.set()
            self.assertEqual(winner.result(timeout=10), {"result": "deleted"})
            self.assertEqual(duplicate_result, {"result": "busy"})

        self.backup.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.DELETE_COMPLETED)
        self.assertEqual(call_count, 1)

    def test_expired_crash_claim_is_recovered_without_long_transaction(self):
        token, result = _claim_backup_deletion(
            CoreWebsiteBackup, self.backup.pk, "crashed-worker"
        )
        self.assertIsNotNone(token)
        self.assertEqual(result, "claimed")
        crashed = CoreWebsiteBackup.objects.get(pk=self.backup.pk)
        metadata = dict(crashed.metadata)
        claim = dict(metadata["_deletion_claim"])
        claim["expires_at"] = "2000-01-01T00:00:00+00:00"
        metadata["_deletion_claim"] = claim
        crashed.metadata = metadata
        crashed.save(update_fields=["metadata", "modified"])

        with mock.patch.object(
            CoreWebsiteBackupStoragePoints,
            "soft_delete",
            autospec=True,
            return_value=True,
        ) as mutate:
            self.assertEqual(
                _delete_backup_requested_id(
                    "website", self.backup.pk, owner="recovery-worker"
                ),
                {"result": "deleted"},
            )

        mutate.assert_called_once()
        self.backup.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.DELETE_COMPLETED)

    def test_crash_after_mutation_keeps_committed_parent_and_point_fences(self):
        observations = []

        def mutate_then_crash(point):
            observations.append(connection.in_atomic_block)
            persisted_backup = CoreWebsiteBackup.objects.get(pk=self.backup.pk)
            persisted_point = CoreWebsiteBackupStoragePoints.objects.get(
                pk=self.point.pk
            )
            self.assertEqual(
                persisted_backup.status, UtilBackup.Status.DELETE_IN_PROGRESS
            )
            self.assertEqual(
                persisted_point.status,
                CoreWebsiteBackupStoragePoints.Status.DELETE_REQUESTED,
            )
            self.assertTrue(persisted_point.upload_lease_token)
            raise _SimulatedWorkerCrash

        with mock.patch.object(
            CoreWebsiteBackupStoragePoints,
            "soft_delete",
            autospec=True,
            side_effect=mutate_then_crash,
        ), self.assertRaises(_SimulatedWorkerCrash):
            _delete_backup_requested_id(
                "website", self.backup.pk, owner="crashed-after-mutation"
            )

        self.assertEqual(observations, [False])
        self.backup.refresh_from_db()
        self.point.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.DELETE_IN_PROGRESS)
        self.assertEqual(
            self.backup.metadata["_deletion_claim"]["owner"],
            "crashed-after-mutation",
        )
        self.assertEqual(
            self.point.upload_lease_owner, "crashed-after-mutation"
        )
        self.assertTrue(self.point.upload_lease_token)

    def test_storage_wide_delete_mutates_only_one_point_outside_transaction(self):
        _second_backup, second_point = _website_point(self.member, self.storage)
        self.storage.status = CoreStorage.Status.DELETE_REQUESTED
        self.storage.save(update_fields=["status", "modified"])
        mutated_ids = []

        def complete_one(point):
            mutated_ids.append(point.pk)
            self.assertFalse(connection.in_atomic_block)
            point.status = point.Status.DELETE_COMPLETED
            point.save(update_fields=["status", "modified"])
            return True

        with mock.patch.object(
            CoreWebsiteBackupStoragePoints,
            "soft_delete",
            autospec=True,
            side_effect=complete_one,
        ), mock.patch(
            "apps._tasks.integration.storage.tasks.delete_storage_requested.apply_async"
        ) as publish:
            self.assertEqual(
                _delete_storage_requested_id(
                    self.storage.pk, owner="storage-delete-one-point"
                ),
                {"result": "pending"},
            )

        self.assertEqual(mutated_ids, [self.point.pk])
        self.storage.refresh_from_db()
        self.point.refresh_from_db()
        second_point.refresh_from_db()
        self.assertEqual(self.storage.status, CoreStorage.Status.DELETE_REQUESTED)
        self.assertEqual(
            self.point.status, CoreWebsiteBackupStoragePoints.Status.DELETE_COMPLETED
        )
        self.assertEqual(
            second_point.status,
            CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
        )
        publish.assert_called_once_with(args=[self.storage.pk])

    def test_crash_point_lease_blocks_replay_until_reconciliation_window(self):
        _parent_token, result = _claim_backup_deletion(
            CoreWebsiteBackup, self.backup.pk, "crashed-worker"
        )
        self.assertEqual(result, "claimed")
        point_token, result = _claim_storage_point_delete(
            "website", self.point.pk, "crashed-worker"
        )
        self.assertIsNotNone(point_token)
        self.assertEqual(result, "claimed")

        crashed = CoreWebsiteBackup.objects.get(pk=self.backup.pk)
        metadata = dict(crashed.metadata)
        claim = dict(metadata["_deletion_claim"])
        claim["expires_at"] = "2000-01-01T00:00:00+00:00"
        metadata["_deletion_claim"] = claim
        crashed.metadata = metadata
        crashed.save(update_fields=["metadata", "modified"])

        with mock.patch.object(
            CoreWebsiteBackupStoragePoints,
            "soft_delete",
            side_effect=AssertionError("live point claim must block replay"),
        ):
            self.assertEqual(
                _delete_backup_requested_id(
                    "website", self.backup.pk, owner="early-recovery"
                ),
                {"result": "busy"},
            )

        point = CoreWebsiteBackupStoragePoints.objects.get(pk=self.point.pk)
        point.upload_lease_expires_at = timezone.now() - timedelta(seconds=1)
        point.save(update_fields=["upload_lease_expires_at", "modified"])
        with mock.patch.object(
            CoreWebsiteBackupStoragePoints,
            "soft_delete",
            autospec=True,
            return_value=True,
        ) as reconcile:
            self.assertEqual(
                _delete_backup_requested_id(
                    "website", self.backup.pk, owner="late-recovery"
                ),
                {"result": "deleted"},
            )
        reconcile.assert_called_once()
