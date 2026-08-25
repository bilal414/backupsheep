from datetime import timedelta
from unittest import mock

from django.utils import timezone

from apps._tasks.helper import tasks as helper_tasks
from apps._tasks.integration.storage.tasks import (
    _prepare_local_backup_destinations_id,
    resume_pending_backup_destination_validations,
)
from apps._tasks.integration.website import backup_website
from apps.console.backup.models import CoreWebsiteBackup
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreWebsite
from apps.console.storage.models import CoreStorage
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class DestinationLaneIsolationTests(BaseTestCase):
    def _source_request(self, node, storage, *, task_id="destination-source-task"):
        return {
            "task_id": task_id,
            "kwargs": {
                "node_id": node.pk,
                "schedule_id": None,
                "storage_ids": [storage.pk],
                "notes": "lane-isolation",
            },
        }

    def _create_unprepared_backup(self, node, storage, *, task_id=None):
        request = self._source_request(
            node,
            storage,
            task_id=task_id or "destination-source-task",
        )
        with mock.patch(
            "apps._tasks.integration.storage.tasks."
            "prepare_local_backup_destinations.apply_async"
        ) as prepare, mock.patch.object(
            CoreConnection, "validate"
        ) as connection_validate, mock.patch.object(
            CoreWebsite, "create_snapshot"
        ) as snapshot:
            backup_website.apply(
                kwargs=request["kwargs"], task_id=request["task_id"]
            )
        backup = CoreWebsiteBackup.objects.get(
            celery_task_id=request["task_id"]
        )
        prepare.assert_called_once_with(
            args=["website", backup.pk],
            task_id=CoreNode.local_destination_preparation_task_id(backup),
        )
        connection_validate.assert_not_called()
        snapshot.assert_not_called()
        return request, backup

    def test_source_stops_then_storage_authorizes_and_republishes_stable_task(self):
        node = factories.make_website_node(self.account, self.member)
        storage = factories.make_storage(
            self.account, self.member, bucket="destination-lane-success"
        )
        request, backup = self._create_unprepared_backup(node, storage)

        with mock.patch.object(
            CoreStorage, "validate", return_value=True
        ) as validate, mock.patch(
            "apps._tasks.integration.storage.tasks.current_app.send_task"
        ) as send_task:
            result = _prepare_local_backup_destinations_id(
                "website", backup.pk
            )

        self.assertEqual(result, {"result": "published"})
        validate.assert_called_once_with()
        send_task.assert_called_once()
        _args, publish = send_task.call_args
        self.assertEqual(_args, ("backup_website",))
        self.assertEqual(publish["task_id"], request["task_id"])
        self.assertEqual(publish["kwargs"]["storage_ids"], [storage.pk])
        self.assertTrue(publish["kwargs"]["resume"])

        point = backup.stored_website_backups.get(storage_id=storage.pk)
        witness = point.metadata["_backup_destination_authorization"]
        self.assertEqual(witness["state"], "complete")
        self.assertTrue(witness["requirements_satisfied"])
        self.assertEqual(witness["source_task_id"], request["task_id"])
        self.assertEqual(witness["accepted_count"], 1)

        with mock.patch.object(
            CoreStorage,
            "validate",
            side_effect=AssertionError("source lane read a storage credential"),
        ), mock.patch.object(
            CoreConnection, "validate", return_value=True
        ) as connection_validate, mock.patch.object(
            CoreWebsite, "create_snapshot"
        ) as snapshot:
            backup_website.apply(
                kwargs=publish["kwargs"], task_id=request["task_id"]
            )
        connection_validate.assert_called_once_with()
        snapshot.assert_called_once()

    def test_source_writable_setup_flag_cannot_forge_storage_authorization(self):
        node = factories.make_website_node(self.account, self.member)
        storage = factories.make_storage(
            self.account, self.member, bucket="destination-lane-forgery"
        )
        request, backup = self._create_unprepared_backup(
            node, storage, task_id="forged-destination-source-task"
        )
        metadata = dict(backup.metadata or {})
        metadata["_backup_destination_setup"] = {
            "state": "complete",
            "requested_count": 1,
            "accepted_count": 1,
        }
        backup.metadata = metadata
        backup.save(update_fields=["metadata", "modified"])

        with mock.patch(
            "apps._tasks.integration.storage.tasks."
            "prepare_local_backup_destinations.apply_async"
        ) as prepare, mock.patch.object(
            CoreConnection, "validate"
        ) as connection_validate, mock.patch.object(
            CoreWebsite, "create_snapshot"
        ) as snapshot:
            backup_website.apply(
                kwargs=request["kwargs"], task_id=request["task_id"]
            )
        prepare.assert_called_once()
        connection_validate.assert_not_called()
        snapshot.assert_not_called()

    def test_rejected_destination_is_terminal_before_source_access(self):
        node = factories.make_website_node(self.account, self.member)
        storage = factories.make_storage(
            self.account, self.member, bucket="destination-lane-rejected"
        )
        _request, backup = self._create_unprepared_backup(
            node, storage, task_id="rejected-destination-source-task"
        )

        with mock.patch.object(
            CoreStorage, "validate", return_value=False
        ), mock.patch.object(
            CoreNode, "notify_storage_validation_fail"
        ), mock.patch(
            "apps._tasks.integration.storage.tasks.current_app.send_task"
        ) as send_task:
            result = _prepare_local_backup_destinations_id(
                "website", backup.pk
            )
        self.assertEqual(result, {"result": "rejected"})
        send_task.assert_not_called()
        backup.refresh_from_db()
        self.assertEqual(
            backup.status, UtilBackup.Status.STORAGE_VALIDATION_FAILED
        )
        self.assertEqual(
            backup.get_execution_state().last_error_code,
            "NO_VALID_STORAGE_DESTINATION",
        )

    def test_storage_sweep_recovers_lost_preparation_publish(self):
        node = factories.make_website_node(self.account, self.member)
        storage = factories.make_storage(
            self.account, self.member, bucket="destination-lane-recovery"
        )
        _request, backup = self._create_unprepared_backup(
            node, storage, task_id="recover-destination-source-task"
        )
        with mock.patch(
            "apps._tasks.integration.storage.tasks."
            "prepare_local_backup_destinations.apply_async"
        ) as prepare:
            result = resume_pending_backup_destination_validations.apply().get()
        self.assertIn(("website", backup.pk), result)
        prepare.assert_called_once_with(
            args=["website", backup.pk],
            task_id=CoreNode.local_destination_preparation_task_id(backup),
        )

    def test_existing_source_recovery_closes_post_authorization_publish_gap(self):
        node = factories.make_website_node(self.account, self.member)
        storage = factories.make_storage(
            self.account, self.member, bucket="destination-source-recovery"
        )
        request, backup = self._create_unprepared_backup(
            node, storage, task_id="recover-source-after-destination-task"
        )
        with mock.patch.object(
            CoreStorage, "validate", return_value=True
        ), mock.patch(
            "apps._tasks.integration.storage.tasks.current_app.send_task",
            side_effect=OSError("broker unavailable"),
        ):
            with self.assertRaisesRegex(OSError, "broker unavailable"):
                _prepare_local_backup_destinations_id("website", backup.pk)

        backup.refresh_from_db()
        self.assertTrue(node.authorized_local_destination_point_ids(backup))
        CoreWebsiteBackup.objects.filter(pk=backup.pk).update(
            modified=timezone.now() - timedelta(hours=1)
        )
        with mock.patch.object(
            helper_tasks.current_app, "send_task"
        ) as send_task:
            helper_tasks.resume_in_progress_files_backups.apply()
        send_task.assert_called_once()
        self.assertEqual(send_task.call_args.args[0], "backup_website")
        self.assertEqual(
            send_task.call_args.kwargs["task_id"], request["task_id"]
        )
