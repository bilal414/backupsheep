"""Crash-safe Vultr restore adoption tests.

All provider HTTP is mocked.  These tests deliberately exercise the response
loss and database-save failure windows; they never contact Vultr.
"""
from types import SimpleNamespace
from unittest import mock

import requests

from apps._tasks.integration.restore import restore_cloud_backup
from apps.console.backup.models import CoreCloudRestore
from apps.console.node.models import CoreNode
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from apps.tests.test_vultr_volume_backup import make_vultr_backup, make_vultr_node


def response(status_code, payload=None):
    return SimpleNamespace(
        status_code=status_code,
        json=lambda: payload if payload is not None else {},
        text="provider response",
    )


class VultrRestoreRecoveryTests(BaseTestCase):
    def _restore(self, node_type=CoreNode.Type.CLOUD, **params):
        node = make_vultr_node(self.account, self.member, node_type=node_type)
        backup = make_vultr_backup(
            node, status=UtilBackup.Status.COMPLETE, unique_id="snapshot-1"
        )
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=backup.id, name="restored", params=params or None
        )
        return node, backup, restore

    def _instance(self, restore, *, status="pending", resource_id="instance-1"):
        return {
            "id": resource_id,
            "status": status,
            "tags": [restore.restore_marker],
            "snapshot_id": "snapshot-1",
            "region": "ewr",
            "plan": "vc2-1c-1gb",
        }

    def test_marker_is_committed_before_create_and_post_has_timeout(self):
        node, backup, restore = self._restore(
            region="ewr", plan="vc2-1c-1gb"
        )
        with mock.patch(
            "apps.console.node.models.requests.get",
            return_value=response(200, {"instances": [], "meta": {}}),
        ), mock.patch(
            "apps.console.node.models.requests.post",
            return_value=response(201, {"instance": {"id": "instance-1"}}),
        ) as post:
            node.vultr.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertTrue(restore.restore_marker.startswith("backupsheep-restore-"))
        self.assertEqual(len(restore.request_fingerprint), 64)
        self.assertEqual(
            restore.operation_phase, CoreCloudRestore.OperationPhase.POLLING
        )
        self.assertEqual(post.call_args.kwargs["timeout"], (10, 60))
        self.assertIn(restore.restore_marker, post.call_args.kwargs["json"]["tags"])
        self.assertEqual(post.call_args.kwargs["json"]["snapshot_id"], "snapshot-1")

    def test_lost_response_is_adopted_on_next_delivery_without_duplicate_post(self):
        node, backup, restore = self._restore(
            region="ewr", plan="vc2-1c-1gb"
        )
        with mock.patch(
            "apps.console.node.models.requests.get",
            return_value=response(200, {"instances": [], "meta": {}}),
        ), mock.patch(
            "apps.console.node.models.requests.post",
            side_effect=requests.Timeout("worker lost after provider accepted request"),
        ):
            # The adapter treats a network failure as an unknown create outcome.
            result = node.vultr.restore_snapshot(backup, restore)
        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)

        restore.refresh_from_db()
        self.assertIsNone(restore.resource_id)
        self.assertEqual(
            restore.operation_phase, CoreCloudRestore.OperationPhase.CREATE_UNKNOWN
        )

        owned = self._instance(restore)
        with mock.patch(
            "apps.console.node.models.requests.get",
            return_value=response(200, {"instances": [owned], "meta": {}}),
        ), mock.patch("apps.console.node.models.requests.post") as post:
            node.vultr.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "instance-1")
        post.assert_not_called()

    def test_database_save_crash_after_post_is_adopted_after_redelivery(self):
        node, backup, restore = self._restore(
            region="ewr", plan="vc2-1c-1gb"
        )
        original_save = CoreCloudRestore.save
        save_count = 0

        def crash_on_provider_save(instance, *args, **kwargs):
            nonlocal save_count
            save_count += 1
            if save_count == 2:
                raise RuntimeError("worker crashed before persisting resource id")
            return original_save(instance, *args, **kwargs)

        with mock.patch(
            "apps.console.node.models.requests.get",
            return_value=response(200, {"instances": [], "meta": {}}),
        ), mock.patch(
            "apps.console.node.models.requests.post",
            return_value=response(201, {"instance": {"id": "instance-1"}}),
        ), mock.patch.object(CoreCloudRestore, "save", crash_on_provider_save):
            with self.assertRaises(RuntimeError):
                node.vultr.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertIsNone(restore.resource_id)
        self.assertTrue(restore.restore_marker)

        with mock.patch(
            "apps.console.node.models.requests.get",
            return_value=response(200, {"instances": [self._instance(restore)], "meta": {}}),
        ), mock.patch("apps.console.node.models.requests.post") as post:
            node.vultr.restore_snapshot(backup, restore)
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "instance-1")
        post.assert_not_called()

    def test_duplicate_owned_candidates_fail_closed_for_manual_review(self):
        node, backup, restore = self._restore(
            region="ewr", plan="vc2-1c-1gb"
        )
        # First call seeds the marker and intentionally returns a transient
        # response so the create path is not reached.
        with mock.patch(
            "apps.console.node.models.requests.get",
            return_value=response(429),
        ):
            self.assertEqual(
                node.vultr.restore_snapshot(backup, restore),
                CoreCloudRestore.Status.IN_PROGRESS,
            )
        restore.refresh_from_db()
        candidates = [self._instance(restore, resource_id="one"), self._instance(restore, resource_id="two")]
        with mock.patch(
            "apps.console.node.models.requests.get",
            return_value=response(200, {"instances": candidates, "meta": {}}),
        ), mock.patch("apps.console.node.models.requests.post") as post:
            with self.assertRaises(Exception):
                node.vultr.restore_snapshot(backup, restore)
        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
        self.assertEqual(
            restore.operation_phase, CoreCloudRestore.OperationPhase.MANUAL_REVIEW
        )
        post.assert_not_called()

    def test_transient_status_checks_remain_resumable(self):
        node, backup, restore = self._restore(
            region="ewr", plan="vc2-1c-1gb"
        )
        restore.restore_marker = "backupsheep-restore-1-marker"
        restore.request_fingerprint = "f" * 64
        restore.resource_id = "instance-1"
        restore.params = {"region": "ewr", "plan": "vc2-1c-1gb"}
        restore.save()
        for status_code in (429, 503):
            with mock.patch(
                "apps.console.node.models.requests.get",
                return_value=response(status_code),
            ):
                self.assertEqual(
                    node.vultr.check_restore(restore),
                    CoreCloudRestore.Status.IN_PROGRESS,
                )
            restore.refresh_from_db()
            self.assertEqual(
                restore.operation_phase, CoreCloudRestore.OperationPhase.POLLING
            )

    def test_terminal_status_and_ownership_mismatch_fail(self):
        node, backup, restore = self._restore(
            region="ewr", plan="vc2-1c-1gb"
        )
        restore.restore_marker = "backupsheep-restore-1-marker"
        restore.request_fingerprint = "f" * 64
        restore.resource_id = "instance-1"
        restore.params = {"region": "ewr", "plan": "vc2-1c-1gb"}
        restore.save()

        foreign = self._instance(restore, status="active")
        foreign["tags"] = ["foreign-marker"]
        with mock.patch(
            "apps.console.node.models.requests.get",
            return_value=response(200, {"instance": foreign}),
        ):
            self.assertEqual(
                node.vultr.check_restore(restore), CoreCloudRestore.Status.FAILED
            )
        restore.refresh_from_db()
        self.assertEqual(
            restore.operation_phase, CoreCloudRestore.OperationPhase.MANUAL_REVIEW
        )

    def test_persisted_resource_id_redelivery_only_polls(self):
        node, backup, restore = self._restore()
        restore.resource_id = "instance-1"
        restore.status = CoreCloudRestore.Status.IN_PROGRESS
        restore.save()
        with mock.patch(
            "apps._tasks.integration.restore.poll_cloud_restore.apply_async"
        ) as poll, mock.patch.object(node.vultr, "restore_snapshot") as create:
            restore_cloud_backup.run(
                node_id=node.id, backup_id=backup.id, restore_id=restore.id
            )
        create.assert_not_called()
        poll.assert_called_once_with(args=[node.id, restore.id], countdown=60)
