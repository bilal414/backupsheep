"""Vultr block-storage (VOLUME) snapshot support + instance-snapshot regression tests.

Covers CoreVultr.create_snapshot (VOLUME branch + JSON-body fix on the CLOUD branch)
and CoreVultrBackup.poll_status / soft_delete branching on node type. All HTTP is
mocked -- no real Vultr API calls.
"""
import uuid
from types import SimpleNamespace
from unittest import mock

from django.conf import settings

from apps._tasks.exceptions import NodeBackupFailedError
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import CoreCloudRestore, CoreVultrBackup
from apps.console.connection.models import CoreAuthVultr
from apps.console.node.models import CoreNode, CoreVultr
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


def make_vultr_node(account, member, *, node_type):
    """Vultr counterpart of factories.make_cloud_node: CoreConnection (code "vultr")
    + CoreAuthVultr (bs_encrypt'ed api key so get_client() works offline) + node of
    the given type + CoreVultr row."""
    conn = factories.make_connection(account, member, code="vultr")
    CoreAuthVultr.objects.create(
        connection=conn, api_key=bs_encrypt("vultr-test-key", account.get_encryption_key())
    )
    node = CoreNode.objects.create(
        connection=conn, type=node_type, name="vultr-node", added_by=member,
    )
    unique_id = "block-1" if node_type == CoreNode.Type.VOLUME else "instance-1"
    CoreVultr.objects.create(node=node, name="vultr-node", unique_id=unique_id)
    return node


def make_vultr_backup(node, **kwargs):
    defaults = dict(
        vultr=node.vultr, uuid=f"t{uuid.uuid4().hex}",
        status=UtilBackup.Status.IN_PROGRESS, attempt_no=1,
        type=UtilBackup.Type.ON_DEMAND,
    )
    defaults.update(kwargs)
    return CoreVultrBackup.objects.create(**defaults)


def _response(status_code, payload=None):
    return SimpleNamespace(
        status_code=status_code, json=lambda: payload or {}, close=lambda: None
    )


class VultrVolumeCreateSnapshotTests(BaseTestCase):
    def test_volume_create_sets_unique_id_and_metadata(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node)
        payload = {
            "id": "bs-snap-1",
            "block_id": "block-1",
            "description": backup.uuid_str,
            "state": "PENDING",
            "size": 10737418240,
        }
        with mock.patch("apps.console.node.models.requests.post",
                        return_value=_response(201, payload)) as post:
            node.vultr.create_snapshot(backup)
        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "bs-snap-1")
        self.assertEqual(backup.metadata, payload)
        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], f"{settings.VULTR_API}/v2/blocks/snapshots")
        self.assertEqual(
            post.call_args.kwargs["json"],
            {"block_id": "block-1", "description": backup.uuid_str},
        )

    def test_volume_create_api_error_raises_node_backup_failed(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node)
        with mock.patch("apps.console.node.models.requests.post",
                        return_value=_response(500)):
            with self.assertRaises(NodeBackupFailedError):
                node.vultr.create_snapshot(backup)
        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "")


class VultrInstanceCreateSnapshotTests(BaseTestCase):
    """Regression: the instance branch must keep working, now with a JSON body."""

    def test_instance_create_sends_json_body_and_sets_unique_id(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.CLOUD)
        backup = make_vultr_backup(node)
        payload = {"snapshot": {"id": "snap-1", "status": "pending"}}
        with mock.patch("apps.console.node.models.requests.post",
                        return_value=_response(201, payload)) as post:
            node.vultr.create_snapshot(backup)
        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "snap-1")
        self.assertEqual(backup.metadata, payload["snapshot"])
        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], f"{settings.VULTR_API}/v2/snapshots")
        self.assertEqual(
            post.call_args.kwargs["json"],
            {"instance_id": "instance-1", "description": node.name},
        )
        self.assertNotIn("data", post.call_args.kwargs)


class VultrPollStatusTests(BaseTestCase):
    def test_volume_poll_complete_marks_backup_complete(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node, unique_id="bs-snap-1")
        payload = {
            "id": "bs-snap-1", "block_id": "block-1",
            "state": "COMPLETE", "size": 10737418240,
        }
        with mock.patch("apps.console.backup.models.requests.get",
                        return_value=_response(200, payload)) as get:
            status = backup.poll_status()
        self.assertEqual(status, UtilBackup.Status.COMPLETE)
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.COMPLETE)
        self.assertEqual(backup.size_gigabytes, 10.74)
        self.assertEqual(get.call_args.args[0],
                         f"{settings.VULTR_API}/v2/blocks/snapshots/bs-snap-1")

    def test_volume_poll_pending_stays_in_progress(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node, unique_id="bs-snap-1")
        payload = {"id": "bs-snap-1", "block_id": "block-1", "state": "PENDING"}
        with mock.patch("apps.console.backup.models.requests.get",
                        return_value=_response(200, payload)):
            status = backup.poll_status()
        self.assertEqual(status, UtilBackup.Status.IN_PROGRESS)
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.IN_PROGRESS)

    def test_instance_poll_complete_unchanged(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.CLOUD)
        backup = make_vultr_backup(node, unique_id="snap-1")
        payload = {"snapshot": {"id": "snap-1", "status": "complete", "size": 10737418240}}
        with mock.patch("apps.console.backup.models.requests.get",
                        return_value=_response(200, payload)) as get:
            status = backup.poll_status()
        self.assertEqual(status, UtilBackup.Status.COMPLETE)
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.COMPLETE)
        self.assertEqual(backup.size_gigabytes, 10.74)
        self.assertEqual(get.call_args.args[0],
                         f"{settings.VULTR_API}/v2/snapshots/snap-1")


class VultrSoftDeleteTests(BaseTestCase):
    def test_volume_soft_delete_uses_block_snapshot_endpoint(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(
            node, unique_id="bs-snap-1", status=UtilBackup.Status.DELETE_REQUESTED)
        with mock.patch("apps.console.backup.models.requests.delete",
                        return_value=_response(204)) as delete:
            backup.soft_delete()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_COMPLETED)
        self.assertEqual(delete.call_args.args[0],
                         f"{settings.VULTR_API}/v2/blocks/snapshots/bs-snap-1")

    def test_instance_soft_delete_uses_snapshot_endpoint(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.CLOUD)
        backup = make_vultr_backup(
            node, unique_id="snap-1", status=UtilBackup.Status.DELETE_REQUESTED)
        with mock.patch("apps.console.backup.models.requests.delete",
                        return_value=_response(204)) as delete:
            backup.soft_delete()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_COMPLETED)
        self.assertEqual(delete.call_args.args[0],
                         f"{settings.VULTR_API}/v2/snapshots/snap-1")


class VultrVolumeRestoreTests(BaseTestCase):
    """CoreVultr.restore_snapshot / check_restore VOLUME branch: a block snapshot
    is restored by creating a new volume via POST /v2/blocks with snapshot_id."""

    def test_volume_restore_posts_block_with_snapshot_id(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node, unique_id="bs-snap-1", status=UtilBackup.Status.COMPLETE)
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=backup.id, name="restored-vol",
            params={"region": "ewr", "size_gb": 80},
        )
        with mock.patch("apps.console.node.models.requests.post",
                        return_value=_response(201, {"block": {"id": "block-new"}})) as post:
            node.vultr.restore_snapshot(backup, restore)
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "block-new")
        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], f"{settings.VULTR_API}/v2/blocks")
        self.assertEqual(
            post.call_args.kwargs["json"],
            {"region": "ewr", "size_gb": 80, "snapshot_id": "bs-snap-1", "label": "restored-vol"},
        )

    def test_volume_restore_falls_back_to_source_block_details(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node, unique_id="bs-snap-1", status=UtilBackup.Status.COMPLETE)
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=backup.id, name="restored-vol",
        )
        with mock.patch("apps.console.node.models.requests.get",
                        return_value=_response(200, {"block": {"region": "lax", "size_gb": 40}})) as get, \
                mock.patch("apps.console.node.models.requests.post",
                           return_value=_response(201, {"block": {"id": "block-new"}})) as post:
            node.vultr.restore_snapshot(backup, restore)
        self.assertEqual(get.call_args.args[0], f"{settings.VULTR_API}/v2/blocks/block-1")
        self.assertEqual(post.call_args.kwargs["json"]["region"], "lax")
        self.assertEqual(post.call_args.kwargs["json"]["size_gb"], 40)

    def test_volume_restore_raises_on_provider_error(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node, unique_id="bs-snap-1", status=UtilBackup.Status.COMPLETE)
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=backup.id, name="restored-vol",
            params={"region": "ewr", "size_gb": 80},
        )
        with mock.patch("apps.console.node.models.requests.post",
                        return_value=_response(400)):
            with self.assertRaises(Exception):
                node.vultr.restore_snapshot(backup, restore)
        restore.refresh_from_db()
        self.assertIsNone(restore.resource_id)

    def test_volume_check_restore_maps_block_status(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=1, name="r", resource_id="block-new",
        )
        for block_status, expected in (
            ("active", CoreCloudRestore.Status.COMPLETE),
            ("pending", CoreCloudRestore.Status.IN_PROGRESS),
        ):
            with mock.patch("apps.console.node.models.requests.get",
                            return_value=_response(200, {"block": {"status": block_status}})) as get:
                self.assertEqual(node.vultr.check_restore(restore), expected)
            self.assertEqual(get.call_args.args[0], f"{settings.VULTR_API}/v2/blocks/block-new")

    def test_instance_check_restore_unchanged(self):
        """Regression: the CLOUD branch keeps mapping instance statuses."""
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.CLOUD)
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=1, name="r", resource_id="instance-new",
        )
        for instance_status, expected in (
            ("active", CoreCloudRestore.Status.COMPLETE),
            ("suspended", CoreCloudRestore.Status.FAILED),
            ("pending", CoreCloudRestore.Status.IN_PROGRESS),
        ):
            with mock.patch("apps.console.node.models.requests.get",
                            return_value=_response(200, {"instance": {"status": instance_status}})) as get:
                self.assertEqual(node.vultr.check_restore(restore), expected)
            self.assertEqual(get.call_args.args[0], f"{settings.VULTR_API}/v2/instances/instance-new")
