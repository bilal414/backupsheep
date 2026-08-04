"""Vultr block-storage (VOLUME) snapshot support + instance-snapshot regression tests.

Covers CoreVultr.create_snapshot (VOLUME branch + JSON-body fix on the CLOUD branch)
and CoreVultrBackup.poll_status / soft_delete branching on node type. All HTTP is
mocked -- no real Vultr API calls.
"""
import uuid
from types import SimpleNamespace
from unittest import mock

import requests
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
        empty_listing = _response(200, {"snapshots": [], "meta": {"total": 0}})
        with mock.patch("apps.console.node.models.requests.get",
                        return_value=empty_listing), mock.patch(
            "apps.console.node.models.requests.post",
            return_value=_response(201, payload),
        ) as post:
            node.vultr.create_snapshot(backup)
        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "bs-snap-1")
        self.assertEqual(backup.metadata["id"], payload["id"])
        self.assertEqual(
            backup.metadata["vultr_ownership"],
            {"source_id": "block-1", "source_key": "block_id"},
        )
        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], f"{settings.VULTR_API}/v2/blocks/snapshots")
        self.assertEqual(
            post.call_args.kwargs["json"],
            {"block_id": "block-1", "description": backup.uuid_str},
        )

    def test_volume_create_api_error_raises_node_backup_failed(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node)
        empty_listing = _response(200, {"snapshots": [], "meta": {"total": 0}})
        with mock.patch("apps.console.node.models.requests.get",
                        return_value=empty_listing), mock.patch(
            "apps.console.node.models.requests.post",
            return_value=_response(500),
        ):
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
        empty_listing = _response(200, {"snapshots": [], "meta": {"total": 0}})
        with mock.patch("apps.console.node.models.requests.get",
                        return_value=empty_listing), mock.patch(
            "apps.console.node.models.requests.post",
            return_value=_response(201, payload),
        ) as post:
            node.vultr.create_snapshot(backup)
        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "snap-1")
        self.assertEqual(backup.metadata["id"], payload["snapshot"]["id"])
        self.assertEqual(
            backup.metadata["vultr_ownership"],
            {"source_id": "instance-1", "source_key": "instance_id"},
        )
        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], f"{settings.VULTR_API}/v2/snapshots")
        self.assertEqual(
            post.call_args.kwargs["json"],
            {"instance_id": "instance-1", "description": backup.uuid_str},
        )
        self.assertNotIn("data", post.call_args.kwargs)


class VultrPollStatusTests(BaseTestCase):
    def test_volume_poll_complete_marks_backup_complete(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node, unique_id="bs-snap-1")
        payload = {
            "id": "bs-snap-1", "block_id": "block-1",
            "description": backup.uuid_str,
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
        payload = {
            "id": "bs-snap-1", "block_id": "block-1",
            "description": backup.uuid_str, "state": "PENDING",
        }
        with mock.patch("apps.console.backup.models.requests.get",
                        return_value=_response(200, payload)):
            status = backup.poll_status()
        self.assertEqual(status, UtilBackup.Status.IN_PROGRESS)
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.IN_PROGRESS)

    def test_volume_poll_pending_create_stays_in_progress(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node, unique_id="bs-snap-1")
        payload = {
            "id": "bs-snap-1", "block_id": "block-1",
            "description": backup.uuid_str, "state": "PENDING_CREATE",
        }
        with mock.patch("apps.console.backup.models.requests.get",
                        return_value=_response(200, payload)):
            status = backup.poll_status()
        self.assertEqual(status, UtilBackup.Status.IN_PROGRESS)

    def test_volume_poll_uses_state_when_provider_status_is_null(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node, unique_id="bs-snap-1")
        payload = {
            "id": "bs-snap-1", "block_id": "block-1",
            "description": backup.uuid_str, "status": None,
            "state": "COMPLETE", "size": 10737418240,
        }
        with mock.patch("apps.console.backup.models.requests.get",
                        return_value=_response(200, payload)):
            status = backup.poll_status()
        self.assertEqual(status, UtilBackup.Status.COMPLETE)

    def test_volume_poll_uses_state_when_provider_status_is_null_like_string(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node, unique_id="bs-snap-1")
        payload = {
            "id": "bs-snap-1", "block_id": "block-1",
            "description": backup.uuid_str, "status": "None",
            "state": "COMPLETE", "size": 10737418240,
        }
        with mock.patch("apps.console.backup.models.requests.get",
                        return_value=_response(200, payload)):
            status = backup.poll_status()
        self.assertEqual(status, UtilBackup.Status.COMPLETE)

    def test_volume_poll_treats_missing_provider_state_as_in_progress(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node, unique_id="bs-snap-1")
        payload = {
            "id": "bs-snap-1", "block_id": "block-1",
            "description": backup.uuid_str,
        }
        with mock.patch("apps.console.backup.models.requests.get",
                        return_value=_response(200, payload)):
            status = backup.poll_status()
        self.assertEqual(status, UtilBackup.Status.IN_PROGRESS)

    def test_instance_poll_complete_unchanged(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.CLOUD)
        backup = make_vultr_backup(node, unique_id="snap-1")
        payload = {"snapshot": {
            "id": "snap-1", "instance_id": "instance-1",
            "description": backup.uuid_str, "status": "complete", "size": 10737418240,
        }}
        with mock.patch("apps.console.backup.models.requests.get",
                        return_value=_response(200, payload)) as get:
            status = backup.poll_status()
        self.assertEqual(status, UtilBackup.Status.COMPLETE)
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.COMPLETE)
        self.assertEqual(backup.size_gigabytes, 10.74)
        self.assertEqual(get.call_args.args[0],
                         f"{settings.VULTR_API}/v2/snapshots/snap-1")

    def test_instance_poll_complete_accepts_vultr_omitted_source_after_create_proof(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.CLOUD)
        backup = make_vultr_backup(
            node,
            unique_id="snap-1",
            metadata={
                "vultr_ownership": {
                    "source_id": "instance-1",
                    "source_key": "instance_id",
                }
            },
        )
        payload = {"snapshot": {
            "id": "snap-1", "instance_id": None,
            "description": backup.uuid_str, "status": "complete", "size": 10737418240,
        }}
        with mock.patch("apps.console.backup.models.requests.get",
                        return_value=_response(200, payload)):
            status = backup.poll_status()
        self.assertEqual(status, UtilBackup.Status.COMPLETE)
        backup.refresh_from_db()
        self.assertTrue(backup.metadata["vultr_ownership_verified"])


class VultrSoftDeleteTests(BaseTestCase):
    def test_volume_soft_delete_uses_block_snapshot_endpoint(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(
            node, unique_id="bs-snap-1", status=UtilBackup.Status.DELETE_REQUESTED)
        owned = _response(200, {
            "id": "bs-snap-1", "block_id": "block-1",
            "description": backup.uuid_str, "state": "COMPLETE",
        })
        with mock.patch("apps.console.backup.models.requests.get", return_value=owned), mock.patch(
            "apps.console.backup.models.requests.delete",
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
        owned = _response(200, {"snapshot": {
            "id": "snap-1", "instance_id": "instance-1",
            "description": backup.uuid_str, "status": "complete",
        }})
        with mock.patch("apps.console.backup.models.requests.get", return_value=owned), mock.patch(
            "apps.console.backup.models.requests.delete",
                        return_value=_response(204)) as delete:
            backup.soft_delete()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_COMPLETED)
        self.assertEqual(delete.call_args.args[0],
                         f"{settings.VULTR_API}/v2/snapshots/snap-1")


class VultrSnapshotSafetyTests(BaseTestCase):
    def test_create_follows_cursor_to_find_existing_snapshot(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node)
        first = _response(200, {"snapshots": [], "meta": {"links": {"next": "cursor-1"}}})
        second = _response(200, {"snapshots": [{
            "id": "bs-snap-1", "block_id": "block-1", "description": backup.uuid_str,
        }], "meta": {"links": {"next": None}}})
        with mock.patch("apps.console.node.models.requests.get", side_effect=[first, second]) as get, \
                mock.patch("apps.console.node.models.requests.post") as post:
            node.vultr.create_snapshot(backup)
        self.assertEqual(backup.refresh_from_db() or backup.unique_id, "bs-snap-1")
        post.assert_not_called()
        self.assertEqual(get.call_args_list[1].kwargs["params"]["cursor"], "cursor-1")
        self.assertIn("timeout", get.call_args_list[0].kwargs)

    def test_create_rejects_repeated_cursor_and_does_not_post(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.CLOUD)
        backup = make_vultr_backup(node)
        response = _response(200, {"snapshots": [], "meta": {"links": {"next": "same"}}})
        with mock.patch("apps.console.node.models.requests.get", side_effect=[response, response]) as get, \
                mock.patch("apps.console.node.models.requests.post") as post:
            with self.assertRaises(NodeBackupFailedError):
                node.vultr.create_snapshot(backup)
        post.assert_not_called()
        self.assertEqual(get.call_count, 2)

    def test_create_rejects_duplicate_descriptions(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.CLOUD)
        backup = make_vultr_backup(node)
        listing = _response(200, {"snapshots": [
            {"id": "snap-1", "instance_id": "instance-1", "description": backup.uuid_str},
            {"id": "snap-2", "instance_id": "instance-1", "description": backup.uuid_str},
        ]})
        with mock.patch("apps.console.node.models.requests.get", return_value=listing), \
                mock.patch("apps.console.node.models.requests.post") as post:
            with self.assertRaises(NodeBackupFailedError):
                node.vultr.create_snapshot(backup)
        post.assert_not_called()

    def test_create_rejects_source_mismatch(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node)
        listing = _response(200, {"snapshots": [{
            "id": "snap-1", "block_id": "foreign-block", "description": backup.uuid_str,
        }]})
        with mock.patch("apps.console.node.models.requests.get", return_value=listing), \
                mock.patch("apps.console.node.models.requests.post") as post:
            with self.assertRaises(NodeBackupFailedError):
                node.vultr.create_snapshot(backup)
        post.assert_not_called()

    def test_poll_rejects_unowned_snapshot(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node, unique_id="bs-snap-1")
        response = _response(200, {
            "id": "bs-snap-1", "block_id": "foreign-block", "description": backup.uuid_str,
            "state": "COMPLETE",
        })
        with mock.patch("apps.console.backup.models.requests.get", return_value=response):
            self.assertEqual(backup.poll_status(), UtilBackup.Status.FAILED)
        backup.refresh_from_db()
        self.assertEqual(backup.metadata["vultr_last_result"]["classification"], "ownership_mismatch")

    def test_poll_404_is_terminal_missing(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.CLOUD)
        backup = make_vultr_backup(node, unique_id="snap-1")
        with mock.patch("apps.console.backup.models.requests.get", return_value=_response(404)):
            self.assertEqual(backup.poll_status(), UtilBackup.Status.FAILED)
        backup.refresh_from_db()
        self.assertEqual(backup.metadata["vultr_last_result"]["classification"], "missing")

    def test_poll_rate_limit_and_provider_outage_remain_resumable(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.CLOUD)
        for code, classification in ((429, "rate_limited"), (503, "transient_provider_error")):
            backup = make_vultr_backup(node, unique_id=f"snap-{code}")
            with mock.patch("apps.console.backup.models.requests.get", return_value=_response(code)) as get:
                self.assertEqual(backup.poll_status(), UtilBackup.Status.IN_PROGRESS)
            self.assertEqual(get.call_args.kwargs["timeout"], (10, 60))
            backup.refresh_from_db()
            self.assertEqual(backup.metadata["vultr_last_result"]["classification"], classification)

    def test_poll_timeout_is_resumable_and_classified(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.CLOUD)
        backup = make_vultr_backup(node, unique_id="snap-timeout")
        with mock.patch("apps.console.backup.models.requests.get", side_effect=requests.Timeout):
            self.assertEqual(backup.poll_status(), UtilBackup.Status.IN_PROGRESS)
        backup.refresh_from_db()
        self.assertEqual(
            backup.metadata["vultr_last_result"]["classification"], "transient_client_error"
        )

    def test_delete_refuses_unowned_snapshot_without_delete_call(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.CLOUD)
        backup = make_vultr_backup(
            node, unique_id="snap-1", status=UtilBackup.Status.DELETE_REQUESTED
        )
        response = _response(200, {"snapshot": {
            "id": "snap-1", "instance_id": "foreign-instance", "description": backup.uuid_str,
        }})
        with mock.patch("apps.console.backup.models.requests.get", return_value=response), \
                mock.patch("apps.console.backup.models.requests.delete") as delete:
            backup.soft_delete()
        delete.assert_not_called()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_FAILED)

    def test_delete_404_is_idempotent_only_after_prior_ownership_proof(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.CLOUD)
        unproven = make_vultr_backup(
            node, unique_id="snap-unproven", status=UtilBackup.Status.DELETE_REQUESTED
        )
        proven = make_vultr_backup(
            node, unique_id="snap-proven", status=UtilBackup.Status.DELETE_REQUESTED,
            metadata={"vultr_ownership_verified": True},
        )
        with mock.patch("apps.console.backup.models.requests.get", return_value=_response(404)):
            unproven.soft_delete()
        with mock.patch("apps.console.backup.models.requests.get", return_value=_response(404)):
            proven.soft_delete()
        unproven.refresh_from_db()
        proven.refresh_from_db()
        self.assertEqual(unproven.status, UtilBackup.Status.DELETE_FAILED)
        self.assertEqual(proven.status, UtilBackup.Status.DELETE_COMPLETED)


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
        with mock.patch(
            "apps.console.node.models.requests.get",
            return_value=_response(200, {"blocks": [], "meta": {}}),
        ), mock.patch("apps.console.node.models.requests.post",
                      return_value=_response(201, {"block": {"id": "block-new"}})) as post:
            node.vultr.restore_snapshot(backup, restore)
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "block-new")
        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], f"{settings.VULTR_API}/v2/blocks")
        self.assertEqual(
            post.call_args.kwargs["json"],
            {
                "region": "ewr",
                "size_gb": 80,
                "snapshot_id": "bs-snap-1",
                "label": restore.restore_marker,
            },
        )

    def test_volume_restore_falls_back_to_source_block_details(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node, unique_id="bs-snap-1", status=UtilBackup.Status.COMPLETE)
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=backup.id, name="restored-vol",
        )
        with mock.patch("apps.console.node.models.requests.get", side_effect=[
                    _response(200, {"block": {"region": "lax", "size_gb": 40}}),
                    _response(200, {"blocks": [], "meta": {}}),
                ]) as get, \
                mock.patch("apps.console.node.models.requests.post",
                           return_value=_response(201, {"block": {"id": "block-new"}})) as post:
            node.vultr.restore_snapshot(backup, restore)
        self.assertIn(
            f"{settings.VULTR_API}/v2/blocks/block-1",
            [call.args[0] for call in get.call_args_list],
        )
        self.assertEqual(post.call_args.kwargs["json"]["region"], "lax")
        self.assertEqual(post.call_args.kwargs["json"]["size_gb"], 40)

    def test_volume_restore_raises_on_provider_error(self):
        node = make_vultr_node(self.account, self.member, node_type=CoreNode.Type.VOLUME)
        backup = make_vultr_backup(node, unique_id="bs-snap-1", status=UtilBackup.Status.COMPLETE)
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=backup.id, name="restored-vol",
            params={"region": "ewr", "size_gb": 80},
        )
        with mock.patch(
            "apps.console.node.models.requests.get",
            return_value=_response(200, {"blocks": [], "meta": {}}),
        ), mock.patch("apps.console.node.models.requests.post",
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
