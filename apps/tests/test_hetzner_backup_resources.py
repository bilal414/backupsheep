"""Hetzner Cloud snapshot/recovery safety tests.

These tests mock the provider boundary.  The live create/restore/cleanup matrix is
kept in ``scripts/hetzner_cloud_e2e.py`` so the unit suite never needs credentials.
"""

from types import SimpleNamespace
from unittest import mock

from django.conf import settings

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.integration.restore import restore_cloud_backup
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.api.v1.utils.http import requests
from apps.console.backup.models import CoreCloudRestore, CoreHetznerBackup
from apps.console.connection.models import CoreAuthHetzner
from apps.console.node.models import CoreHetzner, CoreNode
from apps.console.storage.models import CoreStorageIDrive
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


def response(status_code, payload=None):
    return SimpleNamespace(
        status_code=status_code,
        json=lambda: payload or {},
        close=lambda: None,
    )


def make_hetzner_node(account, member):
    connection = factories.make_connection(account, member, code="hetzner")
    CoreAuthHetzner.objects.create(
        connection=connection,
        api_key=bs_encrypt("hetzner-test-token", account.get_encryption_key()),
    )
    node = CoreNode.objects.create(
        connection=connection,
        type=CoreNode.Type.CLOUD,
        name="hetzner-node",
        added_by=member,
    )
    CoreHetzner.objects.create(node=node, name="hetzner-node", unique_id="server-1")
    return node


def make_backup(node, **kwargs):
    defaults = {
        "uuid": "backup-uuid-1",
        "status": UtilBackup.Status.IN_PROGRESS,
        "attempt_no": 1,
        "type": UtilBackup.Type.ON_DEMAND,
    }
    defaults.update(kwargs)
    return CoreHetznerBackup.objects.create(hetzner=node.hetzner, **defaults)


def source_payload(node):
    return response(
        200,
        {
            "server": {
                "id": node.hetzner.unique_id,
                "status": "running",
                "locked": False,
            }
        },
    )


def ownership_labels(node, backup):
    return {
        CoreHetzner.BACKUP_LABEL_KEY: backup.uuid_str,
        CoreHetzner.BACKUP_SOURCE_LABEL_KEY: str(node.hetzner.unique_id),
        CoreHetzner.BACKUP_ACCOUNT_LABEL_KEY: str(node.connection.account_id),
        CoreHetzner.BACKUP_CONNECTION_LABEL_KEY: str(node.connection_id),
    }


class HetznerDiscoveryTests(BaseTestCase):
    def test_server_discovery_follows_all_pages(self):
        node = make_hetzner_node(self.account, self.member)
        page_one = response(
            200,
            {
                "servers": [{"id": 1, "name": "first", "location": {"name": "fsn1"}}],
                "meta": {"pagination": {"next_page": 2}},
            },
        )
        page_two = response(
            200,
            {
                "servers": [{"id": 2, "name": "second", "location": {"name": "nbg1"}}],
                "meta": {"pagination": {"next_page": None}},
            },
        )
        with mock.patch.object(
            CoreAuthHetzner, "get_client", return_value={"Authorization": "Bearer test"}
        ), mock.patch(
            "apps.console.connection.models.requests.get",
            side_effect=[page_one, page_two],
        ) as get:
            objects = node.connection.auth_hetzner.get_eligible_objects()

        self.assertEqual([item["_bs_unique_id"] for item in objects], [1, 2])
        self.assertEqual(objects[1]["_bs_resource_type"], "server")
        self.assertEqual(get.call_args_list[1].kwargs["params"]["page"], 2)

    def test_volume_discovery_is_rejected_instead_of_claiming_native_support(self):
        node = make_hetzner_node(self.account, self.member)
        with self.assertRaisesMessage(Exception, "native backups are available for server"):
            node.connection.auth_hetzner.get_eligible_objects("volume")


class HetznerSafetyUtilityTests(BaseTestCase):
    def test_snapshot_ambiguity_is_not_silently_selected(self):
        page = response(
            200,
            {
                "images": [
                    {"id": 1, "type": "snapshot", "description": "same"},
                    {"id": 2, "type": "snapshot", "description": "same"},
                ],
                "meta": {"pagination": {"next_page": None}},
            },
        )
        with mock.patch(
            "apps.console.node.models.requests.get", return_value=page
        ):
            with self.assertRaisesMessage(ValueError, "multiple snapshots"):
                CoreHetzner._find_snapshot_by_description(
                    {"Authorization": "Bearer test"}, "same"
                )

    def test_repeated_page_fails_closed(self):
        repeated = response(
            200,
            {"images": [], "meta": {"pagination": {"next_page": 1}}},
        )
        with mock.patch(
            "apps.console.node.models.requests.get", return_value=repeated
        ):
            with self.assertRaisesMessage(Exception, "invalid"):
                CoreHetzner._list_resources(
                    {"Authorization": "Bearer test"}, "images", "images"
                )

    def test_s3_endpoint_normalization_supports_hetzner_and_explicit_urls(self):
        self.assertEqual(
            CoreStorageIDrive.build_endpoint_url("fsn1.your-objectstorage.com"),
            "https://fsn1.your-objectstorage.com",
        )
        self.assertEqual(
            CoreStorageIDrive.build_endpoint_url("https://fsn1.your-objectstorage.com/"),
            "https://fsn1.your-objectstorage.com",
        )


class HetznerSnapshotTests(BaseTestCase):
    def test_lost_create_response_reconciles_snapshot_on_page_two(self):
        node = make_hetzner_node(self.account, self.member)
        backup = make_backup(node)
        first_page = response(
            200,
            {
                "images": [],
                "meta": {"pagination": {"next_page": 2}},
            },
        )
        second_page = response(
            200,
            {
                "images": [
                    {
                        "id": 99,
                        "type": "snapshot",
                        "description": backup.uuid_str,
                        "created_from": {"id": node.hetzner.unique_id},
                        "labels": ownership_labels(node, backup),
                        "status": "available",
                        "disk_size": 10,
                    }
                ],
                "meta": {"pagination": {"next_page": None}},
            },
        )
        with mock.patch.object(
            CoreAuthHetzner, "get_client", return_value={"Authorization": "Bearer test"}
        ), mock.patch(
            "apps.console.node.models.requests.get",
            side_effect=[source_payload(node), first_page, second_page],
        ), mock.patch("apps.console.node.models.requests.post") as post:
            node.hetzner.create_snapshot(backup)

        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "99")
        self.assertEqual(backup.status, UtilBackup.Status.IN_PROGRESS)
        post.assert_not_called()

    def test_create_persists_running_action_and_owned_image(self):
        node = make_hetzner_node(self.account, self.member)
        backup = make_backup(node)
        empty = response(200, {"images": [], "meta": {"pagination": {"next_page": None}}})
        created = response(
            201,
            {
                "image": {
                    "id": 123,
                    "type": "snapshot",
                    "description": backup.uuid_str,
                    "created_from": {"id": node.hetzner.unique_id},
                    "labels": ownership_labels(node, backup),
                    "status": "creating",
                    "disk_size": 20,
                },
                "action": {"id": 456, "status": "running"},
            },
        )
        with mock.patch.object(
            CoreAuthHetzner, "get_client", return_value={"Authorization": "Bearer test"}
        ), mock.patch(
            "apps.console.node.models.requests.get",
            side_effect=[source_payload(node), empty],
        ), mock.patch(
            "apps.console.node.models.requests.post", return_value=created
        ) as post:
            node.hetzner.create_snapshot(backup)

        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "123")
        self.assertEqual(backup.action_id, "456")
        self.assertEqual(backup.size_gigabytes, 20)
        self.assertEqual(
            post.call_args.kwargs["json"],
            {
                "description": backup.uuid_str,
                "type": "snapshot",
                "labels": ownership_labels(node, backup),
            },
        )
        self.assertIn("timeout", post.call_args.kwargs)

    def test_create_rejects_provider_error_without_persisting_an_image(self):
        node = make_hetzner_node(self.account, self.member)
        backup = make_backup(node)
        empty = response(200, {"images": [], "meta": {"pagination": {"next_page": None}}})
        failed = response(
            201,
            {
                "image": {
                    "id": 123,
                    "type": "snapshot",
                    "description": backup.uuid_str,
                    "created_from": {"id": node.hetzner.unique_id},
                    "labels": ownership_labels(node, backup),
                },
                "action": {"id": 456, "status": "error"},
            },
        )
        with mock.patch.object(
            CoreAuthHetzner, "get_client", return_value={"Authorization": "Bearer test"}
        ), mock.patch(
            "apps.console.node.models.requests.get",
            side_effect=[source_payload(node), empty],
        ), mock.patch(
            "apps.console.node.models.requests.post", return_value=failed
        ):
            with self.assertRaises(NodeBackupFailedError):
                node.hetzner.create_snapshot(backup)

        backup.refresh_from_db()
        self.assertFalse(backup.unique_id)

    def test_ambiguous_create_zero_match_never_issues_second_post(self):
        node = make_hetzner_node(self.account, self.member)
        backup = make_backup(node)
        empty = response(
            200, {"images": [], "meta": {"pagination": {"next_page": None}}}
        )
        with mock.patch.object(
            CoreAuthHetzner,
            "get_client",
            return_value={"Authorization": "Bearer test"},
        ), mock.patch(
            "apps.console.node.models.requests.get",
            side_effect=[source_payload(node), empty, source_payload(node), empty],
        ), mock.patch(
            "apps.console.node.models.requests.post",
            side_effect=requests.exceptions.Timeout("lost response"),
        ) as post:
            with self.assertRaises(NodeBackupFailedError):
                node.hetzner.create_snapshot(backup)
            with self.assertRaises(NodeBackupFailedError):
                node.hetzner.create_snapshot(backup)

        post.assert_called_once()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.FAILED)
        state = backup.get_execution_state(create=False)
        self.assertEqual(state.last_error_code, "PROVIDER_RECONCILIATION_REQUIRED")
        self.assertEqual(state.reconciliation_state, "manual_review")

    def test_poll_status_uses_provider_ids_and_maps_available(self):
        node = make_hetzner_node(self.account, self.member)
        backup = make_backup(node, unique_id="123", action_id="456")
        action = response(
            200,
            {
                "action": {
                    "id": 456,
                    "command": "create_image",
                    "status": "success",
                    "resources": [
                        {"id": node.hetzner.unique_id, "type": "server"}
                    ],
                }
            },
        )
        image = response(
            200,
            {
                "image": {
                    "id": 123,
                    "type": "snapshot",
                    "description": backup.uuid_str,
                    "created_from": {"id": node.hetzner.unique_id},
                    "labels": ownership_labels(node, backup),
                    "status": "available",
                    "disk_size": 25,
                }
            },
        )
        with mock.patch.object(
            CoreAuthHetzner, "get_client", return_value={"Authorization": "Bearer test"}
        ), mock.patch(
            "apps.console.backup.models.requests.get", side_effect=[action, image]
        ):
            status = backup.poll_status()

        self.assertEqual(status, UtilBackup.Status.COMPLETE)
        backup.refresh_from_db()
        self.assertEqual(backup.size_gigabytes, 25)

    def test_delete_refuses_wrong_owned_image(self):
        node = make_hetzner_node(self.account, self.member)
        backup = make_backup(
            node,
            unique_id="123",
            status=UtilBackup.Status.DELETE_REQUESTED,
        )
        wrong_image = response(
            200,
            {"image": {"id": 123, "type": "snapshot", "description": "customer-image"}},
        )
        with mock.patch.object(
            CoreAuthHetzner, "get_client", return_value={"Authorization": "Bearer test"}
        ), mock.patch(
            "apps.console.backup.models.requests.get", return_value=wrong_image
        ), mock.patch("apps.console.backup.models.requests.delete") as delete:
            backup.soft_delete()

        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_FAILED)
        delete.assert_not_called()

    def test_delete_lost_response_adopts_absence_without_second_delete(self):
        node = make_hetzner_node(self.account, self.member)
        backup = make_backup(
            node,
            unique_id="123",
            status=UtilBackup.Status.DELETE_REQUESTED,
        )
        owned = response(
            200,
            {
                "image": {
                    "id": 123,
                    "type": "snapshot",
                    "description": backup.uuid_str,
                    "created_from": {"id": node.hetzner.unique_id},
                    "labels": ownership_labels(node, backup),
                    "status": "available",
                }
            },
        )
        with mock.patch.object(
            CoreAuthHetzner,
            "get_client",
            return_value={"Authorization": "Bearer test"},
        ), mock.patch(
            "apps.console.backup.models.requests.get", return_value=owned
        ), mock.patch(
            "apps.console.backup.models.requests.delete",
            side_effect=requests.exceptions.Timeout("lost response"),
        ) as delete:
            self.assertFalse(backup.soft_delete())

        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_IN_PROGRESS)
        delete.assert_called_once()

        absent = response(404, {})
        with mock.patch.object(
            CoreAuthHetzner,
            "get_client",
            return_value={"Authorization": "Bearer test"},
        ), mock.patch(
            "apps.console.backup.models.requests.get", return_value=absent
        ), mock.patch(
            "apps.console.backup.models.requests.delete"
        ) as retry_delete:
            self.assertTrue(backup.soft_delete())

        retry_delete.assert_not_called()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_COMPLETED)


class HetznerRestoreTests(BaseTestCase):
    def test_restore_task_redelivery_resumes_polling_without_provider_create(self):
        node = make_hetzner_node(self.account, self.member)
        backup = make_backup(node, status=UtilBackup.Status.COMPLETE, unique_id="789")
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="restored",
            resource_id="901",
        )
        with mock.patch(
            "apps._tasks.integration.restore.poll_cloud_restore.apply_async"
        ) as poll, mock.patch.object(node.hetzner, "restore_snapshot") as create:
            restore_cloud_backup.run(
                node_id=node.id,
                backup_id=backup.id,
                restore_id=restore.id,
            )

        create.assert_not_called()
        poll.assert_called_once_with(args=[node.id, restore.id], countdown=30)
        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreCloudRestore.Status.IN_PROGRESS)

    def test_restore_adopts_labeled_server_after_ambiguous_create(self):
        node = make_hetzner_node(self.account, self.member)
        backup = make_backup(node, status=UtilBackup.Status.COMPLETE, unique_id="789")
        restore = CoreCloudRestore.objects.create(node=node, backup_id=backup.id, name="restored")
        no_match = response(200, {"servers": [], "meta": {"pagination": {"next_page": None}}})
        source = response(
            200,
            {
                "server": {
                    "id": node.hetzner.unique_id,
                    "server_type": {"name": "cx22"},
                    "location": {"name": "fsn1"},
                }
            },
        )
        created = response(
            201,
            {"server": {"id": 901}, "action": {"id": 902, "status": "running"}},
        )
        with mock.patch.object(
            CoreAuthHetzner, "get_client", return_value={"Authorization": "Bearer test"}
        ), mock.patch(
            "apps.console.node.models.requests.get", side_effect=[no_match, source]
        ), mock.patch(
            "apps.console.node.models.requests.post", return_value=created
        ) as post:
            node.hetzner.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "901")
        self.assertEqual(restore.params["action_id"], 902)
        sent = post.call_args.kwargs["json"]
        self.assertEqual(sent["labels"][CoreHetzner.RESTORE_LABEL_KEY], str(restore.id))
        self.assertEqual(sent["location"], "fsn1")

    def test_restore_redelivery_with_resource_id_does_not_post(self):
        node = make_hetzner_node(self.account, self.member)
        backup = make_backup(node, status=UtilBackup.Status.COMPLETE, unique_id="789")
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="restored",
            resource_id="901",
        )
        with mock.patch.object(
            CoreAuthHetzner, "get_client", return_value={"Authorization": "Bearer test"}
        ), mock.patch("apps.console.node.models.requests.post") as post:
            node.hetzner.restore_snapshot(backup, restore)
        post.assert_not_called()

    def test_check_restore_fails_on_terminal_action_error(self):
        node = make_hetzner_node(self.account, self.member)
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=1,
            name="restored",
            resource_id="901",
            params={"action_id": 902},
        )
        failed = response(200, {"action": {"id": 902, "status": "error"}})
        with mock.patch.object(
            CoreAuthHetzner, "get_client", return_value={"Authorization": "Bearer test"}
        ), mock.patch(
            "apps.console.node.models.requests.get", return_value=failed
        ):
            self.assertEqual(
                node.hetzner.check_restore(restore), CoreCloudRestore.Status.FAILED
            )
