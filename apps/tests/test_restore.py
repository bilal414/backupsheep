from unittest import mock

from rest_framework.test import APIRequestFactory, force_authenticate

from apps.api.v1.node.views import CoreNodeView
from apps.console.backup.models import CoreCloudRestore
from apps.console.node.models import CoreNode
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


def make_completed_backup(node, **kwargs):
    return node.digitalocean.backups.create(
        status=kwargs.pop("status", UtilBackup.Status.COMPLETE),
        type=UtilBackup.Type.ON_DEMAND,
        unique_id=kwargs.pop("unique_id", "123456"),
        **kwargs,
    )


class RestoreEndpointTests(BaseTestCase):
    def _post(self, node, payload):
        view = CoreNodeView.as_view({"post": "restore_backup"})
        request = APIRequestFactory().post(
            f"/api/v1/nodes/{node.id}/restore_backup/", payload, format="json"
        )
        force_authenticate(request, user=self.user)
        return view(request, pk=node.id)

    def test_missing_params_rejected(self):
        node = factories.make_cloud_node(self.account, self.member)
        resp = self._post(node, {})
        self.assertEqual(resp.status_code, 503)

    def test_unsupported_node_type_rejected(self):
        node = factories.make_website_node(self.account, self.member)
        resp = self._post(node, {"backup_id": 1, "name": "restored"})
        self.assertEqual(resp.status_code, 503)

    def test_unknown_backup_rejected(self):
        node = factories.make_cloud_node(self.account, self.member)
        resp = self._post(node, {"backup_id": 999999, "name": "restored"})
        self.assertEqual(resp.status_code, 404)

    def test_incomplete_backup_rejected(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = make_completed_backup(node, status=UtilBackup.Status.IN_PROGRESS)
        resp = self._post(node, {"backup_id": backup.id, "name": "restored"})
        self.assertEqual(resp.status_code, 404)

    def test_restore_creates_record_and_dispatches_task(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = make_completed_backup(node)
        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as dispatch:
            resp = self._post(
                node, {"backup_id": backup.id, "name": "restored", "params": {"size": "s-1vcpu-1gb"}}
            )
        self.assertEqual(resp.status_code, 201)
        dispatch.assert_called_once()

        restore = CoreCloudRestore.objects.get(node=node)
        self.assertEqual(restore.backup_id, backup.id)
        self.assertEqual(restore.name, "restored")
        self.assertEqual(restore.params, {"size": "s-1vcpu-1gb"})
        self.assertEqual(restore.status, CoreCloudRestore.Status.PENDING)
        self.assertEqual(resp.data["name"], "restored")
        self.assertEqual(resp.data["status_display"], "Pending")

    def test_restores_list_scoped_to_node(self):
        node = factories.make_cloud_node(self.account, self.member)
        other = factories.make_cloud_node(self.account, self.member)
        CoreCloudRestore.objects.create(node=node, backup_id=1, name="mine")
        CoreCloudRestore.objects.create(node=other, backup_id=2, name="theirs")

        view = CoreNodeView.as_view({"get": "restores"})
        request = APIRequestFactory().get(f"/api/v1/nodes/{node.id}/restores/")
        force_authenticate(request, user=self.user)
        resp = view(request, pk=node.id)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data), 1)
        self.assertEqual(resp.data[0]["name"], "mine")


class RestoreDispatchTests(BaseTestCase):
    def test_poll_status_dispatches_to_provider(self):
        node = factories.make_cloud_node(self.account, self.member)
        restore = CoreCloudRestore.objects.create(node=node, backup_id=1, name="r")
        with mock.patch.object(
            type(node.digitalocean), "check_restore", return_value=CoreCloudRestore.Status.COMPLETE
        ):
            self.assertEqual(restore.poll_status(), CoreCloudRestore.Status.COMPLETE)

    def test_poll_status_swallows_transient_errors(self):
        node = factories.make_cloud_node(self.account, self.member)
        restore = CoreCloudRestore.objects.create(node=node, backup_id=1, name="r")
        with mock.patch.object(
            type(node.digitalocean), "check_restore", side_effect=Exception("boom")
        ):
            self.assertEqual(restore.poll_status(), CoreCloudRestore.Status.IN_PROGRESS)

    def test_backup_property_resolves_provider_backup(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = make_completed_backup(node)
        restore = CoreCloudRestore.objects.create(node=node, backup_id=backup.id, name="r")
        self.assertEqual(restore.backup.id, backup.id)


class DigitalOceanRestoreTests(BaseTestCase):
    def _make_node_with_auth(self):
        from apps.console.connection.models import CoreAuthDigitalOcean

        node = factories.make_cloud_node(self.account, self.member)
        CoreAuthDigitalOcean.objects.create(connection=node.connection)
        return node

    def _patch_client(self):
        from apps.console.connection.models import CoreAuthDigitalOcean

        return mock.patch.object(
            CoreAuthDigitalOcean,
            "get_client",
            return_value={"Authorization": "Bearer test-token"},
        )

    def test_restore_snapshot_cloud_creates_droplet_from_snapshot(self):
        node = self._make_node_with_auth()
        backup = make_completed_backup(node)
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=backup.id, name="restored", params={"size": "s-1vcpu-1gb"}
        )

        post_resp = mock.MagicMock(status_code=202)
        post_resp.json.return_value = {"droplet": {"id": 777}}
        with self._patch_client(), \
                mock.patch("apps.console.node.models.requests.post", return_value=post_resp) as post:
            node.digitalocean.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "777")
        sent_json = post.call_args.kwargs["json"]
        self.assertEqual(sent_json["image"], 123456)
        self.assertEqual(sent_json["size"], "s-1vcpu-1gb")
        self.assertEqual(sent_json["name"], "restored")

    def test_restore_snapshot_cloud_size_falls_back_to_source_droplet(self):
        node = self._make_node_with_auth()
        backup = make_completed_backup(node)
        restore = CoreCloudRestore.objects.create(node=node, backup_id=backup.id, name="restored")

        get_resp = mock.MagicMock(status_code=200)
        get_resp.json.return_value = {"droplet": {"size_slug": "s-2vcpu-2gb"}}
        post_resp = mock.MagicMock(status_code=202)
        post_resp.json.return_value = {"droplet": {"id": 778}}
        with self._patch_client(), \
                mock.patch("apps.console.node.models.requests.get", return_value=get_resp), \
                mock.patch("apps.console.node.models.requests.post", return_value=post_resp) as post:
            node.digitalocean.restore_snapshot(backup, restore)

        self.assertEqual(post.call_args.kwargs["json"]["size"], "s-2vcpu-2gb")

    def test_restore_snapshot_raises_on_provider_error(self):
        node = self._make_node_with_auth()
        backup = make_completed_backup(node)
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=backup.id, name="restored", params={"size": "s-1vcpu-1gb"}
        )
        post_resp = mock.MagicMock(status_code=422, text="unprocessable")
        with self._patch_client(), \
                mock.patch("apps.console.node.models.requests.post", return_value=post_resp):
            with self.assertRaises(Exception):
                node.digitalocean.restore_snapshot(backup, restore)

    def test_check_restore_maps_droplet_states(self):
        node = self._make_node_with_auth()
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=1, name="r", resource_id="777"
        )
        for droplet_status, expected in (
            ("active", CoreCloudRestore.Status.COMPLETE),
            ("new", CoreCloudRestore.Status.IN_PROGRESS),
            ("off", CoreCloudRestore.Status.IN_PROGRESS),
        ):
            get_resp = mock.MagicMock(status_code=200)
            get_resp.json.return_value = {"droplet": {"status": droplet_status}}
            with self._patch_client(), \
                    mock.patch("apps.console.node.models.requests.get", return_value=get_resp):
                self.assertEqual(node.digitalocean.check_restore(restore), expected)
