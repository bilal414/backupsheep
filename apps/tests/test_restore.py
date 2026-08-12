import io
import hashlib
import os
import stat
import tempfile
from types import SimpleNamespace
from unittest import mock

from rest_framework.test import APIRequestFactory, force_authenticate

from apps._tasks.exceptions import IntegrationValidationError
from apps.api.v1.utils.http import request_timeout
from apps.api.v1.node.views import CoreNodeView
from apps.console.backup.models import CoreCloudRestore
from apps.console.connection.models import CoreAuthDatabase
from apps.console.connection.models import CoreAuthLightsail, CoreLightsailRegion
from apps.console.node.models import CoreNode
from apps.console.node.models import CoreLightsail
from apps.console.node.models import _prepare_cloud_restore
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from apps.tests.test_backup_engine import make_database_node


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
        resp = self._post(
            node,
            {"backup_id": 999999, "name": "restored", "confirm": True},
        )
        self.assertEqual(resp.status_code, 404)

    def test_incomplete_backup_rejected(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = make_completed_backup(node, status=UtilBackup.Status.IN_PROGRESS)
        resp = self._post(
            node,
            {"backup_id": backup.id, "name": "restored", "confirm": True},
        )
        self.assertEqual(resp.status_code, 404)

    def test_restore_creates_record_and_dispatches_task(self):
        node = factories.make_cloud_node(self.account, self.member)
        backup = make_completed_backup(node)
        with mock.patch(
            "apps._tasks.integration.restore.restore_cloud_backup.apply_async"
        ) as dispatch, self.captureOnCommitCallbacks(execute=True):
            resp = self._post(
                node,
                {
                    "backup_id": backup.id,
                    "name": "restored",
                    "params": {"size": "s-1vcpu-1gb"},
                    "confirm": True,
                },
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

    def test_poll_status_propagates_unclassified_errors_to_task_classifier(self):
        node = factories.make_cloud_node(self.account, self.member)
        restore = CoreCloudRestore.objects.create(node=node, backup_id=1, name="r")
        with mock.patch.object(
            type(node.digitalocean), "check_restore", side_effect=Exception("boom")
        ):
            with self.assertRaisesRegex(Exception, "boom"):
                restore.poll_status()

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
            "get_verified_client",
            return_value={"Authorization": "Bearer test-token"},
        )

    @staticmethod
    def _restore_identity(node, backup, restore):
        target_kind = "droplet" if node.type == CoreNode.Type.CLOUD else "volume"
        marker, _params = _prepare_cloud_restore(
            restore,
            provider="digitalocean",
            source_id=backup.unique_id,
            target_kind=target_kind,
            target_name=restore.name,
        )
        identity, _params = node.digitalocean._prepare_digitalocean_restore_identity(
            restore,
            marker=marker,
            source_id=backup.unique_id,
            target_kind=target_kind,
        )
        return identity

    def _make_volume_node_with_auth(self):
        from apps.console.connection.models import CoreAuthDigitalOcean

        node = factories.make_cloud_node(
            self.account,
            self.member,
            node_type=CoreNode.Type.VOLUME,
        )
        node.digitalocean.unique_id = "source-volume"
        node.digitalocean.save(update_fields=["unique_id", "modified"])
        CoreAuthDigitalOcean.objects.create(connection=node.connection)
        return node

    @staticmethod
    def _owned_droplet(node, backup, restore, *, resource_id, status="new"):
        identity = DigitalOceanRestoreTests._restore_identity(
            node, backup, restore
        )
        return {
            "id": resource_id,
            "name": identity["target_name"],
            "tags": [
                identity["marker"],
                identity["source_tag"],
                identity["kind_tag"],
            ],
            "image": {"id": int(backup.unique_id)},
            "status": status,
        }

    @staticmethod
    def _owned_volume(node, backup, restore, *, resource_id, status="new"):
        identity = DigitalOceanRestoreTests._restore_identity(
            node, backup, restore
        )
        return {
            "id": resource_id,
            "name": identity["target_name"],
            "tags": [
                identity["marker"],
                identity["source_tag"],
                identity["kind_tag"],
            ],
            "snapshot_id": str(backup.unique_id),
            "status": status,
        }

    def test_restore_snapshot_cloud_creates_droplet_from_snapshot(self):
        node = self._make_node_with_auth()
        backup = make_completed_backup(node)
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=backup.id, name="restored", params={"size": "s-1vcpu-1gb"}
        )

        post_resp = mock.MagicMock(status_code=202)
        post_resp.json.return_value = {
            "droplet": self._owned_droplet(
                node, backup, restore, resource_id=777
            )
        }
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
        get_resp.json.return_value = {
            "droplet": {
                "id": node.digitalocean.unique_id,
                "size_slug": "s-2vcpu-2gb",
            }
        }
        post_resp = mock.MagicMock(status_code=202)
        post_resp.json.return_value = {
            "droplet": self._owned_droplet(
                node, backup, restore, resource_id=778
            )
        }
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
        backup = make_completed_backup(node)
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=backup.id, name="r", resource_id="777"
        )
        self._restore_identity(node, backup, restore)
        for droplet_status, expected in (
            ("active", CoreCloudRestore.Status.COMPLETE),
            ("new", CoreCloudRestore.Status.IN_PROGRESS),
            ("off", CoreCloudRestore.Status.COMPLETE),
        ):
            get_resp = mock.MagicMock(status_code=200)
            get_resp.json.return_value = {
                "droplet": self._owned_droplet(
                    node,
                    backup,
                    restore,
                    resource_id=777,
                    status=droplet_status,
                )
            }
            with self._patch_client(), \
                    mock.patch("apps.console.node.models.requests.get", return_value=get_resp):
                self.assertEqual(node.digitalocean.check_restore(restore), expected)

    def test_restore_snapshot_volume_uses_snapshot_and_atomic_identity_tags(self):
        node = self._make_volume_node_with_auth()
        backup = make_completed_backup(node, unique_id="volume-snapshot-123")
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="restored-volume",
            params={"region": "nyc3"},
        )
        post_resp = mock.MagicMock(status_code=202)
        post_resp.json.return_value = {
            "volume": self._owned_volume(
                node, backup, restore, resource_id="restored-volume-1"
            )
        }

        with self._patch_client(), mock.patch(
            "apps.console.node.models.requests.post", return_value=post_resp
        ) as post:
            node.digitalocean.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "restored-volume-1")
        self.assertEqual(
            post.call_args.args[0], "https://api.digitalocean.com/v2/volumes"
        )
        sent_json = post.call_args.kwargs["json"]
        identity = self._restore_identity(node, backup, restore)
        self.assertEqual(sent_json["snapshot"], backup.unique_id)
        self.assertNotIn("snapshot_id", sent_json)
        self.assertEqual(
            sent_json["tags"],
            [identity["marker"], identity["source_tag"], identity["kind_tag"]],
        )
        self.assertEqual(post.call_args.kwargs["timeout"], request_timeout())

    def test_restore_snapshot_volume_requires_exact_snapshot_and_source_tag(self):
        node = self._make_volume_node_with_auth()
        backup = make_completed_backup(node, unique_id="volume-snapshot-123")

        cases = (
            ("wrong-snapshot", {"snapshot_id": "foreign-snapshot"}),
            ("missing-source-tag", {"remove_source_tag": True}),
        )
        for suffix, mutation in cases:
            with self.subTest(case=suffix):
                restore = CoreCloudRestore.objects.create(
                    node=node,
                    backup_id=backup.id,
                    name=f"restored-{suffix}",
                    params={"region": "nyc3"},
                )
                volume = self._owned_volume(
                    node, backup, restore, resource_id=f"target-{suffix}"
                )
                identity = self._restore_identity(node, backup, restore)
                if mutation.get("remove_source_tag"):
                    volume["tags"].remove(identity["source_tag"])
                volume.update(
                    {
                        key: value
                        for key, value in mutation.items()
                        if key != "remove_source_tag"
                    }
                )
                post_resp = mock.MagicMock(status_code=202)
                post_resp.json.return_value = {"volume": volume}

                with self._patch_client(), mock.patch(
                    "apps.console.node.models.requests.post", return_value=post_resp
                ) as post:
                    result = node.digitalocean.restore_snapshot(backup, restore)

                restore.refresh_from_db()
                self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
                self.assertIsNone(restore.resource_id)
                self.assertTrue(restore.params["_bs_create_outcome_unknown"])
                self.assertEqual(post.call_count, 1)

    def test_restore_snapshot_volume_lost_response_adopts_one_exact_target_without_replay(self):
        node = self._make_volume_node_with_auth()
        backup = make_completed_backup(node, unique_id="volume-snapshot-123")
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="restored-volume",
            params={"region": "nyc3"},
        )
        with self._patch_client(), mock.patch(
            "apps.console.node.models.requests.post",
            side_effect=TimeoutError("lost response"),
        ) as post:
            first = node.digitalocean.restore_snapshot(backup, restore)
            restore.refresh_from_db()
            candidate = self._owned_volume(
                node, backup, restore, resource_id="adopted-volume-1", status="creating"
            )
            with mock.patch.object(
                node.digitalocean,
                "_find_restore_resource",
                return_value=[candidate],
            ):
                second = node.digitalocean.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(first, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertFalse(restore.params["_bs_create_outcome_unknown"])
        self.assertIsNone(second)
        self.assertEqual(restore.resource_id, "adopted-volume-1")
        self.assertEqual(post.call_count, 1)

    def test_restore_snapshot_volume_lost_response_rejects_duplicate_targets_without_replay(self):
        node = self._make_volume_node_with_auth()
        backup = make_completed_backup(node, unique_id="volume-snapshot-123")
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="restored-volume",
            params={"region": "nyc3"},
        )
        with self._patch_client(), mock.patch(
            "apps.console.node.models.requests.post",
            side_effect=TimeoutError("lost response"),
        ) as post:
            node.digitalocean.restore_snapshot(backup, restore)
            restore.refresh_from_db()
            first = self._owned_volume(
                node, backup, restore, resource_id="duplicate-volume-1"
            )
            second = self._owned_volume(
                node, backup, restore, resource_id="duplicate-volume-2"
            )
            with mock.patch.object(
                node.digitalocean,
                "_find_restore_resource",
                return_value=[first, second],
            ):
                with self.assertRaises(Exception) as raised:
                    node.digitalocean.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(
            getattr(raised.exception, "code", None), "PROVIDER_DUPLICATE_MATCH"
        )
        self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
        self.assertEqual(
            restore.params["_bs_last_error_code"], "PROVIDER_DUPLICATE_MATCH"
        )
        self.assertIsNone(restore.resource_id)
        self.assertEqual(post.call_count, 1)

    def test_restore_snapshot_volume_lost_response_rejects_foreign_target_without_replay(self):
        node = self._make_volume_node_with_auth()
        backup = make_completed_backup(node, unique_id="volume-snapshot-123")
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="restored-volume",
            params={"region": "nyc3"},
        )
        with self._patch_client(), mock.patch(
            "apps.console.node.models.requests.post",
            side_effect=TimeoutError("lost response"),
        ) as post:
            node.digitalocean.restore_snapshot(backup, restore)
            restore.refresh_from_db()
            foreign = self._owned_volume(
                node, backup, restore, resource_id="foreign-volume-1"
            )
            foreign["snapshot_id"] = "foreign-snapshot"
            with mock.patch.object(
                node.digitalocean,
                "_find_restore_resource",
                return_value=[foreign],
            ):
                with self.assertRaises(Exception) as raised:
                    node.digitalocean.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(
            getattr(raised.exception, "code", None), "PROVIDER_OWNERSHIP_MISMATCH"
        )
        self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
        self.assertEqual(
            restore.params["_bs_last_error_code"], "PROVIDER_OWNERSHIP_MISMATCH"
        )
        self.assertIsNone(restore.resource_id)
        self.assertEqual(post.call_count, 1)


class LightsailRestoreTests(BaseTestCase):
    def _make_node_with_auth(self, node_type=CoreNode.Type.CLOUD):
        connection = factories.make_connection(self.account, self.member, code="lightsail")
        CoreAuthLightsail.objects.create(
            connection=connection,
            region=CoreLightsailRegion.objects.get(code="us-east-1"),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=node_type,
            name="server",
            added_by=self.member,
        )
        CoreLightsail.objects.create(node=node, name="server", unique_id="source")
        return node

    @staticmethod
    def _backup(node):
        return node.lightsail.backups.create(
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
            unique_id="snapshot",
            size_gigabytes=20,
        )

    def test_restore_cloud_falls_back_from_regional_snapshot_to_source_zone(self):
        node = self._make_node_with_auth()
        backup = self._backup(node)
        restore = CoreCloudRestore.objects.create(node=node, backup_id=backup.id, name="restored")
        client = mock.MagicMock()
        client.get_instance_snapshot.return_value = {
            "instanceSnapshot": {"location": {"availabilityZone": "all"}}
        }
        client.get_instance.return_value = {
            "instance": {
                "bundleId": "nano_3_0",
                "location": {"availabilityZone": "us-east-1a"},
            }
        }

        with mock.patch.object(CoreAuthLightsail, "get_client", return_value=client):
            node.lightsail.restore_snapshot(backup, restore)

        client.create_instances_from_snapshot.assert_called_once_with(
            instanceNames=["restored"],
            instanceSnapshotName="snapshot",
            availabilityZone="us-east-1a",
            bundleId="nano_3_0",
        )
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "restored")

    def test_restore_volume_falls_back_from_regional_snapshot_to_source_zone(self):
        node = self._make_node_with_auth(node_type=CoreNode.Type.VOLUME)
        backup = self._backup(node)
        restore = CoreCloudRestore.objects.create(node=node, backup_id=backup.id, name="restored-disk")
        client = mock.MagicMock()
        client.get_disk_snapshot.return_value = {
            "diskSnapshot": {"location": {"availabilityZone": "all"}}
        }
        client.get_disk.return_value = {
            "disk": {"location": {"availabilityZone": "us-east-1a"}}
        }

        with mock.patch.object(CoreAuthLightsail, "get_client", return_value=client):
            node.lightsail.restore_snapshot(backup, restore)

        client.create_disk_from_snapshot.assert_called_once_with(
            diskName="restored-disk",
            diskSnapshotName="snapshot",
            availabilityZone="us-east-1a",
            sizeInGb=20,
        )
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "restored-disk")


class AuthDatabaseDirectConnectRobustnessTests(BaseTestCase):
    """CoreAuthDatabase direct-connect hardening (FIX 2): the errno-2061 SSL
    hint lives in the shared _direct_mysql_connect helper, stock-MySQL
    dash-less version strings parse without IndexError, and SSH-mode version
    detection never leaves the decrypted temp private key on disk."""

    def _auth(self, *, db_type=CoreAuthDatabase.DatabaseType.MYSQL,
              version="mysql_8_0", use_private_key=False):
        node = make_database_node(
            self.account, self.member, db_type=db_type, version=version,
            use_private_key=use_private_key)
        return node.connection.auth_database

    @staticmethod
    def _db_con(version_string):
        db_con = mock.Mock(name="db_con")
        db_con.cursor.return_value.fetchone.return_value = (version_string,)
        return db_con

    def test_errno_2061_retries_over_ssl_and_raises_clear_hint(self):
        # First connect fails with 2061 (caching_sha2_password over plain
        # transport); the SSL retry succeeds, so the credentials are fine and
        # the user just needs to enable Use SSL/TLS.
        auth = self._auth()
        err = Exception("Authentication plugin 'caching_sha2_password' cannot be used")
        err.errno = 2061
        ssl_con = mock.Mock(name="ssl_con")
        with mock.patch("mysql.connector.connect", side_effect=[err, ssl_con]) as connect:
            with self.assertRaises(IntegrationValidationError) as ctx:
                auth.find_db_type_and_version()
        self.assertIn("Use SSL/TLS", str(ctx.exception))
        self.assertEqual(connect.call_count, 2)
        self.assertIs(connect.call_args_list[0].kwargs.get("ssl_disabled"), True)
        self.assertIs(connect.call_args_list[1].kwargs.get("ssl_disabled"), False)
        ssl_con.close.assert_called_once()

    def test_dashless_stock_mysql_version_parses(self):
        auth = self._auth()
        with mock.patch("mysql.connector.connect", return_value=self._db_con("8.0.36")):
            self.assertEqual(auth.find_db_type_and_version(), "mysql_8_0_36")

    def test_distro_suffixed_mysql_version_parses(self):
        auth = self._auth()
        with mock.patch("mysql.connector.connect",
                        return_value=self._db_con("8.0.36-0ubuntu0.22.04.1")):
            self.assertEqual(auth.find_db_type_and_version(), "mysql_8_0_36")

    def test_vendor_dashed_mariadb_version_slug_unchanged(self):
        auth = self._auth(db_type=CoreAuthDatabase.DatabaseType.MARIADB,
                          version="mariadb_10_11")
        result = "10.11.6-MariaDB-1:10.11.6+maria~ubu2204"
        with mock.patch("mysql.connector.connect", return_value=self._db_con(result)):
            self.assertEqual(auth.find_db_type_and_version(), "mariadb_10_11_6")

    def test_ssh_mode_closes_client_and_removes_temp_key(self):
        auth = self._auth(use_private_key=True)
        sftp = mock.MagicMock()
        sftp.open.side_effect = lambda _name, _mode: io.StringIO()
        ssh = SimpleNamespace(
            exec_command=lambda command, timeout=None: (
                None,
                io.StringIO("8.0.36\n"),
                io.StringIO(""),
            ),
            open_sftp=lambda: sftp,
            close=mock.Mock(),
        )
        fd, key_path = tempfile.mkstemp(dir="_storage", prefix="sshkey_")
        os.write(fd, b"fake-key")
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(key_path) and os.remove(key_path))
        with mock.patch.object(CoreAuthDatabase, "get_ssh_client",
                               return_value=(ssh, key_path)):
            result = auth.find_db_type_and_version()
        self.assertEqual(result, "mysql_8_0")
        ssh.close.assert_called_once()
        self.assertFalse(os.path.exists(key_path))


class AuthDatabaseSSHSSLFlagTests(BaseTestCase):
    """SSH-mode mysql/mariadb commands must be engine-aware about the TLS flag:
    the MariaDB client rejects the MySQL-style --ssl-mode flag (exit 7,
    "unknown variable"), so mariadb gets bare --ssl while mysql keeps
    --ssl-mode=PREFERRED."""

    def _auth(self, db_type, version):
        node = make_database_node(
            self.account, self.member, db_type=db_type, version=version,
            use_private_key=True)
        auth = node.connection.auth_database
        auth.use_ssl = True
        auth.save()
        return auth

    @staticmethod
    def _capture_command(auth, method, stdout_text):
        captured = []
        sftp = mock.MagicMock()

        def open_remote_file(_name, _mode):
            return io.StringIO()

        sftp.open.side_effect = open_remote_file

        def exec_command(command, timeout=None):
            captured.append(command)
            return None, io.StringIO(stdout_text), io.StringIO("")

        ssh = SimpleNamespace(
            exec_command=exec_command,
            open_sftp=lambda: sftp,
            close=mock.Mock(),
        )
        with mock.patch.object(CoreAuthDatabase, "get_ssh_client",
                               return_value=(ssh, None)):
            getattr(auth, method)()
        return captured[0]

    def test_find_version_mariadb_uses_ssl_flag_not_ssl_mode(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.MARIADB, "mariadb_10_11")
        command = self._capture_command(
            auth, "find_db_type_and_version", "10.11.6-MariaDB\n")
        self.assertIn("--ssl", command)
        self.assertNotIn("ssl-mode", command)

    def test_find_version_mysql_keeps_ssl_mode_preferred(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.MYSQL, "mysql_8_0")
        command = self._capture_command(
            auth, "find_db_type_and_version", "8.0.36\n")
        self.assertIn("--ssl-mode=PREFERRED", command)

    def test_check_connection_mariadb_uses_ssl_flag_not_ssl_mode(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.MARIADB, "mariadb_10_11")
        command = self._capture_command(
            auth, "check_connection", "Server version: 10.11.6-MariaDB\n")
        self.assertIn("--ssl", command)
        self.assertNotIn("ssl-mode", command)

    def test_check_connection_mysql_keeps_ssl_mode_preferred(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.MYSQL, "mysql_8_0")
        command = self._capture_command(
            auth, "check_connection", "Server version: 8.0.36\n")
        self.assertIn("--ssl-mode=PREFERRED", command)

    def test_remote_command_never_contains_database_password(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.MYSQL, "mysql_8_0")
        encryption_key = auth.connection.account.get_encryption_key()
        from apps.api.v1.utils.api_helpers import bs_encrypt

        password = "enterprise-secret-value"
        auth.password = bs_encrypt(password, encryption_key)
        auth.save(update_fields=["password", "modified"])
        command = self._capture_command(
            auth, "check_connection", "Server version: 8.0.36\n"
        )
        self.assertNotIn(password, command)
        self.assertIn("--defaults-extra-file", command)


# ---------------------------------------------------------------------------
# Website + database restore backend (fetch/extract helpers, engines, tasks, API)
# ---------------------------------------------------------------------------
import shutil
import tarfile
import uuid
import zipfile

from django.test import override_settings
from django.utils import timezone

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.integration import restore as restore_tasks
from apps._tasks.integration import restore_common
from apps._tasks.integration import restore_database as RD
from apps._tasks.integration import restore_website as RW
from apps._tasks.integration.restore_common import RestoreError
from apps.api.v1.backup.database.views import CoreDatabaseBackupView
from apps.api.v1.backup.website.views import CoreWebsiteBackupView
from apps.console.backup.models import (
    CoreDatabaseBackup,
    CoreDatabaseBackupStoragePoints,
    CoreDatabaseRestore,
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
    CoreWebsiteRestore,
)
from apps.console.connection.models import CoreAuthWebsite
from apps.console.storage.models import CoreStorage, CoreStorageLocal, CoreStorageType
from apps.tests.test_backup_engine import DB_PASS, _cleanup_storage_artifacts


class _FakeResponse:
    """requests.get context-manager stand-in for streamed downloads."""

    def __init__(self, chunks):
        self._chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=1):
        return iter(self._chunks)


class RestoreBackendBase(BaseTestCase):
    """Shared fixture: a temp LOCAL_STORAGE_ROOT, real tiny zips/tars built inside
    it, and cleanup of the _storage/restore_* artifacts the engines drop."""

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        override = override_settings(LOCAL_STORAGE_ROOT=self.tmp)
        override.enable()
        self.addCleanup(override.disable)

    def _make_zip(self, members, name="backup.zip"):
        zip_path = os.path.join(self.tmp, name)
        with zipfile.ZipFile(zip_path, "w") as zf:
            for member_name, data in members.items():
                zf.writestr(member_name, data)
        return zip_path

    def _make_local_storage(self):
        storage = CoreStorage.objects.create(
            account=self.account,
            type=CoreStorageType.objects.get(code="local"),
            name="local-store",
            added_by=self.member,
        )
        CoreStorageLocal.objects.create(storage=storage, path="")
        return storage

    def _website_backup(self, *, all_paths=False, paths=None,
                        status=UtilBackup.Status.COMPLETE):
        node = factories.make_website_node(self.account, self.member)
        website = node.website
        website.all_paths = all_paths
        website.paths = paths
        website.save()
        backup = CoreWebsiteBackup.objects.create(
            website=website, uuid=f"t{uuid.uuid4().hex}",
            status=status, attempt_no=1, type=UtilBackup.Type.ON_DEMAND,
        )
        self.addCleanup(_cleanup_storage_artifacts(
            f"_storage/restore_{backup.uuid_str}.log",
            f"_storage/restore_{backup.uuid_str}.zip",
            f"_storage/restore_{backup.uuid_str}/",
            f"_storage/ssh_restore_{backup.uuid_str}",
        ))
        return node, backup

    def _database_backup(self, *, db_type, version, tables=None, all_tables=True,
                         status=UtilBackup.Status.COMPLETE):
        node = make_database_node(
            self.account, self.member, db_type=db_type, version=version,
            tables=tables, all_tables=all_tables,
        )
        backup = CoreDatabaseBackup.objects.create(
            database=node.database, uuid=f"t{uuid.uuid4().hex}",
            status=status, attempt_no=1, type=UtilBackup.Type.ON_DEMAND,
            tables=tables, all_tables=all_tables,
        )
        self.addCleanup(_cleanup_storage_artifacts(
            f"_storage/restore_{backup.uuid_str}.log",
            f"_storage/restore_{backup.uuid_str}.zip",
            f"_storage/restore_{backup.uuid_str}/",
            f"_storage/my_restore_{backup.uuid_str}.cnf",
        ))
        return node, backup

    def _website_point(self, backup, zip_path, storage=None):
        return CoreWebsiteBackupStoragePoints.objects.create(
            backup=backup, storage=storage or self._make_local_storage(),
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id=zip_path,
        )

    def _database_point(self, backup, zip_path, storage=None):
        return CoreDatabaseBackupStoragePoints.objects.create(
            backup=backup, storage=storage or self._make_local_storage(),
            status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id=zip_path,
        )


class FetchBackupZipTests(RestoreBackendBase):
    @staticmethod
    def _identity(path):
        digest = hashlib.sha256()
        size = 0
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
        return size, digest.hexdigest()

    def _commit_destination(self, stored, path):
        size, checksum = self._identity(path)
        return stored.backup.record_artifact_integrity(
            role="destination",
            object_key=stored.storage_file_id,
            byte_count=size,
            storage=stored.storage,
            checksum_algorithm="sha256",
            checksum_value=checksum,
            verified_at=timezone.now(),
        )

    def test_local_copy(self):
        node, backup = self._website_backup()
        src = self._make_zip({"index.html": "<h1>hi</h1>"})
        stored = self._website_point(backup, src)
        dest = os.path.join(self.tmp, "fetched.zip")
        restore_common.fetch_backup_zip(stored, dest)
        with zipfile.ZipFile(dest) as zf:
            self.assertEqual(zf.read("index.html"), b"<h1>hi</h1>")

    def test_local_copy_matches_committed_destination_checksum(self):
        _node, backup = self._website_backup()
        source = self._make_zip({"index.html": "verified"})
        stored = self._website_point(backup, source)
        self._commit_destination(stored, source)

        destination = os.path.join(self.tmp, "verified.zip")
        restore_common.fetch_backup_zip(stored, destination)

        self.assertEqual(self._identity(destination), self._identity(source))

    def test_local_copy_rejects_tampered_committed_destination(self):
        _node, backup = self._website_backup()
        source = self._make_zip({"index.html": "original"})
        stored = self._website_point(backup, source)
        self._commit_destination(stored, source)
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("index.html", "tampered")

        destination = os.path.join(self.tmp, "tampered.zip")
        with self.assertRaises(RestoreError) as context:
            restore_common.fetch_backup_zip(stored, destination)

        self.assertIn("SHA-256", str(context.exception))
        self.assertFalse(os.path.exists(destination))

    def test_new_ledger_backup_cannot_restore_without_destination_evidence(self):
        _node, backup = self._website_backup()
        source = self._make_zip({"index.html": "committed source"})
        size, checksum = self._identity(source)
        backup.record_artifact_integrity(
            role="source",
            object_key=os.path.basename(source),
            byte_count=size,
            checksum_algorithm="sha256",
            checksum_value=checksum,
            verified_at=timezone.now(),
        )
        stored = self._website_point(backup, source)

        with self.assertRaises(RestoreError) as context:
            restore_common.fetch_backup_zip(
                stored, os.path.join(self.tmp, "unverified.zip")
            )

        self.assertIn("no committed integrity record", str(context.exception))

    def test_local_path_traversal_rejected(self):
        node, backup = self._website_backup()
        outside_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside_dir, True)
        outside = os.path.join(outside_dir, "outside.zip")
        with zipfile.ZipFile(outside, "w") as zf:
            zf.writestr("x", "y")
        stored = self._website_point(backup, outside)
        with self.assertRaises(RestoreError):
            restore_common.fetch_backup_zip(stored, os.path.join(self.tmp, "fetched.zip"))

    def test_local_missing_file_rejected(self):
        node, backup = self._website_backup()
        stored = self._website_point(backup, os.path.join(self.tmp, "nope.zip"))
        with self.assertRaises(RestoreError):
            restore_common.fetch_backup_zip(stored, os.path.join(self.tmp, "fetched.zip"))

    def test_glacier_sentinel_raises(self):
        node, backup = self._website_backup()
        storage = factories.make_storage(self.account, self.member)
        stored = self._website_point(backup, "unused", storage=storage)
        with mock.patch.object(
            type(stored), "generate_download_url", return_value="restore_in_progress"
        ):
            with self.assertRaises(RestoreError) as ctx:
                restore_common.fetch_backup_zip(stored, os.path.join(self.tmp, "fetched.zip"))
        self.assertIn("Glacier/Deep Archive", str(ctx.exception))

    def test_remote_streaming_download(self):
        node, backup = self._website_backup()
        storage = factories.make_storage(self.account, self.member)
        stored = self._website_point(backup, "unused", storage=storage)
        chunks = [b"PK\x03\x04" + b"x" * 100, b"y" * 50]
        dest = os.path.join(self.tmp, "fetched.zip")
        with mock.patch.object(
            type(stored), "generate_download_url", return_value="https://example.com/dl"
        ), mock.patch.object(
            restore_common.requests, "get", return_value=_FakeResponse(chunks)
        ) as get:
            restore_common.fetch_backup_zip(stored, dest)
        with open(dest, "rb") as fh:
            self.assertEqual(fh.read(), b"".join(chunks))
        args, kwargs = get.call_args
        self.assertEqual(args[0], "https://example.com/dl")
        self.assertTrue(kwargs.get("stream"))
        self.assertIn("timeout", kwargs)

    def _committed_aws_s3_copy(self, payload):
        _node, backup = self._website_backup()
        storage = factories.make_storage(
            self.account,
            self.member,
            code="aws_s3",
            bucket="restore-e2e-bucket",
        )
        storage_config = storage.storage_aws_s3
        storage_config.expected_bucket_owner = "123456789012"
        storage_config.save(update_fields=["expected_bucket_owner", "modified"])
        stored = self._website_point(
            backup,
            "prefix/backup.zip",
            storage=storage,
        )
        digest = hashlib.sha256(payload).hexdigest()
        stored.metadata = {
            "aws_s3_object": {
                "phase": "committed",
                "bucket": storage_config.bucket_name,
                "object_key": stored.storage_file_id,
                "size_bytes": len(payload),
                "sha256": digest,
                "etag": '"etag-1"',
                "version_id": "version-1",
            }
        }
        stored.save(update_fields=["metadata", "modified"])
        backup.record_artifact_integrity(
            role="destination",
            object_key=stored.storage_file_id,
            byte_count=len(payload),
            storage=storage,
            checksum_algorithm="sha256",
            checksum_value=digest,
            etag='"etag-1"',
            version_id="version-1",
            verified_at=timezone.now(),
        )
        head = {
            "ContentLength": len(payload),
            "ETag": '"etag-1"',
            "VersionId": "version-1",
            "Metadata": {
                "backupsheep-backup-id": str(backup.id),
                "backupsheep-bytes": str(len(payload)),
                "backupsheep-sha256": digest,
            },
        }
        return stored, storage_config, head

    def test_aws_s3_restore_streams_exact_committed_version_without_presigned_url(self):
        payload = b"PK\x03\x04" + b"s3-exact-version" * 100
        stored, storage_config, head = self._committed_aws_s3_copy(payload)
        client = mock.Mock()
        client.head_object.side_effect = [dict(head), dict(head)]
        client.get_object.return_value = {**head, "Body": io.BytesIO(payload)}
        destination = os.path.join(self.tmp, "aws-s3.zip")

        with mock.patch.object(
            type(storage_config),
            "_connection_values",
            return_value={
                "bucket_name": storage_config.bucket_name,
                "expected_bucket_owner": storage_config.expected_bucket_owner,
            },
        ), mock.patch.object(
            type(storage_config), "_s3_client", return_value=client
        ), mock.patch.object(
            type(stored), "generate_download_url"
        ) as legacy_url:
            restore_common.fetch_backup_zip(stored, destination)

        with open(destination, "rb") as restored:
            self.assertEqual(restored.read(), payload)
        legacy_url.assert_not_called()
        expected_request = {
            "Bucket": "restore-e2e-bucket",
            "Key": "prefix/backup.zip",
            "VersionId": "version-1",
            "ExpectedBucketOwner": "123456789012",
        }
        self.assertEqual(client.head_object.call_count, 2)
        client.head_object.assert_called_with(**expected_request)
        client.get_object.assert_called_once_with(**expected_request)

    def test_aws_s3_restore_rejects_etag_drift_before_download(self):
        payload = b"PK\x03\x04" + b"s3-etag-drift"
        stored, storage_config, head = self._committed_aws_s3_copy(payload)
        head["ETag"] = '"different-etag"'
        client = mock.Mock()
        client.head_object.return_value = head
        destination = os.path.join(self.tmp, "aws-s3-drift.zip")

        with mock.patch.object(
            type(storage_config),
            "_connection_values",
            return_value={
                "bucket_name": storage_config.bucket_name,
                "expected_bucket_owner": storage_config.expected_bucket_owner,
            },
        ), mock.patch.object(
            type(storage_config), "_s3_client", return_value=client
        ):
            with self.assertRaises(RestoreError) as context:
                restore_common.fetch_backup_zip(stored, destination)

        self.assertEqual(context.exception.code, "PROVIDER_VERSION_DRIFT")
        client.get_object.assert_not_called()
        self.assertFalse(os.path.exists(destination))


class ExtractBackupZipTests(RestoreBackendBase):
    def test_extracts_tree(self):
        zip_path = self._make_zip(
            {"public_html/index.html": "hi", "public_html/css/a.css": "x"}
        )
        dest = restore_common.extract_backup_zip(zip_path, os.path.join(self.tmp, "out"))
        with open(os.path.join(dest, "public_html", "index.html")) as fh:
            self.assertEqual(fh.read(), "hi")

    def test_rejects_path_traversal(self):
        zip_path = self._make_zip({"../evil.txt": "x"}, name="evil.zip")
        with self.assertRaises(RestoreError):
            restore_common.extract_backup_zip(zip_path, os.path.join(self.tmp, "out"))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "evil.txt")))

    def test_rejects_absolute_member(self):
        zip_path = self._make_zip({"/abs/evil.txt": "x"}, name="abs.zip")
        with self.assertRaises(RestoreError):
            restore_common.extract_backup_zip(zip_path, os.path.join(self.tmp, "out"))

    def test_rejects_zip_symlink_member(self):
        zip_path = os.path.join(self.tmp, "symlink.zip")
        member = zipfile.ZipInfo("site-link")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr(member, "../../outside")

        with self.assertRaises(RestoreError) as context:
            restore_common.extract_backup_zip(zip_path, os.path.join(self.tmp, "out"))

        self.assertIn("special file", str(context.exception))


class MaybeExtractTarTests(RestoreBackendBase):
    @staticmethod
    def _tar_bytes(members):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, data in members.items():
                payload = data.encode()
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
        return buf.getvalue()

    def test_unwraps_legacy_tar(self):
        backup_uuid = "t123"
        dest = os.path.join(self.tmp, "out")
        os.makedirs(dest)
        with open(os.path.join(dest, f"{backup_uuid}.tar"), "wb") as fh:
            fh.write(self._tar_bytes({"public_html/index.html": "hi"}))
        root = restore_common.maybe_extract_tar(dest, backup_uuid)
        self.assertTrue(os.path.isfile(os.path.join(root, "public_html", "index.html")))
        # The tar is removed once unwrapped.
        self.assertFalse(os.path.exists(os.path.join(root, f"{backup_uuid}.tar")))

    def test_no_tar_returns_dir_untouched(self):
        dest = os.path.join(self.tmp, "out")
        os.makedirs(dest)
        self.assertEqual(
            restore_common.maybe_extract_tar(dest, "t123"), os.path.realpath(dest)
        )

    def test_tar_traversal_rejected(self):
        backup_uuid = "t123"
        dest = os.path.join(self.tmp, "out")
        os.makedirs(dest)
        with open(os.path.join(dest, f"{backup_uuid}.tar"), "wb") as fh:
            fh.write(self._tar_bytes({"../evil.txt": "x"}))
        with self.assertRaises(RestoreError):
            restore_common.maybe_extract_tar(dest, backup_uuid)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "evil.txt")))


class WebsiteRestoreEngineTests(RestoreBackendBase):
    """restore_website: lftp pushes the extracted tree back (mirror -R / put)."""

    def _run_engine(self, backup, restore):
        scripts = []

        def fake_run(cmd, **kwargs):
            scripts.append(kwargs.get("input") or "")
            return SimpleNamespace(stdout="", returncode=0)

        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(RW.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(RW, "delete_from_disk") as cleanup:
            RW.restore_website(backup, restore)
        return scripts, cleanup

    def _restore_row(self, backup, params=None):
        stored = self._website_point(backup, self._last_zip)
        return CoreWebsiteRestore.objects.create(
            backup=backup, storage_point=stored, name="r", params=params
        )

    def test_mirror_reverse_with_delete(self):
        node, backup = self._website_backup(
            all_paths=False, paths=[{"path": "public_html", "type": "directory"}]
        )
        self._last_zip = self._make_zip({"public_html/index.html": "hi"})
        restore = self._restore_row(backup, params={"delete": True})
        scripts, cleanup = self._run_engine(backup, restore)

        self.assertEqual(len(scripts), 1)
        script = scripts[0]
        self.assertIn("mirror -R", script)
        self.assertIn("--continue", script)
        # --ignore-time/--ignore-size must NOT be present: with them mirror -R
        # skips every file that already exists remotely (verified vs lftp 4.9.2).
        self.assertNotIn("--ignore-time", script)
        self.assertNotIn("--ignore-size", script)
        self.assertIn("--delete", script)
        # local extracted tree pushed back to the same remote path
        self.assertIn(f'restore_{backup.uuid_str}/public_html', script)
        self.assertIn('"public_html"', script)
        # The backup-side manifest/placeholder are never pushed to the site.
        self.assertIn("--exclude-glob=", script)
        cleanup.apply_async.assert_called_once_with(
            args=[f"restore_{backup.uuid_str}", "both"]
        )

    def test_no_delete_by_default(self):
        node, backup = self._website_backup(
            all_paths=False, paths=[{"path": "public_html", "type": "directory"}]
        )
        self._last_zip = self._make_zip({"public_html/index.html": "hi"})
        restore = self._restore_row(backup, params={"delete": False})
        scripts, _ = self._run_engine(backup, restore)
        self.assertIn("mirror -R", scripts[0])
        self.assertNotIn("--delete", scripts[0])

    def test_file_source_uses_put(self):
        node, backup = self._website_backup(
            all_paths=False, paths=[{"path": "index.html", "type": "file"}]
        )
        self._last_zip = self._make_zip({"index.html": "hi"})
        restore = self._restore_row(backup)
        scripts, _ = self._run_engine(backup, restore)
        self.assertIn("put ", scripts[0])
        self.assertIn('-o "index.html"', scripts[0])
        self.assertNotIn("mirror -R", scripts[0])

    def test_tar_wrapped_zip_is_unwrapped(self):
        node, backup = self._website_backup(
            all_paths=False, paths=[{"path": "public_html", "type": "directory"}]
        )
        # Legacy backup_type=4 layout: the zip wraps {uuid}.tar (+ backupsheep.txt).
        payload = b"hi"
        tar_path = os.path.join(self.tmp, f"{backup.uuid_str}.tar")
        with tarfile.open(tar_path, "w") as tf:
            info = tarfile.TarInfo("public_html/index.html")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        zip_path = os.path.join(self.tmp, "backup.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(tar_path, arcname=f"{backup.uuid_str}.tar")
            zf.writestr("backupsheep.txt", "placeholder")
        self._last_zip = zip_path
        restore = self._restore_row(backup)
        scripts, _ = self._run_engine(backup, restore)
        self.assertIn("mirror -R", scripts[0])
        # mirror source is the tar-unwrapped tree, not the raw zip contents
        self.assertIn(f'restore_{backup.uuid_str}/public_html', scripts[0])

    def test_all_paths_mirrors_tree_root(self):
        node, backup = self._website_backup(all_paths=True)
        self._last_zip = self._make_zip({"index.html": "hi"})
        restore = self._restore_row(backup)
        scripts, _ = self._run_engine(backup, restore)
        self.assertIn("mirror -R", scripts[0])
        self.assertIn('"."', scripts[0])

    def test_private_key_restore_uses_canonical_materializer(self):
        from apps.api.v1.utils.api_helpers import bs_encrypt

        node, backup = self._website_backup(
            all_paths=False, paths=[{"path": "public_html", "type": "directory"}]
        )
        auth = node.connection.auth_website
        auth.protocol = CoreAuthWebsite.Protocol.SFTP
        auth.port = 22
        auth.use_private_key = True
        key_without_newline = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "fixture\n"
            "-----END OPENSSH PRIVATE KEY-----"
        )
        auth.private_key = bs_encrypt(
            key_without_newline,
            self.account.get_encryption_key(),
        )
        auth.save()
        self._last_zip = self._make_zip({"public_html/index.html": "hi"})
        restore = self._restore_row(backup)

        with mock.patch.object(
            RW, "_materialize_ssh_private_key"
        ) as materialize, mock.patch.object(RW, "_normalize_ssh_key"):
            self._run_engine(backup, restore)

        materialize.assert_called_once_with(
            f"_storage/ssh_restore_{backup.uuid_str}",
            key_without_newline,
        )

    def test_missing_path_in_archive_fails_before_lftp(self):
        node, backup = self._website_backup(
            all_paths=False, paths=[{"path": "public_html", "type": "directory"}]
        )
        self._last_zip = self._make_zip({"other/x.txt": "x"})
        restore = self._restore_row(backup)
        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(RW.subprocess, "run") as run, \
             mock.patch.object(RW, "delete_from_disk") as cleanup:
            with self.assertRaises(RestoreError):
                RW.restore_website(backup, restore)
        run.assert_not_called()
        cleanup.apply_async.assert_called_once()

    def test_lftp_login_failure_raises(self):
        node, backup = self._website_backup(
            all_paths=False, paths=[{"path": "public_html", "type": "directory"}]
        )
        self._last_zip = self._make_zip({"public_html/index.html": "hi"})
        restore = self._restore_row(backup)

        def fake_run(cmd, **kwargs):
            return SimpleNamespace(stdout="Login failed for user", returncode=0)

        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(RW.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(RW, "delete_from_disk") as cleanup:
            with self.assertRaises(NodeBackupFailedError):
                RW.restore_website(backup, restore)
        cleanup.apply_async.assert_called_once()

    def test_incremental_logs_cache_resync_note(self):
        node, backup = self._website_backup(all_paths=True)
        website = node.website
        website.incremental = True
        website.save()
        self._last_zip = self._make_zip({"index.html": "hi"})
        restore = self._restore_row(backup)
        self._run_engine(backup, restore)
        with open(f"_storage/restore_{backup.uuid_str}.log") as fh:
            self.assertIn("re-syncs automatically", fh.read())


class DatabaseRestoreEngineTests(RestoreBackendBase):
    """restore_database: native client imports with the engines' hardened patterns."""

    @staticmethod
    def _recorded_run(calls, results):
        """subprocess.run fake: records argv/kwargs; result per call index (last repeats)."""

        def fake_run(argv, **kwargs):
            calls.append({"argv": list(argv), "kwargs": kwargs})
            rc, out, err = results[min(len(calls), len(results)) - 1]
            return SimpleNamespace(returncode=rc, stdout=out, stderr=err)

        return fake_run

    def _run_engine(self, backup, restore, fake_run):
        with mock.patch.object(CoreAuthDatabase, "check_connection", lambda *a, **k: None), \
             mock.patch.object(RD.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(RD, "delete_from_disk"), \
             mock.patch.object(
                 RD,
                 "_preflight_database_restore_permissions",
                 return_value={},
             ):
            RD.restore_database(backup, restore)

    def _db_restore(self, backup, members):
        stored = self._database_point(backup, self._make_zip(members))
        return CoreDatabaseRestore.objects.create(
            backup=backup, storage_point=stored, name="r"
        )

    def test_mysql_import_argv_and_stdin(self):
        node, backup = self._database_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0"
        )
        restore = self._db_restore(backup, {"appdb.sql": "CREATE TABLE t(id int);"})
        calls = []
        with mock.patch.object(
            RD,
            "_ensure_mysql_target",
            side_effect=[{"state": "importing", "_new": True}, {"state": "complete"}],
        ), mock.patch.object(RD, "_mysql_query", return_value=""):
            self._run_engine(
                backup, restore, self._recorded_run(calls, [(0, b"", b"")])
            )

        self.assertEqual(len(calls), 1)
        import_argv, import_kwargs = calls[0]["argv"], calls[0]["kwargs"]
        self.assertEqual(
            import_argv[1],
            f"--defaults-extra-file=_storage/my_restore_{backup.uuid_str}.cnf",
        )
        target = restore.params["target_mapping"]["appdb"]
        self.assertNotEqual(target, "appdb")
        self.assertEqual(import_argv[-1], target)
        self.assertIsNotNone(import_kwargs.get("stdin"))  # dump streamed on stdin
        self.assertFalse(import_kwargs.get("shell"))
        self.assertNotIn("env", import_kwargs)
        self.assertEqual(import_kwargs.get("timeout"), 12 * 3600)
        self.assertNotIn(DB_PASS, " ".join(import_argv))

        # The credentials file is deleted afterwards.
        self.assertFalse(
            os.path.exists(f"_storage/my_restore_{backup.uuid_str}.cnf")
        )

    def test_mysql_import_failure_raises_with_server_message(self):
        node, backup = self._database_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0"
        )
        restore = self._db_restore(backup, {"appdb.sql": "CREATE TABLE t(id int);"})
        calls = []
        fake = self._recorded_run(
            calls,
            [(1, b"", b"ERROR 1050 (42S01): Table 't' already exists")],
        )
        with mock.patch.object(
            RD,
            "_ensure_mysql_target",
            return_value={"state": "importing", "_new": True},
        ), mock.patch.object(RD, "_mysql_query", return_value=""):
            with self.assertRaises(NodeBackupFailedError) as ctx:
                self._run_engine(backup, restore, fake)
        self.assertNotIn("already exists", str(ctx.exception))
        self.assertIn("Secured diagnostics", str(ctx.exception))
        self.assertFalse(
            os.path.exists(f"_storage/my_restore_{backup.uuid_str}.cnf")
        )

    def test_postgres_pgpassword_env_and_createdb_flow(self):
        node, backup = self._database_backup(
            db_type=CoreAuthDatabase.DatabaseType.POSTGRESQL, version="postgres_16"
        )
        restore = self._db_restore(backup, {"appdb.sql": "CREATE TABLE t(id int);"})
        calls = []
        with mock.patch.object(
            RD,
            "_ensure_postgres_target",
            side_effect=[{"state": "importing"}, {"state": "complete"}],
        ):
            self._run_engine(
                backup, restore, self._recorded_run(calls, [(0, b"", b"")])
            )

        self.assertEqual(len(calls), 1)
        import_argv, import_kwargs = calls[0]["argv"], calls[0]["kwargs"]
        self.assertTrue(import_argv[0].endswith("psql"))
        target = restore.params["target_mapping"]["appdb"]
        self.assertIn(f"--dbname={target}", import_argv)
        self.assertIn("--single-transaction", import_argv)
        self.assertIn("--set=ON_ERROR_STOP=1", import_argv)
        self.assertNotIn(DB_PASS, " ".join(import_argv))
        self.assertNotIn("PGPASSWORD", import_kwargs["env"])
        self.assertIn("PGPASSFILE", import_kwargs["env"])
        self.assertFalse(os.path.exists(import_kwargs["env"]["PGPASSFILE"]))

    def test_postgres_fork_collision_without_marker_fails_closed(self):
        node, backup = self._database_backup(
            db_type=CoreAuthDatabase.DatabaseType.POSTGRESQL, version="postgres_16"
        )
        restore = self._db_restore(backup, {"appdb.sql": "CREATE TABLE t(id int);"})
        calls = []
        fake = self._recorded_run(calls, [(0, b"", b"")])
        with mock.patch.object(RD, "_postgres_query", side_effect=["1\n", ""]):
            with self.assertRaisesRegex(RestoreError, "not BackupSheep-owned"):
                self._run_engine(backup, restore, fake)
        self.assertEqual(calls, [])

    def test_tables_mode_imports_into_connection_database(self):
        node, backup = self._database_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0",
            tables=["orders"], all_tables=False,
        )
        restore = self._db_restore(backup, {"orders.sql": "INSERT INTO orders VALUES (1);"})
        calls = []
        with mock.patch.object(
            RD,
            "_ensure_mysql_target",
            side_effect=[{"state": "importing", "_new": True}, {"state": "complete"}],
        ), mock.patch.object(RD, "_mysql_query", return_value=""):
            self._run_engine(
                backup, restore, self._recorded_run(calls, [(0, b"", b"")])
            )
        # Table-only dumps still map from the configured source database, but
        # fork-by-default prevents an implicit overwrite of that database.
        target = restore.params["target_mapping"]["appdb"]
        self.assertEqual(calls[0]["argv"][-1], target)
        self.assertNotEqual(target, "appdb")

    def test_no_sql_dumps_fails(self):
        node, backup = self._database_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0"
        )
        restore = self._db_restore(backup, {"backupsheep.txt": "placeholder"})
        with mock.patch.object(CoreAuthDatabase, "check_connection", lambda *a, **k: None), \
             mock.patch.object(RD.subprocess, "run") as run, \
             mock.patch.object(RD, "delete_from_disk") as cleanup:
            with self.assertRaises(RestoreError):
                RD.restore_database(backup, restore)
        run.assert_not_called()
        cleanup.apply_async.assert_called_once()


class WebsiteRestoreTaskTests(RestoreBackendBase):
    def _restore(self):
        node, backup = self._website_backup(all_paths=True)
        stored = self._website_point(backup, self._make_zip({"index.html": "x"}))
        restore = CoreWebsiteRestore.objects.create(
            backup=backup, storage_point=stored, name="r", params={"delete": False}
        )
        return node, backup, restore

    def test_in_progress_to_complete(self):
        node, backup, restore = self._restore()
        seen = {}

        def fake_engine(b, r):
            seen["status"] = r.status

        with mock.patch(
            "apps._tasks.integration.restore_website.restore_website",
            side_effect=fake_engine,
        ):
            restore_tasks.restore_website_backup.apply(args=[node.id, backup.id, restore.id])
        self.assertEqual(seen["status"], CoreWebsiteRestore.Status.IN_PROGRESS)
        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreWebsiteRestore.Status.COMPLETE)
        self.assertIsNone(restore.error)

    def test_failure_marks_failed(self):
        node, backup, restore = self._restore()
        with mock.patch(
            "apps._tasks.integration.restore_website.restore_website",
            side_effect=RestoreError("boom"),
        ):
            restore_tasks.restore_website_backup.apply(args=[node.id, backup.id, restore.id])
        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreWebsiteRestore.Status.FAILED)
        self.assertEqual(restore.last_error_code, "RESTORE_SOURCE_UNAVAILABLE")
        self.assertNotIn("boom", restore.error)
        self.assertIn("not currently available", restore.error)


class DatabaseRestoreTaskTests(RestoreBackendBase):
    def test_in_progress_to_complete(self):
        node, backup = self._database_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0"
        )
        stored = self._database_point(backup, self._make_zip({"appdb.sql": "x"}))
        restore = CoreDatabaseRestore.objects.create(
            backup=backup, storage_point=stored, name="r"
        )
        with mock.patch(
            "apps._tasks.integration.restore_database.restore_database"
        ) as engine:
            restore_tasks.restore_database_backup.apply(args=[node.id, backup.id, restore.id])
        engine.assert_called_once()
        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreDatabaseRestore.Status.COMPLETE)

    def test_client_exit_1_marks_failed(self):
        """End-to-end-ish: real engine, client exits 1 -> restore FAILED with the message."""
        node, backup = self._database_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0"
        )
        stored = self._database_point(backup, self._make_zip({"appdb.sql": "x"}))
        restore = CoreDatabaseRestore.objects.create(
            backup=backup, storage_point=stored, name="r"
        )
        calls = []
        fake = DatabaseRestoreEngineTests._recorded_run(calls, [
            (0, b"GRANT CREATE, DROP ON *.* TO 'test'@'%';\n", b""),
            (1, b"", b"import boom"),
        ])
        with mock.patch.object(CoreAuthDatabase, "check_connection", lambda *a, **k: None), \
             mock.patch.object(RD.subprocess, "run", side_effect=fake), \
             mock.patch.object(RD, "delete_from_disk"):
            restore_tasks.restore_database_backup.apply(args=[node.id, backup.id, restore.id])
        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreDatabaseRestore.Status.FAILED)
        self.assertEqual(restore.last_error_code, "RESTORE_TARGET_REJECTED")
        self.assertNotIn("import boom", restore.error)
        self.assertIn("Secured diagnostics", restore.error)


class WebsiteRestoreAPITests(RestoreBackendBase):
    def _post(self, backup, payload):
        view = CoreWebsiteBackupView.as_view({"post": "restore"})
        request = APIRequestFactory().post(
            f"/api/v1/backups/website/{backup.id}/restore/", payload, format="json"
        )
        force_authenticate(request, user=self.user)
        return view(request, pk=backup.id)

    def _get(self, backup):
        view = CoreWebsiteBackupView.as_view({"get": "restores"})
        request = APIRequestFactory().get(f"/api/v1/backups/website/{backup.id}/restores/")
        force_authenticate(request, user=self.user)
        return view(request, pk=backup.id)

    def test_confirm_required_400(self):
        node, backup = self._website_backup()
        resp = self._post(backup, {})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("detail", resp.data)

    def test_non_complete_backup_404(self):
        node, backup = self._website_backup(status=UtilBackup.Status.IN_PROGRESS)
        resp = self._post(backup, {"confirm": True})
        self.assertEqual(resp.status_code, 404)

    def test_unknown_storage_point_404(self):
        node, backup = self._website_backup()
        resp = self._post(backup, {"confirm": True, "storage_point_id": 999999})
        self.assertEqual(resp.status_code, 404)

    def test_ambiguous_storage_points_400(self):
        node, backup = self._website_backup()
        self._website_point(backup, self._make_zip({"a": "1"}))
        self._website_point(backup, self._make_zip({"a": "1"}))
        resp = self._post(backup, {"confirm": True})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("detail", resp.data)

    def test_no_restorable_copy_400(self):
        node, backup = self._website_backup()
        resp = self._post(backup, {"confirm": True})
        self.assertEqual(resp.status_code, 400)

    def test_happy_path_201_and_task_dispatch(self):
        node, backup = self._website_backup()
        stored = self._website_point(backup, self._make_zip({"index.html": "x"}))
        with mock.patch(
            "apps._tasks.integration.restore.restore_website_backup.apply_async"
        ) as dispatch:
            resp = self._post(backup, {"confirm": True, "delete": True})
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.data["name"], f"Restore of {backup.uuid}")
        self.assertEqual(resp.data["status"], CoreWebsiteRestore.Status.PENDING)
        self.assertEqual(resp.data["status_display"], "Pending")
        self.assertEqual(resp.data["backup"], backup.id)
        self.assertEqual(resp.data["storage_point"], stored.id)
        self.assertEqual(resp.data["params"], {"delete": True})
        dispatch.assert_called_once()
        kwargs = dispatch.call_args.kwargs["kwargs"]
        self.assertEqual(kwargs["node_id"], node.id)
        self.assertEqual(kwargs["backup_id"], backup.id)
        self.assertEqual(kwargs["restore_id"], resp.data["id"])

    def test_explicit_storage_point_accepted(self):
        node, backup = self._website_backup()
        self._website_point(backup, self._make_zip({"a": "1"}))
        stored2 = self._website_point(backup, self._make_zip({"a": "1"}))
        with mock.patch(
            "apps._tasks.integration.restore.restore_website_backup.apply_async"
        ):
            resp = self._post(backup, {"confirm": True, "storage_point_id": stored2.id})
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.data["storage_point"], stored2.id)

    def test_restores_list_shape_matches_ui_contract(self):
        node, backup = self._website_backup()
        stored = self._website_point(backup, self._make_zip({"index.html": "x"}))
        older = CoreWebsiteRestore.objects.create(
            backup=backup, storage_point=stored, name="older"
        )
        newer = CoreWebsiteRestore.objects.create(
            backup=backup, storage_point=stored, name="newer", error="oops"
        )
        resp = self._get(backup)
        self.assertEqual(resp.status_code, 200)
        # newest first
        self.assertEqual([r["id"] for r in resp.data], [newer.id, older.id])
        row = resp.data[0]
        for field in ("id", "name", "status", "status_display", "error", "backup",
                      "storage_point", "created_display", "modified_display"):
            self.assertIn(field, row)
        self.assertEqual(row["name"], "newer")
        self.assertEqual(row["status"], CoreWebsiteRestore.Status.PENDING)
        self.assertEqual(row["status_display"], "Pending")
        self.assertNotEqual(row["error"], "oops")
        self.assertNotIn("oops", row["error"])
        self.assertIn("correlation ID", row["error"])
        self.assertEqual(row["backup"], backup.id)
        self.assertEqual(row["storage_point"], stored.id)


class DatabaseRestoreAPITests(RestoreBackendBase):
    def _post(self, backup, payload):
        view = CoreDatabaseBackupView.as_view({"post": "restore"})
        request = APIRequestFactory().post(
            f"/api/v1/backups/database/{backup.id}/restore/", payload, format="json"
        )
        force_authenticate(request, user=self.user)
        return view(request, pk=backup.id)

    def _get(self, backup):
        view = CoreDatabaseBackupView.as_view({"get": "restores"})
        request = APIRequestFactory().get(f"/api/v1/backups/database/{backup.id}/restores/")
        force_authenticate(request, user=self.user)
        return view(request, pk=backup.id)

    def _db_backup(self):
        return self._database_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0"
        )

    def test_confirm_required_400(self):
        node, backup = self._db_backup()
        resp = self._post(backup, {})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("detail", resp.data)

    def test_non_complete_backup_404(self):
        node, backup = self._database_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0",
            status=UtilBackup.Status.IN_PROGRESS,
        )
        resp = self._post(backup, {"confirm": True})
        self.assertEqual(resp.status_code, 404)

    def test_happy_path_201(self):
        node, backup = self._db_backup()
        stored = self._database_point(backup, self._make_zip({"appdb.sql": "x"}))
        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ) as dispatch:
            resp = self._post(backup, {"confirm": True})
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.data["name"], f"Restore of {backup.uuid}")
        self.assertEqual(resp.data["status"], CoreDatabaseRestore.Status.PENDING)
        self.assertEqual(resp.data["status_display"], "Pending")
        self.assertEqual(resp.data["backup"], backup.id)
        self.assertEqual(resp.data["storage_point"], stored.id)
        self.assertEqual(resp.data["params"]["mode"], "fork")
        self.assertTrue(resp.data["params"]["mapping_locked"])
        self.assertNotEqual(
            resp.data["params"]["target_mapping"]["appdb"], "appdb"
        )
        dispatch.assert_called_once()

    def test_restores_list_shape_matches_ui_contract(self):
        node, backup = self._db_backup()
        stored = self._database_point(backup, self._make_zip({"appdb.sql": "x"}))
        CoreDatabaseRestore.objects.create(
            backup=backup, storage_point=stored, name="only"
        )
        resp = self._get(backup)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data), 1)
        row = resp.data[0]
        for field in ("id", "name", "status", "status_display", "error", "backup",
                      "storage_point", "created_display", "modified_display"):
            self.assertIn(field, row)
        self.assertEqual(row["name"], "only")
        self.assertEqual(row["status_display"], "Pending")
        self.assertEqual(row["backup"], backup.id)
        self.assertEqual(row["storage_point"], stored.id)


# ---------------------------------------------------------------------------
# Hardening: lftp failure detection + disk-space preflight on the restore path
# ---------------------------------------------------------------------------


class WebsiteRestoreFailureDetectionTests(RestoreBackendBase):
    """restore_website must fail loudly when lftp reports failed transfers
    (mirror -R / put). Mechanism: lftp's process exit code -- verified against
    lftp 4.9.2 (non-zero on failed transfers even with a trailing `bye`; zero
    on clean transfers)."""

    def _restore_row(self, backup, params=None):
        stored = self._website_point(backup, self._last_zip)
        return CoreWebsiteRestore.objects.create(
            backup=backup, storage_point=stored, name="r", params=params
        )

    def _run(self, backup, restore, fake_run):
        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(RW.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(RW, "delete_from_disk") as cleanup:
            RW.restore_website(backup, restore)
        return cleanup

    def test_mirror_failure_raises_naming_files(self):
        node, backup = self._website_backup(
            all_paths=False, paths=[{"path": "public_html", "type": "directory"}]
        )
        self._last_zip = self._make_zip({"public_html/index.html": "hi"})
        restore = self._restore_row(backup)

        def fake_run(cmd, **kwargs):
            return SimpleNamespace(
                stdout="mirror: Access failed: Permission denied (secret.txt)\n",
                returncode=1,
            )

        with self.assertRaises(NodeBackupFailedError) as ctx:
            self._run(backup, restore, fake_run)
        self.assertNotIn("secret.txt", str(ctx.exception))
        self.assertIn("Secured diagnostics", str(ctx.exception))
        with open(f"_storage/restore_{backup.uuid_str}.log") as log:
            self.assertIn("LFTP_REJECTED", log.read())

    def test_mirror_failure_schedules_artifact_cleanup(self):
        node, backup = self._website_backup(all_paths=True)
        self._last_zip = self._make_zip({"index.html": "hi"})
        restore = self._restore_row(backup)

        def fake_run(cmd, **kwargs):
            return SimpleNamespace(stdout="mirror: Access failed: boom\n", returncode=1)

        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(RW.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(RW, "delete_from_disk") as cleanup:
            with self.assertRaises(NodeBackupFailedError):
                RW.restore_website(backup, restore)
        cleanup.apply_async.assert_called_once_with(
            args=[f"restore_{backup.uuid_str}", "both"]
        )

    def test_clean_push_exit_zero_succeeds(self):
        node, backup = self._website_backup(all_paths=True)
        self._last_zip = self._make_zip({"index.html": "hi"})
        restore = self._restore_row(backup)
        cleanup = self._run(
            backup, restore,
            lambda cmd, **kwargs: SimpleNamespace(stdout="", returncode=0),
        )
        cleanup.apply_async.assert_called_once()  # success path cleanup
        with open(f"_storage/restore_{backup.uuid_str}.log") as fh:
            self.assertIn("Restore complete.", fh.read())

    def test_put_failure_raises(self):
        node, backup = self._website_backup(
            all_paths=False, paths=[{"path": "index.html", "type": "file"}]
        )
        self._last_zip = self._make_zip({"index.html": "hi"})
        restore = self._restore_row(backup)

        def fake_run(cmd, **kwargs):
            return SimpleNamespace(
                stdout="put: index.html: Access failed: Permission denied\n",
                returncode=1,
            )

        with self.assertRaises(NodeBackupFailedError) as ctx:
            self._run(backup, restore, fake_run)
        self.assertIn("Secured diagnostics", str(ctx.exception))
        self.assertNotIn("index.html", str(ctx.exception))

    def test_put_uses_boolean_pget_flag(self):
        # lftp 4.9.2: `-P` is boolean for put; `-P 3` would make lftp upload an
        # extra file literally named "3" and exit 1 (verified).
        node, backup = self._website_backup(
            all_paths=False, paths=[{"path": "index.html", "type": "file"}]
        )
        self._last_zip = self._make_zip({"index.html": "hi"})
        restore = self._restore_row(backup)
        scripts = []

        def fake_run(cmd, **kwargs):
            scripts.append(kwargs.get("input") or "")
            return SimpleNamespace(stdout="", returncode=0)

        self._run(backup, restore, fake_run)
        self.assertEqual(len(scripts), 1)
        self.assertIn("put -P ", scripts[0])
        self.assertNotIn("-P 3", scripts[0])


class RestoreDiskSpacePreflightTests(RestoreBackendBase):
    """Both restore engines check free space (~3x the stored zip, 1 GiB floor)
    BEFORE fetching/extracting anything."""

    GB = 1 << 30

    def _usage(self, free):
        return SimpleNamespace(total=0, used=0, free=free)

    def test_website_restore_preflight_blocks_before_fetch(self):
        node, backup = self._website_backup(all_paths=True)
        backup.size = 2 * self.GB
        backup.save()
        stored = self._website_point(backup, self._make_zip({"index.html": "x"}))
        restore = CoreWebsiteRestore.objects.create(
            backup=backup, storage_point=stored, name="r"
        )
        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(RW.subprocess, "run") as run, \
             mock.patch.object(RW, "delete_from_disk"), \
             mock.patch(
                 "apps.api.v1.utils.api_helpers.shutil.disk_usage",
                 return_value=self._usage(5 * self.GB),
             ):
            with self.assertRaises(NodeBackupFailedError) as ctx:
                RW.restore_website(backup, restore)
        run.assert_not_called()
        # Capacity details stay in secured diagnostics; public exceptions remain
        # stable and do not reveal worker filesystem/capacity information.
        self.assertNotIn("5.00 GB", str(ctx.exception))
        self.assertIn("Secured diagnostics", str(ctx.exception))
        # The zip was never fetched.
        self.assertFalse(os.path.exists(f"_storage/restore_{backup.uuid_str}.zip"))

    def test_website_restore_preflight_floor_without_size(self):
        node, backup = self._website_backup(all_paths=True)  # backup.size is None
        stored = self._website_point(backup, self._make_zip({"index.html": "x"}))
        restore = CoreWebsiteRestore.objects.create(
            backup=backup, storage_point=stored, name="r"
        )
        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(RW.subprocess, "run") as run, \
             mock.patch.object(RW, "delete_from_disk"), \
             mock.patch(
                 "apps.api.v1.utils.api_helpers.shutil.disk_usage",
                 return_value=self._usage(self.GB - 1),
             ):
            with self.assertRaises(NodeBackupFailedError) as ctx:
                RW.restore_website(backup, restore)
        run.assert_not_called()
        self.assertNotIn("1.00 GB", str(ctx.exception))
        self.assertIn("Secured diagnostics", str(ctx.exception))

    def test_database_restore_preflight_blocks_before_fetch(self):
        node, backup = self._database_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0"
        )
        stored = self._database_point(backup, self._make_zip({"appdb.sql": "x"}))
        restore = CoreDatabaseRestore.objects.create(
            backup=backup, storage_point=stored, name="r"
        )
        with mock.patch.object(CoreAuthDatabase, "check_connection", lambda *a, **k: None), \
             mock.patch.object(RD.subprocess, "run") as run, \
             mock.patch.object(RD, "delete_from_disk"), \
             mock.patch(
                 "apps.api.v1.utils.api_helpers.shutil.disk_usage",
                 return_value=self._usage(0),
             ):
            with self.assertRaises(NodeBackupFailedError) as ctx:
                RD.restore_database(backup, restore)
        run.assert_not_called()
        self.assertNotIn("free disk space", str(ctx.exception).lower())
        self.assertIn("Secured diagnostics", str(ctx.exception))
        self.assertFalse(os.path.exists(f"_storage/restore_{backup.uuid_str}.zip"))
