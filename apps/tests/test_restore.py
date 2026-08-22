import io
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
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
from apps.console.node.models import _restore_record_provider_status
from apps.console.node.models import _restore_safe_failure
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
            "region": {"slug": (restore.params or {}).get("region", "nyc3")},
            "size_gigabytes": max(1, __import__("math").ceil(backup.size_gigabytes)),
            "droplet_ids": [],
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
            restore.refresh_from_db()
            self.assertEqual(
                restore.params["_bs_provider_status"], droplet_status
            )

    def test_check_restore_persists_inferred_available_volume_state(self):
        node = self._make_volume_node_with_auth()
        backup = make_completed_backup(
            node,
            unique_id="volume-snapshot-available",
            size_gigabytes=1,
        )
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="restored-volume",
            resource_id="restored-volume-1",
            params={"region": "nyc3"},
        )
        identity = self._restore_identity(node, backup, restore)
        params = dict(restore.params or {})
        identity.update({"region": "nyc3", "size_gigabytes": 1})
        params["_digitalocean_restore"] = identity
        restore.params = params
        restore.save(update_fields=["params", "modified"])
        volume = self._owned_volume(
            node,
            backup,
            restore,
            resource_id="restored-volume-1",
        )
        volume.pop("status")
        self.assertTrue(
            node.digitalocean._digitalocean_restore_owned(
                volume, identity, resource_id="restored-volume-1"
            )
        )
        get_resp = mock.MagicMock(status_code=200)
        get_resp.json.return_value = {"volume": volume}

        with self._patch_client(), mock.patch(
            "apps.console.node.models.requests.get", return_value=get_resp
        ):
            result = node.digitalocean.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(
            result,
            CoreCloudRestore.Status.COMPLETE,
            restore.params,
        )
        self.assertEqual(restore.params["_bs_provider_status"], "available")

    def test_check_restore_provider_status_merge_preserves_newer_witness(self):
        node = self._make_volume_node_with_auth()
        backup = make_completed_backup(
            node,
            unique_id="volume-snapshot-status-merge",
            size_gigabytes=1,
        )
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="restored-volume",
            resource_id="restored-volume-merge",
            params={"region": "nyc3"},
        )
        identity = self._restore_identity(node, backup, restore)
        params = dict(restore.params or {})
        identity.update({"region": "nyc3", "size_gigabytes": 1})
        params["_digitalocean_restore"] = identity
        restore.params = params
        restore.save(update_fields=["params", "modified"])

        # Simulate a newer worker persisting reconciliation evidence after this
        # poller loaded its row but before it records the provider lifecycle.
        current = dict(params)
        current["concurrent_reconciliation_witness"] = {
            "marker": "durable-newer-witness"
        }
        CoreCloudRestore.objects.filter(pk=restore.pk).update(params=current)

        volume = self._owned_volume(
            node,
            backup,
            restore,
            resource_id="restored-volume-merge",
        )
        volume.pop("status")
        get_resp = mock.MagicMock(status_code=200)
        get_resp.json.return_value = {"volume": volume}

        with self._patch_client(), mock.patch(
            "apps.console.node.models.requests.get", return_value=get_resp
        ):
            self.assertEqual(
                node.digitalocean.check_restore(restore),
                CoreCloudRestore.Status.COMPLETE,
            )

        restore.refresh_from_db()
        self.assertEqual(restore.params["_bs_provider_status"], "available")
        self.assertEqual(
            restore.params["concurrent_reconciliation_witness"],
            {"marker": "durable-newer-witness"},
        )

    def test_safe_failure_merges_witness_after_provider_status_recording(self):
        node = self._make_volume_node_with_auth()
        backup = make_completed_backup(
            node,
            unique_id="volume-snapshot-terminal-merge",
            size_gigabytes=1,
        )
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="restored-volume",
            resource_id="restored-volume-terminal-merge",
            params={"durable_source": "original"},
        )

        # This is the first worker's status transaction.  The caller remains
        # an intentionally stale in-memory object after it returns.
        self.assertTrue(_restore_record_provider_status(restore, "error"))
        stale_params = dict(restore.params)

        # Deterministically model a newer reconciliation worker running after
        # provider-status recording but before terminal error persistence.
        newer_params = dict(stale_params)
        newer_params["new_reconciliation_witness"] = {
            "generation": 2,
            "mutation_id": "accepted-before-readback",
        }
        CoreCloudRestore.objects.filter(pk=restore.pk).update(params=newer_params)

        self.assertNotIn("new_reconciliation_witness", stale_params)
        self.assertEqual(
            _restore_safe_failure(restore, "PROVIDER_FAILED"),
            CoreCloudRestore.Status.FAILED,
        )

        restore.refresh_from_db()
        self.assertEqual(restore.params["durable_source"], "original")
        self.assertEqual(restore.params["_bs_provider_status"], "error")
        self.assertEqual(
            restore.params["new_reconciliation_witness"],
            {
                "generation": 2,
                "mutation_id": "accepted-before-readback",
            },
        )
        self.assertEqual(restore.params["_bs_last_error_code"], "PROVIDER_FAILED")
        self.assertEqual(restore.params["_bs_last_error_category"], "terminal")
        self.assertFalse(restore.params["_bs_create_outcome_unknown"])
        self.assertEqual(restore.operation_phase, CoreCloudRestore.OperationPhase.FAILED)

    def test_success_phase_save_after_provider_status_recording_preserves_witness(self):
        node = self._make_volume_node_with_auth()
        backup = make_completed_backup(
            node,
            unique_id="volume-snapshot-success-merge",
            size_gigabytes=1,
        )
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="restored-volume",
            resource_id="restored-volume-success-merge",
            params={"durable_source": "original"},
        )

        self.assertTrue(_restore_record_provider_status(restore, "available"))
        newer_params = dict(restore.params)
        newer_params["new_mutation_witness"] = {
            "generation": 2,
            "resource_id": "restored-volume-success-merge",
        }
        CoreCloudRestore.objects.filter(pk=restore.pk).update(params=newer_params)

        # Success paths intentionally save only their terminal scalar fields;
        # this is the non-regression contract for a status-only transition.
        restore.status = CoreCloudRestore.Status.COMPLETE
        restore.operation_phase = CoreCloudRestore.OperationPhase.COMPLETE
        restore.error = ""
        restore.save(update_fields=["status", "operation_phase", "error", "modified"])

        restore.refresh_from_db()
        self.assertEqual(restore.params["_bs_provider_status"], "available")
        self.assertEqual(
            restore.params["new_mutation_witness"],
            {
                "generation": 2,
                "resource_id": "restored-volume-success-merge",
            },
        )
        self.assertEqual(restore.status, CoreCloudRestore.Status.COMPLETE)
        self.assertEqual(restore.operation_phase, CoreCloudRestore.OperationPhase.COMPLETE)

    def test_check_restore_persists_inferred_in_use_volume_state(self):
        node = self._make_volume_node_with_auth()
        backup = make_completed_backup(
            node,
            unique_id="volume-snapshot-in-use",
            size_gigabytes=1,
        )
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="restored-volume",
            resource_id="restored-volume-2",
            params={"region": "nyc3"},
        )
        identity = self._restore_identity(node, backup, restore)
        params = dict(restore.params or {})
        identity.update({"region": "nyc3", "size_gigabytes": 1})
        params["_digitalocean_restore"] = identity
        restore.params = params
        restore.save(update_fields=["params", "modified"])
        volume = self._owned_volume(
            node,
            backup,
            restore,
            resource_id="restored-volume-2",
        )
        volume.pop("status")
        volume["droplet_ids"] = [777]
        get_resp = mock.MagicMock(status_code=200)
        get_resp.json.return_value = {"volume": volume}

        with self._patch_client(), mock.patch(
            "apps.console.node.models.requests.get", return_value=get_resp
        ):
            self.assertEqual(
                node.digitalocean.check_restore(restore),
                CoreCloudRestore.Status.COMPLETE,
            )

        restore.refresh_from_db()
        self.assertEqual(restore.params["_bs_provider_status"], "in-use")

    def test_check_restore_rejects_missing_volume_attachment_evidence(self):
        node = self._make_volume_node_with_auth()
        backup = make_completed_backup(
            node,
            unique_id="volume-snapshot-malformed",
            size_gigabytes=1,
        )
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="restored-volume",
            resource_id="restored-volume-3",
            params={"region": "nyc3"},
        )
        identity = self._restore_identity(node, backup, restore)
        params = dict(restore.params or {})
        identity.update({"region": "nyc3", "size_gigabytes": 1})
        params["_digitalocean_restore"] = identity
        restore.params = params
        restore.save(update_fields=["params", "modified"])
        volume = self._owned_volume(
            node,
            backup,
            restore,
            resource_id="restored-volume-3",
        )
        volume.pop("status")
        volume.pop("droplet_ids")
        get_resp = mock.MagicMock(status_code=200)
        get_resp.json.return_value = {"volume": volume}

        with self._patch_client(), mock.patch(
            "apps.console.node.models.requests.get", return_value=get_resp
        ):
            self.assertEqual(
                node.digitalocean.check_restore(restore),
                CoreCloudRestore.Status.FAILED,
            )

        restore.refresh_from_db()
        self.assertEqual(restore.operation_phase, restore.OperationPhase.MANUAL_REVIEW)
        self.assertEqual(
            restore.params["_bs_last_error_code"], "PROVIDER_MALFORMED_RESPONSE"
        )

    def test_restore_snapshot_volume_uses_snapshot_and_atomic_identity_tags(self):
        node = self._make_volume_node_with_auth()
        backup = make_completed_backup(
            node,
            unique_id="volume-snapshot-123",
            size_gigabytes=1.25,
        )
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
        self.assertEqual(
            set(sent_json),
            {"name", "region", "snapshot", "tags", "size_gigabytes"},
        )
        self.assertEqual(sent_json["snapshot"], backup.unique_id)
        self.assertNotIn("snapshot_id", sent_json)
        self.assertEqual(
            sent_json["tags"],
            [identity["marker"], identity["source_tag"], identity["kind_tag"]],
        )
        self.assertIs(type(sent_json["size_gigabytes"]), int)
        self.assertEqual(sent_json["size_gigabytes"], 2)
        self.assertGreater(sent_json["size_gigabytes"], 0)
        self.assertEqual(post.call_args.kwargs["timeout"], request_timeout())
        restore.refresh_from_db()
        self.assertEqual(
            restore.params["_digitalocean_restore"]["region"], "nyc3"
        )
        self.assertEqual(
            restore.params["_digitalocean_restore"]["size_gigabytes"], 2
        )

    def test_restore_snapshot_volume_rejects_invalid_durable_sizes_before_mutation(self):
        missing = object()
        cases = (
            ("missing", missing),
            ("zero", 0),
            ("negative", -1),
            ("nan", float("nan")),
            ("infinite", float("inf")),
        )

        for case, size_gigabytes in cases:
            with self.subTest(case=case):
                node = self._make_volume_node_with_auth()
                backup_kwargs = {
                    "unique_id": f"invalid-volume-snapshot-{case}",
                }
                if size_gigabytes is not missing:
                    backup_kwargs["size_gigabytes"] = size_gigabytes
                backup = make_completed_backup(node, **backup_kwargs)
                restore = CoreCloudRestore.objects.create(
                    node=node,
                    backup_id=backup.id,
                    name=f"restored-invalid-{case}",
                    params={"region": "nyc3"},
                )
                post_resp = mock.MagicMock(status_code=202)
                post_resp.json.return_value = {"volume": {"id": f"fake-{case}"}}

                with self._patch_client(), mock.patch(
                    "apps.console.node.models.requests.post",
                    return_value=post_resp,
                ) as post, mock.patch(
                    "apps.console.node.models.requests.get"
                ) as get:
                    with self.assertRaises(ValueError) as raised:
                        node.digitalocean.restore_snapshot(backup, restore)

                self.assertEqual(
                    getattr(raised.exception, "code", None),
                    "PROVIDER_MALFORMED_RESPONSE",
                )
                post.assert_not_called()
                get.assert_not_called()
                restore.refresh_from_db()
                self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
                self.assertEqual(
                    restore.operation_phase,
                    CoreCloudRestore.OperationPhase.MANUAL_REVIEW,
                )
                self.assertEqual(
                    restore.last_error_code,
                    "PROVIDER_MALFORMED_RESPONSE",
                )
                self.assertEqual(
                    restore.params["_bs_last_error_code"],
                    "PROVIDER_MALFORMED_RESPONSE",
                )
                self.assertFalse(restore.params["_bs_create_outcome_unknown"])
                self.assertNotIn("_bs_mutation_started_at", restore.params)
                self.assertIsNone(restore.resource_id)

    def test_restore_snapshot_volume_requires_exact_exposed_snapshot_and_request_witness(self):
        node = self._make_volume_node_with_auth()
        backup = make_completed_backup(
            node,
            unique_id="volume-snapshot-123",
            size_gigabytes=1,
        )

        cases = (
            ("wrong-snapshot", {"snapshot_id": "foreign-snapshot"}),
            ("missing-source-tag", {"remove_source_tag": True}),
            ("wrong-region", {"region": {"slug": "ams3"}}),
            ("wrong-size", {"size_gigabytes": 2}),
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
        backup = make_completed_backup(
            node,
            unique_id="volume-snapshot-123",
            size_gigabytes=1,
        )
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
        backup = make_completed_backup(
            node,
            unique_id="volume-snapshot-123",
            size_gigabytes=1,
        )
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
        backup = make_completed_backup(
            node,
            unique_id="volume-snapshot-123",
            size_gigabytes=1,
        )
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
    "unknown variable"), so mariadb gets bare --ssl while mysql requires
    --ssl-mode=REQUIRED."""

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
                               return_value=(ssh, None)), \
             mock.patch.object(
                 CoreAuthDatabase,
                 "_validate_mysql_family_client_capability",
             ):
            getattr(auth, method)()
        return captured[0]

    def test_find_version_mariadb_uses_ssl_flag_not_ssl_mode(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.MARIADB, "mariadb_10_11")
        command = self._capture_command(
            auth, "find_db_type_and_version", "10.11.6-MariaDB\n")
        self.assertTrue(command.startswith("mariadb "))
        self.assertIn("--ssl", command)
        self.assertNotIn("ssl-mode", command)

    def test_find_version_mysql_requires_tls(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.MYSQL, "mysql_8_0")
        command = self._capture_command(
            auth, "find_db_type_and_version", "8.0.36\n")
        self.assertTrue(command.startswith("mysql "))
        self.assertIn("--ssl-mode=REQUIRED", command)

    def test_check_connection_mariadb_uses_ssl_flag_not_ssl_mode(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.MARIADB, "mariadb_10_11")
        command = self._capture_command(
            auth, "check_connection", "Server version: 10.11.6-MariaDB\n")
        self.assertTrue(command.startswith("mariadb "))
        self.assertIn("--ssl", command)
        self.assertNotIn("ssl-mode", command)

    def test_check_connection_mysql_requires_tls(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.MYSQL, "mysql_8_0")
        command = self._capture_command(
            auth, "check_connection", "Server version: 8.0.36\n")
        self.assertTrue(command.startswith("mysql "))
        self.assertIn("--ssl-mode=REQUIRED", command)

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
import struct
import tarfile
import uuid
import zipfile

from django.test import SimpleTestCase, override_settings
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
    @staticmethod
    def _clear_utf8_name_flags(zip_path):
        """Recreate the historical Info-ZIP UTF-8-without-bit-11 layout."""
        with zipfile.ZipFile(zip_path) as archive:
            infos = archive.infolist()
            central_offset = archive.start_dir

        with open(zip_path, "r+b") as archive_file:
            for info in infos:
                archive_file.seek(central_offset)
                central = archive_file.read(46)
                filename_length, extra_length, comment_length = struct.unpack_from(
                    "<HHH", central, 28
                )
                central_flags = struct.unpack_from("<H", central, 8)[0]
                archive_file.seek(central_offset + 8)
                archive_file.write(struct.pack("<H", central_flags & ~0x0800))

                archive_file.seek(info.header_offset + 6)
                local_flags = struct.unpack("<H", archive_file.read(2))[0]
                archive_file.seek(info.header_offset + 6)
                archive_file.write(struct.pack("<H", local_flags & ~0x0800))

                central_offset += 46 + filename_length + extra_length + comment_length

    def test_extracts_tree(self):
        zip_path = self._make_zip(
            {"public_html/index.html": "hi", "public_html/css/a.css": "x"}
        )
        dest = restore_common.extract_backup_zip(zip_path, os.path.join(self.tmp, "out"))
        with open(os.path.join(dest, "public_html", "index.html")) as fh:
            self.assertEqual(fh.read(), "hi")

    def test_extracts_valid_empty_website_archive(self):
        zip_path = os.path.join(self.tmp, "empty.zip")
        with zipfile.ZipFile(zip_path, "w"):
            pass

        destination = restore_common.extract_backup_zip(
            zip_path, os.path.join(self.tmp, "empty-out")
        )

        self.assertTrue(os.path.isdir(destination))
        self.assertEqual(os.listdir(destination), [])

    def test_extract_does_not_materialize_zipfile_members(self):
        zip_path = self._make_zip(
            {"public_html/index.html": "bounded"}, name="bounded.zip"
        )
        from apps._tasks.integration.backup import _archive as archive_module

        with mock.patch.object(
            archive_module.zipfile,
            "ZipFile",
            side_effect=AssertionError("ZipFile must not be used for extraction"),
        ):
            dest = restore_common.extract_backup_zip(
                zip_path, os.path.join(self.tmp, "bounded-out")
            )

        with open(os.path.join(dest, "public_html", "index.html")) as restored:
            self.assertEqual(restored.read(), "bounded")
        self.assertEqual(
            list(Path(self.tmp).glob(".backupsheep-zip-index-*")), []
        )

    def test_repairs_historical_unflagged_utf8_names_before_extract(self):
        original_name = "public_html/caf\u00e9-\u0645\u0631\u062d\u0628\u0627-\U0001f642.txt"
        zip_path = self._make_zip({original_name: "unicode payload"}, name="legacy.zip")
        self._clear_utf8_name_flags(zip_path)

        with zipfile.ZipFile(zip_path) as archive:
            self.assertNotIn(original_name, archive.namelist())

        dest = restore_common.extract_backup_zip(
            zip_path, os.path.join(self.tmp, "legacy-out")
        )

        restored_path = os.path.join(dest, *original_name.split("/"))
        with open(restored_path, encoding="utf-8") as restored:
            self.assertEqual(restored.read(), "unicode payload")
        with zipfile.ZipFile(zip_path) as archive:
            self.assertTrue(archive.getinfo(original_name).flag_bits & 0x0800)

    def test_rejects_path_traversal(self):
        zip_path = self._make_zip({"../evil.txt": "x"}, name="evil.zip")
        with self.assertRaises(RestoreError):
            restore_common.extract_backup_zip(zip_path, os.path.join(self.tmp, "out"))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "evil.txt")))

    def test_rejects_absolute_member(self):
        zip_path = self._make_zip({"/abs/evil.txt": "x"}, name="abs.zip")
        with self.assertRaises(RestoreError):
            restore_common.extract_backup_zip(zip_path, os.path.join(self.tmp, "out"))

    def test_rejects_ambiguous_lexical_member_paths(self):
        for index, member_name in enumerate(
            (
                "./site.txt",
                "public_html\\site.txt",
                "a//site.txt",
                "tab\tname.txt",
                "control-\x1f.txt",
            )
        ):
            with self.subTest(member_name=member_name):
                zip_path = self._make_zip(
                    {member_name: "x"}, name=f"ambiguous-{index}.zip"
                )
                with self.assertRaises(RestoreError) as context:
                    restore_common.extract_backup_zip(
                        zip_path, os.path.join(self.tmp, f"ambiguous-{index}")
                    )
                self.assertIn("unsafe archive path", str(context.exception))

    def test_rejects_duplicate_member_paths_with_disk_spooled_index(self):
        zip_path = os.path.join(self.tmp, "duplicate.zip")
        with self.assertWarns(UserWarning):
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("public_html/index.html", "first")
                archive.writestr("public_html/index.html", "second")

        with self.assertRaises(RestoreError) as context:
            restore_common.extract_backup_zip(
                zip_path, os.path.join(self.tmp, "duplicate-out")
            )

        self.assertIn("duplicate archive paths", str(context.exception))
        self.assertEqual(
            list(Path(self.tmp).glob(".backupsheep-zip-index-*")), []
        )

    def test_rejects_file_directory_ancestor_conflicts_in_either_order(self):
        cases = (
            (("parent/child.txt", "child"), ("parent", "file")),
            (("parent", "file"), ("parent/child.txt", "child")),
        )
        for index, members in enumerate(cases):
            with self.subTest(order=index):
                zip_path = os.path.join(self.tmp, f"conflict-{index}.zip")
                with zipfile.ZipFile(zip_path, "w") as archive:
                    for name, payload in members:
                        archive.writestr(name, payload)

                with self.assertRaises(RestoreError) as context:
                    restore_common.extract_backup_zip(
                        zip_path, os.path.join(self.tmp, f"conflict-{index}-out")
                    )

                self.assertIn("conflicting archive paths", str(context.exception))

    def test_preserves_hidden_empty_case_and_unicode_distinct_members(self):
        zip_path = os.path.join(self.tmp, "distinct.zip")
        composed = "caf\u00e9.txt"
        decomposed = "cafe\u0301.txt"
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr("empty-dir/", b"")
            archive.writestr(".hidden", b"")
            archive.writestr("Case.txt", "upper")
            archive.writestr("case.txt", "lower")
            archive.writestr(composed, "composed")
            archive.writestr(decomposed, "decomposed")

        destination = restore_common.extract_backup_zip(
            zip_path, os.path.join(self.tmp, "distinct-out")
        )

        self.assertTrue(os.path.isdir(os.path.join(destination, "empty-dir")))
        self.assertEqual(os.path.getsize(os.path.join(destination, ".hidden")), 0)
        expected = {
            "Case.txt": "upper",
            "case.txt": "lower",
            composed: "composed",
            decomposed: "decomposed",
        }
        for name, payload in expected.items():
            with open(os.path.join(destination, name), encoding="utf-8") as restored:
                self.assertEqual(restored.read(), payload)

    @override_settings(RESTORE_MAX_ARCHIVE_MEMBERS=1)
    def test_rejects_member_count_over_configured_limit(self):
        zip_path = self._make_zip(
            {"one.txt": "1", "two.txt": "2"}, name="too-many.zip"
        )

        with self.assertRaises(RestoreError) as context:
            restore_common.extract_backup_zip(
                zip_path, os.path.join(self.tmp, "too-many-out")
            )

        self.assertIn("too many archive members", str(context.exception))

    def test_rejects_crc_failure_without_publishing_destination(self):
        zip_path = self._make_zip({"site.txt": "crc payload"}, name="crc.zip")
        with zipfile.ZipFile(zip_path) as archive:
            info = archive.getinfo("site.txt")
        with open(zip_path, "r+b") as archive_file:
            archive_file.seek(info.header_offset)
            local = archive_file.read(30)
            filename_length, extra_length = struct.unpack_from("<HH", local, 26)
            payload_offset = info.header_offset + 30 + filename_length + extra_length
            archive_file.seek(payload_offset)
            first_byte = archive_file.read(1)
            archive_file.seek(payload_offset)
            archive_file.write(bytes([first_byte[0] ^ 0xFF]))

        destination = os.path.join(self.tmp, "crc-out")
        with self.assertRaises(RestoreError) as context:
            restore_common.extract_backup_zip(zip_path, destination)

        self.assertIn("CRC validation", str(context.exception))
        self.assertFalse(os.path.exists(destination))

    def test_rejects_unsupported_compression_method(self):
        zip_path = os.path.join(self.tmp, "bzip2.zip")
        with zipfile.ZipFile(
            zip_path, "w", compression=zipfile.ZIP_BZIP2
        ) as archive:
            archive.writestr("site.txt", "bzip2 payload")

        with self.assertRaises(RestoreError) as context:
            restore_common.extract_backup_zip(
                zip_path, os.path.join(self.tmp, "bzip2-out")
            )

        self.assertIn("compression method", str(context.exception))

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


class WebsiteRestoreSourceManifestTests(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _tree(self):
        tree_root = os.path.join(self.tmp, "tree")
        site_root = os.path.join(tree_root, "public_html")
        os.makedirs(site_root)
        return tree_root, site_root

    @staticmethod
    def _source():
        return {"path": "public_html", "type": "directory"}

    @staticmethod
    def _backup():
        return SimpleNamespace(uuid="bounded-website-restore")

    def _index_residue(self, tree_root):
        return [
            name
            for name in os.listdir(tree_root)
            if name.startswith(".backupsheep-source-manifest-")
        ]

    @override_settings(WEBSITE_RESTORE_INLINE_FILE_LIMIT=2)
    def test_large_source_persists_only_bounded_aggregate(self):
        tree_root, site_root = self._tree()
        os.makedirs(os.path.join(site_root, "empty"))
        os.makedirs(os.path.join(site_root, "nested"))
        for index in range(3):
            with open(os.path.join(site_root, f"file-{index}.txt"), "wb") as output:
                output.write(f"payload-{index}".encode())

        records, manifest = RW._prepare_sources(
            tree_root, [self._source()], self._backup()
        )
        record = records[0]
        summary = record["file_manifest"]

        self.assertEqual(summary["file_count"], 3)
        self.assertEqual(summary["directory_count"], 2)
        self.assertEqual(summary["member_count"], 5)
        self.assertEqual(summary["byte_count"], 27)
        self.assertEqual(record["files"], [])
        self.assertNotIn("files", manifest[record["source_key"]])
        state = RW._state_for(record, "pending", files_status="pending")
        self.assertNotIn("files", state)
        self.assertEqual(state["file_manifest"], summary)
        self.assertLess(len(json.dumps(manifest)), 1_000)
        self.assertEqual(self._index_residue(tree_root), [])

    @override_settings(WEBSITE_RESTORE_INLINE_FILE_LIMIT=10)
    def test_small_source_retains_detailed_file_checkpoints(self):
        tree_root, site_root = self._tree()
        for name, payload in (("z.txt", b"z"), ("a.txt", b"alpha")):
            with open(os.path.join(site_root, name), "wb") as output:
                output.write(payload)

        records, manifest = RW._prepare_sources(
            tree_root, [self._source()], self._backup()
        )
        record = records[0]

        self.assertEqual(
            [item["path"] for item in record["files"]], ["a.txt", "z.txt"]
        )
        self.assertEqual(
            list(RW._state_for(record, "pending")["files"]),
            ["a.txt", "z.txt"],
        )
        self.assertEqual(
            manifest[record["source_key"]]["files"], record["files"]
        )
        legacy_identity = {
            "backup_uuid": str(self._backup().uuid),
            "path": "public_html",
            "type": "directory",
            "files": record["files"],
        }
        self.assertEqual(
            record["source_digest"],
            hashlib.sha256(
                RW._canonical(legacy_identity).encode("utf-8")
            ).hexdigest(),
        )
        self.assertEqual(
            set(manifest[record["source_key"]]),
            {"path", "type", "source_digest", "files"},
        )
        RW._verify_source_manifest(record)
        self.assertEqual(self._index_residue(tree_root), [])

    @override_settings(WEBSITE_RESTORE_INLINE_FILE_LIMIT=0)
    def test_content_or_empty_directory_change_fails_reverification(self):
        tree_root, site_root = self._tree()
        payload = os.path.join(site_root, "index.html")
        with open(payload, "wb") as output:
            output.write(b"before")
        records, _manifest = RW._prepare_sources(
            tree_root, [self._source()], self._backup()
        )
        record = records[0]

        with open(payload, "wb") as output:
            output.write(b"after")
        with self.assertRaisesRegex(RestoreError, "changed after validation"):
            RW._verify_source_manifest(record)

        with open(payload, "wb") as output:
            output.write(b"before")
        os.makedirs(os.path.join(site_root, "new-empty-directory"))
        with self.assertRaisesRegex(RestoreError, "changed after validation"):
            RW._verify_source_manifest(record)
        self.assertEqual(self._index_residue(tree_root), [])

    def test_manifest_index_is_removed_after_unsupported_member(self):
        tree_root, site_root = self._tree()
        os.symlink("missing-target", os.path.join(site_root, "link"))

        with self.assertRaisesRegex(RestoreError, "symbolic link"):
            RW._prepare_sources(tree_root, [self._source()], self._backup())

        self.assertEqual(self._index_residue(tree_root), [])


class WebsiteRestoreEngineTests(RestoreBackendBase):
    """restore_website: lftp pushes the extracted tree back (mirror -R / put)."""

    def _run_engine(self, backup, restore):
        scripts = []

        def fake_run(cmd, **kwargs):
            script = kwargs.get("input") or ""
            scripts.append(script)
            stdout = ""
            if all(name in script for name in RW.RESTORE_NAME_FIDELITY_PROBES):
                stdout = "\n".join(RW.RESTORE_NAME_FIDELITY_PROBES)
            return SimpleNamespace(stdout=stdout, returncode=0)

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

    def test_restore_uses_backup_path_snapshot_after_node_configuration_changes(self):
        node, backup = self._website_backup(all_paths=True)
        backup.all_paths = True
        backup.paths = None
        backup.save(update_fields=["all_paths", "paths", "modified"])

        website = node.website
        website.all_paths = False
        website.paths = [
            {"path": "later-node-path", "type": "directory"},
        ]
        website.save(update_fields=["all_paths", "paths", "modified"])

        self._last_zip = self._make_zip({"index.html": "historical-root"})
        restore = self._restore_row(backup)
        scripts, _ = self._run_engine(backup, restore)

        self.assertIn("mirror -R", scripts[0])
        self.assertIn('"."', scripts[0])
        self.assertNotIn("later-node-path", scripts[0])

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

    def test_name_fidelity_probe_waits_for_archive_fetch(self):
        node, backup = self._website_backup(
            all_paths=False,
            paths=[{"path": "public_html", "type": "directory"}],
        )
        auth = node.connection.auth_website
        auth.protocol = CoreAuthWebsite.Protocol.SFTP
        auth.port = 22
        auth.save(update_fields=["protocol", "port", "modified"])
        self._last_zip = self._make_zip({"public_html/index.html": "hi"})
        restore = self._restore_row(backup)

        with mock.patch.object(
            CoreAuthWebsite, "check_connection", lambda *args, **kwargs: None
        ), mock.patch.object(
            RW, "_preflight_restore_target"
        ) as permission_probe, mock.patch.object(
            RW,
            "fetch_backup_zip",
            side_effect=RestoreError("archive provider is still preparing the object"),
        ), mock.patch.object(
            RW, "_preflight_restore_name_fidelity"
        ) as name_probe, mock.patch.object(RW, "delete_from_disk"):
            with self.assertRaisesRegex(RestoreError, "still preparing"):
                RW.restore_website(backup, restore)

        permission_probe.assert_called_once()
        name_probe.assert_not_called()

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
        self.assertTrue(import_argv[0].endswith("/mysql"))
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

    def test_mariadb_import_uses_vendor_client_and_preserves_sandbox_header(self):
        node, backup = self._database_backup(
            db_type=CoreAuthDatabase.DatabaseType.MARIADB,
            version="mariadb_11_8",
        )
        dump = (
            b"/*M!999999\\- enable the sandbox mode */\n"
            b"CREATE TABLE restored(id int);\n"
        )
        restore = self._db_restore(backup, {"appdb.sql": dump})
        calls = []
        imported = []

        def fake_run(argv, **kwargs):
            calls.append({"argv": list(argv), "kwargs": kwargs})
            imported.append(kwargs["stdin"].read())
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        with mock.patch.object(
            RD,
            "_ensure_mysql_target",
            side_effect=[{"state": "importing", "_new": True}, {"state": "complete"}],
        ), mock.patch.object(RD, "_mysql_query", return_value=""):
            self._run_engine(backup, restore, fake_run)

        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0]["argv"][0].endswith("/mariadb"))
        self.assertEqual(imported, [dump])

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
        with mock.patch.object(RD, "_postgres_query", side_effect=["1\n", "0\n"]):
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

    def test_target_name_collision_keeps_actionable_terminal_code(self):
        node, backup, restore = self._restore()
        error = RestoreError("destination listing contained secret-canary")
        error.code = "RESTORE_TARGET_NAME_COLLISION"
        error.retryable = False
        with mock.patch(
            "apps._tasks.integration.restore_website.restore_website",
            side_effect=error,
        ):
            restore_tasks.restore_website_backup.apply(
                args=[node.id, backup.id, restore.id]
            )

        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreWebsiteRestore.Status.FAILED)
        self.assertEqual(
            restore.last_error_code, "RESTORE_TARGET_NAME_COLLISION"
        )
        self.assertIn("cannot preserve distinct", restore.error)
        self.assertNotIn("secret-canary", restore.error)


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
                      "storage_point", "created", "created_display", "modified_display"):
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
                      "storage_point", "created", "created_display", "modified_display"):
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

    def test_deep_tree_stack_abort_retries_same_push_serially(self):
        node, backup = self._website_backup(all_paths=True)
        self._last_zip = self._make_zip({"index.html": "hi"})
        restore = self._restore_row(backup)
        scripts = []

        def fake_run(cmd, **kwargs):
            scripts.append(kwargs.get("input") or "")
            if len(scripts) == 1:
                return SimpleNamespace(
                    stdout=(
                        "lftp: SMTask.cc:152: static void SMTask::Enter(SMTask*): "
                        "Assertion `stack_ptr<SMTASK_MAX_DEPTH' failed.\n"
                    ),
                    returncode=-6,
                )
            return SimpleNamespace(stdout="", returncode=0)

        cleanup = self._run(backup, restore, fake_run)
        cleanup.apply_async.assert_called_once()
        self.assertEqual(len(scripts), 2)
        self.assertIn("--parallel=3", scripts[0])
        self.assertIn("--parallel=1", scripts[1])
        self.assertIn("set net:connection-limit 1", scripts[1])
        with open(f"_storage/restore_{backup.uuid_str}.log") as log:
            self.assertIn("serial directory traversal", log.read())

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
