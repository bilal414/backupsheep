"""Crash-safe OVH regional and UpCloud provider-boundary tests.

No provider credentials or live calls are used here.  Every response is a small
deterministic fake so a test can prove that an ambiguous create is reconciled or
fenced before a second provider mutation is possible.
"""

from unittest import mock

import requests as raw_requests

from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import CoreBackupExecution, CoreCloudRestore
from apps.console.connection.models import (
    CoreAuthOVHCA,
    CoreAuthOVHEU,
    CoreAuthOVHUS,
    CoreAuthUpCloud,
    CoreIntegration,
)
from apps.console.node.models import (
    CoreNode,
    _restore_http_class,
)
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class Response:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


def ovh_source(source_id="source-1", region="GRA9"):
    return {"id": source_id, "region": region, "status": "ACTIVE", "flavorId": "b2-7"}


def ovh_snapshot(snapshot_id, marker, source_id="source-1", region="GRA9", project_id="project-1"):
    return {
        "id": snapshot_id,
        "name": marker,
        "instanceId": source_id,
        "region": region,
        "projectId": project_id,
        "status": "creating",
        "size": 12,
    }


def ovh_restore_target(resource_id, marker, source_id="snapshot-1", region="GRA9", project_id="project-1"):
    return {
        "id": resource_id,
        "name": marker,
        "imageId": source_id,
        "region": region,
        "projectId": project_id,
        "status": "BUILD",
    }


def upcloud_storage(
    storage_id,
    marker,
    source_id="source-1",
    zone="us-chi1",
    storage_type=None,
):
    value = {
        "uuid": storage_id,
        "title": marker,
        "origin": source_id,
        "zone": zone,
        "state": "cloning",
        "size": 10,
        "tier": "standard",
        "encrypted": "yes",
    }
    if storage_type:
        value["type"] = storage_type
    return value


class OVHUpCloudReliabilityTests(BaseTestCase):
    def _ovh(self, code, node_type=CoreNode.Type.CLOUD, region="GRA9"):
        CoreIntegration.objects.get_or_create(
            code=code,
            defaults={"type": CoreIntegration.Type.CLOUD, "enabled": True},
        )
        connection = factories.make_connection(self.account, self.member, code=code)
        auth_model = {
            "ovh_ca": CoreAuthOVHCA,
            "ovh_eu": CoreAuthOVHEU,
            "ovh_us": CoreAuthOVHUS,
        }[code]
        auth_model.objects.create(
            connection=connection,
            consumer_key=bs_encrypt("consumer-key", self.account.get_encryption_key()),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=node_type,
            name=f"{code}-source",
            added_by=self.member,
        )
        integration_class = {
            "ovh_ca": __import__("apps.console.node.models", fromlist=["CoreOVHCA"]).CoreOVHCA,
            "ovh_eu": __import__("apps.console.node.models", fromlist=["CoreOVHEU"]).CoreOVHEU,
            "ovh_us": __import__("apps.console.node.models", fromlist=["CoreOVHUS"]).CoreOVHUS,
        }[code]
        integration = integration_class.objects.create(
            node=node,
            name=f"{code}-source",
            unique_id="source-1",
            project_id="project-1",
            metadata={"_bs_region": region},
        )
        backup = integration.backups.create(
            uuid=f"{code}-backup-1",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
            celery_task_id=f"task-{code}",
        )
        return node, integration, backup, auth_model

    def _upcloud(self, node_type=CoreNode.Type.VOLUME, zone="us-chi1"):
        CoreIntegration.objects.get_or_create(
            code="upcloud",
            defaults={"type": CoreIntegration.Type.CLOUD, "enabled": True},
        )
        connection = factories.make_connection(self.account, self.member, code="upcloud")
        CoreAuthUpCloud.objects.create(
            connection=connection,
            username=bs_encrypt("test-user", self.account.get_encryption_key()),
            password=bs_encrypt("test-password", self.account.get_encryption_key()),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=node_type,
            name="upcloud-source",
            added_by=self.member,
        )
        from apps.console.node.models import CoreUpCloud

        integration = CoreUpCloud.objects.create(
            node=node,
            name="upcloud-source",
            unique_id="source-1",
            metadata={
                "_bs_zone": zone,
                "tier": "standard",
                "encrypted": "yes",
            },
        )
        backup = integration.backups.create(
            uuid="upcloud-backup-1",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
            celery_task_id="task-upcloud",
        )
        return node, integration, backup

    def _ovh_client(self, auth_model, responses):
        client = mock.MagicMock()
        client.get.side_effect = responses
        return mock.patch.object(auth_model, "get_client", return_value=client), client

    def test_ovh_all_regions_reconcile_page_two_without_post(self):
        for code in ("ovh_ca", "ovh_eu", "ovh_us"):
            with self.subTest(provider=code):
                _node, integration, backup, auth_model = self._ovh(code)
                second_page = {"snapshots": [ovh_snapshot("snap-2", backup.uuid_str)]}
                patcher, client = self._ovh_client(
                    auth_model,
                    [
                        ovh_source(),
                        {"snapshots": [], "next_page": 2},
                        second_page,
                    ],
                )
                with patcher, mock.patch.object(
                    self.account, "create_log", return_value=None
                ), mock.patch("apps.console.node.models.requests.post") as post:
                    integration.create_snapshot(backup)

                backup.refresh_from_db()
                self.assertEqual(backup.unique_id, "snap-2")
                self.assertEqual(client.get.call_count, 3)
                post.assert_not_called()
                state = backup.get_execution_state()
                self.assertEqual(state.provider_idempotency_key, backup.uuid_str)
                self.assertTrue(state.provider_metadata["scan_complete"])
                self.assertEqual(state.provider_metadata["scan_match_count"], 1)
                self.assertEqual(
                    state.reconciliation_state,
                    CoreBackupExecution.ReconciliationState.RESOLVED,
                )

    def test_ovh_lost_post_response_is_fenced_and_zero_match_is_manual_safe(self):
        _node, integration, backup, auth_model = self._ovh("ovh_eu")
        patcher, client = self._ovh_client(
            auth_model,
            [ovh_source(), {"snapshots": []}, raw_requests.Timeout("lost response")],
        )
        with patcher, mock.patch.object(
            self.account, "create_log", return_value=None
        ), mock.patch("apps.console.node.models.requests.post"):
            # OVH uses its SDK client, so make the SDK POST itself lose the response.
            client.post.side_effect = raw_requests.Timeout("provider-secret")
            with self.assertRaises(Exception):
                integration.create_snapshot(backup)

        backup.refresh_from_db()
        state = backup.get_execution_state()
        self.assertTrue(state.provider_metadata["create_attempted"])
        self.assertTrue(state.provider_metadata["outcome_unknown"])

        # A redelivery exhausts the complete collection and does not issue another
        # POST when the prior mutation has no unique provider witness.
        client.get.side_effect = [ovh_source(), {"snapshots": []}]
        client.post.reset_mock()
        with mock.patch.object(auth_model, "get_client", return_value=client), mock.patch.object(
            self.account, "create_log", return_value=None
        ):
            with self.assertRaises(Exception):
                integration.create_snapshot(backup)
        client.post.assert_not_called()
        state = backup.get_execution_state()
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
        )
        self.assertEqual(state.last_error_code, "PROVIDER_RECONCILIATION_REQUIRED")

    def test_ovh_repeated_page_fails_closed_without_post(self):
        _node, integration, backup, auth_model = self._ovh("ovh_ca")
        client = mock.MagicMock()
        client.get.side_effect = [
            ovh_source(),
            {"snapshots": [], "next_page": 2},
            {"snapshots": [], "next_page": 2},
        ]
        with mock.patch.object(auth_model, "get_client", return_value=client), mock.patch.object(
            self.account, "create_log", return_value=None
        ):
            with self.assertRaises(Exception):
                integration.create_snapshot(backup)
        client.post.assert_not_called()
        state = backup.get_execution_state()
        self.assertEqual(state.last_error_code, "PROVIDER_MALFORMED_RESPONSE")
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
        )

    def test_ovh_duplicate_or_missing_source_candidate_fails_closed(self):
        for snapshots, expected in (
            (
                [ovh_snapshot("one", "same"), ovh_snapshot("two", "same")],
                "PROVIDER_DUPLICATE_MATCH",
            ),
            (
                [{"id": "foreign", "name": "same", "region": "GRA9"}],
                "PROVIDER_OWNERSHIP_MISMATCH",
            ),
            (
                [{"id": "wrong-scope", "name": "same", "instanceId": "source-1", "region": "GRA9", "projectId": "other-project"}],
                "PROVIDER_OWNERSHIP_MISMATCH",
            ),
        ):
            with self.subTest(expected=expected):
                _node, integration, backup, auth_model = self._ovh("ovh_us")
                backup.uuid = "same"
                backup.save(update_fields=["uuid", "modified"])
                client = mock.MagicMock()
                client.get.side_effect = [ovh_source(), {"snapshots": snapshots}]
                with mock.patch.object(auth_model, "get_client", return_value=client), mock.patch.object(
                    self.account, "create_log", return_value=None
                ):
                    with self.assertRaises(Exception):
                        integration.create_snapshot(backup)
                client.post.assert_not_called()
                state = backup.get_execution_state()
                self.assertEqual(state.last_error_code, expected)
                if expected == "PROVIDER_DUPLICATE_MATCH":
                    self.assertTrue(state.reconciliation_metadata["scan_complete"])
                    self.assertEqual(state.reconciliation_metadata["scan_match_count"], len(snapshots))

    def test_ovh_successful_create_is_redelivery_safe_and_persists_id_before_return(self):
        _node, integration, backup, auth_model = self._ovh("ovh_eu")
        backup.initialize_execution(celery_task_id="task-ovh", attempt_no=1)
        client = mock.MagicMock()
        client.get.side_effect = [ovh_source(), {"snapshots": []}]
        client.post.return_value = {"id": "snap-created", "status": "creating", "size": 9}
        with mock.patch.object(auth_model, "get_client", return_value=client), mock.patch.object(
            self.account, "create_log", return_value=None
        ):
            from apps._tasks.helper.tasks import run_provider_create

            self.assertIsNotNone(run_provider_create(backup, "task-ovh", integration.create_snapshot))
            self.assertIsNotNone(run_provider_create(backup, "task-ovh", integration.create_snapshot))
        self.assertEqual(client.post.call_count, 1)
        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "snap-created")
        state = backup.get_execution_state()
        self.assertEqual(state.provider_resource_id, "snap-created")
        self.assertTrue(state.provider_metadata["adopted"])

    def test_ovh_restore_lost_response_adopts_page_two_and_never_posts_twice(self):
        _node, integration, backup, auth_model = self._ovh("ovh_ca")
        backup.unique_id = "snapshot-1"
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["unique_id", "status", "modified"])
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="customer-visible-restore",
            params={"flavor_id": "b2-7", "region": "GRA9"},
        )
        marker = f"backupsheep-restore-{restore.pk}"
        client = mock.MagicMock()
        client.get.side_effect = [
            {"instances": [], "next_page": 2},
            {"instances": []},
        ]
        client.post.side_effect = raw_requests.Timeout("lost restore response")
        with mock.patch.object(auth_model, "get_client", return_value=client):
            result = integration.restore_snapshot(backup, restore)
        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
        restore.refresh_from_db()
        self.assertTrue(restore.params["_bs_create_outcome_unknown"])
        self.assertEqual(restore.params["_bs_last_error_code"], "PROVIDER_TIMEOUT")
        self.assertEqual(client.post.call_count, 1)

        client.get.side_effect = [
            {"instances": [], "next_page": 2},
            {"instances": [ovh_restore_target("restored-1", marker, "snapshot-1")]},
        ]
        client.post.reset_mock()
        with mock.patch.object(auth_model, "get_client", return_value=client):
            integration.restore_snapshot(backup, restore)
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "restored-1")
        self.assertFalse(restore.params["_bs_create_outcome_unknown"])
        client.post.assert_not_called()

    def test_ovh_restore_duplicate_and_missing_source_are_manual_review(self):
        _node, integration, backup, auth_model = self._ovh("ovh_us")
        backup.unique_id = "snapshot-1"
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["unique_id", "status", "modified"])
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="restore",
            params={"flavor_id": "b2-7", "region": "GRA9", "_bs_create_outcome_unknown": True},
        )
        marker = f"backupsheep-restore-{restore.pk}"
        client = mock.MagicMock()
        client.get.return_value = {
            "instances": [
                ovh_restore_target("one", marker),
                ovh_restore_target("two", marker),
            ]
        }
        with mock.patch.object(auth_model, "get_client", return_value=client):
            with self.assertRaises(ValueError):
                integration.restore_snapshot(backup, restore)
        restore.refresh_from_db()
        self.assertEqual(restore.params["_bs_last_error_code"], "PROVIDER_DUPLICATE_MATCH")
        client.post.assert_not_called()

        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="missing-source",
            params={"region": "GRA9", "_bs_create_outcome_unknown": True},
        )
        marker = f"backupsheep-restore-{restore.pk}"
        missing_source = ovh_restore_target("foreign", marker)
        missing_source.pop("imageId")
        client.get.return_value = {"instances": [missing_source]}
        with mock.patch.object(auth_model, "get_client", return_value=client):
            with self.assertRaises(ValueError):
                integration.restore_snapshot(backup, restore)
        restore.refresh_from_db()
        self.assertEqual(restore.params["_bs_last_error_code"], "PROVIDER_OWNERSHIP_MISMATCH")
        client.post.assert_not_called()

    def test_upcloud_backup_page_two_duplicate_and_repeated_cursor_guards(self):
        _node, integration, backup = self._upcloud()
        client = mock.MagicMock()
        source = Response(
            200,
            {
                "storage": {
                    "uuid": "source-1",
                    "zone": "us-chi1",
                    "tier": "standard",
                    "encrypted": "yes",
                }
            },
        )
        page_two = Response(200, {"storages": {"storage": [upcloud_storage("u-2", backup.uuid_str)]}})
        client.get.side_effect = [
            source,
            Response(200, {"storages": {"storage": [], "next_cursor": "cursor-2"}}),
            page_two,
        ]
        with mock.patch.object(integration.node.connection.auth_upcloud.__class__, "get_verified_client", return_value=client), mock.patch(
            "apps.console.node.models.requests.get", side_effect=client.get.side_effect
        ), mock.patch("apps.console.node.models.requests.post") as post:
            integration.create_snapshot(backup)
        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "u-2")
        post.assert_not_called()

        # A repeated page token is malformed and cannot fall through to POST.
        _node, integration, backup = self._upcloud()
        client = mock.MagicMock()
        client.get.side_effect = [
            source,
            Response(200, {"storages": {"storage": [], "next_cursor": "cursor-2"}}),
            Response(200, {"storages": {"storage": [], "next_cursor": "cursor-2"}}),
        ]
        with mock.patch.object(integration.node.connection.auth_upcloud.__class__, "get_verified_client", return_value=client), mock.patch(
            "apps.console.node.models.requests.get", side_effect=client.get.side_effect
        ), mock.patch("apps.console.node.models.requests.post") as post:
            with self.assertRaises(Exception):
                integration.create_snapshot(backup)
        post.assert_not_called()
        self.assertEqual(backup.get_execution_state().last_error_code, "PROVIDER_MALFORMED_RESPONSE")

        # A matching marker without the provider's zone is not positive ownership.
        _node, integration, backup = self._upcloud()
        client = mock.MagicMock()
        client.get.side_effect = [
            source,
            Response(200, {"storages": {"storage": [{
                "uuid": "missing-zone",
                "title": backup.uuid_str,
                "origin": "source-1",
            }]}}),
        ]
        with mock.patch.object(integration.node.connection.auth_upcloud.__class__, "get_verified_client", return_value=client), mock.patch(
            "apps.console.node.models.requests.get", side_effect=client.get.side_effect
        ), mock.patch("apps.console.node.models.requests.post") as post:
            with self.assertRaises(Exception):
                integration.create_snapshot(backup)
        post.assert_not_called()
        self.assertEqual(backup.get_execution_state().last_error_code, "PROVIDER_OWNERSHIP_MISMATCH")

    def test_upcloud_successful_create_persists_provider_id_before_return(self):
        _node, integration, backup = self._upcloud()
        client = mock.MagicMock()
        client.get.side_effect = [
            Response(
                200,
                {
                    "storage": {
                        "uuid": "source-1",
                        "zone": "us-chi1",
                        "tier": "standard",
                        "encrypted": "yes",
                    }
                },
            ),
            Response(200, {"storages": {"storage": []}}),
        ]
        created = Response(201, {"storage": upcloud_storage("u-created", backup.uuid_str)})
        auth_cls = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(auth_cls, "get_verified_client", return_value=client), mock.patch(
            "apps.console.node.models.requests.get", side_effect=client.get.side_effect
        ), mock.patch("apps.console.node.models.requests.post", return_value=created) as post:
            integration.create_snapshot(backup)
        post.assert_called_once()
        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "u-created")
        self.assertEqual(backup.get_execution_state().provider_resource_id, "u-created")

    def test_upcloud_restore_page_two_adoption_duplicate_and_no_post(self):
        _node, integration, backup = self._upcloud()
        backup.unique_id = "backup-storage-1"
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["unique_id", "status", "modified"])
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="restore",
            params={"zone": "us-chi1", "_bs_create_outcome_unknown": True},
        )
        marker = (
            f"backupsheep-upcloud-{restore.pk}-"
            f"{integration._upcloud_restore_marker_digest(restore, backup.unique_id)}"
        )[:128]
        source = Response(
            200,
            {
                "storage": {
                    "uuid": backup.unique_id,
                    "title": backup.uuid_str,
                    "origin": integration.unique_id,
                    "zone": "us-chi1",
                    "type": "backup",
                    "state": "online",
                    "size": 10,
                }
            },
        )
        restored = upcloud_storage(
            "restored",
            marker,
            "backup-storage-1",
            storage_type="normal",
        )
        unrelated = upcloud_storage(
            "unrelated",
            "another-restore",
            "another-backup",
            storage_type="normal",
        )

        def page_two_get(url, **kwargs):
            if str(url).endswith(f"/storage/{backup.unique_id}"):
                return source
            if str(url).endswith("/storage/normal"):
                offset = kwargs.get("params", {}).get("offset")
                page = [unrelated] if offset == 0 else [restored]
                return Response(
                    200,
                    {"storages": {"storage": page}},
                    headers={"UpCloud-Total-Count": "2"},
                )
            raise AssertionError("Unexpected UpCloud GET in restore test.")

        client = mock.MagicMock()
        auth_cls = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=client
        ), mock.patch(
            "apps.console.node.models.requests.get", side_effect=page_two_get
        ) as get, mock.patch(
            "apps.console.node.models.requests.post"
        ) as post:
            integration.restore_snapshot(backup, restore)
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "restored")
        self.assertEqual(
            [
                call.kwargs["params"]["offset"]
                for call in get.call_args_list
                if "params" in call.kwargs
            ],
            [0, 1],
        )
        post.assert_not_called()

        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="duplicate",
            params={"zone": "us-chi1", "_bs_create_outcome_unknown": True},
        )
        marker = (
            f"backupsheep-upcloud-{restore.pk}-"
            f"{integration._upcloud_restore_marker_digest(restore, backup.unique_id)}"
        )[:128]
        duplicate_candidates = [
            upcloud_storage(
                "one", marker, "backup-storage-1", storage_type="normal"
            ),
            upcloud_storage(
                "two", marker, "backup-storage-1", storage_type="normal"
            ),
        ]

        def duplicate_page_get(url, **kwargs):
            if str(url).endswith(f"/storage/{backup.unique_id}"):
                return source
            if str(url).endswith("/storage/normal"):
                offset = kwargs.get("params", {}).get("offset")
                if offset not in (0, 1):
                    raise AssertionError("Unexpected UpCloud storage offset.")
                return Response(
                    200,
                    {
                        "storages": {
                            "storage": [duplicate_candidates[offset]]
                        }
                    },
                    headers={"UpCloud-Total-Count": "2"},
                )
            raise AssertionError("Unexpected UpCloud GET in restore test.")

        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=client
        ), mock.patch(
            "apps.console.node.models.requests.get",
            side_effect=duplicate_page_get,
        ) as get, mock.patch(
            "apps.console.node.models.requests.post"
        ) as post:
            with self.assertRaises(ValueError):
                integration.restore_snapshot(backup, restore)
        post.assert_not_called()
        self.assertEqual(
            [
                call.kwargs["params"]["offset"]
                for call in get.call_args_list
                if "params" in call.kwargs
            ],
            [0, 1],
        )
        restore.refresh_from_db()
        self.assertEqual(restore.params["_bs_last_error_code"], "PROVIDER_DUPLICATE_MATCH")

    def test_provider_http_categories_are_distinct_and_secret_free(self):
        for status, code in (
            (404, "PROVIDER_NOT_FOUND"),
            (401, "PROVIDER_AUTH_FAILED"),
            (429, "PROVIDER_RATE_LIMIT"),
            (504, "PROVIDER_TIMEOUT"),
            (503, "PROVIDER_TRANSIENT_OUTAGE"),
            (422, "PROVIDER_FAILED"),
        ):
            with self.subTest(status=status):
                error = _restore_http_class(
                    Response(status, {"message": "provider-secret"}), mutation=True
                )
                self.assertEqual(error.code, code)
                self.assertNotIn("provider-secret", str(error))
