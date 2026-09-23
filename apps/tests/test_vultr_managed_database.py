from types import SimpleNamespace
from unittest import mock

import requests
from django.test import SimpleTestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.api.v1.node.views import CoreNodeView
from apps.api.v1.backup.vultr_database.views import CoreVultrDatabaseBackupView
from apps.console.vultr_database import (
    VultrDatabaseCapabilities,
    VultrDatabaseDuplicateError,
    VultrDatabaseError,
    VultrDatabaseUnsupportedError,
    VultrManagedDatabaseClient,
)
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import (
    CoreBackupRequest,
    CoreCloudRestore,
    CoreVultrDatabaseBackup,
    CoreVultrDatabaseRestore,
)
from apps.console.connection.models import CoreAuthVultr
from apps.console.node.models import CoreNode, CoreVultrDatabase
from apps.console.utils.models import UtilBackup
from apps._tasks.integration.vultr_database import _backup_for_task, restore_vultr_database
from apps.tests import factories
from apps.tests.base import BaseTestCase


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.status_code = status_code
        self.reason = "provider error"
        self.content = b"{}"
        self._payload = payload

    def json(self):
        return self._payload


class FakeAuth:
    def get_client(self):
        return {"Authorization": "Bearer test-only"}


class VultrManagedDatabaseClientTests(SimpleTestCase):
    def test_database_discovery_uses_cursor_detail_and_usage(self):
        responses = [
            FakeResponse({
                "databases": [{"id": "db-1", "label": "primary", "database_engine": "postgresql", "region": "ewr", "plan": "startup"}],
                "meta": {"links": {"next": "cursor-2"}},
            }),
            FakeResponse({"databases": [{"id": "db-2", "label": "unsupported", "database_engine": "kafka"}], "meta": {"links": {}}}),
            FakeResponse({"database": {"id": "db-1", "status": "running"}}),
            FakeResponse({"disk": {"usage": 12}}),
            FakeResponse({"database": {"id": "db-2", "status": "running"}}),
            FakeResponse({"disk": {"usage": 3}}),
        ]
        with mock.patch("apps.console.vultr_database.requests.request", side_effect=responses) as request:
            databases = VultrManagedDatabaseClient(FakeAuth()).discover_databases()

        self.assertEqual([item["_bs_unique_id"] for item in databases], ["db-1", "db-2"])
        self.assertEqual(databases[0]["_bs_size"], 12)
        self.assertTrue(databases[0]["_bs_supported"])
        self.assertFalse(databases[1]["_bs_supported"])
        self.assertEqual(request.call_args_list[1].kwargs["params"]["cursor"], "cursor-2")
        self.assertEqual(request.call_args_list[2].args[1], "https://api.vultr.com/v2/databases/db-1")
        self.assertEqual(request.call_args_list[3].args[1], "https://api.vultr.com/v2/databases/db-1/usage")
        self.assertEqual(request.call_args_list[0].kwargs["timeout"], (10, 60))

    def test_cursor_loop_and_provider_error_are_fail_closed(self):
        repeated = FakeResponse({"databases": [], "meta": {"links": {"next": "same"}}})
        with mock.patch("apps.console.vultr_database.requests.request", side_effect=[repeated, repeated]):
            with self.assertRaises(VultrDatabaseError) as context:
                VultrManagedDatabaseClient(FakeAuth()).list_databases()
        self.assertEqual(context.exception.category, "terminal_failure")
        self.assertNotIn("same", str(context.exception))

        with mock.patch("apps.console.vultr_database.requests.request", return_value=FakeResponse({}, 429)):
            with self.assertRaisesRegex(VultrDatabaseError, "HTTP 429") as context:
                VultrManagedDatabaseClient(FakeAuth()).get_database("db-1")
        self.assertEqual(context.exception.category, "rate_limited")

    def test_backup_metadata_uses_plural_backups_endpoint(self):
        response = FakeResponse({
            "latest_backup": {"date": "2026-08-04", "time": "12:00:00"},
            "oldest_backup": {"date": "2026-08-02", "time": "12:00:00"},
        })
        with mock.patch(
            "apps.console.vultr_database.requests.request", return_value=response
        ) as request:
            records = VultrManagedDatabaseClient(FakeAuth()).list_backup_records("db-1")

        self.assertEqual(len(records), 2)
        self.assertEqual(request.call_args.args[1], "https://api.vultr.com/v2/databases/db-1/backups")

    def test_capability_checks_are_explicit(self):
        with self.assertRaises(VultrDatabaseUnsupportedError):
            VultrDatabaseCapabilities("kafka", "startup").require_backup_support()
        with self.assertRaises(VultrDatabaseUnsupportedError):
            VultrDatabaseCapabilities("postgresql", "vultr-dbaas-hobbyist").require_fork_support()
        VultrDatabaseCapabilities("mysql", "vultr-dbaas-startup").require_fork_support()
        VultrDatabaseCapabilities("valkey", "vultr-dbaas-startup").require_fork_support()
        with self.assertRaises(VultrDatabaseUnsupportedError):
            VultrDatabaseCapabilities("valkey", "vultr-dbaas-startup").require_fork_support("pitr")


class VultrManagedDatabaseStateTests(SimpleTestCase):
    def test_provider_error_categories_distinguish_not_found_and_transient(self):
        client = VultrManagedDatabaseClient(FakeAuth())
        for status_code, category in ((404, "not_found"), (429, "rate_limited"), (503, "transient_outage"), (400, "terminal_failure")):
            with self.subTest(status_code=status_code), mock.patch(
                "apps.console.vultr_database.requests.request",
                return_value=FakeResponse({}, status_code),
            ):
                with self.assertRaises(VultrDatabaseError) as context:
                    client.get_database("db-1")
                self.assertEqual(context.exception.category, category)

    def test_request_timeout_is_classified_as_transient_outage(self):
        with mock.patch(
            "apps.console.vultr_database.requests.request",
            side_effect=requests.Timeout("lost response"),
        ):
            with self.assertRaises(VultrDatabaseError) as context:
                VultrManagedDatabaseClient(FakeAuth()).get_database("db-1")
        self.assertEqual(context.exception.category, "timeout")

    def test_provider_body_and_exception_text_never_enter_public_error_state(self):
        canary = "provider-secret-canary-4c4d"
        with mock.patch(
            "apps.console.vultr_database.requests.request",
            return_value=FakeResponse({"error": canary, "token": canary}, 503),
        ):
            with self.assertRaises(VultrDatabaseError) as context:
                VultrManagedDatabaseClient(FakeAuth()).get_database("db-1")

        error = context.exception
        self.assertNotIn(canary, str(error))
        self.assertNotIn(canary, repr(error))
        self.assertNotIn(canary, repr(error.payload))
        self.assertEqual(error.category, "transient_outage")
        self.assertFalse(error.unknown_outcome)


class VultrManagedDatabaseModelTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        connection = factories.make_connection(self.account, self.member, code="vultr")
        CoreAuthVultr.objects.create(
            connection=connection,
            api_key=bs_encrypt("test-only", self.account.get_encryption_key()),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.DATABASE,
            name="managed-db",
            added_by=self.member,
        )
        self.database = CoreVultrDatabase.objects.create(
            node=node,
            name="managed-db",
            unique_id="source-db",
            engine="postgresql",
            region="ewr",
            plan="vultr-dbaas-startup",
        )

    def test_managed_database_uses_database_node_routing(self):
        self.assertEqual(self.database.node.backup_task_name(), "backup_vultr_database")
        self.assertIs(self.database.node._integration_object(), self.database)
        self.assertEqual(self.database.node.get_node_url, f"/console/databases/vultr/{self.database.id}")

    def _backup(self):
        return CoreVultrDatabaseBackup.objects.create(
            vultr_database=self.database,
            uuid="backup-1",
            name="managed-db backup",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )

    def _request(self, task_id):
        return CoreBackupRequest.objects.create(
            request_key=f"vultr-db-request-{task_id}",
            task_id=task_id,
            task_name="backup_vultr_database",
            node=self.database.node,
        )

    def _post_node_restore(self, backup, request_id, **overrides):
        payload = {
            "backup_id": backup.id,
            "name": "restored-managed-database",
            "params": {},
            "confirm": True,
            "request_id": request_id,
        }
        payload.update(overrides)
        request = APIRequestFactory().post(
            f"/api/v1/nodes/{self.database.node_id}/restore_backup/",
            payload,
            format="json",
        )
        force_authenticate(request, user=self.user)
        return CoreNodeView.as_view({"post": "restore_backup"})(
            request, pk=self.database.node_id
        )

    def test_node_restore_api_uses_durable_vultr_database_request(self):
        backup = self._backup()
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["status", "modified"])

        with mock.patch(
            "apps._tasks.integration.vultr_database.restore_vultr_database.apply_async"
        ) as dispatch:
            with self.captureOnCommitCallbacks(execute=True):
                first = self._post_node_restore(backup, "vultr-db-ui-request")
            with self.captureOnCommitCallbacks(execute=True):
                replay = self._post_node_restore(backup, "vultr-db-ui-request")

        self.assertEqual(first.status_code, 201)
        self.assertEqual(replay.status_code, 200)
        self.assertFalse(first.data["idempotent_replay"])
        self.assertTrue(replay.data["idempotent_replay"])
        self.assertEqual(first.data["id"], replay.data["id"])
        self.assertEqual(CoreCloudRestore.objects.count(), 0)
        restore = CoreVultrDatabaseRestore.objects.get()
        self.assertEqual(first.data["correlation_id"], str(restore.correlation_id))
        self.assertEqual(first.data["backup"], backup.id)
        self.assertEqual(first.data["backup_id"], backup.id)
        self.assertEqual(replay.data["backup_id"], backup.id)
        self.assertEqual(first.data["execution_status"]["status"], "pending")
        self.assertNotIn("vultr-db-ui-request", str(first.data))
        dispatch.assert_called_once_with(
            task_id=restore.celery_task_id,
            args=[restore.id],
        )

        list_request = APIRequestFactory().get(
            f"/api/v1/nodes/{self.database.node_id}/restores/"
        )
        force_authenticate(list_request, user=self.user)
        listed = CoreNodeView.as_view({"get": "restores"})(
            list_request, pk=self.database.node_id
        )
        self.assertEqual(listed.status_code, 200)
        self.assertEqual([item["id"] for item in listed.data], [restore.id])
        self.assertEqual([item["backup_id"] for item in listed.data], [backup.id])

    def test_node_restore_api_rejects_vultr_database_key_reuse(self):
        backup = self._backup()
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["status", "modified"])
        with mock.patch(
            "apps._tasks.integration.vultr_database.restore_vultr_database.apply_async"
        ):
            with self.captureOnCommitCallbacks(execute=True):
                first = self._post_node_restore(backup, "vultr-db-conflict")
            conflict = self._post_node_restore(
                backup,
                "vultr-db-conflict",
                name="different-target",
            )

        self.assertEqual(first.status_code, 201)
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.data["code"], "restore_idempotency_conflict")
        self.assertEqual(CoreVultrDatabaseRestore.objects.count(), 1)

    def test_legacy_restore_api_requires_and_replays_idempotency_key(self):
        backup = self._backup()
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["status", "modified"])
        view = CoreVultrDatabaseBackupView.as_view({"post": "restore"})

        missing_request = APIRequestFactory().post(
            f"/api/v1/backups/vultr_database/{backup.id}/restore/",
            {"name": "legacy-target", "confirm": True},
            format="json",
        )
        force_authenticate(missing_request, user=self.user)
        missing = view(missing_request, pk=backup.id)
        self.assertEqual(missing.status_code, 503)
        self.assertEqual(CoreVultrDatabaseRestore.objects.count(), 0)

        payload = {
            "name": "legacy-target",
            "params": {},
            "confirm": True,
            "request_id": "legacy-safe-replay",
        }
        with mock.patch(
            "apps._tasks.integration.vultr_database.restore_vultr_database.apply_async"
        ) as dispatch:
            first_request = APIRequestFactory().post(
                f"/api/v1/backups/vultr_database/{backup.id}/restore/",
                payload,
                format="json",
            )
            force_authenticate(first_request, user=self.user)
            with self.captureOnCommitCallbacks(execute=True):
                first = view(first_request, pk=backup.id)
            replay_request = APIRequestFactory().post(
                f"/api/v1/backups/vultr_database/{backup.id}/restore/",
                payload,
                format="json",
            )
            force_authenticate(replay_request, user=self.user)
            with self.captureOnCommitCallbacks(execute=True):
                replay = view(replay_request, pk=backup.id)

        self.assertEqual(first.status_code, 201)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(first.data["id"], replay.data["id"])
        dispatch.assert_called_once()

    def test_database_backup_delivery_claim_is_durable(self):
        request = self._request("db-task-claimed")
        backup = _backup_for_task(
            self.database.node,
            "db-task-claimed",
            UtilBackup.Type.ON_DEMAND,
            1,
            None,
            "outbox claim",
        )

        self.assertIsNotNone(backup)
        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.CLAIMED)
        self.assertEqual(request.backup_object_id, backup.pk)

    def test_database_backup_duplicate_delivery_links_active_backup(self):
        active = self._backup()
        active.celery_task_id = "db-active-task"
        active.save(update_fields=["celery_task_id", "modified"])
        request = self._request("db-duplicate-task")

        result = _backup_for_task(
            self.database.node,
            "db-duplicate-task",
            UtilBackup.Type.ON_DEMAND,
            1,
            None,
            None,
        )

        self.assertIsNone(result)
        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.DUPLICATE)
        self.assertEqual(request.backup_object_id, active.pk)

    def test_provider_backup_is_adopted_with_source_marker_and_polls(self):
        backup = self._backup()
        record = {"id": "provider-backup-1", "status": "complete", "date": "2026-08-04"}
        with mock.patch.object(
            VultrManagedDatabaseClient, "list_backup_records", return_value=[record]
        ):
            self.database.create_snapshot(backup)
            self.assertEqual(backup.provider_marker, "vultr-db:source-db:provider-backup-1")
            self.assertEqual(backup.provider_backup_id, "provider-backup-1")
            self.assertEqual(backup.metadata["source_database_id"], "source-db")
            self.assertEqual(backup.poll_status(), UtilBackup.Status.COMPLETE)

    def test_backup_time_metadata_without_state_is_available(self):
        backup = self._backup()
        record = {"date": "2026-08-04", "time": "12:00:00"}
        with mock.patch.object(
            VultrManagedDatabaseClient, "list_backup_records", return_value=[record]
        ):
            self.database.create_snapshot(backup)
            self.assertEqual(backup.provider_state, "available")
            self.assertEqual(backup.poll_status(), UtilBackup.Status.COMPLETE)

    def test_backup_state_mapping_preserves_rate_limit_transient_and_not_found(self):
        for category, expected_status, expected_class in (
            ("rate_limited", UtilBackup.Status.IN_PROGRESS, "rate_limited"),
            ("transient_outage", UtilBackup.Status.IN_PROGRESS, "transient_outage"),
            ("not_found", UtilBackup.Status.FAILED, "not_found"),
            ("terminal_failure", UtilBackup.Status.FAILED, "terminal_failure"),
        ):
            with self.subTest(category=category):
                backup = self._backup()
                provider_id = f"provider-backup-{category}"
                backup.provider_backup_id = provider_id
                backup.provider_marker = f"vultr-db:source-db:{provider_id}"
                backup.save()
                with mock.patch.object(
                    VultrManagedDatabaseClient,
                    "list_backup_records",
                    side_effect=VultrDatabaseError(category, category=category, status_code=429 if category == "rate_limited" else None),
                ):
                    self.assertEqual(backup.poll_status(), expected_status)
                backup.refresh_from_db()
                self.assertEqual(backup.provider_error_class, expected_class)

    def test_fork_payload_is_new_cluster_and_redelivery_polls(self):
        backup = self._backup()
        backup.status = UtilBackup.Status.COMPLETE
        backup.provider_backup_id = "provider-backup-1"
        backup.provider_marker = "vultr-db:source-db:provider-backup-1"
        backup.save()
        restore = CoreVultrDatabaseRestore.objects.create(
            backup=backup,
            name="restore-request",
            params={"region": "ewr", "plan": "vultr-dbaas-startup"},
        )
        with mock.patch.object(VultrManagedDatabaseClient, "list_databases", return_value=[]), mock.patch.object(
            VultrManagedDatabaseClient,
            "fork_database",
            return_value={"database": {"id": "new-db"}, "job_id": "fork-job"},
        ) as fork:
            self.database.restore_snapshot(backup, restore)
            self.database.restore_snapshot(backup, restore)

        self.assertEqual(fork.call_count, 1)
        self.assertEqual(fork.call_args.args[0], "source-db")
        self.assertEqual(fork.call_args.args[1]["type"], "basebackup")
        self.assertNotEqual(fork.call_args.args[1]["label"], "restore-request")
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "new-db")
        self.assertEqual(restore.provider_job_id, "fork-job")

    def test_fork_restore_accepts_provider_region_case_normalization(self):
        backup = self._backup()
        backup.status = UtilBackup.Status.COMPLETE
        backup.provider_backup_id = "provider-backup-1"
        backup.provider_marker = "vultr-db:source-db:provider-backup-1"
        backup.save()
        restore = CoreVultrDatabaseRestore.objects.create(
            backup=backup,
            name="restore-region-case",
            params={"region": "ewr", "plan": "vultr-dbaas-startup"},
        )
        with mock.patch.object(VultrManagedDatabaseClient, "list_databases", return_value=[]), mock.patch.object(
            VultrManagedDatabaseClient,
            "fork_database",
            return_value={"database": {"id": "new-db"}},
        ):
            self.database.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        with mock.patch.object(
            VultrManagedDatabaseClient,
            "get_database",
            return_value={
                "id": "new-db",
                "label": restore.provider_marker,
                "region": "EWR",
                "plan": "vultr-dbaas-startup",
                "status": "Running",
            },
        ):
            self.assertEqual(
                self.database.check_restore(restore),
                CoreVultrDatabaseRestore.Status.COMPLETE,
            )

    def test_lost_fork_response_is_adopted_and_duplicate_candidates_fail_closed(self):
        backup = self._backup()
        backup.status = UtilBackup.Status.COMPLETE
        backup.save()
        restore = CoreVultrDatabaseRestore.objects.create(backup=backup, name="restore-request")
        with mock.patch.object(VultrManagedDatabaseClient, "list_databases", side_effect=[[], [{"id": "adopted-db", "label": "bs-restore-" + restore.uuid.hex[:20]}]]), mock.patch.object(
            VultrManagedDatabaseClient,
            "fork_database",
            side_effect=VultrDatabaseError("response lost", category="transient_outage"),
        ):
            with self.assertRaises(VultrDatabaseError):
                self.database.restore_snapshot(backup, restore)
            self.database.restore_snapshot(backup, restore)
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "adopted-db")

        duplicate = CoreVultrDatabaseRestore.objects.create(backup=backup, name="duplicate")
        marker = "bs-restore-" + duplicate.uuid.hex[:20]
        with mock.patch.object(
            VultrManagedDatabaseClient,
            "list_databases",
            return_value=[{"id": "one", "label": marker}, {"id": "two", "label": marker}],
        ):
            with self.assertRaises(VultrDatabaseDuplicateError):
                self.database.restore_snapshot(backup, duplicate)

    def test_unknown_fork_outcome_never_reposts_without_adoption(self):
        backup = self._backup()
        backup.status = UtilBackup.Status.COMPLETE
        backup.save()
        restore = CoreVultrDatabaseRestore.objects.create(backup=backup, name="restore-request")
        with mock.patch.object(VultrManagedDatabaseClient, "list_databases", return_value=[]), mock.patch.object(
            VultrManagedDatabaseClient,
            "fork_database",
            side_effect=VultrDatabaseError("response lost", category="transient_outage"),
        ) as fork:
            with self.assertRaises(VultrDatabaseError):
                self.database.restore_snapshot(backup, restore)
            self.assertEqual(fork.call_count, 1)

        with mock.patch.object(VultrManagedDatabaseClient, "list_databases", return_value=[]), mock.patch.object(
            VultrManagedDatabaseClient, "fork_database"
        ) as fork:
            self.database.restore_snapshot(backup, restore)
        fork.assert_not_called()
        restore.refresh_from_db()
        self.assertEqual(restore.provider_status, "create_unknown")
        self.assertEqual(restore.status, CoreVultrDatabaseRestore.Status.IN_PROGRESS)

    def test_restore_task_redelivery_reuses_persisted_target(self):
        backup = self._backup()
        backup.status = UtilBackup.Status.COMPLETE
        backup.save()
        restore = CoreVultrDatabaseRestore.objects.create(backup=backup, name="restore-request")
        with mock.patch.object(VultrManagedDatabaseClient, "list_databases", return_value=[]), mock.patch.object(
            VultrManagedDatabaseClient,
            "fork_database",
            return_value={"database": {"id": "new-db"}},
        ) as fork, mock.patch(
            "apps._tasks.integration.vultr_database.poll_vultr_database_restore.apply_async"
        ):
            restore_vultr_database.apply(kwargs={"restore_id": restore.id}, task_id="first-delivery")
            restore_vultr_database.apply(kwargs={"restore_id": restore.id}, task_id="redelivered")
        self.assertEqual(fork.call_count, 1)
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "new-db")
