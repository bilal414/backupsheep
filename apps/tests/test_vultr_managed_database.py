from types import SimpleNamespace
from unittest import mock

import requests
from django.test import SimpleTestCase

from apps.console.vultr_database import (
    VultrDatabaseCapabilities,
    VultrDatabaseDuplicateError,
    VultrDatabaseError,
    VultrDatabaseUnsupportedError,
    VultrManagedDatabaseClient,
)
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import CoreVultrDatabaseBackup, CoreVultrDatabaseRestore
from apps.console.connection.models import CoreAuthVultr
from apps.console.node.models import CoreNode, CoreVultrDatabase
from apps.console.utils.models import UtilBackup
from apps._tasks.integration.vultr_database import restore_vultr_database
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
            with self.assertRaisesRegex(VultrDatabaseError, "repeated a cursor"):
                VultrManagedDatabaseClient(FakeAuth()).list_databases()

        with mock.patch("apps.console.vultr_database.requests.request", return_value=FakeResponse({}, 429)):
            with self.assertRaisesRegex(VultrDatabaseError, "HTTP 429") as context:
                VultrManagedDatabaseClient(FakeAuth()).get_database("db-1")
        self.assertEqual(context.exception.category, "rate_limited")

    def test_capability_checks_are_explicit(self):
        with self.assertRaises(VultrDatabaseUnsupportedError):
            VultrDatabaseCapabilities("kafka", "startup").require_backup_support()
        with self.assertRaises(VultrDatabaseUnsupportedError):
            VultrDatabaseCapabilities("postgresql", "vultr-dbaas-hobbyist").require_fork_support()
        VultrDatabaseCapabilities("mysql", "vultr-dbaas-startup").require_fork_support()


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
        self.assertEqual(context.exception.category, "transient_outage")


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
            type=CoreNode.Type.CLOUD,
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

    def _backup(self):
        return CoreVultrDatabaseBackup.objects.create(
            vultr_database=self.database,
            uuid="backup-1",
            name="managed-db backup",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )

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
