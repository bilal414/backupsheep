"""Activity-log coverage: CoreLog.record()/prune(), the console + API log filters,
the auth signals, and a representative sample of the API call sites that now emit
activity rows. External side effects (celery dispatch) are mocked; login endpoints
need the onboarding gate marked configured (same helper pattern as test_auth).
"""
from datetime import timedelta
from unittest import mock

from django.test import override_settings
from django.utils import timezone

from apps.console.account.models import CoreAccount
from apps.console.backup.models import CoreWebsiteBackup, CoreWebsiteBackupStoragePoints
from apps.console.log.models import CoreLog
from apps.console.setting.models import CoreSiteSettings
from apps.console.storage.models import CoreStorage, CoreStorageLocal, CoreStorageType
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


def _mark_configured():
    s = CoreSiteSettings.load()
    s.setup_completed = True
    s.save()
    OnboardingMiddleware._completed = False  # force re-read of the DB flag


class CoreLogRecordTests(BaseTestCase):
    def test_record_creates_a_row_for_every_type(self):
        for log_type in CoreLog.Type.values:
            row = CoreLog.record(self.account, log_type, {"message": f"type {log_type}"})
            self.assertIsNotNone(row)
            self.assertEqual(row.type, log_type)
            self.assertEqual(row.account, self.account)
            self.assertEqual(row.data, {"message": f"type {log_type}"})
        self.assertEqual(CoreLog.objects.filter(account=self.account).count(), len(CoreLog.Type.values))

    def test_record_coerces_non_dict_data(self):
        row = CoreLog.record(self.account, CoreLog.Type.GENERIC, None)
        self.assertEqual(row.data, {"message": "None"})
        row = CoreLog.record(self.account, CoreLog.Type.GENERIC, "plain string")
        self.assertEqual(row.data, {"message": "plain string"})
        row = CoreLog.record(self.account, CoreLog.Type.GENERIC, 123)
        self.assertEqual(row.data, {"message": "123"})

    def test_record_never_raises_on_junk(self):
        before = CoreLog.objects.count()
        # All rejected before any SQL is issued, so the test transaction stays intact.
        self.assertIsNone(CoreLog.record(self.account, "not-a-number", {"message": "x"}))
        self.assertIsNone(CoreLog.record(self.account, CoreLog.Type.GENERIC, {"bad": object()}))
        self.assertIsNone(CoreLog.record(None, CoreLog.Type.GENERIC, {"message": "x"}))
        self.assertIsNone(CoreLog.record(CoreAccount(), CoreLog.Type.GENERIC, {"message": "x"}))
        self.assertEqual(CoreLog.objects.count(), before)


class CoreLogPruneTests(BaseTestCase):
    def _aged_record(self, days_old):
        row = CoreLog.record(self.account, CoreLog.Type.GENERIC, {"message": f"{days_old}d old"})
        CoreLog.objects.filter(pk=row.pk).update(created=timezone.now() - timedelta(days=days_old))
        return row

    @override_settings(LOG_RETENTION_DAYS=30)
    def test_prune_deletes_only_rows_older_than_the_retention_window(self):
        old = self._aged_record(40)
        edge = self._aged_record(29)
        fresh = self._aged_record(1)

        deleted = CoreLog.prune()

        self.assertEqual(deleted, 1)
        remaining = set(CoreLog.objects.values_list("id", flat=True))
        self.assertNotIn(old.id, remaining)
        self.assertIn(edge.id, remaining)
        self.assertIn(fresh.id, remaining)

    @override_settings(LOG_RETENTION_DAYS=10)
    def test_prune_honours_configured_retention(self):
        old = self._aged_record(20)
        fresh = self._aged_record(5)

        deleted = CoreLog.prune()

        self.assertEqual(deleted, 1)
        remaining = set(CoreLog.objects.values_list("id", flat=True))
        self.assertNotIn(old.id, remaining)
        self.assertIn(fresh.id, remaining)

    @override_settings(LOG_RETENTION_DAYS=30)
    def test_prune_returns_zero_when_nothing_is_old(self):
        self._aged_record(2)
        self.assertEqual(CoreLog.prune(), 0)


class ConsoleLogViewFilterTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        CoreLog.record(self.account, CoreLog.Type.NODE, {"message": "node alpha paused"})
        CoreLog.record(self.account, CoreLog.Type.SCHEDULE, {"message": "nightly schedule triggered"})
        CoreLog.record(self.account, CoreLog.Type.BACKUP, {"message": "download ready", "error": "disk nearly full"})
        self.client.force_login(self.user)

    def _rows(self, response):
        return list(response.context["page"].object_list)

    def test_type_filter_applies(self):
        r = self.client.get("/console/logs/", {"type": CoreLog.Type.SCHEDULE})
        self.assertEqual(r.status_code, 200)
        rows = self._rows(r)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].type, CoreLog.Type.SCHEDULE)

    def test_message_filter_applies(self):
        r = self.client.get("/console/logs/", {"message": "paused"})
        self.assertEqual(r.status_code, 200)
        rows = self._rows(r)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].data["message"], "node alpha paused")

    def test_error_filter_applies(self):
        r = self.client.get("/console/logs/", {"error": "disk"})
        self.assertEqual(r.status_code, 200)
        rows = self._rows(r)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].data["error"], "disk nearly full")

    def test_invalid_type_param_is_ignored(self):
        r = self.client.get("/console/logs/", {"type": "abc"})
        self.assertEqual(r.status_code, 200)
        # Nothing is filtered out (force_login above also wrote an AUTH row).
        self.assertEqual(len(self._rows(r)), CoreLog.objects.count())


class ApiLogViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.older = CoreLog.record(
            self.account, CoreLog.Type.NODE,
            {"message": "old", "node_id": 5, "connection_id": 7},
        )
        # BACKUP (not AUTH): force_login writes an AUTH row via the login signal,
        # which must not leak into these assertions.
        self.newer = CoreLog.record(
            self.account, CoreLog.Type.BACKUP,
            {"message": "new", "actor_email": self.user.email},
        )
        # Force distinct timestamps so the default ordering assertion is meaningful.
        CoreLog.objects.filter(pk=self.older.pk).update(created=timezone.now() - timedelta(hours=2))
        CoreLog.objects.filter(pk=self.newer.pk).update(created=timezone.now() - timedelta(hours=1))
        self.client.force_login(self.user)

    def test_default_ordering_is_newest_first(self):
        r = self.client.get("/api/v1/logs/")
        self.assertEqual(r.status_code, 200)
        mine = {self.older.id, self.newer.id}
        ids = [row["id"] for row in r.json() if row["id"] in mine]
        self.assertEqual(ids, [self.newer.id, self.older.id])

    def test_type_filter(self):
        r = self.client.get("/api/v1/logs/", {"type": CoreLog.Type.BACKUP})
        self.assertEqual(r.status_code, 200)
        rows = r.json()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], self.newer.id)

    def test_node_and_integration_passthrough_filters(self):
        r = self.client.get("/api/v1/logs/", {"node": 5})
        self.assertEqual([row["id"] for row in r.json()], [self.older.id])
        r = self.client.get("/api/v1/logs/", {"node": 999})
        self.assertEqual(r.json(), [])
        r = self.client.get("/api/v1/logs/", {"integration": 7})
        self.assertEqual([row["id"] for row in r.json()], [self.older.id])
        r = self.client.get("/api/v1/logs/", {"integration": 999})
        self.assertEqual(r.json(), [])


class ViewActionLogTests(BaseTestCase):
    """Representative call sites: a sample action per area must emit an activity row
    carrying actor_email, without changing the response contract."""

    def test_node_pause_emits_node_log_with_actor(self):
        node = factories.make_website_node(self.account, self.member)
        self.client.force_login(self.user)
        r = self.client.post(f"/api/v1/nodes/{node.id}/pause/")
        self.assertEqual(r.status_code, 200)
        log = CoreLog.objects.get(account=self.account, type=CoreLog.Type.NODE)
        self.assertEqual(log.data["action"], "pause")
        self.assertEqual(log.data["actor_email"], self.user.email)
        self.assertEqual(log.data["node_id"], node.id)

    def test_schedule_pause_emits_schedule_log(self):
        node = factories.make_website_node(self.account, self.member)
        schedule = factories.make_schedule(node, self.member)
        self.client.force_login(self.user)
        r = self.client.post(f"/api/v1/schedules/{schedule.id}/pause/")
        self.assertEqual(r.status_code, 200)
        log = CoreLog.objects.get(account=self.account, type=CoreLog.Type.SCHEDULE)
        self.assertEqual(log.data["action"], "pause")
        self.assertEqual(log.data["actor_email"], self.user.email)
        self.assertEqual(log.data["schedule_id"], schedule.id)

    def test_schedule_trigger_emits_schedule_log(self):
        node = factories.make_website_node(self.account, self.member)
        schedule = factories.make_schedule(node, self.member)
        self.client.force_login(self.user)
        with mock.patch("apps.api.v1.schedule.views.current_app") as capp:
            r = self.client.post(
                f"/api/v1/schedules/{schedule.id}/trigger/",
                {"request_id": "req-activity-1"},
                content_type="application/json",
            )
        self.assertEqual(r.status_code, 201)
        capp.send_task.assert_called_once()
        log = CoreLog.objects.get(account=self.account, type=CoreLog.Type.SCHEDULE)
        self.assertEqual(log.data["action"], "trigger")
        self.assertEqual(log.data["actor_email"], self.user.email)
        self.assertEqual(log.data["schedule_id"], schedule.id)

    def test_backup_download_emits_backup_log(self):
        node = factories.make_website_node(self.account, self.member)
        storage = CoreStorage.objects.create(
            account=self.account, type=CoreStorageType.objects.get(code="local"),
            name="local-store", added_by=self.member,
        )
        CoreStorageLocal.objects.create(storage=storage)
        backup = CoreWebsiteBackup.objects.create(
            website=node.website, uuid="t-activity-dl",
            status=UtilBackup.Status.COMPLETE, attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        point = CoreWebsiteBackupStoragePoints.objects.create(
            backup=backup, storage=storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="/backups/x.zip",
        )
        self.client.force_login(self.user)
        # Local storage generates an in-app streaming URL -- no external calls.
        r = self.client.get(
            f"/api/v1/backups/website/{backup.id}/download/",
            {"storage_point_id": point.id},
        )
        self.assertEqual(r.status_code, 201)
        log = CoreLog.objects.get(account=self.account, type=CoreLog.Type.BACKUP)
        self.assertEqual(log.data["action"], "download")
        self.assertEqual(log.data["actor_email"], self.user.email)
        self.assertEqual(log.data["backup_id"], backup.id)
        self.assertEqual(log.data["node_id"], node.id)


class AuthSignalLogTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        _mark_configured()  # so OnboardingMiddleware doesn't intercept /api/

    def test_successful_login_writes_auth_log(self):
        r = self.client.post("/api/v1/auth/login/",
                             {"email": self.user.email, "password": "x-Secret-123"},
                             content_type="application/json")
        self.assertEqual(r.status_code, 200)
        log = CoreLog.objects.get(account=self.account, type=CoreLog.Type.AUTH)
        self.assertEqual(log.data["action"], "login")
        self.assertEqual(log.data["actor_email"], self.user.email)
        self.assertTrue(log.data.get("ip"))

    def test_failed_login_known_email_writes_auth_log(self):
        r = self.client.post("/api/v1/auth/login/",
                             {"email": self.user.email, "password": "wrong"},
                             content_type="application/json")
        self.assertNotEqual(r.status_code, 200)
        log = CoreLog.objects.get(account=self.account, type=CoreLog.Type.AUTH)
        self.assertEqual(log.data["action"], "login_failed")
        self.assertEqual(log.data["actor_email"], self.user.username)

    def test_failed_login_unknown_email_skips_silently(self):
        r = self.client.post("/api/v1/auth/login/",
                             {"email": "nobody@example.com", "password": "x-Secret-123"},
                             content_type="application/json")
        # No crash, and no account to attach a row to -> nothing logged.
        self.assertNotEqual(r.status_code, 200)
        self.assertEqual(CoreLog.objects.filter(type=CoreLog.Type.AUTH).count(), 0)
