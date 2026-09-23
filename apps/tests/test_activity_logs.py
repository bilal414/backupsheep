"""Activity-log coverage: CoreLog.record()/prune(), the console + API log filters,
the auth signals, and a representative sample of the API call sites that now emit
activity rows. External side effects (celery dispatch) are mocked; login endpoints
need the onboarding gate marked configured (same helper pattern as test_auth).
"""
import json
from datetime import datetime, timedelta, timezone as datetime_timezone
from urllib.parse import parse_qs
from unittest import mock

from django.contrib.auth.models import Group
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.test import override_settings
from django.utils import timezone
from django.utils.text import slugify

from apps.console.account.models import CoreAccount, CoreAccountGroup
from apps.console.backup.models import CoreWebsiteBackup, CoreWebsiteBackupStoragePoints
from apps.console.log.models import CoreLog
from apps.console.member.models import CoreMemberAccount
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


class ActivityPresentationTests(BaseTestCase):
    def test_success_is_only_claimed_from_explicit_or_narrow_evidence(self):
        prose_only = CoreLog.record(
            self.account,
            CoreLog.Type.BACKUP,
            {
                "message": "Backup successful and ready.",
                "actor_email": self.user.email,
            },
        )
        explicit = CoreLog.record(
            self.account,
            CoreLog.Type.BACKUP,
            {"message": "Provider callback received.", "outcome": "SUCCESS"},
        )
        login = CoreLog.record(
            self.account,
            CoreLog.Type.AUTH,
            {"message": "Signed in.", "action": "LOGIN"},
        )

        self.assertEqual(prose_only.build_presentation().outcome_label, "Recorded")
        self.assertEqual(explicit.build_presentation().outcome_label, "Succeeded")
        self.assertEqual(login.build_presentation().outcome_label, "Succeeded")

    def test_reconciliation_is_progress_and_placeholder_error_is_omitted(self):
        row = CoreLog.record(
            self.account,
            CoreLog.Type.BACKUP,
            {
                "message": "Backup is still being reconciled by Oracle Cloud.",
                "error": "N/A",
            },
        )

        presentation = row.build_presentation()

        self.assertEqual(presentation.outcome_label, "In progress")
        self.assertEqual(presentation.error, "")

    def test_display_text_scrubs_credentials_and_credential_urls(self):
        row = CoreLog.record(
            self.account,
            CoreLog.Type.GENERIC,
            {
                "message": (
                    "Worker returned Bearer bearer-secret-123 "
                    "password=plain-secret "
                    "postgres://db-user:db-pass@db.internal:5432/customer"
                ),
                "error": "api_key=private-key-456",
            },
        )

        presentation = row.build_presentation()
        displayed = f"{presentation.message} {presentation.error}"

        self.assertIn("Bearer [Filtered]", displayed)
        self.assertIn("password=[Filtered]", displayed)
        self.assertIn("api_key=[Filtered]", displayed)
        self.assertIn("postgres://db.internal:5432/[Filtered]", displayed)
        for secret in (
            "bearer-secret-123",
            "plain-secret",
            "private-key-456",
            "db-user",
            "db-pass",
        ):
            self.assertNotIn(secret, displayed)

    def test_display_text_has_strict_output_and_processing_bounds(self):
        row = CoreLog.record(
            self.account,
            CoreLog.Type.GENERIC,
            {
                "message": "m" * 100_000,
                "error": "e" * 100_000,
                "request_id": "r" * 10_000,
            },
        )

        presentation = row.build_presentation()

        self.assertEqual(len(presentation.message), 1200)
        self.assertEqual(len(presentation.error), 1200)
        self.assertEqual(len(presentation.request_id), 160)

    def test_bulk_presenter_does_not_issue_per_row_queries(self):
        node = factories.make_website_node(self.account, self.member)
        rows = [
            CoreLog.record(
                self.account,
                CoreLog.Type.NODE,
                {"node_id": node.id, "message": f"row {index}"},
            )
            for index in range(10)
        ]
        node_connection = node.connection

        with CaptureQueriesContext(connection) as queries:
            CoreLog.attach_presentations(
                rows,
                nodes_by_id={node.id: node},
                connections_by_id={node.connection_id: node_connection},
            )
            rendered = [row.presentation.subject_label for row in rows]

        self.assertEqual(len(queries), 0)
        self.assertEqual(rendered, [node.name] * 10)


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

    def test_search_actor_and_outcome_filters_compose(self):
        target = CoreLog.record(
            self.account,
            CoreLog.Type.RESTORE,
            {
                "message": "Restore request alpha was rejected.",
                "actor_email": "operator@example.com",
                "outcome": "FAILED",
            },
        )
        CoreLog.record(
            self.account,
            CoreLog.Type.RESTORE,
            {
                "message": "Restore request alpha accepted.",
                "actor_email": "someone@example.com",
                "outcome": "accepted",
            },
        )

        response = self.client.get(
            "/console/logs/",
            {"q": "alpha", "actor": "operator@", "outcome": "failed"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual([row.id for row in self._rows(response)], [target.id])

    def test_outcome_filter_matches_case_insensitive_presenter_aliases(self):
        explicit = [
            CoreLog.record(
                self.account,
                CoreLog.Type.BACKUP,
                {"message": stored, "outcome": stored},
            )
            for stored in ("SUCCESS", "Succeeded", "oK")
        ]
        prose_only = CoreLog.record(
            self.account,
            CoreLog.Type.BACKUP,
            {"message": "Backup successful.", "actor_email": self.user.email},
        )

        response = self.client.get("/console/logs/", {"outcome": "succeeded"})
        returned_ids = {row.id for row in self._rows(response)}

        self.assertTrue({row.id for row in explicit}.issubset(returned_ids))
        self.assertNotIn(prose_only.id, returned_ids)
        self.assertTrue(
            all(
                row.build_presentation().outcome_label == "Succeeded"
                for row in explicit
            )
        )

    def test_date_filter_uses_member_timezone_and_inclusive_calendar_day(self):
        self.member.timezone = "America/Chicago"
        self.member.save(update_fields=["timezone", "modified"])
        timestamps = (
            datetime(2026, 8, 30, 4, 59, tzinfo=datetime_timezone.utc),
            datetime(2026, 8, 30, 5, 0, tzinfo=datetime_timezone.utc),
            datetime(2026, 8, 31, 4, 59, tzinfo=datetime_timezone.utc),
            datetime(2026, 8, 31, 5, 0, tzinfo=datetime_timezone.utc),
        )
        rows = []
        for index, created in enumerate(timestamps):
            row = CoreLog.record(
                self.account,
                CoreLog.Type.GENERIC,
                {"message": f"boundary-{index}"},
            )
            CoreLog.objects.filter(pk=row.pk).update(created=created)
            rows.append(row)

        response = self.client.get(
            "/console/logs/",
            {"date_from": "2026-08-30", "date_to": "2026-08-30"},
        )
        returned_ids = {row.id for row in self._rows(response)}

        self.assertNotIn(rows[0].id, returned_ids)
        self.assertIn(rows[1].id, returned_ids)
        self.assertIn(rows[2].id, returned_ids)
        self.assertNotIn(rows[3].id, returned_ids)

    def test_page_size_is_a_view_preference_not_an_active_filter(self):
        response = self.client.get("/console/logs/", {"p_size": "25"})

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["filters_active"])
        self.assertEqual(response.context["filter_count"], 0)

    def test_pagination_uses_only_validated_state_and_preserves_scope(self):
        for index in range(30):
            CoreLog.record(
                self.account,
                CoreLog.Type.BACKUP,
                {
                    "message": f"pagination needle {index}",
                    "backup_id": 77,
                },
            )

        response = self.client.get(
            "/console/logs/",
            {
                "backup": "77",
                "q": "pagination needle",
                "p_size": "25",
                "unexpected": "do-not-reflect",
            },
        )
        query = parse_qs(response.context["pagination_query"])
        clear_query = parse_qs(response.context["clear_filters_query"])

        self.assertEqual(response.context["logs_count"], 30)
        self.assertEqual(
            query,
            {
                "backup": ["77"],
                "q": ["pagination needle"],
                "p_size": ["25"],
            },
        )
        self.assertEqual(clear_query, {"backup": ["77"], "p_size": ["25"]})
        self.assertNotContains(response, "do-not-reflect")

    def test_invalid_type_param_is_ignored(self):
        r = self.client.get("/console/logs/", {"type": "abc"})
        self.assertEqual(r.status_code, 200)
        # Nothing is filtered out (force_login above also wrote an AUTH row).
        self.assertEqual(len(self._rows(r)), CoreLog.objects.count())

    def test_stale_backup_log_without_connection_does_not_500(self):
        """Historical rows may outlive the connection they reference."""
        node = factories.make_website_node(self.account, self.member)
        CoreLog.record(
            self.account,
            CoreLog.Type.BACKUP,
            {"node_id": node.id, "backup_id": 987654, "message": "legacy row"},
        )

        response = self.client.get("/console/logs/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "987654")

    def test_template_has_one_h1_scope_truth_and_no_raw_json(self):
        row = CoreLog.record(
            self.account,
            CoreLog.Type.GENERIC,
            {
                "message": "Trace included Bearer never-render-this-token",
                "unreviewed_internal_field": "never-render-raw-json",
            },
        )

        response = self.client.get("/console/logs/", {"q": "Trace included"})
        content = response.content.decode()

        self.assertEqual(response.status_code, 200)
        self.assertIn(row.id, [item.id for item in self._rows(response)])
        self.assertEqual(content.count("<h1"), 1)
        self.assertContains(response, "not an immutable audit archive")
        self.assertContains(response, "Bearer [Filtered]")
        self.assertNotContains(response, "never-render-this-token")
        self.assertNotContains(response, "never-render-raw-json")
        self.assertContains(response, "<caption", html=False)

    def test_malformed_pagination_and_numeric_filters_are_ignored(self):
        response = self.client.get(
            "/console/logs/",
            {
                "p_no": "not-a-page",
                "p_size": "not-a-size",
                "node": "not-a-node",
                "backup": "not-a-backup",
                "integration": "not-an-integration",
            },
        )

        self.assertEqual(response.status_code, 200)


class RestrictedConsoleLogScopeTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        auth_group = Group.objects.create(
            name=slugify(f"activity-scope-{self.account.id}")
        )
        self.group = CoreAccountGroup.objects.create(
            account=self.account,
            group=auth_group,
            name="activity scope",
            type=CoreAccountGroup.Type.Client,
            default=False,
        )
        _account, self.restricted_member, self.restricted_user = factories.make_account(
            email=f"activity-restricted-{self.account.id}@example.com"
        )
        self.restricted_member.memberships.filter(current=True).update(current=False)
        CoreMemberAccount.objects.create(
            member=self.restricted_member,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=True,
            primary=False,
        )
        self.restricted_user.groups.add(auth_group)
        self.allowed_node = factories.make_website_node(self.account, self.member)
        self.hidden_node = factories.make_website_node(self.account, self.member)
        self.group.nodes.add(self.allowed_node)

    def test_self_actor_does_not_restore_revoked_resource_visibility(self):
        allowed = CoreLog.record(
            self.account,
            CoreLog.Type.NODE,
            {
                "message": "allowed source event",
                "node_id": self.allowed_node.id,
            },
        )
        allowed_legacy_string_id = CoreLog.record(
            self.account,
            CoreLog.Type.NODE,
            {
                "message": "allowed legacy source event",
                "node_id": str(self.allowed_node.id),
            },
        )
        hidden = CoreLog.record(
            self.account,
            CoreLog.Type.NODE,
            {
                "message": "hidden source event",
                "node_id": self.hidden_node.id,
                "actor_email": self.restricted_user.email,
            },
        )
        own_identity = CoreLog.record(
            self.account,
            CoreLog.Type.MEMBER,
            {
                "message": "own profile event",
                "actor_email": self.restricted_user.email,
            },
        )
        self.client.force_login(self.restricted_user)

        response = self.client.get("/console/logs/")
        returned_ids = {row.id for row in response.context["page"].object_list}

        self.assertEqual(response.status_code, 200)
        self.assertIn(allowed.id, returned_ids)
        self.assertIn(allowed_legacy_string_id.id, returned_ids)
        self.assertIn(own_identity.id, returned_ids)
        self.assertNotIn(hidden.id, returned_ids)
        self.assertNotContains(response, "hidden source event")
        self.assertEqual(response.context["scope_mode"], "assigned")

    def test_api_uses_same_revoked_source_and_identity_scope(self):
        allowed = CoreLog.record(
            self.account,
            CoreLog.Type.NODE,
            {
                "message": "api allowed source event",
                "node_id": self.allowed_node.id,
            },
        )
        allowed_legacy_string_id = CoreLog.record(
            self.account,
            CoreLog.Type.NODE,
            {
                "message": "api allowed legacy source event",
                "node_id": str(self.allowed_node.id),
            },
        )
        hidden = CoreLog.record(
            self.account,
            CoreLog.Type.NODE,
            {
                "message": "api hidden source event",
                "node_id": self.hidden_node.id,
                "actor_email": self.restricted_user.email,
            },
        )
        own_identity = CoreLog.record(
            self.account,
            CoreLog.Type.AUTH,
            {
                "message": "api own identity event",
                "actor_email": self.restricted_user.email,
            },
        )
        own_resource_auth = CoreLog.record(
            self.account,
            CoreLog.Type.AUTH,
            {
                "message": "api hidden resource auth event",
                "actor_email": self.restricted_user.email,
                "node_id": self.hidden_node.id,
            },
        )
        another_identity = CoreLog.record(
            self.account,
            CoreLog.Type.MEMBER,
            {
                "message": "another member identity event",
                "actor_email": self.user.email,
            },
        )
        self.client.force_login(self.restricted_user)

        response = self.client.get("/api/v1/logs/")
        returned_ids = {row["id"] for row in response.json()}

        self.assertEqual(response.status_code, 200)
        self.assertIn(allowed.id, returned_ids)
        self.assertIn(allowed_legacy_string_id.id, returned_ids)
        self.assertIn(own_identity.id, returned_ids)
        self.assertNotIn(hidden.id, returned_ids)
        self.assertNotIn(own_resource_auth.id, returned_ids)
        self.assertNotIn(another_identity.id, returned_ids)


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

    def test_null_and_non_mapping_legacy_data_fail_closed(self):
        null_row = CoreLog.objects.create(
            account=self.account,
            type=CoreLog.Type.GENERIC,
            data=None,
        )
        list_row = CoreLog.objects.create(
            account=self.account,
            type=CoreLog.Type.GENERIC,
            data=[{"message": "not an event mapping"}],
        )
        scalar_row = CoreLog.objects.create(
            account=self.account,
            type=CoreLog.Type.GENERIC,
            data="legacy scalar",
        )

        response = self.client.get("/api/v1/logs/")
        by_id = {row["id"]: row for row in response.json()}

        self.assertEqual(response.status_code, 200)
        self.assertEqual(by_id[null_row.id]["data"], {})
        self.assertEqual(by_id[list_row.id]["data"], {})
        self.assertEqual(by_id[scalar_row.id]["data"], {})

    def test_api_recursively_redacts_secrets_but_preserves_safe_structure(self):
        row = CoreLog.record(
            self.account,
            CoreLog.Type.GENERIC,
            {
                "node_id": 42,
                "correlation_id": "corr-safe-123",
                "notes": 999,
                "message": (
                    "Worker returned Bearer api-bearer-secret "
                    "password=message-password"
                ),
                "api_key": "top-level-key",
                "callback_url": (
                    "https://url-user:url-password@provider.invalid/"
                    "signed/path?token=query-secret"
                ),
                "nested": {
                    "safe_id": 17,
                    "label": "safe label",
                    "password": "nested-password",
                },
                "items": [
                    {
                        "request_id": "req-safe-456",
                        "token": "nested-token",
                    }
                ],
            },
        )

        response = self.client.get("/api/v1/logs/")
        api_row = next(item for item in response.json() if item["id"] == row.id)
        data = api_row["data"]
        serialized = json.dumps(data, sort_keys=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["node_id"], 42)
        self.assertEqual(data["correlation_id"], "corr-safe-123")
        self.assertEqual(data["notes"], 999)
        self.assertEqual(data["nested"]["safe_id"], 17)
        self.assertEqual(data["nested"]["label"], "safe label")
        self.assertEqual(data["items"][0]["request_id"], "req-safe-456")
        self.assertEqual(data["api_key"], "[Filtered]")
        self.assertEqual(data["nested"]["password"], "[Filtered]")
        self.assertEqual(data["items"][0]["token"], "[Filtered]")
        self.assertEqual(
            data["callback_url"],
            "https://provider.invalid/[Filtered]",
        )
        self.assertIn("Bearer [Filtered]", data["message"])
        self.assertIn("password=[Filtered]", data["message"])
        for secret in (
            "api-bearer-secret",
            "message-password",
            "top-level-key",
            "url-user",
            "url-password",
            "query-secret",
            "nested-password",
            "nested-token",
        ):
            self.assertNotIn(secret, serialized)


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
        # Schedule triggers are accepted through the durable transactional
        # outbox; publication uses the dispatch module's Celery app.
        with mock.patch("apps._tasks.backup_dispatch.current_app") as capp:
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

    @override_settings(
        BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=True,
        BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=False,
    )
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
        self.assertEqual(
            CoreLog.objects.filter(
                account=self.account,
                type=CoreLog.Type.AUTH,
            ).count(),
            1,
        )

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
