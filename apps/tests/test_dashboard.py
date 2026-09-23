from apps.console.backup.models import CoreWebsiteBackup
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class DashboardTests(BaseTestCase):
    def test_dashboard_shows_recovery_brief_and_upcoming_schedule(self):
        node = factories.make_website_node(self.account, self.member)
        schedule = factories.make_schedule(node, self.member)
        CoreWebsiteBackup.objects.create(
            website=node.website,
            status=UtilBackup.Status.COMPLETE,
        )
        self.client.force_login(self.user)

        response = self.client.get("/console/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Recovery operations")
        self.assertContains(response, "No flagged records found")
        self.assertContains(response, "Recent operations")
        self.assertContains(response, "Next scheduled")
        self.assertContains(
            response,
            "These are observed operational facts, not a recovery-readiness assessment.",
        )
        self.assertNotContains(response, "Open exceptions")
        self.assertNotContains(response, "Latest activity")
        self.assertEqual(response.context["visible_node_count"], 1)
        self.assertEqual(response.context["active_schedule_count"], 1)
        self.assertEqual(list(response.context["upcoming_schedules"]), [schedule])

    def test_dashboard_uses_neutral_empty_state_for_connected_source(self):
        factories.make_website_node(self.account, self.member)
        self.client.force_login(self.user)

        response = self.client.get("/console/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No run history yet")
        self.assertContains(response, "No backup runs are recorded in this view.")
        self.assertContains(response, "No run records yet")
        self.assertContains(
            response,
            "Review connected sources and activate a schedule to begin recording activity.",
        )
        self.assertNotContains(response, "No flagged records found")

    def test_dashboard_guides_empty_workspace_to_add_source(self):
        self.client.force_login(self.user)

        response = self.client.get("/console/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No run history yet")
        self.assertContains(response, "No run records yet")
        self.assertContains(
            response,
            "Connect a source and activate a schedule to begin building operational history.",
        )
        self.assertContains(response, "Add a source to begin recording backup activity.")

    def test_dashboard_labels_bounded_review_records_honestly(self):
        node = factories.make_website_node(self.account, self.member)
        for _ in range(5):
            CoreWebsiteBackup.objects.create(
                website=node.website,
                status=UtilBackup.Status.MAX_RETRY_FAILED,
            )
        self.client.force_login(self.user)

        response = self.client.get("/console/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["failed_backups"]), 4)
        self.assertContains(response, "Latest flagged records")
        self.assertContains(response, "Up to four records in review states.")
        self.assertContains(response, "4 shown")
        self.assertNotContains(response, "Open exceptions")
        self.assertTrue(
            all(
                backup.dashboard_status_tone == "incident"
                for backup in response.context["failed_backups"]
            )
        )

    def test_dashboard_distinguishes_active_schedule_without_calculable_run(self):
        node = factories.make_website_node(self.account, self.member)
        schedule = factories.make_schedule(node, self.member)
        schedule.minute = "invalid"
        schedule.save(update_fields=["minute"])
        self.client.force_login(self.user)

        response = self.client.get("/console/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["active_schedule_count"], 1)
        self.assertEqual(response.context["upcoming_schedules"], [])
        self.assertContains(response, "No upcoming run available")
        self.assertContains(
            response,
            "An active schedule exists, but its next run could not be calculated.",
        )
