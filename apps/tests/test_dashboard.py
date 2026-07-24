from apps.console.log.models import CoreLog
from apps.tests import factories
from apps.tests.base import BaseTestCase


class DashboardTests(BaseTestCase):
    def test_dashboard_shows_recent_activity_and_upcoming_schedule(self):
        node = factories.make_website_node(self.account, self.member)
        schedule = factories.make_schedule(node, self.member)
        CoreLog.record(
            self.account,
            CoreLog.Type.NODE,
            {"message": "Node is protected.", "node_id": node.id},
        )
        self.client.force_login(self.user)

        response = self.client.get("/console/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Operational pulse")
        self.assertEqual(response.context["visible_node_count"], 1)
        self.assertEqual(response.context["active_schedule_count"], 1)
        self.assertEqual(list(response.context["upcoming_schedules"]), [schedule])
        self.assertIn(
            node.id,
            [log.data.get("node_id") for log in response.context["recent_activity"]],
        )
