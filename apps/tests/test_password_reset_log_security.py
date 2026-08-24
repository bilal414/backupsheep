from unittest import mock

from apps.console.member.models import CoreMember
from apps.console.notification.models import CoreNotificationLogEmail
from apps.tests.base import BaseTestCase


class PasswordResetLogSecurityTests(BaseTestCase):
    @mock.patch.object(CoreNotificationLogEmail, "send")
    @mock.patch.object(
        CoreMember,
        "issue_password_reset_token",
        return_value="password-reset-bearer-canary",
    )
    def test_reset_bearer_exists_only_in_delivery_context(self, issue_token, send):
        self.member.send_password_reset()

        row = CoreNotificationLogEmail.objects.get(template="password_reset")
        persisted = " ".join(
            [
                str(row.context or ""),
                str(row.html_body or ""),
                str(row.text_body or ""),
                str(row.subject or ""),
            ]
        )
        self.assertNotIn("password-reset-bearer-canary", persisted)
        self.assertEqual(
            row.context["action_url"], "[redacted password reset link]"
        )
        send.assert_called_once_with(
            delivery_context={
                "action_url": (
                    "http://localhost:8000/reset/password-reset-bearer-canary/"
                )
            },
            persist_rendered=False,
        )
        issue_token.assert_called_once_with()
