from datetime import timedelta
from unittest import mock

from django.test import Client
from django.utils import timezone

from apps.console.notification.models import (
    CoreNotificationEmail,
    CoreNotificationLogEmail,
)
from apps.tests import factories
from apps.tests.base import BaseTestCase


class NotificationVerificationSecurityTests(BaseTestCase):
    @mock.patch.object(CoreNotificationLogEmail, "send")
    def test_verification_token_has_full_entropy_and_is_single_use(self, send):
        row = CoreNotificationEmail.objects.create(
            member=self.member,
            email="alerts@example.com",
        )
        row.send_verification_email()
        row.refresh_from_db()
        delivery = send.call_args.kwargs["delivery_context"]["action_url"]
        token = delivery.rstrip("/").rsplit("/", 1)[-1]
        self.assertGreaterEqual(len(token), 40)
        self.assertNotEqual(row.verify_code, token)
        self.assertEqual(
            row.verify_code,
            CoreNotificationEmail.verification_token_digest(token),
        )
        self.assertIsNotNone(row.verify_code_created)
        log = CoreNotificationLogEmail.objects.get(template="verify_email")
        persisted = " ".join(
            [
                str(log.context or ""),
                str(log.html_body or ""),
                str(log.text_body or ""),
            ]
        )
        self.assertNotIn(token, persisted)
        self.assertFalse(send.call_args.kwargs["persist_rendered"])

        client = Client()
        client.force_login(self.user)
        response = client.get(
            f"/console/notification/email/verify/{token}/"
        )
        self.assertEqual(response.status_code, 302)
        row.refresh_from_db()
        self.assertEqual(row.status, CoreNotificationEmail.Status.VERIFIED)
        self.assertIsNone(row.verify_code)
        self.assertIsNone(row.verify_code_created)

        replay = client.get(f"/console/notification/email/verify/{token}/")
        self.assertEqual(replay.status_code, 302)
        row.refresh_from_db()
        self.assertEqual(row.status, CoreNotificationEmail.Status.VERIFIED)
        self.assertEqual(send.call_count, 1)

    def test_expired_or_other_member_token_cannot_verify(self):
        row = CoreNotificationEmail.objects.create(
            member=self.member,
            email="alerts@example.com",
            verify_code=CoreNotificationEmail.verification_token_digest(
                "expired-verification-token"
            ),
            verify_code_created=timezone.now()
            - timedelta(hours=CoreNotificationEmail.VERIFY_TOKEN_TTL_HOURS + 1),
        )
        other_account, other_member, other_user = factories.make_account()
        client = Client()
        client.force_login(other_user)

        response = client.get(
            "/console/notification/email/verify/expired-verification-token/"
        )
        self.assertEqual(response.status_code, 302)
        row.refresh_from_db()
        self.assertEqual(row.status, CoreNotificationEmail.Status.UN_VERIFIED)
        self.assertEqual(
            row.verify_code,
            CoreNotificationEmail.verification_token_digest(
                "expired-verification-token"
            ),
        )

    @mock.patch.object(CoreNotificationLogEmail, "send")
    def test_reissuing_on_an_old_row_starts_a_fresh_token_ttl(self, send):
        row = CoreNotificationEmail.objects.create(
            member=self.member,
            email="old-row@example.com",
        )
        old = timezone.now() - timedelta(days=90)
        CoreNotificationEmail.objects.filter(pk=row.pk).update(
            created=old,
            modified=old,
        )

        row.refresh_from_db()
        row.send_verification_email()
        row.refresh_from_db()
        self.assertGreater(row.verify_code_created, old + timedelta(days=89))
        action_url = send.call_args.kwargs["delivery_context"]["action_url"]
        token = action_url.rstrip("/").rsplit("/", 1)[-1]

        client = Client()
        client.force_login(self.user)
        response = client.get(f"/console/notification/email/verify/{token}/")
        self.assertEqual(response.status_code, 302)
        row.refresh_from_db()
        self.assertEqual(row.status, CoreNotificationEmail.Status.VERIFIED)
