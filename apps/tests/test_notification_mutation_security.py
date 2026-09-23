from unittest import mock

from django.contrib.auth import get_user_model
from django.test import Client

from apps.console.member.models import CoreMember, CoreMemberAccount
from apps.console.notification.models import (
    CoreNotificationEmail,
    CoreNotificationTelegram,
)
from apps.tests import factories
from apps.tests.base import BaseTestCase


User = get_user_model()


class NotificationMutationSecurityTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        member_user = User.objects.create_user(
            username="tenant-member@example.com",
            email="tenant-member@example.com",
            password="x-Secret-123",
        )
        self.tenant_member = CoreMember.objects.create(
            user=member_user,
            timezone="UTC",
        )
        CoreMemberAccount.objects.create(
            member=self.tenant_member,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=True,
            primary=False,
        )
        self.member_user = member_user
        self.member_client = Client()
        self.member_client.force_login(member_user)
        self.owner_client = Client()
        self.owner_client.force_login(self.user)

        self.telegram = CoreNotificationTelegram.objects.create(
            account=self.account,
            added_by=self.member,
            channel_name="Tenant alerts",
            chat_id="private-chat-id",
        )
        self.owner_email = CoreNotificationEmail.objects.create(
            member=self.member,
            email="owner-alerts@example.com",
            verify_code=CoreNotificationEmail.verification_token_digest("internal"),
        )
        self.member_email = CoreNotificationEmail.objects.create(
            member=self.tenant_member,
            email="member-alerts@example.com",
        )
        other_account, other_member, _ = factories.make_account()
        self.other_telegram = CoreNotificationTelegram.objects.create(
            account=other_account,
            added_by=other_member,
            channel_name="Other tenant",
            chat_id="other-private-chat-id",
        )
        self.other_email = CoreNotificationEmail.objects.create(
            member=other_member,
            email="other-tenant@example.com",
        )

    def test_telegram_reads_are_tenant_safe_but_chat_id_is_not_serialized(self):
        response = self.member_client.get(
            f"/api/v1/notifications-telegram/{self.telegram.pk}/"
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["channel_name"], "Tenant alerts")
        self.assertNotIn("chat_id", response.json())
        self.assertNotIn("private-chat-id", response.content.decode())

    def test_telegram_member_cannot_create_mutate_delete_or_validate(self):
        create = self.member_client.post(
            "/api/v1/notifications-telegram/",
            {"channel_name": "No", "chat_id": "no"},
            content_type="application/json",
        )
        patch = self.member_client.patch(
            f"/api/v1/notifications-telegram/{self.telegram.pk}/",
            {"channel_name": "Changed"},
            content_type="application/json",
        )
        delete = self.member_client.delete(
            f"/api/v1/notifications-telegram/{self.telegram.pk}/"
        )
        with mock.patch.object(CoreNotificationTelegram, "validate") as validate:
            validation = self.member_client.post(
                f"/api/v1/notifications-telegram/{self.telegram.pk}/validate/"
            )
        self.assertEqual(
            [create.status_code, patch.status_code, delete.status_code, validation.status_code],
            [403, 403, 403, 403],
        )
        validate.assert_not_called()
        self.telegram.refresh_from_db()
        self.assertEqual(self.telegram.channel_name, "Tenant alerts")

    def test_telegram_owner_can_mutate_and_validate(self):
        with mock.patch.object(CoreNotificationTelegram, "validate", return_value=True):
            validation = self.owner_client.post(
                f"/api/v1/notifications-telegram/{self.telegram.pk}/validate/"
            )
        self.assertEqual(validation.status_code, 200, validation.content)
        self.assertEqual(
            self.owner_client.get(
                f"/api/v1/notifications-telegram/{self.telegram.pk}/validate/"
            ).status_code,
            405,
        )

        deleted = self.owner_client.delete(
            f"/api/v1/notifications-telegram/{self.telegram.pk}/"
        )
        self.assertEqual(deleted.status_code, 204, deleted.content)
        self.assertFalse(
            CoreNotificationTelegram.objects.filter(pk=self.telegram.pk).exists()
        )

    def test_telegram_cross_tenant_objects_are_not_addressable(self):
        detail = self.owner_client.get(
            f"/api/v1/notifications-telegram/{self.other_telegram.pk}/"
        )
        mutation = self.owner_client.delete(
            f"/api/v1/notifications-telegram/{self.other_telegram.pk}/"
        )
        with mock.patch.object(CoreNotificationTelegram, "validate") as validate:
            validation = self.owner_client.post(
                f"/api/v1/notifications-telegram/{self.other_telegram.pk}/validate/"
            )
        self.assertEqual(
            [detail.status_code, mutation.status_code, validation.status_code],
            [404, 404, 404],
        )
        validate.assert_not_called()

    def test_email_member_can_read_tenant_rows_but_only_mutate_their_own(self):
        detail = self.member_client.get(
            f"/api/v1/notifications-email/{self.owner_email.pk}/"
        )
        self.assertEqual(detail.status_code, 200, detail.content)
        self.assertNotIn("verify_code", detail.json())
        self.assertNotIn("internal", detail.content.decode())

        denied_patch = self.member_client.patch(
            f"/api/v1/notifications-email/{self.owner_email.pk}/",
            {"email": "stolen@example.com"},
            content_type="application/json",
        )
        with mock.patch.object(CoreNotificationEmail, "send_verification_email") as send:
            denied_send = self.member_client.post(
                f"/api/v1/notifications-email/{self.owner_email.pk}/send_verification_email/"
            )
        self.assertEqual([denied_patch.status_code, denied_send.status_code], [403, 403])
        send.assert_not_called()

        own_patch = self.member_client.patch(
            f"/api/v1/notifications-email/{self.member_email.pk}/",
            {
                "email": "member-new@example.com",
                "status": CoreNotificationEmail.Status.VERIFIED,
                "verify_code": "forged",
            },
            content_type="application/json",
        )
        self.assertEqual(own_patch.status_code, 200, own_patch.content)
        self.member_email.refresh_from_db()
        self.assertEqual(self.member_email.email, "member-new@example.com")
        self.assertEqual(
            self.member_email.status,
            CoreNotificationEmail.Status.UN_VERIFIED,
        )
        self.assertIsNone(self.member_email.verify_code)
        self.assertEqual(self.member_email.member, self.tenant_member)

    def test_email_owner_can_administer_member_row_and_send_verification(self):
        patch = self.owner_client.patch(
            f"/api/v1/notifications-email/{self.member_email.pk}/",
            {"email": "owner-managed@example.com"},
            content_type="application/json",
        )
        self.assertEqual(patch.status_code, 200, patch.content)
        self.member_email.refresh_from_db()
        self.assertEqual(self.member_email.email, "owner-managed@example.com")
        self.assertEqual(self.member_email.member, self.tenant_member)

        with mock.patch.object(CoreNotificationEmail, "send_verification_email") as send:
            response = self.owner_client.post(
                f"/api/v1/notifications-email/{self.member_email.pk}/send_verification_email/"
            )
        self.assertEqual(response.status_code, 200, response.content)
        send.assert_called_once_with()

    def test_email_cross_tenant_objects_are_not_addressable(self):
        detail = self.owner_client.get(
            f"/api/v1/notifications-email/{self.other_email.pk}/"
        )
        mutation = self.owner_client.delete(
            f"/api/v1/notifications-email/{self.other_email.pk}/"
        )
        with mock.patch.object(CoreNotificationEmail, "send_verification_email") as send:
            verification = self.owner_client.post(
                f"/api/v1/notifications-email/{self.other_email.pk}/send_verification_email/"
            )
        self.assertEqual(
            [detail.status_code, mutation.status_code, verification.status_code],
            [404, 404, 404],
        )
        send.assert_not_called()
