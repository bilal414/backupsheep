import importlib
from types import SimpleNamespace
from unittest import mock

from cryptography.fernet import Fernet
from django.http import HttpResponseRedirect
from django.db.migrations.exceptions import IrreversibleError
from django.test import SimpleTestCase, override_settings
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.api.v1.callback.views import APICallbackSlack
from apps.api.v1.utils.oauth_security import issue_oauth_state
from apps.console.notification.models import (
    CoreNotificationLogEmail,
    CoreNotificationSlack,
    SLACK_SECRET_PREFIX,
)
from apps.tests.base import BaseTestCase


def make_slack(account, member, **overrides):
    values = {
        "account": account,
        "added_by": member,
        "app_id": "A1",
        "token_type": "bot",
        "access_token": "xoxb-access-secret",
        "bot_user_id": "U1",
        "refresh_token": "xoxe-refresh-secret",
        "channel": "security",
        "channel_id": "C1",
        "configuration_url": "https://workspace.slack.com/services/C1",
        "url": "https://hooks.slack.com/services/T1/B1/secret",
        "data": {
            "team": {"id": "T1", "name": "Security"},
            "access_token": "raw-response-secret",
            "incoming_webhook": {
                "url": "https://hooks.slack.com/services/raw-secret"
            },
        },
    }
    values.update(overrides)
    return CoreNotificationSlack.objects.create(**values)


class SlackSecretModelTests(BaseTestCase):
    def test_direct_orm_writes_are_encrypted_versioned_and_not_double_encrypted(self):
        row = make_slack(self.account, self.member)
        row.refresh_from_db()

        original = {}
        for field_name, plaintext in {
            "access_token": "xoxb-access-secret",
            "refresh_token": "xoxe-refresh-secret",
            "configuration_url": "https://workspace.slack.com/services/C1",
            "url": "https://hooks.slack.com/services/T1/B1/secret",
        }.items():
            stored = getattr(row, field_name)
            self.assertTrue(stored.startswith(SLACK_SECRET_PREFIX))
            self.assertNotIn(plaintext, stored)
            self.assertEqual(row._decrypt_secret(field_name), plaintext)
            original[field_name] = stored

        self.assertEqual(row.data, {"team": {"id": "T1", "name": "Security"}})
        row.channel = "ops"
        row.save()
        row.refresh_from_db()
        for field_name, stored in original.items():
            self.assertEqual(getattr(row, field_name), stored)

    @mock.patch("apps.console.notification.models.requests.post")
    def test_send_uses_exact_decrypted_webhook_without_redirect_or_broker_payload(
        self, post
    ):
        post.return_value = SimpleNamespace(status_code=200, text="ok")
        row = make_slack(self.account, self.member)

        self.assertTrue(row.send("backup completed"))
        post.assert_called_once()
        self.assertEqual(
            post.call_args.args[0],
            "https://hooks.slack.com/services/T1/B1/secret",
        )
        self.assertEqual(post.call_args.kwargs["json"], {"text": "backup completed"})
        self.assertFalse(post.call_args.kwargs["allow_redirects"])
        self.assertTrue(post.call_args.kwargs["verify"])
        self.assertEqual(len(post.call_args.kwargs["timeout"]), 2)

    @mock.patch("apps.console.notification.models.requests.post")
    def test_malformed_ciphertext_and_host_confusion_fail_before_network(self, post):
        row = make_slack(self.account, self.member)
        CoreNotificationSlack.objects.filter(pk=row.pk).update(
            url=f"{SLACK_SECRET_PREFIX}not-a-fernet-token"
        )
        row.refresh_from_db()
        self.assertFalse(row.send("must not send"))
        post.assert_not_called()

        row = make_slack(
            self.account,
            self.member,
            channel="other",
            channel_id="C2",
            url="https://hooks.slack.com.attacker.invalid/services/secret",
        )
        self.assertFalse(row.validate())
        post.assert_not_called()

    @mock.patch("apps.console.notification.models.capture_exception")
    @mock.patch("apps.console.notification.models.requests.post")
    def test_webhook_failure_never_reports_decrypted_bearer_to_sentry(
        self, post, capture_exception
    ):
        post.side_effect = RuntimeError("provider unavailable")
        row = make_slack(
            self.account,
            self.member,
            channel="sentry",
            channel_id="C-sentry",
            url="https://hooks.slack.com/services/sentry-canary-secret",
        )

        self.assertFalse(row.send("safe message"))
        capture_exception.assert_not_called()

    @override_settings(
        SLACK_TOKEN_URL="https://slack.com/api/oauth.v2.access",
        SLACK_CLIENT_ID="client-id",
        SLACK_CLIENT_SECRET="client-secret",
    )
    @mock.patch("apps.console.notification.models.requests.post")
    def test_refresh_uses_plaintext_only_for_bounded_exchange_then_reencrypts(self, post):
        post.return_value = SimpleNamespace(
            status_code=200,
            json=lambda: {
                "ok": True,
                "access_token": "rotated-access-secret",
                "refresh_token": "rotated-refresh-secret",
                "expires_in": 3600,
                "team": {"id": "T2", "name": "Rotated Team"},
                "incoming_webhook": {"url": "raw-webhook-secret"},
            },
        )
        row = make_slack(self.account, self.member)

        self.assertTrue(row.refresh_auth_token())
        self.assertEqual(post.call_args.args[0], "https://slack.com/api/oauth.v2.access")
        self.assertEqual(
            post.call_args.kwargs["data"]["refresh_token"],
            "xoxe-refresh-secret",
        )
        self.assertFalse(post.call_args.kwargs["allow_redirects"])
        row.refresh_from_db()
        self.assertEqual(row._decrypt_secret("access_token"), "rotated-access-secret")
        self.assertEqual(row._decrypt_secret("refresh_token"), "rotated-refresh-secret")
        self.assertNotIn("rotated-access-secret", row.access_token)
        self.assertEqual(row.data, {"team": {"id": "T2", "name": "Rotated Team"}})


@override_settings(
    APP_URL="https://demo.backupsheep.com",
    SLACK_TOKEN_URL="https://slack.com/api/oauth.v2.access",
    SLACK_CLIENT_ID="slack-client",
    SLACK_CLIENT_SECRET="slack-client-secret",
)
class SlackCallbackPersistenceTests(BaseTestCase):
    @mock.patch("apps.api.v1.callback.views.redirect")
    @mock.patch("apps.api.v1.callback.views.messages.add_message")
    @mock.patch(
        "apps.api.v1.callback.views.current_account_is_primary", return_value=True
    )
    @mock.patch("apps.api.v1.callback.views.requests.post")
    def test_callback_persists_only_encrypted_secrets_and_safe_metadata(
        self, post, is_primary, add_message, redirect
    ):
        redirect.return_value = HttpResponseRedirect("/settings")
        result = mock.Mock(status_code=200)
        result.json.return_value = {
            "ok": True,
            "app_id": "A1",
            "token_type": "bot",
            "access_token": "callback-access-secret",
            "refresh_token": "callback-refresh-secret",
            "bot_user_id": "U1",
            "expires_in": 3600,
            "team": {"id": "T1", "name": "Callback Team"},
            "incoming_webhook": {
                "channel": "security",
                "channel_id": "C1",
                "configuration_url": "https://workspace.slack.com/services/C1",
                "url": "https://hooks.slack.com/services/T1/B1/callback-secret",
            },
        }
        post.return_value = result

        factory = APIRequestFactory()
        request = factory.get("/api/v1/callback/slack/", {"code": "code"})
        request.session = {}
        state = issue_oauth_state(
            request,
            provider="slack",
            member=self.member,
            account=self.account,
        )
        request.GET = request.GET.copy()
        request.GET["state"] = state["state"]
        force_authenticate(request, user=self.user)

        response = APICallbackSlack.as_view()(request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(post.call_count, 1)
        row = CoreNotificationSlack.objects.get()
        serialized_row = " ".join(
            filter(
                None,
                [row.access_token, row.refresh_token, row.configuration_url, row.url],
            )
        )
        for secret in (
            "callback-access-secret",
            "callback-refresh-secret",
            "callback-secret",
        ):
            self.assertNotIn(secret, serialized_row)
            self.assertNotIn(secret, str(row.data))
        self.assertEqual(row.data, {"team": {"id": "T1", "name": "Callback Team"}})


class SensitiveEmailDeliveryTests(BaseTestCase):
    @mock.patch("apps.console.notification.models.requests.post")
    @mock.patch("apps.console.setting.models.CoreSiteSettings.load")
    def test_delivery_context_sends_bearer_link_without_persisting_it(
        self, load_site, post
    ):
        site = mock.Mock()
        site.get_app_name.return_value = "BackupSheep"
        site.get_app_protocol.return_value = "https://"
        site.get_app_domain.return_value = "demo.backupsheep.com"
        site.get_email_provider.return_value = "mailgun"
        site.email_cred.side_effect = lambda name, fallback=None: {
            "api_url": "https://api.mailgun.example/v3",
            "domain": "mail.example",
            "api_key": "mailgun-secret",
            "email": "no-reply@example.com",
        }.get(name)
        load_site.return_value = site
        post.return_value.json.return_value = {"message_id": "message-1"}
        bearer_link = "https://demo.backupsheep.com/reset/bearer-secret-marker/"
        row = CoreNotificationLogEmail.objects.create(
            member=self.member,
            email=self.user.email,
            template="password_reset",
            context={
                "action_url": "[redacted password reset link]",
                "help_url": "https://demo.backupsheep.com",
                "sender_name": "BackupSheep - Notification Bot",
            },
        )

        row.send(
            delivery_context={"action_url": bearer_link},
            persist_rendered=False,
        )
        delivered = post.call_args.kwargs["data"]
        self.assertIn(bearer_link, delivered["html"])
        self.assertIn(bearer_link, delivered["text"])
        row.refresh_from_db()
        self.assertNotIn("bearer-secret-marker", str(row.context))
        self.assertIsNone(row.html_body)
        self.assertIsNone(row.text_body)
        self.assertNotIn("bearer-secret-marker", row.subject)
        self.assertEqual(row.message_id, "message-1")


class SlackMigrationHelperTests(SimpleTestCase):
    def test_legacy_encryption_is_idempotent_and_rejects_malformed_ciphertext(self):
        migration = importlib.import_module(
            "apps._migrations.0036_encrypt_slack_notification_secrets"
        )
        key = Fernet.generate_key()
        encrypted = migration._encrypt_legacy_value(
            "legacy-secret", key, row_id=1, field_name="access_token"
        )
        self.assertTrue(encrypted.startswith(SLACK_SECRET_PREFIX))
        self.assertNotIn("legacy-secret", encrypted)
        self.assertEqual(
            migration._encrypt_legacy_value(
                encrypted, key, row_id=1, field_name="access_token"
            ),
            encrypted,
        )
        with self.assertRaises(RuntimeError):
            migration._encrypt_legacy_value(
                f"{SLACK_SECRET_PREFIX}broken",
                key,
                row_id=1,
                field_name="access_token",
            )
        with self.assertRaises(IrreversibleError):
            migration.refuse_plaintext_reverse(None, None)
