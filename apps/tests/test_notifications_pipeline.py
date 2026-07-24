"""Tests for the notification pipeline: recipient resolution, the generic email
task, Slack/Telegram fan-out, restore notifications + activity-log events, the
notification-email API, and the email templates themselves.

All provider sends (email HTTP APIs, Slack webhooks, Telegram, celery broker
publishes) are mocked -- no external service is ever contacted.
"""
import uuid
from unittest import mock

from django.contrib.auth import get_user_model
from django.template.loader import render_to_string
from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from apps._tasks.helper import tasks as helper_tasks
from apps._tasks.integration import restore as restore_tasks
from apps._tasks.integration.restore_common import RestoreError
from apps.api.v1.notification.views import CoreNotificationEmailView
from apps.console.account.models import CoreAccount
from apps.console.backup.models import CoreWebsiteRestore
from apps.console.log.models import CoreLog
from apps.console.member.models import CoreMember, CoreMemberAccount
from apps.console.notification.models import (
    CoreNotificationEmail,
    CoreNotificationLogEmail,
    CoreNotificationSlack,
    CoreNotificationTelegram,
)
from apps.console.setting.models import CoreSiteSettings
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from apps.tests.test_restore import RestoreBackendBase

User = get_user_model()


def make_membership(account, *, status=CoreMemberAccount.Status.ACTIVE,
                    notify_on_success=True, notify_on_fail=True):
    """Attach an extra member to `account` with the given notification flags."""
    email = f"extra-{uuid.uuid4().hex[:8]}@example.com"
    user = User.objects.create_user(username=email, email=email, password="x-Secret-123")
    member = CoreMember.objects.create(user=user, timezone="UTC")
    membership = CoreMemberAccount.objects.create(
        member=member, account=account, status=status,
        notify_on_success=notify_on_success, notify_on_fail=notify_on_fail,
    )
    return member, membership


class NotificationRecipientTests(BaseTestCase):
    """CoreAccount.get_notification_recipients(event)."""

    def test_flags_honored_for_both_events(self):
        member_ok, _ = make_membership(self.account)
        member_no_success, _ = make_membership(self.account, notify_on_success=False)
        member_no_fail, _ = make_membership(self.account, notify_on_fail=False)

        success_emails = {email for _m, email in self.account.get_notification_recipients("success")}
        fail_emails = {email for _m, email in self.account.get_notification_recipients("fail")}

        self.assertIn(self.user.email, success_emails)
        self.assertIn(member_ok.user.email, success_emails)
        self.assertNotIn(member_no_success.user.email, success_emails)
        self.assertIn(member_no_fail.user.email, success_emails)

        self.assertIn(self.user.email, fail_emails)
        self.assertIn(member_ok.user.email, fail_emails)
        self.assertIn(member_no_success.user.email, fail_emails)
        self.assertNotIn(member_no_fail.user.email, fail_emails)

    def test_null_flag_counts_as_true(self):
        member_null, _ = make_membership(
            self.account, notify_on_success=None, notify_on_fail=None
        )
        success_emails = {email for _m, email in self.account.get_notification_recipients("success")}
        fail_emails = {email for _m, email in self.account.get_notification_recipients("fail")}
        self.assertIn(member_null.user.email, success_emails)
        self.assertIn(member_null.user.email, fail_emails)

    def test_primary_membership_always_included(self):
        primary = self.account.memberships.get(primary=True)
        primary.notify_on_success = False
        primary.notify_on_fail = False
        primary.save()

        success_emails = {email for _m, email in self.account.get_notification_recipients("success")}
        fail_emails = {email for _m, email in self.account.get_notification_recipients("fail")}
        self.assertIn(self.user.email, success_emails)
        self.assertIn(self.user.email, fail_emails)

    def test_inactive_memberships_excluded(self):
        member_pending, _ = make_membership(
            self.account, status=CoreMemberAccount.Status.PENDING
        )
        fail_emails = {email for _m, email in self.account.get_notification_recipients("fail")}
        self.assertNotIn(member_pending.user.email, fail_emails)

    def test_returns_distinct_member_email_pairs(self):
        make_membership(self.account)
        recipients = self.account.get_notification_recipients("fail")
        self.assertEqual(len(recipients), len({(m.id, e) for m, e in recipients}))
        for member, email in recipients:
            self.assertEqual(member.user.email, email)

    def test_unknown_event_rejected(self):
        with self.assertRaises(ValueError):
            self.account.get_notification_recipients("bogus")


class NotifyBackupSuccessTests(BaseTestCase):
    """notify_backup_success emails every eligible member, not just the primary."""

    def test_emails_every_eligible_member(self):
        node = factories.make_website_node(self.account, self.member)
        member_ok, _ = make_membership(self.account)
        member_opted_out, _ = make_membership(self.account, notify_on_success=False)

        backup = node.website.backups.create(
            uuid=f"t{uuid.uuid4().hex}", status=UtilBackup.Status.COMPLETE,
            attempt_no=1, type=UtilBackup.Type.ON_DEMAND,
        )

        with mock.patch("apps._tasks.helper.tasks.send_postmark_email.delay") as delay:
            node.notify_backup_success(backup)

        emailed = {call.args[0] for call in delay.call_args_list}
        self.assertEqual(emailed, {self.user.email, member_ok.user.email})
        for call in delay.call_args_list:
            self.assertEqual(call.args[1], "backup_is_complete")

        # the DB activity log entry is still written exactly once
        self.assertTrue(CoreLog.objects.filter(account=self.account).exists())


class GenericEmailTaskTests(BaseTestCase):
    """The rewritten send_postmark_email task sends ANY template."""

    def test_sends_non_password_template(self):
        with mock.patch.object(CoreNotificationLogEmail, "send") as send_mock:
            helper_tasks.send_postmark_email(
                self.user.email, "backup_is_complete", {"message": "hi"}
            )
        send_mock.assert_called_once()
        log = CoreNotificationLogEmail.objects.get()
        self.assertEqual(log.member, self.member)
        self.assertEqual(log.email, self.user.email)
        self.assertEqual(log.template, "backup_is_complete")

    def test_unknown_email_is_skipped(self):
        with mock.patch.object(CoreNotificationLogEmail, "send") as send_mock:
            helper_tasks.send_postmark_email(
                "nobody@example.com", "backup_is_complete", {}
            )
        send_mock.assert_not_called()
        self.assertFalse(CoreNotificationLogEmail.objects.exists())


class SendLogToDbNotificationTests(BaseTestCase):
    """BREAK-1: send_log_to_db fans bot messages out via account.send_notification."""

    def test_bot_message_fans_out(self):
        with mock.patch.object(CoreAccount, "send_notification") as notify:
            helper_tasks.send_log_to_db({
                "account_id": self.account.id,
                "sender_name": "BackupSheep - Notification Bot",
                "message": "backup done",
                "error_details": "",
            })
        notify.assert_called_once_with("backup done")
        self.assertTrue(CoreLog.objects.filter(account=self.account).exists())


class AccountSendNotificationTests(BaseTestCase):
    """CoreAccount.send_notification fans out to Slack+Telegram and isolates failures."""

    def _slack(self, channel="general"):
        return CoreNotificationSlack.objects.create(
            account=self.account, app_id="A1", token_type="bot",
            access_token="xoxb-1", bot_user_id="U1", refresh_token="r1",
            channel=channel, channel_id=f"C-{channel}",
            configuration_url="https://slack.com/configure/1",
            url=f"https://hooks.slack.com/services/{channel}",
            data={"team": {"name": "team"}},
            added_by=self.member,
        )

    def _telegram(self):
        return CoreNotificationTelegram.objects.create(
            account=self.account, chat_id="42", channel_name="ops",
            added_by=self.member,
        )

    def test_fans_out_to_all_channels(self):
        self._slack("one")
        self._slack("two")
        self._telegram()
        with mock.patch.object(CoreNotificationSlack, "send") as slack_send, \
             mock.patch.object(CoreNotificationTelegram, "send") as telegram_send:
            self.account.send_notification("hello")
        self.assertEqual(slack_send.call_count, 2)
        telegram_send.assert_called_once_with("hello")

    def test_failing_channel_does_not_break_others(self):
        self._slack("bad")
        self._slack("good")
        self._telegram()
        with mock.patch.object(
            CoreNotificationSlack, "send", side_effect=[Exception("boom"), None]
        ) as slack_send, \
             mock.patch.object(CoreNotificationTelegram, "send") as telegram_send:
            # must not raise
            self.account.send_notification("hello")
        self.assertEqual(slack_send.call_count, 2)
        telegram_send.assert_called_once_with("hello")


class RestoreNotificationTests(RestoreBackendBase):
    """Restore tasks emit email + CoreLog RESTORE activity-log events."""

    def _restore(self):
        node, backup = self._website_backup(all_paths=True)
        stored = self._website_point(backup, self._make_zip({"index.html": "x"}))
        restore = CoreWebsiteRestore.objects.create(
            backup=backup, storage_point=stored, name="r", params={"delete": False}
        )
        return node, backup, restore

    def test_completed_restore_emails_and_logs(self):
        node, backup, restore = self._restore()
        with mock.patch("apps._tasks.integration.restore_website.restore_website"), \
             mock.patch("apps._tasks.helper.tasks.send_postmark_email.delay") as delay, \
             mock.patch("apps.console.log.models.CoreLog") as core_log:
            restore_tasks.restore_website_backup.apply(args=[node.id, backup.id, restore.id])

        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreWebsiteRestore.Status.COMPLETE)

        templates = [call.args[1] for call in delay.call_args_list]
        self.assertEqual(templates, ["restore_started", "restore_completed"])
        for call in delay.call_args_list:
            self.assertEqual(call.args[0], self.user.email)
        completed_ctx = delay.call_args_list[1].args[2]
        self.assertEqual(completed_ctx["node_id"], node.id)
        self.assertEqual(completed_ctx["node_name"], node.name)
        self.assertEqual(completed_ctx["restore_name"], "r")
        self.assertEqual(completed_ctx["backup_name"], backup.uuid_str)

        # one RESTORE activity-log entry per event (started + completed)
        self.assertEqual(core_log.record.call_count, 2)
        record_account = core_log.record.call_args_list[1].args[0]
        record_data = core_log.record.call_args_list[1].args[2]
        self.assertEqual(record_account, self.account)
        self.assertEqual(record_data["node_id"], node.id)
        self.assertIn("completed", record_data["message"])

    def test_failed_restore_emails_and_logs(self):
        node, backup, restore = self._restore()
        with mock.patch(
            "apps._tasks.integration.restore_website.restore_website",
            side_effect=RestoreError("boom"),
        ), \
             mock.patch("apps._tasks.helper.tasks.send_postmark_email.delay") as delay, \
             mock.patch("apps.console.log.models.CoreLog") as core_log:
            restore_tasks.restore_website_backup.apply(args=[node.id, backup.id, restore.id])

        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreWebsiteRestore.Status.FAILED)

        templates = [call.args[1] for call in delay.call_args_list]
        self.assertEqual(templates, ["restore_started", "restore_failed"])
        failed_ctx = delay.call_args_list[1].args[2]
        self.assertIn("boom", failed_ctx["error_details"])
        self.assertEqual(core_log.record.call_count, 2)


class NotificationEmailApiTests(BaseTestCase):
    """The fixed notification-email API (member FK, no Telegram validate)."""

    def test_register_email(self):
        view = CoreNotificationEmailView.as_view({"post": "create"})
        request = APIRequestFactory().post(
            "/api/v1/notifications-email/", {"email": "alerts@example.com"}, format="json"
        )
        force_authenticate(request, user=self.user)
        resp = view(request)
        self.assertEqual(resp.status_code, 201)
        row = CoreNotificationEmail.objects.get(email="alerts@example.com")
        self.assertEqual(row.member, self.member)
        self.assertEqual(row.status, CoreNotificationEmail.Status.UN_VERIFIED)

    def test_queryset_scoped_to_current_account(self):
        mine = CoreNotificationEmail.objects.create(member=self.member, email="mine@example.com")
        other_account, other_member, _ = factories.make_account()
        theirs = CoreNotificationEmail.objects.create(member=other_member, email="theirs@example.com")

        request = mock.MagicMock()
        request.user = self.user
        view = CoreNotificationEmailView()
        view.request = request
        view.kwargs = {}

        ids = set(view.get_queryset().values_list("id", flat=True))
        self.assertIn(mine.id, ids)
        self.assertNotIn(theirs.id, ids)

    def test_send_verification_email_action(self):
        row = CoreNotificationEmail.objects.create(member=self.member, email="mine@example.com")
        view = CoreNotificationEmailView.as_view({"post": "send_verification_email"})
        request = APIRequestFactory().post(
            f"/api/v1/notifications-email/{row.id}/send_verification_email/"
        )
        force_authenticate(request, user=self.user)
        with mock.patch.object(CoreNotificationLogEmail, "send"):
            resp = view(request, pk=row.id)
        self.assertEqual(resp.status_code, 200)
        row.refresh_from_db()
        self.assertTrue(row.verify_code)
        self.assertEqual(row.status, CoreNotificationEmail.Status.UN_VERIFIED)
        log = CoreNotificationLogEmail.objects.get()
        self.assertEqual(log.template, "verify_email")


class SesCredentialFallbackTests(BaseTestCase):
    """SES provider must fall back to the SES_* settings names (not AWS_SES_*)."""

    def test_ses_client_uses_settings_fallback_names(self):
        log = CoreNotificationLogEmail.objects.create(
            member=self.member, email=self.user.email,
            template="backup_is_complete",
            context={"message": "hi"},
        )
        from django.conf import settings as django_settings

        with mock.patch.object(
            CoreSiteSettings, "get_email_provider", return_value="ses"
        ), \
             mock.patch("apps.console.notification.models.boto3.client") as boto_client, \
             mock.patch("apps.console.notification.models.SesMailSender") as sender_cls:
            sender_cls.return_value.send_email.return_value = "ses-message-id-1"
            log.send()

        boto_client.assert_called_once()
        kwargs = boto_client.call_args.kwargs
        self.assertEqual(kwargs["aws_access_key_id"], django_settings.SES_ACCESS_KEY_ID)
        self.assertEqual(kwargs["aws_secret_access_key"], django_settings.SES_SECRET_ACCESS_KEY)
        self.assertEqual(kwargs["region_name"], django_settings.SES_REGION_NAME)
        sender_cls.return_value.send_email.assert_called_once()


class DeleteOldDbLogsTaskTests(TestCase):
    def test_calls_core_log_prune(self):
        with mock.patch("apps.console.log.models.CoreLog") as core_log:
            helper_tasks.delete_old_db_logs()
        core_log.prune.assert_called_once()


class EmailTemplateRenderTests(TestCase):
    """All notification templates render cleanly with a representative context."""

    def _ctx(self, **overrides):
        ctx = {
            # branding vars injected by CoreNotificationLogEmail.send()
            "site_app_name": "BackupSheep",
            "site_app_url": "https://bs.example.com",
            "node_id": 7,
            "node_name": "web-1",
            "node_type": "website",
            "node_status": "Active",
            "connection_name": "conn-1",
            "connection_status": "Active",
            "backup_name": "bs-backup-1",
            "backup_type": "On-Demand",
            "backup_time": "Jan 01 2026 - 10:00AM UTC",
            "backup_size": "1 MB",
            "backup_duration": "1 minute",
            "restore_id": 3,
            "restore_name": "Restore of bs-backup-1",
            "storage_type": "Amazon S3",
            "storage_name": "s3-store",
            "endpoint_name": "local",
            "endpoint_location": "local",
            "endpoint_ip": "1.2.3.4",
            "endpoint_ipv6": "",
            "error_details": "boom",
            "message": "msg",
            "action_url": "https://bs.example.com/console/nodes/7/",
            "help_url": "https://help.example.com",
            "sender_name": "BackupSheep - Notification Bot",
            "email": "u@example.com",
        }
        ctx.update(overrides)
        return ctx

    def _render(self, template, suffix, ctx=None):
        return render_to_string(
            f"console/emails/{template}.{suffix}", ctx or self._ctx()
        )

    def test_new_templates_render(self):
        for template in (
            "restore_started", "restore_completed", "restore_failed",
            "storage_validation_failed",
        ):
            for suffix in ("html", "txt.html", "subject.html"):
                rendered = self._render(template, suffix)
                self.assertTrue(rendered.strip(), f"{template}.{suffix} rendered empty")

    def test_restore_templates_build_action_url_from_site_app_url(self):
        for template in ("restore_started", "restore_completed", "restore_failed"):
            html = self._render(template, "html")
            self.assertIn("https://bs.example.com/console/nodes/7/", html)
            txt = self._render(template, "txt.html")
            self.assertIn("https://bs.example.com/console/nodes/7/", txt)

    def test_restore_templates_include_names(self):
        html = self._render("restore_completed", "html")
        self.assertIn("web-1", html)
        self.assertIn("Restore of bs-backup-1", html)
        self.assertIn("bs-backup-1", html)
        failed = self._render("restore_failed", "html")
        self.assertIn("boom", failed)

    def test_error_during_backup_subject_and_txt_not_swapped(self):
        subject = self._render("error_during_backup", "subject.html").strip()
        self.assertEqual(subject, "Backup Status - Error During Backup")
        txt = self._render("error_during_backup", "txt.html")
        self.assertIn("Whoops!", txt)
        self.assertIn("boom", txt)
        self.assertNotIn("Backup Status - Error During Backup", txt)

    def test_password_reset_txt_is_a_password_reset(self):
        txt = self._render("password_reset", "txt.html")
        self.assertIn("reset the password", txt)
        self.assertIn("https://bs.example.com/console/nodes/7/", txt)  # action_url var
        self.assertNotIn("invited", txt.lower())

    def test_existing_templates_render_without_hardcoded_app_urls(self):
        for template in (
            "backup_is_complete", "error_during_backup",
            "unable_to_start_backup", "unable_to_upload_backup",
        ):
            for suffix in ("html", "txt.html"):
                rendered = self._render(template, suffix)
                self.assertTrue(rendered.strip(), f"{template}.{suffix} rendered empty")
                self.assertNotIn("https://backupsheep.com", rendered)
                self.assertNotIn("support.backupsheep.com", rendered)
                self.assertNotIn("docs.backupsheep.com", rendered)
