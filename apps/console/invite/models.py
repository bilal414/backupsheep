from datetime import timedelta

from django.db import models
from django.utils import timezone
from model_utils.models import TimeStampedModel
import uuid
from apps.console.account.models import CoreAccount, CoreAccountGroup
from apps.console.member.models import CoreMember


class CoreInvite(TimeStampedModel):
    class Status(models.IntegerChoices):
        ACCEPTED = 1, "Accepted"
        EXPIRED = 2, "Expired"
        CANCELLED = 3, "Cancelled"
        PENDING = 4, "Pending"

    # Pending invite links stop working this many days after they are issued.
    INVITE_TTL_DAYS = 7

    added_by = models.ForeignKey(
        CoreMember,
        related_name="invites_sent",
        on_delete=models.CASCADE,
    )

    account = models.ForeignKey(
        CoreAccount, related_name="invites", editable=False, on_delete=models.CASCADE
    )
    groups = models.ManyToManyField(
        CoreAccountGroup, related_name="invites"
    )
    status = models.IntegerField(choices=Status.choices, default=Status.PENDING, editable=False)
    notify_on_success = models.BooleanField(default=True, null=True)
    notify_on_fail = models.BooleanField(default=True, null=True)
    timezone = models.CharField(max_length=64, default="UTC")
    first_name = models.CharField(max_length=64)
    last_name = models.CharField(max_length=64)
    email = models.EmailField()
    uuid = models.UUIDField(default=uuid.uuid4, editable=False)
    expires_at = models.DateTimeField(null=True)

    class Meta:
        db_table = "core_invite"

    def save(self, *args, **kwargs):
        # New invites get a fresh acceptance window unless an expiry was set explicitly.
        if self._state.adding and self.expires_at is None:
            self.expires_at = timezone.now() + timedelta(days=self.INVITE_TTL_DAYS)
        super().save(*args, **kwargs)

    @property
    def full_name(self):
        """Returns the person's full name."""
        return f"{self.first_name} {self.last_name}"

    @property
    def is_expired(self):
        """A pending invite whose acceptance window has passed."""
        return (
            self.status == self.Status.PENDING
            and self.expires_at is not None
            and timezone.now() > self.expires_at
        )

    def expire_if_needed(self):
        """Lazily flip a past-expiry PENDING invite to EXPIRED (invites carry no
        sweeper task, so expiry is enforced wherever an invite is loaded).
        Returns True when the invite is (now) expired."""
        if self.is_expired:
            self.status = self.Status.EXPIRED
            self.save(update_fields=["status", "modified"])
        return self.status == self.Status.EXPIRED

    def reset_expiry(self):
        """Restart the acceptance window (used by the resend action)."""
        self.expires_at = timezone.now() + timedelta(days=self.INVITE_TTL_DAYS)
        self.save(update_fields=["expires_at", "modified"])

    @property
    def accept_url(self):
        """Public accept/signup link emailed to the invitee."""
        from apps.console.setting.models import CoreSiteSettings

        site = CoreSiteSettings.load()
        return f"{site.get_app_protocol()}{site.get_app_domain()}/invite/{self.uuid}/"

    def send_invite_email(self):
        """Queue the team_invite email through the notification log (the working
        pattern used by CoreMember.send_password_reset). Branding vars
        (site_app_name/site_app_url) are injected by CoreNotificationLogEmail.send().
        With no email provider configured this just renders and stores the log row."""
        from apps.console.notification.models import CoreNotificationLogEmail
        from apps.console.setting.models import CoreSiteSettings

        site = CoreSiteSettings.load()
        app_url = f"{site.get_app_protocol()}{site.get_app_domain()}"

        email_notification = CoreNotificationLogEmail()
        # The invitee may not have an account yet, so the log row is filed under
        # the inviter's member record while the email itself goes to the invitee.
        email_notification.member = self.added_by
        email_notification.email = self.email
        email_notification.template = "team_invite"
        email_notification.context = {
            "account_name": self.account.get_name(),
            "member_name": self.added_by.full_name,
            "member_email": self.added_by.email,
            "action_url": self.accept_url,
            "help_url": app_url,
            "sender_name": f"{site.get_app_name()} - Notification Bot",
        }
        email_notification.save()

        # Now Send email
        email_notification.send()

    def accept(self, member):
        """Grant the accepting member access: create the account membership (with
        the invite's notify flags) if missing, enroll them in the invite's groups
        and mark the invite ACCEPTED. Shared by the API accept action and the
        public /invite/<uuid>/ console page."""
        from apps.console.member.models import CoreMemberAccount

        if not member.memberships.filter(account=self.account).exists():
            CoreMemberAccount.objects.create(
                notify_on_success=self.notify_on_success,
                notify_on_fail=self.notify_on_fail,
                member=member,
                account=self.account,
            )
        for enrollment in self.groups.filter():
            member.user.groups.add(enrollment.group)

        self.status = self.Status.ACCEPTED
        self.save(update_fields=["status", "modified"])
