import uuid
from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.db.models import UniqueConstraint, Q
from model_utils.models import TimeStampedModel
from apps.console.account.models import CoreAccount


class CoreMember(TimeStampedModel):
    user = models.OneToOneField(User, related_name='member', on_delete=models.CASCADE)
    accounts = models.ManyToManyField(CoreAccount, related_name='members', through='CoreMemberAccount')
    timezone = models.CharField(max_length=64, default="UTC")
    password_reset_token = models.CharField(null=True, max_length=255, blank=True)

    class Meta:
        db_table = 'core_member'
        verbose_name = "Member"
        verbose_name_plural = "Members"

    def __str__(self):
        return f'{self.full_name} - {self.email}'

    @property
    def full_name(self):
        """Returns the person's full name."""
        return f'{self.user.first_name} {self.user.last_name}'

    @property
    def email(self):
        return self.user.email

    @property
    def email_verified(self):
        from ..notification.models import CoreNotificationEmail

        if CoreNotificationEmail.objects.filter(email=self.email, status=CoreNotificationEmail.Status.VERIFIED).exists():
            return True
        else:
            return False

    @property
    def email_notification_id(self):
        from ..notification.models import CoreNotificationEmail

        if CoreNotificationEmail.objects.filter(email=self.email).exists():
            return CoreNotificationEmail.objects.get(email=self.email).id
        else:
            return None

    @property
    def account(self):
        if self.accounts.filter().count() == 1:
            return self.accounts.first()

    @property
    def multiple_accounts(self):
        if self.accounts.filter().count() > 1:
            return True

    def set_current_account(self, account=None):
        if not self.multiple_accounts:
            membership = self.memberships.get()
            membership.current = True
            membership.save()

        if account:
            if self.memberships.filter(account=account).exists():
                membership = self.memberships.get(account=account)
                membership.current = True
                membership.save()

    def get_current_account(self):
        if self.memberships.filter(current=True).exists():
            return self.memberships.get(current=True).account
        elif self.memberships.filter().count() == 1:
            membership = self.memberships.first()
            membership.current = True
            membership.save()
            return membership.account

    def get_primary_account(self):
        if self.memberships.filter(primary=True).exists():
            return self.memberships.get(primary=True).account
        elif self.memberships.filter().count() == 1:
            membership = self.memberships.first()
            membership.current = True
            membership.primary = True
            membership.save()
            return membership.account

    def get_encryption_key(self):
        return bytes(self.get_current_account().encryption_key)

    def invites_received(self):
        from ..invite.models import CoreInvite
        return CoreInvite.objects.filter(email=self.user.email)

    @property
    def group_count(self):
        return self.user.groups.count()

    @property
    def is_primary_account(self):
        return self.memberships.filter(primary=True, account=self.get_current_account()).exists()

    @property
    def get_password_reset_link(self):
        password_reset_token = str(uuid.uuid4()).split("-")[0]

        if not self.password_reset_token:
            self.password_reset_token = password_reset_token
            self.save()

        return f"{settings.APP_URL}/reset/{self.password_reset_token}/"

    def send_verification_email(self):
        self.notification_email.get().send_verification_email()

    def send_welcome_email(self):
        from apps.console.notification.models import CoreNotificationLogEmail

        email_notification = CoreNotificationLogEmail()
        email_notification.member = self
        email_notification.email = self.email
        email_notification.template = "welcome"
        email_notification.context = {
            "action_url": f"{settings.APP_URL}",
            "help_url": f"{settings.APP_URL}",
            "sender_name": f"{settings.APP_NAME} - Notification Bot",
        }
        email_notification.save()

        # Now Send email
        email_notification.send()

    def send_password_reset(self, next_url=None):
        from apps.console.notification.models import CoreNotificationLogEmail

        password_reset_token = str(uuid.uuid4()).split("-")[0]

        self.password_reset_token = password_reset_token
        self.save()

        email_notification = CoreNotificationLogEmail()
        email_notification.member = self
        email_notification.email = self.user.email
        email_notification.template = "password_reset"
        email_notification.context = {
            "action_url": self.get_password_reset_link,
            "help_url": f"{settings.APP_URL}",
            "sender_name": f"{settings.APP_NAME} - Notification Bot",
        }
        email_notification.save()

        # Now Send email
        email_notification.send()


class CoreMemberAccount(TimeStampedModel):
    class Status(models.IntegerChoices):
        ACTIVE = 1, 'Active'
        PENDING = 2, 'Pending'
        SUSPENDED = 3, 'Suspended'
        INVITED = 4, 'Invited'

    member = models.ForeignKey(CoreMember, on_delete=models.CASCADE, related_name='memberships')
    account = models.ForeignKey(CoreAccount, on_delete=models.CASCADE, related_name='memberships')
    status = models.IntegerField(choices=Status.choices, default=Status.ACTIVE)
    notify_on_success = models.BooleanField(default=True, null=True)
    notify_on_fail = models.BooleanField(default=True, null=True)
    current = models.BooleanField(default=False, editable=False)
    primary = models.BooleanField(default=False, editable=False)

    class Meta:
        db_table = 'core_member_mtm_account'
        verbose_name = 'Member Account'
        verbose_name_plural = 'Member Accounts'
        constraints = [
            UniqueConstraint(fields=['member', 'account'], name='unique_membership'),
            UniqueConstraint(fields=['member'], condition=Q(current=True), name='unique_member_current_account'),
            UniqueConstraint(fields=['member'], condition=Q(primary=True), name='unique_member_primary_account')
        ]
