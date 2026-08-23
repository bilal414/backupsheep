import uuid
from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.db import transaction
from django.db.models import UniqueConstraint, Q
from model_utils.models import TimeStampedModel
from apps.console.account.models import CoreAccount


class CoreMember(TimeStampedModel):
    user = models.OneToOneField(User, related_name='member', on_delete=models.CASCADE)
    accounts = models.ManyToManyField(CoreAccount, related_name='members', through='CoreMemberAccount')
    timezone = models.CharField(max_length=64, default="UTC")
    password_reset_token = models.CharField(null=True, max_length=255, blank=True)
    password_reset_token_created = models.DateTimeField(null=True, blank=True, editable=False)
    auth_multi_factor_secret = models.BinaryField(null=True, editable=False)
    auth_multi_factor_display_name = models.CharField(max_length=128, blank=True, default="")
    auth_multi_factor_pending_created = models.DateTimeField(null=True, editable=False)
    auth_multi_factor_enabled_at = models.DateTimeField(null=True, editable=False)
    auth_multi_factor_last_counter = models.BigIntegerField(null=True, editable=False)

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

    @property
    def mfa_enabled(self):
        return bool(self.auth_multi_factor_secret and self.auth_multi_factor_enabled_at)

    @property
    def auth_multi_factor_id(self):
        """Compatibility value for the existing console template/API."""
        return "totp" if self.mfa_enabled else None

    def set_pending_totp_secret(self, secret, display_name):
        from django.utils import timezone
        from apps.console.setting.models import _site_fernet

        # MFA belongs to the identity, not one of its possibly many accounts.
        # Use the site key so switching the current account cannot lock the user out.
        self.auth_multi_factor_secret = _site_fernet().encrypt(
            str(secret).encode("utf-8")
        )
        self.auth_multi_factor_display_name = str(display_name or "")[:128]
        self.auth_multi_factor_pending_created = timezone.now()
        self.auth_multi_factor_enabled_at = None
        self.auth_multi_factor_last_counter = None
        self.save(
            update_fields=[
                "auth_multi_factor_secret",
                "auth_multi_factor_display_name",
                "auth_multi_factor_pending_created",
                "auth_multi_factor_enabled_at",
                "auth_multi_factor_last_counter",
                "modified",
            ]
        )

    def get_totp_secret(self):
        if not self.auth_multi_factor_secret:
            return None
        from cryptography.fernet import InvalidToken
        from apps.console.setting.models import _site_fernet

        try:
            return _site_fernet().decrypt(
                bytes(self.auth_multi_factor_secret)
            ).decode("utf-8")
        except (InvalidToken, TypeError, ValueError):
            return None

    def verify_pending_totp(self, token, *, at_time=None, ttl_seconds=600):
        from datetime import timedelta
        from django.utils import timezone
        from .totp import matching_totp_counter

        with transaction.atomic():
            locked = CoreMember.objects.select_for_update().get(pk=self.pk)
            if (
                not locked.auth_multi_factor_secret
                or locked.auth_multi_factor_enabled_at
                or not locked.auth_multi_factor_pending_created
                or timezone.now()
                > locked.auth_multi_factor_pending_created + timedelta(seconds=ttl_seconds)
            ):
                return False
            secret = locked.get_totp_secret()
            counter = matching_totp_counter(secret, token, at_time=at_time) if secret else None
            if counter is None:
                return False
            locked.auth_multi_factor_enabled_at = timezone.now()
            locked.auth_multi_factor_pending_created = None
            # The enrollment token cannot be replayed immediately as a login token.
            locked.auth_multi_factor_last_counter = counter
            locked.save(
                update_fields=[
                    "auth_multi_factor_enabled_at",
                    "auth_multi_factor_pending_created",
                    "auth_multi_factor_last_counter",
                    "modified",
                ]
            )
            self.auth_multi_factor_enabled_at = locked.auth_multi_factor_enabled_at
            self.auth_multi_factor_pending_created = None
            self.auth_multi_factor_last_counter = counter
            return True

    def consume_totp(self, token, *, at_time=None):
        """Validate and atomically burn a TOTP counter to prevent replay."""
        from .totp import matching_totp_counter

        with transaction.atomic():
            locked = CoreMember.objects.select_for_update().get(pk=self.pk)
            if not locked.mfa_enabled:
                return False
            secret = locked.get_totp_secret()
            counter = matching_totp_counter(secret, token, at_time=at_time) if secret else None
            if counter is None or (
                locked.auth_multi_factor_last_counter is not None
                and counter <= locked.auth_multi_factor_last_counter
            ):
                return False
            locked.auth_multi_factor_last_counter = counter
            locked.save(
                update_fields=["auth_multi_factor_last_counter", "modified"]
            )
            self.auth_multi_factor_last_counter = counter
            return True

    def clear_mfa(self):
        self.auth_multi_factor_secret = None
        self.auth_multi_factor_display_name = ""
        self.auth_multi_factor_pending_created = None
        self.auth_multi_factor_enabled_at = None
        self.auth_multi_factor_last_counter = None
        self.save(
            update_fields=[
                "auth_multi_factor_secret",
                "auth_multi_factor_display_name",
                "auth_multi_factor_pending_created",
                "auth_multi_factor_enabled_at",
                "auth_multi_factor_last_counter",
                "modified",
            ]
        )

    def invites_received(self):
        from ..invite.models import CoreInvite
        return CoreInvite.objects.filter(email=self.user.email)

    @property
    def group_count(self):
        return self.user.groups.count()

    @property
    def is_primary_account(self):
        return self.memberships.filter(primary=True, account=self.get_current_account()).exists()

    # Password reset tokens expire this many hours after they are issued.
    PASSWORD_RESET_TOKEN_TTL_HOURS = 1

    @staticmethod
    def generate_password_reset_token():
        # Cryptographically strong, single-use, ~256-bit token (replaces the old
        # 32-bit uuid4()[:8] token which was brute-forceable).
        import secrets

        return secrets.token_urlsafe(32)

    def password_reset_token_is_valid(self, token):
        """A token matches only if it is non-empty, equal (constant-time) and unexpired."""
        import secrets
        from django.utils import timezone
        from datetime import timedelta

        if not token or not self.password_reset_token:
            return False
        if not secrets.compare_digest(str(self.password_reset_token), str(token)):
            return False
        if not self.password_reset_token_created:
            return False
        expires_at = self.password_reset_token_created + timedelta(hours=self.PASSWORD_RESET_TOKEN_TTL_HOURS)
        return timezone.now() <= expires_at

    @property
    def get_password_reset_link(self):
        from django.utils import timezone

        if not self.password_reset_token:
            self.password_reset_token = self.generate_password_reset_token()
            self.password_reset_token_created = timezone.now()
            self.save()

        return f"{settings.APP_URL}/reset/{self.password_reset_token}/"

    def send_verification_email(self):
        self.notification_email.get().send_verification_email()

    def send_password_reset(self, next_url=None):
        from apps.console.notification.models import CoreNotificationLogEmail
        from django.utils import timezone

        self.password_reset_token = self.generate_password_reset_token()
        self.password_reset_token_created = timezone.now()
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
