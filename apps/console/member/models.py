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
    auth_session_version = models.PositiveBigIntegerField(default=1, editable=False)

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
        active_memberships = self.memberships.filter(
            status=CoreMemberAccount.Status.ACTIVE
        ).select_related("account")
        if active_memberships.count() == 1:
            return active_memberships.first().account
        return None

    @property
    def multiple_accounts(self):
        return self.memberships.filter(status=CoreMemberAccount.Status.ACTIVE).count() > 1

    def set_current_account(self, account=None):
        """Atomically select an ACTIVE membership as the current tenant.

        Membership state can change between an API pre-check and the write.  Re-read
        every row under a lock so a stale suspended/pending/invited membership can
        never be made current.  With no explicit account, prefer the active primary
        membership and then the oldest active membership for deterministic recovery.
        """
        account_id = getattr(account, "pk", account) if account is not None else None

        with transaction.atomic():
            memberships = list(
                self.memberships.select_for_update()
                .select_related("account")
                .order_by("-primary", "id")
            )
            active_memberships = [
                membership
                for membership in memberships
                if membership.status == CoreMemberAccount.Status.ACTIVE
            ]
            if account_id is None:
                target = next(
                    (membership for membership in active_memberships if membership.current),
                    active_memberships[0] if active_memberships else None,
                )
            else:
                target = next(
                    (
                        membership
                        for membership in active_memberships
                        if str(membership.account_id) == str(account_id)
                    ),
                    None,
                )

            if target is None:
                return None

            # Clear the old selector before setting the replacement so the
            # database's conditional unique constraint is satisfied even when
            # the primary membership is the destination and sorts first.
            for membership in memberships:
                if membership.current and membership.pk != target.pk:
                    membership.current = False
                    membership.save(update_fields=["current", "modified"])
            if not target.current:
                target.current = True
                target.save(update_fields=["current", "modified"])

            return target

    def get_active_current_membership(self):
        """Return an active current membership, repairing a stale selector safely."""
        membership = (
            self.memberships.filter(
                current=True,
                status=CoreMemberAccount.Status.ACTIVE,
            )
            .select_related("account")
            .first()
        )
        return membership or self.set_current_account()

    def get_current_account(self):
        membership = self.get_active_current_membership()
        return membership.account if membership else None

    def get_primary_account(self):
        membership = (
            self.memberships.filter(
                primary=True,
                status=CoreMemberAccount.Status.ACTIVE,
            )
            .select_related("account")
            .first()
        )
        return membership.account if membership else None

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

    def rotate_auth_session_version(self):
        """Atomically revoke every previously issued browser session."""
        from django.db.models import F

        CoreMember.objects.filter(pk=self.pk).update(
            auth_session_version=F("auth_session_version") + 1
        )
        self.refresh_from_db(fields=["auth_session_version"])
        return self.auth_session_version

    def invites_received(self):
        from ..invite.models import CoreInvite
        return CoreInvite.objects.filter(email=self.user.email)

    @property
    def group_count(self):
        return self.user.groups.count()

    @property
    def is_primary_account(self):
        membership = self.get_active_current_membership()
        return bool(membership and membership.primary)

    # Password reset tokens expire this many hours after they are issued.
    PASSWORD_RESET_TOKEN_TTL_HOURS = 1

    @staticmethod
    def generate_password_reset_token():
        # Cryptographically strong, single-use, ~256-bit token (replaces the old
        # 32-bit uuid4()[:8] token which was brute-forceable).
        import secrets

        return secrets.token_urlsafe(32)

    @staticmethod
    def password_reset_token_digest(token):
        """Return the site-keyed digest persisted for a reset bearer token."""
        from django.utils.crypto import salted_hmac

        if not token:
            return None
        return salted_hmac(
            "backupsheep.password-reset-token.v1",
            str(token),
        ).hexdigest()

    def issue_password_reset_token(self):
        """Create a reset token while persisting only its keyed digest."""
        from django.utils import timezone

        token = self.generate_password_reset_token()
        self.password_reset_token = self.password_reset_token_digest(token)
        self.password_reset_token_created = timezone.now()
        self.save(
            update_fields=[
                "password_reset_token",
                "password_reset_token_created",
                "modified",
            ]
        )
        return token

    def password_reset_token_is_valid(self, token):
        """A token matches only if it is non-empty, equal (constant-time) and unexpired."""
        from datetime import timedelta
        from django.utils import timezone
        from django.utils.crypto import constant_time_compare

        if not token or not self.password_reset_token:
            return False

        expected_digest = self.password_reset_token_digest(token)
        if not constant_time_compare(
            str(self.password_reset_token), str(expected_digest)
        ):
            return False
        if not self.password_reset_token_created:
            return False
        expires_at = self.password_reset_token_created + timedelta(
            hours=self.PASSWORD_RESET_TOKEN_TTL_HOURS
        )
        return timezone.now() <= expires_at

    @property
    def get_password_reset_link(self):
        token = self.issue_password_reset_token()
        return f"{settings.APP_URL}/reset/{token}/"

    def send_verification_email(self):
        self.notification_email.get().send_verification_email()

    def send_password_reset(self, next_url=None):
        from apps.console.notification.models import CoreNotificationLogEmail

        reset_token = self.issue_password_reset_token()

        email_notification = CoreNotificationLogEmail()
        email_notification.member = self
        email_notification.email = self.user.email
        email_notification.template = "password_reset"
        email_notification.context = {
            "action_url": f"{settings.APP_URL}/reset/{reset_token}/",
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
