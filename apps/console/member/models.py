import uuid

from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from model_utils.models import TimeStampedModel
from sentry_sdk import capture_exception


class CoreMember(TimeStampedModel):
    class Status(models.IntegerChoices):
        DISABLED = 0, 'Disabled'
        ACTIVE = 1, 'Active'
        PENDING = 3, 'Pending'

    user = models.OneToOneField(User, related_name='member', on_delete=models.CASCADE)
    status = models.IntegerField(choices=Status.choices, default=Status.ACTIVE)
    timezone = models.CharField(max_length=64, default="America/New_York")
    street_1 = models.CharField(max_length=1024, null=True, blank=True)
    street_2 = models.CharField(max_length=1024, null=True, blank=True)
    city = models.CharField(max_length=50, null=True, blank=True)
    state = models.CharField(max_length=50, null=True, blank=True)
    zip_code = models.CharField(max_length=10, null=True, blank=True)
    country = models.CharField(max_length=50, default="US")
    phone = models.CharField(max_length=255, null=True, blank=True)
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
    def short_name(self):
        """Returns the person's short_name."""
        return f'{self.user.first_name[0]}{self.user.last_name[0]}{self.id}'

    @property
    def first_name(self):
        return f'{self.user.first_name}'

    @property
    def last_name(self):
        return f'{self.user.last_name}'

    @property
    def email(self):
        return self.user.email

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
            "help_url": "https://backupsheep.com",
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
            "action_url": f"{settings.APP_URL}/reset/{self.password_reset_token}/",
            "help_url": "https://backupsheep.com",
            "sender_name": f"{settings.APP_NAME} - Notification Bot",
        }
        email_notification.save()

        # Now Send email
        email_notification.send()
