import boto3
import requests
from django.conf import settings
from django.db import models
from django.db.models import UniqueConstraint
from model_utils.models import TimeStampedModel
import uuid

from apps.console.member.models import CoreMember
from apps.api.v1._thirdparty.aws.ses import SesMailSender, SesDestination


class CoreNotificationEmail(TimeStampedModel):
    class Status(models.IntegerChoices):
        UN_VERIFIED = 0, "Un-Verified"
        VERIFIED = 1, "Verified"
        HARD_BOUNCE = 2, "Hard bounce"
        SPAM_COMPLAINT = 3, "Spam complaint"

    member = models.ForeignKey(CoreMember, related_name="notification_email", on_delete=models.CASCADE)
    email = models.EmailField(max_length=256)
    status = models.IntegerField(choices=Status.choices, default=Status.UN_VERIFIED)
    verify_code = models.CharField(max_length=256, null=True)

    class Meta:
        db_table = "core_notification_email"
        constraints = [
            UniqueConstraint(
                fields=["member", "email"],
                name="unique_account_notification",
            ),
        ]

    def send_verification_email(self):
        verify_code = str(uuid.uuid4()).split("-")[0]

        self.verify_code = verify_code
        self.status = self.Status.UN_VERIFIED
        self.save()

        email_notification = CoreNotificationLogEmail()
        email_notification.member = self.member
        email_notification.email = self.email
        email_notification.template = "verify_email"
        email_notification.context = {
            "action_url": f"{settings.APP_URL}/console/notification/email/verify/{self.verify_code}/",
            "help_url": "https://backupsheep.com",
            "sender_name": "BackupSheep - Notification Bot",
        }
        email_notification.save()

        # Now Send email
        email_notification.send()


class CoreNotificationLogEmail(TimeStampedModel):
    member = models.ForeignKey(CoreMember, related_name="notification_log_email", on_delete=models.CASCADE)
    email = models.EmailField(editable=False)
    text_body = models.TextField(editable=False, null=True)
    html_body = models.TextField(editable=False, null=True)
    subject = models.TextField(editable=False, null=True)
    context = models.JSONField(editable=False, null=True)
    template = models.CharField(max_length=1024, null=True)
    message_id = models.CharField(max_length=1024, null=True)

    class Meta:
        db_table = "core_notification_log_email"

    def send(self):
        from django.template.loader import render_to_string
        import json

        self.html_body = render_to_string(f"console/emails/{self.template}.html", self.context)
        self.text_body = render_to_string(f"console/emails/{self.template}.txt.html", self.context)
        self.subject = render_to_string(f"console/emails/{self.template}.subject.html", self.context)
        self.save()

        email_provider = settings.EMAIL_PROVIDER

        if email_provider == "mailgun":
            response = requests.post(
                url=f"{settings.MAILGUN_API_URL}/{settings.MAILGUN_DOMAIN}/messages",
                auth=("api", settings.MAILGUN_API_KEY),
                data={"from": f"{settings.APP_NAME} <{settings.MAILGUN_EMAIL}>",
                      "to": [self.email],
                      "subject": self.subject,
                      "text": self.text_body,
                      "html": self.html_body
                      }
            )
            self.message_id = response.json().get("message_id")
            self.save()
        elif email_provider == "postmark":
            parameters = {"From": f"{settings.APP_NAME} <{settings.POSTMARK_EMAIL}>",
                          "To": self.email,
                          "Subject": self.subject,
                          "TextBody": self.text_body,
                          "HtmlBody": self.html_body,
                          "MessageStream": "outbound"
                          }
            data = json.dumps(parameters)

            response = requests.post(
                url=f"{settings.POSTMARK_API_URL}/email",
                headers={"Content-Type": "application/json", "Accept": "application/json",
                         "X-Postmark-Server-Token": settings.POSTMARK_API_KEY},
                data=data
            )
            self.message_id = response.json().get("MessageID")
            self.save()
        elif email_provider == "ses":
            # If you are using dedicated IP then update this configset accordingly.
            config_set = "default"

            ses_client = boto3.client(
                "ses",
                aws_access_key_id=settings.AWS_SES_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SES_SECRET_ACCESS_KEY,
                region_name=settings.AWS_SES_REGION_NAME,
            )

            ses_mail_sender = SesMailSender(ses_client)
            source = f"{settings.APP_NAME} <notifications@backupsheep.com>"

            # Send Email
            message_id = ses_mail_sender.send_email(
                source,
                SesDestination([self.email]),
                self.subject,
                self.text_body,
                self.html_body,
                config_set=config_set,
            )

            self.message_id = message_id
            self.save()
