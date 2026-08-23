import boto3
from apps.api.v1.utils.http import request_timeout, requests
from apps.api.v1.utils.boto import bounded_boto3_client
from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt
from django.conf import settings
from django.db import models
from django.db.models import UniqueConstraint
from django.utils import timezone
from model_utils.models import TimeStampedModel
import secrets
from django.utils.crypto import salted_hmac

from sentry_sdk import capture_exception

from apps.console.account.models import CoreAccount
from apps.console.member.models import CoreMember
from apps.api.v1._thirdparty.aws.ses import SesMailSender, SesDestination


SLACK_SECRET_PREFIX = "bs-slack-fernet-v1:"
SLACK_API_HOSTNAMES = frozenset({"slack.com", "slack-gov.com"})
SLACK_WEBHOOK_HOSTNAMES = frozenset({"hooks.slack.com", "hooks.slack-gov.com"})


def sanitize_slack_oauth_metadata(payload):
    """Keep display-only Slack identity metadata, never OAuth/webhook secrets."""

    if not isinstance(payload, dict):
        return {}

    sanitized = {}
    for name in ("team", "enterprise"):
        value = payload.get(name)
        if not isinstance(value, dict):
            continue
        identity = {
            key: value.get(key)
            for key in ("id", "name")
            if isinstance(value.get(key), str) and value.get(key)
        }
        if identity:
            sanitized[name] = identity
    return sanitized


class CoreNotificationEmail(TimeStampedModel):
    VERIFY_TOKEN_TTL_HOURS = 24

    @staticmethod
    def verification_token_digest(token):
        return salted_hmac(
            "backupsheep.notification-email-verification",
            str(token or ""),
        ).hexdigest()

    class Status(models.IntegerChoices):
        UN_VERIFIED = 0, "Un-Verified"
        VERIFIED = 1, "Verified"
        HARD_BOUNCE = 2, "Hard bounce"
        SPAM_COMPLAINT = 3, "Spam complaint"

    member = models.ForeignKey(CoreMember, related_name="notification_email", on_delete=models.CASCADE)
    email = models.EmailField(max_length=256)
    status = models.IntegerField(choices=Status.choices, default=Status.UN_VERIFIED)
    verify_code = models.CharField(max_length=256, null=True)
    verify_code_created = models.DateTimeField(null=True, editable=False)

    class Meta:
        db_table = "core_notification_email"
        constraints = [
            UniqueConstraint(
                fields=["member", "email"],
                name="unique_account_notification",
            ),
        ]

    def send_verification_email(self):
        # A short UUID prefix provided only 32 bits of entropy. This bearer is
        # delivered by email, so give it full token entropy and expire it at use.
        verify_code = secrets.token_urlsafe(32)

        self.verify_code = self.verification_token_digest(verify_code)
        self.verify_code_created = timezone.now()
        self.status = self.Status.UN_VERIFIED
        self.save()

        email_notification = CoreNotificationLogEmail()
        email_notification.member = self.member
        email_notification.email = self.email
        email_notification.template = "verify_email"
        email_notification.context = {
            "action_url": "[redacted email verification link]",
            "help_url": f"{settings.APP_URL}",
            "sender_name": f"{settings.APP_NAME} - Notification Bot",
        }
        email_notification.save()

        email_notification.send(
            delivery_context={
                "action_url": (
                    f"{settings.APP_URL}/console/notification/email/verify/"
                    f"{verify_code}/"
                )
            },
            persist_rendered=False,
        )


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

    def send(self, *, delivery_context=None, persist_rendered=True):
        """Render and deliver an email without requiring bearer data at rest.

        ``delivery_context`` exists only for this call and overrides the safe,
        persisted context.  Callers sending password-reset or other bearer links
        can set ``persist_rendered=False`` so neither rendered body is retained.
        The default remains compatible with ordinary notification audit logs.
        """

        from django.template.loader import render_to_string
        from apps.console.setting.models import CoreSiteSettings
        import json

        if delivery_context is not None and not isinstance(delivery_context, dict):
            raise TypeError("delivery_context must be a dictionary")

        # Provider + credentials and branding come from the DB-backed site settings
        # (configured in the onboarding wizard), falling back to the matching .env values.
        site = CoreSiteSettings.load()
        app_name = site.get_app_name()
        app_url = f"{site.get_app_protocol()}{site.get_app_domain()}"

        # render_to_string does not run context processors, so inject branding explicitly.
        email_context = {
            **(self.context or {}),
            **(delivery_context or {}),
            "site_app_name": app_name,
            "site_app_url": app_url,
        }
        rendered_html = render_to_string(
            f"console/emails/{self.template}.html", email_context
        )
        rendered_text = render_to_string(
            f"console/emails/{self.template}.txt.html", email_context
        )
        rendered_subject = render_to_string(
            f"console/emails/{self.template}.subject.html", email_context
        )
        self.subject = rendered_subject
        if persist_rendered:
            self.html_body = rendered_html
            self.text_body = rendered_text
        else:
            # Clear bodies as well, in case a log row is deliberately re-sent.
            self.html_body = None
            self.text_body = None
        self.save()

        email_provider = site.get_email_provider()

        if email_provider == "mailgun":
            api_url = site.email_cred("api_url", "MAILGUN_API_URL")
            domain = site.email_cred("domain", "MAILGUN_DOMAIN")
            response = requests.post(
                url=f"{api_url}/{domain}/messages",
                auth=("api", site.email_cred("api_key", "MAILGUN_API_KEY")),
                data={"from": f"{app_name} <{site.email_cred('email', 'MAILGUN_EMAIL')}>",
                      "to": [self.email],
                      "subject": rendered_subject,
                      "text": rendered_text,
                      "html": rendered_html
                      }
            )
            self.message_id = response.json().get("message_id")
            self.save()
        elif email_provider == "postmark":
            parameters = {"From": f"{app_name} <{site.email_cred('email', 'POSTMARK_EMAIL')}>",
                          "To": self.email,
                          "Subject": rendered_subject,
                          "TextBody": rendered_text,
                          "HtmlBody": rendered_html,
                          "MessageStream": "outbound"
                          }
            data = json.dumps(parameters)

            response = requests.post(
                url=f"{site.email_cred('api_url', 'POSTMARK_API_URL')}/email",
                headers={"Content-Type": "application/json", "Accept": "application/json",
                         "X-Postmark-Server-Token": site.email_cred("api_key", "POSTMARK_API_KEY")},
                data=data
            )
            self.message_id = response.json().get("MessageID")
            self.save()
        elif email_provider == "ses":
            # If you are using dedicated IP then update this configset accordingly.
            config_set = "default"

            ses_client = bounded_boto3_client(
                "ses",
                aws_access_key_id=site.email_cred("access_key_id", "SES_ACCESS_KEY_ID"),
                aws_secret_access_key=site.email_cred("secret_access_key", "SES_SECRET_ACCESS_KEY"),
                region_name=site.email_cred("region_name", "SES_REGION_NAME"),
            )

            ses_mail_sender = SesMailSender(ses_client)
            from_email = site.email_cred("from_email") or f"notifications@{site.get_app_domain()}"
            source = f"{app_name} <{from_email}>"

            # Send Email
            message_id = ses_mail_sender.send_email(
                source,
                SesDestination([self.email]),
                rendered_subject,
                rendered_text,
                rendered_html,
                config_set=config_set,
            )

            self.message_id = message_id
            self.save()


class CoreNotificationSlack(TimeStampedModel):
    account = models.ForeignKey(CoreAccount, related_name="notification_slack", on_delete=models.CASCADE)
    app_id = models.CharField(max_length=64, editable=False)
    token_type = models.CharField(max_length=64, editable=False)
    access_token = models.TextField(null=True, editable=False)
    bot_user_id = models.CharField(max_length=64, editable=False)
    refresh_token = models.TextField(null=True, editable=False)
    expiry = models.DateTimeField(null=True)
    channel = models.CharField(max_length=64, editable=False)
    channel_id = models.CharField(max_length=64, editable=False)
    configuration_url = models.TextField(null=True, editable=False)
    url = models.TextField(null=True, editable=False)
    data = models.JSONField(null=True)
    added_by = models.ForeignKey(
        CoreMember,
        related_name="notification_slack",
        on_delete=models.CASCADE,
        null=True,
    )

    class Meta:
        db_table = "core_notification_slack"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(access_token__isnull=True)
                | models.Q(access_token__startswith=SLACK_SECRET_PREFIX),
                name="slack_access_token_ciphertext_v1",
            ),
            models.CheckConstraint(
                condition=models.Q(refresh_token__isnull=True)
                | models.Q(refresh_token__startswith=SLACK_SECRET_PREFIX),
                name="slack_refresh_token_ciphertext_v1",
            ),
            models.CheckConstraint(
                condition=models.Q(configuration_url__isnull=True)
                | models.Q(configuration_url__startswith=SLACK_SECRET_PREFIX),
                name="slack_configuration_ciphertext_v1",
            ),
            models.CheckConstraint(
                condition=models.Q(url__isnull=True)
                | models.Q(url__startswith=SLACK_SECRET_PREFIX),
                name="slack_webhook_ciphertext_v1",
            ),
        ]

    _SECRET_FIELDS = ("access_token", "refresh_token", "configuration_url", "url")

    @staticmethod
    def _normalize_secret_value(value):
        if isinstance(value, memoryview):
            value = value.tobytes()
        if isinstance(value, (bytes, bytearray)):
            try:
                return bytes(value).decode("ascii")
            except UnicodeDecodeError:
                return value
        return value

    def _encrypt_secret(self, value):
        if value in (None, "", b""):
            return None
        if not isinstance(value, str):
            raise ValueError("Slack secrets must be supplied as plaintext strings")
        ciphertext = bs_encrypt(value, self.account.get_encryption_key())
        if not ciphertext:
            raise ValueError("Unable to encrypt Slack secret")
        return SLACK_SECRET_PREFIX + bytes(ciphertext).decode("ascii")

    def _decrypt_secret(self, field_name):
        value = self._normalize_secret_value(getattr(self, field_name, None))
        if not isinstance(value, str) or not value.startswith(SLACK_SECRET_PREFIX):
            return None
        try:
            return bs_decrypt(
                value[len(SLACK_SECRET_PREFIX) :].encode("ascii"),
                self.account.get_encryption_key(),
            )
        except Exception as error:
            # Account/key damage and malformed ciphertext must never fall back to
            # treating the database value as a usable provider credential.
            capture_exception(error)
            return None

    def set_secrets(
        self,
        *,
        access_token=None,
        refresh_token=None,
        configuration_url=None,
        webhook_url=None,
    ):
        self.access_token = self._encrypt_secret(access_token)
        self.refresh_token = self._encrypt_secret(refresh_token)
        self.configuration_url = self._encrypt_secret(configuration_url)
        self.url = self._encrypt_secret(webhook_url)

    @property
    def team_name(self):
        metadata = sanitize_slack_oauth_metadata(self.data)
        return metadata.get("team", {}).get("name") or "your Slack workspace"

    def save(self, *args, **kwargs):
        # Protect direct ORM callers as well as the OAuth callback. Versioned
        # ciphertext is validated before any row can be re-saved, preventing
        # accidental plaintext writes and accidental double encryption.
        for field_name in self._SECRET_FIELDS:
            value = self._normalize_secret_value(getattr(self, field_name, None))
            if isinstance(value, str):
                if not value:
                    setattr(self, field_name, None)
                    continue
                if not value.startswith(SLACK_SECRET_PREFIX):
                    value = self._encrypt_secret(value)
                setattr(self, field_name, value)
                if self._decrypt_secret(field_name) is None:
                    raise ValueError(f"{field_name} ciphertext could not be decrypted")
            elif value not in (None, b""):
                raise ValueError(f"{field_name} is not versioned ciphertext")
        self.data = sanitize_slack_oauth_metadata(self.data)
        return super().save(*args, **kwargs)

    def refresh_auth_token(self):
        from datetime import timedelta
        from apps.api.v1.utils.oauth_security import validated_https_endpoint

        refresh_token = self._decrypt_secret("refresh_token")
        if not refresh_token:
            return False
        token_request_url = validated_https_endpoint(
            settings.SLACK_TOKEN_URL,
            allowed_hostnames=SLACK_API_HOSTNAMES,
            allowed_paths={"/api/oauth.v2.access"},
        )
        if token_request_url is None:
            return False

        result = requests.post(
            token_request_url,
            data={
                "grant_type": "refresh_token",
                "client_id": settings.SLACK_CLIENT_ID,
                "client_secret": settings.SLACK_CLIENT_SECRET,
                "refresh_token": refresh_token,
            },
            headers={"Accept": "application/json"},
            allow_redirects=False,
            verify=True,
            timeout=request_timeout(),
        )

        if result.status_code != 200:
            return False
        try:
            slack_data = result.json()
            access_token = slack_data.get("access_token")
            rotated_refresh_token = slack_data.get("refresh_token")
            expires_in = int(slack_data.get("expires_in"))
        except (TypeError, ValueError):
            return False
        if (
            not slack_data.get("ok")
            or not isinstance(access_token, str)
            or not access_token
            or not isinstance(rotated_refresh_token, str)
            or not rotated_refresh_token
            or expires_in <= 0
        ):
            return False

        self.access_token = self._encrypt_secret(access_token)
        self.refresh_token = self._encrypt_secret(rotated_refresh_token)
        self.expiry = timezone.now() + timedelta(seconds=expires_in)
        merged_metadata = sanitize_slack_oauth_metadata(self.data)
        merged_metadata.update(sanitize_slack_oauth_metadata(slack_data))
        self.data = merged_metadata
        self.save()
        return True

    def _post_webhook(self, message):
        from apps.api.v1.utils.oauth_security import validated_https_endpoint

        webhook_url = self._decrypt_secret("url")
        if not webhook_url:
            return False
        endpoint = validated_https_endpoint(
            webhook_url,
            allowed_hostnames=SLACK_WEBHOOK_HOSTNAMES,
            allowed_path_prefixes={"/services/"},
        )
        if endpoint is None:
            return False
        try:
            response = requests.post(
                endpoint,
                json={"text": str(message)},
                headers={"Accept": "text/plain"},
                allow_redirects=False,
                verify=True,
                timeout=request_timeout(),
            )
            return response.status_code == 200 and response.text.strip() == "ok"
        except Exception:
            # Do not report this exception through Sentry here: SDK local-variable
            # capture would include the decrypted webhook bearer in this frame.
            return False

    def send(self, message):
        # Deliberately avoid putting a decrypted webhook URL in a Celery message,
        # where it would become a durable broker credential.
        return self._post_webhook(message)

    def validate(self):
        return self._post_webhook(
            "Hey! This is validation message that your Slack integration is working fine."
        )


class CoreNotificationTelegram(TimeStampedModel):
    account = models.ForeignKey(CoreAccount, related_name="notification_telegram", on_delete=models.CASCADE)
    chat_id = models.CharField(max_length=64, editable=False)
    channel_name = models.CharField(max_length=64, editable=False)
    added_by = models.ForeignKey(
        CoreMember,
        related_name="notification_telegram",
        on_delete=models.CASCADE,
        null=True,
    )

    class Meta:
        db_table = "core_notification_telegram"

    def send(self, message):
        from apps._tasks.helper.tasks import send_log_to_telegram

        send_log_to_telegram.delay(chat_id=self.chat_id, message=message)

    def validate(self):
        try:
            result = requests.get(
                f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_KEY}/sendMessage?"
                f"chat_id={self.chat_id}"
                f"&text=Hey! This is validation message that your Telegram integration is working fine.",
                headers={"content-type": "application/json"},
                verify=True,
            )
            if result.status_code == 200:
                return True
            else:
                raise ValueError(result.json().get("description"))
        except Exception as e:
            capture_exception(e)
            return False
