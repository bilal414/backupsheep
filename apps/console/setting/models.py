"""DB-backed, operator-configurable site settings.

A singleton (pk=1) written by the first-run onboarding wizard. Reads fall back to the
matching .env value, so an unset field preserves existing behavior. Only "soft" config
lives here -- infrastructure that must be known at boot (SECRET_KEY, DATABASES,
CELERY_BROKER_URL, ALLOWED_HOSTS, CSRF_TRUSTED_ORIGINS) stays in .env.
"""
import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import models
from model_utils.models import TimeStampedModel


def _site_fernet():
    """Fernet built from a SECRET_KEY-derived key, used to encrypt email credentials."""
    digest = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


class CoreSiteSettings(TimeStampedModel):
    class EmailProvider(models.TextChoices):
        NONE = "none", "Disabled"
        POSTMARK = "postmark", "Postmark"
        MAILGUN = "mailgun", "Mailgun"
        SES = "ses", "Amazon SES"

    # Application
    app_name = models.CharField(max_length=255, blank=True, default="")
    app_protocol = models.CharField(max_length=16, blank=True, default="")
    app_domain = models.CharField(max_length=255, blank=True, default="")
    default_timezone = models.CharField(max_length=64, blank=True, default="")

    # Email provider + credentials (credentials are an encrypted JSON blob keyed by
    # provider; never stored in plaintext).
    email_provider = models.CharField(max_length=16, blank=True, default="")
    email_credentials_encrypted = models.TextField(blank=True, default="")

    # Onboarding state
    setup_completed = models.BooleanField(default=False)
    setup_completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "core_site_settings"

    def save(self, *args, **kwargs):
        self.pk = 1  # enforce singleton
        super().save(*args, **kwargs)

    @classmethod
    def load(cls):
        """Return the singleton, creating it (with defaults) on first access."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    # ----- encrypted email credentials -----
    def set_email_credentials(self, data):
        token = _site_fernet().encrypt(json.dumps(data or {}).encode("utf-8"))
        self.email_credentials_encrypted = token.decode("utf-8")

    @property
    def email_credentials(self):
        if not self.email_credentials_encrypted:
            return {}
        try:
            raw = _site_fernet().decrypt(self.email_credentials_encrypted.encode("utf-8"))
            return json.loads(raw.decode("utf-8"))
        except (InvalidToken, ValueError):
            return {}

    def email_cred(self, key, fallback_setting=None):
        """One credential for the active provider; DB value, else the .env fallback."""
        value = (self.email_credentials.get(self.get_email_provider()) or {}).get(key)
        if value:
            return value
        return getattr(settings, fallback_setting, None) if fallback_setting else None

    # ----- effective values (DB override, else .env fallback) -----
    def get_app_name(self):
        return self.app_name or getattr(settings, "APP_NAME", "BackupSheep")

    def get_app_protocol(self):
        return self.app_protocol or getattr(settings, "APP_PROTOCOL", "https://")

    def get_app_domain(self):
        return self.app_domain or getattr(settings, "APP_DOMAIN", "")

    def get_default_timezone(self):
        return self.default_timezone or getattr(settings, "TIME_ZONE", "UTC")

    def get_email_provider(self):
        return self.email_provider or getattr(settings, "EMAIL_PROVIDER", "none")

    def send_test_email(self, to_email):
        """Send a plain connectivity-test email via the active provider using the stored
        credentials. Returns (ok: bool, detail: str). Used by the onboarding email step."""
        provider = self.get_email_provider()
        app_name = self.get_app_name()
        subject = f"{app_name} test email"
        text = (f"This is a test email from {app_name}. If you received it, your email "
                f"provider is configured correctly.")
        try:
            if provider == "postmark":
                import json
                import requests
                r = requests.post(
                    f"{self.email_cred('api_url', 'POSTMARK_API_URL')}/email",
                    headers={"Content-Type": "application/json", "Accept": "application/json",
                             "X-Postmark-Server-Token": self.email_cred("api_key", "POSTMARK_API_KEY")},
                    data=json.dumps({"From": f"{app_name} <{self.email_cred('email', 'POSTMARK_EMAIL')}>",
                                     "To": to_email, "Subject": subject, "TextBody": text,
                                     "MessageStream": "outbound"}),
                )
                return (r.status_code == 200), (r.json().get("Message", "Sent") if r.status_code != 200 else "Sent")
            elif provider == "mailgun":
                import requests
                r = requests.post(
                    f"{self.email_cred('api_url', 'MAILGUN_API_URL')}/{self.email_cred('domain', 'MAILGUN_DOMAIN')}/messages",
                    auth=("api", self.email_cred("api_key", "MAILGUN_API_KEY")),
                    data={"from": f"{app_name} <{self.email_cred('email', 'MAILGUN_EMAIL')}>",
                          "to": [to_email], "subject": subject, "text": text},
                )
                return (r.status_code == 200), ("Sent" if r.status_code == 200 else r.text[:200])
            elif provider == "ses":
                import boto3
                client = boto3.client(
                    "ses",
                    aws_access_key_id=self.email_cred("access_key_id", "AWS_SES_ACCESS_KEY_ID"),
                    aws_secret_access_key=self.email_cred("secret_access_key", "AWS_SES_SECRET_ACCESS_KEY"),
                    region_name=self.email_cred("region_name", "AWS_SES_REGION_NAME"),
                )
                from_email = self.email_cred("from_email") or f"notifications@{self.get_app_domain()}"
                client.send_email(
                    Source=f"{app_name} <{from_email}>",
                    Destination={"ToAddresses": [to_email]},
                    Message={"Subject": {"Data": subject}, "Body": {"Text": {"Data": text}}},
                )
                return True, "Sent"
            return False, "No email provider is selected."
        except Exception as e:
            return False, str(e)[:200]
