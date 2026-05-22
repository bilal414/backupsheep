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
