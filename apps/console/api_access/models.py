"""Personal API tokens: scoped, expiring, revocable bearer credentials.

A token is bound to one member *and* one workspace at creation time.  The raw
secret (``bsk_`` + 43 URL-safe characters) is shown exactly once; only its
SHA-256 digest is stored, so a database read never yields a usable credential.
"""

import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone
from model_utils.models import TimeStampedModel

from apps.api.v1.utils.api_scopes import expand_scopes, parse_scope_string
from apps.console.account.models import CoreAccount
from apps.console.member.models import CoreMember

# How often ``last_used_at`` is written back; a busy integration must not turn
# every request into an UPDATE.
LAST_USED_WRITE_INTERVAL = timedelta(seconds=60)


class CoreApiToken(TimeStampedModel):
    PREFIX = "bsk_"
    SECRET_BYTES = 32
    KEY_PREFIX_LENGTH = 12  # "bsk_" + 8 identifying characters

    member = models.ForeignKey(
        CoreMember, related_name="api_tokens", on_delete=models.CASCADE
    )
    account = models.ForeignKey(
        CoreAccount, related_name="api_tokens", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=128)
    key_prefix = models.CharField(max_length=16, db_index=True, editable=False)
    key_hash = models.CharField(max_length=64, unique=True, editable=False)
    # Space-separated, mirroring django-oauth-toolkit's AccessToken.scope.
    scope = models.TextField(blank=True, default="")
    expires_at = models.DateTimeField()
    last_used_at = models.DateTimeField(null=True, blank=True, editable=False)
    revoked_at = models.DateTimeField(null=True, blank=True, editable=False)

    class Meta:
        db_table = "core_api_token"
        ordering = ("-created",)

    def __str__(self):
        # Never render anything derived from the secret beyond the display prefix.
        return f"{self.name} ({self.key_prefix}…)"

    # ---- issuance -----------------------------------------------------------
    @staticmethod
    def generate_secret():
        return CoreApiToken.PREFIX + secrets.token_urlsafe(CoreApiToken.SECRET_BYTES)

    @staticmethod
    def hash_secret(secret):
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    @classmethod
    def max_ttl_seconds(cls):
        return int(getattr(settings, "API_TOKEN_MAX_TTL_SECONDS", 90 * 24 * 60 * 60))

    @classmethod
    def default_ttl_seconds(cls):
        return min(int(settings.API_TOKEN_TTL_SECONDS), cls.max_ttl_seconds())

    @classmethod
    def issue(cls, *, member, account, name, scopes, ttl_seconds=None, now=None):
        """Create a token and return ``(token, secret)``.

        ``secret`` is the only copy of the credential; the caller must hand it to
        the user immediately.  ``ttl_seconds`` is clamped by validation in the
        API layer; this method still refuses out-of-range values as defence in
        depth.
        """
        now = now or timezone.now()
        ttl = int(ttl_seconds or cls.default_ttl_seconds())
        if ttl <= 0 or ttl > cls.max_ttl_seconds():
            raise ValueError("Token lifetime is outside the permitted range.")
        secret = cls.generate_secret()
        token = cls.objects.create(
            member=member,
            account=account,
            name=name,
            key_prefix=secret[: cls.KEY_PREFIX_LENGTH],
            key_hash=cls.hash_secret(secret),
            scope=" ".join(scopes),
            expires_at=now + timedelta(seconds=ttl),
        )
        return token, secret

    def rotate(self, *, now=None):
        """Replace the secret in place, keeping name, scopes, and expiry policy."""
        now = now or timezone.now()
        secret = self.generate_secret()
        self.key_prefix = secret[: self.KEY_PREFIX_LENGTH]
        self.key_hash = self.hash_secret(secret)
        # A rotated token starts a fresh lifetime of the same length.
        lifetime = self.expires_at - self.created
        if lifetime <= timedelta(0) or lifetime > timedelta(seconds=self.max_ttl_seconds()):
            lifetime = timedelta(seconds=self.default_ttl_seconds())
        self.expires_at = now + lifetime
        self.revoked_at = None
        self.save(update_fields=["key_prefix", "key_hash", "expires_at", "revoked_at", "modified"])
        return secret

    # ---- lookup -------------------------------------------------------------
    @classmethod
    def looks_like_secret(cls, value):
        return isinstance(value, str) and value.startswith(cls.PREFIX) and len(value) < 256

    @classmethod
    def for_secret(cls, secret):
        """Return the token row for a presented secret (any state), or ``None``."""
        if not cls.looks_like_secret(secret):
            return None
        return (
            cls.objects.select_related("member__user", "account")
            .filter(key_hash=cls.hash_secret(secret))
            .first()
        )

    # ---- state --------------------------------------------------------------
    @property
    def is_revoked(self):
        return self.revoked_at is not None

    def is_expired(self, now=None):
        return (now or timezone.now()) >= self.expires_at

    def is_valid(self, scopes=None, now=None):
        return not self.is_revoked and not self.is_expired(now) and self.allow_scopes(scopes)

    @property
    def scopes(self):
        return parse_scope_string(self.scope)

    def allow_scopes(self, scopes):
        """Mirror ``AccessToken.allow_scopes`` so both credential types share checks."""
        if not scopes:
            return True
        return set(scopes).issubset(expand_scopes(self.scopes))

    def revoke(self, now=None):
        if self.revoked_at is None:
            self.revoked_at = now or timezone.now()
            self.save(update_fields=["revoked_at", "modified"])

    def touch_last_used(self, now=None):
        now = now or timezone.now()
        if self.last_used_at is not None and now - self.last_used_at < LAST_USED_WRITE_INTERVAL:
            return False
        # Update without ``save()`` so a concurrent revoke is never overwritten.
        CoreApiToken.objects.filter(pk=self.pk).update(last_used_at=now)
        self.last_used_at = now
        return True

    @property
    def status(self):
        if self.is_revoked:
            return "revoked"
        if self.is_expired():
            return "expired"
        return "active"
