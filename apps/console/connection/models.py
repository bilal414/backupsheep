import ipaddress
import json
import math
import os
import re
import shlex
import subprocess
import tempfile
import uuid
from urllib.parse import urlsplit, urlunsplit

from apps.api.v1.utils.http import request_timeout, requests
from apps.api.v1.utils.boto import bounded_boto3_client
from botocore.exceptions import ClientError
from django.conf import settings
from django.core.cache import cache
from django.core.validators import RegexValidator
from django.db import models
import time

from django.utils.text import slugify
from django_celery_beat.models import PeriodicTasks
from google.auth.transport.requests import AuthorizedSession, Request
from google.oauth2 import service_account
from requests.exceptions import SSLError, JSONDecodeError
from requests_toolbelt import SSLAdapter

from rest_framework.exceptions import APIException
from sentry_sdk import capture_exception, capture_message

from apps._tasks.exceptions import (
    NodeConnectionErrorSSH,
    NodeConnectionErrorMYSQL,
    NodeConnectionErrorMARIADB,
    NodeConnectionErrorPOSTGRESQL,
    NodeConnectionErrorWebsite,
    NodeConnectionErrorEligibleObjects,
    NodeConnectionErrorSFTP,
    IntegrationValidationFailed,
    IntegrationValidationError,
)
from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt

from ..account.models import CoreAccount
from model_utils.models import TimeStampedModel

from ..member.models import CoreMember
from ..utils.models import UtilBase
from ..vultr import iter_vultr_collection, vultr_request_timeout
from .reliability import (
    ClassifiedConnectionError,
    DatabaseClientCapabilityError,
    DatabaseEventPrivilegeError,
    DatabaseTLSRequiredError,
    classify_connection_error,
    classified_connection_error,
    database_tls_required_message,
)
from .ssh import cleanup_temporary_key, configure_host_keys, open_ssh_client


_PROVIDER_SDK_TIMEOUT_DEFAULT = (10.0, 60.0)
_PROVIDER_SDK_TIMEOUT_FLOOR = 0.1
_PROVIDER_SDK_TIMEOUT_MAX_DEFAULT = 300.0
_GOOGLE_TIMEOUT_UNSET = object()
_GOOGLE_REFRESH_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
WORDPRESS_SECRET_PREFIX = "bs-wordpress-fernet-v1:"
WORDPRESS_KEY_HEADER = "X-BackupSheep-Key"
_WORDPRESS_ROUTES = frozenset(
    {
        "backup",
        "delete",
        "download",
        "files",
        "rebuild_history",
        "status",
        "validate",
    }
)


def _provider_sdk_timeout():
    """Return a finite connect/read timeout pair for provider SDK clients.

    Provider SDKs are constructed in model methods, so keep this policy local to
    this module instead of changing process-wide SDK or requests defaults.  Invalid
    settings fall back to conservative values and an operator-configurable ceiling
    prevents an accidental multi-hour socket wait.
    """

    try:
        maximum = float(
            getattr(
                settings,
                "PROVIDER_HTTP_MAX_TIMEOUT",
                _PROVIDER_SDK_TIMEOUT_MAX_DEFAULT,
            )
        )
    except (TypeError, ValueError):
        maximum = _PROVIDER_SDK_TIMEOUT_MAX_DEFAULT
    if not math.isfinite(maximum) or maximum < _PROVIDER_SDK_TIMEOUT_FLOOR:
        maximum = _PROVIDER_SDK_TIMEOUT_MAX_DEFAULT

    values = []
    for setting_name, default in zip(
        ("PROVIDER_HTTP_CONNECT_TIMEOUT", "PROVIDER_HTTP_READ_TIMEOUT"),
        _PROVIDER_SDK_TIMEOUT_DEFAULT,
    ):
        try:
            value = float(getattr(settings, setting_name, default))
        except (TypeError, ValueError):
            value = default
        if not math.isfinite(value):
            value = default
        values.append(min(max(value, _PROVIDER_SDK_TIMEOUT_FLOOR), maximum))
    return tuple(values)


class _BoundedGoogleAuthorizedSession(AuthorizedSession):
    """Google auth session with bounded I/O and mutation-safe refresh behavior.

    ``AuthorizedSession`` retries the original request after a credential refresh.
    That is safe for reads, but a replayed POST/PATCH/DELETE can duplicate a
    provider mutation when the first response was lost.  Reads retain the SDK's
    bounded refresh behavior; mutations do not get an automatic credential-refresh
    replay.  The caller's explicit timeout remains authoritative.
    """

    def __init__(self, credentials, *, timeout=None):
        self._backupsheep_timeout = timeout or _provider_sdk_timeout()

        # The auth-token exchange is a POST and has no BackupSheep idempotency
        # token.  Use a private session with zero adapter retries; this does not
        # alter requests or Google SDK process globals.
        auth_session = requests.Session()
        auth_session.max_redirects = 0
        no_retry_adapter = requests.adapters.HTTPAdapter(max_retries=0)
        auth_session.mount("http://", no_retry_adapter)
        auth_session.mount("https://", no_retry_adapter)

        super().__init__(
            credentials,
            auth_request=Request(auth_session),
            refresh_timeout=self._backupsheep_timeout[1],
        )
        self.max_redirects = 0

        # AuthorizedSession inherits requests.Session.  Make the no-retry policy
        # explicit for all methods; task-level recovery and provider idempotency
        # witnesses handle retries outside this SDK client.
        self.mount("http://", requests.adapters.HTTPAdapter(max_retries=0))
        self.mount("https://", requests.adapters.HTTPAdapter(max_retries=0))

    def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        max_allowed_time=None,
        timeout=_GOOGLE_TIMEOUT_UNSET,
        **kwargs,
    ):
        if timeout is _GOOGLE_TIMEOUT_UNSET or timeout is None:
            timeout = self._backupsheep_timeout

        # AuthorizedSession's credential refresh can recursively replay a request.
        # Only allow that replay for methods that are safe to repeat.  The private
        # attempt marker is consumed by Google's implementation and is scoped to
        # this request; no global state is changed.
        if str(method).upper() not in _GOOGLE_REFRESH_SAFE_METHODS:
            kwargs["_credential_refresh_attempt"] = self._max_refresh_attempts

        return super().request(
            method,
            url,
            data=data,
            headers=headers,
            max_allowed_time=max_allowed_time,
            timeout=timeout,
            **kwargs,
        )


def _oci_client_kwargs():
    """Return bounded, no-automatic-retry kwargs for an OCI service client."""

    import oci

    return {
        "timeout": _provider_sdk_timeout(),
        "retry_strategy": oci.retry.NoneRetryStrategy(),
    }


def _configure_ssh_host_keys(ssh):
    """Backward-compatible wrapper around the shared strict SSH policy."""
    configure_host_keys(ssh)


class CoreIntegration(UtilBase):
    class Type(models.TextChoices):
        CLOUD = "cloud", "Cloud"
        SAAS = "saas", "SaaS"
        WEBSITE = "website", "Website"
        DATABASE = "database", "Database"

    code = models.CharField(max_length=64, unique=True)
    public_key = models.TextField(null=True)
    description = models.TextField(null=True)
    position = models.IntegerField(null=True)
    url = models.URLField(null=True)
    image = models.CharField(null=True, max_length=2048)
    enabled = models.BooleanField(default=True)
    type = models.CharField(
        max_length=64,
        choices=Type.choices,
        default=Type.CLOUD,
    )

    class Meta:
        db_table = "core_integration"


class CoreWasabiRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)

    class Meta:
        db_table = "core_wasabi_region"


class CoreDoSpacesRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)

    class Meta:
        db_table = "core_do_spaces_region"


class CoreFilebaseRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)

    class Meta:
        db_table = "core_filebase_region"


class CoreExoscaleRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)

    class Meta:
        db_table = "core_exoscale_region"


class CoreOracleRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)

    class Meta:
        db_table = "core_oracle_region"


class CoreScalewayRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)

    class Meta:
        db_table = "core_scaleway_region"


class CoreAWSRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)
    rds_endpoint = models.CharField(max_length=255, null=True)
    s3_endpoint = models.CharField(max_length=255, null=True)

    class Meta:
        db_table = "core_aws_region"


class CoreTencentRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)

    class Meta:
        db_table = "core_tencent_region"


class CoreAlibabaRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)

    class Meta:
        db_table = "core_alibab_region"


class CoreIonosRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)

    class Meta:
        db_table = "core_ionos_region"


class CoreRackCorpRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    class Meta:
        db_table = "core_rackcorp_region"

class CoreIBMRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    class Meta:
        db_table = "core_ibm_region"


class CoreLightsailRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)
    rds_endpoint = models.CharField(max_length=255, null=True)

    class Meta:
        db_table = "core_lightsail_region"


class CoreAuthDigitalOcean(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_digitalocean", on_delete=models.CASCADE)
    # all clear
    access_token = models.BinaryField(null=True)
    # all clear
    refresh_token = models.BinaryField(null=True)
    scope = models.CharField(max_length=32, null=True)
    token_type = models.CharField(max_length=32, null=True)
    expiry = models.DateTimeField(null=True)
    token_refresh_failed = models.BooleanField(default=False)
    info_name = models.CharField(max_length=64, null=True)
    info_email = models.CharField(max_length=64, null=True)
    info_uuid = models.CharField(max_length=255, null=True)
    # 2022 - This is new method. oAuth doesn't work well with teams setup
    api_key = models.BinaryField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_digitalocean"

    def refresh_auth_token(self):
        from datetime import datetime, timezone

        from ..node.models import CoreNode
        from apps.api.v1.connection.digitalocean.client import DigitalOceanAPIError
        from apps.api.v1.utils.oauth_security import validated_https_endpoint

        # Personal access-token connections do not use OAuth refresh tokens.
        if self.api_key:
            return True

        if not self.refresh_token:
            return False
        encryption_key = self.connection.account.get_encryption_key()
        refresh_token_decrypted = bs_decrypt(self.refresh_token, encryption_key)
        if not refresh_token_decrypted:
            return False

        token_url = validated_https_endpoint(
            settings.DIGITALOCEAN_TOKEN_URL,
            allowed_hostnames={"cloud.digitalocean.com"},
            allowed_paths={"/v1/oauth/token"},
        )
        if token_url is None:
            raise DigitalOceanAPIError("PROVIDER_REQUEST_FAILED")

        form = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token_decrypted,
        }
        if settings.DIGITALOCEAN_APP_CLIENT_ID:
            form["client_id"] = settings.DIGITALOCEAN_APP_CLIENT_ID
        if settings.DIGITALOCEAN_APP_CLIENT_SECRET:
            form["client_secret"] = settings.DIGITALOCEAN_APP_CLIENT_SECRET

        result = None
        try:
            result = requests.post(
                token_url,
                data=form,
                headers={"Accept": "application/json"},
                allow_redirects=False,
                verify=True,
                timeout=request_timeout(),
            )
            if result.status_code in {400, 401}:
                self.token_refresh_failed = True
                self.save(update_fields=["token_refresh_failed", "modified"])
                self.connection.status = CoreConnection.Status.TOKEN_REFRESH_FAIL
                self.connection.save(update_fields=["status", "modified"])
                return False
            if result.status_code == 429:
                raise DigitalOceanAPIError(
                    "PROVIDER_RATE_LIMIT", retryable=True, status_code=429
                )
            if result.status_code in {408, 425} or result.status_code >= 500:
                raise DigitalOceanAPIError(
                    "PROVIDER_TRANSIENT_OUTAGE",
                    retryable=True,
                    status_code=result.status_code,
                )
            if result.status_code != 200:
                raise DigitalOceanAPIError(
                    "PROVIDER_REQUEST_FAILED", status_code=result.status_code
                )
            try:
                do_tokens = result.json()
                access_token = str(do_tokens["access_token"])
                next_refresh_token = str(
                    do_tokens.get("refresh_token") or refresh_token_decrypted
                )
                expires_in = int(do_tokens["expires_in"])
            except (KeyError, TypeError, ValueError):
                raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE") from None
            if (
                not access_token
                or not next_refresh_token
                or expires_in <= 0
                or any(char in access_token for char in "\r\n")
                or any(char in next_refresh_token for char in "\r\n")
            ):
                raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")

            self.access_token = bs_encrypt(access_token, encryption_key)
            self.refresh_token = bs_encrypt(next_refresh_token, encryption_key)
            self.token_type = "Bearer"
            self.expiry = datetime.fromtimestamp(
                int(time.time()) + expires_in, tz=timezone.utc
            )
            self.token_refresh_failed = False
            self.save(
                update_fields=[
                    "access_token",
                    "refresh_token",
                    "token_type",
                    "expiry",
                    "token_refresh_failed",
                    "modified",
                ]
            )
        except requests.exceptions.Timeout as error:
            raise DigitalOceanAPIError(
                "PROVIDER_TIMEOUT", retryable=True
            ) from error
        except requests.exceptions.RequestException as error:
            raise DigitalOceanAPIError(
                "PROVIDER_TRANSIENT_OUTAGE", retryable=True
            ) from error
        finally:
            close = getattr(result, "close", None)
            if callable(close):
                close()

        # Re-read the account only through the pinned-identity path.  In
        # particular, a rotated token must never silently replace an existing
        # team witness when the provider account has changed.
        self.get_verified_client()
        self.connection.status = CoreConnection.Status.ACTIVE
        self.connection.save(update_fields=["status", "modified"])
        self.connection.nodes.filter(
            status=CoreNode.Status.PAUSED_MAX_RETRIES
        ).update(status=CoreNode.Status.ACTIVE)
        return True

    def get_client(self):
        from apps.api.v1.connection.digitalocean.client import DigitalOceanAPIError

        encryption_key = self.connection.account.get_encryption_key()

        if self.api_key:
            credential = bs_decrypt(self.api_key, encryption_key)
        # Legacy method. We switched to API Access Token in 2022
        else:
            if str(self.token_type or "Bearer").casefold() != "bearer":
                raise DigitalOceanAPIError("PROVIDER_AUTH_FAILED")
            if not self.access_token:
                raise DigitalOceanAPIError("PROVIDER_AUTH_FAILED")
            credential = bs_decrypt(self.access_token, encryption_key)
        credential = str(credential or "")
        if not credential or any(char in credential for char in "\r\n"):
            raise DigitalOceanAPIError("PROVIDER_AUTH_FAILED")
        return {
            "content-type": "application/json",
            "Authorization": f"Bearer {credential}",
        }

    @staticmethod
    def _account_identity(payload):
        """Return a validated, non-secret DigitalOcean account identity."""
        from apps.api.v1.connection.digitalocean.client import DigitalOceanAPIError

        if not isinstance(payload, dict):
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
        account = payload.get("account")
        if not isinstance(account, dict):
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
        status = account.get("status")
        if not isinstance(status, str):
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
        if status != "active":
            raise DigitalOceanAPIError("PROVIDER_AUTH_FAILED")

        raw_team = account.get("team")
        if raw_team is not None and not isinstance(raw_team, dict):
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
        team = raw_team or {}
        provider_uuid = team.get("uuid") or account.get("uuid")
        if not isinstance(provider_uuid, str) or not provider_uuid.strip():
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")

        for value in (
            team.get("name"),
            account.get("name"),
            account.get("email"),
        ):
            if value not in (None, "") and not isinstance(value, str):
                raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")

        return {
            "info_uuid": provider_uuid.strip(),
            "info_name": team.get("name") or account.get("name"),
            "info_email": account.get("email"),
        }

    def get_verified_client(self):
        """Return the local client only after verifying the pinned account.

        ``get_client`` intentionally remains a decryption-only operation.  This
        method is the explicit network boundary for workers and validation paths:
        it reads the current account, requires an active account, and adopts a
        missing legacy witness once.  A populated witness is immutable unless a
        credential replacement serializer has already completed a successful
        validation and written the new witness.
        """
        from django.db import transaction

        from apps.api.v1.connection.digitalocean.client import get_json

        headers = self.get_client()
        identity = self._account_identity(get_json("/v2/account", headers=headers))

        with transaction.atomic():
            current = type(self).objects.select_for_update().get(pk=self.pk)
            pinned_uuid = str(current.info_uuid or "").strip()
            if pinned_uuid and pinned_uuid != identity["info_uuid"]:
                from apps.api.v1.connection.digitalocean.client import DigitalOceanAPIError

                raise DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")

            changed = []
            if not pinned_uuid:
                current.info_uuid = identity["info_uuid"]
                changed.append("info_uuid")
            # These fields are descriptive only.  They may refresh after the
            # UUID has matched (or has been adopted for a legacy row), but an
            # incomplete provider response never erases a known value.
            for field in ("info_name", "info_email"):
                value = identity[field]
                if value not in (None, "") and getattr(current, field) != value:
                    setattr(current, field, value)
                    changed.append(field)
            if changed:
                current.save(update_fields=list(dict.fromkeys(changed + ["modified"])))

        return current.get_client()

    def get_eligible_objects(self, object_type="cloud"):
        from apps.api.v1.connection.digitalocean.client import (
            DigitalOceanAPIError,
            list_eligible_objects,
        )

        try:
            return list_eligible_objects(
                headers=self.get_verified_client(), object_type=object_type
            )
        except ValueError as error:
            raise APIException(detail=str(error)) from error
        except DigitalOceanAPIError as error:
            raise APIException(detail=str(error)) from error

    def validate(self, check_errors=None, raise_exp=None):
        self.get_verified_client()
        return True


class CoreAuthHetzner(TimeStampedModel):
    API_PAGE_SIZE = 50

    connection = models.OneToOneField("CoreConnection", related_name="auth_hetzner", on_delete=models.CASCADE)
    api_key = models.BinaryField(null=True)
    token_refresh_failed = models.BooleanField(default=False)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_hetzner"

    def get_client(self):
        encryption_key = self.connection.account.get_encryption_key()

        client = {
            "content-type": "application/json",
            "Authorization": f"Bearer {bs_decrypt(self.api_key, encryption_key)}",
        }
        return client

    def get_eligible_objects(self, object_type="cloud"):
        """List the Hetzner resources that BackupSheep can link as sources.

        Hetzner Cloud only offers native backups for a server's primary disk.
        Volumes are intentionally rejected instead of being presented as a
        backupable resource: the provider documents that it has no native volume
        backup/snapshot API and server snapshots do not include attached volumes.
        """
        object_type = object_type or "cloud"
        if object_type != "cloud":
            raise APIException(
                detail=(
                    "Hetzner Cloud native backups are available for server primary "
                    "disks only; attached volumes do not support provider snapshots."
                )
            )

        client = self.get_client()
        eligible_objects = []
        page = 1
        seen_pages = set()
        while True:
            if page in seen_pages or len(seen_pages) >= 1000:
                raise APIException(
                    detail="Hetzner returned invalid pagination metadata."
                )
            seen_pages.add(page)
            result = requests.get(
                settings.HETZNER_API + "/v1/servers",
                headers=client,
                params={"page": page, "per_page": self.API_PAGE_SIZE},
                verify=True,
                timeout=request_timeout(),
            )
            if result.status_code == 200:
                try:
                    payload = result.json()
                except Exception:
                    raise APIException(
                        detail="Hetzner returned an invalid resource response."
                    ) from None
                servers = payload.get("servers") if isinstance(payload, dict) else None
                pagination = (
                    (payload.get("meta") or {}).get("pagination")
                    if isinstance(payload, dict)
                    else None
                )
                if not isinstance(servers, list) or not isinstance(pagination, dict):
                    raise APIException(
                        detail="Hetzner returned an invalid resource response."
                    )
                for server in servers:
                    if not isinstance(server, dict):
                        raise APIException(
                            detail="Hetzner returned an invalid resource response."
                        )
                    server["_bs_unique_id"] = server.get("id", None)
                    server["_bs_name"] = server.get("name", None)
                    server["_bs_region"] = (
                        server.get("location", {}).get("description")
                        or server.get("location", {}).get("name")
                    )
                    server["_bs_size"] = server.get("primary_disk_size", None)
                    server["_bs_resource_type"] = "server"
                    eligible_objects.append(server)
            else:
                raise APIException(
                    detail=f"Hetzner API returned status {result.status_code}."
                )
            result.close()
            next_page = pagination.get("next_page")
            if not next_page:
                break
            if isinstance(next_page, bool):
                raise APIException(
                    detail="Hetzner returned invalid pagination metadata."
                )
            try:
                next_page = int(next_page)
            except (TypeError, ValueError):
                raise APIException(
                    detail="Hetzner returned invalid pagination metadata."
                ) from None
            if next_page <= page or next_page in seen_pages:
                raise APIException(
                    detail="Hetzner returned invalid pagination metadata."
                )
            page = next_page
        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        client = self.get_client()
        # The bare global GET /v1/actions list was removed (410 Gone) in Jan 2025;
        # hit a lightweight authenticated endpoint to confirm the token instead.
        result = requests.get(
            settings.HETZNER_API + "/v1/servers",
            headers=client,
            params={"per_page": 1},
            verify=True,
            timeout=request_timeout(),
        )
        if result.status_code == 200:
            return True
        else:
            return None


class CoreAuthUpCloud(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_upcloud", on_delete=models.CASCADE)
    username = models.BinaryField(null=True)
    password = models.BinaryField(null=True)
    api_token = models.BinaryField(null=True)
    token_refresh_failed = models.BooleanField(default=False)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_upcloud"

    @staticmethod
    def token_client(api_token):
        """Build a redacted requests auth object for UpCloud bearer tokens."""
        from requests.auth import AuthBase

        token = str(api_token or "").strip()
        if not token or any(character in token for character in "\r\n"):
            raise ValueError("The UpCloud API token is invalid.")

        class _UpCloudBearerAuth(AuthBase):
            __slots__ = ("_token",)

            def __init__(self, value):
                self._token = value

            def __call__(self, request):
                request.headers["Authorization"] = f"Bearer {self._token}"
                return request

            def __repr__(self):
                return "<UpCloudBearerAuth redacted>"

        return _UpCloudBearerAuth(token)

    def get_client(self):
        from requests.auth import HTTPBasicAuth

        encryption_key = self.connection.account.get_encryption_key()
        if self.api_token:
            return self.token_client(bs_decrypt(self.api_token, encryption_key))

        username = bs_decrypt(self.username, encryption_key) if self.username else ""
        password = bs_decrypt(self.password, encryption_key) if self.password else ""
        if not username or not password:
            raise ValueError("UpCloud credentials are not configured.")
        return HTTPBasicAuth(username, password)

    @staticmethod
    def _account_username(payload):
        """Return the validated UpCloud account username without provider text."""
        from apps.console.node.models import _BackupProviderError

        if not isinstance(payload, dict):
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        account = payload.get("account")
        if not isinstance(account, dict):
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        username = account.get("username")
        if (
            not isinstance(username, str)
            or not username.strip()
            or any(character in username for character in "\r\n")
        ):
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        return username.strip()

    def get_verified_client(self):
        """Return the local client only after verifying the pinned username."""
        from django.db import transaction

        from apps._tasks.integration.upcloud import _upcloud_json
        from apps.console.node.models import _BackupProviderError

        try:
            client = self.get_client()
        except Exception:
            raise _BackupProviderError("PROVIDER_AUTH_FAILED") from None

        response = None
        try:
            response = requests.get(
                settings.UPCLOUD_API + "/account",
                auth=client,
                verify=True,
                timeout=request_timeout(),
                headers={"accept": "application/json"},
                allow_redirects=False,
            )
            provider_username = self._account_username(_upcloud_json(response))
        except requests.exceptions.Timeout as error:
            raise _BackupProviderError(
                "PROVIDER_TIMEOUT", retryable=True
            ) from error
        except requests.exceptions.RequestException as error:
            raise _BackupProviderError(
                "PROVIDER_TRANSIENT_OUTAGE", retryable=True
            ) from error
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

        encryption_key = self.connection.account.get_encryption_key()
        with transaction.atomic():
            current = type(self).objects.select_for_update().get(pk=self.pk)
            stored_username = (
                bs_decrypt(current.username, encryption_key)
                if current.username
                else ""
            )
            stored_username = str(stored_username or "").strip()
            if stored_username and stored_username != provider_username:
                raise _BackupProviderError("PROVIDER_OWNERSHIP_MISMATCH")
            if not stored_username:
                current.username = bs_encrypt(provider_username, encryption_key)
                current.save(update_fields=["username", "modified"])

        return current.get_client()

    def get_eligible_objects(self, object_type="cloud"):
        """Return a complete, bounded UpCloud server or storage inventory."""
        object_type = object_type or "cloud"
        if object_type not in {"cloud", "volume"}:
            return []

        from apps._tasks.integration.upcloud import (
            _BackupProviderError,
            list_upcloud_servers,
            list_upcloud_storages,
        )

        try:
            resources = (
                list_upcloud_servers(self.get_verified_client())
                if object_type == "cloud"
                else list_upcloud_storages(
                    self.get_verified_client(), storage_type="normal"
                )
            )
        except _BackupProviderError as error:
            raise APIException(
                detail=f"UpCloud resource discovery failed ({error.code})."
            ) from None

        eligible_objects = []
        for resource in resources:
            item = dict(resource)
            item["_bs_unique_id"] = item.get("uuid")
            item["_bs_name"] = item.get("title")
            item["_bs_region"] = item.get("zone")
            item["_bs_size"] = (
                item.get("size")
                if object_type == "volume"
                else None
            )
            item["_bs_resource_type"] = object_type
            eligible_objects.append(item)
        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        self.get_verified_client()
        return True


class CoreAuthAWS(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_aws", on_delete=models.CASCADE)
    access_key = models.BinaryField(null=True)
    secret_key = models.BinaryField(null=True)
    region = models.ForeignKey(CoreAWSRegion, related_name="auth_aws", on_delete=models.PROTECT)
    # AWS Backup is used for resource types that do not have a simple snapshot
    # API (currently S3 and DynamoDB).  Keep these as connection-level settings
    # so every linked resource uses the same vault and least-privilege role.
    backup_vault_name = models.CharField(
        max_length=255,
        default="Default",
        validators=[
            RegexValidator(
                regex=r"^[A-Za-z0-9_-]{2,50}$",
                message="AWS Backup vault names must be 2-50 letters, numbers, hyphens, or underscores.",
            )
        ],
    )
    backup_role_arn = models.CharField(max_length=2048, blank=True, default="")
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_aws"

    def get_client(self, service_name="ec2"):
        encryption_key = self.connection.account.get_encryption_key()

        client = bounded_boto3_client(
            service_name,
            region_name=self.region.code,
            aws_access_key_id=bs_decrypt(self.access_key, encryption_key),
            aws_secret_access_key=bs_decrypt(self.secret_key, encryption_key),
        )
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client(
            "s3" if object_type == "s3" else
            "dynamodb" if object_type == "dynamodb" else "ec2"
        )
        if object_type == "cloud":
            reservations = client.describe_instances().get("Reservations")
            instances = [i for r in reservations for i in r["Instances"]]
            for aws_instance in instances:
                aws_instance["_bs_unique_id"] = aws_instance.get("InstanceId", None)
                aws_instance["_bs_name"] = aws_instance.get("KeyName", None)
                aws_instance["_bs_region"] = aws_instance.get("Placement", {}).get("AvailabilityZone", None)
                aws_instance["_bs_size"] = aws_instance.get("size_gigabytes", None)
                if not aws_instance["_bs_name"]:
                    aws_instance["_bs_name"] = aws_instance.get("InstanceId", None)
                aws_instance["_bs_resource_type"] = "instance"
                eligible_objects.append(aws_instance)
        elif object_type == "volume":
            volumes = client.describe_volumes().get("Volumes")
            for aws_volume in volumes:
                aws_volume["_bs_unique_id"] = aws_volume.get("VolumeId", None)
                aws_volume["_bs_name"] = aws_volume.get("VolumeId", None)
                aws_volume["_bs_region"] = aws_volume.get("AvailabilityZone", None)
                aws_volume["_bs_size"] = aws_volume.get("Size", None)
                aws_volume["_bs_resource_type"] = "volume"
                eligible_objects.append(aws_volume)
        elif object_type == "s3":
            s3 = client
            buckets = s3.list_buckets().get("Buckets") or []
            for bucket in buckets:
                bucket_name = bucket.get("Name")
                if not bucket_name:
                    continue
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name).get(
                        "LocationConstraint"
                    )
                    # AWS returns null for us-east-1 and the legacy EU token for
                    # eu-west-1. Normalize both to the SDK region spelling.
                    region = "us-east-1" if not location else location
                    if region == "EU":
                        region = "eu-west-1"
                except Exception:
                    # A bucket in another account or with a restrictive policy
                    # should not prevent the remaining catalog from loading.
                    continue
                if region != self.region.code:
                    continue
                bucket["_bs_unique_id"] = bucket_name
                bucket["_bs_name"] = bucket_name
                bucket["_bs_region"] = region
                bucket["_bs_size"] = None
                bucket["_bs_resource_type"] = "s3"
                eligible_objects.append(bucket)
        elif object_type == "dynamodb":
            dynamodb = client
            paginator = dynamodb.get_paginator("list_tables")
            for page in paginator.paginate():
                for table_name in page.get("TableNames") or []:
                    try:
                        table = dynamodb.describe_table(TableName=table_name).get(
                            "Table"
                        ) or {}
                    except Exception:
                        continue
                    table["_bs_unique_id"] = table_name
                    table["_bs_name"] = table_name
                    table["_bs_region"] = self.region.code
                    table["_bs_size"] = (
                        (table.get("TableSizeBytes") or 0) / 1000**3
                    )
                    table["_bs_resource_type"] = "dynamodb"
                    eligible_objects.append(table)
        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            # Validate the credentials themselves, not a single optional
            # service. An AWS connection may be used only for S3/DynamoDB and
            # therefore legitimately lack EC2 list permission; each selected
            # resource is validated by CoreAWS.validate.
            self.get_client("sts").get_caller_identity()
            return True
        except ClientError as e:
            return False
        except Exception as e:
            return False


class CoreAuthLightsail(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_lightsail", on_delete=models.CASCADE)
    info_name = models.CharField(max_length=64, null=True)
    access_key = models.BinaryField(null=True)
    secret_key = models.BinaryField(null=True)
    region = models.ForeignKey(CoreLightsailRegion, related_name="auth_lightsail", on_delete=models.PROTECT)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_lightsail"

    def get_client(self):
        encryption_key = self.connection.account.get_encryption_key()

        client = bounded_boto3_client(
            "lightsail",
            region_name=self.region.code,
            aws_access_key_id=bs_decrypt(self.access_key, encryption_key),
            aws_secret_access_key=bs_decrypt(self.secret_key, encryption_key),
        )
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        if object_type == "cloud":
            more_objects = True
            next_page_token = ''

            while more_objects is True:
                response = client.get_instances(pageToken=next_page_token)

                for instance in response["instances"]:
                    instance["_bs_unique_id"] = instance.get("name", None)
                    instance["_bs_name"] = instance.get("name", None)
                    instance["_bs_region"] = instance.get("location", {}).get("regionName", {})
                    instance["_bs_size"] = instance.get("hardware", {}).get("disks", [])[0].get("sizeInGb")
                    eligible_objects.append(instance)

                next_page_token = response.get("nextPageToken")

                if not next_page_token:
                    more_objects = False

        elif object_type == "volume":
            more_objects = True
            next_page_token = ''

            while more_objects is True:
                response = client.get_disks(pageToken=next_page_token)

                for disk in response["disks"]:
                    disk["_bs_unique_id"] = disk.get("name", None)
                    disk["_bs_name"] = disk.get("name", None)
                    disk["_bs_region"] = disk.get("location", {}).get("regionName", {})
                    disk["_bs_size"] = disk.get("sizeInGb", None)
                    eligible_objects.append(disk)

                next_page_token = response.get("nextPageToken")

                if not next_page_token:
                    more_objects = False

        elif object_type in {"database", "relational_database"}:
            next_page_token = None

            while True:
                request = {"pageToken": next_page_token} if next_page_token else {}
                response = client.get_relational_databases(**request)
                response = response if isinstance(response, dict) else {}

                for database in response.get("relationalDatabases") or []:
                    if not isinstance(database, dict):
                        continue
                    database["_bs_unique_id"] = database.get("name")
                    database["_bs_name"] = database.get("name")
                    database["_bs_region"] = (database.get("location") or {}).get(
                        "regionName"
                    )
                    database["_bs_size"] = (database.get("hardware") or {}).get(
                        "diskSizeInGb"
                    )
                    eligible_objects.append(database)

                next_page_token = response.get("nextPageToken")
                if not next_page_token:
                    break

        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            client = self.get_client()
            client.get_instances()
            return True
        except ClientError as e:
            return False
        except Exception as e:
            return False


class CoreAuthAWSRDS(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_aws_rds", on_delete=models.CASCADE)
    access_key = models.BinaryField()
    info_name = models.CharField(max_length=64, null=True)
    secret_key = models.BinaryField()
    region = models.ForeignKey(CoreAWSRegion, related_name="auth_aws_rds", on_delete=models.PROTECT)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_aws_rds"

    def get_client(self):
        encryption_key = self.connection.account.get_encryption_key()

        client = bounded_boto3_client(
            "rds",
            region_name=self.region.code,
            aws_access_key_id=bs_decrypt(self.access_key, encryption_key),
            aws_secret_access_key=bs_decrypt(self.secret_key, encryption_key),
        )
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        instances = client.describe_db_instances()
        for rds_instance in instances.get("DBInstances"):
            rds_instance["_bs_unique_id"] = rds_instance.get("DBInstanceIdentifier", None)
            rds_instance["_bs_name"] = rds_instance.get("DBInstanceIdentifier", None)
            rds_instance["_bs_region"] = rds_instance.get("AvailabilityZone", None)
            rds_instance["_bs_size"] = rds_instance.get("AllocatedStorage", None)
            eligible_objects.append(rds_instance)
        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            client = self.get_client()
            client.describe_db_instances()
            return True
        except ClientError as e:
            return False
        except Exception as e:
            return False


def _ovh_region_name(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        value = value.get("name") or value.get("region") or value.get("id")
        if value:
            return str(value)
    return None


def _ovh_project_regions(client, project_id):
    regions = client.get(f"/cloud/project/{project_id}/region")
    return [
        region
        for region in (_ovh_region_name(item) for item in regions)
        if region
    ] if isinstance(regions, list) else []


class CoreAuthOVHCA(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_ovh_ca", on_delete=models.CASCADE)
    consumer_key = models.BinaryField(null=True)
    info_customer_code = models.CharField(max_length=1024, null=True)
    info_name = models.CharField(max_length=1024, null=True)
    info_email = models.CharField(max_length=255, null=True)
    info_organization = models.CharField(max_length=1024, null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_ovh_ca"

    def get_client(self):
        from apps.api.v1.connection.ovh_oauth import build_ovh_client

        encryption_key = self.connection.account.get_encryption_key()
        return build_ovh_client(
            "ovh_ca",
            consumer_key=bs_decrypt(self.consumer_key, encryption_key),
        )

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        projects = client.get("/cloud/project")

        if object_type == "cloud":
            for project in projects:
                project_details = client.get(f"/cloud/project/{project}")
                for region in _ovh_project_regions(client, project):
                    servers = client.get(
                        f"/cloud/project/{project}/region/{region}/instance"
                    )
                    for cloud_server in servers:
                        cloud_server["project"] = project_details
                        cloud_server["_bs_unique_id"] = cloud_server.get("id", None)
                        cloud_server["_bs_name"] = cloud_server.get("name", None)
                        cloud_server["_bs_region"] = cloud_server.get("region") or region
                        cloud_server["_bs_size"] = cloud_server.get("size", None)
                        eligible_objects.append(cloud_server)
            return eligible_objects
        elif object_type == "volume":
            for project in projects:
                project_details = client.get(f"/cloud/project/{project}")
                for region in _ovh_project_regions(client, project):
                    volumes = client.get(
                        f"/cloud/project/{project}/region/{region}/volume"
                    )
                    for cloud_volume in volumes:
                        cloud_volume["project"] = project_details
                        cloud_volume["_bs_unique_id"] = cloud_volume.get("id", None)
                        cloud_volume["_bs_name"] = cloud_volume.get("name", None)
                        cloud_volume["_bs_region"] = cloud_volume.get("region") or region
                        cloud_volume["_bs_size"] = cloud_volume.get("size", None)
                        eligible_objects.append(cloud_volume)
            return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            client = self.get_client()
            client.get("/cloud/project")
            return True
        except Exception as e:
            return False


class CoreAuthOVHEU(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_ovh_eu", on_delete=models.CASCADE)
    consumer_key = models.BinaryField(null=True)
    info_customer_code = models.CharField(max_length=1024, null=True)
    info_name = models.CharField(max_length=1024, null=True)
    info_email = models.CharField(max_length=255, null=True)
    info_organization = models.CharField(max_length=1024, null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_ovh_eu"

    def get_client(self):
        from apps.api.v1.connection.ovh_oauth import build_ovh_client

        encryption_key = self.connection.account.get_encryption_key()
        return build_ovh_client(
            "ovh_eu",
            consumer_key=bs_decrypt(self.consumer_key, encryption_key),
        )

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        projects = client.get("/cloud/project")

        if object_type == "cloud":
            for project in projects:
                project_details = client.get(f"/cloud/project/{project}")
                for region in _ovh_project_regions(client, project):
                    servers = client.get(
                        f"/cloud/project/{project}/region/{region}/instance"
                    )
                    for cloud_server in servers:
                        cloud_server["project"] = project_details
                        cloud_server["_bs_unique_id"] = cloud_server.get("id", None)
                        cloud_server["_bs_name"] = cloud_server.get("name", None)
                        cloud_server["_bs_region"] = cloud_server.get("region") or region
                        cloud_server["_bs_size"] = cloud_server.get("size", None)
                        eligible_objects.append(cloud_server)
            return eligible_objects
        elif object_type == "volume":
            for project in projects:
                project_details = client.get(f"/cloud/project/{project}")
                for region in _ovh_project_regions(client, project):
                    volumes = client.get(
                        f"/cloud/project/{project}/region/{region}/volume"
                    )
                    for cloud_volume in volumes:
                        cloud_volume["project"] = project_details
                        cloud_volume["_bs_unique_id"] = cloud_volume.get("id", None)
                        cloud_volume["_bs_name"] = cloud_volume.get("name", None)
                        cloud_volume["_bs_region"] = cloud_volume.get("region") or region
                        cloud_volume["_bs_size"] = cloud_volume.get("size", None)
                        eligible_objects.append(cloud_volume)
            return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            client = self.get_client()
            client.get("/cloud/project")
            return True
        except Exception as e:
            return False


class CoreAuthOVHUS(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_ovh_us", on_delete=models.CASCADE)
    consumer_key = models.BinaryField(null=True)
    info_customer_code = models.CharField(max_length=1024, null=True)
    info_name = models.CharField(max_length=1024, null=True)
    info_email = models.CharField(max_length=255, null=True)
    info_organization = models.CharField(max_length=1024, null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_ovh_us"

    def get_client(self):
        from apps.api.v1.connection.ovh_oauth import build_ovh_client

        encryption_key = self.connection.account.get_encryption_key()
        return build_ovh_client(
            "ovh_us",
            consumer_key=bs_decrypt(self.consumer_key, encryption_key),
        )

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        projects = client.get("/cloud/project")

        if object_type == "cloud":
            for project in projects:
                project_details = client.get(f"/cloud/project/{project}")
                for region in _ovh_project_regions(client, project):
                    servers = client.get(
                        f"/cloud/project/{project}/region/{region}/instance"
                    )
                    for cloud_server in servers:
                        cloud_server["project"] = project_details
                        cloud_server["_bs_unique_id"] = cloud_server.get("id", None)
                        cloud_server["_bs_name"] = cloud_server.get("name", None)
                        cloud_server["_bs_region"] = cloud_server.get("region") or region
                        cloud_server["_bs_size"] = cloud_server.get("size", None)
                        eligible_objects.append(cloud_server)
            return eligible_objects
        elif object_type == "volume":
            for project in projects:
                project_details = client.get(f"/cloud/project/{project}")
                for region in _ovh_project_regions(client, project):
                    volumes = client.get(
                        f"/cloud/project/{project}/region/{region}/volume"
                    )
                    for cloud_volume in volumes:
                        cloud_volume["project"] = project_details
                        cloud_volume["_bs_unique_id"] = cloud_volume.get("id", None)
                        cloud_volume["_bs_name"] = cloud_volume.get("name", None)
                        cloud_volume["_bs_region"] = cloud_volume.get("region") or region
                        cloud_volume["_bs_size"] = cloud_volume.get("size", None)
                        eligible_objects.append(cloud_volume)
            return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            client = self.get_client()
            client.get("/cloud/project")
            return True
        except Exception as e:
            return False


class CoreAuthVultr(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_vultr", on_delete=models.CASCADE)
    api_key = models.BinaryField(null=True)
    info_name = models.CharField(max_length=64, null=True)
    info_email = models.CharField(max_length=64, null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_vultr"

    def get_client(self):
        encryption_key = self.connection.account.get_encryption_key()

        client = {
            "Authorization": f"Bearer {bs_decrypt(self.api_key, encryption_key)}",
        }
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()

        if object_type in {"database", "managed_database", "vultr_database"}:
            from apps.console.vultr_database import VultrManagedDatabaseClient

            return VultrManagedDatabaseClient(self).discover_databases()

        regions = list(iter_vultr_collection(
            requests.get,
            f"{settings.VULTR_API}/v2/regions",
            headers=client,
            item_key="regions",
        ))
        region_by_id = {region.get("id"): region for region in regions}

        if object_type == "cloud":
            instances = iter_vultr_collection(
                requests.get,
                f"{settings.VULTR_API}/v2/instances",
                headers=client,
                item_key="instances",
            )
            for instance in instances:
                instance["_bs_unique_id"] = instance.get("id")
                # `tag` is deprecated in favor of the `tags` list; prefer the first tag when present.
                tags = instance.get("tags") or []
                instance_tag = tags[0] if tags else instance.get("tag")
                if instance.get("hostname") == "vultr.guest" and instance_tag:
                    instance["_bs_name"] = f"{instance_tag}"
                else:
                    instance["_bs_name"] = f"{instance.get('hostname')}"
                region = region_by_id.get(instance.get("region"))
                if not region:
                    raise ValueError("Vultr instance referenced an unknown region.")
                instance["_bs_region"] = f"{region['city']}, {region['country']}"
                instance["_bs_size"] = instance.get("disk")
                eligible_objects.append(instance)
        elif object_type == "volume":
            blocks = iter_vultr_collection(
                requests.get,
                f"{settings.VULTR_API}/v2/blocks",
                headers=client,
                item_key="blocks",
            )
            for block in blocks:
                block["_bs_unique_id"] = block.get("id")
                block["_bs_name"] = block.get("label")
                region = region_by_id.get(block.get("region"))
                if not region:
                    raise ValueError("Vultr block referenced an unknown region.")
                block["_bs_region"] = f"{region['city']}, {region['country']}"
                block["_bs_size"] = block.get("size_gb")
                eligible_objects.append(block)
        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        client = self.get_client()
        result = requests.get(
            f"{settings.VULTR_API}/v2/account",
            headers=client,
            timeout=vultr_request_timeout(),
        )
        if result.status_code == 200:
            return True
        else:
            return None


class CoreAuthOracle(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_oracle", on_delete=models.CASCADE)
    user = models.CharField(max_length=255)
    fingerprint = models.CharField(max_length=255)
    tenancy = models.CharField(max_length=255)
    region = models.CharField(max_length=255)
    private_key = models.BinaryField()
    profile = models.CharField(max_length=255)

    class Meta:
        db_table = "core_auth_oracle"

    def get_client(self, data=None):
        from oci.config import validate_config

        if data:
            user = data["user"]
            fingerprint = data["fingerprint"]
            tenancy = data["tenancy"]
            region = data["region"]
            private_key = data["private_key"]
        else:
            user = self.user
            fingerprint = self.fingerprint
            tenancy = self.tenancy
            region = self.region
            encryption_key = self.connection.account.get_encryption_key()
            private_key = bs_decrypt(self.private_key, encryption_key)

        # key_content passes the private key inline so no temp key file is written to disk.
        config = {
            "user": user,
            "key_content": private_key,
            "fingerprint": fingerprint,
            "tenancy": tenancy,
            "region": region,
        }
        validate_config(config)
        # identity = oci.identity.IdentityClient(config)
        return config

    def get_verified_client(self, data=None):
        """Return an OCI config only after pinning its tenancy identity.

        The configured tenancy OCID is the durable identity witness for legacy
        Oracle rows.  A first use safely adopts that existing value only after
        ``get_tenancy`` returns the exact same OCID; every later use performs
        the same read-back, so credentials cannot silently drift to another
        tenancy.  No provider response body or credential is persisted.
        """
        import oci

        from apps._tasks.integration.oracle import (
            OracleProviderError,
            classify_oracle_error,
        )

        try:
            config = self.get_client(data=data)
            identity = oci.identity.IdentityClient(
                config, **_oci_client_kwargs()
            )
            response = identity.get_tenancy(config["tenancy"])
            status = getattr(response, "status", None)
            if status != 200:
                synthetic = type(
                    "OracleIdentityResponseError",
                    (),
                    {
                        "status": status,
                        "code": "",
                        "headers": getattr(response, "headers", {}) or {},
                    },
                )()
                raise classify_oracle_error(synthetic)

            payload = getattr(response, "data", None)
            if isinstance(payload, dict):
                observed_id = payload.get("id")
                lifecycle_state = payload.get("lifecycle_state")
            else:
                observed_id = getattr(payload, "id", None)
                lifecycle_state = getattr(payload, "lifecycle_state", None)
            expected_id = str(config.get("tenancy") or "").strip()
            if not expected_id or str(observed_id or "").strip() != expected_id:
                raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
            if lifecycle_state not in (None, "") and str(
                lifecycle_state
            ).upper() != "ACTIVE":
                raise OracleProviderError("PROVIDER_AUTH_FAILED")
            return config
        except OracleProviderError:
            raise
        except Exception as error:
            raise classify_oracle_error(error) from error

    def get_eligible_objects(self, object_type="cloud"):
        import oci
        from oci.identity.models import Compartment

        eligible_objects = []
        per_page = 1000
        config = self.get_verified_client()

        if object_type == "cloud":
            pass
        elif object_type == "volume":
            block_storage_client = oci.core.BlockstorageClient(
                config, **_oci_client_kwargs()
            )
            identity_client = oci.identity.IdentityClient(
                config, **_oci_client_kwargs()
            )

            """
            Volumes can live in child compartments, so list the volumes of the
            tenancy root plus every accessible compartment beneath it.
            """
            compartment_ids = [self.tenancy]
            compartments = identity_client.list_compartments(self.tenancy, compartment_id_in_subtree=True)
            if compartments.status == 200:
                for compartment in compartments.data:
                    if compartment.lifecycle_state == Compartment.LIFECYCLE_STATE_ACTIVE:
                        compartment_ids.append(compartment.id)

            for compartment_id in compartment_ids:
                """
                Get Boot Volumes
                """
                boot_volumes = oci.pagination.list_call_get_all_results(
                    block_storage_client.list_boot_volumes, limit=per_page, compartment_id=compartment_id
                )

                if boot_volumes.status == 200:
                    for boot_volume in boot_volumes.data:
                        eligible_object = {
                            "id": boot_volume.id,
                            "_bs_unique_id": boot_volume.id,
                            "_bs_name": boot_volume.display_name,
                            "_bs_region": boot_volume.availability_domain,
                            "_bs_size": boot_volume.size_in_gbs,
                            "_bs_vol_type": "boot",
                        }
                        eligible_objects.append(eligible_object)

                """
                Get Block Volumes
                """
                volumes = oci.pagination.list_call_get_all_results(
                    block_storage_client.list_volumes, limit=per_page, compartment_id=compartment_id
                )

                if volumes.status == 200:
                    for volume in volumes.data:
                        eligible_object = {
                            "id": volume.id,
                            "_bs_unique_id": volume.id,
                            "_bs_name": volume.display_name,
                            "_bs_region": volume.availability_domain,
                            "_bs_size": volume.size_in_gbs,
                            "_bs_vol_type": "block",
                        }
                        eligible_objects.append(eligible_object)
                else:
                    raise ValueError(f"Unable to get list of volumes. Received status code {volumes.status} from API.")
        return eligible_objects

    def validate(self, data=None, check_errors=None, raise_exp=None):
        import oci

        if data:
            user = data["user"]
        else:
            user = self.user
        try:
            config = self.get_verified_client(data=data)
            identity = oci.identity.IdentityClient(
                config, **_oci_client_kwargs()
            )
            response = identity.get_user(config["user"])
            if getattr(response, "status", None) != 200:
                return False
            oracle_user = response.data
            observed_id = (
                oracle_user.get("id")
                if isinstance(oracle_user, dict)
                else getattr(oracle_user, "id", None)
            )
            return str(observed_id or "") == str(user or "")
        except Exception as e:
            if check_errors:
                raise ValueError(f"Validation failed. Please check your integration details. Error: {e.__str__()}")
            else:
                return False


class CoreAuthGoogleCloud(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_google_cloud", on_delete=models.CASCADE)
    service_key = models.BinaryField()
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_google_cloud"

    def get_client(self, data=None):
        if data:
            service_key_json = json.loads(data["service_key"])
        else:
            encryption_key = self.connection.account.get_encryption_key()
            service_key_json = json.loads(bs_decrypt(self.service_key, encryption_key))

        credentials = service_account.Credentials.from_service_account_info(service_key_json)
        scoped_credentials = credentials.with_scopes(["https://www.googleapis.com/auth/cloud-platform"])
        client = _BoundedGoogleAuthorizedSession(scoped_credentials)
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        active_projects = []
        client = self.get_client()
        params = {"maxResults": 500}

        if object_type == "cloud":
            projects = []
            page_token = None
            while True:
                project_params = {"pageSize": 100}
                if page_token:
                    project_params["pageToken"] = page_token
                result = client.get(f"{settings.GOOGLE_RESOURCE_API}/v3/projects:search", params=project_params)
                if result.status_code != 200:
                    break
                projects.extend(result.json().get("projects", []))
                page_token = result.json().get("nextPageToken")
                if not page_token:
                    break
            if result.status_code == 200:
                # Check for active projects
                for project in projects:
                    if project["state"] == "ACTIVE":
                        active_projects.append(project)

                if len(active_projects) > 0:
                    for active_project in active_projects:
                        zones = []
                        page_token = None
                        while True:
                            zone_params = dict(params)
                            if page_token:
                                zone_params["pageToken"] = page_token
                            result = client.get(
                                f"{settings.GOOGLE_COMPUTE_API}/compute/v1/projects/{active_project['projectId']}/zones",
                                params=zone_params,
                            )
                            if result.status_code != 200:
                                break
                            zones.extend(result.json().get("items", []))
                            page_token = result.json().get("nextPageToken")
                            if not page_token:
                                break
                        if result.status_code == 200:
                            for zone in zones:
                                instances = []
                                page_token = None
                                while True:
                                    instance_params = dict(params)
                                    if page_token:
                                        instance_params["pageToken"] = page_token
                                    result = client.get(
                                        f"{settings.GOOGLE_COMPUTE_API}/compute/v1/projects/{active_project['projectId']}/zones/{zone['name']}/instances",
                                        params=instance_params,
                                    )
                                    if result.status_code != 200:
                                        break
                                    instances.extend(result.json().get("items", []))
                                    page_token = result.json().get("nextPageToken")
                                    if not page_token:
                                        break
                                if result.status_code == 200:
                                    for instance in instances:
                                        instance["_bs_unique_id"] = instance.get("id", None)
                                        instance["_bs_name"] = f"{instance.get('name', None)}"
                                        instance["_bs_region"] = zone["name"]
                                        instance["_bs_size"] = (instance.get("disks") or [{}])[0].get("diskSizeGb")
                                        instance["_bs_project_id"] = active_project["projectId"]
                                        instance["_bs_zone"] = zone["name"]
                                        eligible_objects.append(instance)

                                result.close()
                        else:
                            if result.json().get("error"):
                                error = result.json().get("error")
                                # permission_error = all([char in error["message"].lower() for char in ["required", "permission", "for"]])
                                # if not permission_error:
                                raise ValueError(error["message"])
                            else:
                                raise ValueError(
                                    f"Unable to get list of instances. Received status code {result.status_code} from API."
                                )
            else:
                if result.json().get("error"):
                    error = result.json().get("error")
                    raise ValueError(error["message"])
                else:
                    raise ValueError(
                        f"Unable to get list of instances. Received status code {result.status_code} from API."
                    )
        elif object_type == "volume":
            projects = []
            page_token = None
            while True:
                project_params = {"pageSize": 100}
                if page_token:
                    project_params["pageToken"] = page_token
                result = client.get(f"{settings.GOOGLE_RESOURCE_API}/v3/projects:search", params=project_params)
                if result.status_code != 200:
                    break
                projects.extend(result.json().get("projects", []))
                page_token = result.json().get("nextPageToken")
                if not page_token:
                    break
            if result.status_code == 200:
                # Check for active projects
                for project in projects:
                    if project["state"] == "ACTIVE":
                        active_projects.append(project)

                if len(active_projects) > 0:
                    for active_project in active_projects:
                        zones = []
                        page_token = None
                        while True:
                            zone_params = dict(params)
                            if page_token:
                                zone_params["pageToken"] = page_token
                            result = client.get(
                                f"{settings.GOOGLE_COMPUTE_API}/compute/v1/projects/{active_project['projectId']}/zones",
                                params=zone_params,
                            )
                            if result.status_code != 200:
                                break
                            zones.extend(result.json().get("items", []))
                            page_token = result.json().get("nextPageToken")
                            if not page_token:
                                break
                        if result.status_code == 200:
                            for zone in zones:
                                disks = []
                                page_token = None
                                while True:
                                    disk_params = dict(params)
                                    if page_token:
                                        disk_params["pageToken"] = page_token
                                    result = client.get(
                                        f"{settings.GOOGLE_COMPUTE_API}/compute/v1/projects/{active_project['projectId']}/zones/{zone['name']}/disks",
                                        params=disk_params,
                                    )
                                    if result.status_code != 200:
                                        break
                                    disks.extend(result.json().get("items", []))
                                    page_token = result.json().get("nextPageToken")
                                    if not page_token:
                                        break
                                if result.status_code == 200:
                                    for disk in disks:
                                        disk["_bs_unique_id"] = disk.get("id", None)
                                        disk["_bs_name"] = f"{disk.get('name', None)}"
                                        disk["_bs_region"] = zone["name"]
                                        disk["_bs_size"] = disk["sizeGb"]
                                        disk["_bs_project_id"] = active_project["projectId"]
                                        disk["_bs_zone"] = zone["name"]
                                        eligible_objects.append(disk)

                                result.close()
                        else:
                            if result.json().get("error"):
                                error = result.json().get("error")
                                # permission_error = all([char in error["message"].lower() for char in ["required", "permission", "for"]])
                                # if not permission_error:
                                raise ValueError(error["message"])
                            else:
                                raise ValueError(
                                    f"Unable to get list of instances. Received status code {result.status_code} from API."
                                )
            else:
                if result.json().get("error"):
                    error = result.json().get("error")
                    raise ValueError(error["message"])
                else:
                    raise ValueError(
                        f"Unable to get list of instances. Received status code {result.status_code} from API."
                    )
        return eligible_objects

    def validate(self, data=None, check_errors=None, raise_exp=None):
        try:
            client = self.get_client(data=data)
            result = client.get(f"{settings.GOOGLE_RESOURCE_API}/v3/projects:search", params={"pageSize": 100})
            if result.status_code == 200:
                return True
        except Exception as e:
            if check_errors:
                raise ValueError(f"Validation failed. Please check your integration details. Error: {e.__str__()}")
            else:
                return False
        # url = f"https://openidconnect.googleapis.com/v1/userinfo"
        #
        # profile_request = requests.get(url, headers=self.get_client())
        #
        # return profile_request.status_code == 200


class CoreAuthWebsite(TimeStampedModel):
    class Protocol(models.IntegerChoices):
        FTP = 1, "FTP"
        SFTP = 2, "SFTP"
        FTPS = 3, "FTPS"

    connection = models.OneToOneField("CoreConnection", related_name="auth_website", on_delete=models.CASCADE)
    host = models.CharField(max_length=255)
    port = models.IntegerField()
    use_private_key = models.BooleanField(null=True)
    # all cleaned
    private_key = models.BinaryField(null=True)
    # all clear
    username = models.BinaryField(null=True)
    # all clear
    password = models.BinaryField(null=True)
    protocol = models.IntegerField(choices=Protocol.choices, null=True)
    info_name = models.CharField(max_length=64, null=True)
    use_public_key = models.BooleanField(null=True)
    ftps_use_explicit_ssl = models.BooleanField(null=True)
    # Verify the server's TLS certificate for FTPS (default on). Turn off for hosts with
    # self-signed/mismatched certs.
    verify_ssl = models.BooleanField(default=True)
    encryption_updated = models.BooleanField(default=False)
    # https://xtresoft.atlassian.net/browse/BS-12
    flag_use_sha1_key_verification = models.BooleanField(default=False, null=True)

    class Meta:
        db_table = "core_auth_website"

    def check_connection(self, data=None, check_errors=None):
        import ftputil
        from apps.api.v1.utils.api_helpers import (
            bs_decrypt,
            FtpSession,
            ftp_tls_session_factory,
        )
        import paramiko
        import tempfile
        import os

        raw_protocol = data.get("protocol") if data else self.protocol
        try:
            protocol = self.Protocol(int(raw_protocol))
        except (TypeError, ValueError):
            raise NodeConnectionErrorWebsite(
                "The website transfer protocol is missing or unsupported."
            ) from None
        if (
            protocol == self.Protocol.FTP
            and not settings.ALLOW_INSECURE_FTP
        ):
            raise NodeConnectionErrorWebsite(
                "Plain FTP is disabled because it exposes credentials and backup "
                "data in transit. Use SFTP or FTPS, or explicitly set "
                "ALLOW_INSECURE_FTP=true after accepting that risk."
            )

        if data:
            username = data.get("username")
            password = data.get("password")
            port = data.get("port")
            host = data.get("host")
            verify_ssl = data.get("verify_ssl") is not False
            ftps_use_explicit_ssl = bool(data.get("ftps_use_explicit_ssl"))
        else:
            encryption_key = self.connection.account.get_encryption_key()
            username = bs_decrypt(self.username, encryption_key)
            password = bs_decrypt(self.password, encryption_key)
            port = self.port
            host = self.host
            verify_ssl = self.verify_ssl is not False
            ftps_use_explicit_ssl = bool(self.ftps_use_explicit_ssl)

        if protocol == self.Protocol.FTP:
            try:
                path = None
                with ftputil.FTPHost(
                    host,
                    username,
                    password,
                    port=port,
                    session_factory=FtpSession,
                ) as hosting_host:

                    hosting_host.listdir(path or ".")
                    hosting_host.close()
            except Exception as e:
                raise NodeConnectionErrorWebsite(e.__str__())
        elif protocol == self.Protocol.FTPS:
            try:
                path = None

                with ftputil.FTPHost(
                    host,
                    username,
                    password,
                    port=port,
                    session_factory=ftp_tls_session_factory(
                        verify_ssl=verify_ssl,
                        explicit=ftps_use_explicit_ssl,
                    ),
                ) as hosting_host:
                    hosting_host.listdir(path or ".")
                    hosting_host.close()
            except Exception as e:
                raise NodeConnectionErrorWebsite(e.__str__())
        elif protocol == self.Protocol.SFTP:
            try:
                # All we want is to check if connection can be made.
                sftp, ssh, ssh_key_path = self.get_sftp_client(data)

                # Now close connections and remove key file.
                sftp.close()
                ssh.close()
                if ssh_key_path:
                    os.remove(ssh_key_path)
            except ClassifiedConnectionError:
                raise
            except Exception as e:
                raise NodeConnectionErrorWebsite(e.__str__())

    def get_sftp_client(self, data=None):
        if data:
            username = data.get("username")
            password = data.get("password")
            private_key = data.get("private_key")
            port = data.get("port")
            host = data.get("host")
            use_public_key = data.get("use_public_key")
            use_private_key = data.get("use_private_key")
            flag_use_sha1_key_verification = data.get("flag_use_sha1_key_verification")
        else:
            encryption_key = self.connection.account.get_encryption_key()
            username = bs_decrypt(self.username, encryption_key)
            password = bs_decrypt(self.password, encryption_key)
            private_key = bs_decrypt(self.private_key, encryption_key)
            port = self.port
            host = self.host
            use_public_key = self.use_public_key
            use_private_key = self.use_private_key
            flag_use_sha1_key_verification = self.flag_use_sha1_key_verification

        ssh, ssh_key_path = open_ssh_client(
            host=host,
            port=port,
            username=username,
            password=password if not (use_public_key or use_private_key) else None,
            private_key=private_key if use_private_key else None,
            private_key_passphrase=password if use_private_key else None,
            use_managed_key=bool(use_public_key),
            allow_legacy_rsa=bool(flag_use_sha1_key_verification),
        )
        try:
            sftp = ssh.open_sftp()
        except Exception as error:
            ssh.close()
            cleanup_temporary_key(ssh_key_path)
            raise classified_connection_error(error, stage="sftp") from error
        return sftp, ssh, ssh_key_path

    def get_eligible_objects(self, path=None):
        if not path:
            path = "."

        eligible_objects = []
        self.check_connection()
        try:
            import os
            import ftputil
            from apps.api.v1.utils.api_helpers import (
                bs_decrypt,
                FtpSession,
                ftp_tls_session_factory,
                isFile,
                isdir,
            )

            encryption_key = self.connection.account.get_encryption_key()

            if self.protocol == self.Protocol.FTP:
                with ftputil.FTPHost(
                    self.host,
                    bs_decrypt(self.username, encryption_key),
                    bs_decrypt(self.password, encryption_key),
                    port=int(self.port),
                    session_factory=FtpSession,
                ) as hosting_host:

                    names = hosting_host.listdir(path or ".")

                    for name in names:
                        try:
                            full_path = (
                                (path if (path != "." and path != "/") else "") + ("/" if path != "." else "") + name
                            )

                            hosting_host.path.getsize(full_path)

                            if hosting_host.path.isdir(full_path):
                                obj_type = "directory"
                            elif hosting_host.path.isfile(full_path):
                                obj_type = "file"

                            eligible_objects.append(
                                {
                                    "directory": path,
                                    "path": (path if (path != "." and path != "/") else "")
                                    + ("/" if path != "." else "")
                                    + name,
                                    "type": obj_type,
                                    "name": name,
                                }
                            )
                        except Exception as e:
                            # Ignore this for now. But later add checks here.
                            capture_exception(e)
                    hosting_host.close()
                    # Sort by type and then by object type(file or dir)
                    eligible_objects = sorted(eligible_objects, key=lambda k: k["type"])
                    eligible_objects = sorted(eligible_objects, key=lambda k: k["name"])

            elif self.protocol == self.Protocol.FTPS:
                with ftputil.FTPHost(
                    self.host,
                    bs_decrypt(self.username, encryption_key),
                    bs_decrypt(self.password, encryption_key),
                    port=int(self.port),
                    session_factory=ftp_tls_session_factory(
                        verify_ssl=self.verify_ssl is not False,
                        explicit=bool(self.ftps_use_explicit_ssl),
                    ),
                ) as hosting_host:

                    names = hosting_host.listdir(path or ".")

                    for name in names:
                        try:
                            full_path = (
                                (path if (path != "." and path != "/") else "") + ("/" if path != "." else "") + name
                            )

                            hosting_host.path.getsize(full_path)

                            if hosting_host.path.isdir(full_path):
                                obj_type = "directory"
                            elif hosting_host.path.isfile(full_path):
                                obj_type = "file"

                            eligible_objects.append(
                                {
                                    "directory": path,
                                    "path": (path if (path != "." and path != "/") else "")
                                    + ("/" if path != "." else "")
                                    + name,
                                    "type": obj_type,
                                    "name": name,
                                }
                            )
                        except Exception as e:
                            # Ignore this for now. But later add checks here.
                            capture_exception(e)
                    hosting_host.close()
                    # Sort by type and then by object type(file or dir)
                    eligible_objects = sorted(eligible_objects, key=lambda k: k["type"])
                    eligible_objects = sorted(eligible_objects, key=lambda k: k["name"])

            elif self.protocol == self.Protocol.SFTP:
                sftp, ssh, ssh_key_path = self.get_sftp_client()
                # Some files and dir won't have correct permission so we will ignore them.
                try:
                    names = sftp.listdir(path or ".")
                except (IOError, OSError):
                    names = []

                for name in names:
                    full_path = (path if path != "." else "") + ("/" if path != "." else "") + name

                    if isFile(full_path, sftp):
                        obj_type = "file"
                        eligible_objects.append(
                            {
                                "directory": path,
                                "path": (path if (path != "." and path != "/") else "")
                                + ("/" if path != "." else "")
                                + name,
                                "type": obj_type,
                                "name": name,
                            }
                        )
                    elif isdir(full_path, sftp):
                        obj_type = "directory"
                        eligible_objects.append(
                            {
                                "directory": path,
                                "path": (path if (path != "." and path != "/") else "")
                                + ("/" if path != "." else "")
                                + name,
                                "type": obj_type,
                                "name": name,
                            }
                        )

                # Sort by type and then by object type(file or dir)
                eligible_objects = sorted(eligible_objects, key=lambda k: k["type"])
                eligible_objects = sorted(eligible_objects, key=lambda k: k["name"])

                # Now close connections and remove key file.
                sftp.close()
                ssh.close()
                if ssh_key_path:
                    os.remove(ssh_key_path)

        except Exception as e:
            raise NodeConnectionErrorEligibleObjects()

        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            self.check_connection(data=None, check_errors=check_errors)
            return True
        except Exception as e:
            if check_errors:
                raise IntegrationValidationError(e.__str__())
            else:
                return False


class CoreAuthDatabase(TimeStampedModel):
    class DatabaseType(models.IntegerChoices):
        MYSQL = 1, "MySQL"
        MARIADB = 2, "MariaDB"
        POSTGRESQL = 3, "PostgreSQL"

    class DatabaseVersion(models.TextChoices):
        MYSQL_8_4 = "mysql_8_4", "MySQL 8.4"
        MYSQL_8_0 = "mysql_8_0", "MySQL 8.0"
        MYSQL_5_7 = "mysql_5_7", "MySQL 5.7"
        MYSQL_5_6 = "mysql_5_6", "MySQL 5.6"
        MYSQL_5_5 = "mysql_5_5", "MySQL 5.5"

        MARIADB_11_8 = "mariadb_11_8", "MariaDB 11.8"
        MARIADB_11_4 = "mariadb_11_4", "MariaDB 11.4"
        MARIADB_10_11 = "mariadb_10_11", "MariaDB 10.11"
        MARIADB_10_10 = "mariadb_10_10", "MariaDB 10.10"
        MARIADB_10_9 = "mariadb_10_9", "MariaDB 10.9"
        MARIADB_10_8 = "mariadb_10_8", "MariaDB 10.8"
        MARIADB_10_7 = "mariadb_10_7", "MariaDB 10.7"
        MARIADB_10_6 = "mariadb_10_6", "MariaDB 10.6"
        MARIADB_10_5 = "mariadb_10_5", "MariaDB 10.5"
        MARIADB_10_4 = "mariadb_10_4", "MariaDB 10.4"
        MARIADB_10_3 = "mariadb_10_3", "MariaDB 10.3"
        MARIADB_10_2 = "mariadb_10_2", "MariaDB 10.2"
        MARIADB_10_1 = "mariadb_10_1", "MariaDB 10.1"
        POSTGRESQL_18 = "postgres_18", "PostgreSQL 18"
        POSTGRESQL_17 = "postgres_17", "PostgreSQL 17"
        POSTGRESQL_16 = "postgres_16", "PostgreSQL 16"
        POSTGRESQL_15 = "postgres_15", "PostgreSQL 15"
        POSTGRESQL_14 = "postgres_14", "PostgreSQL 14"
        POSTGRESQL_13 = "postgres_13", "PostgreSQL 13"
        POSTGRESQL_12 = "postgres_12", "PostgreSQL 12"
        POSTGRESQL_11 = "postgres_11", "PostgreSQL 11"
        POSTGRESQL_10 = "postgres_10", "PostgreSQL 10"
        POSTGRESQL_9 = "postgres_9", "PostgreSQL 9"

    connection = models.OneToOneField("CoreConnection", related_name="auth_database", on_delete=models.CASCADE)
    host = models.CharField(max_length=255)
    port = models.IntegerField()
    database_name = models.CharField(max_length=255, null=True)
    all_databases = models.BooleanField(default=False)
    # all clear
    username = models.BinaryField(null=True)
    # all clear
    password = models.BinaryField(null=True)
    type = models.IntegerField(choices=DatabaseType.choices)
    version = models.CharField(choices=DatabaseVersion.choices, max_length=32)
    include_stored_procedure = models.BooleanField(null=True)
    use_ssl = models.BooleanField(default=False)
    info_name = models.CharField(max_length=64, null=True)
    # all clear
    ssh_username = models.BinaryField(null=True)
    # all clear
    ssh_password = models.BinaryField(null=True)
    ssh_port = models.IntegerField(null=True)
    ssh_host = models.CharField(max_length=255, null=True)
    use_public_key = models.BooleanField(null=True)
    use_private_key = models.BooleanField(null=True)
    # all clear
    private_key = models.BinaryField(null=True)
    encryption_updated = models.BooleanField(default=False)
    # https://xtresoft.atlassian.net/browse/BS-12
    flag_use_sha1_key_verification = models.BooleanField(default=False, null=True)

    class Meta:
        db_table = "core_auth_database"

    @classmethod
    def mysql_family_client_binary(cls, database_type):
        """Return the vendor client required by a MySQL-family connection."""
        if database_type == cls.DatabaseType.MYSQL:
            return "mysql"
        if database_type == cls.DatabaseType.MARIADB:
            return "mariadb"
        raise ValueError("database type is not part of the MySQL family")

    @classmethod
    def mysql_family_dump_binary(cls, database_type):
        """Return the vendor dump client required by a MySQL-family connection."""
        if database_type == cls.DatabaseType.MYSQL:
            return "mysqldump"
        if database_type == cls.DatabaseType.MARIADB:
            return "mariadb-dump"
        raise ValueError("database type is not part of the MySQL family")

    @classmethod
    def _mysql_family_engine_name(cls, database_type):
        if database_type == cls.DatabaseType.MYSQL:
            return "mysql"
        if database_type == cls.DatabaseType.MARIADB:
            return "mariadb"
        raise ValueError("database type is not part of the MySQL family")

    @classmethod
    def _mysql_family_ssl_option(cls, database_type, use_ssl):
        """Return the vendor-correct, non-ambiguous database TLS option."""
        if database_type == cls.DatabaseType.MARIADB:
            # MariaDB's client rejects MySQL's --ssl-mode option. Its boolean
            # --ssl flag is added only when the user enables database TLS.
            return "--ssl" if use_ssl else ""
        if database_type == cls.DatabaseType.MYSQL:
            # MySQL's PREFERRED default can silently fall back to plaintext.
            # The product switch is therefore exact: on requires TLS; off is
            # an explicit opt-out for deployments that deliberately allow it.
            return "--ssl-mode=REQUIRED" if use_ssl else "--ssl-mode=DISABLED"
        raise ValueError("database type is not part of the MySQL family")

    @staticmethod
    def _mysql_cli_version(output):
        match = re.search(
            r"\b(?:Distrib|Ver)\s+(\d+)\.(\d+)",
            str(output or ""),
            re.IGNORECASE,
        )
        if not match:
            return None
        return int(match.group(1)), int(match.group(2))

    @classmethod
    def _validate_mysql_family_version_output(
        cls,
        database_type,
        configured_version,
        client_output,
        dump_output,
    ):
        engine = cls._mysql_family_engine_name(database_type)
        client_text = str(client_output or "").lower()
        dump_text = str(dump_output or "").lower()
        if database_type == cls.DatabaseType.MARIADB:
            if "mariadb" not in client_text or "mariadb" not in dump_text:
                raise DatabaseClientCapabilityError(engine)
            return

        if (
            "mysql" not in client_text
            or "mysql" not in dump_text
            or "mariadb" in client_text
            or "mariadb" in dump_text
        ):
            raise DatabaseClientCapabilityError(engine)
        configured_match = re.fullmatch(
            r"mysql_(\d+)_(\d+)", str(configured_version or "")
        )
        client_version = cls._mysql_cli_version(client_output)
        dump_version = cls._mysql_cli_version(dump_output)
        if not configured_match or not client_version or not dump_version:
            raise DatabaseClientCapabilityError(engine)
        configured = (
            int(configured_match.group(1)),
            int(configured_match.group(2)),
        )
        if client_version < configured or dump_version < configured:
            raise DatabaseClientCapabilityError(engine)

    @staticmethod
    def _run_local_database_client_command(argv):
        process = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=int(
                getattr(settings, "DATABASE_VALIDATION_COMMAND_TIMEOUT", 30)
            ),
            check=False,
        )
        output = (process.stdout or b"") + b"\n" + (process.stderr or b"")
        output = output.decode("utf-8", "replace").strip()
        if process.returncode != 0:
            if database_tls_required_message(output):
                raise DatabaseTLSRequiredError()
            failure = classify_connection_error(
                RuntimeError(output), stage="database"
            )
            if failure.code != "CONNECTION_VALIDATION_FAILED":
                raise ClassifiedConnectionError(failure)
            raise RuntimeError(
                f"database client exited with status {process.returncode}"
            )
        return output

    def _install_local_database_credentials(
        self,
        *,
        host,
        port,
        username,
        password,
    ):
        content = "\n".join(
            [
                "[client]",
                f"host={self._mysql_option_value(host)}",
                f"port={self._mysql_option_value(port)}",
                f"user={self._mysql_option_value(username)}",
                f"password={self._mysql_option_value(password)}",
                "",
            ]
        ).encode("utf-8")
        descriptor, path = tempfile.mkstemp(
            prefix=".backupsheep-database-capability-",
            suffix=".cnf",
        )
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, content)
        except Exception:
            os.close(descriptor)
            try:
                os.remove(path)
            except OSError:
                pass
            raise
        os.close(descriptor)
        return path

    def _validate_mysql_family_client_capability(
        self,
        *,
        database_type,
        version,
        host,
        port,
        database_name,
        username,
        password,
        use_ssl,
        all_databases=False,
        include_database_objects=False,
        ssh=None,
        remote_credentials=None,
    ):
        """Prove query/import and dump clients before backup or restore mutation.

        MariaDB's exact sandbox header is executed with a read-only ``SELECT 1``
        probe.  MariaDB documents that older MariaDB clients and MySQL's client
        reject this header, so the feature probe is stronger than a patch-version
        allowlist.  MySQL clients must be vendor-correct and no older than the
        configured server contract.
        """
        engine = self._mysql_family_engine_name(database_type)
        client = self.mysql_family_client_binary(database_type)
        dump = self.mysql_family_dump_binary(database_type)
        probe = "SELECT 1;"
        if database_type == self.DatabaseType.MARIADB:
            probe = "/*M!999999\\- enable the sandbox mode */\nSELECT 1;"
        ssl_option = self._mysql_family_ssl_option(database_type, use_ssl)

        def event_database_names(discovered=""):
            if all_databases:
                system_databases = {
                    "information_schema",
                    "mysql",
                    "performance_schema",
                    "sys",
                }
                return sorted(
                    {
                        line.strip()
                        for line in str(discovered or "").splitlines()
                        if line.strip()
                        and line.strip().lower() not in system_databases
                    }
                )
            if database_name:
                return [str(database_name)]
            raise DatabaseEventPrivilegeError(
                internal_detail="database_name_missing"
            )

        local_credentials = None
        try:
            if ssh is not None:
                if not remote_credentials:
                    raise RuntimeError("remote credentials were not installed")
                client_output, _ = self._run_remote_database_command(
                    ssh, f"{client} --version"
                )
                dump_output, _ = self._run_remote_database_command(
                    ssh, f"{dump} --version"
                )
                self._validate_mysql_family_version_output(
                    database_type,
                    version,
                    client_output,
                    dump_output,
                )

                def remote_query(sql, *, selected_database=None):
                    parts = [client, remote_credentials["mysql_option"]]
                    if ssl_option:
                        parts.append(ssl_option)
                    parts.extend(["--batch", "--skip-column-names"])
                    if selected_database:
                        parts.append(
                            f"--database={shlex.quote(str(selected_database))}"
                        )
                    parts.append(f"--execute={shlex.quote(str(sql))}")
                    output, _error = self._run_remote_database_command(
                        ssh, " ".join(parts)
                    )
                    return output

                probe_output = remote_query(
                    probe,
                    selected_database=database_name,
                )
                if include_database_objects:
                    discovered = (
                        remote_query("SHOW DATABASES;")
                        if all_databases
                        else ""
                    )
                    for event_database in event_database_names(discovered):
                        event_sql = (
                            "SHOW EVENTS FROM "
                            f"{self._mysql_identifier(event_database)};"
                        )
                        try:
                            remote_query(event_sql)
                        except DatabaseTLSRequiredError:
                            raise
                        except Exception as error:
                            raise DatabaseEventPrivilegeError(
                                internal_detail=error.__class__.__name__
                            ) from error
            else:
                # New-connection validation runs on an unsaved model instance,
                # so select the client bundle from the submitted version rather
                # than the instance's still-empty ``self.version`` field.
                binary_path = self.bin_path(version=version)
                client_path = f"{binary_path}{client}"
                dump_path = f"{binary_path}{dump}"
                client_output = self._run_local_database_client_command(
                    [client_path, "--version"]
                )
                dump_output = self._run_local_database_client_command(
                    [dump_path, "--version"]
                )
                self._validate_mysql_family_version_output(
                    database_type,
                    version,
                    client_output,
                    dump_output,
                )
                local_credentials = self._install_local_database_credentials(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                )

                def local_query(sql, *, selected_database=None):
                    argv = [
                        client_path,
                        f"--defaults-extra-file={local_credentials}",
                    ]
                    if ssl_option:
                        argv.append(ssl_option)
                    argv.extend(["--batch", "--skip-column-names"])
                    if selected_database:
                        argv.append(f"--database={selected_database}")
                    argv.extend(["--execute", str(sql)])
                    return self._run_local_database_client_command(argv)

                probe_output = local_query(
                    probe,
                    selected_database=database_name,
                )
                if include_database_objects:
                    discovered = (
                        local_query("SHOW DATABASES;")
                        if all_databases
                        else ""
                    )
                    for event_database in event_database_names(discovered):
                        event_sql = (
                            "SHOW EVENTS FROM "
                            f"{self._mysql_identifier(event_database)};"
                        )
                        try:
                            local_query(event_sql)
                        except DatabaseTLSRequiredError:
                            raise
                        except Exception as error:
                            raise DatabaseEventPrivilegeError(
                                internal_detail=error.__class__.__name__
                            ) from error
            if str(probe_output or "").strip() != "1":
                raise RuntimeError("database client capability probe returned no result")
        except ClassifiedConnectionError as error:
            if not use_ssl and error.code == "AUTH_FAILED":
                # MySQL accounts declared with REQUIRE SSL may deliberately
                # return the same 1045 response as a wrong password on a
                # plaintext attempt. Prove the distinction with one bounded
                # TLS-required SELECT probe using the same credentials. A
                # successful probe means configuration, not authentication,
                # is the problem; any failure preserves the original auth
                # result. Do not run object/event checks in this hint probe.
                try:
                    self._validate_mysql_family_client_capability(
                        database_type=database_type,
                        version=version,
                        host=host,
                        port=port,
                        database_name=database_name,
                        username=username,
                        password=password,
                        use_ssl=True,
                        all_databases=all_databases,
                        include_database_objects=False,
                        ssh=ssh,
                        remote_credentials=remote_credentials,
                    )
                except Exception:
                    raise error
                raise DatabaseTLSRequiredError()
            raise
        except (
            DatabaseClientCapabilityError,
            DatabaseEventPrivilegeError,
            DatabaseTLSRequiredError,
        ):
            raise
        except Exception as error:
            raise DatabaseClientCapabilityError(
                engine,
                internal_detail=error.__class__.__name__,
            ) from error
        finally:
            if local_credentials:
                try:
                    os.remove(local_credentials)
                except OSError:
                    pass

    def bin_path(self, *, version=None):
        """Local directory of the version-matched client tools for direct-mode backups.

        The SaaS build ran `docker exec <version-container> <tool>`; the self-hosted
        worker image ships the tools instead, and this picks the right one by version:
        - PostgreSQL: the exact /usr/lib/postgresql/<N>/bin (pg_dump is forward
          compatible, so the newest installed client is used as a fallback).
        - MySQL: a real MySQL client if dropped in at /opt/mysql/bin, else the system client.
        - MariaDB (and anything else): the system mariadb client (mariadb-dump / mysqldump).
        """
        version = version or self.version or ""
        if version.startswith("postgres_"):
            wanted = version.split("postgres_", 1)[1]
            for v in [wanted, "18", "17", "16", "15", "14"]:
                candidate = f"/usr/lib/postgresql/{v}/bin/"
                if os.path.isdir(candidate):
                    return candidate
            return "/usr/bin/"
        if version.startswith("mysql_"):
            if os.path.exists("/opt/mysql/bin/mysqldump"):
                return "/opt/mysql/bin/"
            return "/usr/bin/"
        return "/usr/bin/"

    def _direct_mysql_connect(self, host, port, username, password, database_name, use_ssl):
        """Direct-mode MySQL/MariaDB connect, with an SSL hint.

        MySQL 8.4 dropped mysql_native_password, so servers default to
        caching_sha2_password, which refuses to exchange credentials over a
        plain connection (errno 2061). When that happens with SSL disabled,
        retry once with SSL on: if that connects, the credentials are fine
        and the server simply requires TLS, so raise a clear message instead
        of the cryptic 2061. If the retry also fails, the original error
        stands.
        """
        import mysql.connector

        try:
            return mysql.connector.connect(
                host=host,
                port=int(port),
                user=username,
                passwd=password,
                db=database_name,
                connect_timeout=int(getattr(settings, "DATABASE_CONNECT_TIMEOUT", 15)),
                ssl_disabled=(not use_ssl),
            )
        except Exception as e:
            if use_ssl or getattr(e, "errno", None) != 2061:
                raise
            try:
                retry_con = mysql.connector.connect(
                    host=host,
                    port=int(port),
                    user=username,
                    passwd=password,
                    db=database_name,
                    connect_timeout=int(getattr(settings, "DATABASE_CONNECT_TIMEOUT", 15)),
                    ssl_disabled=False,
                )
            except Exception:
                raise e
            retry_con.close()
            raise IntegrationValidationError(
                "The database server requires an SSL/TLS connection"
                " (the default on MySQL 8.4). Enable \"Use SSL/TLS\" on"
                " this connection and validate again."
            )

    @staticmethod
    def _direct_postgresql_connect(
        host, port, username, password, database_name, use_ssl
    ):
        import psycopg2

        statement_timeout_ms = int(
            getattr(settings, "DATABASE_STATEMENT_TIMEOUT_MS", 15000)
        )
        lock_timeout_ms = int(getattr(settings, "DATABASE_LOCK_TIMEOUT_MS", 5000))
        return psycopg2.connect(
            dbname=database_name,
            user=username,
            password=password,
            host=host,
            port=port,
            connect_timeout=int(getattr(settings, "DATABASE_CONNECT_TIMEOUT", 15)),
            sslmode="require" if use_ssl else "prefer",
            options=(
                f"-c statement_timeout={statement_timeout_ms} "
                f"-c lock_timeout={lock_timeout_ms}"
            ),
        )

    @staticmethod
    def _mysql_option_value(value):
        """Quote an option-file value without allowing new options to be injected."""
        value = str(value or "")
        value = (
            value.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\r", "\\r")
            .replace("\n", "\\n")
        )
        return f'"{value}"'

    @staticmethod
    def _mysql_identifier(value):
        """Quote one MySQL identifier without allowing statement injection."""
        return "`" + str(value or "").replace("`", "``") + "`"

    @staticmethod
    def _pgpass_value(value):
        return str(value or "").replace("\\", "\\\\").replace(":", "\\:")

    def _install_remote_database_credentials(
        self,
        ssh,
        *,
        host,
        port,
        username,
        password,
    ):
        """Install short-lived 0600 client files in the SSH user's home.

        Passwords never appear in a remote command, shell environment, process list,
        or worker log.  The caller must invoke ``_remove_remote_database_credentials``
        before closing the SSH client; every call site does so in ``finally``.
        """
        marker = uuid.uuid4().hex
        mysql_name = f".backupsheep-{marker}.cnf"
        pgpass_name = f".backupsheep-{marker}.pgpass"
        mysql_content = "\n".join(
            [
                "[client]",
                f"host={self._mysql_option_value(host)}",
                f"port={self._mysql_option_value(port)}",
                f"user={self._mysql_option_value(username)}",
                f"password={self._mysql_option_value(password)}",
                "",
            ]
        )
        pgpass_content = (
            f"{self._pgpass_value(host)}:{self._pgpass_value(port)}:*:"
            f"{self._pgpass_value(username)}:{self._pgpass_value(password)}\n"
        )
        sftp = ssh.open_sftp()
        created = []
        try:
            for name, content in (
                (mysql_name, mysql_content),
                (pgpass_name, pgpass_content),
            ):
                with sftp.open(name, "w") as handle:
                    handle.write(content)
                sftp.chmod(name, 0o600)
                created.append(name)
        except Exception:
            for name in created:
                try:
                    sftp.remove(name)
                except Exception:
                    pass
            raise
        finally:
            sftp.close()
        return {
            "files": (mysql_name, pgpass_name),
            "mysql_option": (
                f'--defaults-extra-file="$HOME/{mysql_name}"'
            ),
            "pgpass_env": f'PGPASSFILE="$HOME/{pgpass_name}"',
        }

    @staticmethod
    def _remove_remote_database_credentials(ssh, credentials):
        if not credentials:
            return
        try:
            sftp = ssh.open_sftp()
        except Exception:
            return
        try:
            for name in credentials.get("files") or ():
                try:
                    sftp.remove(name)
                except Exception:
                    pass
        finally:
            sftp.close()

    @staticmethod
    def _postgres_remote_command(
        credentials,
        *,
        host,
        port,
        username,
        database_name,
        sql=None,
        list_databases=False,
        tuples_only=False,
    ):
        """Build a shell-safe psql command; the password lives only in pgpass."""
        parts = [
            credentials["pgpass_env"],
            "psql",
            "--no-password",
            f"--host={shlex.quote(str(host))}",
            f"--port={shlex.quote(str(port))}",
            f"--username={shlex.quote(str(username))}",
        ]
        if database_name:
            parts.append(f"--dbname={shlex.quote(str(database_name))}")
        if tuples_only:
            parts.extend(["--quiet", "--tuples-only", "--no-align"])
        if list_databases:
            parts.append("--list")
        if sql is not None:
            parts.append(f"--command={shlex.quote(str(sql))}")
        return " ".join(parts)

    @staticmethod
    def _run_remote_database_command(ssh, command):
        """Run a bounded remote client command and require a successful exit."""
        _stdin, stdout, stderr = ssh.exec_command(
            command,
            timeout=int(
                getattr(settings, "DATABASE_VALIDATION_COMMAND_TIMEOUT", 30)
            ),
        )

        def decode_lines(stream):
            return "".join(
                line.decode("utf-8", "replace")
                if isinstance(line, bytes)
                else str(line)
                for line in (stream.readlines() or [])
            ).strip()

        output = decode_lines(stdout)
        error = decode_lines(stderr)
        channel = getattr(stdout, "channel", None)
        status = channel.recv_exit_status() if channel is not None else 0
        if status != 0:
            combined = f"{output}\n{error}"
            if database_tls_required_message(combined):
                raise DatabaseTLSRequiredError()
            failure = classify_connection_error(
                RuntimeError(combined), stage="database"
            )
            if failure.code != "CONNECTION_VALIDATION_FAILED":
                raise ClassifiedConnectionError(failure)
            # This detail is used only by the classifier and Sentry. Passwords are
            # absent from both the command and client stderr because auth uses files.
            raise RuntimeError(error or f"Database client exited with status {status}.")
        return output, error

    @staticmethod
    def _mysql_version_slug(result):
        """Build the "<type>_<major>_<minor>" slug from a SELECT version() string.

        MariaDB (and vendor-suffixed MySQL builds) include the vendor name after
        a dash ("10.11.6-MariaDB-1:...") -- keep the historical slug for those so
        detected values stay identical. Stock MySQL returns a bare version
        ("8.0.36" or "8.0.36-0ubuntu0.22.04.1"): take the first token before any
        space and strip anything after a dash instead of assuming one exists.
        """
        if ("mariadb" in result.lower() or "mysql" in result.lower()) and "-" in result:
            return slugify(f"{result.split('-')[1]}_{result.split('-')[0]}".replace(".", "_")).replace("-", "_")
        version = result.split(" ")[0].split("-")[0]
        if version and version[0].isdigit():
            return slugify(f"mysql_{version}".replace(".", "_")).replace("-", "_")
        return None

    def check_connection(self, data=None, check_errors=None):
        import mysql.connector
        import psycopg2

        if data:
            host = data.get("host")
            port = data.get("port")
            database_name = data.get("database_name")
            username = data.get("username")
            password = data.get("password")
            all_databases = data.get("all_databases")
            include_database_objects = bool(
                data.get("include_stored_procedure")
            )
            use_ssl = data.get("use_ssl", False)

            type = self.DatabaseType(data.get("type"))
            use_public_key = data.get("use_public_key")
            use_private_key = data.get("use_private_key")
        else:
            encryption_key = self.connection.account.get_encryption_key()
            host = self.host
            port = self.port
            database_name = self.database_name
            all_databases = self.all_databases
            include_database_objects = bool(self.include_stored_procedure)
            username = bs_decrypt(self.username, encryption_key)
            password = bs_decrypt(self.password, encryption_key)
            type = self.type
            use_public_key = self.use_public_key
            use_private_key = self.use_private_key
            use_ssl = self.use_ssl

        if use_public_key or use_private_key:
            ssh, ssh_key_path = self.get_ssh_client(data=data)
            remote_credentials = None
            try:
                remote_credentials = self._install_remote_database_credentials(
                    ssh,
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                )
                if type in (
                    self.DatabaseType.MYSQL,
                    self.DatabaseType.MARIADB,
                ):
                    option_ssl_mode = self._mysql_family_ssl_option(type, use_ssl)
                    self._validate_mysql_family_client_capability(
                        database_type=type,
                        version=(data or {}).get("version", self.version),
                        host=host,
                        port=port,
                        database_name=database_name,
                        username=username,
                        password=password,
                        use_ssl=use_ssl,
                        all_databases=all_databases,
                        include_database_objects=include_database_objects,
                        ssh=ssh,
                        remote_credentials=remote_credentials,
                    )
                    client_binary = self.mysql_family_client_binary(type)
                    execstr = (
                        f"{client_binary}"
                        f" {remote_credentials['mysql_option']}"
                        f" {option_ssl_mode}"
                        f" --disable-column-names"
                        f" --execute={shlex.quote('STATUS;')}"
                    )
                    output, error = self._run_remote_database_command(ssh, execstr)
                    combined = f"{output}\n{error}"
                    if not (
                        "server:" in combined.lower()
                        or "server version:" in combined.lower()
                    ):
                        raise RuntimeError("Database client returned no server status.")

                elif type == self.DatabaseType.POSTGRESQL:
                    execstr = self._postgres_remote_command(
                        remote_credentials,
                        host=host,
                        port=port,
                        username=username,
                        database_name="postgres" if all_databases else database_name,
                        sql="SELECT version();",
                    )
                    output, error = self._run_remote_database_command(ssh, execstr)
                    combined = f"{output}\n{error}"

                    if "postgresql" in combined.lower() and "compiled by" in combined.lower():
                        output_list = output.lower().strip().split(" ")

                        if len(output_list) > 0:
                            find_index = lambda l, e: l.index(e) if e in l else None

                            if find_index(output_list, "postgresql"):

                                db_server_version = output_list[find_index(output_list, "postgresql") + 1]

                                # Now get pg_dump version
                                output_lines, _error = self._run_remote_database_command(
                                    ssh, "pg_dump --version"
                                )

                                # Server/pg_dump versions do not always parse as a single
                                # number (e.g. '9.6.24', or extra distro suffixes) -- skip
                                # the comparison with a warning instead of crashing validation.
                                try:
                                    ssh_pg_dump_version = output_lines.strip().split(" ")[2]
                                    db_server_version_num = float(db_server_version)
                                    ssh_pg_dump_version_num = float(ssh_pg_dump_version)
                                except (IndexError, ValueError):
                                    capture_message(
                                        f"Skipping pg_dump version check: could not parse"
                                        f" server version '{db_server_version}' or"
                                        f" pg_dump version output '{output_lines}'",
                                        level="warning",
                                    )
                                else:
                                    if db_server_version_num > ssh_pg_dump_version_num:
                                        raise IntegrationValidationError(
                                            f"The pg_dump version ({ssh_pg_dump_version})"
                                            f" on SSH server must be equal or higher"
                                            f" than your PostgreSQL version ({db_server_version})"
                                        )
                    else:
                        raise RuntimeError("PostgreSQL client returned no version.")
            except ClassifiedConnectionError:
                raise
            except Exception as error:
                raise classified_connection_error(error, stage="database") from error
            finally:
                self._remove_remote_database_credentials(ssh, remote_credentials)
                ssh.close()
                cleanup_temporary_key(ssh_key_path)
        else:
            if type in (
                self.DatabaseType.MYSQL,
                self.DatabaseType.MARIADB,
            ):
                try:
                    self._validate_mysql_family_client_capability(
                        database_type=type,
                        version=(data or {}).get("version", self.version),
                        host=host,
                        port=port,
                        database_name=database_name,
                        username=username,
                        password=password,
                        use_ssl=use_ssl,
                        all_databases=all_databases,
                        include_database_objects=include_database_objects,
                    )
                    db_con = self._direct_mysql_connect(host, port, username, password, database_name, use_ssl)
                    cursor = db_con.cursor()
                    cursor.execute(
                        "SHOW DATABASES" if all_databases else "SHOW TABLES"
                    )
                    cursor.fetchall()
                    cursor.close()
                    db_con.close()
                except Exception as e:
                    raise classified_connection_error(e, stage="database") from e
            elif type == self.DatabaseType.POSTGRESQL:
                try:
                    db_con = self._direct_postgresql_connect(
                        host,
                        port,
                        username,
                        password,
                        database_name,
                        use_ssl,
                    )
                    cursor = db_con.cursor()
                    cursor.execute("select relname from pg_class where relkind='r' and relname !~ '^(pg_|sql_)';")
                    cursor.fetchall()
                    cursor.close()
                    db_con.close()
                except Exception as e:
                    raise classified_connection_error(e, stage="database") from e

    """
    Find DB Version & automatically set correct version
    """

    def find_db_type_and_version(self, data=None):
        import mysql.connector
        import psycopg2

        if data:
            host = data.get("host")
            port = data.get("port")
            database_name = data.get("database_name")
            username = data.get("username")
            password = data.get("password")
            use_ssl = data.get("use_ssl", False)

            type = self.DatabaseType(data.get("type"))
            use_public_key = data.get("use_public_key")
            use_private_key = data.get("use_private_key")
        else:
            encryption_key = self.connection.account.get_encryption_key()
            host = self.host
            port = self.port
            database_name = self.database_name
            username = bs_decrypt(self.username, encryption_key)
            password = bs_decrypt(self.password, encryption_key)
            type = self.type
            use_public_key = self.use_public_key
            use_private_key = self.use_private_key
            use_ssl = self.use_ssl

        if use_public_key or use_private_key:
            ssh, ssh_key_path = self.get_ssh_client(data=data)
            remote_credentials = None
            try:
                remote_credentials = self._install_remote_database_credentials(
                    ssh,
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                )
                option_ssl_mode = self._mysql_family_ssl_option(type, use_ssl)

                if type in (
                    self.DatabaseType.MYSQL,
                    self.DatabaseType.MARIADB,
                ):
                    client_binary = self.mysql_family_client_binary(type)
                    execstr = (
                        f"{client_binary}"
                        f" {remote_credentials['mysql_option']}"
                        f" {option_ssl_mode}"
                        f" --disable-column-names"
                        f" --execute={shlex.quote('SELECT version();')}"
                    )
                    output, _error = self._run_remote_database_command(ssh, execstr)
                    db_type_version = None
                    if output:
                        result = output.strip()
                        version = int(result.split(".")[0])
                        if version >= 10:
                            db_type = "mariadb"
                        else:
                            db_type = "mysql"
                        db_version = result.split(".")[0] + "_" + result.split(".")[1]
                        db_type_version = f"{db_type}_{db_version}"
                    return db_type_version
                elif type == self.DatabaseType.POSTGRESQL:
                    execstr = self._postgres_remote_command(
                        remote_credentials,
                        host=host,
                        port=port,
                        username=username,
                        database_name=database_name or "postgres",
                        sql="SELECT version();",
                    )
                    output, _error = self._run_remote_database_command(ssh, execstr)
                    db_type_version = None
                    if output:
                        result = output.strip()
                        if "postgresql" in result.lower():
                            db_type = slugify(result.replace(".", "_")).split("-")[1].replace("postgresql", "postgres")
                            db_version = slugify(result.replace(".", "_")).split("-")[2]
                            db_type_version = f"{db_type}_{db_version}"
                    return db_type_version
            except ClassifiedConnectionError:
                raise
            except Exception as error:
                raise classified_connection_error(error, stage="database") from error
            finally:
                self._remove_remote_database_credentials(ssh, remote_credentials)
                ssh.close()
                cleanup_temporary_key(ssh_key_path)
        else:
            if type == self.DatabaseType.MYSQL:
                db_con = self._direct_mysql_connect(host, port, username, password, database_name, use_ssl)
                cursor = db_con.cursor()
                cursor.execute("select version();")
                result = cursor.fetchone()[0]
                cursor.close()
                db_con.close()
                return self._mysql_version_slug(result)
            elif type == self.DatabaseType.MARIADB:
                db_con = self._direct_mysql_connect(host, port, username, password, database_name, use_ssl)
                cursor = db_con.cursor()
                cursor.execute("select version();")
                result = cursor.fetchone()[0]
                cursor.close()
                db_con.close()
                return self._mysql_version_slug(result)
            elif type == self.DatabaseType.POSTGRESQL:
                db_con = self._direct_postgresql_connect(
                    host,
                    port,
                    username,
                    password,
                    database_name,
                    use_ssl,
                )
                cursor = db_con.cursor()
                cursor.execute("select version();")
                result = cursor.fetchone()[0]
                cursor.close()
                db_con.close()

                if "postgres" in result.lower():
                    db_type_version = result.split("on")[0].replace("postgresql", "postgres")
                    return (
                        slugify(f"{db_type_version.split(' ')[0]}_{db_type_version.split(' ')[1]}".replace(".", "_"))
                        .replace("-", "_")
                        .replace("postgresql", "postgres")
                    )
                else:
                    return None

    """
    Fix and update DB Version based on find_db_type_and_version
    """

    def update_db_type_and_version(self):
        available_db_versions = CoreAuthDatabase.DatabaseVersion.values
        available_db_types = CoreAuthDatabase.DatabaseType.choices
        db_version = self.find_db_type_and_version()
        if db_version:
            for available_db_versions in available_db_versions:
                if available_db_versions in db_version:
                    self.version = available_db_versions
                    self.save()
            for available_db_type in available_db_types:
                if available_db_type[1].lower() in db_version:
                    self.type = available_db_type[0]
                    self.save()
        return {"type": self.get_type_display(), "version": self.get_version_display()}

    def get_ssh_client(self, data=None):
        if data:
            ssh_username = data.get("ssh_username")
            ssh_password = data.get("ssh_password")
            ssh_port = data.get("ssh_port")
            ssh_host = data.get("ssh_host")
            private_key = data.get("private_key")
            use_public_key = data.get("use_public_key")
            use_private_key = data.get("use_private_key")
            flag_use_sha1_key_verification = data.get("flag_use_sha1_key_verification")
        else:
            encryption_key = self.connection.account.get_encryption_key()
            ssh_username = bs_decrypt(self.ssh_username, encryption_key)
            ssh_password = bs_decrypt(self.ssh_password, encryption_key)
            ssh_port = self.ssh_port
            ssh_host = self.ssh_host
            private_key = bs_decrypt(self.private_key, encryption_key)
            use_public_key = self.use_public_key
            use_private_key = self.use_private_key
            flag_use_sha1_key_verification = self.flag_use_sha1_key_verification

        ssh, ssh_key_path = open_ssh_client(
            host=ssh_host,
            port=ssh_port,
            username=ssh_username,
            private_key=private_key if use_private_key else None,
            private_key_passphrase=ssh_password if use_private_key else None,
            use_managed_key=bool(use_public_key),
            allow_legacy_rsa=bool(flag_use_sha1_key_verification),
        )
        try:
            sftp = ssh.open_sftp()
            sftp.listdir(".")
            sftp.close()
        except Exception as error:
            ssh.close()
            cleanup_temporary_key(ssh_key_path)
            raise classified_connection_error(error, stage="sftp") from error
        return ssh, ssh_key_path

    def get_eligible_objects(self):
        encryption_key = self.connection.account.get_encryption_key()
        eligible_objects = []
        self.check_connection(data=None, check_errors=True)
        username = bs_decrypt(self.username, encryption_key)
        password = bs_decrypt(self.password, encryption_key)

        try:
            if self.type in (
                self.DatabaseType.MYSQL,
                self.DatabaseType.MARIADB,
            ):
                option_ssl_mode = self._mysql_family_ssl_option(
                    self.type, self.use_ssl
                )
                if self.use_public_key or self.use_private_key:
                    ssh, ssh_key_path = self.get_ssh_client()
                    remote_credentials = None
                    try:
                        remote_credentials = self._install_remote_database_credentials(
                            ssh,
                            host=self.host,
                            port=self.port,
                            username=username,
                            password=password,
                        )
                        query = (
                            f"USE {self._mysql_identifier(self.database_name)}; SHOW TABLES;"
                            if self.database_name
                            else "SHOW DATABASES;"
                        )
                        client_binary = self.mysql_family_client_binary(self.type)
                        execstr = (
                            f"{client_binary}"
                            f" {remote_credentials['mysql_option']}"
                            f" {option_ssl_mode}"
                            f" --disable-column-names"
                            f" --execute={shlex.quote(query)}"
                        )
                        output, _error = self._run_remote_database_command(
                            ssh, execstr
                        )
                        for name in output.splitlines():
                            name = name.strip()
                            if name:
                                eligible_objects.append({"name": name})
                    finally:
                        self._remove_remote_database_credentials(
                            ssh, remote_credentials
                        )
                        ssh.close()
                        cleanup_temporary_key(ssh_key_path)
                else:
                    db_con = self._direct_mysql_connect(
                        self.host,
                        self.port,
                        username,
                        password,
                        self.database_name,
                        self.use_ssl,
                    )
                    cursor = None
                    try:
                        cursor = db_con.cursor()
                        cursor.execute(
                            "SHOW TABLES" if self.database_name else "SHOW DATABASES"
                        )
                        for item in cursor.fetchall():
                            eligible_objects.append({"name": item[0]})
                    finally:
                        try:
                            if cursor is not None:
                                cursor.close()
                        finally:
                            db_con.close()
            elif self.type == self.DatabaseType.POSTGRESQL:
                if self.use_public_key or self.use_private_key:
                    ssh, ssh_key_path = self.get_ssh_client()
                    remote_credentials = None
                    try:
                        remote_credentials = self._install_remote_database_credentials(
                            ssh,
                            host=self.host,
                            port=self.port,
                            username=username,
                            password=password,
                        )
                        if self.database_name:
                            database = self.database_name
                            sql = (
                                "SELECT tablename FROM pg_catalog.pg_tables "
                                "WHERE schemaname NOT IN "
                                "('pg_catalog','information_schema') "
                                "ORDER BY tablename;"
                            )
                        else:
                            database = "postgres"
                            sql = (
                                "SELECT datname FROM pg_database "
                                "WHERE datallowconn AND NOT datistemplate "
                                "ORDER BY datname;"
                            )
                        command = self._postgres_remote_command(
                            remote_credentials,
                            host=self.host,
                            port=self.port,
                            username=username,
                            database_name=database,
                            sql=sql,
                            tuples_only=True,
                        )
                        output, _error = self._run_remote_database_command(
                            ssh, command
                        )
                        for name in output.splitlines():
                            name = name.strip()
                            if name:
                                eligible_objects.append({"name": name})
                    finally:
                        self._remove_remote_database_credentials(
                            ssh, remote_credentials
                        )
                        ssh.close()
                        cleanup_temporary_key(ssh_key_path)
                else:
                    db_con = self._direct_postgresql_connect(
                        self.host,
                        self.port,
                        username,
                        password,
                        self.database_name or "postgres",
                        self.use_ssl,
                    )
                    cursor = None
                    try:
                        cursor = db_con.cursor()
                        if self.database_name:
                            cursor.execute(
                                "SELECT tablename FROM pg_catalog.pg_tables "
                                "WHERE schemaname NOT IN "
                                "('pg_catalog','information_schema') "
                                "ORDER BY tablename;"
                            )
                        else:
                            cursor.execute(
                                "SELECT datname FROM pg_database "
                                "WHERE datallowconn AND NOT datistemplate "
                                "ORDER BY datname;"
                            )
                        for item in cursor.fetchall():
                            eligible_objects.append({"name": item[0]})
                    finally:
                        try:
                            if cursor is not None:
                                cursor.close()
                        finally:
                            db_con.close()
        except ClassifiedConnectionError:
            raise
        except Exception as error:
            raise classified_connection_error(error, stage="database") from error

        return sorted(eligible_objects, key=lambda item: item["name"])

    def validate(self, check_errors=None, raise_exp=None):
        try:
            self.check_connection(data=None, check_errors=check_errors)
            return True
        except Exception as e:
            if check_errors and raise_exp:
                raise IntegrationValidationError(e.__str__())
            else:
                return False


class CoreAuthWordPress(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_wordpress", on_delete=models.CASCADE)
    url = models.URLField()
    key = models.TextField(editable=False)
    http_user = models.TextField(null=True, blank=True, editable=False)
    http_pass = models.TextField(null=True, blank=True, editable=False)

    class Meta:
        db_table = "core_auth_wordpress"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(key__startswith=WORDPRESS_SECRET_PREFIX),
                name="wordpress_key_ciphertext_v1",
            ),
            models.CheckConstraint(
                condition=models.Q(http_user__isnull=True)
                | models.Q(http_user__startswith=WORDPRESS_SECRET_PREFIX),
                name="wordpress_http_user_ciphertext_v1",
            ),
            models.CheckConstraint(
                condition=models.Q(http_pass__isnull=True)
                | models.Q(http_pass__startswith=WORDPRESS_SECRET_PREFIX),
                name="wordpress_http_pass_ciphertext_v1",
            ),
        ]

    _SECRET_FIELDS = ("key", "http_user", "http_pass")

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

    def _account_encryption_key(self):
        if not self.connection_id:
            raise ValueError("A saved WordPress connection is required")
        try:
            key = self.connection.account.get_encryption_key()
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError(
                "The WordPress connection account has no usable encryption key"
            ) from error
        if not key:
            raise ValueError(
                "The WordPress connection account has no usable encryption key"
            )
        return key

    def _encrypt_secret(self, value):
        if value in (None, "", b""):
            return None
        if not isinstance(value, str):
            raise ValueError("WordPress credentials must be plaintext strings")
        ciphertext = bs_encrypt(value, self._account_encryption_key())
        if not ciphertext:
            raise ValueError("Unable to encrypt WordPress credential")
        return WORDPRESS_SECRET_PREFIX + bytes(ciphertext).decode("ascii")

    def _decrypt_secret(self, field_name):
        if field_name not in self._SECRET_FIELDS:
            raise ValueError("Unknown WordPress credential field")
        value = self._normalize_secret_value(getattr(self, field_name, None))
        if not isinstance(value, str) or not value.startswith(WORDPRESS_SECRET_PREFIX):
            return None
        return bs_decrypt(
            value[len(WORDPRESS_SECRET_PREFIX) :].encode("ascii"),
            self._account_encryption_key(),
        )

    def get_key(self):
        return self._decrypt_secret("key")

    def get_http_user(self):
        return self._decrypt_secret("http_user")

    def get_http_pass(self):
        return self._decrypt_secret("http_pass")

    def save(self, *args, **kwargs):
        changed_secret_fields = set()
        for field_name in self._SECRET_FIELDS:
            value = self._normalize_secret_value(getattr(self, field_name, None))
            if value in (None, "", b""):
                if field_name == "key":
                    raise ValueError("A WordPress integration key is required")
                normalized = None
            elif isinstance(value, str):
                normalized = value
                if not normalized.startswith(WORDPRESS_SECRET_PREFIX):
                    normalized = self._encrypt_secret(normalized)
                setattr(self, field_name, normalized)
                if self._decrypt_secret(field_name) is None:
                    raise ValueError(
                        f"{field_name} ciphertext could not be decrypted for this account"
                    )
            else:
                raise ValueError(f"{field_name} is not versioned ciphertext")
            if normalized != value:
                changed_secret_fields.add(field_name)
            setattr(self, field_name, normalized)

        update_fields = kwargs.get("update_fields")
        if update_fields is not None and changed_secret_fields:
            kwargs["update_fields"] = set(update_fields) | changed_secret_fields
        return super().save(*args, **kwargs)

    @staticmethod
    def _normalized_base_url(value):
        """Return an origin-bound WordPress base URL without ambient URL data."""

        if not isinstance(value, str) or not value.strip():
            raise ValueError("A WordPress URL is required")
        parts = urlsplit(value.strip())
        if parts.scheme.lower() != "https" or not parts.hostname:
            raise ValueError("WordPress credentials require an HTTPS URL")
        if parts.username is not None or parts.password is not None:
            raise ValueError("WordPress URL must not contain credentials")
        if parts.query or parts.fragment:
            raise ValueError("WordPress URL must not contain a query or fragment")

        host = parts.hostname.rstrip(".").lower()
        try:
            host = host.encode("idna").decode("ascii")
            port = parts.port
        except (UnicodeError, ValueError) as error:
            raise ValueError("WordPress URL has an invalid host or port") from error
        if not host or any(ord(character) < 32 for character in parts.path):
            raise ValueError("WordPress URL is invalid")
        rendered_host = f"[{host}]" if ":" in host else host
        if port is not None:
            rendered_host = f"{rendered_host}:{port}"
        path = (parts.path or "").rstrip("/")
        return urlunsplit((parts.scheme.lower(), rendered_host, path, "", ""))

    def request(self, route, *, params=None, data=None, stream=False, timeout=None):
        """Call one exact WordPress origin without placing credentials in its URL."""

        from apps.api.v1.utils.wordpress_transport import (
            pinned_wordpress_get,
            require_wordpress_protocol_v2,
            resolve_wordpress_target,
        )

        # Refuse the legacy public plugin contract before resolving a target or
        # decrypting any credential.  Re-enabling requires the reviewed v2 protocol;
        # there is deliberately no query-string-key compatibility mode.
        require_wordpress_protocol_v2()
        if route not in _WORDPRESS_ROUTES:
            raise ValueError("Unsupported WordPress API route")
        supplied = data or {}
        base_url = self._normalized_base_url(supplied.get("url", self.url))

        # Resolve and approve the target before decrypting any credential. The
        # transport later connects to this exact IP and never resolves again.
        target = resolve_wordpress_target(base_url)
        key = supplied.get("key") if data is not None else self.get_key()
        http_user = (
            supplied.get("http_user") if data is not None else self.get_http_user()
        )
        http_pass = (
            supplied.get("http_pass") if data is not None else self.get_http_pass()
        )
        if not isinstance(key, str) or not key:
            raise ValueError("WordPress integration key is unavailable")
        if bool(http_user) != bool(http_pass):
            raise ValueError(
                "WordPress HTTP username and password must be configured together"
            )

        headers = self.get_client()
        headers[WORDPRESS_KEY_HEADER] = key
        query = {"rest_route": f"/backupsheep/updraftplus/{route}"}
        for name, value in (params or {}).items():
            if str(name).lower() in {"key", "x-backupsheep-key", "authorization"}:
                raise ValueError("WordPress credentials must not be query parameters")
            query[name] = value
        request_kwargs = {
            "params": query,
            "headers": headers,
            "auth": (http_user, http_pass) if http_user and http_pass else None,
            "stream": stream,
        }
        if timeout is not None:
            request_kwargs["timeout"] = timeout
        return pinned_wordpress_get(
            target,
            params=request_kwargs["params"],
            headers=request_kwargs["headers"],
            auth=request_kwargs["auth"],
            stream=request_kwargs["stream"],
            timeout=request_kwargs.get("timeout"),
        )

    def get_client(self):
        return {
            "User-Agent": "BackupSheep-WordPress/1",
            "content-type": "application/json",
        }

    def get_auth(self, data=None):
        if data:
            http_user = data.get("http_user")
            http_pass = data.get("http_pass")
        else:
            http_user = self.get_http_user()
            http_pass = self.get_http_pass()
        auth = None
        if http_user and http_pass:
            auth = (http_user, http_pass)
        return auth

    def validate(self, data=None, check_errors=None, raise_exp=None):
        from bs4 import BeautifulSoup
        import time

        if data:
            url = data["url"]
        else:
            url = self.url
        safe_url = self._normalized_base_url(url)
        try:
            result = self.request(
                "validate",
                params={"t": time.time()},
                data=data,
                timeout=60,
            )
        except Exception as e:
            if check_errors:
                if "handshake failure" in e.__str__():
                    raise ValueError(
                        "SSL handshake failed. "
                        f"Please use our website and database integration for this website. Validation URL: {safe_url}"
                    )
                elif "retries exceeded with url" in e.__str__():
                    raise ValueError(
                        f"Unable to connect to your WordPress website due to timeout. If you are using Cloudflare,"
                        f" Stackpath or any security plugin in your WordPress then please allow backup server IPs."
                        f"  Validation URL: {safe_url}"
                    )
                else:
                    raise ValueError(
                        f"Unable to connect to your website. If you are using Cloudflare, "
                        f"Stackpath or any security plugin in your WordPress then please allow backup "
                        f"server IPs or you can"
                        f" use our website and database integration for this website. Validation URL: {safe_url}"
                    )
            else:
                return False
        try:
            result.raise_for_status()
        except Exception as e:
            if check_errors:
                raise ValueError(
                    f"WordPress validation returned HTTP {result.status_code}. "
                    f"Validation URL: {safe_url}"
                ) from e
            return False
        if result.status_code == 200:
            try:
                if result.json().get("plugins", {}).get("backupsheep") and result.json().get("plugins", {}).get(
                    "updraftplus"
                ):
                    return True
                elif not result.json().get("validate_backupsheep_key"):
                    raise ValueError(
                        "Invalid WordPress Key. Please get correct WordPress Key from your integration "
                        f"and add it to BackupSheep Wordpress plugin. Validation URL: {safe_url}"
                    )
                elif not result.json().get("plugins", {}).get("backupsheep") and not result.json().get(
                    "plugins", {}
                ).get("updraftplus"):
                    raise ValueError(f"Your BackupSheep & UpdraftPlus plugins are not active. Validation URL: {safe_url}")
                elif not result.json().get("plugins", {}).get("backupsheep") and not result.json().get(
                    "plugins", {}
                ).get("updraftplus"):
                    raise ValueError(f"Your BackupSheep & UpdraftPlus plugins are not active. Validation URL: {safe_url}")
                elif not result.json().get("plugins", {}).get("backupsheep"):
                    raise ValueError(f"Your BackupSheep plugin is not active. Validation URL: {safe_url}")
                elif not result.json().get("plugins", {}).get("updraftplus"):
                    raise ValueError(f"Your UpdraftPlus plugin is not active. Validation URL: {safe_url}")
            except JSONDecodeError:
                if check_errors:
                    raise ValueError(
                        f"Invalid JSON response. If you are using Cloudflare then add backup server IPs"
                        f"to web application firewall. Also check your .htaccess file on your web server."
                        f" Validation URL: {safe_url}"
                    )
                else:
                    return False
            except Exception as e:
                if check_errors:
                    raise ValueError(e.__str__())
                else:
                    return False
        elif result.status_code == 404:
            if result.json().get("rest_no_route") == "rest_no_route":
                raise ValueError(
                    "Please install BackupSheep and UpdraftPlus plugin. "
                    f"Validation URL: {safe_url}"
                )
        else:
            if check_errors:
                soup = BeautifulSoup(result.text)
                raise ValueError(soup.get_text())
            else:
                return None


class CoreAuthBasecamp(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_basecamp", on_delete=models.CASCADE)
    access_token = models.BinaryField(null=True)
    refresh_token = models.BinaryField(null=True)
    token_type = models.CharField(max_length=255, default="Bearer")
    expiry = models.DateTimeField(null=True)
    identity_id = models.CharField(max_length=255)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_auth_basecamp"

    def get_client(self):
        encryption_key = self.connection.account.get_encryption_key()

        access_token = bs_decrypt(self.access_token, encryption_key)
        token_type = self.token_type

        client = {
            "Authorization": f"{token_type.capitalize()} {access_token}",
            "content-type": "application/json"
        }

        return client

    def get_refresh_token(self):
        from django.conf import settings
        from datetime import datetime
        from apps.api.v1.utils.oauth_security import validated_https_endpoint

        encryption_key = self.connection.account.get_encryption_key()

        refresh_token = bs_decrypt(self.refresh_token, encryption_key)

        params = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": settings.BASECAMP_CLIENT_ID,
            "client_secret": settings.BASECAMP_CLIENT_SECRET,
            # "redirect_uri": f"{settings.APP_URL + settings.BASECAMP_REDIRECT_URL}",
        }

        token_endpoint = validated_https_endpoint(
            settings.BASECAMP_TOKEN_ENDPOINT,
            allowed_hostnames={"launchpad.37signals.com"},
            allowed_paths={"/authorization/token"},
        )
        if token_endpoint is None:
            return False

        token_request = requests.post(
            token_endpoint,
            data=params,
            headers={"Accept": "application/json"},
            allow_redirects=False,
            verify=True,
            timeout=request_timeout(),
        )

        if token_request.status_code == 200:
            token_data = token_request.json()
            self.access_token = bs_encrypt(token_data["access_token"], encryption_key)
            if token_data.get("refresh_token"):
                self.refresh_token = bs_encrypt(token_data["refresh_token"], encryption_key)
            self.expiry = datetime.fromtimestamp((int(time.time()) + int(token_data["expires_in"])), tz=timezone.utc)
            self.save()
            return True
        return False

    def validate(self, data=None, check_errors=None, raise_exp=None):
        url = "https://launchpad.37signals.com/authorization.json"

        headers = self.get_client()

        response = requests.request(
            "GET",
            url,
            headers=headers,
            data={},
            allow_redirects=False,
            verify=True,
            timeout=request_timeout(),
        )

        if response.status_code == 200:
            return True
        else:
            return False

    def get_eligible_objects(self):
        eligible_objects = []

        url = "https://launchpad.37signals.com/authorization.json"

        headers = self.get_client()

        response = requests.request("GET", url, headers=headers, data={})

        if response.status_code == 200:
            data = response.json()

            for account in data.get("accounts"):
                url = f"{account['href']}/projects.json"
                headers = self.get_client()
                project_response = requests.request("GET", url, headers=headers, data={})

                if project_response.status_code == 200:
                    projects = project_response.json()
                    for project in projects:
                        eligible_objects.append(
                            {
                                "id": project["id"],
                                "name": project["name"],
                                "description": project["description"],
                                "account_id": account["id"],
                                "account_name": account["name"],
                                "account_product": account["product"],
                            }
                        )
        return eligible_objects

class CoreConnectionStatus(models.Model):
    code = models.CharField(max_length=64, unique=True)
    private = models.BooleanField(default=False)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_connection_status"


class CoreConnectionLocation(UtilBase):
    code = models.CharField(max_length=64, unique=True)
    ip_address = models.GenericIPAddressField(null=True)
    ip_address_v6 = models.GenericIPAddressField(null=True)
    location = models.CharField(max_length=64, null=True)
    image_url = models.TextField(null=True)
    api_endpoint = models.CharField(max_length=255, null=True)
    api_url = models.URLField(null=True)
    queue = models.CharField(max_length=64, null=True)
    position = models.IntegerField(null=True)
    integrations = models.ManyToManyField(
        CoreIntegration,
        related_name="locations",
        through="CoreConnectionLocationIntegration",
    )
    task_list = models.JSONField(null=True)

    class Meta:
        db_table = "core_connection_location"
        verbose_name = "Location"
        verbose_name_plural = "Locations"
        ordering = ["position"]

    def compile_url(self, path):
        if "node-web-" in settings.SERVER_CODE:
            url = f"{self.api_url}{path}"
        elif settings.SERVER_CODE == "local":
            url = f"{settings.APP_URL}{path}"
        else:
            url = f"{self.api_url}{path}"
        return url

    # Throttle for refresh_local_ip_addresses(): the cache key's TTL doubles as the
    # re-check interval -- 24h after a successful refresh, ~15 min after any failure
    # so a lookup-service outage doesn't get hammered on every request.
    LOCAL_IP_CACHE_KEY = "core_connection_location_local_ip_refresh"
    LOCAL_IP_SUCCESS_TTL = 60 * 60 * 24
    LOCAL_IP_FAILURE_TTL = 60 * 15

    @classmethod
    def refresh_local_ip_addresses(cls):
        """Detect this server's public IPv4/IPv6 and persist them on the self-hosted
        ("local") location, so the connection-setup UI can show them for firewall
        allow-listing. Throttled via the cache and never raises -- a lookup failure
        must not break the request or task that triggered it."""
        try:
            location = cls.objects.filter(code="local").first()
            if location is None:
                return
            # Atomic gate: only the first caller within the TTL performs the lookups.
            if not cache.add(cls.LOCAL_IP_CACHE_KEY, True, timeout=cls.LOCAL_IP_FAILURE_TTL):
                return

            failed = False
            update_fields = []

            try:
                response = requests.get(settings.PUBLIC_IPV4_LOOKUP_URL, timeout=5)
                ip4 = str(ipaddress.IPv4Address(response.text.strip()))
                if location.ip_address != ip4:
                    location.ip_address = ip4
                    update_fields.append("ip_address")
            except Exception as e:
                # Leave the stored value alone on transient errors.
                failed = True
                print(f"local location IPv4 lookup failed: {e}")

            try:
                response = requests.get(settings.PUBLIC_IPV6_LOOKUP_URL, timeout=5)
                ip6 = str(ipaddress.IPv6Address(response.text.strip()))
                if location.ip_address_v6 != ip6:
                    location.ip_address_v6 = ip6
                    update_fields.append("ip_address_v6")
            except Exception as e:
                failed = True
                print(f"local location IPv6 lookup failed: {e}")

            if update_fields:
                location.save(update_fields=update_fields)
            if not failed:
                cache.set(cls.LOCAL_IP_CACHE_KEY, True, timeout=cls.LOCAL_IP_SUCCESS_TTL)
        except Exception as e:
            print(f"refresh_local_ip_addresses failed: {e}")


class CoreConnectionLocationIntegration(TimeStampedModel):
    def __str__(self):
        return "%s --  %s " % (self.integration.name, self.location.name)

    location = models.ForeignKey(CoreConnectionLocation, on_delete=models.PROTECT)
    integration = models.ForeignKey(CoreIntegration, on_delete=models.PROTECT)

    class Meta:
        db_table = "core_connection_location_mtm_integrations"
        verbose_name = "Integration Location"
        verbose_name_plural = "Integration Locations"


class CoreConnection(TimeStampedModel):
    class Status(models.IntegerChoices):
        ACTIVE = 1, "Active"
        PENDING = 2, "Pending"
        SUSPENDED = 3, "Suspended"
        PAUSED = 4, "Paused"
        DELETE_REQUESTED = 5, "Delete Requested"
        TOKEN_REFRESH_FAIL = 6, "Token Refresh Failed"

    class Notification(models.IntegerChoices):
        NOT_SENT = 1, "Not Sent"
        SENT = 2, "Sent"

    account = models.ForeignKey(CoreAccount, related_name="connections", on_delete=models.CASCADE)
    old_status = models.ForeignKey(
        CoreConnectionStatus,
        related_name="connections",
        on_delete=models.CASCADE,
        null=True,
    )
    status = models.IntegerField(choices=Status.choices, default=Status.ACTIVE)
    notification = models.IntegerField(choices=Notification.choices, default=Notification.NOT_SENT)
    integration = models.ForeignKey(CoreIntegration, related_name="connections", on_delete=models.PROTECT)
    location = models.ForeignKey(
        CoreConnectionLocation,
        related_name="connections",
        on_delete=models.PROTECT,
        null=True,
    )
    name = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    added_by = models.ForeignKey(
        CoreMember,
        related_name="added_connections",
        on_delete=models.CASCADE,
        null=True,
    )

    class Meta:
        db_table = "core_connection"

    def update_scheduled_backup_locations(self, location):
        pass

        # from apps.console.node.models import CoreSchedule
        #
        # for schedule in CoreSchedule.objects.filter(node__connection_id=self.id):
        #     if schedule.celery_periodic_task:
        #         if schedule.celery_periodic_task.queue:
        #             schedule.celery_periodic_task.queue = (
        #                 schedule.celery_periodic_task.queue.replace(
        #                     schedule.node.connection.location.queue, location.queue
        #                 )
        #             )
        #             schedule.celery_periodic_task.save()
        #             PeriodicTasks.changed(schedule.celery_periodic_task)

    # Todo: Also terminate current running backups.
    def delete_requested(self):
        self.status = CoreConnection.Status.DELETE_REQUESTED
        self.save()
        for node in self.nodes.all():
            node.delete_requested()

    def validate(self, check_errors=None, raise_exp=None):
        if hasattr(self, f"auth_{self.integration.code}"):
            auth_object = getattr(self, f"auth_{self.integration.code}")
            return auth_object.validate(check_errors=check_errors, raise_exp=raise_exp)

    def backup_ready_to_initiate(self):
        launch_ok = self.status == self.Status.ACTIVE
        return launch_ok

    def total_nodes(self):
        return self.nodes.filter().count()

    def type(self):
        return  self.integration.type

    @property
    def incremental_backup_available(self):
        if self.integration.code == "website":
            return self.auth_website.use_public_key or self.auth_website.use_private_key
