import pytz
from django.conf import settings
from django.db import transaction
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault,
    IntegrationDefault, bs_encrypt,
)
from apps.api.v1.utils.http import request_timeout, requests
from apps.console.connection.models import (
    CoreConnection,
    CoreConnectionLocation,
    CoreAuthDigitalOcean,
)
from apps.console.node.models import CoreNode
from apps.api.v1.account.serializers import CoreAccountSerializer
from apps.api.v1.connection.digitalocean.client import DigitalOceanAPIError
from apps.api.v1.connection.serializers import (
    CoreIntegrationSerializer,
    CoreConnectionLocationSerializer,
)


class CoreAuthDigitalOceanReadSerializer(serializers.ModelSerializer):
    api_key_configured = serializers.SerializerMethodField()

    class Meta:
        model = CoreAuthDigitalOcean
        fields = (
            "id",
            "api_key_configured",
            "info_name",
            "info_email",
            "info_uuid",
        )
        datatables_always_serialize = (
            "id",
            "api_key_configured",
            "info_name",
            "info_email",
            "info_uuid",
        )

    def get_api_key_configured(self, obj):
        return bool(obj.api_key)


class CoreDigitalOceanConnectionReadSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer(read_only=True)
    integration = CoreIntegrationSerializer(read_only=True)
    location = CoreConnectionLocationSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    nodes_total = serializers.SerializerMethodField()
    cloud_total = serializers.SerializerMethodField()
    volume_total = serializers.SerializerMethodField()
    auth_digitalocean = CoreAuthDigitalOceanReadSerializer(read_only=True)

    class Meta:
        model = CoreConnection
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "auth_digitalocean",
        )

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

    @staticmethod
    def get_timezone(obj):
        return str(get_current_timezone())

    @staticmethod
    def get_created_display(obj):
        timezone = str(get_current_timezone())
        timezone = pytz.timezone(timezone)
        date_time = obj.created.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")
        return date_time

    @staticmethod
    def get_modified_display(obj):
        timezone = str(get_current_timezone())
        timezone = pytz.timezone(timezone)
        date_time = obj.modified.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")
        return date_time

    @staticmethod
    def get_nodes_total(obj):
        return obj.nodes.count()

    @staticmethod
    def get_cloud_total(obj):
        return obj.nodes.filter(type=CoreNode.Type.CLOUD).count()

    @staticmethod
    def get_volume_total(obj):
        return obj.nodes.filter(type=CoreNode.Type.VOLUME).count()


class CoreAuthDigitalOceanWriteSerializer(serializers.ModelSerializer):
    api_key = serializers.CharField(write_only=True, required=False)
    access_token = serializers.CharField(write_only=True, required=False, allow_null=True)
    refresh_token = serializers.CharField(write_only=True, required=False, allow_null=True)
    info_uuid = serializers.CharField(read_only=True, allow_null=True)
    connection = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreAuthDigitalOcean
        fields = "__all__"

    @staticmethod
    def _provider_error(code):
        messages = {
            "PROVIDER_AUTH_FAILED": "DigitalOcean rejected the configured credentials or permissions.",
            "PROVIDER_MALFORMED_RESPONSE": "DigitalOcean returned an incomplete account response.",
            "PROVIDER_OWNERSHIP_MISMATCH": "The DigitalOcean account does not match the requested credential replacement.",
            "PROVIDER_RATE_LIMIT": "DigitalOcean rate-limited account validation.",
            "PROVIDER_TIMEOUT": "DigitalOcean account validation timed out. Please try again.",
            "PROVIDER_TRANSIENT_OUTAGE": "DigitalOcean is temporarily unavailable. Please try again.",
            "PROVIDER_REQUEST_FAILED": "DigitalOcean rejected account validation.",
        }
        detail = serializers.ErrorDetail(
            messages.get(code, messages["PROVIDER_REQUEST_FAILED"]),
            code=code,
        )
        return serializers.ValidationError({"credentials": [detail]})

    @staticmethod
    def _response_error_code(result):
        try:
            status_code = int(result.status_code)
        except (AttributeError, TypeError, ValueError):
            return "PROVIDER_MALFORMED_RESPONSE"
        if status_code in {401, 403}:
            return "PROVIDER_AUTH_FAILED"
        if status_code == 429:
            return "PROVIDER_RATE_LIMIT"
        if status_code in {408, 425}:
            return "PROVIDER_TIMEOUT"
        if status_code >= 500:
            return "PROVIDER_TRANSIENT_OUTAGE"
        return "PROVIDER_REQUEST_FAILED"

    def validate(self, data):
        legacy_supplied = {"access_token", "refresh_token"}.intersection(data)
        if "api_key" in data and legacy_supplied:
            raise serializers.ValidationError(
                {"credentials": "Configure either an API key or OAuth tokens, not both."}
            )
        if legacy_supplied and legacy_supplied != {"access_token", "refresh_token"}:
            raise serializers.ValidationError(
                {"credentials": "Access and refresh tokens must be replaced together."}
            )
        if "api_key" not in data and not legacy_supplied:
            if getattr(getattr(self, "parent", None), "instance", None) is None:
                raise serializers.ValidationError(
                    {"credentials": "An API key or OAuth token pair is required."}
                )
            return data
        result = None
        try:
            credential = data.get("api_key") or data.get("access_token")
            if (
                not isinstance(credential, str)
                or not credential.strip()
                or any(char in credential for char in "\r\n")
            ):
                raise self._provider_error("PROVIDER_AUTH_FAILED")
            headers = {
                "content-type": "application/json",
                "Authorization": f"Bearer {credential}",
            }
            result = requests.get(
                settings.DIGITALOCEAN_API + "/v2/account",
                headers=headers,
                verify=True,
                timeout=request_timeout(),
                allow_redirects=False,
            )
            if result.status_code != 200:
                raise self._provider_error(self._response_error_code(result))
            try:
                identity = CoreAuthDigitalOcean._account_identity(result.json())
            except DigitalOceanAPIError as error:
                raise self._provider_error(error.code) from None
            # Provider identity is set only after the credential has passed a
            # complete account read.  A credential replacement is the explicit
            # API path that may intentionally replace an old witness.
            data.update(identity)
            for field in ("api_key", "access_token", "refresh_token"):
                if data.get(field):
                    data[field] = bs_encrypt(data[field], self.context["encryption_key"])
        except serializers.ValidationError:
            raise
        except requests.exceptions.Timeout:
            raise serializers.ValidationError(
                "DigitalOcean authentication validation timed out. Please try again."
            )
        except requests.exceptions.RequestException:
            raise self._provider_error("PROVIDER_TRANSIENT_OUTAGE")
        except Exception:
            raise self._provider_error("PROVIDER_MALFORMED_RESPONSE") from None
        finally:
            close = getattr(result, "close", None)
            if callable(close):
                close()
        return data


class CoreDigitalOceanConnectionWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(CurrentMemberDefault())
    )
    account = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(CurrentAccountDefault())
    )
    integration = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(IntegrationDefault("digitalocean"))
    )
    location = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnectionLocation.objects.filter()
    )
    auth_digitalocean = CoreAuthDigitalOceanWriteSerializer()

    class Meta:
        model = CoreConnection
        fields = "__all__"

    def create(self, validated_data):
        auth_digitalocean = validated_data.pop("auth_digitalocean", [])
        with transaction.atomic():
            instance = CoreConnection.objects.create(**validated_data)
            auth_digitalocean["connection"] = instance
            CoreAuthDigitalOcean.objects.create(**auth_digitalocean)
        return instance

    def update(self, instance, validated_data):
        if validated_data.get("location"):
            if instance.location != validated_data["location"]:
                instance.update_scheduled_backup_locations(validated_data["location"])
        auth_digitalocean = validated_data.pop("auth_digitalocean", [])
        with transaction.atomic():
            if len(auth_digitalocean) > 0:
                super().update(instance.auth_digitalocean, auth_digitalocean)
            instance = super().update(instance, validated_data)
        return instance
