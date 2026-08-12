import pytz
from django.conf import settings
from django.db import transaction
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.account.models import CoreAccount
from apps.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault, IntegrationDefault, bs_decrypt, bs_encrypt,
)
from apps.api.v1.utils.http import request_timeout, requests
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
    CoreAuthUpCloud,
)
from apps.console.node.models import CoreNode
from apps.api.v1.account.serializers import CoreAccountSerializer
from apps.api.v1.connection.serializers import CoreIntegrationSerializer, CoreConnectionLocationSerializer



class CoreAuthUpCloudReadSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()
    password_configured = serializers.SerializerMethodField()
    api_token_configured = serializers.SerializerMethodField()

    class Meta:
        model = CoreAuthUpCloud
        fields = (
            "id",
            "username",
            "password_configured",
            "api_token_configured",
        )
        datatables_always_serialize = (
            "id",
            "username",
            "password_configured",
            "api_token_configured",
        )

    def get_username(self, obj):
        if not obj.username:
            return None
        return bs_decrypt(obj.username, self.context["encryption_key"])

    def get_password_configured(self, obj):
        return bool(obj.password)

    def get_api_token_configured(self, obj):
        return bool(obj.api_token)


class CoreUpCloudConnectionReadSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer(read_only=True)
    integration = CoreIntegrationSerializer(read_only=True)
    location = CoreConnectionLocationSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    nodes_total = serializers.SerializerMethodField()
    cloud_total = serializers.SerializerMethodField()
    volume_total = serializers.SerializerMethodField()
    auth_upcloud = CoreAuthUpCloudReadSerializer(read_only=True)

    class Meta:
        model = CoreConnection
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "auth_upcloud",
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


class CoreAuthUpCloudWriteSerializer(serializers.ModelSerializer):
    username = serializers.CharField(write_only=True, required=False)
    password = serializers.CharField(write_only=True, required=False)
    api_token = serializers.CharField(
        write_only=True,
        required=False,
        max_length=4096,
        trim_whitespace=False,
    )
    connection = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreAuthUpCloud
        fields = "__all__"

    @staticmethod
    def _provider_error(code):
        messages = {
            "PROVIDER_AUTH_FAILED": "UpCloud rejected the configured credentials or permissions.",
            "PROVIDER_MALFORMED_RESPONSE": "UpCloud returned an incomplete account response.",
            "PROVIDER_OWNERSHIP_MISMATCH": "The UpCloud account does not match the requested credential replacement.",
            "PROVIDER_RATE_LIMIT": "UpCloud rate-limited account validation.",
            "PROVIDER_TIMEOUT": "UpCloud account validation timed out. Please try again.",
            "PROVIDER_TRANSIENT_OUTAGE": "UpCloud is temporarily unavailable. Please try again.",
            "PROVIDER_REQUEST_FAILED": "UpCloud rejected account validation.",
        }
        detail = serializers.ErrorDetail(
            messages.get(code, messages["PROVIDER_REQUEST_FAILED"]),
            code=code,
        )
        return serializers.ValidationError({"credentials": [detail]})

    def validate(self, data):
        basic_supplied = {"username", "password"}.intersection(data)
        token_supplied = "api_token" in data
        is_update = bool(
            self.instance is not None
            or getattr(getattr(self, "parent", None), "instance", None) is not None
        )

        if token_supplied and basic_supplied:
            raise serializers.ValidationError(
                {"credentials": "Configure either an API token or username and password."}
            )
        if not token_supplied and not basic_supplied:
            if not is_update:
                raise serializers.ValidationError(
                    {"credentials": "An API token or username and password is required."}
                )
            return data
        if basic_supplied != {"username", "password"} and not token_supplied:
            raise serializers.ValidationError(
                {"credentials": "Username and password must be replaced together."}
            )

        result = None
        try:
            if token_supplied:
                api_token = data["api_token"]
                client = CoreAuthUpCloud.token_client(api_token)
            else:
                from requests.auth import HTTPBasicAuth

                username = data["username"]
                password = data["password"]
                client = HTTPBasicAuth(username, password)
            result = requests.get(
                settings.UPCLOUD_API + "/account",
                auth=client,
                verify=True,
                timeout=request_timeout(),
                headers={"accept": "application/json"},
                allow_redirects=False,
            )
            if result.status_code != 200:
                from apps._tasks.integration.upcloud import classify_upcloud_response

                problem = classify_upcloud_response(result)
                raise self._provider_error(
                    problem.code if problem is not None else "PROVIDER_REQUEST_FAILED"
                )
            try:
                from apps._tasks.integration.upcloud import _upcloud_json

                provider_username = CoreAuthUpCloud._account_username(
                    _upcloud_json(result)
                )
            except Exception as error:
                code = getattr(error, "code", "PROVIDER_MALFORMED_RESPONSE")
                raise self._provider_error(code) from None
            if token_supplied:
                data["api_token"] = bs_encrypt(
                    api_token, self.context["encryption_key"]
                )
                # The token remains the credential and username is the
                # encrypted, non-secret provider identity witness.
                data["username"] = bs_encrypt(
                    provider_username, self.context["encryption_key"]
                )
                data["password"] = None
            else:
                data["username"] = bs_encrypt(
                    provider_username, self.context["encryption_key"]
                )
                data["password"] = bs_encrypt(
                    password, self.context["encryption_key"]
                )
                data["api_token"] = None
        except serializers.ValidationError:
            raise
        except requests.exceptions.Timeout:
            raise self._provider_error("PROVIDER_TIMEOUT")
        except requests.exceptions.RequestException:
            raise self._provider_error("PROVIDER_TRANSIENT_OUTAGE")
        except Exception:
            raise self._provider_error("PROVIDER_MALFORMED_RESPONSE") from None
        finally:
            close = getattr(result, "close", None)
            if callable(close):
                close()
        return data


class CoreUpCloudConnectionWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentMemberDefault()))
    account = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentAccountDefault()))
    integration = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(IntegrationDefault("upcloud"))
    )
    location = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnectionLocation.objects.filter()
    )
    auth_upcloud = CoreAuthUpCloudWriteSerializer()

    class Meta:
        model = CoreConnection
        fields = "__all__"

    def create(self, validated_data):
        auth_upcloud = validated_data.pop("auth_upcloud", [])
        with transaction.atomic():
            instance = CoreConnection.objects.create(**validated_data)
            auth_upcloud["connection"] = instance
            CoreAuthUpCloud.objects.create(**auth_upcloud)
        return instance

    def update(self, instance, validated_data):
        if validated_data.get("location"):
            if instance.location != validated_data["location"]:
                instance.update_scheduled_backup_locations(validated_data["location"])
        auth_upcloud = validated_data.pop("auth_upcloud", [])
        with transaction.atomic():
            if len(auth_upcloud) > 0:
                super().update(instance.auth_upcloud, auth_upcloud)
            instance = super().update(instance, validated_data)
        return instance
