import pytz
from django.conf import settings
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault,
    IntegrationDefault, bs_encrypt,
)
from apps.api.v1.utils.http import requests
from apps.console.connection.models import (
    CoreConnection,
    CoreConnectionLocation,
    CoreAuthDigitalOcean,
)
from apps.console.node.models import CoreNode
from apps.api.v1.account.serializers import CoreAccountSerializer
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
        )
        datatables_always_serialize = (
            "id",
            "api_key_configured",
            "info_name",
            "info_email",
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
    connection = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreAuthDigitalOcean
        fields = "__all__"

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
        try:
            credential = data.get("api_key") or data.get("access_token")
            headers = {
                "content-type": "application/json",
                "Authorization": f"Bearer {credential}",
            }
            result = requests.get(
                settings.DIGITALOCEAN_API + "/v2/account", headers=headers, verify=True
            )
            if result.status_code != 200:
                raise serializers.ValidationError(
                    "Unable to authenticate. "
                    "Please check your API Key and "
                    "make sure you whitelisted the BackupSheep Endpoint IP address."
                )
            for field in ("api_key", "access_token", "refresh_token"):
                if data.get(field):
                    data[field] = bs_encrypt(data[field], self.context["encryption_key"])
        except Exception:
            raise serializers.ValidationError(
                "Unable to authenticate. "
                "Please check your api_key and "
                "make sure you enabled read and write permissions."
            )
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
        instance = CoreConnection.objects.create(**validated_data)
        auth_digitalocean["connection"] = instance
        CoreAuthDigitalOcean.objects.create(**auth_digitalocean)
        return instance

    def update(self, instance, validated_data):
        if validated_data.get("location"):
            if instance.location != validated_data["location"]:
                instance.update_scheduled_backup_locations(validated_data["location"])
        auth_digitalocean = validated_data.pop("auth_digitalocean", [])
        if len(auth_digitalocean) > 0:
            super().update(instance.auth_digitalocean, auth_digitalocean)
        instance = super().update(instance, validated_data)
        return instance
