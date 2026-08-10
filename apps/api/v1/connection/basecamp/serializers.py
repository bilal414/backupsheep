import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault,
    IntegrationDefault,
    bs_encrypt,
)
from apps.api.v1.utils.http import requests
from apps.console.connection.models import (
    CoreConnection,
    CoreConnectionLocation,
    CoreAuthBasecamp,
)
from apps.api.v1.account.serializers import CoreAccountSerializer
from apps.api.v1.connection.serializers import (
    CoreIntegrationSerializer,
    CoreConnectionLocationSerializer,
)


class CoreAuthBasecampReadSerializer(serializers.ModelSerializer):
    access_token_configured = serializers.SerializerMethodField()
    refresh_token_configured = serializers.SerializerMethodField()

    class Meta:
        model = CoreAuthBasecamp
        fields = (
            "id",
            "identity_id",
            "access_token_configured",
            "refresh_token_configured",
        )

    @staticmethod
    def get_access_token_configured(obj):
        return bool(obj.access_token)

    @staticmethod
    def get_refresh_token_configured(obj):
        return bool(obj.refresh_token)


class CoreBasecampConnectionReadSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer(read_only=True)
    integration = CoreIntegrationSerializer(read_only=True)
    location = CoreConnectionLocationSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    nodes_total = serializers.SerializerMethodField()
    auth_basecamp = CoreAuthBasecampReadSerializer(read_only=True)

    class Meta:
        model = CoreConnection
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "auth_basecamp",
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


class CoreAuthBasecampWriteSerializer(serializers.ModelSerializer):
    name = serializers.CharField(write_only=True, required=False)
    access_token = serializers.CharField(write_only=True, required=False, allow_null=True)
    refresh_token = serializers.CharField(write_only=True, required=False, allow_null=True)
    metadata = serializers.JSONField(write_only=True, required=False, allow_null=True)
    connection = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreAuthBasecamp
        fields = "__all__"

    def validate(self, data):
        if "refresh_token" in data and "access_token" not in data:
            raise serializers.ValidationError(
                {"credentials": "Provide the access token when replacing the refresh token."}
            )
        if data.get("access_token"):
            try:
                response = requests.get(
                    "https://launchpad.37signals.com/authorization.json",
                    headers={"Authorization": f"Bearer {data['access_token']}"},
                )
            except Exception:
                raise serializers.ValidationError(
                    "Unable to authenticate. Basecamp is temporarily unreachable."
                )
            if response.status_code != 200:
                raise serializers.ValidationError(
                    "Unable to authenticate. Please verify the Basecamp token and permissions."
                )
        for field in ("access_token", "refresh_token"):
            if field in data and data[field]:
                data[field] = bs_encrypt(data[field], self.context["encryption_key"])
        return data


class CoreBasecampConnectionWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentMemberDefault()))
    account = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentAccountDefault()))
    integration = serializers.HiddenField(default=serializers.CreateOnlyDefault(IntegrationDefault("basecamp")))
    location = serializers.PrimaryKeyRelatedField(queryset=CoreConnectionLocation.objects.filter())
    auth_basecamp = CoreAuthBasecampWriteSerializer()

    class Meta:
        model = CoreConnection
        fields = "__all__"

    def create(self, validated_data):
        auth_basecamp = validated_data.pop("auth_basecamp", [])
        instance = CoreConnection.objects.create(**validated_data)
        auth_basecamp["connection"] = instance
        CoreAuthBasecamp.objects.create(**auth_basecamp)
        return instance

    def update(self, instance, validated_data):
        if validated_data.get("location"):
            if instance.location != validated_data["location"]:
                instance.update_scheduled_backup_locations(validated_data["location"])
        auth_basecamp = validated_data.pop("auth_basecamp", [])
        if len(auth_basecamp) > 0:
            super().update(instance.auth_basecamp, auth_basecamp)
        instance = super().update(instance, validated_data)
        return instance
