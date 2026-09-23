import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.account.models import CoreAccount
from apps.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault, IntegrationDefault, bs_encrypt,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
    CoreAuthOVHUS,
)
from apps.console.node.models import CoreNode
from apps.api.v1.account.serializers import CoreAccountSerializer
from apps.api.v1.connection.serializers import CoreIntegrationSerializer, CoreConnectionLocationSerializer
from ..ovh_oauth import build_ovh_client


class CoreAuthOVHUSReadSerializer(serializers.ModelSerializer):
    consumer_key_configured = serializers.SerializerMethodField()

    class Meta:
        model = CoreAuthOVHUS
        fields = (
            "id",
            "info_name",
            "info_email",
            "info_organization",
            "consumer_key_configured",
        )
        datatables_always_serialize = (
            "id",
            "info_name",
            "info_email",
            "info_organization",
            "consumer_key_configured",
        )

    @staticmethod
    def get_consumer_key_configured(obj):
        return bool(obj.consumer_key)


class CoreOVHUSConnectionReadSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer(read_only=True)
    integration = CoreIntegrationSerializer(read_only=True)
    location = CoreConnectionLocationSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    nodes_total = serializers.SerializerMethodField()
    cloud_total = serializers.SerializerMethodField()
    volume_total = serializers.SerializerMethodField()
    auth_ovh_us = CoreAuthOVHUSReadSerializer(read_only=True)

    class Meta:
        model = CoreConnection
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "auth_ovh_us",
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


class CoreAuthOVHUSWriteSerializer(serializers.ModelSerializer):
    consumer_key = serializers.CharField(write_only=True, required=False, allow_null=True)
    connection = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreAuthOVHUS
        fields = "__all__"

    def validate(self, data):
        if data.get("consumer_key"):
            try:
                client = build_ovh_client(
                    "ovh_us",
                    consumer_key=data["consumer_key"],
                )
                client.get("/cloud/project")
            except Exception:
                raise serializers.ValidationError(
                    "Unable to authenticate. Please verify the OVH consumer key and permissions."
                )
            data["consumer_key"] = bs_encrypt(
                data["consumer_key"], self.context["encryption_key"]
            )
        return data


class CoreOVHUSConnectionWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentMemberDefault()))
    account = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentAccountDefault()))
    integration = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(IntegrationDefault("ovh_us"))
    )
    location = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnectionLocation.objects.filter()
    )

    class Meta:
        model = CoreConnection
        fields = "__all__"

    def create(self, validated_data):
        instance = CoreConnection.objects.create(**validated_data)
        return instance

    def update(self, instance, validated_data):
        if validated_data.get("location"):
            if instance.location != validated_data["location"]:
                instance.update_scheduled_backup_locations(validated_data["location"])
        instance = super().update(instance, validated_data)
        return instance
