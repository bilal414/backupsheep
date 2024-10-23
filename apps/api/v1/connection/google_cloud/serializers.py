import json
from json import JSONDecodeError

import boto.ec2
import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.account.models import CoreAccount
from apps.console.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault,
    IntegrationDefault,
    bs_encrypt,
    bs_decrypt,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
    CoreAuthGoogleCloud,
)
from apps.console.node.models import CoreNode
from apps.console.api.v1.account.serializers import CoreAccountSerializer
from apps.console.api.v1.connection.serializers import CoreIntegrationSerializer, CoreConnectionLocationSerializer


class CoreAuthGoogleCloudReadSerializer(serializers.ModelSerializer):
    service_key = serializers.SerializerMethodField()

    class Meta:
        model = CoreAuthGoogleCloud
        fields = (
            "id",
            "service_key",
        )
        datatables_always_serialize = (
            "id",
            "service_key",
        )

    def get_service_key(self, obj):
        return bs_decrypt(obj.service_key, self.context["encryption_key"])


class CoreGoogleCloudConnectionReadSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer(read_only=True)
    integration = CoreIntegrationSerializer(read_only=True)
    location = CoreConnectionLocationSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    nodes_total = serializers.SerializerMethodField()
    cloud_total = serializers.SerializerMethodField()
    volume_total = serializers.SerializerMethodField()
    auth_google_cloud = CoreAuthGoogleCloudReadSerializer(read_only=True)

    class Meta:
        model = CoreConnection
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "auth_google_cloud",
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


class CoreAuthGoogleCloudWriteSerializer(serializers.ModelSerializer):
    connection = serializers.PrimaryKeyRelatedField(read_only=True)
    service_key = serializers.CharField(write_only=True)

    class Meta:
        model = CoreAuthGoogleCloud
        fields = "__all__"

    def validate(self, data):
        auth_google_cloud = CoreAuthGoogleCloud()

        try:
            json.loads(data["service_key"])
        except JSONDecodeError:
            raise serializers.ValidationError({"service_key": "Please enter valid service key in JSON format."})

        if not auth_google_cloud.validate(data, check_errors=True):
            raise serializers.ValidationError("Unable to authenticate. Please verify your authentication data.")

        data["service_key"] = bs_encrypt(data["service_key"], self.context["encryption_key"])
        return data


class CoreGoogleCloudConnectionWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentMemberDefault()))
    account = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentAccountDefault()))
    integration = serializers.HiddenField(default=serializers.CreateOnlyDefault(IntegrationDefault("google_cloud")))
    location = serializers.PrimaryKeyRelatedField(queryset=CoreConnectionLocation.objects.filter())
    auth_google_cloud = CoreAuthGoogleCloudWriteSerializer()

    class Meta:
        model = CoreConnection
        fields = "__all__"

    def create(self, validated_data):
        auth_google_cloud = validated_data.pop("auth_google_cloud", [])
        instance = CoreConnection.objects.create(**validated_data)
        auth_google_cloud["connection"] = instance
        CoreAuthGoogleCloud.objects.create(**auth_google_cloud)
        return instance

    def update(self, instance, validated_data):
        if validated_data.get("location"):
            if instance.location != validated_data["location"]:
                instance.update_scheduled_backup_locations(validated_data["location"])
        auth_google_cloud = validated_data.pop("auth_google_cloud", [])
        if len(auth_google_cloud) > 0:
            super().update(instance.auth_google_cloud, auth_google_cloud)
        instance = super().update(instance, validated_data)
        return instance
