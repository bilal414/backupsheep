import boto.ec2
import pytz
from django.conf import settings
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.account.models import CoreAccount
from apps.console.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault,
    IntegrationDefault, bs_encrypt, bs_decrypt,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
    CoreAuthHetzner,
)
from apps.console.node.models import CoreNode
from apps.console.api.v1.account.serializers import CoreAccountSerializer
from apps.console.api.v1.connection.serializers import CoreIntegrationSerializer, CoreConnectionLocationSerializer



class CoreAuthHetznerReadSerializer(serializers.ModelSerializer):
    api_key = serializers.SerializerMethodField()

    class Meta:
        model = CoreAuthHetzner
        fields = (
            "id",
            "api_key",
        )
        datatables_always_serialize = (
            "id",
            "api_key",
        )

    def get_api_key(self, obj):
        return bs_decrypt(obj.api_key, self.context["encryption_key"])


class CoreHetznerConnectionReadSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer(read_only=True)
    integration = CoreIntegrationSerializer(read_only=True)
    location = CoreConnectionLocationSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    nodes_total = serializers.SerializerMethodField()
    cloud_total = serializers.SerializerMethodField()
    volume_total = serializers.SerializerMethodField()
    auth_hetzner = CoreAuthHetznerReadSerializer(read_only=True)

    class Meta:
        model = CoreConnection
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "auth_hetzner",
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


class CoreAuthHetznerWriteSerializer(serializers.ModelSerializer):
    api_key = serializers.CharField(write_only=True)
    connection = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreAuthHetzner
        fields = "__all__"

    def validate(self, data):
        try:
            import requests

            api_key = data["api_key"]
            headers = {
                "content-type": "application/json",
                "Authorization": f"Bearer {api_key}",
            }
            result = requests.get(
                settings.HETZNER_API + "/v1/actions", headers=headers, verify=True
            )
            if result.status_code != 200:
                raise serializers.ValidationError(
                    "Unable to authenticate. "
                    "Please check your API Key and "
                    "make sure you whitelisted the BackupSheep Endpoint IP address."
                )
            data["api_key"] = bs_encrypt(api_key, self.context["encryption_key"])
        except Exception as e:
            raise serializers.ValidationError(
                "Unable to authenticate. "
                "Please check your api_key and "
                "make sure you enabled read and write permissions."
            )
        return data


class CoreHetznerConnectionWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(CurrentMemberDefault())
    )
    account = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(CurrentAccountDefault())
    )
    integration = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(IntegrationDefault("hetzner"))
    )
    location = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnectionLocation.objects.filter()
    )
    auth_hetzner = CoreAuthHetznerWriteSerializer()

    class Meta:
        model = CoreConnection
        fields = "__all__"

    def create(self, validated_data):
        auth_hetzner = validated_data.pop("auth_hetzner", [])
        instance = CoreConnection.objects.create(**validated_data)
        auth_hetzner["connection"] = instance
        CoreAuthHetzner.objects.create(**auth_hetzner)
        return instance

    def update(self, instance, validated_data):
        if validated_data.get("location"):
            if instance.location != validated_data["location"]:
                instance.update_scheduled_backup_locations(validated_data["location"])
        auth_hetzner = validated_data.pop("auth_hetzner", [])
        if len(auth_hetzner) > 0:
            super().update(instance.auth_hetzner, auth_hetzner)
        instance = super().update(instance, validated_data)
        return instance
