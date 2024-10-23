import boto.ec2
import boto3
import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.account.models import CoreAccount
from apps.console.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault, IntegrationDefault, bs_encrypt, bs_decrypt,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
    CoreAuthLightsail,
    CoreLightsailRegion,
)
from apps.console.node.models import CoreNode
from apps.console.api.v1.account.serializers import CoreAccountSerializer
from apps.console.api.v1.connection.serializers import CoreIntegrationSerializer, CoreConnectionLocationSerializer


class CoreLightsailRegionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreLightsailRegion
        fields = "__all__"
        datatables_always_serialize = ("id",)


class CoreAuthLightsailReadSerializer(serializers.ModelSerializer):
    region = CoreLightsailRegionSerializer()
    access_key = serializers.SerializerMethodField()
    secret_key = serializers.SerializerMethodField()

    class Meta:
        model = CoreAuthLightsail
        fields = (
            "id",
            "region",
            "access_key",
            "secret_key",
        )
        datatables_always_serialize = (
            "id",
            "access_key",
            "secret_key",
        )

    def get_access_key(self, obj):
        return bs_decrypt(obj.access_key, self.context["encryption_key"])

    def get_secret_key(self, obj):
        return bs_decrypt(obj.secret_key, self.context["encryption_key"])


class CoreLightsailConnectionReadSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer(read_only=True)
    integration = CoreIntegrationSerializer(read_only=True)
    location = CoreConnectionLocationSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    nodes_total = serializers.SerializerMethodField()
    cloud_total = serializers.SerializerMethodField()
    volume_total = serializers.SerializerMethodField()
    auth_lightsail = CoreAuthLightsailReadSerializer(read_only=True)

    class Meta:
        model = CoreConnection
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "auth_lightsail",
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

class CoreAuthLightsailWriteSerializer(serializers.ModelSerializer):
    region = serializers.PrimaryKeyRelatedField(queryset=CoreLightsailRegion.objects.filter())
    access_key = serializers.CharField(write_only=True)
    secret_key = serializers.CharField(write_only=True)
    connection = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreAuthLightsail
        fields = "__all__"

    def validate(self, data):
        try:
            region = data["region"]
            access_key = data["access_key"]
            secret_key = data["secret_key"]

            client = boto3.client(
                'lightsail',
                region_name=region.code,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
            client.get_instances()

            data["access_key"] = bs_encrypt(access_key, self.context["encryption_key"])
            data["secret_key"] = bs_encrypt(secret_key, self.context["encryption_key"])
        except Exception as e:
            raise serializers.ValidationError(
                "Unable to authenticate. "
                "Please check your access_key and secret_key and "
                "if they have valid permissions."
            )
        return data


class CoreLightsailConnectionWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentMemberDefault()))
    account = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentAccountDefault()))
    integration = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(IntegrationDefault("lightsail"))
    )
    location = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnectionLocation.objects.filter()
    )
    auth_lightsail = CoreAuthLightsailWriteSerializer()

    class Meta:
        model = CoreConnection
        fields = "__all__"

    def create(self, validated_data):
        auth_lightsail = validated_data.pop("auth_lightsail", [])
        instance = CoreConnection.objects.create(**validated_data)
        auth_lightsail["connection"] = instance
        CoreAuthLightsail.objects.create(**auth_lightsail)
        return instance

    def update(self, instance, validated_data):
        if validated_data.get("location"):
            if instance.location != validated_data["location"]:
                instance.update_scheduled_backup_locations(validated_data["location"])
        auth_lightsail = validated_data.pop("auth_lightsail", [])
        if len(auth_lightsail) > 0:
            super().update(instance.auth_lightsail, auth_lightsail)
        instance = super().update(instance, validated_data)
        return instance
