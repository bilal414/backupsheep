import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault,
    IntegrationDefault,
    bs_decrypt,
    bs_encrypt,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreConnectionLocation,
    CoreAuthOracle,
)
from apps.console.node.models import CoreNode
from apps.console.api.v1.account.serializers import CoreAccountSerializer
from apps.console.api.v1.connection.serializers import (
    CoreIntegrationSerializer,
    CoreConnectionLocationSerializer,
)


class CoreAuthOracleReadSerializer(serializers.ModelSerializer):
    private_key = serializers.SerializerMethodField()

    class Meta:
        model = CoreAuthOracle
        fields = (
            "id",
            "user",
            "fingerprint",
            "tenancy",
            "region",
            "profile",
            "private_key",
        )
        datatables_always_serialize = (
            "id",
            "user",
            "fingerprint",
            "tenancy",
            "region",
            "profile",
            "private_key",
        )

    def get_private_key(self, obj):
        return bs_decrypt(obj.private_key, self.context["encryption_key"])


class CoreOracleConnectionReadSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer(read_only=True)
    integration = CoreIntegrationSerializer(read_only=True)
    location = CoreConnectionLocationSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    nodes_total = serializers.SerializerMethodField()
    cloud_total = serializers.SerializerMethodField()
    volume_total = serializers.SerializerMethodField()
    auth_oracle = CoreAuthOracleReadSerializer(read_only=True)

    class Meta:
        model = CoreConnection
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "auth_oracle",
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


class CoreAuthOracleWriteSerializer(serializers.ModelSerializer):
    user = serializers.CharField(write_only=True)
    fingerprint = serializers.CharField(write_only=True)
    tenancy = serializers.CharField(write_only=True)
    region = serializers.CharField(write_only=True)
    private_key = serializers.CharField(write_only=True)
    connection = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreAuthOracle
        fields = "__all__"

    def validate(self, data):
        auth_oracle = CoreAuthOracle()

        if not auth_oracle.validate(data, check_errors=True):
            raise serializers.ValidationError("Unable to authenticate. Please verify your authentication data.")

        data["private_key"] = bs_encrypt(data["private_key"], self.context["encryption_key"])
        return data


class CoreOracleConnectionWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentMemberDefault()))
    account = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentAccountDefault()))
    integration = serializers.HiddenField(default=serializers.CreateOnlyDefault(IntegrationDefault("oracle")))
    location = serializers.PrimaryKeyRelatedField(queryset=CoreConnectionLocation.objects.filter())
    auth_oracle = CoreAuthOracleWriteSerializer()

    class Meta:
        model = CoreConnection
        fields = "__all__"

    def create(self, validated_data):
        auth_oracle = validated_data.pop("auth_oracle", [])
        instance = CoreConnection.objects.create(**validated_data)
        auth_oracle["connection"] = instance
        CoreAuthOracle.objects.create(**auth_oracle)
        return instance

    def update(self, instance, validated_data):
        if validated_data.get("location"):
            if instance.location != validated_data["location"]:
                instance.update_scheduled_backup_locations(validated_data["location"])
        auth_oracle = validated_data.pop("auth_oracle", [])
        if len(auth_oracle) > 0:
            super().update(instance.auth_oracle, auth_oracle)
        instance = super().update(instance, validated_data)
        return instance
