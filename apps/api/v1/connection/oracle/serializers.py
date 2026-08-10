import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.api.v1.utils.api_helpers import (
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
from apps.api.v1.account.serializers import CoreAccountSerializer
from apps.api.v1.connection.serializers import (
    CoreIntegrationSerializer,
    CoreConnectionLocationSerializer,
)


class CoreAuthOracleReadSerializer(serializers.ModelSerializer):
    private_key_configured = serializers.SerializerMethodField()

    class Meta:
        model = CoreAuthOracle
        fields = (
            "id",
            "user",
            "fingerprint",
            "tenancy",
            "region",
            "profile",
            "private_key_configured",
        )
        datatables_always_serialize = (
            "id",
            "user",
            "fingerprint",
            "tenancy",
            "region",
            "profile",
            "private_key_configured",
        )

    def get_private_key_configured(self, obj):
        return bool(obj.private_key)


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
    user = serializers.CharField(write_only=True, required=False)
    fingerprint = serializers.CharField(write_only=True, required=False)
    tenancy = serializers.CharField(write_only=True, required=False)
    region = serializers.CharField(write_only=True, required=False)
    private_key = serializers.CharField(write_only=True, required=False)
    connection = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreAuthOracle
        fields = "__all__"

    def validate(self, data):
        credential_fields = {"user", "fingerprint", "tenancy", "region", "private_key"}
        if not credential_fields.intersection(data):
            if getattr(getattr(self, "parent", None), "instance", None) is None:
                raise serializers.ValidationError(
                    {field: "This credential field is required." for field in credential_fields}
                )
            return data

        parent_instance = getattr(getattr(self, "parent", None), "instance", None)
        existing = getattr(parent_instance, "auth_oracle", None) if parent_instance else None
        combined = {}
        for field in credential_fields:
            if field in data:
                combined[field] = data[field]
            elif existing is not None:
                value = getattr(existing, field)
                if field == "private_key":
                    value = bs_decrypt(value, self.context["encryption_key"])
                combined[field] = value

        missing = [field for field in credential_fields if not combined.get(field)]
        if missing:
            raise serializers.ValidationError(
                {field: "This credential field is required." for field in missing}
            )

        auth_oracle = CoreAuthOracle()

        try:
            authenticated = auth_oracle.validate(combined, check_errors=True)
        except Exception:
            raise serializers.ValidationError(
                "Unable to authenticate. Please verify the Oracle identifiers, key, region, and permissions."
            )
        if not authenticated:
            raise serializers.ValidationError(
                "Unable to authenticate. Please verify the Oracle identifiers, key, region, and permissions."
            )

        if "private_key" in data:
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
