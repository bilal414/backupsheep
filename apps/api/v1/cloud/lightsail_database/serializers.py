from rest_framework import serializers

from apps.api.v1.node.serializers import (
    CoreCloudNodeWriteSerializer,
    CoreNodeReadSerializer,
)
from apps.console.node.models import CoreLightsail, CoreNode, CoreSchedule
from apps.console.utils.models import UtilBackup


class CoreCloudLightsailDatabaseReadSerializer(serializers.ModelSerializer):
    node = CoreNodeReadSerializer(read_only=True)
    totals = serializers.SerializerMethodField()

    class Meta:
        model = CoreLightsail
        fields = "__all__"
        datatables_always_serialize = ("id", "unique_id", "notes")

    @staticmethod
    def get_totals(obj):
        return {
            "backups": obj.backups.filter(
                status=UtilBackup.Status.COMPLETE
            ).count(),
            "schedules": CoreSchedule.objects.filter(
                node=obj.node, status=CoreSchedule.Status.ACTIVE
            ).count(),
        }


class CoreCloudLightsailDatabaseWriteSerializer(serializers.ModelSerializer):
    node = CoreCloudNodeWriteSerializer(write_only=True)
    resource_type = serializers.HiddenField(
        default=CoreLightsail.ResourceType.DATABASE
    )

    class Meta:
        model = CoreLightsail
        fields = "__all__"

    def validate(self, attrs):
        node_data = attrs.get("node")
        connection = (
            node_data.get("connection")
            if node_data is not None
            else getattr(getattr(self.instance, "node", None), "connection", None)
        )
        if connection is None or connection.integration.code != "lightsail":
            raise serializers.ValidationError(
                {"node": {"connection": "The node connection must use Lightsail."}}
            )
        member = getattr(getattr(self.context.get("request"), "user", None), "member", None)
        account = member.get_current_account() if member else None
        if account is None or connection.account_id != account.id:
            raise serializers.ValidationError(
                {"node": {"connection": "The connection is outside the current account."}}
            )
        try:
            connection.auth_lightsail
        except Exception as error:
            raise serializers.ValidationError(
                {"node": {"connection": "The Lightsail connection has no credentials configured."}}
            ) from error
        return attrs

    def create(self, validated_data):
        node = validated_data.pop("node", [])
        validated_data["node"] = CoreNode.objects.create(**node)
        return CoreLightsail.objects.create(**validated_data)

    def update(self, instance, validated_data):
        node = validated_data.pop("node", None)
        if node is not None:
            super().update(instance.node, node)
        return super().update(instance, validated_data)
