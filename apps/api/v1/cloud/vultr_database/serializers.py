from rest_framework import serializers

from apps.api.v1.node.serializers import (
    CoreDatabaseNodeWriteSerializer,
    CoreNodeReadSerializer,
)
from apps.console.node.models import CoreNode, CoreSchedule, CoreVultrDatabase
from apps.console.utils.models import UtilBackup


class CoreVultrDatabaseReadSerializer(serializers.ModelSerializer):
    node = CoreNodeReadSerializer(read_only=True)
    totals = serializers.SerializerMethodField()

    class Meta:
        model = CoreVultrDatabase
        fields = "__all__"
        datatables_always_serialize = ("id", "unique_id", "notes", "engine", "region", "plan")

    @staticmethod
    def get_totals(obj):
        return {
            "backups": obj.backups.filter(status=UtilBackup.Status.COMPLETE).count(),
            "schedules": CoreSchedule.objects.filter(
                node=obj.node, status=CoreSchedule.Status.ACTIVE
            ).count(),
        }


class CoreVultrDatabaseWriteSerializer(serializers.ModelSerializer):
    # A managed database has its own provider integration object and must be
    # persisted as a DATABASE node.  Using the generic cloud serializer here
    # makes schedules dispatch ``backup_vultr`` and leaves the database object
    # unreachable through CoreNode's normal backup helpers.
    node = CoreDatabaseNodeWriteSerializer(write_only=True)

    class Meta:
        model = CoreVultrDatabase
        fields = "__all__"

    def validate(self, attrs):
        node_data = attrs.get("node")
        connection = node_data.get("connection") if node_data else getattr(
            getattr(self.instance, "node", None), "connection", None
        )
        if connection is None or connection.integration.code != "vultr":
            raise serializers.ValidationError(
                {"node": {"connection": "The node connection must use Vultr."}}
            )
        return attrs

    def create(self, validated_data):
        node = validated_data.pop("node")
        validated_data["node"] = CoreNode.objects.create(**node)
        return CoreVultrDatabase.objects.create(**validated_data)

    def update(self, instance, validated_data):
        node = validated_data.pop("node", None)
        if node is not None:
            super().update(instance.node, node)
        return super().update(instance, validated_data)
