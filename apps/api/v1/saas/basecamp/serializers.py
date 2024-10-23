from rest_framework import serializers
from apps.console.node.models import CoreBasecamp, CoreNode, CoreSchedule
from apps.console.utils.models import UtilBackup
from apps.console.api.v1.node.serializers import (
    CoreNodeReadSerializer,
    CoreSaaSNodeWriteSerializer,
)


class CoreBasecampReadSerializer(serializers.ModelSerializer):
    node = CoreNodeReadSerializer(read_only=True)
    totals = serializers.SerializerMethodField()

    class Meta:
        model = CoreBasecamp
        fields = "__all__"

    @staticmethod
    def get_totals(obj):
        totals = {
            "backups": obj.backups.filter(status=UtilBackup.Status.COMPLETE).count(),
            "schedules": CoreSchedule.objects.filter(node=obj.node, status=CoreSchedule.Status.ACTIVE).count(),
        }
        return totals


class CoreBasecampWriteSerializer(serializers.ModelSerializer):
    node = CoreSaaSNodeWriteSerializer()

    class Meta:
        model = CoreBasecamp
        fields = "__all__"

    def create(self, validated_data):
        node = validated_data.pop("node", [])
        validated_data["node"] = CoreNode.objects.create(**node)
        instance = CoreBasecamp.objects.create(**validated_data)
        return instance

    def update(self, instance, validated_data):
        node = validated_data.pop("node", [])
        super().update(instance.node, node)
        instance = super().update(instance, validated_data)
        return instance
