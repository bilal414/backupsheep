from django.db import transaction
from rest_framework import serializers

from apps._tasks.integration.oracle import (
    OracleProviderError,
    discover_exact_oracle_object,
)
from apps.api.v1.node.serializers import (
    CoreCloudNodeWriteSerializer,
    CoreNodeReadSerializer,
)
from apps.console.account.models import CoreAccount
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreOracle, CoreSchedule
from apps.console.utils.models import UtilBackup


def _oracle_duplicate_exists(connection, resource_id):
    """Oracle resource IDs are owned once per account, across connections."""
    return CoreOracle.objects.filter(
        node__connection__account=connection.account,
        node__connection__integration__code="oracle",
        unique_id=str(resource_id),
    ).exclude(node__status=CoreNode.Status.DELETE_COMPLETED).exists()


class CoreCloudOracleReadSerializer(serializers.ModelSerializer):
    node = CoreNodeReadSerializer(read_only=True)
    totals = serializers.SerializerMethodField()

    class Meta:
        model = CoreOracle
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


class CoreCloudOracleWriteSerializer(serializers.ModelSerializer):
    node = CoreCloudNodeWriteSerializer(write_only=True)

    class Meta:
        model = CoreOracle
        fields = "__all__"

    def validate(self, data):
        instance = getattr(self, "instance", None)
        node_data = data.get("node") or {}
        connection = node_data.get("connection")
        if connection is None and instance is not None:
            connection = instance.node.connection
        integration_code = getattr(
            getattr(connection, "integration", None), "code", None
        )
        if connection is None or integration_code != "oracle":
            raise serializers.ValidationError(
                "Select an Oracle Cloud connection for this server."
            )

        resource_id = data.get("unique_id")
        if resource_id is None and instance is not None:
            resource_id = instance.unique_id
        if instance is not None:
            if str(resource_id) != str(instance.unique_id):
                raise serializers.ValidationError(
                    {"unique_id": "The linked Oracle Cloud resource is immutable."}
                )
            if connection.pk != instance.node.connection_id:
                raise serializers.ValidationError(
                    {"node": "The linked Oracle Cloud connection is immutable."}
                )
            if "metadata" in data and data["metadata"] != instance.metadata:
                raise serializers.ValidationError(
                    {"metadata": "Provider discovery metadata cannot be replaced."}
                )
            return data

        try:
            provider = discover_exact_oracle_object(
                connection.auth_oracle, "cloud", resource_id
            )
        except OracleProviderError as error:
            raise serializers.ValidationError(str(error)) from error
        if _oracle_duplicate_exists(connection, provider["_bs_unique_id"]):
            raise serializers.ValidationError(
                {"unique_id": "This Oracle Cloud server is already linked."}
            )
        data["unique_id"] = provider["_bs_unique_id"]
        data["name"] = provider["_bs_name"]
        data["metadata"] = provider
        node_data["name"] = provider["_bs_name"]
        data["node"] = node_data
        return data

    @transaction.atomic
    def create(self, validated_data):
        node = validated_data.pop("node")
        connection = CoreConnection.objects.select_for_update().select_related(
            "account", "integration"
        ).get(pk=node["connection"].pk)
        CoreAccount.objects.select_for_update().get(pk=connection.account_id)
        if _oracle_duplicate_exists(connection, validated_data["unique_id"]):
            raise serializers.ValidationError(
                {"unique_id": "This Oracle Cloud server is already linked."}
            )
        node["connection"] = connection
        validated_data["node"] = CoreNode.objects.create(**node)
        return CoreOracle.objects.create(**validated_data)

    @transaction.atomic
    def update(self, instance, validated_data):
        node = validated_data.pop("node", {})
        if node:
            super().update(instance.node, node)
        return super().update(instance, validated_data)
