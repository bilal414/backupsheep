from django.db import transaction
from rest_framework import serializers

from apps._tasks.integration.upcloud import list_upcloud_servers
from apps.api.v1.node.serializers import (
    CoreCloudNodeWriteSerializer,
    CoreNodeReadSerializer,
)
from apps.console.account.models import CoreAccount
from apps.console.connection.models import CoreConnection
from apps.console.node.models import (
    CoreNode,
    CoreSchedule,
    CoreUpCloud,
    _BackupProviderError,
)
from apps.console.utils.models import UtilBackup


def _upcloud_resource_error(error):
    """Turn provider discovery failures into a bounded serializer error."""
    if isinstance(error, _BackupProviderError):
        detail = serializers.ErrorDetail(str(error), code=error.code)
    else:
        detail = serializers.ErrorDetail(
            "UpCloud resource discovery failed safely. Verify the connection and try again.",
            code="PROVIDER_MALFORMED_RESPONSE",
        )
    raise serializers.ValidationError({"unique_id": [detail]}) from None


def _discover_upcloud_server(connection, resource_id):
    """Return the provider-authoritative server payload for one immutable UUID."""
    try:
        resources = list_upcloud_servers(
            connection.auth_upcloud.get_verified_client()
        )
        matches = []
        for resource in resources:
            if not isinstance(resource, dict) or not resource.get("uuid"):
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            if str(resource["uuid"]).strip() == resource_id:
                matches.append(resource)
    except _BackupProviderError:
        raise
    except Exception:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        ) from None

    if not matches:
        raise _BackupProviderError("PROVIDER_NOT_FOUND")
    if len(matches) != 1:
        raise _BackupProviderError("PROVIDER_DUPLICATE_MATCH", manual_review=True)

    provider = dict(matches[0])
    if str(provider.get("uuid") or "").strip() != resource_id:
        raise _BackupProviderError(
            "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True
        )
    provider.update(
        {
            "_bs_unique_id": resource_id,
            "_bs_name": str(provider.get("title") or resource_id),
            "_bs_region": provider.get("zone"),
            "_bs_size": None,
            "_bs_resource_type": "cloud",
        }
    )
    return provider


def _upcloud_duplicate_exists(connection, resource_id):
    """Provider IDs are owned once per account, including across connections."""
    return CoreUpCloud.objects.filter(
        node__connection__account=connection.account,
        node__connection__integration__code="upcloud",
        unique_id=resource_id,
    ).exclude(node__status=CoreNode.Status.DELETE_COMPLETED).exists()


class CoreCloudUpCloudReadSerializer(serializers.ModelSerializer):
    node = CoreNodeReadSerializer(read_only=True)
    totals = serializers.SerializerMethodField()

    class Meta:
        model = CoreUpCloud
        fields = "__all__"
        datatables_always_serialize = ("id", "unique_id", "notes")

    @staticmethod
    def get_totals(obj):
        return {
            "backups": obj.backups.filter(
                status=UtilBackup.Status.COMPLETE
            ).count(),
            "schedules": CoreSchedule.objects.filter(
                node=obj.node,
                status=CoreSchedule.Status.ACTIVE,
            ).count(),
        }


class CoreCloudUpCloudWriteSerializer(serializers.ModelSerializer):
    node = CoreCloudNodeWriteSerializer(write_only=True)

    class Meta:
        model = CoreUpCloud
        fields = "__all__"

    def validate(self, data):
        instance = getattr(self, "instance", None)
        node_data = data.get("node") or {}
        connection = node_data.get("connection")
        if connection is None and instance is not None:
            connection = instance.node.connection
        if connection is None or connection.integration.code != "upcloud":
            raise serializers.ValidationError(
                "Select an UpCloud connection for this server."
            )

        initial_data = getattr(self, "initial_data", {})
        if (
            isinstance(initial_data, dict)
            and "resource_type" in initial_data
            and initial_data.get("resource_type") not in (None, "", "cloud")
        ):
            raise serializers.ValidationError(
                {"resource_type": "The selected provider resource is not a server."}
            )

        resource_id = data.get("unique_id")
        if resource_id is None and instance is not None:
            resource_id = instance.unique_id
        resource_id = str(resource_id or "").strip()
        if not resource_id:
            raise serializers.ValidationError(
                {"unique_id": "Select an UpCloud server to link."}
            )

        if instance is not None:
            if resource_id != str(instance.unique_id):
                raise serializers.ValidationError(
                    {"unique_id": "The linked UpCloud server ID is immutable."}
                )
            if connection.pk != instance.node.connection_id:
                raise serializers.ValidationError(
                    {"node": "The linked UpCloud connection is immutable."}
                )
            if "metadata" in data and data["metadata"] != instance.metadata:
                raise serializers.ValidationError(
                    {"metadata": "Provider discovery metadata cannot be replaced."}
                )
            return data

        try:
            provider = _discover_upcloud_server(connection, resource_id)
        except Exception as error:
            _upcloud_resource_error(error)

        if _upcloud_duplicate_exists(connection, resource_id):
            raise serializers.ValidationError(
                {"unique_id": "This UpCloud server is already linked."}
            )
        if data.get("metadata") not in (None, provider):
            raise serializers.ValidationError(
                {
                    "metadata": "The selected UpCloud server metadata is not provider-authoritative."
                }
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
        if _upcloud_duplicate_exists(connection, validated_data["unique_id"]):
            raise serializers.ValidationError(
                {"unique_id": "This UpCloud server is already linked."}
            )
        node["connection"] = connection
        validated_data["node"] = CoreNode.objects.create(**node)
        return CoreUpCloud.objects.create(**validated_data)

    def update(self, instance, validated_data):
        node = validated_data.pop("node", None)
        if node is not None:
            super().update(instance.node, node)
        return super().update(instance, validated_data)
