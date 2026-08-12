import pytz
from django.db import transaction
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.api.v1.connection.digitalocean.client import (
    DigitalOceanAPIError,
    list_eligible_objects,
)
from apps.api.v1.node.serializers import (
    CoreCloudNodeWriteSerializer,
    CoreNodeReadSerializer,
)
from apps.console.account.models import CoreAccount
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreDigitalOcean, CoreNode, CoreSchedule
from apps.console.utils.models import UtilBackup


_DIGITALOCEAN_RESOURCE_MESSAGES = {
    "CONNECTION_PROVIDER_MISMATCH": "Select a DigitalOcean connection for this server.",
    "RESOURCE_ID_REQUIRED": "Select a DigitalOcean server to link.",
    "RESOURCE_TYPE_MISMATCH": "The selected DigitalOcean resource is not a server.",
    "RESOURCE_ALREADY_LINKED": "This DigitalOcean server is already linked.",
    "PROVIDER_NOT_FOUND": "DigitalOcean could not find the requested server.",
    "PROVIDER_DUPLICATE_MATCH": "DigitalOcean returned multiple matches for this server.",
    "PROVIDER_MALFORMED_RESPONSE": "DigitalOcean returned an incomplete or malformed server response.",
    "PROVIDER_OWNERSHIP_MISMATCH": "The DigitalOcean server did not match the expected resource type or identity.",
    "PROVIDER_AUTH_FAILED": "DigitalOcean rejected the configured credentials or permissions.",
    "PROVIDER_RATE_LIMIT": "DigitalOcean rate-limited resource discovery.",
    "PROVIDER_TIMEOUT": "DigitalOcean resource discovery timed out.",
    "PROVIDER_TRANSIENT_OUTAGE": "DigitalOcean is temporarily unavailable.",
    "PROVIDER_REQUEST_FAILED": "DigitalOcean rejected resource discovery.",
    "PROVIDER_RECONCILIATION_REQUIRED": "DigitalOcean resource discovery requires reconciliation.",
}


def _digitalocean_error(code, *, field="unique_id"):
    code = str(code)
    if code not in _DIGITALOCEAN_RESOURCE_MESSAGES:
        code = "PROVIDER_MALFORMED_RESPONSE"
    detail = serializers.ErrorDetail(
        _DIGITALOCEAN_RESOURCE_MESSAGES[code],
        code=code,
    )
    raise serializers.ValidationError({field: [detail]}) from None


def _raise_digitalocean_resource_error(error):
    if isinstance(error, DigitalOceanAPIError):
        _digitalocean_error(error.code)
    _digitalocean_error("PROVIDER_MALFORMED_RESPONSE")


def _validate_submitted_metadata(metadata, resource_id):
    """Treat browser metadata as assertions, never as provider authority.

    The connection discovery endpoint historically emits numeric helper IDs and
    no explicit resource type.  Accept that exact payload and stale descriptive
    fields, but reject any identity or type field that contradicts the selected
    server.  Fresh provider discovery always replaces this payload before save.
    """
    if metadata is None:
        return
    if not isinstance(metadata, dict):
        _digitalocean_error("PROVIDER_MALFORMED_RESPONSE", field="metadata")

    for key in ("id", "_bs_unique_id"):
        value = metadata.get(key)
        if value not in (None, "") and str(value).strip() != resource_id:
            _digitalocean_error("PROVIDER_OWNERSHIP_MISMATCH", field="metadata")

    for key in ("resource_type", "_bs_resource_type"):
        value = metadata.get(key)
        if value in (None, ""):
            continue
        if str(value).strip().casefold() not in {"cloud", "droplet"}:
            _digitalocean_error("PROVIDER_OWNERSHIP_MISMATCH", field="metadata")


def _discover_digitalocean_server(connection, resource_id):
    """Rediscover one server from the provider's authoritative inventory."""
    try:
        resources = list_eligible_objects(
            headers=connection.auth_digitalocean.get_verified_client(),
            object_type="cloud",
        )
        if not isinstance(resources, list):
            raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")

        matches = []
        for resource in resources:
            if not isinstance(resource, dict):
                raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
            provider_id = resource.get("id")
            helper_id = resource.get("_bs_unique_id")
            if provider_id in (None, "") and helper_id in (None, ""):
                raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
            if (
                provider_id not in (None, "")
                and helper_id not in (None, "")
                and str(provider_id).strip() != str(helper_id).strip()
            ):
                raise DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")
            candidate_id = str(
                provider_id if provider_id not in (None, "") else helper_id
            ).strip()
            if candidate_id == resource_id:
                matches.append(resource)
    except DigitalOceanAPIError:
        raise
    except Exception:
        raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE") from None

    if not matches:
        raise DigitalOceanAPIError("PROVIDER_NOT_FOUND")
    if len(matches) != 1:
        raise DigitalOceanAPIError("PROVIDER_DUPLICATE_MATCH")

    provider = dict(matches[0])
    provider_id = provider.get("id", provider.get("_bs_unique_id"))
    if str(provider_id or "").strip() != resource_id:
        raise DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")
    explicit_types = {
        str(provider[key]).strip().casefold()
        for key in ("resource_type", "_bs_resource_type")
        if provider.get(key) not in (None, "")
    }
    if explicit_types and not explicit_types.issubset({"cloud", "droplet"}):
        raise DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")

    name = provider.get("_bs_name", provider.get("name"))
    if name in (None, ""):
        name = resource_id
    if not isinstance(name, str):
        raise DigitalOceanAPIError("PROVIDER_MALFORMED_RESPONSE")
    provider["_bs_unique_id"] = resource_id
    provider["_bs_name"] = name
    provider["_bs_resource_type"] = "cloud"
    return provider


def _digitalocean_server_duplicate_exists(connection, resource_id):
    """A provider ID is linkable once per account's DigitalOcean integration."""
    return CoreDigitalOcean.objects.filter(
        node__connection__account=connection.account,
        node__connection__integration__code="digitalocean",
        unique_id=resource_id,
    ).exclude(node__status=CoreNode.Status.DELETE_COMPLETED).exists()


class CoreCloudDigitalOceanReadSerializer(serializers.ModelSerializer):
    node = CoreNodeReadSerializer(read_only=True)
    totals = serializers.SerializerMethodField()

    class Meta:
        model = CoreDigitalOcean
        fields = "__all__"
        datatables_always_serialize = ("id", "unique_id", "notes")

    @staticmethod
    def get_totals(obj):
        totals = {
            "backups": obj.backups.filter(status=UtilBackup.Status.COMPLETE).count(),
            "schedules": CoreSchedule.objects.filter(node=obj.node, status=CoreSchedule.Status.ACTIVE).count(),
        }
        return totals


class CoreCloudDigitalOceanWriteSerializer(serializers.ModelSerializer):
    node = CoreCloudNodeWriteSerializer(write_only=True)

    class Meta:
        model = CoreDigitalOcean
        fields = "__all__"

    def validate(self, data):
        instance = getattr(self, "instance", None)
        node_data = data.get("node") or {}
        connection = node_data.get("connection")
        if connection is None and instance is not None:
            connection = instance.node.connection
        if connection is None or getattr(connection.integration, "code", None) != "digitalocean":
            _digitalocean_error("CONNECTION_PROVIDER_MISMATCH", field="node")

        initial_data = getattr(self, "initial_data", {})
        resource_type = initial_data.get("resource_type") if hasattr(initial_data, "get") else None
        if resource_type not in (None, "", "cloud", "droplet"):
            _digitalocean_error("RESOURCE_TYPE_MISMATCH", field="resource_type")

        resource_id = data.get("unique_id")
        if resource_id is None and instance is not None:
            resource_id = instance.unique_id
        resource_id = str(resource_id or "").strip()
        if not resource_id:
            _digitalocean_error("RESOURCE_ID_REQUIRED")

        if instance is not None:
            if resource_id != str(instance.unique_id).strip():
                _digitalocean_error("PROVIDER_OWNERSHIP_MISMATCH")
            if connection.pk != instance.node.connection_id:
                _digitalocean_error("PROVIDER_OWNERSHIP_MISMATCH", field="node")
            if "metadata" in data and data["metadata"] != instance.metadata:
                _digitalocean_error("PROVIDER_OWNERSHIP_MISMATCH", field="metadata")
            data["unique_id"] = resource_id
            return data

        _validate_submitted_metadata(data.get("metadata"), resource_id)

        try:
            provider = _discover_digitalocean_server(connection, resource_id)
        except Exception as error:
            _raise_digitalocean_resource_error(error)

        if _digitalocean_server_duplicate_exists(connection, resource_id):
            _digitalocean_error("RESOURCE_ALREADY_LINKED")

        data["unique_id"] = resource_id
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
        if getattr(connection.integration, "code", None) != "digitalocean":
            _digitalocean_error("CONNECTION_PROVIDER_MISMATCH", field="node")
        resource_id = str(validated_data["unique_id"]).strip()
        if _digitalocean_server_duplicate_exists(connection, resource_id):
            _digitalocean_error("RESOURCE_ALREADY_LINKED")
        node["connection"] = connection
        validated_data["unique_id"] = resource_id
        validated_data["node"] = CoreNode.objects.create(**node)
        return CoreDigitalOcean.objects.create(**validated_data)

    def update(self, instance, validated_data):
        node = validated_data.pop("node", None)
        if node is not None:
            super().update(instance.node, node)
        return super().update(instance, validated_data)
