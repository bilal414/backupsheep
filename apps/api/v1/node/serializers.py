import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.console.account.models import CoreAccount
from apps.api.v1.account.serializers import CoreAccountSerializer
from apps.api.v1.connection.serializers import CoreConnectionSerializer
from apps.api.v1.utils.api_helpers import (
    CurrentAccountDefault,
    CurrentMemberDefault,
    visible_connections,
)
from apps.api.v1.utils.api_permissions import (
    SOURCE_DISCOVERY_PERMISSIONS,
    active_current_membership,
    member_has_perm,
)
from apps.console.backup.models import CoreCloudRestore, CoreVultrDatabaseRestore
from apps.console.connection.models import CoreConnection
from apps.api.v1.backup.serializers import RestoreExecutionStatusMixin
from apps.console.node.models import (
    CoreNode,
)
from backupsheep.source_recovery_policy import require_source_backup_creation


_CONNECTION_UNAVAILABLE = (
    "Select a connection you can access in your active workspace."
)


class CurrentWorkspaceConnectionField(serializers.PrimaryKeyRelatedField):
    """Resolve connection identifiers only inside the active workspace scope.

    A global ``CoreConnection`` queryset lets a guessed primary key become a
    hydrated connection before the nested source serializer can enforce its
    tenant boundary.  Some provider serializers immediately use that hydrated
    object to obtain credentials and rediscover the provider resource.  Scope
    the relation itself so a foreign, non-current, suspended-membership, or
    group-hidden connection is indistinguishable from an unknown identifier
    and cannot reach that provider path.
    """

    default_error_messages = {
        "does_not_exist": _CONNECTION_UNAVAILABLE,
        "incorrect_type": _CONNECTION_UNAVAILABLE,
    }

    def get_queryset(self):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        member = getattr(user, "member", None)
        if member is None or not getattr(user, "is_authenticated", False):
            return CoreConnection.objects.none()

        membership = active_current_membership(member)
        if membership is None:
            return CoreConnection.objects.none()

        # ``visible_connections`` applies both the active-account boundary and
        # the member's node/group scope.  Retaining the explicit account
        # predicate documents the invariant and keeps this field fail-closed if
        # the helper's implementation evolves.
        return visible_connections(member).filter(account_id=membership.account_id)


def _is_source_creation(serializer):
    """Return whether this nested serializer is validating a create action."""

    view = serializer.context.get("view")
    action = getattr(view, "action", None)
    if action is not None:
        return action == "create"
    return serializer.instance is None


def _validate_current_workspace_connection(serializer, data):
    """Defense-in-depth for callers that bypass the DRF view permission gate."""

    connection = data.get("connection")
    if connection is None and serializer.instance is not None:
        connection = getattr(serializer.instance, "connection", None)
    if connection is None:
        return data

    request = serializer.context.get("request")
    user = getattr(request, "user", None)
    member = getattr(user, "member", None)
    membership = active_current_membership(member) if member is not None else None
    if (
        membership is None
        or connection.account_id != membership.account_id
        or not visible_connections(member).filter(pk=connection.pk).exists()
    ):
        raise serializers.ValidationError({"connection": _CONNECTION_UNAVAILABLE})

    # Source registration consumes a connection and may enter a provider
    # credential/client path.  Match inventory discovery's conjunctive
    # authorization boundary even when a serializer is invoked outside its
    # normal viewset.
    if _is_source_creation(serializer) and not all(
        member_has_perm(request, codename)
        for codename in SOURCE_DISCOVERY_PERMISSIONS
    ):
        raise serializers.ValidationError({"connection": _CONNECTION_UNAVAILABLE})
    return data


class CurrentWorkspaceNodeWriteSerializer(serializers.ModelSerializer):
    """Shared tenant and authorization boundary for nested source writes."""

    source_creation_permissions = SOURCE_DISCOVERY_PERMISSIONS
    connection = CurrentWorkspaceConnectionField(
        queryset=CoreConnection.objects.all()
    )

    def validate(self, data):
        return _validate_current_workspace_connection(self, data)


class CoreNodeSerializer(serializers.ModelSerializer):
    source_creation_permissions = SOURCE_DISCOVERY_PERMISSIONS
    connection = CurrentWorkspaceConnectionField(
        queryset=CoreConnection.objects.all()
    )
    account = CoreAccountSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    type_display = serializers.SerializerMethodField(read_only=True)
    type_details = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreNode
        fields = "__all__"
        datatables_always_serialize = ("id",)

    def validate(self, data):
        if self.instance is None:
            _validate_current_workspace_connection(self, data)
        # Existing rows stay readable and can still be paused/deleted, but a
        # generic PATCH must not reactivate a recovery-incomplete source.
        if (
            self.instance is not None
            and data.get("status") == CoreNode.Status.ACTIVE
        ):
            require_source_backup_creation(
                self.instance.connection.integration.code
            )
        return data

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

    @staticmethod
    def get_type_display(obj):
        return obj.get_type_display()

    @staticmethod
    def get_type_details(obj):
        if hasattr(obj, "database"):
            return {"name": "database", "id": obj.database.id}
        elif hasattr(obj, "vultr_database"):
            return {"name": "vultr_database", "id": obj.vultr_database.id}
        elif hasattr(obj, "website"):
            return {"name": "website", "id": obj.website.id}
        elif hasattr(obj, "wordpress"):
            return {"name": "wordpress", "id": obj.wordpress.id}
        elif hasattr(obj, "vultr"):
            return {"name": "vultr", "id": obj.vultr.id}
        elif hasattr(obj, "aws_rds"):
            return {"name": "aws_rds", "id": obj.aws_rds.id}
        elif hasattr(obj, "lightsail"):
            return {"name": "lightsail", "id": obj.lightsail.id}
        elif hasattr(obj, "aws"):
            return {"name": "aws", "id": obj.aws.id}
        elif hasattr(obj, "ovh_eu"):
            return {"name": "ovh_eu", "id": obj.ovh_eu.id}
        elif hasattr(obj, "ovh_ca"):
            return {"name": "ovh_ca", "id": obj.ovh_ca.id}
        elif hasattr(obj, "ovh_us"):
            return {"name": "ovh_us", "id": obj.ovh_us.id}
        elif hasattr(obj, "digitalocean"):
            return {"name": "digitalocean", "id": obj.digitalocean.id}
        elif hasattr(obj, "upcloud"):
            return {"name": "upcloud", "id": obj.upcloud.id}
        elif hasattr(obj, "oracle"):
            return {"name": "oracle", "id": obj.oracle.id}

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


class CoreNodeReadSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    account = serializers.HiddenField(default=CurrentAccountDefault())
    connection = CoreConnectionSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreNode
        fields = "__all__"

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

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


class CoreDatabaseNodeWriteSerializer(CurrentWorkspaceNodeWriteSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    type = serializers.HiddenField(default=CoreNode.Type.DATABASE)

    class Meta:
        model = CoreNode
        fields = "__all__"


class CoreWebsiteNodeWriteSerializer(CurrentWorkspaceNodeWriteSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    type = serializers.HiddenField(default=CoreNode.Type.WEBSITE)

    class Meta:
        model = CoreNode
        fields = "__all__"


class CoreNodeWriteSerializer(CurrentWorkspaceNodeWriteSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    type = serializers.HiddenField(default=CoreNode.Type.CLOUD)

    class Meta:
        model = CoreNode
        fields = "__all__"


class CoreSaaSNodeWriteSerializer(CurrentWorkspaceNodeWriteSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    type = serializers.HiddenField(default=CoreNode.Type.SAAS)

    class Meta:
        model = CoreNode
        fields = "__all__"

    def validate(self, data):
        data = super().validate(data)
        connection = data["connection"]
        require_source_backup_creation(connection.integration.code)
        return data


class CoreCloudNodeWriteSerializer(CurrentWorkspaceNodeWriteSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    type = serializers.HiddenField(default=CoreNode.Type.CLOUD)

    class Meta:
        model = CoreNode
        fields = "__all__"


class CoreVolumeNodeWriteSerializer(CurrentWorkspaceNodeWriteSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    type = serializers.HiddenField(default=CoreNode.Type.VOLUME)

    class Meta:
        model = CoreNode
        fields = "__all__"


class CoreCloudRestoreSerializer(RestoreExecutionStatusMixin, serializers.ModelSerializer):
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    can_resume_verification = serializers.BooleanField(read_only=True)
    verification_resume_mode = serializers.CharField(read_only=True)

    class Meta:
        model = CoreCloudRestore
        fields = "__all__"
        read_only_fields = (
            "node",
            "resource_id",
            "provider_job_id",
            "status",
            "error",
            "celery_task_id",
        )
        datatables_always_serialize = ("id",)

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

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


class CoreVultrDatabaseRestoreSerializer(
    RestoreExecutionStatusMixin, serializers.ModelSerializer
):
    """Expose Vultr fork restores through the same safe UI status contract."""

    # Keep the model's conventional ``backup`` relation for compatibility and
    # expose the same scalar identity used by every other native restore API.
    # The browser's durable reconciliation contract must not branch by provider.
    backup_id = serializers.IntegerField(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreVultrDatabaseRestore
        fields = "__all__"
        read_only_fields = (
            "backup",
            "resource_id",
            "provider_job_id",
            "provider_marker",
            "provider_status",
            "provider_http_status",
            "status",
            "error",
            "celery_task_id",
        )
        datatables_always_serialize = ("id",)

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

    @staticmethod
    def get_created_display(obj):
        timezone = pytz.timezone(str(get_current_timezone()))
        return obj.created.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")

    @staticmethod
    def get_modified_display(obj):
        timezone = pytz.timezone(str(get_current_timezone()))
        return obj.modified.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")
