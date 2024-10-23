import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.console.account.models import CoreAccount
from apps.console.api.v1.account.serializers import CoreAccountSerializer
from apps.console.api.v1.connection.serializers import CoreConnectionSerializer
from apps.console.api.v1.utils.api_helpers import CurrentMemberDefault, CurrentAccountDefault
from apps.console.connection.models import CoreConnection
from apps.console.node.models import (
    CoreNode,
)


class CoreNodeSerializer(serializers.ModelSerializer):
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
        elif hasattr(obj, "website"):
            return {"name": "website", "id": obj.website.id}
        elif hasattr(obj, "wordpress"):
            return {"name": "wordpress", "id": obj.wordpress.id}
        elif hasattr(obj, "linode"):
            return {"name": "linode", "id": obj.linode.id}
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


class CoreDatabaseNodeWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    type = serializers.HiddenField(default=CoreNode.Type.DATABASE)
    connection = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnection.objects.filter()
    )

    class Meta:
        model = CoreNode
        fields = "__all__"

    def validate(self, data):
        connection = data["connection"]
        member = self.context["request"].user.member
        if not connection.account.memberships.filter(member=member).exists():
            raise serializers.ValidationError(
                "You don't have access to this node."
            )
        return data


class CoreWebsiteNodeWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    type = serializers.HiddenField(default=CoreNode.Type.WEBSITE)
    connection = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnection.objects.filter()
    )

    class Meta:
        model = CoreNode
        fields = "__all__"

    def validate(self, data):
        connection = data["connection"]
        member = self.context["request"].user.member
        if not connection.account.memberships.filter(member=member).exists():
            raise serializers.ValidationError(
                "You don't have access to this node."
            )
        return data


class CoreNodeWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    type = serializers.HiddenField(default=CoreNode.Type.CLOUD)
    connection = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnection.objects.filter()
    )

    class Meta:
        model = CoreNode
        fields = "__all__"

    def validate(self, data):
        connection = data["connection"]
        member = self.context["request"].user.member
        if not connection.account.memberships.filter(member=member).exists():
            raise serializers.ValidationError(
                "You don't have access to this node."
            )
        return data


class CoreSaaSNodeWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    type = serializers.HiddenField(default=CoreNode.Type.SAAS)
    connection = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnection.objects.filter()
    )

    class Meta:
        model = CoreNode
        fields = "__all__"

    def validate(self, data):
        connection = data["connection"]
        member = self.context["request"].user.member
        if not connection.account.memberships.filter(member=member).exists():
            raise serializers.ValidationError(
                "You don't have access to this node."
            )
        return data


class CoreCloudNodeWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    type = serializers.HiddenField(default=CoreNode.Type.CLOUD)
    connection = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnection.objects.filter()
    )

    class Meta:
        model = CoreNode
        fields = "__all__"

    def validate(self, data):
        connection = data["connection"]
        member = self.context["request"].user.member
        if not connection.account.memberships.filter(member=member).exists():
            raise serializers.ValidationError(
                "You don't have access to this node."
            )
        return data


class CoreVolumeNodeWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    type = serializers.HiddenField(default=CoreNode.Type.VOLUME)
    connection = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnection.objects.filter()
    )

    class Meta:
        model = CoreNode
        fields = "__all__"

    def validate(self, data):
        connection = data["connection"]
        member = self.context["request"].user.member
        if not connection.account.memberships.filter(member=member).exists():
            raise serializers.ValidationError(
                "You don't have access to this node."
            )
        return data
