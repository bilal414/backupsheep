import pytz
from django.conf import settings
from django.utils.timezone import get_current_timezone
from requests import JSONDecodeError
from rest_framework import serializers

from apps.console.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault,
    IntegrationDefault,
    bs_encrypt,
    bs_decrypt,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreConnectionLocation,
    CoreAuthWordPress,
)
from apps.console.node.models import CoreNode
from apps.console.api.v1.account.serializers import CoreAccountSerializer
from apps.console.api.v1.connection.serializers import (
    CoreIntegrationSerializer,
    CoreConnectionLocationSerializer,
)


class CoreAuthWordPressReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreAuthWordPress
        fields = (
            "id",
            "url",
            "key",
            "http_user",
            "http_pass",
        )


class CoreWordPressConnectionReadSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer(read_only=True)
    integration = CoreIntegrationSerializer(read_only=True)
    location = CoreConnectionLocationSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    nodes_total = serializers.SerializerMethodField()
    auth_wordpress = CoreAuthWordPressReadSerializer(read_only=True)

    class Meta:
        model = CoreConnection
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "auth_wordpress",
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


class CoreAuthWordPressWriteSerializer(serializers.ModelSerializer):
    key = serializers.CharField(write_only=True)
    http_user = serializers.CharField(write_only=True, allow_null=True, allow_blank=True, required=False)
    http_pass = serializers.CharField(write_only=True, allow_null=True, allow_blank=True, required=False)
    url = serializers.URLField(write_only=True)
    connection = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreAuthWordPress
        fields = "__all__"

    def validate(self, data):
        try:
            auth_wordpress = CoreAuthWordPress()

            data["url"] = data["url"].rstrip('/')

            if not auth_wordpress.validate(data, check_errors=True):
                raise serializers.ValidationError(
                    "Unable to authenticate. "
                    "Did you add our endpoint IPs to firewall/cloudflare and WordPress Key to plugin page?. Also "
                    "make sure you activated BackupSheep & UpdraftPlus (free version) plugins."
                )
        except JSONDecodeError as e:
            raise serializers.ValidationError(
                f"Unable to authenticate. Invalid response from URL."
            )
        except ValueError as e:
            raise serializers.ValidationError(
                f"{e.__str__()}"
            )
        # except Exception as e:
        #     raise serializers.ValidationError(e)
        return data


class CoreWordPressConnectionWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(CurrentMemberDefault())
    )
    account = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(CurrentAccountDefault())
    )
    integration = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(IntegrationDefault("wordpress"))
    )
    location = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnectionLocation.objects.filter()
    )
    auth_wordpress = CoreAuthWordPressWriteSerializer()

    class Meta:
        model = CoreConnection
        fields = "__all__"

    def create(self, validated_data):
        auth_wordpress = validated_data.pop("auth_wordpress", [])
        instance = CoreConnection.objects.create(**validated_data)
        auth_wordpress["connection"] = instance
        CoreAuthWordPress.objects.create(**auth_wordpress)
        return instance

    def update(self, instance, validated_data):
        if validated_data.get("location"):
            if instance.location != validated_data["location"]:
                instance.update_scheduled_backup_locations(validated_data["location"])
        auth_wordpress = validated_data.pop("auth_wordpress", [])
        if len(auth_wordpress) > 0:
            super().update(instance.auth_wordpress, auth_wordpress)
        instance = super().update(instance, validated_data)
        return instance
