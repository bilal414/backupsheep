import boto.ec2
import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.account.models import CoreAccount
from apps.console.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault, IntegrationDefault, bs_decrypt, bs_encrypt,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
    CoreAuthWebsite,
)
from apps.console.api.v1.account.serializers import CoreAccountSerializer
from apps.console.api.v1.connection.serializers import CoreIntegrationSerializer, CoreConnectionLocationSerializer


class CoreAuthWebsiteReadSerializer(serializers.ModelSerializer):
    password = serializers.SerializerMethodField()
    username = serializers.SerializerMethodField()
    private_key = serializers.SerializerMethodField()
    protocol_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreAuthWebsite
        fields = (
            "id",
            "info_name",
            "host",
            "port",
            "protocol",
            "protocol",
            "password",
            "username",
            "ftps_use_explicit_ssl",
            "use_private_key",
            "use_public_key",
            "private_key",
            "protocol_display",
        )
        datatables_always_serialize = (
            "id",
            "info_name",
            "host",
            "port",
            "protocol",
            "password",
            "username",
            "ftps_use_explicit_ssl",
            "use_private_key",
            "use_public_key",
            "private_key",
        )

    def get_password(self, obj):
        return bs_decrypt(obj.password, self.context["encryption_key"])

    def get_username(self, obj):
        return bs_decrypt(obj.username, self.context["encryption_key"])

    def get_private_key(self, obj):
        return bs_decrypt(obj.private_key, self.context["encryption_key"])

    @staticmethod
    def get_protocol_display(obj):
        return obj.get_protocol_display()


class CoreWebsiteConnectionReadSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer(read_only=True)
    integration = CoreIntegrationSerializer(read_only=True)
    location = CoreConnectionLocationSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    nodes_total = serializers.SerializerMethodField()
    auth_website = CoreAuthWebsiteReadSerializer(read_only=True)

    class Meta:
        model = CoreConnection
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "auth_website",
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


class CoreAuthWebsiteWriteSerializer(serializers.ModelSerializer):
    host = serializers.CharField(write_only=True)
    port = serializers.IntegerField(write_only=True, min_value=1)
    password = serializers.CharField(write_only=True, allow_null=True, allow_blank=True, required=False)
    username = serializers.CharField(write_only=True)
    protocol = serializers.ChoiceField(write_only=True, choices=CoreAuthWebsite.Protocol)
    use_private_key = serializers.BooleanField(
        write_only=True, allow_null=True, required=False
    )
    use_public_key = serializers.BooleanField(
        write_only=True, allow_null=True, required=False
    )
    flag_turn_off_sha2 = serializers.BooleanField(
        write_only=True, allow_null=True, required=False
    )
    private_key = serializers.CharField(
        write_only=True, required=False, allow_null=True, allow_blank=True
    )

    flag_use_sha1_key_verification = serializers.BooleanField(
        write_only=True, allow_null=True, required=False
    )

    connection = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreAuthWebsite
        fields = "__all__"

    def validate(self, data):
        # Check for private key
        errors = {}
        if data.get("use_private_key"):
            if not data.get("private_key") or data.get("private_key") == "":
                errors["private_key"] = ["This field is required."]
                raise serializers.ValidationError(errors)

        if data.get("password"):
            if "'" in data.get("password") or "\"" in data.get("password"):
                errors["password"] = ["The \" or ' characters are not allowed."]
                raise serializers.ValidationError(errors)
        try:
            auth = CoreAuthWebsite()
            auth.check_connection(data=data)

            data["username"] = bs_encrypt(data.get("username"), self.context["encryption_key"])
            data["password"] = bs_encrypt(data.get("password"), self.context["encryption_key"])
            data["private_key"] = bs_encrypt(data.get("private_key"), self.context["encryption_key"])
        except Exception as e:
            raise serializers.ValidationError(
                "Unable to authenticate. "
                "Please check your credentials and "
                "if they have valid permissions."
            )
        return data


class CoreWebsiteConnectionWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentMemberDefault()))
    account = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentAccountDefault()))
    integration = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(IntegrationDefault("website"))
    )
    location = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnectionLocation.objects.filter()
    )
    auth_website = CoreAuthWebsiteWriteSerializer()

    class Meta:
        model = CoreConnection
        fields = "__all__"

    def create(self, validated_data):
        auth_website = validated_data.pop("auth_website", [])
        instance = CoreConnection.objects.create(**validated_data)
        auth_website["connection"] = instance
        CoreAuthWebsite.objects.create(**auth_website)
        return instance

    def update(self, instance, validated_data):
        if validated_data.get("location"):
            if instance.location != validated_data["location"]:
                instance.update_scheduled_backup_locations(validated_data["location"])
        auth_website = validated_data.pop("auth_website", [])
        if len(auth_website) > 0:
            super().update(instance.auth_website, auth_website)
        instance = super().update(instance, validated_data)
        return instance
