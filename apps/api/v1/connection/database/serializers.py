import boto.ec2
import pytz
from django.conf import settings
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.account.models import CoreAccount
from apps.console.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault,
    IntegrationDefault,
    bs_encrypt,
    bs_decrypt,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
    CoreAuthDatabase,
)
from apps.console.api.v1.account.serializers import CoreAccountSerializer
from apps.console.api.v1.connection.serializers import CoreIntegrationSerializer, CoreConnectionLocationSerializer


class CoreAuthDatabaseReadSerializer(serializers.ModelSerializer):
    password = serializers.SerializerMethodField()
    username = serializers.SerializerMethodField()
    private_key = serializers.SerializerMethodField()
    ssh_username = serializers.SerializerMethodField()
    ssh_password = serializers.SerializerMethodField()

    class Meta:
        model = CoreAuthDatabase
        fields = (
            "id",
            "info_name",
            "host",
            "port",
            "database_name",
            "all_databases",
            "username",
            "password",
            "include_stored_procedure",
            "use_ssl",
            "ssh_username",
            "ssh_password",
            "ssh_port",
            "ssh_host",
            "private_key",
            "type",
            "version",
            "use_public_key",
            "use_private_key",
        )
        datatables_always_serialize = (
            "id",
            "info_name",
            "host",
            "port",
            "database_name",
            "all_databases",
            "username",
            "password",
            "include_stored_procedure",
            "use_ssl",
            "ssh_username",
            "ssh_password",
            "ssh_port",
            "ssh_host",
            "private_key",
            "type",
            "version",
            "use_public_key",
            "use_private_key",
        )

    def get_password(self, obj):
        return bs_decrypt(obj.password, self.context["encryption_key"])

    def get_username(self, obj):
        return bs_decrypt(obj.username, self.context["encryption_key"])

    def get_private_key(self, obj):
        return bs_decrypt(obj.private_key, self.context["encryption_key"])

    def get_ssh_username(self, obj):
        return bs_decrypt(obj.ssh_username, self.context["encryption_key"])

    def get_ssh_password(self, obj):
        return bs_decrypt(obj.ssh_password, self.context["encryption_key"])


class CoreDatabaseConnectionReadSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer(read_only=True)
    integration = CoreIntegrationSerializer(read_only=True)
    location = CoreConnectionLocationSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    type_display = serializers.SerializerMethodField()
    nodes_total = serializers.SerializerMethodField()
    auth_database = CoreAuthDatabaseReadSerializer(read_only=True)

    class Meta:
        model = CoreConnection
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "auth_database",
        )

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

    @staticmethod
    def get_type_display(obj):
        return obj.auth_database.get_type_display()

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


class CoreAuthDatabaseWriteSerializer(serializers.ModelSerializer):
    host = serializers.CharField(write_only=True)
    port = serializers.IntegerField(write_only=True)
    database_name = serializers.CharField(write_only=True, allow_null=True, allow_blank=True, required=False)
    all_databases = serializers.BooleanField(write_only=True, allow_null=True, required=False)

    username = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
    type = serializers.ChoiceField(write_only=True, choices=CoreAuthDatabase.DatabaseType)
    include_stored_procedure = serializers.BooleanField(write_only=True, allow_null=True, required=False)
    use_ssl = serializers.BooleanField(write_only=True, allow_null=True, required=False)
    ssh_username = serializers.CharField(write_only=True, allow_null=True, allow_blank=True, required=False)
    ssh_password = serializers.CharField(write_only=True, allow_null=True, allow_blank=True, required=False)
    ssh_port = serializers.IntegerField(write_only=True, allow_null=True, required=False)
    ssh_host = serializers.CharField(write_only=True, allow_null=True, allow_blank=True, required=False)

    use_public_key = serializers.BooleanField(write_only=True, allow_null=True, required=False)
    use_private_key = serializers.BooleanField(write_only=True, allow_null=True, required=False)
    flag_turn_off_sha2 = serializers.BooleanField(write_only=True, allow_null=True, required=False)

    private_key = serializers.CharField(write_only=True, required=False, allow_null=True, allow_blank=True)

    flag_use_sha1_key_verification = serializers.BooleanField(write_only=True, allow_null=True, required=False)

    connection = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreAuthDatabase
        fields = "__all__"

    def validate(self, data):
        errors = {}
        if not data.get("all_databases"):
            if not data.get("database_name"):
                errors["database_name"] = ["This field is required."]
        if data.get("use_private_key"):
            if not data.get("private_key"):
                errors["private_key"] = ["This field is required."]
        if data.get("use_public_key") or data.get("use_private_key"):
            if not data.get("ssh_host"):
                errors["ssh_host"] = ["This field is required."]
            if not data.get("ssh_username"):
                errors["ssh_username"] = ["This field is required."]
            if not data.get("ssh_port"):
                errors["ssh_port"] = ["This field is required."]

        if data.get("password"):
            if "'" in data.get("password") or '"' in data.get("password"):
                errors["password"] = ["The \" or ' characters are not allowed."]
                raise serializers.ValidationError(errors)

        if data.get("ssh_password"):
            if "'" in data.get("ssh_password") or '"' in data.get("ssh_password"):
                errors["ssh_password"] = ["The \" or ' characters are not allowed."]
                raise serializers.ValidationError(errors)

        if bool(errors):
            raise serializers.ValidationError(errors)
        try:
            auth = CoreAuthDatabase()
            auth.check_connection(data=data)

            data["username"] = bs_encrypt(data.get("username"), self.context["encryption_key"])
            data["password"] = bs_encrypt(data.get("password"), self.context["encryption_key"])
            data["ssh_username"] = bs_encrypt(data.get("ssh_username"), self.context["encryption_key"])
            data["ssh_password"] = bs_encrypt(data.get("ssh_password"), self.context["encryption_key"])
            data["private_key"] = bs_encrypt(data.get("private_key"), self.context["encryption_key"])
        except Exception as e:
            raise serializers.ValidationError(e.__str__())
        return data


class CoreDatabaseConnectionWriteSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentMemberDefault()))
    account = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentAccountDefault()))
    integration = serializers.HiddenField(default=serializers.CreateOnlyDefault(IntegrationDefault("database")))
    location = serializers.PrimaryKeyRelatedField(queryset=CoreConnectionLocation.objects.filter())
    auth_database = CoreAuthDatabaseWriteSerializer()

    class Meta:
        model = CoreConnection
        fields = "__all__"

    def create(self, validated_data):
        auth_database = validated_data.pop("auth_database", [])
        instance = CoreConnection.objects.create(**validated_data)
        auth_database["connection"] = instance
        CoreAuthDatabase.objects.create(**auth_database)
        return instance

    def update(self, instance, validated_data):
        if instance.location != validated_data["location"]:
            instance.update_scheduled_backup_locations(validated_data["location"])
        auth_database = validated_data.pop("auth_database", [])
        if len(auth_database) > 0:
            super().update(instance.auth_database, auth_database)
        instance = super().update(instance, validated_data)
        return instance
