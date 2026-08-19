import pytz
from django.conf import settings
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.account.models import CoreAccount
from apps.api.v1.utils.api_helpers import (
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
from apps.api.v1.account.serializers import CoreAccountSerializer
from apps.api.v1.connection.serializers import CoreIntegrationSerializer, CoreConnectionLocationSerializer
from apps.api.v1.connection.serializer_helpers import (
    StructuredConnectionValidationMixin,
    safe_connection_validation_error,
)


class CoreAuthDatabaseReadSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()
    ssh_username = serializers.SerializerMethodField()
    password_configured = serializers.SerializerMethodField()
    private_key_configured = serializers.SerializerMethodField()
    ssh_password_configured = serializers.SerializerMethodField()
    auth_mode = serializers.SerializerMethodField()

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
            "password_configured",
            "include_stored_procedure",
            "use_ssl",
            "ssh_username",
            "ssh_password_configured",
            "ssh_port",
            "ssh_host",
            "private_key_configured",
            "type",
            "version",
            "use_public_key",
            "use_private_key",
            "auth_mode",
        )
        datatables_always_serialize = (
            "id",
            "info_name",
            "host",
            "port",
            "database_name",
            "all_databases",
            "username",
            "password_configured",
            "include_stored_procedure",
            "use_ssl",
            "ssh_username",
            "ssh_password_configured",
            "ssh_port",
            "ssh_host",
            "private_key_configured",
            "type",
            "version",
            "use_public_key",
            "use_private_key",
            "auth_mode",
        )

    def get_username(self, obj):
        return bs_decrypt(obj.username, self.context["encryption_key"])

    def get_ssh_username(self, obj):
        return bs_decrypt(obj.ssh_username, self.context["encryption_key"])

    @staticmethod
    def get_password_configured(obj):
        return bool(obj.password)

    @staticmethod
    def get_private_key_configured(obj):
        return bool(obj.private_key)

    @staticmethod
    def get_ssh_password_configured(obj):
        return bool(obj.ssh_password)

    @staticmethod
    def get_auth_mode(obj):
        if obj.use_public_key:
            return "public_key"
        if obj.use_private_key:
            return "private_key"
        return "direct"


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
    password = serializers.CharField(
        write_only=True,
        required=False,
        allow_null=True,
        allow_blank=True,
    )
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

    def _existing_auth(self):
        parent_instance = getattr(self.parent, "instance", None)
        if parent_instance is None or not getattr(parent_instance, "pk", None):
            return None
        try:
            return parent_instance.auth_database
        except CoreAuthDatabase.DoesNotExist:
            return None

    def _existing_secret(self, instance, field_name):
        if instance is None:
            return None
        return bs_decrypt(
            getattr(instance, field_name),
            self.context["encryption_key"],
        )

    @staticmethod
    def _auth_mode(use_public_key, use_private_key):
        if use_public_key:
            return "public_key"
        if use_private_key:
            return "private_key"
        return "direct"

    def validate(self, data):
        existing = self._existing_auth()
        errors = {}

        # MySQL 8.4 uses caching_sha2_password by default and many fresh
        # accounts require secure transport. New connections therefore start
        # with database TLS enabled. An explicit false remains a supported
        # opt-out; updates never rewrite an existing connection silently.
        if (
            existing is None
            and data.get("use_ssl") is None
            and data.get("type") == CoreAuthDatabase.DatabaseType.MYSQL
            and data.get("version")
            == CoreAuthDatabase.DatabaseVersion.MYSQL_8_4
        ):
            data["use_ssl"] = True

        previous_public_key = bool(getattr(existing, "use_public_key", False))
        previous_private_key = bool(getattr(existing, "use_private_key", False))

        if data.get("use_public_key") is True and data.get("use_private_key") is True:
            errors["use_public_key"] = [
                "Public-key and private-key authentication cannot both be enabled."
            ]
            errors["use_private_key"] = [
                "Public-key and private-key authentication cannot both be enabled."
            ]

        use_public_key = previous_public_key
        use_private_key = previous_private_key
        if data.get("use_public_key") is True:
            use_public_key = True
            use_private_key = False
        elif data.get("use_private_key") is True:
            use_public_key = False
            use_private_key = True
        else:
            if "use_public_key" in data:
                use_public_key = bool(data["use_public_key"])
            if "use_private_key" in data:
                use_private_key = bool(data["use_private_key"])

        if use_public_key and use_private_key:
            errors["use_public_key"] = [
                "Public-key and private-key authentication cannot both be enabled."
            ]
            errors["use_private_key"] = [
                "Public-key and private-key authentication cannot both be enabled."
            ]

        mode = self._auth_mode(use_public_key, use_private_key)
        previous_mode = None
        if existing is not None:
            previous_mode = self._auth_mode(
                previous_public_key,
                previous_private_key,
            )
        mode_changed = previous_mode is not None and previous_mode != mode

        all_databases = data.get(
            "all_databases",
            bool(getattr(existing, "all_databases", False)),
        )
        database_name = data.get(
            "database_name",
            getattr(existing, "database_name", None),
        )
        if all_databases:
            database_name = None
        elif not database_name:
            errors["database_name"] = ["This field is required."]

        username = data.get("username")
        if "username" not in data:
            username = self._existing_secret(existing, "username")
        password = data.get("password")
        if "password" not in data:
            password = self._existing_secret(existing, "password")

        entering_ssh_mode = mode != "direct" and previous_mode == "direct"
        ssh_host = data.get("ssh_host")
        ssh_port = data.get("ssh_port")
        ssh_username = data.get("ssh_username")
        if existing is not None and not entering_ssh_mode:
            if "ssh_host" not in data:
                ssh_host = existing.ssh_host
            if "ssh_port" not in data:
                ssh_port = existing.ssh_port
            if "ssh_username" not in data:
                ssh_username = self._existing_secret(existing, "ssh_username")

        ssh_password = data.get("ssh_password")
        if (
            "ssh_password" not in data
            and existing is not None
            and mode == "private_key"
            and previous_mode == "private_key"
        ):
            ssh_password = self._existing_secret(existing, "ssh_password")

        private_key = data.get("private_key")
        if (
            "private_key" not in data
            and existing is not None
            and mode == "private_key"
            and previous_mode == "private_key"
        ):
            private_key = self._existing_secret(existing, "private_key")

        if not username:
            errors["username"] = ["This field is required."]
        if not password:
            errors["password"] = ["This field is required."]
        if mode != "direct":
            if not ssh_host:
                errors["ssh_host"] = ["This field is required for SSH authentication."]
            if not ssh_username:
                errors["ssh_username"] = ["This field is required for SSH authentication."]
            if not ssh_port:
                errors["ssh_port"] = ["This field is required for SSH authentication."]
        if mode == "private_key" and not private_key:
            errors["private_key"] = [
                "This field is required when private-key authentication is selected."
            ]

        if "password" in data and data.get("password"):
            if "'" in data["password"] or '"' in data["password"]:
                errors["password"] = ["The \" or ' characters are not allowed."]
        if mode == "private_key" and "ssh_password" in data and data.get("ssh_password"):
            if "'" in data["ssh_password"] or '"' in data["ssh_password"]:
                errors["ssh_password"] = ["The \" or ' characters are not allowed."]

        if errors:
            raise serializers.ValidationError(errors)

        if mode == "direct":
            ssh_host = None
            ssh_port = None
            ssh_username = None
            ssh_password = None
            private_key = None
        elif mode == "public_key":
            ssh_password = None
            private_key = None

        connection_data = {}
        for field_name in (
            "host",
            "port",
            "type",
            "version",
            "include_stored_procedure",
            "use_ssl",
            "flag_use_sha1_key_verification",
        ):
            connection_data[field_name] = data.get(
                field_name,
                getattr(existing, field_name, None),
            )
        connection_data.update(
            {
                "database_name": database_name,
                "all_databases": all_databases,
                "username": username,
                "password": password,
                "ssh_host": ssh_host,
                "ssh_port": ssh_port,
                "ssh_username": ssh_username,
                "ssh_password": ssh_password,
                "private_key": private_key,
                "use_public_key": use_public_key,
                "use_private_key": use_private_key,
            }
        )

        try:
            auth = CoreAuthDatabase()
            auth.check_connection(data=connection_data)
        except Exception as error:
            raise safe_connection_validation_error(error, stage="database") from None

        data["all_databases"] = all_databases
        if all_databases or "database_name" in data:
            data["database_name"] = database_name
        data["use_public_key"] = use_public_key
        data["use_private_key"] = use_private_key

        if "username" in data or existing is None:
            data["username"] = bs_encrypt(
                username,
                self.context["encryption_key"],
            )
        if "password" in data or existing is None:
            data["password"] = bs_encrypt(
                password,
                self.context["encryption_key"],
            )

        if mode == "direct":
            data["ssh_host"] = None
            data["ssh_port"] = None
            data["ssh_username"] = None
            data["ssh_password"] = None
            data["private_key"] = None
        else:
            if "ssh_host" in data or mode_changed or existing is None:
                data["ssh_host"] = ssh_host
            if "ssh_port" in data or mode_changed or existing is None:
                data["ssh_port"] = ssh_port
            if "ssh_username" in data or mode_changed or existing is None:
                data["ssh_username"] = bs_encrypt(
                    ssh_username,
                    self.context["encryption_key"],
                )
            if mode == "public_key":
                data["ssh_password"] = None
                data["private_key"] = None
            else:
                if "ssh_password" in data or mode_changed or existing is None:
                    data["ssh_password"] = bs_encrypt(
                        ssh_password,
                        self.context["encryption_key"],
                    )
                if "private_key" in data or mode_changed or existing is None:
                    data["private_key"] = bs_encrypt(
                        private_key,
                        self.context["encryption_key"],
                    )
        return data


class CoreDatabaseConnectionWriteSerializer(
    StructuredConnectionValidationMixin,
    serializers.ModelSerializer,
):
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
        if validated_data.get("location") and instance.location != validated_data["location"]:
            instance.update_scheduled_backup_locations(validated_data["location"])
        auth_database = validated_data.pop("auth_database", [])
        if len(auth_database) > 0:
            super().update(instance.auth_database, auth_database)
        instance = super().update(instance, validated_data)
        return instance
