import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.account.models import CoreAccount
from apps.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault, IntegrationDefault, bs_decrypt, bs_encrypt,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
    CoreAuthWebsite,
)
from apps.api.v1.account.serializers import CoreAccountSerializer
from apps.api.v1.connection.serializers import CoreIntegrationSerializer, CoreConnectionLocationSerializer
from apps.api.v1.connection.serializer_helpers import (
    StructuredConnectionValidationMixin,
    safe_connection_validation_error,
)


class CoreAuthWebsiteReadSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()
    password_configured = serializers.SerializerMethodField()
    private_key_configured = serializers.SerializerMethodField()
    auth_mode = serializers.SerializerMethodField()
    protocol_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreAuthWebsite
        fields = (
            "id",
            "info_name",
            "host",
            "port",
            "protocol",
            "username",
            "password_configured",
            "ftps_use_explicit_ssl",
            "verify_ssl",
            "use_private_key",
            "use_public_key",
            "private_key_configured",
            "auth_mode",
            "protocol_display",
        )
        datatables_always_serialize = (
            "id",
            "info_name",
            "host",
            "port",
            "protocol",
            "username",
            "password_configured",
            "ftps_use_explicit_ssl",
            "verify_ssl",
            "use_private_key",
            "use_public_key",
            "private_key_configured",
            "auth_mode",
        )

    def get_username(self, obj):
        return bs_decrypt(obj.username, self.context["encryption_key"])

    @staticmethod
    def get_password_configured(obj):
        return bool(obj.password)

    @staticmethod
    def get_private_key_configured(obj):
        return bool(obj.private_key)

    @staticmethod
    def get_auth_mode(obj):
        if obj.protocol == CoreAuthWebsite.Protocol.SFTP:
            if obj.use_public_key:
                return "public_key"
            if obj.use_private_key:
                return "private_key"
        return "password"

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

    def _existing_auth(self):
        parent_instance = getattr(self.parent, "instance", None)
        if parent_instance is None or not getattr(parent_instance, "pk", None):
            return None
        try:
            return parent_instance.auth_website
        except CoreAuthWebsite.DoesNotExist:
            return None

    def _existing_secret(self, instance, field_name):
        if instance is None:
            return None
        return bs_decrypt(
            getattr(instance, field_name),
            self.context["encryption_key"],
        )

    @staticmethod
    def _auth_mode(protocol, use_public_key, use_private_key):
        if protocol == CoreAuthWebsite.Protocol.SFTP:
            if use_public_key:
                return "public_key"
            if use_private_key:
                return "private_key"
        return "password"

    def validate(self, data):
        existing = self._existing_auth()
        errors = {}

        protocol = data.get("protocol", getattr(existing, "protocol", None))
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

        if protocol != CoreAuthWebsite.Protocol.SFTP:
            if data.get("use_public_key") is True or data.get("use_private_key") is True:
                errors["protocol"] = [
                    "Key authentication is available only for SFTP connections."
                ]
            use_public_key = False
            use_private_key = False

        mode = self._auth_mode(protocol, use_public_key, use_private_key)
        previous_mode = None
        if existing is not None:
            previous_mode = self._auth_mode(
                existing.protocol,
                previous_public_key,
                previous_private_key,
            )
        mode_changed = previous_mode is not None and previous_mode != mode

        username = data.get("username")
        if "username" not in data:
            username = self._existing_secret(existing, "username")

        password = data.get("password")
        if "password" not in data and existing is not None and not mode_changed:
            password = self._existing_secret(existing, "password")

        private_key = data.get("private_key")
        if "private_key" not in data and existing is not None and not (
            mode_changed and mode == "private_key"
        ):
            private_key = self._existing_secret(existing, "private_key")

        if not username:
            errors["username"] = ["This field is required."]
        if mode == "password" and not password:
            errors["password"] = [
                "This field is required when password authentication is selected."
            ]
        if mode == "private_key" and not private_key:
            errors["private_key"] = [
                "This field is required when private-key authentication is selected."
            ]
        if mode != "private_key" and data.get("private_key"):
            errors["private_key"] = [
                "A private key can be supplied only when private-key authentication is selected."
            ]
        if mode == "public_key" and data.get("password"):
            errors["password"] = [
                "A password or passphrase cannot be supplied with public-key authentication."
            ]

        if "password" in data and data.get("password"):
            if "'" in data["password"] or '"' in data["password"]:
                errors["password"] = ["The \" or ' characters are not allowed."]

        if errors:
            raise serializers.ValidationError(errors)

        connection_data = {}
        for field_name in (
            "host",
            "port",
            "protocol",
            "ftps_use_explicit_ssl",
            "verify_ssl",
            "flag_use_sha1_key_verification",
        ):
            connection_data[field_name] = data.get(
                field_name,
                getattr(existing, field_name, None),
            )
        connection_data.update(
            {
                "username": username,
                "password": password if mode != "public_key" else None,
                "private_key": private_key if mode == "private_key" else None,
                "use_public_key": use_public_key,
                "use_private_key": use_private_key,
            }
        )

        try:
            auth = CoreAuthWebsite()
            auth.check_connection(data=connection_data)
        except Exception as error:
            raise safe_connection_validation_error(error, stage="website") from None

        data["use_public_key"] = use_public_key
        data["use_private_key"] = use_private_key
        if "username" in data or existing is None:
            data["username"] = bs_encrypt(
                username,
                self.context["encryption_key"],
            )
        if "password" in data or mode_changed or existing is None or mode == "public_key":
            data["password"] = bs_encrypt(
                password if mode != "public_key" else None,
                self.context["encryption_key"],
            )
        if "private_key" in data or mode_changed or existing is None or mode != "private_key":
            data["private_key"] = bs_encrypt(
                private_key if mode == "private_key" else None,
                self.context["encryption_key"],
            )
        return data


class CoreWebsiteConnectionWriteSerializer(
    StructuredConnectionValidationMixin,
    serializers.ModelSerializer,
):
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
