import pytz
from django.db import transaction
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied

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
    MANAGED_SSH_SINGLE_ACCOUNT_VALIDATION_DETAIL,
    StructuredConnectionValidationMixin,
    safe_connection_validation_error,
)
from apps.console.connection.managed_ssh import (
    _active_request_permission,
    acquire_managed_ssh_mutation_lock,
    assert_managed_ssh_single_account,
    create_managed_ssh_operation,
    ManagedSSHOperationError,
    managed_public_key_fingerprint,
)
from apps.console.connection.ssh import normalize_ssh_host
from apps.console.connection.reliability import classify_and_record_connection_error


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
        legacy_rsa = bool(
            data.get(
                "flag_use_sha1_key_verification",
                getattr(existing, "flag_use_sha1_key_verification", False),
            )
        )
        if mode == "public_key" and legacy_rsa:
            errors["flag_use_sha1_key_verification"] = [
                "Legacy RSA/SHA-1 is not permitted with the managed SSH key."
            ]
        if mode == "public_key":
            try:
                assert_managed_ssh_single_account(
                    self.context["request"].user.member.get_current_account().pk
                )
            except ManagedSSHOperationError as error:
                classify_and_record_connection_error(
                    error,
                    stage="managed_ssh_policy",
                )
                errors["use_public_key"] = [
                    MANAGED_SSH_SINGLE_ACCOUNT_VALIDATION_DETAIL
                ]

        if "password" in data and data.get("password"):
            if "'" in data["password"] or '"' in data["password"]:
                errors["password"] = ["The \" or ' characters are not allowed."]

        if errors:
            raise serializers.ValidationError(errors)

        if protocol == CoreAuthWebsite.Protocol.SFTP:
            try:
                data["host"] = normalize_ssh_host(
                    data.get("host", getattr(existing, "host", None))
                )
            except (TypeError, ValueError):
                raise serializers.ValidationError(
                    {"host": ["A valid canonical SSH host is required."]}
                ) from None

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
                "_account_id": self.context["request"].user.member.get_current_account().pk,
                "username": username,
                "password": password if mode != "public_key" else None,
                "private_key": private_key if mode == "private_key" else None,
                "use_public_key": use_public_key,
                "use_private_key": use_private_key,
            }
        )

        try:
            if mode == "public_key":
                # The web container deliberately has no managed private key. Its
                # syntax/binding is checked here; a files-lane worker performs the
                # network validation after the durable rows commit.
                managed_public_key_fingerprint(source_lane="files")
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
        read_only_fields = (
            "status",
            "old_status",
            "notification",
            "managed_ssh_generation",
        )

    def _requesting_member(self):
        request = self.context.get("request")
        member = getattr(getattr(request, "user", None), "member", None)
        if member is None or not getattr(member, "pk", None):
            raise serializers.ValidationError(
                {"detail": "A requesting member is required for managed SSH."}
            )
        return member

    @staticmethod
    def _lock_request_permission(account_id, member_id):
        try:
            return _active_request_permission(account_id, member_id)
        except ManagedSSHOperationError:
            raise PermissionDenied(
                "Integration-change permission is required."
            ) from None

    @transaction.atomic
    def create(self, validated_data):
        acquire_managed_ssh_mutation_lock()
        requesting_member = self._requesting_member()
        account = CoreAccount.objects.select_for_update().get(
            pk=validated_data["account"].pk
        )
        self._lock_request_permission(account.pk, requesting_member.pk)
        validated_data["account"] = account
        auth_website = validated_data.pop("auth_website", [])
        managed_key = bool(auth_website.get("use_public_key"))
        validated_data["status"] = CoreConnection.Status.PENDING
        instance = CoreConnection.objects.create(**validated_data)
        auth_website["connection"] = instance
        CoreAuthWebsite.objects.create(**auth_website)
        if managed_key:
            try:
                self.managed_ssh_operation = create_managed_ssh_operation(
                    instance,
                    "validate",
                    requested_by_member=requesting_member,
                )
            except Exception as error:
                raise safe_connection_validation_error(
                    error, stage="managed_ssh_intent"
                ) from None
        return instance

    @transaction.atomic
    def update(self, instance, validated_data):
        acquire_managed_ssh_mutation_lock()
        requesting_member = self._requesting_member()
        account = CoreAccount.objects.select_for_update().get(pk=instance.account_id)
        self._lock_request_permission(account.pk, requesting_member.pk)
        instance = CoreConnection.objects.select_for_update().get(
            pk=instance.pk,
            account=account,
        )
        locked_auth = CoreAuthWebsite.objects.select_for_update().get(
            connection=instance
        )
        instance._state.fields_cache["auth_website"] = locked_auth
        if validated_data.get("location"):
            if instance.location != validated_data["location"]:
                instance.update_scheduled_backup_locations(validated_data["location"])
        auth_website = validated_data.pop("auth_website", [])
        if auth_website:
            validated_data["status"] = CoreConnection.Status.PENDING
        if len(auth_website) > 0:
            super().update(instance.auth_website, auth_website)
            # The website auth fence can advance the connection generation and
            # force PENDING. Refresh every trigger-owned field before DRF saves
            # the parent model so its stale in-memory snapshot cannot clobber or
            # illegally replay that generation.
            instance.refresh_from_db(
                fields=("managed_ssh_generation", "status", "modified")
            )
        instance = super().update(instance, validated_data)
        if auth_website and bool(locked_auth.use_public_key):
            try:
                self.managed_ssh_operation = create_managed_ssh_operation(
                    instance,
                    "validate",
                    requested_by_member=requesting_member,
                )
            except Exception as error:
                raise safe_connection_validation_error(
                    error, stage="managed_ssh_intent"
                ) from None
        return instance
