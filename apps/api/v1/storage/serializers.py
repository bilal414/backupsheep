from collections.abc import Mapping

import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.api.v1.account.serializers import CoreAccountSerializer
from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt
from apps.console.storage.models import CoreStorage, CoreStorageType


class ConfiguredSecretField(serializers.Field):
    """Expose credential presence without reading or decrypting its value."""

    def __init__(self, secret_name, **kwargs):
        self.secret_name = secret_name
        kwargs["read_only"] = True
        super().__init__(**kwargs)

    def get_attribute(self, instance):
        return instance

    def to_representation(self, instance):
        return bool(getattr(instance, self.secret_name, None))


class StorageCredentialReadSerializerMixin:
    """Remove encrypted credentials from output and expose presence booleans."""

    credential_fields = ()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        always = getattr(getattr(cls, "Meta", None), "datatables_always_serialize", ())
        if always:
            credential_names = set(cls.credential_fields)
            cls.Meta.datatables_always_serialize = tuple(
                f"{name}_configured" if name in credential_names else name
                for name in always
            )

    def get_fields(self):
        fields = super().get_fields()
        for credential_name in self.credential_fields:
            fields.pop(credential_name, None)
            fields[f"{credential_name}_configured"] = ConfiguredSecretField(
                credential_name
            )
        return fields


class StorageCredentialWriteSerializerMixin:
    """Make encrypted credentials replacement-only and PATCH-safe.

    Existing serializers validate credentials against provider APIs before
    encrypting them. For PATCH, this mixin temporarily supplies the existing
    plaintext credentials to that validation path, then removes them from the
    validated result. Omitted encrypted database values therefore remain
    byte-for-byte unchanged.
    """

    credential_fields = ()
    credential_groups = ()

    def get_fields(self):
        fields = super().get_fields()
        for credential_name in self.credential_fields:
            field = fields.get(credential_name)
            if field is not None:
                field.write_only = True
        return fields

    def _existing_credential_instance(self):
        if self.instance is not None:
            return self.instance

        root_instance = getattr(self.root, "instance", None)
        relation_name = getattr(self, "field_name", None)
        if root_instance is not None and relation_name:
            try:
                return getattr(root_instance, relation_name)
            except (AttributeError, self.Meta.model.DoesNotExist):
                return None
        return None

    def _validate_credential_replacement(self, submitted_fields):
        groups = self.credential_groups or (tuple(self.credential_fields),)
        for group in groups:
            supplied = set(group).intersection(submitted_fields)
            if supplied and supplied != set(group):
                missing = ", ".join(sorted(set(group) - supplied))
                raise serializers.ValidationError(
                    {
                        "credentials": (
                            "Credential fields must be replaced together. "
                            f"Missing: {missing}."
                        )
                    }
                )

    def run_validation(self, data=serializers.empty):
        if data is serializers.empty or not isinstance(data, Mapping):
            return super().run_validation(data)

        submitted_fields = set(data)
        self._validate_credential_replacement(submitted_fields)
        if set(self.credential_fields).intersection(submitted_fields) and not self.context.get(
            "encryption_key"
        ):
            raise serializers.ValidationError(
                {"credentials": "Encryption context is required."}
            )
        existing = self._existing_credential_instance()
        injected = set()
        validation_input = data.copy()

        if existing is not None:
            encryption_key = self.context.get("encryption_key")
            if not encryption_key:
                raise serializers.ValidationError(
                    {"credentials": "Encryption context is required."}
                )
            for credential_name in self.credential_fields:
                if credential_name not in submitted_fields:
                    encrypted_value = getattr(existing, credential_name, None)
                    if encrypted_value:
                        validation_input[credential_name] = bs_decrypt(
                            encrypted_value, encryption_key
                        )
                        injected.add(credential_name)

            # Provider validators generally expect a complete connection
            # document. Supply omitted metadata for validation only, then strip
            # it from validated_data so PATCH still changes exactly what the
            # caller submitted.
            for field_name, field in self.fields.items():
                if (
                    field_name in submitted_fields
                    or field_name in self.credential_fields
                    or field.read_only
                    or not hasattr(existing, field_name)
                ):
                    continue
                value = getattr(existing, field_name)
                if isinstance(field, serializers.PrimaryKeyRelatedField):
                    value = getattr(value, "pk", value)
                validation_input[field_name] = value
                injected.add(field_name)

        validated = super().run_validation(validation_input)
        for field_name in injected:
            validated.pop(field_name, None)

        encryption_key = self.context.get("encryption_key")
        for credential_name in self.credential_fields:
            value = validated.get(credential_name)
            # Existing provider serializers already encrypt their primary
            # credentials. This safely covers any additional credential field
            # declared by a model without double-encrypting bytes.
            if credential_name in submitted_fields and isinstance(value, str):
                validated[credential_name] = bs_encrypt(value, encryption_key)
        return validated


class CoreStorageTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreStorageType
        fields = "__all__"
        ref_name = "Storage Type"


class CoreStorageSerializer(serializers.ModelSerializer):
    type = CoreStorageTypeSerializer(read_only=True)
    account = CoreAccountSerializer(read_only=True)
    status_display = serializers.SerializerMethodField()
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreStorage
        fields = "__all__"

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
