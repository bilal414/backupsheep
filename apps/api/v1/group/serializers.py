from django.db import transaction
from django.db.models import Q
from django.utils.text import slugify
from rest_framework import serializers
from django.contrib.auth.models import Group

from apps.console.account.models import CoreAccountGroup
from apps.console.node.models import CoreNode
from apps.api.v1.utils.api_helpers import CurrentAccountDefault, AccountGroupDefault


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = "__all__"


class CurrentAccountNodePrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):
    """Resolve source ids only inside the request's active workspace."""

    def get_queryset(self):
        queryset = super().get_queryset()
        request = self.context.get("request")
        try:
            account = request.user.member.get_current_account()
        except (AttributeError, TypeError):
            return queryset.none()
        if account is None:
            return queryset.none()
        return queryset.filter(connection__account=account)


class CoreAccountGroupWriteSerializer(serializers.ModelSerializer):
    account = serializers.HiddenField(default=CurrentAccountDefault(), write_only=True)
    # group = GroupSerializer(write_only=True)
    default = serializers.HiddenField(default=AccountGroupDefault())
    type_display = serializers.SerializerMethodField(read_only=True)
    permissions = serializers.ListField(required=False, child=serializers.CharField(), write_only=True)
    notes = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    # Node ids are resolved from the active account before cross-field validation.
    nodes = CurrentAccountNodePrimaryKeyRelatedField(
        many=True, queryset=CoreNode.objects.all(), required=False
    )

    class Meta:
        model = CoreAccountGroup
        fields = (
            "id",
            "name",
            "type",
            "type_display",
            "default",
            "account",
            "group",
            "permissions",
            "notes",
            "nodes",
        )

    def validate_permissions(self, value):
        """Accept only the explicit BackupSheep account-group capabilities."""

        allowed = {
            codename for codename, _label in CoreAccountGroup._meta.permissions
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise serializers.ValidationError(
                "Unknown operational permission: " + ", ".join(unknown)
            )
        # Preserve the submitted order while ensuring a capability is applied once.
        return list(dict.fromkeys(value))

    def validate(self, data):
        errors = {}
        account = self.context["request"].user.member.get_current_account()
        name = data.get("name", getattr(self.instance, "name", None))

        if name:
            query = Q(name__iexact=name)
            if self.instance:
                query &= ~Q(id=self.instance.id)
            if account.enrollments.filter(query).exists():
                errors["name"] = ["Group name must be unique."]

        if bool(errors):
            raise serializers.ValidationError(errors)

        # Validation must remain side-effect free. The backing auth Group is
        # created or renamed only after all fields, including tenant-scoped node
        # ids, have validated successfully.
        return data

    @staticmethod
    def _auth_group_name(account, name, group_type):
        type_name = dict(CoreAccountGroup.Type.choices)[int(group_type)]
        return slugify(f"{account.id}-{name}-{type_name}")

    @transaction.atomic
    def create(self, validated_data):
        group_name = self._auth_group_name(
            validated_data["account"],
            validated_data["name"],
            validated_data["type"],
        )
        validated_data["group"] = Group.objects.create(name=group_name)
        return super().create(validated_data)

    @transaction.atomic
    def update(self, instance, validated_data):
        name = validated_data.get("name", instance.name)
        group_type = validated_data.get("type", instance.type)
        auth_group = Group.objects.select_for_update().get(pk=instance.group_id)
        auth_group.name = self._auth_group_name(instance.account, name, group_type)
        auth_group.save(update_fields=["name"])
        instance.group = auth_group
        return super().update(instance, validated_data)

    @staticmethod
    def get_type_display(obj):
        return obj.get_type_display()


class CoreAccountGroupReadSerializer(serializers.ModelSerializer):
    account = serializers.HiddenField(default=CurrentAccountDefault(), write_only=True)
    type_display = serializers.SerializerMethodField(read_only=True)
    permissions = serializers.SerializerMethodField(read_only=True)
    permission_details = serializers.SerializerMethodField(read_only=True)
    # Node-level scoping: ids of the account nodes assigned to this group.
    nodes = serializers.PrimaryKeyRelatedField(many=True, read_only=True)

    class Meta:
        model = CoreAccountGroup
        fields = (
            "id",
            "name",
            "type",
            "type_display",
            "account",
            "group",
            "permissions",
            "permission_details",
            "notes",
            "nodes",
        )

    @staticmethod
    def get_type_display(obj):
        return obj.get_type_display()

    @staticmethod
    def get_permissions(obj):
        permissions = {
            item: True
            for item in set(
                obj.group.permissions.filter(
                    content_type__app_label=CoreAccountGroup._meta.app_label,
                    content_type__model=CoreAccountGroup._meta.model_name,
                ).values_list("codename", flat=True)
            )
        }
        return permissions

    @staticmethod
    def get_permission_details(obj):
        permissions = list(
            obj.group.permissions.filter(
                content_type__app_label=CoreAccountGroup._meta.app_label,
                content_type__model=CoreAccountGroup._meta.model_name,
            ).values("name", "codename")
        )

        for permission in permissions:
            permission["codename_alt"] = permission["codename"].replace("_", " ").title()
        return permissions
