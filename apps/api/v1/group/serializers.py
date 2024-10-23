from django.db.models import Q
from django.utils.text import slugify
from rest_framework import serializers
from django.contrib.auth.models import Group, Permission

from apps.console.account.models import CoreAccountGroup
from apps.console.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault,
    GenerateGroup,
    AccountGroupDefault,
)


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = "__al__"


class CoreAccountGroupWriteSerializer(serializers.ModelSerializer):
    account = serializers.HiddenField(default=CurrentAccountDefault(), write_only=True)
    # group = GroupSerializer(write_only=True)
    default = serializers.HiddenField(default=AccountGroupDefault())
    type_display = serializers.SerializerMethodField(read_only=True)
    permissions = serializers.ListField(required=False, child=serializers.CharField(), write_only=True)
    notes = serializers.CharField(required=False, allow_null=True, allow_blank=True)

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
        )

    def validate(self, data):
        errors = {}
        # Generate Group Name
        account = self.context["request"].user.member.get_current_account()
        type_choices = dict(CoreAccountGroup.Type.choices)
        type_name = type_choices[int(data["type"])]
        group_name = slugify(f"{account.id}-{data['name']}-{type_name}")

        if self.instance:
            query = Q(name__iexact=data["name"])
            query &= ~Q(id=self.instance.id)
            if account.enrollments.filter(query).exists():
                errors["name"] = ["Group name must be unique."]
            else:
                self.instance.group.name = group_name
                self.instance.group.save()
                #
                # # Now add permissions to group
                # if data.get("permissions"):
                #     for permission in data.get("permissions"):
                #         self.instance.group.permissions.add(permission)
        else:
            if account.enrollments.filter(name__iexact=data["name"]).exists():
                errors["name"] = ["Group name must be unique."]
            else:
                data["group"] = Group.objects.create(name=group_name)

        if bool(errors):
            raise serializers.ValidationError(errors)

        return data

    @staticmethod
    def get_type_display(obj):
        return obj.get_type_display()


class CoreAccountGroupReadSerializer(serializers.ModelSerializer):
    account = serializers.HiddenField(default=CurrentAccountDefault(), write_only=True)
    type_display = serializers.SerializerMethodField(read_only=True)
    permissions = serializers.SerializerMethodField(read_only=True)
    permission_details = serializers.SerializerMethodField(read_only=True)

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
        )

    @staticmethod
    def get_type_display(obj):
        return obj.get_type_display()

    @staticmethod
    def get_permissions(obj):
        permissions = {item: True for item in set(obj.group.permissions.values_list("codename", flat=True))}
        return permissions

    @staticmethod
    def get_permission_details(obj):
        permissions = list(obj.group.permissions.values("name", "codename"))

        for permission in permissions:
            permission["codename_alt"] = permission["codename"].replace("_", " ").title()
        return permissions
