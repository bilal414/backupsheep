import pytz
from django.contrib.auth.models import User
from django.utils.timezone import get_current_timezone
from firebase_admin.auth import UserNotFoundError
from rest_framework import serializers
from firebase_admin import auth
from apps.console.account.models import CoreAccount
from apps.console.api.v1.account.serializers import CoreAccountSerializer
from apps.console.member.models import CoreMember, CoreMemberAccount


class CoreMemberAccountSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer()

    class Meta:
        model = CoreMemberAccount
        fields = "__all__"


class CoreMemberAccountWriteSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreMemberAccount
        fields = (
            "notify_on_success",
            "notify_on_fail",
        )


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = ("password",)


class UserWriteSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(read_only=True)
    password = serializers.CharField(max_length=128, allow_null=True, allow_blank=False, write_only=True, min_length=6)
    password_confirm = serializers.CharField(
        max_length=128, allow_null=True, allow_blank=False, write_only=True, min_length=6
    )

    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "email", "password", "password_confirm")

    def validate(self, data):
        if data.get("password") != data.get("password_confirm"):
            raise serializers.ValidationError(
                {"password": "Both passwords fields should be same."},
                {"password_confirm": "Both passwords fields should be same."},
            )
        else:
            return data

    # def validate_email(self, data):
    #     if self.parent.instance.user.email != data:
    #         try:
    #             auth.get_user_by_email(data)
    #             raise serializers.ValidationError(
    #                 "User already exists with same email. Please use different email."
    #             )
    #         except UserNotFoundError:
    #             return data
    #     else:
    #         return data


class MemberTokenAuthSerializer(serializers.Serializer):
    display_name = serializers.CharField(max_length=128, allow_null=False, allow_blank=False, min_length=6)

    def validate(self, data):
        if self.context.get("auth_multi_factor_id"):
            raise serializers.ValidationError(
                f"Two-Factor token authentication is already setup. Revoke auth token and try again."
            )
        return data


class MemberTokenVerifyAuthSerializer(serializers.Serializer):
    auth_multi_factor_id = serializers.CharField(max_length=128, allow_null=False, allow_blank=False, min_length=6)
    auth_multi_factor_token = serializers.CharField(max_length=128, allow_null=False, allow_blank=False, min_length=6)
    display_name = serializers.CharField(max_length=128, allow_null=False, allow_blank=False, min_length=6)


class CoreMemberSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    full_name = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    user = UserSerializer()
    memberships = CoreMemberAccountSerializer(many=True)

    class Meta:
        model = CoreMember
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "user",
            "memberships",
        )

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
    def get_full_name(obj):
        return obj.full_name

    @staticmethod
    def get_email(obj):
        return obj.email


class CoreMemberWriteSerializer(serializers.ModelSerializer):
    user = UserWriteSerializer()
    memberships = CoreMemberAccountWriteSerializer(many=True)

    class Meta:
        model = CoreMember
        fields = (
            "notify_on_success",
            "notify_on_fail",
            "timezone",
            "user",
            "memberships",
        )

    def update(self, instance, validated_data):
        user = validated_data.pop("user", [])
        memberships = validated_data.pop("memberships", [])
        auth.update_user(
            instance.user.username,
            email=user.get("email"),
            password=user.get("password"),
            display_name=f"{user.get('first_name')} {user.get('last_name')} ",
        )
        user.pop("password", None)
        user.pop("password_confirm", None)
        super().update(instance.user, user)
        for membership in memberships:
            super().update(instance.memberships.get(current=True), membership)
            super().update(instance.memberships.get(current=True).account, membership)
        instance = super().update(instance, validated_data)
        if instance.timezone:
            self.context["request"].session["django_timezone"] = instance.timezone
        return instance
