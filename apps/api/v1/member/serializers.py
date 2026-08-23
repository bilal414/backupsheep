import pytz
from django.contrib.auth.models import User
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.timezone import get_current_timezone
from rest_framework.authtoken.models import Token
from rest_framework import serializers
from apps.console.account.models import CoreAccount
from apps.api.v1.account.serializers import CoreAccountSerializer
from apps.console.member.models import CoreMember, CoreMemberAccount


class CoreMemberAccountSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer()

    class Meta:
        model = CoreMemberAccount
        fields = "__all__"


class CurrentAccountMembershipSerializer(serializers.ModelSerializer):
    """One membership row for the account member list (Users settings page):
    member details plus groups/notify flags/status within the current account."""

    id = serializers.IntegerField(source="member.id", read_only=True)
    membership_id = serializers.IntegerField(source="pk", read_only=True)
    member_id = serializers.IntegerField(source="member.id", read_only=True)
    first_name = serializers.CharField(source="member.user.first_name", read_only=True)
    last_name = serializers.CharField(source="member.user.last_name", read_only=True)
    full_name = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    email = serializers.CharField(source="member.user.email", read_only=True)
    status_display = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    role_display = serializers.SerializerMethodField()
    account = CoreAccountSerializer(read_only=True)
    groups = serializers.SerializerMethodField()

    class Meta:
        model = CoreMemberAccount
        fields = (
            "id",
            "membership_id",
            "member_id",
            "first_name",
            "last_name",
            "full_name",
            "name",
            "email",
            "status",
            "status_display",
            "role",
            "role_display",
            "account",
            "notify_on_success",
            "notify_on_fail",
            "current",
            "primary",
            "groups",
            "created",
        )

    @staticmethod
    def get_full_name(obj):
        return obj.member.full_name

    @staticmethod
    def get_name(obj):
        return obj.member.full_name

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

    @staticmethod
    def get_role(obj):
        return "owner" if obj.primary else "member"

    @staticmethod
    def get_role_display(obj):
        return "Owner" if obj.primary else "Member"

    def get_groups(self, obj):
        # Intersect the member's auth groups with the current account's enrollments.
        account = self.context["account"]
        enrollments = account.enrollments.filter(group__user=obj.member.user)
        return [
            {
                "id": enrollment.id,
                "name": enrollment.name,
                "type": enrollment.type,
                "type_display": enrollment.get_type_display(),
            }
            for enrollment in enrollments
        ]


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
    current_password = serializers.CharField(
        max_length=128, required=False, allow_blank=False, write_only=True
    )
    password = serializers.CharField(
        max_length=128, required=False, allow_blank=False, write_only=True, min_length=8
    )
    password_confirm = serializers.CharField(
        max_length=128, required=False, allow_blank=False, write_only=True, min_length=8
    )

    class Meta:
        model = User
        fields = (
            "id",
            "first_name",
            "last_name",
            "email",
            "current_password",
            "password",
            "password_confirm",
        )

    def validate(self, data):
        changing_password = any(
            key in data for key in ("current_password", "password", "password_confirm")
        )
        if not changing_password:
            return data

        if not all(
            data.get(key) for key in ("current_password", "password", "password_confirm")
        ):
            raise serializers.ValidationError(
                "Current password, new password, and confirmation are all required."
            )
        if data["password"] != data["password_confirm"]:
            raise serializers.ValidationError(
                {"password_confirm": "Both password fields must match."}
            )

        request = self.context.get("request")
        if request is None or not request.user.check_password(data["current_password"]):
            raise serializers.ValidationError(
                {"current_password": "Current password is incorrect."}
            )
        try:
            validate_password(data["password"], user=request.user)
        except DjangoValidationError as error:
            raise serializers.ValidationError({"password": list(error.messages)})
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
        # Password reset capability is a bearer secret. It must never appear in
        # the team-member API, even to another member of the same account.
        exclude = ("password_reset_token", "password_reset_token_created")
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
            "timezone",
            "user",
            "memberships",
        )

    def update(self, instance, validated_data):
        user = validated_data.pop("user", {})
        memberships = validated_data.pop("memberships", [])
        password = user.pop("password", None)
        user.pop("current_password", None)
        user.pop("password_confirm", None)
        django_user = super().update(instance.user, user)
        if password:
            django_user.set_password(password)
            django_user.save(update_fields=["password"])
            Token.objects.filter(user=django_user).delete()
            request = self.context.get("request")
            if request is not None:
                update_session_auth_hash(request, django_user)
        for membership in memberships:
            super().update(instance.memberships.get(current=True), membership)
            super().update(instance.memberships.get(current=True).account, membership)
        instance = super().update(instance, validated_data)
        if instance.timezone:
            self.context["request"].session["django_timezone"] = instance.timezone
        return instance
