from django.contrib.auth.models import User
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.authtoken.models import Token
from rest_framework import serializers
from apps.console.account.models import CoreAccount
from apps.api.v1.account.serializers import CoreAccountSerializer
from apps.console.member.models import CoreMember, CoreMemberAccount
from utils.middleware import AUTH_SESSION_VERSION_KEY


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
    """Public identity fields embedded in member read responses.

    Authorization metadata belongs to Django's authentication boundary.  A
    shared-workspace member may see a peer's basic directory identity, but must
    never receive staff flags, global permissions, or auth-group primary keys.
    Profile mutations continue to use the separate UserWriteSerializer below.
    """

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "first_name",
            "last_name",
            "email",
        )
        read_only_fields = fields


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
    current_password = serializers.CharField(
        max_length=128, allow_null=False, allow_blank=False, write_only=True
    )

    def validate(self, data):
        member = self.context["member"]
        if member.mfa_enabled:
            raise serializers.ValidationError(
                f"Two-Factor token authentication is already setup. Revoke auth token and try again."
            )
        if not member.user.check_password(data["current_password"]):
            raise serializers.ValidationError(
                {"current_password": "Current password is incorrect."}
            )
        return data


class MemberTokenVerifyAuthSerializer(serializers.Serializer):
    auth_multi_factor_token = serializers.RegexField(r"^\d{6}$")


class MemberTokenRevokeAuthSerializer(serializers.Serializer):
    current_password = serializers.CharField(
        max_length=128, allow_null=False, allow_blank=False, write_only=True
    )
    auth_multi_factor_token = serializers.RegexField(r"^\d{6}$")

    def validate_current_password(self, value):
        if not self.context["member"].user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value


class CoreMemberSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    user = UserSerializer()
    memberships = serializers.SerializerMethodField()

    class Meta:
        model = CoreMember
        # This shared-workspace read endpoint is a directory contract, not an
        # identity-security or profile-settings endpoint. Keep it allowlisted so
        # new CoreMember fields (MFA state, reset state, timezone, account M2M,
        # etc.) cannot become tenant-visible merely by being added to the model.
        fields = (
            "id",
            "user",
            "full_name",
            "email",
            "memberships",
        )
        read_only_fields = fields
        datatables_always_serialize = (
            "id",
            "user",
            "memberships",
        )

    @staticmethod
    def get_full_name(obj):
        return obj.full_name

    @staticmethod
    def get_email(obj):
        return obj.email

    def get_memberships(self, obj):
        """Expose self memberships while constraining peer workspace state.

        The signed-in identity keeps its account-switcher contract. A peer may be
        discoverable through a shared workspace, but that must not turn the peer
        detail representation into a directory of their other workspaces.
        """
        request = self.context.get("request")
        if request is None or not hasattr(request.user, "member"):
            memberships = obj.memberships.none()
        elif obj.pk == request.user.member.pk:
            # Preserve the signed-in identity endpoint as the account switcher
            # contract: a person may review their own workspace memberships.
            memberships = obj.memberships.all()
        else:
            account = request.user.member.get_current_account()
            memberships = obj.memberships.filter(account=account)
        return CoreMemberAccountSerializer(
            memberships,
            many=True,
            context=self.context,
        ).data


class CoreMemberWriteSerializer(serializers.ModelSerializer):
    user = UserWriteSerializer()
    memberships = CoreMemberAccountWriteSerializer(
        many=True,
        required=False,
        max_length=1,
    )

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
            instance.rotate_auth_session_version()
            request = self.context.get("request")
            if request is not None:
                update_session_auth_hash(request, django_user)
                request.session[AUTH_SESSION_VERSION_KEY] = (
                    instance.auth_session_version
                )
        # These are the signed-in member's recipient preferences for the current
        # workspace.  Account-wide event gates are owner-managed through the
        # account endpoint and must never be writable through a self-profile PATCH.
        if memberships:
            super().update(instance.memberships.get(current=True), memberships[0])
        instance = super().update(instance, validated_data)
        if instance.timezone:
            self.context["request"].session["django_timezone"] = instance.timezone
        return instance
