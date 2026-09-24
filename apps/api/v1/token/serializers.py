from django.conf import settings
from rest_framework import serializers

from apps.api.v1.utils.api_scopes import SCOPES, validate_scopes
from apps.console.api_access.models import CoreApiToken
from apps.console.member.models import CoreMemberAccount


class CurrentPasswordSerializer(serializers.Serializer):
    """Re-authenticate before minting or rotating a credential."""

    current_password = serializers.CharField(write_only=True, style={"input_type": "password"})

    def validate_current_password(self, value):
        user = self.context["request"].user
        if not user.has_usable_password() or not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value


class ApiTokenAccountSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    name = serializers.CharField(read_only=True)


class ApiTokenSerializer(serializers.ModelSerializer):
    scopes = serializers.ListField(child=serializers.CharField(), read_only=True)
    account = ApiTokenAccountSerializer(read_only=True)
    status = serializers.CharField(read_only=True)

    class Meta:
        model = CoreApiToken
        fields = (
            "id",
            "name",
            "key_prefix",
            "scopes",
            "account",
            "status",
            "expires_at",
            "last_used_at",
            "revoked_at",
            "created",
        )
        read_only_fields = fields


class ApiTokenCreateSerializer(CurrentPasswordSerializer):
    name = serializers.CharField(max_length=128)
    scopes = serializers.ListField(
        child=serializers.CharField(max_length=64),
        allow_empty=False,
        help_text="Scopes to grant; see GET /api/v1/tokens/scopes/.",
    )
    expires_in = serializers.IntegerField(
        required=False,
        min_value=300,
        help_text="Lifetime in seconds (default API_TOKEN_TTL_SECONDS, capped by "
        "API_TOKEN_MAX_TTL_SECONDS).",
    )
    account_id = serializers.IntegerField(
        required=False,
        help_text="Workspace the token is bound to (default: your current workspace).",
    )

    def validate_scopes(self, value):
        try:
            return validate_scopes(value)
        except ValueError as error:
            raise serializers.ValidationError(str(error))

    def validate_expires_in(self, value):
        maximum = int(settings.API_TOKEN_MAX_TTL_SECONDS)
        if value > maximum:
            raise serializers.ValidationError(
                f"Token lifetime may not exceed {maximum} seconds on this install."
            )
        return value

    def validate(self, data):
        member = self.context["request"].user.member
        memberships = member.memberships.filter(status=CoreMemberAccount.Status.ACTIVE)
        if "account_id" in data:
            membership = memberships.filter(account_id=data["account_id"]).first()
            if membership is None:
                raise serializers.ValidationError(
                    {"account_id": "You do not have an active membership in that workspace."}
                )
        else:
            membership = member.get_active_current_membership()
            if membership is None:
                raise serializers.ValidationError(
                    {"account_id": "No active workspace is selected."}
                )
        data["account"] = membership.account
        return data


class ApiScopeSerializer(serializers.Serializer):
    scope = serializers.ChoiceField(choices=[(name, name) for name in SCOPES])
    description = serializers.CharField()
    implies = serializers.ListField(child=serializers.CharField())
