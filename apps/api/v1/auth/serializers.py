from django.contrib.auth import authenticate
from rest_framework import serializers

from apps.console.member.models import CoreMember


class APIAuthLoginSerializer(serializers.Serializer):
    def __init__(self, **kwargs):
        super(APIAuthLoginSerializer, self).__init__(**kwargs)
        self.member = None
        self.requires_mfa = False

    email = serializers.EmailField(required=True, allow_blank=False)
    password = serializers.CharField(max_length=128, required=True)
    auth_multi_factor_token = serializers.CharField(
        max_length=8, required=False, allow_blank=True, write_only=True
    )

    def validate_password(self, value):
        # Use a single generic error for both unknown-email and wrong-password so the
        # endpoint does not let an attacker enumerate which emails are registered.
        initial_values = self.get_initial()
        email = initial_values.get("email")

        generic_error = serializers.ValidationError("wrong email & password combination")

        member = CoreMember.objects.filter(user__email__iexact=email).first()
        if not member:
            raise generic_error

        user = authenticate(username=member.user.username, password=value)
        if not user:
            raise generic_error

        self.member = user.member
        return value

    def validate(self, attrs):
        if self.member and self.member.mfa_enabled:
            token = attrs.get("auth_multi_factor_token")
            if not token:
                # Password was valid, but do not create a session or bearer token.
                # The browser uses this flag to reveal the authenticator-code field.
                self.requires_mfa = True
                return attrs
            if not self.member.consume_totp(token):
                raise serializers.ValidationError(
                    {"auth_multi_factor_token": "Invalid or already-used authenticator code."}
                )
        return attrs


class APIAuthResetSerializer(serializers.Serializer):
    def __init__(self, **kwargs):
        super(APIAuthResetSerializer, self).__init__(**kwargs)
        self.member = None

    def update(self, instance, validated_data):
        pass

    email = serializers.EmailField(required=True, allow_blank=False)

    def validate_email(self, value):
        # Always validate successfully; whether a reset email is actually sent depends on
        # whether the address exists, but the response must not reveal that (account
        # enumeration). The view only sends when self.member is set.
        self.member = CoreMember.objects.filter(user__email__iexact=value).first()
        return value


class APIAuthResetPatchSerializer(serializers.Serializer):
    def __init__(self, **kwargs):
        super(APIAuthResetPatchSerializer, self).__init__(**kwargs)
        self.member = None

    def update(self, instance, validated_data):
        pass

    password = serializers.CharField(min_length=8, required=True, allow_blank=False)
    password_confirm = serializers.CharField(
        min_length=8, required=True, allow_blank=False
    )
    password_token = serializers.CharField(required=True, allow_blank=False)

    def validate_password(self, value):
        from django.contrib.auth.password_validation import validate_password
        from django.core.exceptions import ValidationError as DjangoValidationError

        # Apply Django's configured AUTH_PASSWORD_VALIDATORS (length, common, numeric, ...);
        # set_password() does not enforce these on its own.
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, attrs):
        if attrs.get("password") != attrs.get("password_confirm"):
            raise serializers.ValidationError(
                {"password_confirm": "Both password fields must match."}
            )
        return attrs

    def validate_password_token(self, value):
        # Resolve the token without leaking which tokens exist, then enforce
        # constant-time match + expiry via the model helper.
        for member in CoreMember.objects.filter(password_reset_token=value):
            if member.password_reset_token_is_valid(value):
                self.member = member
                return value
        raise serializers.ValidationError("Invalid or expired password reset token")
