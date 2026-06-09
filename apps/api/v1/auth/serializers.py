from django.contrib.auth import authenticate
from rest_framework import serializers

from apps.console.member.models import CoreMember


class APIAuthLoginSerializer(serializers.Serializer):
    def __init__(self, **kwargs):
        super(APIAuthLoginSerializer, self).__init__(**kwargs)
        self.member = None

    email = serializers.EmailField(required=True, allow_blank=False)
    password = serializers.CharField(max_length=128, required=True)

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

        initial_values = self.get_initial()

        if value != initial_values["password_confirm"]:
            raise serializers.ValidationError("password do not match")

        # Apply Django's configured AUTH_PASSWORD_VALIDATORS (length, common, numeric, ...);
        # set_password() does not enforce these on its own.
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate_password_confirm(self, value):

        initial_values = self.get_initial()

        if value != initial_values["password"]:
            raise serializers.ValidationError("password do not match")
        return value

    def validate_password_token(self, value):
        # Resolve the token without leaking which tokens exist, then enforce
        # constant-time match + expiry via the model helper.
        for member in CoreMember.objects.filter(password_reset_token=value):
            if member.password_reset_token_is_valid(value):
                self.member = member
                return value
        raise serializers.ValidationError("Invalid or expired password reset token")
