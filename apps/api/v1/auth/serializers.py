from django.contrib.auth import authenticate
from rest_framework import serializers

from apps.console.member.models import CoreMember


class APIAuthLoginSerializer(serializers.Serializer):
    def __init__(self, **kwargs):
        super(APIAuthLoginSerializer, self).__init__(**kwargs)
        self.member = None

    email = serializers.EmailField(required=True, allow_blank=False)
    password = serializers.CharField(max_length=128, required=True)

    @staticmethod
    def validate_email(value):
        if CoreMember.objects.filter(
                user__email__iexact=value, status=CoreMember.Status.DISABLED
        ).exists():
            raise serializers.ValidationError(
                "Your account is disabled. Please contact administrator."
            )
        elif CoreMember.objects.filter(
                user__email__iexact=value, status=CoreMember.Status.PENDING
        ).exists():
            raise serializers.ValidationError(
                "Your account is pending. Please contact administrator."
            )
        elif not CoreMember.objects.filter(user__email__iexact=value).exists():
            raise serializers.ValidationError("Email not found")
        return value

    def validate_password(self, value):
        initial_values = self.get_initial()

        email = initial_values["email"]

        if CoreMember.objects.filter(user__email__iexact=email).exists():
            member = CoreMember.objects.get(user__email__iexact=email)
            user = member.user

            if not authenticate(username=user.username, password=value):
                raise serializers.ValidationError("wrong email & password combination")
            else:
                user = authenticate(username=user.username, password=value)
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
        if CoreMember.objects.filter(user__email__iexact=value).exists() is False:
            raise serializers.ValidationError("email doesn't exists")
        elif CoreMember.objects.filter(user__email__iexact=value).exists() is True:
            self.member = CoreMember.objects.get(user__email__iexact=value)
        return value


class APIAuthResetPatchSerializer(serializers.Serializer):
    def __init__(self, **kwargs):
        super(APIAuthResetPatchSerializer, self).__init__(**kwargs)
        self.member = None

    def update(self, instance, validated_data):
        pass

    password = serializers.CharField(min_length=4, required=True, allow_blank=False)
    password_confirm = serializers.CharField(
        min_length=4, required=True, allow_blank=False
    )
    password_token = serializers.CharField(required=True, allow_blank=False)

    def validate_password(self, value):

        initial_values = self.get_initial()

        if value != initial_values["password_confirm"]:
            raise serializers.ValidationError("password do not match")
        return value

    def validate_password_confirm(self, value):

        initial_values = self.get_initial()

        if value != initial_values["password"]:
            raise serializers.ValidationError("password do not match")
        return value

    def validate_password_token(self, value):
        if CoreMember.objects.filter(password_reset_token=value).exists() is False:
            raise serializers.ValidationError("wrong password reset token")
        elif CoreMember.objects.filter(password_reset_token=value).exists() is True:
            self.member = CoreMember.objects.get(password_reset_token=value)
        return value
