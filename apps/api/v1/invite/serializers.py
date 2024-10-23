import pytz
from django.contrib.auth.models import User
from django.utils.timezone import get_current_timezone
from firebase_admin.auth import UserNotFoundError
from rest_framework import serializers
from firebase_admin import auth
from apps.console.api.v1.utils.api_helpers import CurrentAccountDefault, CurrentMemberDefault
from apps.console.invite.models import CoreInvite
from apps.console.member.models import CoreMember


class CoreInviteReadSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreInvite
        fields = "__all__"

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


class CoreInviteWriteSerializer(serializers.ModelSerializer):
    account = serializers.HiddenField(default=CurrentAccountDefault(), write_only=True)
    added_by = serializers.HiddenField(default=CurrentMemberDefault())

    class Meta:
        model = CoreInvite
        fields = "__all__"

    def validate(self, data):
        if not CoreMember.objects.filter(user__email=data["email"]).exists():
            raise serializers.ValidationError(
                {
                    "email": f"We could not locate any user with the email {data['email']}. If they are a new user, please have them create a free Developer account first, after which you can send an invitation."
                }
            )
        return data

    # def update(self, instance, validated_data):
    #     user = validated_data.pop("user", [])
    #     memberships = validated_data.pop("memberships", [])
    #     auth.update_user(
    #         instance.user.username,
    #         email=user.get("email"),
    #         password=user.get("password"),
    #         display_name=f"{user.get('first_name')} {user.get('last_name')} ",
    #     )
    #     user.pop('password', None)
    #     user.pop('password_confirm', None)
    #     super().update(instance.user, user)
    #     for membership in memberships:
    #         super().update(instance.memberships.get(current=True), membership)
    #         super().update(instance.memberships.get(current=True).account, membership)
    #     instance = super().update(instance, validated_data)
    #     if instance.timezone:
    #         self.context["request"].session["django_timezone"] = instance.timezone
    #     return instance

    # def create(self, validated_data):
    #     # Create User First
    #     user = validated_data.pop("user", [])
    #     if auth.get_user_by_email(user["email"]):
    #     serializer = UserWriteSerializer(user)
    #     serializer.is_valid(raise_exception=True)
    #     serializer.save()
    #
    #     validated_data["user"] = User.objects.create(**user)
    #     instance = super().create(**validated_data)
    #     return instance
