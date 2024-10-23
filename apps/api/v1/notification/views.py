from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, mixins
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from apps.console.api.v1.utils.api_permissions import MemberPermissions
from apps.console.notification.models import CoreNotificationSlack, CoreNotificationTelegram, CoreNotificationEmail
from .filters import CoreNotificationSlackFilter, CoreNotificationTelegramFilter, CoreNotificationEmailFilter
from .permissions import (
    CoreNotificationSlackViewPermissions,
    CoreNotificationTelegramViewPermissions,
    CoreNotificationEmailViewPermissions,
)
from .serializers import (
    CoreNotificationSlackSerializer,
    CoreNotificationTelegramSerializer,
    CoreNotificationEmailSerializer,
)
from ..utils.api_filters import DateRangeFilter
from rest_framework.response import Response

from ..utils.api_serializers import ReadWriteSerializerMixin


class CoreNotificationSlackView(viewsets.ModelViewSet):
    permission_classes = (
        IsAuthenticated,
        CoreNotificationSlackViewPermissions,
    )
    serializer_class = CoreNotificationSlackSerializer
    all_fields = [f.name for f in CoreNotificationSlack._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreNotificationSlackFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query_partners = Q(account=member.get_current_account())
        queryset = CoreNotificationSlack.objects.filter(query_partners)
        return queryset

    @action(detail=True)
    def validate(self, request, pk=None):
        slack_notification = self.get_object()
        if slack_notification.validate():
            return Response(
                {
                    "detail": f"Validation request successful for Slack team {slack_notification.data['team']['name']} "
                    f"on channel {slack_notification.channel}."
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {
                    "detail": f"Unable to connect to Slack team {slack_notification.data['team']['name']} "
                    f"on channel {slack_notification.channel}. Please reconnect or contact support."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


class CoreNotificationTelegramView(viewsets.ModelViewSet):
    permission_classes = (
        IsAuthenticated,
        CoreNotificationTelegramViewPermissions,
    )
    serializer_class = CoreNotificationTelegramSerializer
    all_fields = [f.name for f in CoreNotificationTelegram._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreNotificationTelegramFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query_partners = Q(account=member.get_current_account())
        queryset = CoreNotificationTelegram.objects.filter(query_partners)
        return queryset

    @action(detail=True)
    def validate(self, request, pk=None):
        telegram_notification = self.get_object()
        try:
            if telegram_notification.validate():
                return Response(
                    {
                        "detail": f"Validation request successful for Telegram channel {telegram_notification.channel_name}."
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"detail": f"Unable to connect to Telegram channel {telegram_notification.channel_name}."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            return Response(
                {"detail": e.__str__()},
                status=status.HTTP_400_BAD_REQUEST,
            )


class CoreNotificationEmailView(viewsets.ModelViewSet):
    permission_classes = (
        IsAuthenticated,
        CoreNotificationEmailViewPermissions,
    )
    serializer_class = CoreNotificationEmailSerializer
    all_fields = [f.name for f in CoreNotificationEmail._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreNotificationEmailFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query_partners = Q(account=member.get_current_account())
        queryset = CoreNotificationEmail.objects.filter(query_partners)
        return queryset

    @action(detail=True, methods=["post"])
    def send_verification_email(self, request, pk=None):
        email_notification = self.get_object()
        email_notification.send_verification_email()
        return Response(
            {"detail": f"Verification email sent. Please check your inbox and junk/spam folder."},
            status=status.HTTP_200_OK,
        )
