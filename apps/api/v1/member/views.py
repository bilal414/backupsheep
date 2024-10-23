from django.conf import settings
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, mixins
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from twilio.rest.verify.v2.service.entity.new_factor import NewFactorInstance

from apps.console.member.models import CoreMember
from .filters import CoreMemberFilter
from .permissions import CoreMemberViewPermissions
from .serializers import (
    CoreMemberSerializer,
    CoreMemberWriteSerializer,
    MemberTokenAuthSerializer,
    MemberTokenVerifyAuthSerializer,
)
from ..utils.api_filters import DateRangeFilter
from ..utils.api_serializers import ReadWriteSerializerMixin
from rest_framework.response import Response
from twilio.rest import Client


class CoreMemberView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreMemberViewPermissions)
    read_serializer_class = CoreMemberSerializer
    write_serializer_class = CoreMemberWriteSerializer
    all_fields = [f.name for f in CoreMember._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreMemberFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query = Q(id=member.id)
        queryset = CoreMember.objects.filter(query)
        return queryset

    @action(detail=True, methods=["post"])
    def switch_current_account(self, request, pk=None):
        member = self.get_object()
        account_id = self.request.data.get("account_id")

        if member.memberships.filter(account_id=account_id).exists():
            membership = member.memberships.get(current=True)
            membership.current = False
            membership.save()

            membership = member.memberships.get(account_id=account_id)
            membership.current = True
            membership.save()

            return Response(
                {"detail": f"Current account switched to account {membership.account.name}."},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"detail": "Unable to switch account. Please contact support."},
                status=status.HTTP_400_BAD_REQUEST,
            )

    @action(detail=True, methods=["post"])
    def auth_multi_factor_token_setup(self, request, pk=None):
        member = self.get_object()

        serializer = MemberTokenAuthSerializer(
            data=request.data, context={"auth_multi_factor_id": member.auth_multi_factor_id}
        )
        serializer.is_valid(raise_exception=True)

        display_name = serializer.data["display_name"]

        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

        # factors = (
        #     client.verify.v2.services(settings.TWILIO_VERIFY_SID).entities(member.user.username).factors.list(limit=20)
        # )
        #
        # # Clear any previous factors
        # for record in factors:
        #     print(record.sid)
        #     if record.factor_type == "totp" and record.status == "unverified":
        #         client.verify.v2.services(settings.TWILIO_VERIFY_SID).entities(member.user.username).factors(
        #             record.sid
        #         ).delete()

        new_factor = (
            client.verify.v2.services(settings.TWILIO_VERIFY_SID)
            .entities(self.request.user.username)
            .new_factors.create(friendly_name=display_name, factor_type=NewFactorInstance.FactorTypes.TOTP)
        )

        return Response(
            {
                "detail": f"Please scan QR code with Authy or Google Authenticator.",
                "binding": new_factor.binding,
                "auth_multi_factor_id": new_factor.sid,
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"])
    def auth_multi_factor_token_verify(self, request, pk=None):
        member = self.get_object()

        serializer = MemberTokenVerifyAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        auth_multi_factor_token = serializer.data["auth_multi_factor_token"]
        auth_multi_factor_id = serializer.data["auth_multi_factor_id"]
        display_name = serializer.data["display_name"]

        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

        try:
            # challenge = (
            #     client.verify.v2.services(settings.TWILIO_VERIFY_SID)
            #     .entities(member.user.username)
            #     .challenges.create(auth_payload=auth_multi_factor_token, factor_sid=member.auth_multi_factor_id)
            # )
            factor = (
                client.verify.v2.services(settings.TWILIO_VERIFY_SID)
                .entities(member.user.username)
                .factors(auth_multi_factor_id)
                .update(auth_payload=auth_multi_factor_token)
            )

            if factor.status == "verified":

                member.auth_multi_factor_id = auth_multi_factor_id
                member.auth_multi_factor_display_name = display_name
                member.save()

                return Response(
                    {
                        "detail": f"Token verification successful.",
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "detail": f"Token verification failed. Check your token.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            return Response(
                {
                    "detail": f"Token verification failed. Check your token.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

    @action(detail=True, methods=["post"])
    def auth_multi_factor_token_revoke(self, request, pk=None):
        member = self.get_object()

        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

        client.verify.v2.services(settings.TWILIO_VERIFY_SID).entities(member.user.username).factors(
            member.auth_multi_factor_id
        ).delete()

        member.auth_multi_factor_id = None
        member.auth_multi_factor_display_name = None
        member.save()

        return Response(
            {
                "detail": f"Token authentication revoked.",
            },
            status=status.HTTP_200_OK,
        )
