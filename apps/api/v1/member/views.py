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

from apps.console.member.models import CoreMember, CoreMemberAccount
from .filters import CoreMemberFilter
from .permissions import CoreMemberViewPermissions
from .serializers import (
    CoreMemberSerializer,
    CoreMemberWriteSerializer,
    CurrentAccountMembershipSerializer,
    MemberTokenAuthSerializer,
    MemberTokenVerifyAuthSerializer,
)
from ..utils.api_filters import DateRangeFilter
from ..utils.api_serializers import ReadWriteSerializerMixin
from rest_framework.response import Response
from twilio.rest import Client


def _record_member_log(account, data):
    """Team-activity audit log. Never allowed to break the action it describes."""
    try:
        from apps.console.log.models import CoreLog

        CoreLog.record(account, CoreLog.Type.MEMBER, data)
    except Exception as e:
        print(f"Unable to record member log: {e}")


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
        query = Q(memberships__account=member.get_current_account())
        queryset = CoreMember.objects.filter(query).distinct()
        return queryset

    def list(self, request, *args, **kwargs):
        """The member list is membership-centric: every membership of the current
        account with member details, groups, notify flags and status markers."""
        account = request.user.member.get_current_account()
        memberships = (
            CoreMemberAccount.objects.filter(account=account)
            .select_related("member__user")
            .prefetch_related("member__user__groups")
            .order_by("id")
        )
        serializer = CurrentAccountMembershipSerializer(
            memberships, many=True, context={"request": request, "account": account}
        )
        return Response(serializer.data)

    @action(detail=True, methods=["post"])
    def update_membership(self, request, pk=None):
        """Update a member's groups and notify flags within the current account.

        Gated to the account's primary member (same rule as remove_membership).
        Group sync reuses the invite-accept pattern: drop every auth group of this
        account's enrollments, then add the selected ones."""
        member = request.user.member
        account = member.get_current_account()

        if not member.is_primary_account:
            return Response(
                {"detail": "Only the account owner can manage users."},
                status=status.HTTP_403_FORBIDDEN,
            )

        membership = (
            CoreMemberAccount.objects.filter(member_id=pk, account=account)
            .select_related("member__user")
            .first()
        )
        if not membership:
            return Response(
                {"detail": "Membership not found for this account."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if membership.member_id == member.id:
            return Response(
                {"detail": "You cannot change your own groups here."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            group_ids = [int(group_id) for group_id in request.data.get("groups", [])]
        except (TypeError, ValueError):
            return Response(
                {"detail": "Invalid groups."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        enrollments = list(account.enrollments.filter(id__in=group_ids))
        if len(enrollments) != len(set(group_ids)):
            return Response(
                {"detail": "Groups must belong to the current account."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Sync auth Group membership from the account's CoreAccountGroups.
        for enrollment in account.enrollments.all():
            membership.member.user.groups.remove(enrollment.group)
        for enrollment in enrollments:
            membership.member.user.groups.add(enrollment.group)

        if "notify_on_success" in request.data:
            membership.notify_on_success = bool(request.data.get("notify_on_success"))
        if "notify_on_fail" in request.data:
            membership.notify_on_fail = bool(request.data.get("notify_on_fail"))
        membership.save()

        _record_member_log(
            account,
            {
                "message": f"Groups updated for member {membership.member.email}.",
                "actor_email": request.user.email,
                "member_id": membership.member_id,
                "member_email": membership.member.email,
                "group_ids": group_ids,
            },
        )

        serializer = CurrentAccountMembershipSerializer(
            membership, context={"request": request, "account": account}
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

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
