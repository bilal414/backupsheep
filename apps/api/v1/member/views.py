from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, mixins
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend

from apps.console.member.models import CoreMember, CoreMemberAccount
from .filters import CoreMemberFilter
from .permissions import CoreMemberViewPermissions
from .serializers import (
    CoreMemberSerializer,
    CoreMemberWriteSerializer,
    CurrentAccountMembershipSerializer,
    MemberTokenAuthSerializer,
    MemberTokenRevokeAuthSerializer,
    MemberTokenVerifyAuthSerializer,
)
from ..utils.api_filters import DateRangeFilter
from ..utils.api_serializers import ReadWriteSerializerMixin
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from apps.console.member.totp import generate_totp_secret, provisioning_uri
from utils.middleware import AUTH_SESSION_VERSION_KEY
from ..utils.api_throttles import MFARateThrottle, MFAIdentityRateThrottle


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

        try:
            target_id = int(pk)
        except (TypeError, ValueError):
            target_id = None

        membership = None
        if target_id is not None:
            # The API uses member IDs in this route. Accepting a membership ID
            # as a fallback keeps the existing web editor compatible, while the
            # account filter prevents cross-tenant membership updates.
            membership = (
                CoreMemberAccount.objects.filter(member_id=target_id, account=account)
                .select_related("member__user")
                .first()
            )
            if membership is None:
                membership = (
                    CoreMemberAccount.objects.filter(pk=target_id, account=account)
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
        member = request.user.member
        if str(pk) != str(member.pk):
            return Response(
                {"detail": "You can only switch your own current account."},
                status=status.HTTP_403_FORBIDDEN,
            )

        account_id = self.request.data.get("account_id")

        membership = member.set_current_account(account_id)
        if membership is not None:
            return Response(
                {"detail": f"Current account switched to account {membership.account.name}."},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"detail": "Unable to switch account. Please contact support."},
                status=status.HTTP_400_BAD_REQUEST,
            )

    @action(
        detail=True,
        methods=["post"],
        throttle_classes=[MFARateThrottle, MFAIdentityRateThrottle],
    )
    def auth_multi_factor_token_setup(self, request, pk=None):
        member = self.get_object()

        serializer = MemberTokenAuthSerializer(
            data=request.data, context={"member": member, "request": request}
        )
        serializer.is_valid(raise_exception=True)

        display_name = serializer.validated_data["display_name"]
        secret = generate_totp_secret()
        member.set_pending_totp_secret(secret, display_name)

        return Response(
            {
                "detail": "Add the secret to your authenticator app, then verify the six-digit code.",
                "binding": {
                    "secret": secret,
                    "uri": provisioning_uri(secret, member.email),
                },
                "auth_multi_factor_id": "totp-pending",
            },
            status=status.HTTP_200_OK,
        )

    @action(
        detail=True,
        methods=["post"],
        throttle_classes=[MFARateThrottle, MFAIdentityRateThrottle],
    )
    def auth_multi_factor_token_verify(self, request, pk=None):
        member = self.get_object()

        serializer = MemberTokenVerifyAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["auth_multi_factor_token"]
        if not member.verify_pending_totp(token):
            return Response(
                {"detail": "Token verification failed or the setup expired."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        Token.objects.filter(user=member.user).delete()
        member.rotate_auth_session_version()
        request.session[AUTH_SESSION_VERSION_KEY] = member.auth_session_version
        return Response(
            {"detail": "Authenticator verification successful."},
            status=status.HTTP_200_OK,
        )

    @action(
        detail=True,
        methods=["post"],
        throttle_classes=[MFARateThrottle, MFAIdentityRateThrottle],
    )
    def auth_multi_factor_token_revoke(self, request, pk=None):
        member = self.get_object()
        serializer = MemberTokenRevokeAuthSerializer(
            data=request.data, context={"member": member, "request": request}
        )
        serializer.is_valid(raise_exception=True)
        if not member.consume_totp(
            serializer.validated_data["auth_multi_factor_token"]
        ):
            return Response(
                {"detail": "The authenticator code is invalid or was already used."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        member.clear_mfa()
        Token.objects.filter(user=member.user).delete()
        member.rotate_auth_session_version()
        request.session[AUTH_SESSION_VERSION_KEY] = member.auth_session_version

        return Response(
            {
                "detail": f"Token authentication revoked.",
            },
            status=status.HTTP_200_OK,
        )
