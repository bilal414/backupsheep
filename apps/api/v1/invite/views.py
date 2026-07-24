from django.db.models import Q
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, mixins
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from apps.console.invite.models import CoreInvite
from .filters import CoreInviteFilter
from .permissions import CoreInviteViewPermissions
from .serializers import CoreInviteReadSerializer, CoreInviteWriteSerializer
from ..utils.api_filters import DateRangeFilter
from ..utils.api_serializers import ReadWriteSerializerMixin
from rest_framework.response import Response


def _send_invite_email_safe(invite):
    """Send the invite email without ever breaking the invite flow itself: the
    invite (and its accept link) must survive a misconfigured/unreachable email
    provider -- the admin can always resend later."""
    try:
        invite.send_invite_email()
    except Exception as e:
        print(f"Unable to send invite email for invite {invite.id}: {e}")


def _record_member_log(account, data):
    """Team-activity audit log. Never allowed to break the action it describes."""
    try:
        from apps.console.log.models import CoreLog

        CoreLog.record(account, CoreLog.Type.MEMBER, data)
    except Exception as e:
        print(f"Unable to record member log: {e}")


class CoreInviteView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreInviteViewPermissions)
    read_serializer_class = CoreInviteReadSerializer
    write_serializer_class = CoreInviteWriteSerializer
    all_fields = [f.name for f in CoreInvite._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreInviteFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query = Q(account=member.get_current_account())
        queryset = CoreInvite.objects.filter(query)
        # Lazily flip past-expiry pending invites so listings show the real state.
        queryset.filter(
            status=CoreInvite.Status.PENDING, expires_at__lt=timezone.now()
        ).update(status=CoreInvite.Status.EXPIRED)
        return queryset

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        invite = serializer.instance

        _send_invite_email_safe(invite)
        _record_member_log(
            invite.account,
            {
                "message": f"Invite sent to {invite.email}.",
                "actor_email": request.user.email,
                "invite_id": invite.id,
                "invitee_email": invite.email,
            },
        )

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    @action(detail=True, methods=["post"])
    def resend(self, request, pk=None):
        """Re-send the invite email and restart the acceptance window. Pending
        invites only -- a cancelled/accepted invite cannot be revived."""
        invite = self.get_object()

        if invite.status != CoreInvite.Status.PENDING:
            return Response(
                {"detail": f"Only pending invites can be resent. This invite is {invite.get_status_display().lower()}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        invite.reset_expiry()
        _send_invite_email_safe(invite)

        return Response(
            {"detail": f"Invite resent to {invite.email}."},
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"])
    def cancel(self, request, pk=None):
        """Cancel a pending invite; its accept link stops working immediately."""
        invite = self.get_object()

        if invite.status != CoreInvite.Status.PENDING:
            return Response(
                {"detail": f"Only pending invites can be cancelled. This invite is {invite.get_status_display().lower()}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        invite.status = CoreInvite.Status.CANCELLED
        invite.save(update_fields=["status", "modified"])
        _record_member_log(
            invite.account,
            {
                "message": f"Invite for {invite.email} cancelled.",
                "actor_email": request.user.email,
                "invite_id": invite.id,
                "invitee_email": invite.email,
            },
        )

        return Response(
            {"detail": f"Invite for {invite.email} cancelled."},
            status=status.HTTP_200_OK,
        )

    @action(detail=True)
    def accept(self, request, pk=None):
        member = self.request.user.member

        invite = CoreInvite.objects.filter(
            id=pk,
            email__iexact=self.request.user.email,
        ).first()

        # Lazily enforce the acceptance window before looking at the status.
        if invite and invite.expire_if_needed():
            return Response(
                {"detail": "This invite has expired. Please ask for a new invite."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if invite and invite.status == CoreInvite.Status.PENDING:
            invite.accept(member)
            _record_member_log(
                invite.account,
                {
                    "message": f"Invite accepted by {member.email}.",
                    "actor_email": request.user.email,
                    "invite_id": invite.id,
                    "invitee_email": invite.email,
                },
            )

            return Response(
                {"detail": f"Invite accepted. You can access resources from account {invite.account.name}."},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"detail": "Unable to accept invite. Please contact support."},
                status=status.HTTP_400_BAD_REQUEST,
            )
