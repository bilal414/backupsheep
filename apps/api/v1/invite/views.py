from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, mixins
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from apps.console.invite.models import CoreInvite
from apps.console.member.models import CoreMemberAccount
from .filters import CoreInviteFilter
from .permissions import CoreInviteViewPermissions
from .serializers import CoreInviteReadSerializer, CoreInviteWriteSerializer
from ..utils.api_filters import DateRangeFilter
from ..utils.api_serializers import ReadWriteSerializerMixin
from rest_framework.response import Response


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
        return queryset

    def create(self, request, *args, **kwargs):
        from apps.console.api.v1._tasks.helper.tasks import send_postmark_email

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        invite = CoreInvite.objects.get(id=serializer.data['id'])

        send_postmark_email(
            invite.email,
            "team_invite",
            {
                "account_name": invite.account.get_name(),
                "member_name": invite.added_by.full_name,
                "member_email": invite.account.get_primary_member().user.email,
                "action_url": "https://backupsheep.com/console/settings/invites",
                "help_url": "https://support.backupsheep.com",
                "sender_name": "BackupSheep - Notification Bot",
            },
        )

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    @action(detail=True)
    def accept(self, request, pk=None):
        member = self.request.user.member

        if CoreInvite.objects.filter(
            id=pk,
            email__iexact=self.request.user.email,
            status=CoreInvite.Status.PENDING,
        ).exists():
            invite = CoreInvite.objects.get(
                id=pk,
                email__iexact=self.request.user.email,
                status=CoreInvite.Status.PENDING,
            )

            if not member.memberships.filter(account=invite.account).exists():
                CoreMemberAccount.objects.create(
                    notify_on_success=invite.notify_on_success,
                    notify_on_fail=invite.notify_on_fail,
                    member=self.request.user.member,
                    account=invite.account,
                )
            for enrollment in invite.groups.filter():
                member.user.groups.add(enrollment.group)

            invite.status = CoreInvite.Status.ACCEPTED
            invite.save()

            return Response(
                {"detail": f"Invite accepted. You can access resources from account {invite.account.name}."},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"detail": "Unable to accept invite. Please contact support."},
                status=status.HTTP_400_BAD_REQUEST,
            )
