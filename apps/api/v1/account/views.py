from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, mixins
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from rest_framework.response import Response
from apps.console.account.models import CoreAccount
from .filters import CoreAccountFilter
from .permissions import CoreAccountViewPermissions
from .serializers import CoreAccountSerializer, CoreAccountWriteSerializer
from ..utils.api_filters import DateRangeFilter
from ..utils.api_serializers import ReadWriteSerializerMixin


def _record_member_log(account, data):
    """Team-activity audit log. Never allowed to break the action it describes."""
    try:
        from apps.console.log.models import CoreLog

        CoreLog.record(account, CoreLog.Type.MEMBER, data)
    except Exception as e:
        print(f"Unable to record member log: {e}")


class CoreAccountView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreAccountViewPermissions)
    read_serializer_class = CoreAccountSerializer
    write_serializer_class = CoreAccountWriteSerializer
    all_fields = [f.name for f in CoreAccount._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreAccountFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        queryset = CoreAccount.objects.filter(members=member, memberships__primary=True)
        return queryset

    @action(detail=True, methods=["post"])
    def remove_membership(self, request, pk=None):
        account = self.get_object()
        membership_id = self.request.data.get("membership_id")

        if account.memberships.filter(id=membership_id).exists() and self.request.user.member.is_primary_account:

            membership = account.memberships.get(id=membership_id)
            removed_member = membership.member

            # Remove from groups
            for enrollment in account.enrollments.filter():
                membership.member.user.groups.remove(enrollment.group)

            # Remove membership
            membership.delete()

            _record_member_log(
                account,
                {
                    "message": f"Member {removed_member.email} removed from the account.",
                    "actor_email": request.user.email,
                    "member_id": removed_member.id,
                    "member_email": removed_member.email,
                },
            )

            return Response(
                {"detail": f"User access removed from account {account.name}."},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"detail": "Unable to remove user access. Please contact support."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # if CoreInvite.objects.filter(
        #     id=pk,
        #     email__iexact=self.request.user.email,
        #     status=CoreInvite.Status.PENDING,
        # ).exists():
        #     invite = CoreInvite.objects.get(
        #         id=pk,
        #         email__iexact=self.request.user.email,
        #         status=CoreInvite.Status.PENDING,
        #     )
        #
        #     if not member.memberships.filter(account=invite.account).exists():
        #         CoreMemberAccount.objects.create(
        #             notify_on_success=invite.notify_on_success,
        #             notify_on_fail=invite.notify_on_fail,
        #             member=self.request.user.member,
        #             account=invite.account,
        #         )
        #     for enrollment in invite.groups.filter():
        #         member.user.groups.add(enrollment.group)
        #
        #     invite.status = CoreInvite.Status.ACCEPTED
        #     invite.save()
        #
        #     return Response(
        #         {"detail": f"Invite accepted. You can access resources from account {invite.account.name}."},
        #         status=status.HTTP_200_OK,
        #     )
        # else:
        #     return Response(
        #         {"detail": "Unable to accept invite. Please contact support."},
        #         status=status.HTTP_400_BAD_REQUEST,
        #     )

    @action(detail=True, methods=["post"])
    def leave_membership(self, request, pk=None):
        account = self.get_object()

        membership_id = self.request.data.get("membership_id")

        if request.user.member.memberships.filter(id=membership_id, primary=False).exists():

            membership = request.user.member.memberships.get(id=membership_id, primary=False)

            # Remove from groups
            for enrollment in membership.account.enrollments.filter():
                membership.member.user.groups.remove(enrollment.group)

            # Remove membership
            membership.delete()

            request.user.member.set_current_account()

            return Response(
                {"detail": f"Your access is removed from account {account.name}."},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"detail": "Unable to remove your access. Please contact support."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # if CoreInvite.objects.filter(
        #     id=pk,
        #     email__iexact=self.request.user.email,
        #     status=CoreInvite.Status.PENDING,
        # ).exists():
        #     invite = CoreInvite.objects.get(
        #         id=pk,
        #         email__iexact=self.request.user.email,
        #         status=CoreInvite.Status.PENDING,
        #     )
        #
        #     if not member.memberships.filter(account=invite.account).exists():
        #         CoreMemberAccount.objects.create(
        #             notify_on_success=invite.notify_on_success,
        #             notify_on_fail=invite.notify_on_fail,
        #             member=self.request.user.member,
        #             account=invite.account,
        #         )
        #     for enrollment in invite.groups.filter():
        #         member.user.groups.add(enrollment.group)
        #
        #     invite.status = CoreInvite.Status.ACCEPTED
        #     invite.save()
        #
        #     return Response(
        #         {"detail": f"Invite accepted. You can access resources from account {invite.account.name}."},
        #         status=status.HTTP_200_OK,
        #     )
        # else:
        #     return Response(
        #         {"detail": "Unable to accept invite. Please contact support."},
        #         status=status.HTTP_400_BAD_REQUEST,
        #     )