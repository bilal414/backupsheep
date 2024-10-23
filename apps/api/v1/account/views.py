import stripe
from django.conf import settings
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
from apps.console.billing.models import CorePlan
from apps.console.utils.models import UtilAppSumoCode
from .filters import CoreAccountFilter
from .permissions import CoreAccountViewPermissions
from .serializers import CoreAccountSerializer, CoreAccountWriteSerializer
from .._tasks.helper.tasks import billing_sync_all
from ..utils.api_filters import DateRangeFilter
from ..utils.api_serializers import ReadWriteSerializerMixin


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

    # @action(detail=True, methods=["post"])
    # def appsumo(self, request, pk=None):
    #     account = self.get_object()
    #     appsumo_code = self.request.data.get("appsumo_code")
    #
    #     if account.appsumo_code_count < 2 and UtilAppSumoCode.objects.filter(code=appsumo_code, account__isnull=True).exists():
    #         # This is first code so apply it to membership.
    #         if account.appsumo_code_count == 0:
    #             stripe.api_key = settings.STRIPE_SECRET_KEY
    #             promo_code = stripe.PromotionCode.list(limit=1, code=appsumo_code)["data"][0]
    #             plan = settings.STRIPE_APPSUMO_PLAN_PRICE_ID
    #
    #             subscription = stripe.Subscription.retrieve(account.billing.stripe_plan_sub)
    #
    #             try:
    #                 stripe.Subscription.modify(
    #                     account.billing.stripe_plan_sub,
    #                     cancel_at_period_end=False,
    #                     proration_behavior=None,
    #                     trial_end="now",
    #                     promotion_code=promo_code["id"],
    #                     items=[
    #                         {
    #                          'id': subscription['items']['data'][0].id,
    #                          "price": plan},
    #                     ],
    #                 )
    #             except Exception as e:
    #                 # Above is USD. Try with old plan of CAD
    #                 stripe.Subscription.modify(
    #                     account.billing.stripe_plan_sub,
    #                     cancel_at_period_end=False,
    #                     proration_behavior=None,
    #                     trial_end="now",
    #                     promotion_code=promo_code["id"],
    #                     items=[
    #                         {
    #                             'id': subscription['items']['data'][0].id,
    #                             "price": "price_1IsbnCLtk6SsKI58D8mts6j0"},
    #                     ],
    #                 )
    #             # # Update Storage
    #             # subscription = stripe.Subscription.retrieve(account.billing.stripe_storage_sub)
    #             #
    #             # stripe.Subscription.modify(
    #             #     account.billing.stripe_storage_sub,
    #             #     cancel_at_period_end=False,
    #             #     proration_behavior=None,
    #             #     trial_end="now",
    #             #     promotion_code=promo_code["id"],
    #             #     items=[
    #             #         {
    #             #          'id': subscription['items']['data'][0].id,
    #             #          "price": settings.STRIPE_STORAGE_PRICE_ID},
    #             #     ],
    #             # )
    #             account.appsumo = True
    #             account.save()
    #             account.billing.plan = CorePlan.objects.get(code=plan)
    #             account.billing.save()
    #
    #         # This is second code so apply it to storage
    #         elif account.appsumo_code_count == 1:
    #             stripe.api_key = settings.STRIPE_SECRET_KEY
    #             promo_code = stripe.PromotionCode.list(limit=1, code=appsumo_code)["data"][0]
    #             stripe.PromotionCode.modify(
    #                 promo_code["id"],
    #                 active=False,
    #                 metadata={"account_id": account.id},
    #             )
    #         code = UtilAppSumoCode.objects.get(code=appsumo_code, account__isnull=True)
    #         code.account = account
    #         code.save()
    #     return Response(status=status.HTTP_202_ACCEPTED, data={})

    @action(detail=True, methods=["post"])
    def sync_billing(self, request, pk=None):
        if self.request.user.member.memberships.filter(account_id=pk).exists():
            membership = self.request.user.member.memberships.get(account_id=pk)
            billing_sync_all(
                membership.account.billing.id,
            )
            return Response(
                status=status.HTTP_202_ACCEPTED,
                data={"detail": f"Your billing, storage and nodes will be synced in next few minutes."},
            )
        else:
            return Response(
                status=status.HTTP_404_NOT_FOUND,
                data={"detail": f"Sorry you don't have access to this account."},
            )

    @action(detail=True, methods=["post"])
    def remove_membership(self, request, pk=None):
        account = self.get_object()
        membership_id = self.request.data.get("membership_id")

        if account.memberships.filter(id=membership_id).exists() and self.request.user.member.is_primary_account:

            membership = account.memberships.get(id=membership_id)

            # Remove from groups
            for enrollment in account.enrollments.filter():
                membership.member.user.groups.remove(enrollment.group)

            # Remove membership
            membership.delete()

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