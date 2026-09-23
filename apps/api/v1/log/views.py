from django.db.models import CharField, Q, Subquery
from django.db.models.fields.json import KT
from django.db.models.functions import Cast
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, mixins
from rest_framework import viewsets
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from apps.api.v1.utils.api_permissions import MemberPermissions
from apps.api.v1.utils.api_helpers import visible_nodes
from apps.console.log.models import CoreLog
from .filters import CoreLogFilter
from .permissions import CoreLogViewPermissions
from .serializers import CoreLogSerializer
from ..utils.api_filters import DateRangeFilter


class CoreLogView(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated, CoreLogViewPermissions,)
    serializer_class = CoreLogSerializer
    all_fields = [f.name for f in CoreLog._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreLogFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        membership = member.get_active_current_membership()
        if membership is None:
            return CoreLog.objects.none()

        queryset = CoreLog.objects.filter(account=membership.account)
        if not membership.primary:
            scoped_nodes = visible_nodes(member)
            visible_node_ids_as_text = scoped_nodes.annotate(
                activity_scope_node_id=Cast("id", output_field=CharField())
            ).values("activity_scope_node_id")
            queryset = queryset.annotate(
                activity_node_id_text=KT("data__node_id")
            ).filter(
                Q(
                    activity_node_id_text__in=Subquery(
                        visible_node_ids_as_text
                    )
                )
                | (
                    Q(type__in=(CoreLog.Type.AUTH, CoreLog.Type.MEMBER))
                    & Q(data__actor_email__iexact=self.request.user.email)
                    & Q(data__node_id__isnull=True)
                    & Q(data__connection_id__isnull=True)
                    & Q(data__backup_id__isnull=True)
                )
            )
        # Stable ordering prevents rows with the same timestamp moving between
        # responses and matches the console register.
        return queryset.order_by("-created", "-id")
