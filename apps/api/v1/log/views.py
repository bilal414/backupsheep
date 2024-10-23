from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, mixins
from rest_framework import viewsets
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from apps.console.api.v1.utils.api_permissions import MemberPermissions
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
        query_partners = Q(account=member.get_current_account())
        queryset = CoreLog.objects.filter(query_partners)
        return queryset
