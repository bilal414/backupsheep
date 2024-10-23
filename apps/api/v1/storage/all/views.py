from django.db.models import Q
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_datatables.filters import DatatablesFilterBackend
from apps.console.storage.models import CoreStorage
from .filters import CoreStorageAllFilter
from .permissions import CoreStorageAllPermissions
from .serializers import CoreStorageSerializer
from ...utils.api_filters import DateRangeFilter


class CoreStorageAllView(viewsets.ReadOnlyModelViewSet):
    permission_classes = (IsAuthenticated, CoreStorageAllPermissions,)
    serializer_class = CoreStorageSerializer
    all_fields = [f.name for f in CoreStorage._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreStorageAllFilter
    search_fields = ["name", "type__code", "type__name"]

    def get_queryset(self):
        member = self.request.user.member
        query = Q(account=member.get_current_account())
        # query &= ~Q(status=CoreStorage.Status.DELETE_REQUESTED)
        queryset = CoreStorage.objects.filter(query)
        return queryset

    @method_decorator(cache_page(60 * 60 * 1))
    @action(detail=False)
    def totals(self, request):
        return Response("")