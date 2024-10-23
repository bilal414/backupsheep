import humanfriendly
import pytz
import arrow
from django.db.models import Q, Sum
from django.utils.decorators import method_decorator
from django.utils.timezone import get_current_timezone
from django.views.decorators.cache import cache_page
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_datatables.filters import DatatablesFilterBackend

from apps.console.storage.models import CoreStorage
from .filters import CoreStorageBSFilter
from .permissions import CoreStorageBSPermissions
from .serializers import CoreStorageReadSerializer
from ..._tasks.exceptions import StorageValidationFailed
from ...utils.api_filters import DateRangeFilter
from ...utils.api_helpers import get_start_end_of_previous_day
from ...utils.api_serializers import ReadWriteSerializerMixin


class CoreStorageBSView(viewsets.ReadOnlyModelViewSet):
    permission_classes = (
        IsAuthenticated,
        CoreStorageBSPermissions,
    )
    serializer_class = CoreStorageReadSerializer
    all_fields = [f.name for f in CoreStorage._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreStorageBSFilter
    search_fields = ["name", "type__code", "type__name"]

    def get_serializer_context(self):
        return {
            "encryption_key": self.request.user.member.get_encryption_key(),
            "request": self.request,
            "format": self.format_kwarg,
            "view": self,
        }

    def get_queryset(self):
        member = self.request.user.member
        query = Q(account=member.get_current_account(), type__code="bs")
        # query &= ~Q(status=CoreStorage.Status.DELETE_REQUESTED)
        queryset = CoreStorage.objects.filter(query)
        return queryset


    @method_decorator(cache_page(60 * 60 * 1))
    @action(detail=False)
    def totals(self, request):
        return Response("")


    @action(detail=False)
    def highcharts(self, request):
        graph = {"categories": [], "series": []}
        timezone = str(get_current_timezone())
        timezone = pytz.timezone(timezone)

        start_time = arrow.get(get_start_end_of_previous_day(days=30)["start_time"])
        end_time = arrow.get(get_start_end_of_previous_day(days=0)["start_time"])

        temp_data = []
        for r in arrow.Arrow.span_range("day", start_time.astimezone(timezone), end_time.astimezone(timezone)):
            size = (
                self.get_queryset()
                .filter(
                    stored_website_backups__backup__created__gte=r[0].datetime,
                    stored_website_backups__backup__created__lte=r[1].datetime,
                )
                .aggregate(Sum("stored_website_backups__backup__size"))
            )
            total_website_size = size["stored_website_backups__backup__size__sum"] or 0

            size = (
                self.get_queryset()
                .filter(
                    stored_database_backups__backup__created__gte=r[0].datetime,
                    stored_database_backups__backup__created__lte=r[1].datetime,
                )
                .aggregate(Sum("stored_database_backups__backup__size"))
            )
            total_database_size = size["stored_database_backups__backup__size__sum"] or 0
            total_size = total_website_size + total_database_size

            temp_data.append([humanfriendly.format_size(total_size or 0), total_size])

        graph["series"].append(
            {
                "name": "BackupSheep Storage",
                "data": temp_data,
                "visible": True,
            }
        )

        # we need labels for the days.
        for r in arrow.Arrow.span_range("day", start_time, end_time):
            graph["categories"].append(r[0].format("MM/DD/YY"))

        return Response(graph)
