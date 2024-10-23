from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from rest_framework.response import Response
from apps.console.api.v1.utils.api_filters import DateRangeFilter
from apps.console.api.v1.utils.api_serializers import ReadWriteSerializerMixin
from apps.console.api.v1.website.filters import CoreWebsiteFilter
from apps.console.api.v1.website.permissions import CoreWebsiteViewPermissions
from apps.console.api.v1.website.serializers import CoreWebsiteReadSerializer, CoreWebsiteWriteSerializer
from apps.console.backup.models import CoreWebsiteBackup
from apps.console.connection.models import CoreConnection, CoreAuthWebsite
from apps.console.node.models import CoreWebsite, CoreNode
from rest_framework import status

from apps.console.utils.models import UtilBackup


class CoreWebsiteView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreWebsiteViewPermissions,)
    read_serializer_class = CoreWebsiteReadSerializer
    write_serializer_class = CoreWebsiteWriteSerializer
    all_fields = [f.name for f in CoreWebsite._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreWebsiteFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query = Q(node__connection__account=member.get_current_account())
        query &= (
                Q(node__connection__auth_website__protocol=CoreAuthWebsite.Protocol.SFTP)
                | Q(node__connection__auth_website__protocol=CoreAuthWebsite.Protocol.FTP)
                | Q(node__connection__auth_website__protocol=CoreAuthWebsite.Protocol.FTPS)
        )
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        queryset = CoreWebsite.objects.filter(query)
        return queryset

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.node.delete_requested()
        return Response(status=status.HTTP_204_NO_CONTENT, data={})

    @action(detail=False, methods=["get"])
    def connections(self, request):
        member = self.request.user.member
        query = Q(account=member.get_current_account(), integration__code="website")

        query &= ~Q(status=CoreConnection.Status.DELETE_REQUESTED)
        regions = CoreConnection.objects.filter(query).values(
            "id",
            "name",
            "location_id",
            "location__name",
            "location__image_url",
        )
        return Response(regions)

    @action(detail=False)
    def totals(self, request):
        member = self.request.user.member
        query = Q(node__connection__account=member.get_current_account())
        query &= (
                Q(node__connection__auth_website__protocol=CoreAuthWebsite.Protocol.SFTP)
                | Q(node__connection__auth_website__protocol=CoreAuthWebsite.Protocol.FTP)
                | Q(node__connection__auth_website__protocol=CoreAuthWebsite.Protocol.FTPS)
        )
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        websites = CoreWebsite.objects.filter(query)
        all_totals = {
            "nodes": websites.count(),
            "backups": CoreWebsiteBackup.objects.filter(
                website__in=websites,
                status=UtilBackup.Status.COMPLETE
            ).count(),
            "storage": 0,
            "in_progress": CoreNode.objects.filter(
                website__in=websites, status=CoreNode.Status.BACKUP_IN_PROGRESS
            ).count(),
        }
        return Response(all_totals)
