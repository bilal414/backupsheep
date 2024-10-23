from django.db.models import Q
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, mixins
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework_datatables.filters import DatatablesFilterBackend
from apps.console.api.v1.utils.api_permissions import MemberPermissions
from apps.console.node.models import CoreNode
from apps.console.storage.models import CoreStorage
from .filters import CoreStorageFilter
from .serializers import CoreStorageSerializer
from ..utils.api_filters import DateRangeFilter
from ..utils.api_serializers import ReadWriteSerializerMixin


class CoreStorageView(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated, MemberPermissions,)
    serializer_class = CoreStorageSerializer
    all_fields = [f.name for f in CoreStorage._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreStorageFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query_partners = Q(account=member.get_current_account())
        queryset = CoreStorage.objects.filter(query_partners)
        return queryset

    @action(detail=True, methods=["post"])
    def pause(self, request, pk=None):
        storage = self.get_object()
        notes = self.request.data.get("notes")
        storage.status = CoreStorage.Status.PAUSED
        storage.save()
        return Response({"detail": "Storage is paused."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def resume(self, request, pk=None):
        storage = self.get_object()
        notes = self.request.data.get("notes")
        storage.status = CoreStorage.Status.ACTIVE
        storage.save()
        return Response({"detail": "Storage is resumed."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def delete(self, request, pk=None):
        storage = self.get_object()
        notes = self.request.data.get("notes")
        storage.status = CoreStorage.Status.DELETE_REQUESTED
        storage.save()
        return Response({"detail": "Storage will be deleted soon."}, status=status.HTTP_200_OK)
