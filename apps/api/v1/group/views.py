from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, status
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from slugify import slugify

from apps.console.account.models import CoreAccountGroup
from .filters import CoreAccountGroupFilter
from .permissions import CoreAccountGroupViewPermissions
from .serializers import CoreAccountGroupReadSerializer
from .serializers import CoreAccountGroupWriteSerializer
from ..utils.api_filters import DateRangeFilter
from ..utils.api_serializers import ReadWriteSerializerMixin
from django.contrib.auth.models import Group, Permission
from rest_framework.response import Response


class CoreAccountGroupView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreAccountGroupViewPermissions)
    read_serializer_class = CoreAccountGroupReadSerializer
    write_serializer_class = CoreAccountGroupWriteSerializer
    all_fields = [f.name for f in CoreAccountGroup._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreAccountGroupFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        queryset = CoreAccountGroup.objects.filter(account=member.get_current_account())
        return queryset

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        permissions = serializer.validated_data.pop("permissions", [])

        self.perform_create(serializer)
        account_group = serializer.instance

        # Now add permissions to group
        if len(permissions) > 0:
            # add new previous permissions.
            for permission in permissions:
                account_group.group.permissions.add(Permission.objects.get(codename=permission))

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        permissions = serializer.validated_data.pop("permissions", [])

        self.perform_update(serializer)
        account_group = serializer.instance

        # Now add permissions to group
        if len(permissions) > 0:
            # clear previous permissions but only custom permissions of this model
            for permission in account_group._meta.permissions:
                account_group.group.permissions.remove(Permission.objects.get(codename=permission[0]))
            # add new previous permissions.
            for permission in permissions:
                account_group.group.permissions.add(Permission.objects.get(codename=permission))

        if getattr(instance, "_prefetched_objects_cache", None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.member_count > 0:
            return Response(
                data={"detail": "Please remove all the users from the group before deleting it."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        instance.group.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
