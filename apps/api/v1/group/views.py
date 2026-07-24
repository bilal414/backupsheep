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


def _record_member_log(account, data):
    """Team-activity audit log. Never allowed to break the action it describes."""
    try:
        from apps.console.log.models import CoreLog

        CoreLog.record(account, CoreLog.Type.MEMBER, data)
    except Exception as e:
        print(f"Unable to record member log: {e}")


def _sync_permissions(account_group, permissions):
    """Replace the group's custom permissions with the submitted set.

    The submitted list replaces, not augments: an empty list clears all custom
    permissions (previously a no-op guard made "clear everything" impossible).
    Only this model's custom permissions are touched."""
    for permission in account_group._meta.permissions:
        account_group.group.permissions.remove(Permission.objects.get(codename=permission[0]))
    for permission in permissions:
        account_group.group.permissions.add(Permission.objects.get(codename=permission))


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
        # None = key absent (leave permissions alone); [] = clear all.
        permissions = serializer.validated_data.pop("permissions", None)

        self.perform_create(serializer)
        account_group = serializer.instance

        # Now sync permissions to group
        if permissions is not None:
            _sync_permissions(account_group, permissions)

        _record_member_log(
            account_group.account,
            {
                "message": f"Group {account_group.name} created.",
                "actor_email": request.user.email,
                "group_id": account_group.id,
                "group_name": account_group.name,
            },
        )

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        # None = key absent (leave permissions alone); [] = clear all.
        permissions = serializer.validated_data.pop("permissions", None)

        self.perform_update(serializer)
        account_group = serializer.instance

        # Now sync permissions to group
        if permissions is not None:
            _sync_permissions(account_group, permissions)

        _record_member_log(
            account_group.account,
            {
                "message": f"Group {account_group.name} updated.",
                "actor_email": request.user.email,
                "group_id": account_group.id,
                "group_name": account_group.name,
            },
        )

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
        _record_member_log(
            instance.account,
            {
                "message": f"Group {instance.name} deleted.",
                "actor_email": request.user.email,
                "group_id": instance.id,
                "group_name": instance.name,
            },
        )
        instance.group.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
