from django.db import transaction
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, status
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend

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
    allowed_codenames = {
        codename for codename, _label in account_group._meta.permissions
    }
    requested = set(permissions)
    unknown = requested - allowed_codenames
    if unknown:
        raise ValueError("Unknown account-group permission")

    model_permissions = Permission.objects.filter(
        content_type__app_label=account_group._meta.app_label,
        content_type__model=account_group._meta.model_name,
        codename__in=allowed_codenames,
    )
    account_group.group.permissions.remove(*model_permissions)
    selected = model_permissions.filter(codename__in=requested)
    account_group.group.permissions.add(*selected)


def _locked_group_delete_impact(account_group, auth_group):
    """Capture deletion impact while both group records are row-locked."""
    member_count = auth_group.user_set.count()
    source_count = account_group.nodes.count()
    return member_count, source_count


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

        with transaction.atomic():
            self.perform_create(serializer)
            account_group = serializer.instance
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

        with transaction.atomic():
            self.perform_update(serializer)
            account_group = serializer.instance
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
        authorized_instance = self.get_object()
        authorized_group_id = authorized_instance.group_id
        authorized_enrollment_id = authorized_instance.id
        actor_email = request.user.email

        with transaction.atomic():
            # Lock in the same order as group updates: the backing Django auth
            # Group first, then the tenant enrollment. The auth Group lock
            # serializes auth_user_groups FK inserts so a member cannot be added
            # after the zero-member check but before deletion.
            locked_auth_group = get_object_or_404(
                Group.objects.select_for_update(),
                pk=authorized_group_id,
            )
            locked_account_group = get_object_or_404(
                self.get_queryset()
                .select_for_update()
                .select_related("account"),
                pk=authorized_enrollment_id,
                group_id=locked_auth_group.id,
            )
            self.check_object_permissions(request, locked_account_group)

            member_count, source_count = _locked_group_delete_impact(
                locked_account_group,
                locked_auth_group,
            )
            if member_count > 0:
                return Response(
                    data={
                        "detail": (
                            "Please remove all the users from the group before "
                            "deleting it."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            account = locked_account_group.account
            group_id = locked_account_group.id
            group_name = locked_account_group.name
            source_scope = "selected_sources" if source_count else "all_sources"
            audit_data = {
                "message": (
                    f"Access group {group_name} deleted. Its member assignment and "
                    "source-scope policy were removed; protected sources and recovery "
                    "points were not deleted."
                ),
                "action": "group_delete",
                "outcome": "succeeded",
                "actor_email": actor_email,
                "group_id": group_id,
                "group_name": group_name,
                "member_count": member_count,
                "source_count": source_count,
                "source_scope": source_scope,
            }

            locked_auth_group.delete()
            # A callback registered after deletion is discarded automatically if
            # this transaction (or an enclosing request transaction) rolls back.
            transaction.on_commit(
                lambda account=account, data=audit_data: _record_member_log(
                    account, data
                )
            )

        return Response(status=status.HTTP_204_NO_CONTENT)
