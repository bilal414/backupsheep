from rest_framework import permissions

from apps.api.v1.utils.api_permissions import active_current_membership
from apps.console.member.models import CoreMemberAccount


class CoreAccountGroupViewPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            member = request.user.member
        except AttributeError:
            return False
        membership = active_current_membership(member)
        if membership is None:
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        return membership.primary

    def has_object_permission(self, request, view, obj):
        member = request.user.member
        if active_current_membership(member) is None:
            return False
        memberships = member.memberships.filter(
            account=obj.account,
            status=CoreMemberAccount.Status.ACTIVE,
        )
        if not memberships.exists():
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        if obj.default:
            return False
        return memberships.filter(primary=True).exists()
