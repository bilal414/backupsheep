from rest_framework import permissions

from apps.api.v1.utils.api_permissions import active_current_membership


class CoreAccountViewPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            membership = active_current_membership(request.user.member)
        except AttributeError:
            return False
        if membership is None:
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        if getattr(view, "action", None) == "leave_membership":
            return True
        return membership.primary

    def has_object_permission(self, request, view, obj):
        try:
            member = request.user.member
        except AttributeError:
            return False
        if active_current_membership(member) is None:
            return False
        from apps.console.member.models import CoreMemberAccount

        memberships = member.memberships.filter(
            account=obj,
            status=CoreMemberAccount.Status.ACTIVE,
        )
        if not memberships.exists():
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        if getattr(view, "action", None) == "leave_membership":
            return True
        return memberships.filter(primary=True).exists()
