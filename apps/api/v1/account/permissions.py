from rest_framework import permissions


class CoreAccountViewPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return hasattr(request.user, "member")
        if getattr(view, "action", None) == "leave_membership":
            return hasattr(request.user, "member")
        try:
            return request.user.member.is_primary_account
        except AttributeError:
            return False

    def has_object_permission(self, request, view, obj):
        try:
            memberships = request.user.member.memberships.filter(account=obj)
        except AttributeError:
            return False
        if not memberships.exists():
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        if getattr(view, "action", None) == "leave_membership":
            return True
        return memberships.filter(primary=True).exists()
