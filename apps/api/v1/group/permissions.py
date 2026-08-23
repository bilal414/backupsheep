from rest_framework import permissions


class CoreAccountGroupViewPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            member = request.user.member
        except AttributeError:
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        return member.is_primary_account

    def has_object_permission(self, request, view, obj):
        memberships = request.user.member.memberships.filter(account=obj.account)
        if not memberships.exists():
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        if obj.default:
            return False
        return memberships.filter(primary=True).exists()
