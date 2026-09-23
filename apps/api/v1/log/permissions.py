from rest_framework import permissions

from apps.api.v1.utils.api_permissions import active_current_membership


class CoreLogViewPermissions(permissions.BasePermission):
    # def has_permission(self, request, view):
    #     if request.method in permissions.SAFE_METHODS:
    #         return True
    #     else:
    #         return hasattr(request.user, "member")

    def has_permission(self, request, view):
        try:
            return active_current_membership(request.user.member) is not None
        except AttributeError:
            return False

    def has_object_permission(self, request, view, obj):
        try:
            membership = active_current_membership(request.user.member)
        except AttributeError:
            return False
        return membership is not None and membership.account_id == obj.account_id
