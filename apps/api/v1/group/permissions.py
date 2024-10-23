from rest_framework import permissions


class CoreAccountGroupViewPermissions(permissions.BasePermission):
    # def has_permission(self, request, view):
    #     return hasattr(request.user, "member")

    def has_object_permission(self, request, view, obj):
        if obj.default:
            return None
        else:
            return request.user.member.memberships.filter(account=obj.account).exists()
