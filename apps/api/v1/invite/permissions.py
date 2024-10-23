from rest_framework import permissions


class CoreInviteViewPermissions(permissions.BasePermission):
    # def has_permission(self, request, view):
    #     return hasattr(request.user, "member")

    def has_object_permission(self, request, view, obj):
        return request.user.member.memberships.filter(account=obj.account).exists()