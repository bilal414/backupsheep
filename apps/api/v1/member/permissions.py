from rest_framework import permissions


class CoreMemberViewPermissions(permissions.BasePermission):
    # def has_permission(self, request, view):
    #     return hasattr(request.user, "member")

    def has_object_permission(self, request, view, obj):
        return request.user.member.memberships.filter(account=obj.get_current_account()).exists()
