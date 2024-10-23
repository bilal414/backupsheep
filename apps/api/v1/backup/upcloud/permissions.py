from rest_framework import permissions


class CoreUpCloudBackupViewPermissions(permissions.BasePermission):
    # def has_permission(self, request, view):
    #     if request.method in permissions.SAFE_METHODS:
    #         return True
    #     else:
    #         return hasattr(request.user, "member")

    def has_object_permission(self, request, view, obj):
        if request.user.member.memberships.filter(account=obj.upcloud.node.connection.account).exists():
            return True
