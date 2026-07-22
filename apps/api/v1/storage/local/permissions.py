from rest_framework import permissions


class CoreStorageLocalPermissions(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.member.memberships.filter(account=obj.account).exists():
            return True
