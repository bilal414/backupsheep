from rest_framework import permissions


class CoreNotificationSlackViewPermissions(permissions.BasePermission):
    # def has_permission(self, request, view):
    #     if request.method in permissions.SAFE_METHODS:
    #         return True
    #     else:
    #         return hasattr(request.user, "member")

    def has_object_permission(self, request, view, obj):
        if request.user.member.memberships.filter(account=obj.account).exists():
            return True


class CoreNotificationTelegramViewPermissions(permissions.BasePermission):
    # def has_permission(self, request, view):
    #     if request.method in permissions.SAFE_METHODS:
    #         return True
    #     else:
    #         return hasattr(request.user, "member")

    def has_object_permission(self, request, view, obj):
        if request.user.member.memberships.filter(account=obj.account).exists():
            return True


class CoreNotificationEmailViewPermissions(permissions.BasePermission):
    # def has_permission(self, request, view):
    #     if request.method in permissions.SAFE_METHODS:
    #         return True
    #     else:
    #         return hasattr(request.user, "member")

    def has_object_permission(self, request, view, obj):
        if request.user.member.memberships.filter(account=obj.account).exists():
            return True
