from rest_framework import permissions


class CoreNotificationSlackViewPermissions(permissions.BasePermission):
    # def has_permission(self, request, view):
    #     if request.method in permissions.SAFE_METHODS:
    #         return True
    #     else:
    #         return hasattr(request.user, "member")

    def has_permission(self, request, view):
        try:
            member = request.user.member
        except AttributeError:
            return False
        # Listing/retrieval exposes only redacted metadata. Mutating or actively
        # validating the shared account integration is owner administration.
        if request.method in permissions.SAFE_METHODS and getattr(view, "action", None) != "validate":
            return True
        return member.is_primary_account

    def has_object_permission(self, request, view, obj):
        memberships = request.user.member.memberships.filter(account=obj.account)
        if not memberships.exists():
            return False
        if request.method in permissions.SAFE_METHODS and getattr(view, "action", None) != "validate":
            return True
        return memberships.filter(primary=True).exists()


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
        # CoreNotificationEmail has a `member` FK (no account FK): allow when the
        # email's member belongs to the requester's current account.
        if obj.member.memberships.filter(
            account=request.user.member.get_current_account()
        ).exists():
            return True
