from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreDigitalOceanViewPermissions(MemberGroupPermissions):
    action_permissions = {
        "oauth_url": "integration_changes",
        "*": "integration_changes",
    }

    def has_object_permission(self, request, view, obj):
        if request.user.member.memberships.filter(account=obj.account).exists():
            return True
