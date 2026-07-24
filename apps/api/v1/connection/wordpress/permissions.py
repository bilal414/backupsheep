from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreWordPressViewPermissions(MemberGroupPermissions):
    action_permissions = {"*": "integration_changes"}

    def has_object_permission(self, request, view, obj):
        if request.user.member.memberships.filter(account=obj.account).exists():
            return True
