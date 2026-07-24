from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreVolumeOracleViewPermissions(MemberGroupPermissions):
    action_permissions = {"*": "node_changes"}

    def has_object_permission(self, request, view, obj):
        if request.user.member.memberships.filter(account=obj.node.connection.account).exists():
            return True
