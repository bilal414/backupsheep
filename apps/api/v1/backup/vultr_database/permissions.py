from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreVultrDatabaseBackupViewPermissions(MemberGroupPermissions):
    action_permissions = {
        "create": "backup_create",
        "destroy": "backup_delete",
        "cancel": "backup_delete",
        "restore": "backup_create",
    }

    def has_object_permission(self, request, view, obj):
        return request.user.member.memberships.filter(
            account=obj.vultr_database.node.connection.account
        ).exists()
