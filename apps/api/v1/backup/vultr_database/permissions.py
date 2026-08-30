from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreVultrDatabaseBackupViewPermissions(MemberGroupPermissions):
    action_permissions = {
        "create": "backup_create",
        "destroy": "backup_delete",
        "cancel": "backup_delete",
        "restore": "backup_restore",
    }

    object_node_path = "vultr_database.node"
