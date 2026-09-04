from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreDatabaseBackupViewPermissions(MemberGroupPermissions):
    action_permissions = {
        "create": "backup_create",
        "download": "backup_download",
        "download_transfer_log": "backup_download",
        "download_dir_tree": "backup_download",
        "destroy": "backup_delete",
        "cancel": "backup_delete",
        "retry": "backup_create",
        "restore": "backup_restore",
        "resume_restore": "backup_restore",
    }

    object_node_path = "database.node"
