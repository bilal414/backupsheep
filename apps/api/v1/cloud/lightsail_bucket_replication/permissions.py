from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreLightsailBucketReplicationViewPermissions(MemberGroupPermissions):
    action_permissions = {
        "create": "node_changes",
        "update": "node_changes",
        "partial_update": "node_changes",
        "destroy": "node_changes",
        "run": "backup_create",
        "restore": "backup_create",
        "validate": "backup_create",
    }

    object_account_path = "account"
