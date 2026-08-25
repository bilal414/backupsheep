from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreDatabaseViewPermissions(MemberGroupPermissions):
    action_permissions = {
        "objects": "integration_changes",
        "validate": "integration_changes",
        "update_db_type_and_version": "integration_changes",
        "managed_ssh_operation": "integration_changes",
        "*": "integration_changes",
    }

    object_account_path = "account"
