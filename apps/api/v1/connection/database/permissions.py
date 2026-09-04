from apps.api.v1.utils.api_permissions import (
    MemberGroupPermissions,
    SOURCE_DISCOVERY_PERMISSIONS,
)


class CoreDatabaseViewPermissions(MemberGroupPermissions):
    action_permissions = {
        "objects": SOURCE_DISCOVERY_PERMISSIONS,
        "validate": "integration_changes",
        "update_db_type_and_version": "integration_changes",
        "managed_ssh_operation": "integration_changes",
        "*": "integration_changes",
    }

    object_account_path = "account"
