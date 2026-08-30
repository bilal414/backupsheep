from apps.api.v1.utils.api_permissions import (
    MemberGroupPermissions,
    SOURCE_DISCOVERY_PERMISSIONS,
)


class CoreOracleViewPermissions(MemberGroupPermissions):
    action_permissions = {
        "objects": SOURCE_DISCOVERY_PERMISSIONS,
        "*": "integration_changes",
    }

    object_account_path = "account"
