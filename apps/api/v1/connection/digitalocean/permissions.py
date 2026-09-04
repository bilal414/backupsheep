from apps.api.v1.utils.api_permissions import (
    MemberGroupPermissions,
    SOURCE_DISCOVERY_PERMISSIONS,
)


class CoreDigitalOceanViewPermissions(MemberGroupPermissions):
    action_permissions = {
        "oauth_url": "integration_changes",
        "objects": SOURCE_DISCOVERY_PERMISSIONS,
        "*": "integration_changes",
    }

    object_account_path = "account"
