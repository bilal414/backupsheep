from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreWebsiteViewPermissions(MemberGroupPermissions):
    action_permissions = {
        "objects": "integration_changes",
        "validate": "integration_changes",
        "managed_ssh_operation": "integration_changes",
        "*": "integration_changes",
    }

    object_account_path = "account"
