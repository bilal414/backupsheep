from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreDigitalOceanViewPermissions(MemberGroupPermissions):
    action_permissions = {
        "oauth_url": "integration_changes",
        "*": "integration_changes",
    }

    object_account_path = "account"
