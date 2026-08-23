from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreUpCloudViewPermissions(MemberGroupPermissions):
    action_permissions = {"*": "integration_changes"}

    object_account_path = "account"
