from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreStorageScalewayPermissions(MemberGroupPermissions):
    action_permissions = {"*": "storage_changes"}

    object_account_path = "account"
