from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreStorageBackBlazeB2Permissions(MemberGroupPermissions):
    action_permissions = {"*": "storage_changes"}

    object_account_path = "account"
