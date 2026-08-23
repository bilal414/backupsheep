from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreStorageWasabiPermissions(MemberGroupPermissions):
    action_permissions = {"*": "storage_changes"}

    object_account_path = "account"
