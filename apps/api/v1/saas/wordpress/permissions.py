from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreWordPressViewPermissions(MemberGroupPermissions):
    action_permissions = {"*": "node_changes"}

    object_node_path = "node"
