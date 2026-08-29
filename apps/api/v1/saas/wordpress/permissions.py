from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreWordPressViewPermissions(MemberGroupPermissions):
    action_permissions = {
        "generate_key": "integration_changes",
        "*": "node_changes",
    }

    object_node_path = "node"
