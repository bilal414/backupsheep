from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreScheduleViewPermissions(MemberGroupPermissions):
    action_permissions = {"*": "schedule_changes"}

    object_node_path = "node"
