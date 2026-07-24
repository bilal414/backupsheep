from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreAWSRDSBackupViewPermissions(MemberGroupPermissions):
    action_permissions = {
        "create": "backup_create",
        "download": "backup_download",
        "download_transfer_log": "backup_download",
        "download_dir_tree": "backup_download",
        "destroy": "backup_delete",
    }

    def has_object_permission(self, request, view, obj):
        if request.user.member.memberships.filter(account=obj.aws_rds.node.connection.account).exists():
            return True
