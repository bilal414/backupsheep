from apps.api.v1.utils.api_permissions import MemberGroupPermissions


class CoreStorageAWSS3Permissions(MemberGroupPermissions):
    action_permissions = {"*": "storage_changes"}

    def has_object_permission(self, request, view, obj):
        if request.user.member.memberships.filter(account=obj.account).exists():
            return True
