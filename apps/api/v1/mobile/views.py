from django.conf import settings
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.api.v1.utils.api_permissions import member_has_perm
from backupsheep.source_recovery_policy import available_backup_endpoints


class MobileBootstrapView(APIView):
    """Return the small, stable contract a native client needs at sign-in.

    The response deliberately contains identity, authorization, and capability
    metadata only. Provider credentials, internal worker state, and raw account
    settings never cross this boundary.
    """

    permission_classes = (IsAuthenticated,)

    API_VERSION = 1.0
    MOBILE_API_VERSION = 1

    PERMISSION_CODENAMES = (
        "notify_on_success",
        "notify_on_fail",
        "notify_via_email",
        "notify_via_slack",
        "notify_via_telegram",
        "backup_create",
        "backup_restore",
        "backup_download",
        "backup_delete",
        "schedule_changes",
        "node_changes",
        "integration_changes",
        "storage_changes",
    )

    FEATURE_KEYS = (
        "dashboard",
        "nodes",
        "backups",
        "restores",
        "schedules",
        "storage",
        "connections",
        "activity",
        "accounts",
        "members",
        "groups",
        "invites",
        "notifications",
        "profile",
        "multifactor",
        "oauth",
    )

    BACKUP_ENDPOINTS = (
        "database",
        "website",
        "basecamp",
        "digitalocean",
        "aws",
        "aws_rds",
        "lightsail",
        "vultr",
        "vultr_database",
        "ovh_ca",
        "ovh_eu",
        "ovh_us",
        "hetzner",
        "upcloud",
        "oracle",
        "google_cloud",
    )

    def get(self, request):
        member = request.user.member
        account = member.get_current_account()
        membership = (
            member.memberships.filter(account=account).first() if account else None
        )
        is_owner = bool(membership and membership.primary)

        full_name = member.full_name.strip()
        canonical_url = request.build_absolute_uri("/").rstrip("/")

        return Response(
            {
                "api_version": self.API_VERSION,
                "mobile_api_version": self.MOBILE_API_VERSION,
                "installation": {
                    "display_name": getattr(settings, "APP_NAME", "BackupSheep"),
                    "canonical_url": canonical_url,
                },
                "session": {
                    "member": {
                        "id": member.id,
                        "name": full_name or member.email,
                        "email": member.email,
                        "timezone": member.timezone,
                    },
                    "account": (
                        {"id": account.id, "name": account.name}
                        if account is not None
                        else None
                    ),
                    "role": "owner" if is_owner else "member",
                    "is_owner": is_owner,
                    "permissions": {
                        codename: member_has_perm(request, codename)
                        for codename in self.PERMISSION_CODENAMES
                    },
                },
                "capabilities": {
                    "features": list(self.FEATURE_KEYS),
                    "node_kinds": [
                        "cloud",
                        "volume",
                        "website",
                        "database",
                        "saas",
                    ],
                    "backup_endpoints": available_backup_endpoints(
                        self.BACKUP_ENDPOINTS
                    ),
                    "notification_channels": ["email", "slack", "telegram"],
                    "mutation_contracts": {
                        "on_demand_backup_idempotency": True,
                        "schedule_trigger_idempotency": True,
                        # Existing local restore creation routes do not yet take a
                        # caller-controlled request identity. Native clients must
                        # keep creation gated until that contract is upgraded.
                        "local_restore_idempotency": False,
                    },
                },
            }
        )
