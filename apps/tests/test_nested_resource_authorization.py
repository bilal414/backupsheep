import importlib
import inspect
from pathlib import Path
from types import SimpleNamespace
import uuid

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import RequestFactory
from rest_framework.test import APIClient

from apps.api.v1.utils.api_permissions import MemberGroupPermissions
from apps.api.v1.backup.website.permissions import (
    CoreWebsiteBackupViewPermissions,
)
from apps.api.v1.node.views import CoreNodeView
from apps.console.account.models import CoreAccountGroup
from apps.console.backup.models import CoreWebsiteBackup
from apps.console.member.models import CoreMemberAccount
from apps.console.setting.models import CoreSiteSettings
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


def _permission(codename):
    content_type = ContentType.objects.get_for_model(CoreAccountGroup)
    return Permission.objects.get(content_type=content_type, codename=codename)


def _permission_classes():
    repo_root = Path(__file__).resolve().parents[2]
    api_root = repo_root / "apps" / "api" / "v1"
    for source in sorted(api_root.rglob("permissions.py")):
        module_name = ".".join(source.relative_to(repo_root).with_suffix("").parts)
        module = importlib.import_module(module_name)
        for _name, candidate in inspect.getmembers(module, inspect.isclass):
            if (
                candidate is not MemberGroupPermissions
                and issubclass(candidate, MemberGroupPermissions)
                and candidate.__module__ == module_name
            ):
                yield candidate


def _object_with_path(path, value):
    for part in reversed(path.split(".")):
        value = SimpleNamespace(**{part: value})
    return value


def _view_for(permission):
    mapping = permission.action_permissions
    for action in (
        "destroy",
        "download",
        "partial_update",
        "update",
        "run",
        "restore",
        "validate",
        "create",
    ):
        if action in mapping:
            return SimpleNamespace(action=action)
    if "*" in mapping:
        return SimpleNamespace(action="partial_update")
    raise AssertionError(
        f"{permission.__class__.__name__} has no mapped action to exercise"
    )


class NestedResourceAuthorizationTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        settings = CoreSiteSettings.load()
        settings.setup_completed = True
        settings.save()
        OnboardingMiddleware._completed = False

        _foreign_account, self.team_member, self.team_user = factories.make_account(
            email=f"nested-scope-{self.account.pk}@example.com"
        )
        self.team_member.memberships.filter(current=True).update(current=False)
        CoreMemberAccount.objects.create(
            member=self.team_member,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=True,
            primary=False,
        )

        self.allowed_node = factories.make_website_node(self.account, self.member)
        self.visibility_only_node = factories.make_website_node(
            self.account, self.member
        )
        foreign_account, foreign_member, _foreign_user = factories.make_account(
            email=f"nested-foreign-{self.account.pk}@example.com"
        )
        self.foreign_node = factories.make_website_node(
            foreign_account, foreign_member
        )

        action_auth_group = Group.objects.create(
            name=f"nested-actions-{self.account.pk}-{uuid.uuid4().hex}"
        )
        self.action_group = CoreAccountGroup.objects.create(
            account=self.account,
            group=action_auth_group,
            name="nested actions",
            type=CoreAccountGroup.Type.Team,
            default=False,
        )
        action_auth_group.permissions.set(
            [
                _permission(codename)
                for codename in (
                    "backup_create",
                    "backup_restore",
                    "backup_download",
                    "backup_delete",
                    "schedule_changes",
                    "node_changes",
                    "integration_changes",
                    "storage_changes",
                )
            ]
        )
        self.action_group.nodes.add(self.allowed_node)
        self.team_user.groups.add(action_auth_group)

        visibility_auth_group = Group.objects.create(
            name=f"nested-visible-{self.account.pk}-{uuid.uuid4().hex}"
        )
        self.visibility_group = CoreAccountGroup.objects.create(
            account=self.account,
            group=visibility_auth_group,
            name="nested visibility only",
            type=CoreAccountGroup.Type.Team,
            default=False,
        )
        self.visibility_group.nodes.add(self.visibility_only_node)
        self.team_user.groups.add(visibility_auth_group)

        self.team_request = RequestFactory().post("/nested-action/")
        self.team_request.user = self.team_user
        self.owner_request = RequestFactory().post("/nested-action/")
        self.owner_request.user = self.user

    def test_every_concrete_permission_declares_and_enforces_object_scope(self):
        node_scoped = []
        account_scoped = []

        for permission_class in _permission_classes():
            self.assertNotIn(
                "has_object_permission",
                permission_class.__dict__,
                f"{permission_class.__module__}.{permission_class.__name__} "
                "must use the common fail-closed object-scope check",
            )
            permission = permission_class()
            self.assertNotEqual(
                bool(permission.object_node_path),
                bool(permission.object_account_path),
                f"{permission_class.__module__}.{permission_class.__name__} "
                "must declare exactly one object scope",
            )
            view = _view_for(permission)
            self.assertTrue(
                permission.has_permission(self.team_request, view),
                permission_class.__name__,
            )

            if permission.object_node_path:
                node_scoped.append(permission_class)
                allowed = _object_with_path(
                    permission.object_node_path, self.allowed_node
                )
                visibility_only = _object_with_path(
                    permission.object_node_path, self.visibility_only_node
                )
                foreign = _object_with_path(
                    permission.object_node_path, self.foreign_node
                )
                self.assertTrue(
                    permission.has_object_permission(
                        self.team_request, view, allowed
                    ),
                    permission_class.__name__,
                )
                self.assertFalse(
                    permission.has_object_permission(
                        self.team_request, view, visibility_only
                    ),
                    permission_class.__name__,
                )
                self.assertFalse(
                    permission.has_object_permission(
                        self.team_request, view, foreign
                    ),
                    permission_class.__name__,
                )
                self.assertTrue(
                    permission.has_object_permission(
                        self.owner_request, view, visibility_only
                    ),
                    permission_class.__name__,
                )
            else:
                account_scoped.append(permission_class)
                current = _object_with_path(
                    permission.object_account_path, self.account
                )
                foreign = _object_with_path(
                    permission.object_account_path,
                    self.foreign_node.connection.account,
                )
                self.assertTrue(
                    permission.has_object_permission(
                        self.team_request, view, current
                    ),
                    permission_class.__name__,
                )
                self.assertFalse(
                    permission.has_object_permission(
                        self.team_request, view, foreign
                    ),
                    permission_class.__name__,
                )

        # These lower bounds make accidental discovery/import failures visible
        # while allowing new provider modules to be added without test churn.
        self.assertGreaterEqual(len(node_scoped), 40)
        self.assertGreaterEqual(len(account_scoped), 30)

    def test_visible_backup_action_is_bound_to_granting_group_node(self):
        allowed_backup = CoreWebsiteBackup.objects.create(
            website=self.allowed_node.website,
            name="allowed nested backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )
        visibility_only_backup = CoreWebsiteBackup.objects.create(
            website=self.visibility_only_node.website,
            name="visibility-only nested backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )
        team_client = APIClient()
        team_client.force_authenticate(user=self.team_user)

        list_response = team_client.get("/api/v1/backups/website/")
        self.assertEqual(list_response.status_code, 200, list_response.content)
        self.assertEqual(
            {item["id"] for item in list_response.json()},
            {allowed_backup.id, visibility_only_backup.id},
        )

        # This action is intentionally side-effect free and returns 404 after
        # successful authorization in the self-hosted build.  The member may
        # reach node A, but the same account-wide codename cannot be composed
        # with node B's visibility-only group.
        allowed_response = team_client.get(
            f"/api/v1/backups/website/{allowed_backup.id}/download_transfer_log/"
        )
        self.assertEqual(allowed_response.status_code, 404, allowed_response.content)
        denied_response = team_client.get(
            f"/api/v1/backups/website/{visibility_only_backup.id}/download_transfer_log/"
        )
        self.assertEqual(denied_response.status_code, 403, denied_response.content)

        owner_client = APIClient()
        owner_client.force_authenticate(user=self.user)
        owner_response = owner_client.get(
            f"/api/v1/backups/website/{visibility_only_backup.id}/download_transfer_log/"
        )
        self.assertEqual(owner_response.status_code, 404, owner_response.content)

    def test_backup_creation_does_not_authorize_logical_or_native_restore(self):
        restore_permission = _permission("backup_restore")
        self.action_group.group.permissions.remove(restore_permission)

        logical_permission = CoreWebsiteBackupViewPermissions()
        logical_view = SimpleNamespace(action="restore")
        logical_object = _object_with_path(
            logical_permission.object_node_path,
            self.allowed_node,
        )
        native_permission = MemberGroupPermissions()
        native_view = SimpleNamespace(
            action="restore_backup",
            action_permissions=CoreNodeView.action_permissions,
        )

        self.assertFalse(
            logical_permission.has_permission(self.team_request, logical_view)
        )
        self.assertFalse(
            logical_permission.has_object_permission(
                self.team_request,
                logical_view,
                logical_object,
            )
        )
        self.assertFalse(
            native_permission.has_permission(self.team_request, native_view)
        )
        self.assertFalse(
            native_permission.has_object_permission(
                self.team_request,
                native_view,
                self.allowed_node,
            )
        )

        self.action_group.group.permissions.add(restore_permission)

        self.assertTrue(
            logical_permission.has_permission(self.team_request, logical_view)
        )
        self.assertTrue(
            logical_permission.has_object_permission(
                self.team_request,
                logical_view,
                logical_object,
            )
        )
        self.assertTrue(
            native_permission.has_permission(self.team_request, native_view)
        )
        self.assertTrue(
            native_permission.has_object_permission(
                self.team_request,
                native_view,
                self.allowed_node,
            )
        )
