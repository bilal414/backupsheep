"""Every registered API route must classify to a scope (fail-closed contract)."""

import re

from django.test import SimpleTestCase
from django.urls import URLResolver, get_resolver

from apps.api.v1.utils import api_scopes
from apps.api.v1.utils.api_scopes import (
    ANY,
    INTERACTIVE_ONLY,
    PUBLIC,
    SCOPES,
    expand_scopes,
    requirement_for,
    scope_catalog,
    validate_scopes,
)

_SAFE = ("GET", "HEAD", "OPTIONS")


def _concrete(route):
    """Turn a Django route/regex into one representative concrete path."""
    route = route.replace("\\Z", "").replace("^", "").replace("$", "")
    route = route.replace("/?", "/")
    route = re.sub(r"\(\?P<[^>]+>[^)]+\)", "1", route)
    route = re.sub(r"<(?:[a-z]+:)?[^>]+>", "1", route)
    route = re.sub(r"/{2,}", "/", route)
    return route if route.startswith("/") else "/" + route


def registered_api_operations(prefixes=("/api/v1/",)):
    operations = []

    def walk(patterns, prefix=""):
        for pattern in patterns:
            route = prefix + str(pattern.pattern)
            if isinstance(pattern, URLResolver):
                walk(pattern.url_patterns, route)
                continue
            path = _concrete(route)
            if not path.startswith(tuple(prefixes)):
                continue
            callback = pattern.callback
            actions = getattr(callback, "actions", None)
            if actions:
                methods = [method.upper() for method in actions if method not in ("head", "options")]
            else:
                view_class = getattr(callback, "view_class", None) or getattr(callback, "cls", None)
                methods = [
                    method.upper()
                    for method in getattr(view_class, "http_method_names", ("get",))
                    if method not in ("head", "options") and callable(getattr(view_class, method, None))
                ] or ["GET"]
            for method in methods:
                operations.append((method, path, route, callback))

    walk(get_resolver().url_patterns)
    return operations


class ScopeRegistryTests(SimpleTestCase):
    def test_every_api_route_is_classified(self):
        unclassified = [
            (method, route)
            for method, path, route, _callback in registered_api_operations()
            if requirement_for(method, path) is None
        ]
        self.assertEqual(unclassified, [], "add a rule to api_scopes.RULES for these routes")

    def test_scoped_requirements_only_reference_registered_scopes(self):
        for method, path, _route, _callback in registered_api_operations():
            requirement = requirement_for(method, path)
            if requirement.needs_scope:
                self.assertIn(requirement.scope, SCOPES, (method, path))

    def test_high_impact_actions_have_dedicated_scopes(self):
        cases = {
            ("POST", "/api/v1/backups/website/7/restore/"): "backups:restore",
            ("POST", "/api/v1/backups/database/7/resume_restore/"): "backups:restore",
            ("POST", "/api/v1/nodes/7/restore_backup/"): "backups:restore",
            ("POST", "/api/v1/clouds/lightsail_bucket_replications/7/restore/"): "backups:restore",
            ("GET", "/api/v1/backups/website/7/download/"): "backups:download",
            ("GET", "/api/v1/backups/database/7/download_transfer_log/"): "backups:download",
            ("GET", "/api/v1/backups/website/7/download_dir_tree/"): "backups:download",
            ("GET", "/api/v1/storage/local/file/database/abc/"): "backups:download",
            ("GET", "/api/v1/backups/website/7/restores/"): "backups:read",
            ("DELETE", "/api/v1/backups/website/7/"): "backups:write",
            ("POST", "/api/v1/nodes/7/take_snapshot/"): "backups:write",
            ("POST", "/api/v1/schedules/7/trigger/"): "schedules:write",
            ("POST", "/api/v1/storage/aws_s3/"): "storage:write",
            ("GET", "/api/v1/storage/all/"): "storage:read",
            ("POST", "/api/v1/utils/ssh-host-keys/preview/"): "sources:write",
            ("GET", "/api/v1/logs/"): "activity:read",
            ("GET", "/api/v1/stats/backups/"): "activity:read",
            ("GET", "/api/v1/mobile/bootstrap/"): "profile",
            ("PATCH", "/api/v1/members/7/"): "account:write",
            ("GET", "/api/v1/accounts/"): "account:read",
        }
        for (method, path), expected in cases.items():
            with self.subTest(method=method, path=path):
                self.assertEqual(requirement_for(method, path).scope, expected)

    def test_credential_management_and_callbacks_are_interactive_only(self):
        for method, path in (
            ("POST", "/api/v1/members/7/auth_multi_factor_token_setup/"),
            ("POST", "/api/v1/members/7/auth_multi_factor_token_verify/"),
            ("POST", "/api/v1/members/7/auth_multi_factor_token_revoke/"),
            ("GET", "/api/v1/callback/digitalocean/"),
            ("GET", "/api/v1/tokens/"),
            ("POST", "/api/v1/tokens/"),
            ("DELETE", "/api/v1/tokens/3/"),
            ("POST", "/api/v1/tokens/3/rotate/"),
            ("POST", "/api/v1/oauth/applications/"),
            ("GET", "/api/v1/oauth/authorized-applications/"),
        ):
            with self.subTest(method=method, path=path):
                self.assertEqual(requirement_for(method, path).scope, INTERACTIVE_ONLY)

    def test_public_and_any_routes(self):
        self.assertEqual(requirement_for("POST", "/api/v1/auth/login/").scope, PUBLIC)
        self.assertEqual(requirement_for("PATCH", "/api/v1/auth/reset/").scope, PUBLIC)
        self.assertEqual(requirement_for("GET", "/api/v1/utils/test/").scope, PUBLIC)
        self.assertEqual(requirement_for("GET", "/api/v1/utils/test").scope, PUBLIC)
        self.assertEqual(requirement_for("POST", "/api/v1/auth/logout/").scope, ANY)
        self.assertEqual(requirement_for("GET", "/api/v1/check/login/").scope, ANY)
        self.assertEqual(requirement_for("GET", "/api/v1/tokens/scopes/").scope, ANY)
        self.assertEqual(requirement_for("GET", "/api/v1/schema/").scope, ANY)
        self.assertEqual(requirement_for("GET", "/api/v1/docs/swagger/").scope, ANY)

    def test_switching_workspace_is_denied_to_account_bound_tokens(self):
        requirement = requirement_for("POST", "/api/v1/members/7/switch_current_account/")
        self.assertEqual(requirement.scope, "profile")
        self.assertFalse(requirement.account_bound_allowed)

    def test_unknown_and_malformed_paths_fail_closed(self):
        self.assertIsNone(requirement_for("GET", "/api/v1/not-a-resource/"))
        self.assertIsNone(requirement_for("GET", "/api/v2/backups/"))
        self.assertIsNone(requirement_for("GET", "/console/"))
        self.assertIsNone(requirement_for("GET", None))
        # A double slash after the prefix never resolves to a permissive rule.
        self.assertIsNone(requirement_for("GET", "/api/v1//backups/website/"))

    def test_write_scopes_imply_their_read_scope(self):
        self.assertEqual(
            expand_scopes(["backups:write"]), {"backups:write", "backups:read"}
        )
        self.assertEqual(expand_scopes(["backups:restore"]), {"backups:restore"})
        self.assertEqual(expand_scopes(["backups:download"]), {"backups:download"})

    def test_validate_scopes_rejects_unknown_and_empty(self):
        self.assertEqual(validate_scopes(["backups:read", "backups:read"]), ["backups:read"])
        with self.assertRaises(ValueError):
            validate_scopes(["admin"])
        with self.assertRaises(ValueError):
            validate_scopes([])
        with self.assertRaises(ValueError):
            validate_scopes(["backups:write"], allowed=("backups:read",))

    def test_catalog_matches_registry(self):
        catalog = scope_catalog()
        self.assertEqual([entry["scope"] for entry in catalog], list(SCOPES))
        for entry in catalog:
            self.assertTrue(entry["description"])
            for implied in entry["implies"]:
                self.assertIn(implied, SCOPES)

    def test_safe_methods_constant_matches_http(self):
        self.assertEqual(tuple(api_scopes.SAFE_METHODS), _SAFE)


    def test_public_routes_are_served_by_repository_views(self):
        """The Bruno manifest records each view's source file; a third-party
        view mounted directly would record a site-packages path that differs
        between machines and break the collection validator in CI."""
        import inspect
        from pathlib import Path

        from django.conf import settings

        root = Path(settings.BASE_DIR).resolve()
        foreign = set()
        for _method, path, _route, callback in registered_api_operations(
            prefixes=("/api/v1/", "/o/", "/.well-known/oauth-authorization-server")
        ):
            view = getattr(callback, "view_class", None) or getattr(callback, "cls", None) or callback
            source = Path(inspect.getsourcefile(view)).resolve()
            if root not in source.parents:
                foreign.add((path, str(source)))
        self.assertEqual(sorted(foreign), [], "subclass third-party views inside the repository")
