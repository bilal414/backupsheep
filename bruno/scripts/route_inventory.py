#!/usr/bin/env python3
"""Shared Django URL-resolver inventory for the BackupSheep Bruno collection."""

from __future__ import annotations

import inspect
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path


# Keep route-audit runs from leaving generated interpreter artifacts in the
# Git-native Bruno collection.
sys.dont_write_bytecode = True


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def configure_django():
    """Load routing without relying on production secrets or touching the database."""

    os.environ.update(
        {
            "DJANGO_SETTINGS_MODULE": "backupsheep.settings",
            "DJANGO_SERVER": "dev",
            "DJANGO_SECRET_KEY": "bruno-route-introspection-only-not-a-runtime-secret",
            "DJANGO_ALLOWED_HOSTS": "localhost",
            "APP_PROTOCOL": "http://",
            "APP_DOMAIN": "localhost",
            "BACKUPSHEEP_INSTALLATION_ID": "0" * 64,
            "BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE": "false",
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER": "local-development",
            "BACKUPSHEEP_ARTIFACT_LOCAL_WRAPPING_KEY": (
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            ),
            "BACKUPSHEEP_ARTIFACT_LOCAL_KEY_ID": "bruno-introspection-v1",
        }
    )
    import django

    django.setup()


@dataclass(frozen=True)
class Operation:
    method: str
    path: str
    regex_route: str
    action: str
    view_name: str
    source: str
    auth: str
    safety: str
    kind: str
    callback: object

    @property
    def key(self):
        return self.method, self.path


_VARIABLE_NAMES = {
    "pk": "resourceId",
    "run_pk": "runId",
    "stored_backup_id": "storedBackupId",
}


def _variable(name: str) -> str:
    if name in _VARIABLE_NAMES:
        return _VARIABLE_NAMES[name]
    pieces = name.split("_")
    return pieces[0] + "".join(piece.title() for piece in pieces[1:])


def normalize_route(route: str) -> str:
    """Convert Django route/regex text to a concrete Bruno variable URL path."""

    route = route.replace("\\Z", "$")
    route = route.replace("/?$", "/").replace("$", "")
    route = re.sub(
        r"\(\?P<(?P<name>[A-Za-z_][A-Za-z0-9_]*)>[^)]+\)",
        lambda match: "{{" + _variable(match.group("name")) + "}}",
        route,
    )
    route = re.sub(
        r"<(?:(?:str|int|slug|uuid|path):)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)>",
        lambda match: "{{" + _variable(match.group("name")) + "}}",
        route,
    )
    route = route.replace("^", "")
    route = re.sub(r"/{2,}", "/", route)
    if not route.startswith("/"):
        route = "/" + route
    return route


def _methods(callback) -> list[str]:
    actions = getattr(callback, "actions", None)
    if actions:
        return sorted(
            method.upper()
            for method in actions
            if method not in {"head", "options"}
        )
    view_class = getattr(callback, "view_class", None) or getattr(callback, "cls", None)
    if view_class:
        return [
            method.upper()
            for method in getattr(view_class, "http_method_names", ())
            if method not in {"head", "options"}
            and callable(getattr(view_class, method, None))
        ]
    return ["GET"]


def _action(callback, method: str) -> str:
    actions = getattr(callback, "actions", None) or {}
    return actions.get(method.lower(), method.lower())


def _view_class(callback):
    return getattr(callback, "view_class", None) or getattr(callback, "cls", None)


def _source(callback) -> str:
    target = _view_class(callback) or callback
    filename = inspect.getsourcefile(target)
    if not filename:
        return "unknown"
    try:
        return str(Path(filename).resolve().relative_to(REPO_ROOT))
    except ValueError:
        return filename


def _auth(path: str) -> str:
    if path in {"/healthz/", "/api/v1/utils/test/"}:
        return "none"
    if path.startswith("/api/v1/auth/"):
        return "none"
    if path == "/api/v1/check/login/":
        return "optional-token"
    if path in {
        "/api/v1/connections/digitalocean/oauth_url/",
        "/api/v1/connections/ovh_ca/oauth_url/",
        "/api/v1/connections/ovh_eu/oauth_url/",
        "/api/v1/connections/ovh_us/oauth_url/",
    }:
        # These starts create state in the same browser session that must later
        # receive the provider callback. API tokens cannot safely substitute
        # for the session/CSRF boundary.
        return "browser-session-csrf"
    return "token"


def _safety(method: str, path: str) -> str:
    if path == "/api/v1/auth/login/":
        return "safe-auth"
    if method != "GET":
        if path == "/api/v1/utils/ssh-host-keys/preview/":
            return "live-read"
        return "mutation"
    stateful_suffixes = (
        "/accept/",
        "/update_db_type_and_version/",
        "/validate/",
    )
    if (
        path.startswith("/api/v1/callback/")
        or path == "/api/v1/auth/logout/"
        or path.endswith(stateful_suffixes)
    ):
        return "stateful-get"
    if "/download" in path or path.endswith("/file/{{storedBackupId}}/"):
        return "download"
    return "safe-read"


def _kind(path: str) -> str:
    if path == "/healthz/":
        return "health"
    if path.startswith("/api/v1/callback/"):
        return "browser-oauth-callback"
    return "machine-api"


def operations() -> list[Operation]:
    configure_django()
    from django.urls import URLResolver, get_resolver

    result: list[Operation] = []

    def walk(patterns, prefix=""):
        for pattern in patterns:
            route = prefix + str(pattern.pattern)
            if isinstance(pattern, URLResolver):
                walk(pattern.url_patterns, route)
                continue
            path = normalize_route(route)
            if not (path.startswith("/api/v1/") or path == "/healthz/"):
                continue
            callback = pattern.callback
            view_class = _view_class(callback)
            view_name = (
                f"{view_class.__module__}.{view_class.__name__}"
                if view_class
                else f"{callback.__module__}.{callback.__name__}"
            )
            for method in _methods(callback):
                result.append(
                    Operation(
                        method=method,
                        path=path,
                        regex_route=route,
                        action=_action(callback, method),
                        view_name=view_name,
                        source=_source(callback),
                        auth=_auth(path),
                        safety=_safety(method, path),
                        kind=_kind(path),
                        callback=callback,
                    )
                )

    walk(get_resolver().url_patterns)
    result.sort(key=lambda item: (item.path, item.method, item.view_name, item.action))
    return result
