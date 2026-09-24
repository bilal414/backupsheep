"""Scope registry and route classification for scoped API credentials.

Personal API tokens and OAuth 2.0 access tokens carry a space-separated list of
scopes.  Rather than annotating each of the ~900 operations in the API, every
route is classified here from its method and path.  The classification is
fail-closed: a route that no rule matches is unavailable to scoped tokens, and
``apps/tests/test_api_scopes.py`` asserts that every registered ``/api/v1/``
route is covered so an unclassified endpoint cannot ship silently.

Interactive credentials (the CSRF-protected console session and the legacy
login token) are not scoped and are unaffected by this module.
"""

import re
from dataclasses import dataclass


API_PREFIX = "/api/v1/"
# Kept free of Django/DRF imports so settings.py can import the scope registry.
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

# Sentinels for routes that are not gated by a scope.
PUBLIC = "public"  # no credential needed
ANY = "any"  # any valid credential, no specific scope
INTERACTIVE_ONLY = "interactive-only"  # never available to scoped tokens

SCOPES = {
    "profile": (
        "Read your own identity, workspace memberships, and console capabilities"
    ),
    "account:read": (
        "Read workspace settings, members, access groups, invitations, and "
        "notification channels"
    ),
    "account:write": (
        "Manage workspace settings, members, access groups, invitations, and "
        "notification channels"
    ),
    "sources:read": "Read integrations, connections, and backup sources",
    "sources:write": (
        "Create, validate, and change integrations, connections, and backup "
        "sources (including on-demand snapshots)"
    ),
    "backups:read": "List backups, restores, storage points, and transfer history",
    "backups:write": "Trigger, retry, cancel, and delete backups",
    "backups:restore": "Start and resume restores from backups",
    "backups:download": "Download backup archives, directory trees, and transfer logs",
    "storage:read": "Read storage destinations and their usage",
    "storage:write": "Create, validate, and change storage destinations",
    "schedules:read": "Read backup schedules",
    "schedules:write": "Create, change, pause, and trigger backup schedules",
    "activity:read": "Read activity logs and backup statistics",
}

# ``<family>:write`` implies ``<family>:read``.  Restore and download stay
# separate because they move backup data out of the system.
IMPLIED_SCOPES = {
    "account:write": ("account:read",),
    "sources:write": ("sources:read",),
    "backups:write": ("backups:read",),
    "storage:write": ("storage:read",),
    "schedules:write": ("schedules:read",),
}

# Scopes a public (non-confidential) OAuth client such as a mobile app may hold.
# Everything is available; the split exists so operators can tighten it later.
PUBLIC_CLIENT_SCOPES = tuple(SCOPES)

DEFAULT_OAUTH_SCOPES = ("profile",)


@dataclass(frozen=True)
class Requirement:
    """The credential requirement resolved for one request."""

    scope: str
    # Account-bound personal tokens cannot exercise identity-level state such as
    # switching the member's current workspace.
    account_bound_allowed: bool = True

    @property
    def is_public(self):
        return self.scope == PUBLIC

    @property
    def is_interactive_only(self):
        return self.scope == INTERACTIVE_ONLY

    @property
    def needs_scope(self):
        return self.scope not in (PUBLIC, ANY, INTERACTIVE_ONLY)


class _Rule:
    __slots__ = ("pattern", "read", "write", "account_bound_allowed")

    def __init__(self, pattern, *, read=None, write=None, account_bound_allowed=True):
        self.pattern = re.compile(r"^" + pattern + r"$")
        self.read = read
        self.write = write
        self.account_bound_allowed = account_bound_allowed

    def match(self, method, path):
        if not self.pattern.match(path):
            return None
        scope = self.read if method in SAFE_METHODS else self.write
        if scope is None:
            return None
        return Requirement(scope, self.account_bound_allowed)


def _rule(pattern, scope=None, *, read=None, write=None, account_bound_allowed=True):
    if scope is not None:
        read = write = scope
    return _Rule(pattern, read=read, write=write, account_bound_allowed=account_bound_allowed)


_ID = r"[^/]+"

# Ordered: the first rule that yields a scope for the method wins, so action
# specific rules precede their resource family.
RULES = (
    # Authentication and health.
    _rule(r"auth/(login|reset)/", PUBLIC),
    _rule(r"auth/logout/", ANY),
    _rule(r"check/login/", ANY),
    _rule(r"utils/test/?", PUBLIC),
    # Provider OAuth callbacks complete browser-session state and can never be
    # driven by a bearer token.
    _rule(r"callback/.*", INTERACTIVE_ONLY),
    # Credential and API-access management is reserved for interactive
    # sessions so a leaked scoped token can never mint broader credentials.
    _rule(r"members/" + _ID + r"/auth_multi_factor_[a-z_]+/", INTERACTIVE_ONLY),
    _rule(r"tokens/scopes/", read=ANY),
    _rule(r"tokens(/.*)?", INTERACTIVE_ONLY),
    _rule(r"oauth/.*", INTERACTIVE_ONLY),
    # API documentation.
    _rule(r"(schema|docs)(/.*)?", read=ANY),
    # Identity.
    _rule(r"mobile/bootstrap/", read="profile"),
    _rule(
        r"members/" + _ID + r"/switch_current_account/",
        write="profile",
        account_bound_allowed=False,
    ),
    # Restore, download, and restore history appear under several families.
    _rule(r".*/(restore|resume_restore|restore_backup)/", write="backups:restore"),
    _rule(r".*/restores/", read="backups:read"),
    _rule(r".*/download(_transfer_log|_dir_tree)?/", read="backups:download"),
    _rule(r"storage/local/file/.*", read="backups:download"),
    _rule(r"nodes/" + _ID + r"/backup_request_status/", read="backups:read"),
    _rule(r"nodes/" + _ID + r"/take_snapshot/", write="backups:write"),
    _rule(r"clouds/" + _ID + r"/" + _ID + r"/runs/", read="backups:read"),
    _rule(r"clouds/" + _ID + r"/" + _ID + r"/run/", write="backups:write"),
    # Resource families.
    _rule(r"backups/.*", read="backups:read", write="backups:write"),
    _rule(
        r"(nodes|connections|clouds|saas|volumes|databases|websites)/.*",
        read="sources:read",
        write="sources:write",
    ),
    _rule(r"utils/ssh-host-keys/.*", write="sources:write"),
    _rule(r"storage/.*", read="storage:read", write="storage:write"),
    _rule(r"schedules/.*", read="schedules:read", write="schedules:write"),
    _rule(r"(logs|stats)/.*", read="activity:read"),
    _rule(
        r"(accounts|groups|invites|members|notifications-(email|slack|telegram))/.*",
        read="account:read",
        write="account:write",
    ),
)


def normalize_path(path):
    """Return the request path relative to the API prefix, or ``None``."""
    if not isinstance(path, str) or not path.startswith(API_PREFIX):
        return None
    relative = path[len(API_PREFIX):]
    # Collapse duplicate slashes so a rule cannot be bypassed by ``//``.
    return re.sub(r"/{2,}", "/", relative)


def requirement_for(method, path):
    """Classify one request.  ``None`` means "unclassified" and fails closed."""
    relative = normalize_path(path)
    if relative is None:
        return None
    method = (method or "GET").upper()
    for rule in RULES:
        requirement = rule.match(method, relative)
        if requirement is not None:
            return requirement
    return None


def expand_scopes(scopes):
    """Return the effective scope set including implied read scopes."""
    effective = set()
    for scope in scopes:
        effective.add(scope)
        effective.update(IMPLIED_SCOPES.get(scope, ()))
    return effective


def parse_scope_string(value):
    """Split a space-separated scope string, dropping blanks and duplicates."""
    seen = []
    for item in str(value or "").split():
        if item not in seen:
            seen.append(item)
    return seen


def validate_scopes(scopes, *, allowed=None):
    """Return the normalized scope list or raise ``ValueError`` naming the problem."""
    allowed = set(SCOPES if allowed is None else allowed)
    normalized = []
    for scope in scopes:
        if not isinstance(scope, str) or scope not in SCOPES:
            raise ValueError(f"Unknown scope: {scope!r}")
        if scope not in allowed:
            raise ValueError(f"Scope not permitted for this credential: {scope!r}")
        if scope not in normalized:
            normalized.append(scope)
    if not normalized:
        raise ValueError("At least one scope is required.")
    return normalized


def scope_catalog():
    """Serializable scope listing for the documentation and token endpoints."""
    return [
        {
            "scope": name,
            "description": description,
            "implies": list(IMPLIED_SCOPES.get(name, ())),
        }
        for name, description in SCOPES.items()
    ]
