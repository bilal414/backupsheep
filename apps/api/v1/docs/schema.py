"""drf-spectacular integration: security schemes and per-operation scopes."""

import re

from drf_spectacular.contrib.django_oauth_toolkit import DjangoOAuthToolkitScheme
from drf_spectacular.extensions import OpenApiAuthenticationExtension

from apps.api.v1.utils.api_scopes import ANY, PUBLIC, requirement_for

API_TOKEN_SCHEME = "apiToken"
OAUTH2_SCHEME = "oauth2"
# Names drf-spectacular assigns to DRF's TokenAuthentication and SessionAuthentication.
LEGACY_TOKEN_SCHEME = "tokenAuth"
SESSION_SCHEME = "cookieAuth"

_PATH_PARAM = re.compile(r"\{[^}]+\}")


class ApiTokenScheme(OpenApiAuthenticationExtension):
    target_class = "apps.api.v1.utils.api_authentication.ApiTokenAuthentication"
    name = API_TOKEN_SCHEME

    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "bsk_…",
            "description": (
                "Personal API token created in Settings → API access or with "
                "`POST /api/v1/tokens/`. Bound to one workspace and limited to "
                "the scopes chosen at creation."
            ),
        }


class ScopedOAuth2Scheme(DjangoOAuthToolkitScheme):
    target_class = "apps.api.v1.utils.api_authentication.ScopedOAuth2Authentication"
    name = OAUTH2_SCHEME

    def get_security_requirement(self, auto_schema):
        # Requirements are attached per operation by ``postprocess_security``.
        return None

    def get_security_definition(self, auto_schema):
        definition = super().get_security_definition(auto_schema)
        definition["description"] = (
            "OAuth 2.0 bearer token issued by this install's authorization server "
            "(authorization code with PKCE, or client credentials)."
        )
        return definition


def security_for(requirement):
    """OpenAPI ``security`` alternatives for one classified operation."""
    interactive = [{SESSION_SCHEME: []}, {LEGACY_TOKEN_SCHEME: []}]
    if requirement is None or requirement.is_interactive_only:
        return interactive
    if requirement.scope == PUBLIC:
        return []
    if requirement.scope == ANY:
        return [{API_TOKEN_SCHEME: []}, {OAUTH2_SCHEME: []}] + interactive
    return [
        {API_TOKEN_SCHEME: []},
        {OAUTH2_SCHEME: [requirement.scope]},
    ] + interactive


def postprocess_security(result, generator, request, public):
    """Replace drf-spectacular's per-view guesses with the route classification."""
    for path, operations in result.get("paths", {}).items():
        concrete_path = _PATH_PARAM.sub("1", path)
        for method, operation in operations.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            requirement = requirement_for(method.upper(), concrete_path)
            operation["security"] = security_for(requirement)
            if requirement is None or requirement.is_interactive_only:
                label = "interactive only"
                operation["x-backupsheep-scope"] = "interactive-only"
            elif requirement.scope == PUBLIC:
                label = "none (public endpoint)"
                operation["x-backupsheep-scope"] = "public"
            elif requirement.scope == ANY:
                label = "any authenticated credential"
                operation["x-backupsheep-scope"] = "any"
            else:
                label = f"`{requirement.scope}`"
                operation["x-backupsheep-scope"] = requirement.scope
            description = operation.get("description") or ""
            operation["description"] = f"**Required scope:** {label}" + (
                f"\n\n{description}" if description else ""
            )
    return result
