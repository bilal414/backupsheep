"""Introductory text for the generated OpenAPI document.

Kept free of Django imports because ``settings.py`` reads it at boot.
"""

from apps.api.v1.utils.api_scopes import IMPLIED_SCOPES, SCOPES


def _scope_table():
    rows = ["| Scope | Grants | Implies |", "| --- | --- | --- |"]
    for name, description in SCOPES.items():
        implies = ", ".join(f"`{item}`" for item in IMPLIED_SCOPES.get(name, ())) or "—"
        rows.append(f"| `{name}` | {description} | {implies} |")
    return "\n".join(rows)


API_DOCS_DESCRIPTION = f"""
The BackupSheep API exposes every workspace-scoped resource the console uses:
integrations, connections, backup sources, storage destinations, schedules,
backups, restores, notifications, activity, and team access. All paths live
under `/api/v1/` on your own BackupSheep instance.

## Authentication

| Credential | Header | Best for |
| --- | --- | --- |
| Personal API token (`bsk_…`) | `Authorization: Bearer bsk_…` | Scripts, CI, and service integrations bound to one workspace |
| OAuth 2.0 access token | `Authorization: Bearer …` | Third-party apps and the BackupSheep mobile apps (authorization code + PKCE) |
| Legacy login token | `Authorization: Token …` | Existing automation created with `POST /api/v1/auth/login/` |
| Console session | cookie + `X-CSRFToken` | The web console itself |

Personal tokens and OAuth tokens are **scoped**. Each operation below lists the
scope it requires under *Required scope*; a token that lacks it receives
`403` with `"code": "insufficient_scope"`. Operations marked *interactive
only* (credential management, provider OAuth callbacks, authenticator setup)
never accept a scoped token.

## Scopes

{_scope_table()}

## OAuth 2.0

* Authorization endpoint: `/o/authorize/` (authorization code, PKCE `S256` required)
* Token endpoint: `/o/token/` (`authorization_code`, `refresh_token`, `client_credentials`)
* Revocation: `/o/revoke_token/` · Introspection: `/o/introspect/`
* Discovery: `/.well-known/oauth-authorization-server`

Refresh tokens rotate on every use; reusing an old refresh token revokes the
whole token family. Register applications with `POST /api/v1/oauth/applications/`.

## Limits and pagination

Every identity is rate limited (sustained per-user and per-peer ceilings plus a
tighter limit for writes). A `429` response carries `Retry-After`. List
endpoints return complete collections unless `limit` (max 500) and optional
`offset` are sent, in which case the response is the envelope
`{{"count", "next", "previous", "results"}}`.
""".strip()
