# API authentication

BackupSheep accepts four credentials. Pick the one that matches the caller:

| Credential | Header | Scoped | Best for |
|---|---|---|---|
| Personal API token | `Authorization: Bearer bsk_…` | Yes, workspace-bound | Scripts, CI jobs, monitoring, and service-to-service integrations |
| OAuth 2.0 access token | `Authorization: Bearer …` | Yes | Third-party applications and the BackupSheep mobile apps |
| Legacy login token | `Authorization: Token …` | No | Existing automation built on `POST /api/v1/auth/login/` |
| Console session | cookie + `X-CSRFToken` | No | The web console |

Scoped credentials can only call the endpoints their scopes allow, and they can never
manage credentials, complete provider OAuth callbacks, or change authenticator/password
settings. Everything a credential does is still limited by the member's own
permissions in the workspace: a token never grants more than the person who created it
has.

## Personal API tokens

### Create a token

Create tokens in the console under **Settings → API access**, or with the API while
signed in (session or legacy login token). Re-entering the current password is
required so a hijacked browser tab cannot mint credentials silently.

```http
POST /api/v1/tokens/
Content-Type: application/json

{
  "name": "Nightly report",
  "scopes": ["backups:read", "activity:read"],
  "expires_in": 2592000,
  "current_password": "replace-me"
}
```

```json
{
  "id": 12,
  "name": "Nightly report",
  "key_prefix": "bsk_4fJq9pLm",
  "scopes": ["backups:read", "activity:read"],
  "account": {"id": 1, "name": "Acme"},
  "status": "active",
  "expires_at": "2026-10-23T09:12:00Z",
  "last_used_at": null,
  "revoked_at": null,
  "created": "2026-09-23T09:12:00Z",
  "token": "bsk_4fJq9pLmB2hV…"
}
```

`token` is shown once. Only its SHA-256 digest is stored, so a lost token cannot be
recovered — rotate or create a new one instead.

Optional fields:

- `expires_in` — lifetime in seconds. Defaults to `API_TOKEN_TTL_SECONDS` and may not
  exceed `API_TOKEN_MAX_TTL_SECONDS` (90 days unless the operator raised it).
- `account_id` — the workspace to bind the token to. Defaults to your current
  workspace; you must hold an active membership there.

### Send the token

```http
Authorization: Bearer bsk_4fJq9pLmB2hV…
Accept: application/json
```

Every request made with the token runs inside the bound workspace, regardless of the
workspace currently selected in the console. Tokens cannot switch workspaces.

### Manage tokens

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/tokens/` | List your tokens (never includes secrets). |
| `GET` | `/api/v1/tokens/{id}/` | One token with status `active`, `expired`, or `revoked`. |
| `POST` | `/api/v1/tokens/{id}/rotate/` | Issue a new secret for the same token (requires `current_password`). |
| `DELETE` | `/api/v1/tokens/{id}/` | Revoke. The row stays visible as an audit record. |
| `GET` | `/api/v1/tokens/scopes/` | The scope catalog (available to any credential). |

Token creation, rotation, and revocation are written to the workspace activity log.
Revocation is immediate. Tokens also stop working when the member's membership in the
bound workspace is suspended or removed, when the user is deactivated, and when the
token is used with `POST /api/v1/auth/logout/` (which revokes only that token).

## Scopes

| Scope | Grants | Implies |
|---|---|---|
| `profile` | Your identity, memberships, and console capabilities (`mobile/bootstrap/`, switching workspace for OAuth tokens) | — |
| `account:read` | Read workspace settings, members, access groups, invitations, notification channels | — |
| `account:write` | Manage the same resources | `account:read` |
| `sources:read` | Read integrations, connections, and backup sources | — |
| `sources:write` | Create, validate, and change them (including SSH host-key approval) | `sources:read` |
| `backups:read` | List backups, restore history, storage points, transfer history | — |
| `backups:write` | Trigger, retry, cancel, and delete backups; on-demand snapshots | `backups:read` |
| `backups:restore` | Start and resume restores | — |
| `backups:download` | Download archives, directory trees, and transfer logs | — |
| `storage:read` | Read storage destinations and usage | — |
| `storage:write` | Create, validate, and change destinations | `storage:read` |
| `schedules:read` | Read schedules | — |
| `schedules:write` | Create, change, pause, resume, and trigger schedules | `schedules:read` |
| `activity:read` | Activity logs and backup statistics | — |

`backups:restore` and `backups:download` are deliberately not implied by
`backups:write` because they move backup data out of BackupSheep. A restore
automation usually needs `backups:read` + `backups:restore`.

The OpenAPI document (`/api/v1/schema/`) and the Redoc page (`/api/v1/docs/`) show the
required scope on every operation. A request whose credential lacks the scope receives:

```json
{"detail": "The credential does not include the required scope.",
 "code": "insufficient_scope", "required_scope": "backups:restore"}
```

with status `403`. Endpoints reserved for interactive use return `403` with
`"code": "interactive_credential_required"`.

## OAuth 2.0

Third-party applications and the mobile apps obtain scoped access tokens through the
built-in authorization server. See [OAuth 2.0](oauth.md) for application registration,
the authorization-code + PKCE flow, refresh, revocation, and the iOS integration guide.

## Legacy login token

`POST /api/v1/auth/login/` still returns `api_key`, a Django REST Framework token sent
as `Authorization: Token …`. It is unscoped, expires after `API_TOKEN_TTL_SECONDS`, is
replaced on every login, and is revoked by `POST /api/v1/auth/logout/`, password
changes, and authenticator changes. Existing automation keeps working; new integrations
should use a personal API token or OAuth so their access is scoped and revocable on its
own.

```http
POST /api/v1/auth/login/
Content-Type: application/json

{"email": "operator@example.com", "password": "replace-me"}
```

A member with an authenticator enabled receives `{"auth_multi_factor": true}` and must
repeat the request with `auth_multi_factor_token`. Browser session creation additionally
requires the console's same-origin request marker and CSRF proof; native callers only
receive the token.

## Session authentication

The console authenticates with Django's session cookie. Unsafe session-authenticated
requests (`POST`, `PUT`, `PATCH`, and `DELETE`) must also pass Django's CSRF check by
sending the CSRF cookie value in the `X-CSRFToken` header. Bearer and `Token`
credentials do not use cookies and need no CSRF token.

## Authentication endpoints

| Method | Endpoint | Authentication | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/auth/login/` | Public, rate limited | Verify email/password (and authenticator code), start a session or return the legacy token. |
| `POST` | `/api/v1/auth/logout/` | Any | Session/legacy token: end the session and revoke the legacy token. Scoped credential: revoke that credential only. |
| `GET` | `/api/v1/check/login/` | Any (optional) | Whether the request is authenticated. |
| `POST` | `/api/v1/auth/reset/` | Public, rate limited | Request a password-reset email. |
| `PATCH` | `/api/v1/auth/reset/` | Public, rate limited | Complete a password reset. |
| `GET` | `/api/v1/mobile/bootstrap/` | `profile` | Identity, permissions, and capabilities for native clients. |

## Current workspace

A member may belong to more than one workspace. Sessions, legacy tokens, and OAuth
tokens operate in the member's *current* workspace and may change it with
`POST /api/v1/members/{member_id}/switch_current_account/` (`profile` scope). Personal
API tokens are bound to one workspace at creation and ignore the console selection, so
automation never drifts between tenants.

## Common authentication failures

| Status | Meaning | Check |
|---|---|---|
| `401 Unauthorized` | Missing, invalid, expired, or revoked credential; inactive user; no active membership. | The exact header scheme (`Bearer` for personal/OAuth tokens, `Token` for the legacy token), expiry, and membership status. |
| `403 Forbidden` with `insufficient_scope` | Valid scoped credential without the required scope. | `required_scope` in the body; create a token with that scope or request it during OAuth consent. |
| `403 Forbidden` with `interactive_credential_required` | The endpoint is reserved for the console session or legacy token. | Perform the action in the console. |
| `403 Forbidden` (other) | CSRF or a workspace/group permission rejected the action. | For session auth send `X-CSRFToken`; otherwise check group permissions and node visibility. |
| `429 Too Many Requests` | A rate limit was hit. | Wait for `Retry-After`; see [Rate limits](conventions.md#rate-limits). |
