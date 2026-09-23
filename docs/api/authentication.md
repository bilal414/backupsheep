# API authentication

BackupSheep supports persistent DRF tokens for scripts and Bruno, plus the
CSRF-protected Django session used by the browser console.

## Token authentication

### Obtain a token

```http
POST /api/v1/auth/login/
Content-Type: application/json

{
  "email": "operator@example.com",
  "password": "replace-me"
}
```

A successful response has this shape:

```json
{
  "api_key": "token-value",
  "next": null
}
```

The login also creates a browser session. API clients only need the returned token.

### Send the token

```http
Authorization: Token token-value
Accept: application/json
```

`Token` is the authentication scheme name. `Bearer token-value` is not equivalent and
will not authenticate.

### Token lifetime and storage

The login endpoint gets or creates one token for the Django user. It does not return an
expiry timestamp or scopes, and logging out of the browser does not revoke that token.
Treat it like a long-lived password:

- store it in a secrets manager or local uncommitted Bruno secret;
- do not put it in URLs, screenshots, logs, issues, or Git history;
- use a dedicated least-privilege account for automation;
- if a token may be exposed, have an instance administrator revoke or replace it in
  Django administration before trusting the account again.

## Session authentication

The console authenticates with Django's session cookie. Unsafe session-authenticated
requests (`POST`, `PUT`, `PATCH`, and `DELETE`) must also pass Django's CSRF check.
Send the CSRF cookie value in the `X-CSRFToken` header, as the console does.

Token-authenticated requests do not use cookie authentication and therefore do not
need a CSRF token.

For non-browser automation, token authentication is simpler and avoids accidentally
mixing a session cookie with a missing CSRF header.

## Authentication endpoints

| Method | Endpoint | Authentication | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/auth/login/` | Public, rate limited | Verify email/password, start a session, and return the user's API token. |
| `GET` | `/api/v1/auth/logout/` | Public | End the current browser session. It does not revoke the API token. |
| `GET` | `/api/v1/check/login/` | Required | Return the current member/session context used by the console. |
| `POST` | `/api/v1/auth/reset/` | Public, rate limited | Request a password-reset email. The response does not disclose whether an address exists. |
| `PATCH` | `/api/v1/auth/reset/` | Public, rate limited | Set a new password with a valid reset token. |

Password-reset request body:

```json
{
  "email": "operator@example.com"
}
```

Password-reset completion body:

```json
{
  "password": "a-new-strong-password",
  "password_confirm": "a-new-strong-password",
  "password_token": "token-from-the-reset-email"
}
```

## Current account

A member may belong to more than one BackupSheep account. Most API querysets use the
member's current account. Discover the member/account state with
`GET /api/v1/check/login/` or the account and member endpoints, then use
`POST /api/v1/members/{member_id}/switch_current_account/` when an interactive client
intentionally changes context.

Switching context affects subsequent requests made with that user's session or token.
Do not switch a shared automation identity concurrently between accounts; use a
separate identity for predictable automation.

## Common authentication failures

| Status | Meaning | Check |
|---|---|---|
| `401 Unauthorized` | No usable session/token, invalid token, inactive user, or expired login state. | Confirm the exact `Authorization: Token ...` header and the member's active status. |
| `403 Forbidden` | Authenticated, but CSRF or an account/group permission rejected the action. | For session auth, send `X-CSRFToken`; otherwise check current account, node visibility, and group permissions. |
| `429 Too Many Requests` | A public authentication endpoint was rate limited. | Stop retrying in a loop and wait before the next attempt. |
