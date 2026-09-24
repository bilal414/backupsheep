# OAuth 2.0

Every BackupSheep install runs its own OAuth 2.0 authorization server. Applications
registered on an install obtain scoped, expiring access tokens on behalf of a member,
and the member can review or revoke that access at any time.

## Endpoints

| Purpose | URL |
|---|---|
| Discovery (RFC 8414) | `GET /.well-known/oauth-authorization-server` |
| Authorization (consent) | `GET /o/authorize/` |
| Token | `POST /o/token/` |
| Revocation (RFC 7009) | `POST /o/revoke_token/` |
| Introspection (RFC 7662) | `POST /o/introspect/` (client-authenticated confidential clients) |

Security posture, fixed by configuration:

- Only the **authorization code** grant (with mandatory PKCE `S256`), **refresh token**
  grant, and **client credentials** grant are offered. The implicit and password
  grants are refused.
- Redirect URIs must match a registered value exactly. Allowed schemes are
  `https` and the mobile app scheme `backupsheep` unless the operator changes
  `OAUTH2_ALLOWED_REDIRECT_URI_SCHEMES` (adding `http` enables RFC 8252 loopback
  `http://127.0.0.1:<port>/…` callbacks for CLI tools; the port may vary).
- Access tokens expire after `OAUTH2_ACCESS_TOKEN_TTL_SECONDS` (1 hour by default).
  Refresh tokens rotate on every use, expire after `OAUTH2_REFRESH_TOKEN_TTL_SECONDS`
  counted from the access token's expiry, and a **replayed refresh token revokes the
  whole token family**.
- Tokens and client secrets are stored hashed. Access tokens are accepted only in the
  `Authorization` header, never in a query string.
- The consent page is served with a strict Content-Security-Policy and requires the
  member to be signed in to the console (including the authenticator challenge, if
  enabled) and to hold an active workspace membership.
- The token, revocation, and introspection endpoints are rate limited per peer and per
  client.

## Register an application

Any member can register applications they own with an interactive credential (console
session or legacy login token); scoped tokens cannot. The console page is
**Settings → API access**.

```http
POST /api/v1/oauth/applications/
Content-Type: application/json

{
  "name": "Acme Dashboard",
  "client_type": "confidential",
  "authorization_grant_type": "authorization-code",
  "redirect_uris": ["https://dashboard.acme.example/oauth/callback"],
  "current_password": "replace-me"
}
```

The response contains `client_id` and, for confidential clients, `client_secret`
(shown once; rotate it with `POST /api/v1/oauth/applications/{id}/rotate_secret/`).
Public clients (mobile, desktop, and single-page apps) receive no secret and must use
PKCE.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/oauth/applications/` | Applications you registered. |
| `PATCH` | `/api/v1/oauth/applications/{id}/` | Rename or change redirect URIs. Client type and grant type are fixed. |
| `DELETE` | `/api/v1/oauth/applications/{id}/` | Delete the application and every token issued to it. |
| `GET` | `/api/v1/oauth/authorized-applications/` | Applications currently holding access on your behalf, with their scopes. |
| `DELETE` | `/api/v1/oauth/authorized-applications/{application_id}/` | Withdraw that application's access (all tokens, refresh tokens, and pending codes). |

First-party clients that must exist on every install (for example the BackupSheep
mobile app) are provisioned by the operator with a fixed identifier:

```bash
python manage.py provision_oauth_client \
  --client-id backupsheep-ios \
  --name "BackupSheep for iOS" \
  --owner-email operator@example.com \
  --redirect-uri backupsheep://oauth/callback \
  --skip-consent
```

`--skip-consent` marks the client as trusted so members are not shown the consent page;
omit it for anything that is not shipped by the operator.

## Authorization code flow with PKCE

1. Generate a `code_verifier` (43–128 URL-safe characters) and its
   `code_challenge = BASE64URL(SHA256(code_verifier))`.
2. Send the member to the consent page:

   ```text
   https://backup.example.com/o/authorize/
     ?response_type=code
     &client_id=CLIENT_ID
     &redirect_uri=https%3A%2F%2Fdashboard.acme.example%2Foauth%2Fcallback
     &scope=profile%20backups%3Aread%20backups%3Awrite
     &state=RANDOM_STATE
     &code_challenge=CODE_CHALLENGE
     &code_challenge_method=S256
   ```

   A member who is not signed in is redirected to the console login first. On
   approval the browser is redirected to the registered URI with `code`, `state`,
   and `iss` (RFC 9207). On refusal it receives `error=access_denied`.
3. Exchange the code within 60 seconds:

   ```http
   POST /o/token/
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&code=CODE&redirect_uri=https%3A%2F%2Fdashboard.acme.example%2Foauth%2Fcallback&client_id=CLIENT_ID&code_verifier=CODE_VERIFIER
   ```

   Confidential clients also authenticate with HTTP Basic (`client_id:client_secret`)
   or `client_secret` in the body.

   ```json
   {
     "access_token": "…",
     "expires_in": 3600,
     "token_type": "Bearer",
     "scope": "profile backups:read backups:write",
     "refresh_token": "…"
   }
   ```
4. Call the API with `Authorization: Bearer ACCESS_TOKEN`.
5. Before the access token expires, refresh:

   ```http
   POST /o/token/
   Content-Type: application/x-www-form-urlencoded

   grant_type=refresh_token&refresh_token=REFRESH_TOKEN&client_id=CLIENT_ID
   ```

   Store the **new** refresh token before using the new access token; the previous
   refresh token is invalid immediately (there is no grace window, because tokens are
   stored hashed). Using an old refresh token revokes the entire family, and the app
   must send the member through the consent page again.

Scopes are listed in [Authentication → Scopes](authentication.md#scopes) and in the
discovery document's `scopes_supported`. Request only what the application needs;
members see every requested scope on the consent page.

## Client credentials

A confidential application registered with `"authorization_grant_type":
"client-credentials"` obtains tokens without user interaction. The token acts as the
member who registered the application, limited to the requested scopes and that
member's permissions, and stops working if that member loses their workspace access.

```http
POST /o/token/
Authorization: Basic BASE64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=backups:read%20activity:read
```

No refresh token is issued; request a new access token when the current one expires.

## Revocation and sign-out

- `POST /o/revoke_token/` with `token` (and client authentication) revokes an access
  or refresh token (RFC 7009).
- `POST /api/v1/auth/logout/` with an OAuth access token revokes that access token and
  its refresh token.
- Members revoke an application from **Settings → API access** or with
  `DELETE /api/v1/oauth/authorized-applications/{application_id}/`.
- Deleting an application revokes everything issued to it.

## Errors

The token endpoint returns RFC 6749 error bodies (`invalid_grant`, `invalid_client`,
`invalid_scope`, `unsupported_grant_type`, …). Rate limiting returns `429` with
`{"error": "slow_down"}` and `Retry-After`. Resource requests with an invalid or
expired access token receive `401` with a `WWW-Authenticate: Bearer` challenge; a valid
token without the required scope receives `403` with `"code": "insufficient_scope"`.

## Native and mobile apps

See [iOS integration](ios.md) for a complete Swift example using
`ASWebAuthenticationSession`, PKCE, the keychain, and refresh handling. The same flow
applies to Android (Custom Tabs) and desktop clients (loopback redirect).
