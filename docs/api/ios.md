# iOS integration guide

The BackupSheep iOS app (and any native client) uses the same REST API as the console,
authenticated with OAuth 2.0 access tokens obtained through the authorization-code
flow with PKCE. This guide describes the contract and shows the client-side pieces.

## Server-side prerequisites

Each self-hosted install must expose the app as a **public** OAuth client with a fixed
identifier. Operators run once:

```bash
python manage.py provision_oauth_client \
  --client-id backupsheep-ios \
  --name "BackupSheep for iOS" \
  --owner-email operator@example.com \
  --redirect-uri backupsheep://oauth/callback \
  --skip-consent
```

The app therefore needs only the install's base URL from the user. It discovers the
endpoints from `GET /.well-known/oauth-authorization-server` and uses
`client_id=backupsheep-ios` with the `backupsheep://oauth/callback` redirect. Because
custom URL schemes can be claimed by other apps, PKCE is mandatory and the server
never issues a token without the matching `code_verifier`.

## Recommended scopes

Request the minimum set for the feature surface the app exposes:

```text
profile sources:read backups:read backups:write schedules:read storage:read activity:read
```

Add `backups:restore` or `backups:download` only if the app offers those actions; the
consent page lists every requested scope. Members with an authenticator enabled
complete the TOTP challenge on the console login page inside the authentication
session; the app never handles passwords or codes.

## Bootstrap after sign-in

`GET /api/v1/mobile/bootstrap/` (scope `profile`) returns the member, the current
workspace, granted permissions, feature flags, and the supported backup families.
Call it after every token acquisition and after switching workspaces with
`POST /api/v1/members/{member_id}/switch_current_account/`.

## Swift example

```swift
import AuthenticationServices
import CryptoKit
import Foundation

struct OAuthConfig {
    let baseURL: URL                    // e.g. https://backup.example.com
    let clientID = "backupsheep-ios"
    let redirectURI = "backupsheep://oauth/callback"
    let scopes = ["profile", "sources:read", "backups:read", "backups:write",
                  "schedules:read", "storage:read", "activity:read"]
}

struct TokenResponse: Decodable {
    let access_token: String
    let refresh_token: String?
    let expires_in: Int
    let scope: String
}

final class BackupSheepAuth: NSObject, ASWebAuthenticationPresentationContextProviding {
    private let config: OAuthConfig
    private var session: ASWebAuthenticationSession?

    init(config: OAuthConfig) { self.config = config }

    // MARK: PKCE
    private static func verifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64URLEncodedString()
    }
    private static func challenge(for verifier: String) -> String {
        Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
    }

    // MARK: Authorization code flow
    func signIn() async throws -> TokenResponse {
        let verifier = Self.verifier()
        let state = Self.verifier()
        var components = URLComponents(url: config.baseURL.appendingPathComponent("o/authorize/"),
                                       resolvingAgainstBaseURL: false)!
        components.queryItems = [
            .init(name: "response_type", value: "code"),
            .init(name: "client_id", value: config.clientID),
            .init(name: "redirect_uri", value: config.redirectURI),
            .init(name: "scope", value: config.scopes.joined(separator: " ")),
            .init(name: "state", value: state),
            .init(name: "code_challenge", value: Self.challenge(for: verifier)),
            .init(name: "code_challenge_method", value: "S256"),
        ]

        let callback: URL = try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(url: components.url!,
                                                     callbackURLScheme: "backupsheep") { url, error in
                if let url { continuation.resume(returning: url) }
                else { continuation.resume(throwing: error ?? URLError(.cancelled)) }
            }
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = false // reuse the console login
            self.session = session
            session.start()
        }

        let items = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems ?? []
        guard items.first(where: { $0.name == "state" })?.value == state,
              let code = items.first(where: { $0.name == "code" })?.value else {
            throw URLError(.userAuthenticationRequired)
        }
        return try await token(form: [
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.redirectURI,
            "client_id": config.clientID,
            "code_verifier": verifier,
        ])
    }

    // MARK: Refresh
    func refresh(refreshToken: String) async throws -> TokenResponse {
        try await token(form: [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": config.clientID,
        ])
    }

    private func token(form: [String: String]) async throws -> TokenResponse {
        var request = URLRequest(url: config.baseURL.appendingPathComponent("o/token/"))
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = form.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "")" }
            .joined(separator: "&").data(using: .utf8)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw URLError(.userAuthenticationRequired) // inspect the RFC 6749 error body
        }
        return try JSONDecoder().decode(TokenResponse.self, from: data)
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        ASPresentationAnchor()
    }
}

extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
```

## Token handling rules

- Store `access_token` and `refresh_token` in the keychain
  (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`); never in `UserDefaults`.
- Refresh proactively a minute before `expires_in` elapses, and always **replace** the
  stored refresh token with the one in the refresh response. Refresh tokens rotate:
  reusing an old one revokes the family and forces a fresh sign-in.
- Serialize refreshes (one in flight at a time). If two requests race and one fails
  with `invalid_grant`, retry once with the newest stored token before signing out.
- Treat `401` on an API call as "refresh, then retry once"; treat `403` with
  `insufficient_scope` as a missing scope, not an authentication failure.
- On sign-out call `POST /api/v1/auth/logout/` with the access token (revokes the
  token pair) and clear the keychain.
- Respect `429` + `Retry-After` and back off; the app shares the member's rate limit
  with their other clients.

## API usage notes for the app

- All list endpoints accept `limit` (≤ 500) and `offset` and then return
  `{count, next, previous, results}`. Without `limit` the full list is returned.
- Backups, restores, and snapshots are asynchronous; poll the durable status endpoints
  described in [Conventions → Background operations](conventions.md#background-operations).
- Send `Idempotency-Key` on job-creating requests so a retried request after a
  network failure does not start a second backup or restore.
- The consent and login pages are standard web pages; present them with
  `ASWebAuthenticationSession` rather than an embedded `WKWebView` so the member's
  console session and password manager are available.
