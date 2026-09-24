# BackupSheep REST API

BackupSheep exposes the same account-scoped resources used by its web console under
`/api/v1/`. The API can manage integrations, sources, storage destinations,
schedules, backups, restores, notifications, and team access, and it is the contract
the BackupSheep mobile apps are built on.

The API is part of the self-hosted application. Replace `https://backup.example.com`
in every example with the URL of your own BackupSheep instance.

## Start here

1. Read [Authentication](authentication.md) and create a **personal API token** in
   Settings → API access (or with `POST /api/v1/tokens/`). Building an app for other
   people? Register an [OAuth 2.0](oauth.md) application instead.
2. Read [Conventions and safety](conventions.md), especially the notes about
   account scope, pagination, rate limits, background operations, idempotency, and
   destructive requests.
3. Follow [Common workflows](workflows.md) for a practical sequence from connection
   setup through backup and restore.
4. Browse the live, install-specific documentation at `/api/v1/docs/` (Redoc) or
   `/api/v1/docs/swagger/` (Swagger UI), or download the OpenAPI 3 document from
   `/api/v1/schema/`. Every operation lists the scope it requires.
5. Use the [Endpoint reference](reference.md) to find a resource family and import the
   repository's [Bruno collection](../../bruno/README.md) for runnable requests.

## Base URL

```text
https://backup.example.com/api/v1
```

Most resource URLs end in `/`. Keep the trailing slash in API clients so a proxy or
Django redirect never has to replay a request body.

## Minimal example

Create a token in the console (Settings → API access) with the `sources:read` scope,
then:

```bash
curl --url https://backup.example.com/api/v1/nodes/ \
  --header 'Accept: application/json' \
  --header 'Authorization: Bearer bsk_YOUR_TOKEN'
```

Add `?limit=50` to receive the first page of a large collection.

## Credentials at a glance

| Credential | Header | Scoped | Use it for |
|---|---|---|---|
| Personal API token | `Authorization: Bearer bsk_…` | yes, bound to one workspace | scripts, CI, service integrations |
| OAuth 2.0 access token | `Authorization: Bearer …` | yes | third-party apps, the iOS app |
| Legacy login token | `Authorization: Token …` | no | existing automation using `auth/login/` |
| Console session | cookie + `X-CSRFToken` | no | the web console |

## OpenAPI and interactive docs

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/schema/` | OpenAPI 3 document (`Accept: application/vnd.oai.openapi+json` for JSON, default YAML) |
| `GET /api/v1/docs/` | Redoc reference, grouped by resource family |
| `GET /api/v1/docs/swagger/` | Swagger UI with "try it out" |

The documentation is served from local static files (no CDN) and requires a signed-in
member unless the operator sets `API_DOCS_PUBLIC=true`. Generate a file for client
code generation with `python manage.py spectacular --file openapi.yaml`.

## API scope

The API is account-aware and permission-aware:

- Lists and object lookups are scoped to the member's workspace and, where
  applicable, the nodes visible through that member's groups. Personal tokens are
  pinned to the workspace chosen at creation.
- The primary account member has full account access. Other members need the relevant
  group permission for write and operational actions. A token never grants more than
  its owner has, and a scoped token grants only the scopes it carries.
- A valid object ID from another account is not authorization. Always discover IDs
  through a list endpoint available to the same credential.
- Provider credentials, storage secrets, raw worker coordination fields, and unsafe
  provider responses are not intended to be returned by public serializers.

## Formats

- Requests and responses normally use JSON.
- The API also accepts multipart bodies where a view needs them.
- Archive download routes remain in the v1 surface, but the stock enterprise artifact
  pipeline refuses direct download of BSE1 ciphertext. Do not expect a file response or
  provider URL for a current archive; use its authenticated restore action. Other file
  endpoints and explicitly enabled legacy-artifact deployments can have different
  response behavior.
- List endpoints return the whole collection unless `limit` is sent; see
  [Pagination](conventions.md#pagination).
- Datetimes are serialized by Django REST Framework. Human-readable `*_display`
  fields are convenience values, not stable machine timestamps.

## Versioning and compatibility

The current public namespace is `v1`. The OpenAPI document served by each install is
the machine-readable contract for that version; this documentation, the checked-in
Bruno collection, and the route coverage validator describe the same surface. Review
API changes when upgrading a self-hosted instance.

## Security reminders

- Use HTTPS before sending credentials or tokens over a network.
- Prefer scoped credentials with the smallest scope set and the shortest practical
  lifetime; rotate or revoke them from Settings → API access.
- Never commit a real token, client secret, provider credential, session cookie, OAuth
  code, or signed download URL.
- Use a dedicated member with the smallest practical group permissions for
  automation.
- Keep production tokens outside Bruno's committed environment template.
- `GET` is not universally side-effect-free in this legacy API. For example, logout,
  invite acceptance, validation, OAuth callbacks, and some provider discovery actions
  can change session or provider-linked state. Read the request documentation before
  running a folder as a batch.

## Related documentation

- [OAuth 2.0](oauth.md) and the [iOS integration guide](ios.md)
- [Feature guides](../features/README.md)
- [Provider and destination reference](../reference/provider-matrix.md)
- [Environment variables](../reference/environment-variables.md) (token lifetimes, rate limits, OAuth settings)
- [Production security](../../SECURITY.md)
- [Troubleshooting](../guides/troubleshooting.md)
