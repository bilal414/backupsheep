# BackupSheep REST API

BackupSheep exposes the same account-scoped resources used by its web console under
`/api/v1/`. The API can manage integrations, sources, storage destinations,
schedules, backups, restores, notifications, and team access.

The API is part of the self-hosted application. Replace `https://backup.example.com`
in every example with the URL of your own BackupSheep instance.

## Start here

1. Read [Authentication](authentication.md) and obtain a token from
   `POST /api/v1/auth/login/`.
2. Read [Conventions and safety](conventions.md), especially the notes about
   account scope, background operations, idempotency, and destructive requests.
3. Follow [Common workflows](workflows.md) for a practical sequence from connection
   setup through backup and restore.
4. Use the [Endpoint reference](reference.md) to find a resource family.
5. Import the repository's [Bruno collection](../../bruno/README.md) for runnable
   requests, variables, sample bodies, and complete route coverage.

## Base URL

```text
https://backup.example.com/api/v1
```

Most resource URLs end in `/`. Keep the trailing slash in API clients so a proxy or
Django redirect never has to replay a request body.

## Minimal example

Log in with the email and password of an existing BackupSheep member:

```bash
curl --request POST \
  --url https://backup.example.com/api/v1/auth/login/ \
  --header 'Content-Type: application/json' \
  --data '{"email":"operator@example.com","password":"replace-me"}'
```

The response includes `api_key`. Send it with the DRF token scheme—not `Bearer`:

```bash
curl --url https://backup.example.com/api/v1/nodes/ \
  --header 'Accept: application/json' \
  --header 'Authorization: Token YOUR_API_KEY'
```

## API scope

The API is account-aware and permission-aware:

- Lists and object lookups are scoped to the signed-in member's current account and,
  where applicable, the nodes visible through that member's groups.
- The primary account member has full account access. Other members need the relevant
  group permission for write and operational actions.
- A valid object ID from another account is not authorization. Always discover IDs
  through a list endpoint available to the same token.
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
- List endpoints are not globally paginated. Some console requests use DataTables
  query parameters and may receive its table-shaped response.
- Datetimes are serialized by Django REST Framework. Human-readable `*_display`
  fields are convenience values, not stable machine timestamps.

## Versioning and compatibility

The current public namespace is `v1`. BackupSheep does not currently publish an
OpenAPI document, so treat this documentation, the checked-in Bruno collection, and
the route coverage validator as the repository contract. Review API changes when
upgrading a self-hosted instance.

## Security reminders

- Use HTTPS before sending credentials or tokens over a network.
- Never commit a real API key, provider credential, session cookie, OAuth code, or
  signed download URL.
- Use a dedicated member with the smallest practical group permissions for
  automation.
- Keep production tokens outside Bruno's committed environment template.
- `GET` is not universally side-effect-free in this legacy API. For example, logout,
  invite acceptance, validation, OAuth callbacks, and some provider discovery actions
  can change session or provider-linked state. Read the request documentation before
  running a folder as a batch.

## Related documentation

- [Feature guides](../features/README.md)
- [Provider and destination reference](../reference/provider-matrix.md)
- [Production security](../../SECURITY.md)
- [Troubleshooting](../guides/troubleshooting.md)
