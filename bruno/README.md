# BackupSheep Bruno collection

This collection is generated from the Django URL resolver on the `develop` branch.
It contains one Bruno request for every supported HTTP method on every active
`/api/v1/` route, plus `/healthz/`. The generated `route-manifest.json` is the
auditable mapping between Django route, HTTP method, view/action, safety class, and
the corresponding `.bru` file. At generation time that is 920 API operations plus
one health operation across 528 distinct paths.

## Start here

1. Open this `bruno/` directory in Bruno.
2. Select `Local` or copy `Self Hosted` to a private environment ignored by Git.
3. Set `baseUrl`, `email`, and `password` locally.
4. Run `01 Authentication/Login`. Its post-response script stores `apiToken` only
   in Bruno's in-memory runtime variables.
5. Run individual read requests. Protected requests send exactly
   `Authorization: Token <key>`; BackupSheep does not use Bearer tokens.

Committed values are inert examples. Never put a real API token, password, OAuth
code, cloud credential, private key, or SSH approval token in a tracked file.

## Mutation safety

All writes and stateful GET operations have a pre-request guard. They fail locally
unless `allowMutations` is explicitly set to `true`. Stateful GET operations include
OAuth callbacks, validation probes, invite acceptance, logout, and the legacy
database-type refresh action. Some provider validation calls perform live remote
reads or a write/read/delete probe, so treat them as mutations for operational
safety.

Do not run the entire collection against an installation. Select the exact request,
confirm all IDs and provider details, then enable mutations only for that run.
Restore requests can create billable provider resources; their examples include
confirmation and idempotency fields but remain blocked by default.

## Request bodies

Standard create and update bodies are derived from each DRF write serializer's
writable required fields. Provider credentials are represented by generic placeholder
variables and are never read from the repository's `.env`. Custom operations have
hand-authored examples for backup requests, restores, membership changes, replication,
password reset, and SSH host-key approval. Optional provider-specific fields may still
need to be added for the resource selected on your installation.

## Surface boundaries

Included:

- all active `/api/v1/**` methods exposed by Django and DRF routers;
- token/session authentication endpoints and login probe;
- OAuth callback endpoints, marked as browser callbacks and stateful;
- local-storage download, reporting, utility, and health endpoints.

Excluded intentionally:

- `/django-admin/**`: Django's HTML administrator;
- `/api-auth/**`: DRF's development-only browser login/logout UI;
- `/login/`, `/logout/`, `/reset/**`, `/onboarding/**`, `/console/**`, and
  `/invite/**`: HTML console workflows rather than machine APIs;
- static/media serving patterns;
- `apps.api.v1.incoming.urls`, because it currently declares no URL patterns.

There is no active generic inbound-webhook route in the current URL graph. OAuth
callbacks are kept because they are callable integration endpoints, but they normally
complete a signed-in browser flow and redirect to the console.

## Verify or regenerate

From the repository root, with project dependencies installed:

```sh
.venv/bin/python bruno/scripts/validate_collection.py
.venv/bin/python bruno/scripts/generate_collection.py
```

Validation fails on a missing, stale, duplicate, or extra operation and checks that
the referenced Bruno request has the correct method, URL, authentication prefix, and
mutation guard. Generation only replaces `bruno/requests/` when its generated marker
is present.
