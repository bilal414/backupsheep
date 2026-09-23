# GitHub documentation and Bruno API collection handoff

**Work date:** 2026-08-12

**Repository publication date:** 2026-08-23

**Repository:** `bilal414/backupsheep`

**Branch:** `develop`

**Inspected code baseline:** `5a5542e061ef72fb0b76a12acff4dcb2d312808e`

**Release parent:** `8dba19be0a4a87650a86c00202006858913e6c72`

**Documentation release commit:** `21e5da1edd9d9a31a49df3d4393b6d49b81fcf34`

**Final record commit:** the commit containing this file; resolve it with the command in
the resume section after pulling `develop`

This record is the resume point for the complete GitHub documentation and Bruno API
collection work. It distinguishes repository completeness, demo deployment evidence,
and work that remains installation- or provider-specific.

## Objective

The requested outcome was to inspect the current `develop` branch, replace the scattered
top-level user guidance with a detailed GitHub documentation system, and supply a Bruno
collection for all active BackupSheep APIs. The follow-up release request added a commit,
push, deployment to the existing demo installation, and an evidence-backed resume record.
The user then explicitly canceled the demo deployment. The repository release continues;
no remote deployment is part of this handoff.

## Delivered documentation

### GitHub entry points

- `README.md` now points to the canonical documentation by user journey instead of a
  flat list of older files.
- `docs/README.md` is the main documentation hub and explicitly separates current
  product/operator guidance from dated engineering E2E reports and handoffs.
- `docs/releases/README.md` indexes dated deployment/resume evidence.

### Feature documentation

Ten guides under `docs/features/` describe the implemented product surface:

1. feature overview;
2. core account/connection/node/storage/schedule/backup/restore concepts;
3. dashboard and console workflows;
4. website, database, cloud, volume, WordPress, and Basecamp sources;
5. all 26 storage destinations and multi-copy behavior;
6. schedule timing, retention, air-gapped-copy policy, and on-demand runs;
7. durable execution state, retries, reconciliation, history, logs, and downloads;
8. website/database/native-cloud/replication restore behavior and safety;
9. email, Slack, and Telegram notifications;
10. teams, accounts, invites, groups, node visibility, permissions, MFA, and API access.

Each guide links to the implementation files that support its claims. Important product
boundaries are explicit: catalog support is not universal live certification; seeded
Zendesk and Slack backup sources are not wired; one-time schedule creation is not in the
current console editor; WordPress/Basecamp do not expose automatic restore; and provider
restore behavior varies.

### API documentation

Five guides under `docs/api/` cover:

- API base URL, formats, version boundary, and security;
- persistent DRF token authentication and CSRF-protected browser sessions;
- CRUD patterns, current-account/node scope, filtering, asynchronous execution,
  idempotency, error handling, and mutation/restore safety;
- end-to-end connection, source, storage, schedule, backup, download, restore,
  notification, and team workflows;
- a human-readable map of every API family and custom action.

The documentation calls out the exact authentication prefix:
`Authorization: Token <key>`, not `Bearer`.

### Operator and reference documentation

The canonical runbooks under `docs/guides/` cover installation, configuration, secure
first-run onboarding, production/TLS hardening, routine operations, upgrades/rollback,
disaster recovery, observability, and troubleshooting.

The reference set under `docs/reference/` covers the service/queue/persistence
architecture, environment variables, and provider/source/destination matrix.

Older focused platform/provider guides remain linked for their narrow subjects. Dated
test reports remain preserved but are labeled as run-specific evidence rather than
current user instructions.

### Security documentation correction

`SECURITY.md` previously said browser-session REST CSRF enforcement was disabled. Current
code uses standard DRF session authentication and the console attaches `X-CSRFToken` to
unsafe requests. The policy now matches the running implementation and separately
describes token authentication.

## Bruno collection

The top-level `bruno/` directory is directly importable into Bruno and includes:

- collection metadata and safe shared headers;
- `Local` and `Self Hosted` environments containing placeholders only;
- login post-response handling that keeps the API token in Bruno runtime memory;
- an explicit `Authorization: Token {{apiToken}}` header on protected operations;
- a default `allowMutations=false` guard on writes and legacy/stateful GET actions;
- placeholder request bodies derived from DRF serializers plus hand-authored bodies for
  login/reset, backup, restore, replication, membership, MFA, and SSH host-key actions;
- idempotency variables and headers on durable mutation paths;
- request-level smoke assertions;
- `route-manifest.json`, mapping method/path to view, action, source, auth, safety class,
  and request file;
- resolver inventory, deterministic generator, and drift validator scripts.

### Coverage boundary

The Django resolver exposes:

| Surface | Count |
|---|---:|
| `/api/v1/**` method/path operations | 916 |
| `/healthz/` operations | 1 |
| Total Bruno request files | 917 |
| Unique paths | 524 |

Intentional exclusions are HTML console/onboarding/invite routes, Django administration,
the DRF development browser login UI, and static/media patterns. The included incoming
URL module currently has no active routes. OAuth callbacks are included and classified
as stateful browser-flow endpoints.

The collection is broad by design. Do not run all requests against a real installation:
some calls create backups, restores, provider resources, lifecycle policies, membership
changes, or deletions. Review one request, all IDs, and the selected environment before
temporarily enabling mutations.

## Repository validation

The release validation performed for this work is recorded below. These checks verify
documentation/collection consistency; they are not a live provider recovery
certification.

| Check | Result |
|---|---|
| Django system check with non-production validation settings | `System check identified no issues (0 silenced)` |
| Bruno resolver drift validator | `916 API operations + 1 health operation across 524 paths; 917 request files` |
| Bruno CLI parser/execution against a local non-mutating stub | `917/917` request tests passed |
| Markdown local-link validation | Passed for 90 release Markdown files |
| `git diff --check` for release scope | Passed |
| Placeholder/secret-pattern review | Passed; no live credential or private-key pattern found in the release material |

No real provider credential, API token, OAuth code, password, SSH key, or signed URL is
stored in the collection. The final staged release scan found no live-key or private-key
pattern in the added material. Private Bruno environment filename patterns and Python
caches are ignored.

## Demo deployment record

**Status: explicitly skipped at the user's direction.** The following facts came from a
read-only preflight before the cancellation. They are a point-in-time safety record, not
evidence that the documentation release is running on the demo.

### Target and preflight

| Item | Evidence |
|---|---|
| Public URL | `https://demo.backupsheep.com` |
| Server checkout | `/opt/backupsheep` on `develop` |
| Revision observed during preflight | `5a5542e061ef72fb0b76a12acff4dcb2d312808e` |
| Public health during preflight | HTTP 200 from `/healthz/` |
| Tracked remote changes during preflight | None |
| Active durable backup/restore work | Zero at that preflight |
| Celery active/reserved/scheduled work | Zero at that preflight |
| RabbitMQ ready/unacknowledged messages | Zero at that preflight |

The observed checkout also had a root-only `.env`, root-only
`docker-compose.override.yml`, and an untracked acceptance proxy file. Any future
deployment must rediscover and preserve those files byte-for-byte, preserve the named
PostgreSQL, RabbitMQ, work, and archive volumes and all provider/account data, and create
a verified PostgreSQL dump plus protected configuration copies outside the checkout
before updating it. Because this was only a preflight, those recovery artifacts were not
created during this release task.

### Deployment outcome

No deployment commands were run after the cancellation. In particular, this release did
not fetch or merge the new revision on the server, stop Beat, build or recreate Compose
services, run a new migration, alter protected files, or remove/recreate volumes. The
demo therefore remained on the revision observed above when the preflight ended. Recheck
that live fact before any later deployment; do not rely on this dated snapshot.

## What remains

### Collection maintenance

- Run `bruno/scripts/validate_collection.py` whenever URLs, methods, or actions change.
- Regenerate after intentional route changes and review the manifest diff; do not accept
  a large generated diff without checking auth, safety classification, and custom bodies.
- Provider serializers expose many optional, plan-specific fields. The generated bodies
  cover required serializer fields and common actions, but users may need to add optional
  fields for their exact provider resource.
- OAuth callback requests document route coverage; normal users should start OAuth from
  the console rather than replaying codes manually.
- Consider adding a CI job for the route drift validator and Markdown link checker.

### Documentation maintenance

- Update the feature and provider matrix in the same change whenever source,
  destination, restore, or permission behavior changes.
- Keep dated provider/E2E reports as evidence, but route normal users to `docs/README.md`.
- Revalidate provider APIs and live behavior before describing a provider as certified
  for a new region, plan, engine, or credential model.
- Capture screenshots or a docs site only if a future publication workflow will keep
  them synchronized; the current GitHub Markdown is intentionally source-linked and
  low-maintenance.

### Product and operational follow-up outside this documentation release

- Live provider credentials and recovery results remain installation-specific. A green
  doc build, Django check, or demo health endpoint does not establish recoverability.
- Complete disposable backup and restore rehearsals for any provider relied on in
  production and retain data-level verification evidence.
- Previously recorded reliability acceptance gates—fresh final-code Hetzner crash
  validation, final-code AWS Backup lost-response tests, retained-resource cleanup/drift
  audit, and credential rotation—remain separate from this documentation release unless
  a later dated report proves them complete.
- Legacy management endpoints do not all use one uniform owner/group permission gate;
  keep the documented least-privilege and tenant-scope caveat until those endpoints are
  normalized and regression-tested.

## Resume commands

From the repository root:

```bash
git status --short --branch
git log -3 --oneline --decorate
git log -1 --format='%H %s' -- docs/releases/2026-08-12-documentation-and-bruno-handoff.md
DJANGO_SERVER=dev DJANGO_SECRET_KEY=release-validation-only \
  .venv/bin/python manage.py check
.venv/bin/python bruno/scripts/validate_collection.py
```

Open the collection by selecting the repository's `bruno/` directory. Copy the Self
Hosted environment to an ignored private environment, set the instance URL/email/password
locally, run the login request, and then run only the reviewed operation needed.
