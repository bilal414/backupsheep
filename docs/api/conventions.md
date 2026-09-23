# API conventions and safety

## Resource patterns

Most API resources are Django REST Framework viewsets:

| Operation | Method and path |
|---|---|
| List | `GET /api/v1/{resource}/` |
| Create | `POST /api/v1/{resource}/` |
| Retrieve | `GET /api/v1/{resource}/{id}/` |
| Replace | `PUT /api/v1/{resource}/{id}/` |
| Update selected fields | `PATCH /api/v1/{resource}/{id}/` |
| Delete | `DELETE /api/v1/{resource}/{id}/` |

Not every resource permits every operation. Aggregated resources such as
`/storage/all/` and `/logs/` are read-only, while action URLs add operations such as
`pause`, `validate`, `trigger`, `restore`, and `retry`.

Provider-specific create and update bodies are not interchangeable. Use the matching
request in the Bruno collection as the starting body and remove any optional field you
do not intend to change.

## IDs and discovery

Most URL IDs are database integers. Provider object IDs, backup UUIDs, execution
correlation IDs, task IDs, and restore IDs may also appear inside responses.

Do not guess an ID or copy it between installations. List the relevant account-scoped
collection first, then reuse the returned `id` in detail/action requests.

## Current-account and node visibility

Authentication is only the first access boundary. Querysets also enforce current
account membership and, for delegated users, visible-node scope. Write actions apply
group permissions such as integration, node, storage, schedule, backup, restore, team,
or notification management.

An empty list can mean the account has no objects or that the member has no visible
objects. A `403` generally means the identity is known but lacks an action permission.
A detail route may behave as not found when the object is outside the scoped queryset.

## Filtering and search

Many list endpoints accept:

- `search=<text>` for the fields configured by that resource;
- `dateFrom=DD-Mon-YYYY` and `dateTo=DD-Mon-YYYY` on list views using the shared date
  range filter;
- provider-specific filters such as `node=<id>`, status, type, integration, or region;
- DataTables parameters used by the console.

There is no single global filter schema. Unknown filters may be ignored. Start with the
query examples in Bruno and confirm a provider's filter class before depending on a
query parameter in long-lived automation.

## Background operations

BackupSheep performs backups, restores, provider snapshots, uploads, replication, and
deferred deletion through Celery. An accepted response means the request was recorded
or queued; it does not mean the provider operation is complete.

Monitor durable state through the relevant resource:

- `GET /api/v1/nodes/{id}/backup_request_status/` for an on-demand backup request;
- `GET /api/v1/backups/{provider}/{backup_id}/` for a backup row;
- `GET /api/v1/nodes/{id}/restores/` or a backup family's `restores` action for restore
  history;
- replication `runs` and `restores` actions for Lightsail bucket replication.

Backup serializers expose `execution_status` when a durable execution record exists.
Useful fields include the correlation ID, phase, public status, attempt count,
progress, reconciliation state, next retry time, last safe error code, and verified
artifact summary. Internal worker leases, raw provider payloads, and secret-bearing
metadata are deliberately omitted.

## Idempotency

Use a unique `Idempotency-Key` header for job-creating requests. Keep the same key when
retrying the same logical request after a timeout; use a new key when the body or target
changes.

It is required or materially used by the durable paths for on-demand snapshots and
managed restore/replication operations. Relevant requests in Bruno include the
`{{idempotencyKey}}` variable.

```http
Idempotency-Key: backup-node-42-2026-08-12T180000Z
```

Reusing a key with a different restore body can return a conflict. A client timeout
does not prove the request failed—query the corresponding status endpoint before
submitting a different key.

## Destructive and provider-mutating actions

The collection contains real mutating requests. Depending on the target, they can:

- create or delete BackupSheep configuration;
- create/delete snapshots or restored provider resources;
- import a database dump or mirror files onto a server;
- delete backup archives from one or more destinations;
- change lifecycle rules, membership, group permissions, or the current account;
- pause schedules, sources, storage, or connections.

Set all IDs explicitly, inspect the selected environment, and run one request at a time
against a test account before using production. Do not use Bruno's folder or collection
runner against a production environment.

## Restore safety

Restore bodies vary by source and provider. Some modes create a new provider resource;
database and website restores can target connected infrastructure, and exact-mirror
website restore can delete remote paths not present in the archive.

Before calling a restore endpoint:

1. Verify the backup is complete and its storage point is available.
2. Read the provider/source-specific restore guide.
3. Use a fresh idempotency key.
4. Prefer a new or isolated target for the first test.
5. Poll the restore row to a terminal state and independently verify the restored
   resource or data.

## Responses and errors

Success responses commonly use `200`, `201`, `202`, or `204`. Common failures include:

| Status | Typical meaning |
|---|---|
| `400` | Invalid body, invalid state transition, validation failure, or missing idempotency input. |
| `401` | Missing/invalid authentication. |
| `403` | CSRF or group/account permission failure. |
| `404` | Route or scoped object not found. |
| `409` | Object is still attached, duplicate/conflicting operation, or reused idempotency key with different input. |
| `429` | Authentication or provider-related rate limiting. |
| `5xx` | Application, broker, worker, or upstream failure; inspect durable state before retrying a mutation. |

Error bodies are not fully uniform because the API contains both newer durable
operations and legacy viewsets. Clients should tolerate `detail`, field-error objects,
and safe `code`/`message` fields rather than parsing one global envelope.

## OAuth callbacks

Routes under `/api/v1/callback/` complete interactive OAuth or provider authorization
flows. They depend on browser session state and query parameters from the provider.
They are included in Bruno for route completeness, but they are not a substitute for
starting the corresponding OAuth flow in the console.

Never paste a real OAuth authorization code into a committed environment.
