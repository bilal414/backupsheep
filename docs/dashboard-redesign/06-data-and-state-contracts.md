# Data and state contracts

## Purpose

The interface can only be as trustworthy as its read models and state vocabulary. This
document defines the proposed contract between durable BackupSheep evidence and the new
console. It is a design contract, not an implemented endpoint or schema.

No agent may build the Recovery dashboard by joining unrelated endpoints in browser
JavaScript, counting a limited result list, interpreting free-form error strings, or
aggregating before permission scope is applied.

## Authority order

When sources disagree, use this order:

1. durable request/execution/artifact/recovery records;
2. persisted provider reconciliation evidence;
3. configured policy/objective and validation evidence;
4. a versioned server-side read model derived from those records;
5. UI presenter state.

Celery task state, transient worker memory, animation, toast response, and provider-name
heuristics are not product truth.

## Canonical scope

### Requirement

Define one server-side visibility function/contract for Workloads and use it before:

- dashboard aggregation;
- Workloads list and detail;
- Operations list and detail;
- findings;
- Activity;
- policies;
- connections/destinations and affected-object counts;
- exports;
- polling or push subscriptions;
- search/filter option counts.

The existing dashboard/API/log paths already use variants of a `visible_nodes`
contract, while the current server-rendered node list/detail appear to scope directly to
the current account. Slice 0 must prove and correct parity before adding links or
aggregates.

### Scope descriptor

Every top-level read contract returns a safe scope descriptor:

~~~json
{
  "scope": {
    "workspace_ref": "ws_opaque",
    "label": "Acme backups",
    "mode": "full",
    "visible_workload_count": 42,
    "can_reveal_total_count": true
  }
}
~~~

`mode` is `full` or `restricted`. When total account size is not authorized, do not
return or imply it. A restricted empty result says zero visible/assigned workloads, not
zero account workloads.

### Invariants

- Detail authorization and aggregate inclusion are derived from the same scoped
  queryset/service.
- An opaque record reference that is outside scope returns the project's established
  non-disclosing response; do not reveal existence through different timing/copy.
- Authorization is re-evaluated on every request and live subscription update.
- Cache keys include principal/workspace/scope version or another proven non-leaking
  discriminator.
- Pagination totals and filter facets are scoped.

## Proposed overview read model

### Endpoint

Recommended new read endpoint:

    GET /api/v1/recovery/overview/

The exact route can change during API review. The important decisions are:

- one versioned envelope;
- computed server-side;
- canonical scope first;
- deterministic rules;
- bounded items with exact totals;
- no provider secrets or raw log payloads;
- compatible with server rendering or progressive enhancement.

### Envelope

~~~json
{
  "schema_version": "bs.recovery-overview.v1",
  "generated_at": "2026-08-12T15:42:18Z",
  "scope": {
    "workspace_ref": "ws_opaque",
    "label": "Acme backups",
    "mode": "full",
    "visible_workload_count": 42,
    "can_reveal_total_count": true
  },
  "freshness": {
    "state": "fresh",
    "source_watermark": "2026-08-12T15:42:16Z",
    "last_successful_generated_at": "2026-08-12T15:42:18Z",
    "stale_after_seconds": 60
  },
  "capabilities": {
    "recovery_readiness": false,
    "recovery_proof": false,
    "live_operations": true,
    "destination_evidence": true,
    "cost_visibility": true
  },
  "posture": {
    "state": "unavailable",
    "reason": "objectives_not_implemented",
    "bands": []
  },
  "observed_evidence": {
    "latest_completed_point": {"known": 35, "unknown": 7},
    "source_artifact_verified": {"known": 31, "unknown": 11},
    "destination_copies_verified": {"known": 19, "unknown": 23},
    "restore_record_available": {"known": 4, "unknown": 38}
  },
  "findings": {
    "total": 7,
    "critical": 2,
    "items": []
  },
  "operations": {
    "live_total": 2,
    "manual_review_total": 1,
    "items": []
  },
  "coverage": {
    "total": 42,
    "items": [],
    "next_cursor": null
  },
  "upcoming": [],
  "destinations": [],
  "setup": null
}
~~~

This example is structural, not a fixture. The capability flag and `posture.state`
prevent a client from presenting current observed backup facts as implemented recovery
readiness.

### Count contract

Each collection distinguishes:

- exact `total`;
- bounded preview `items`;
- optional `next_cursor`;
- whether the total is authorized and available.

Never derive a headline from `items.length`. The current Overview's capped exception
preview is the failure mode this contract must eliminate.

## State axes

Do not collapse these into one status.

### 1. Connection/configuration state

Proposed normalized values:

| Code | Label | Meaning |
| --- | --- | --- |
| `active` | Connection active | Saved configuration is enabled; not a backup claim. |
| `paused` | Connection paused | Discovery/provider access is intentionally paused. |
| `validation_required` | Validation required | Credentials/configuration need a current validation. |
| `validation_failed` | Validation failed | The defined validation contract failed. |
| `delete_requested` | Removal pending | Removal request exists; downstream impact applies. |
| `unavailable` | State unavailable | State could not be determined. |

### 2. Protection state

| Code | Label | Meaning |
| --- | --- | --- |
| `unconfigured` | Not configured | No effective schedule/manual protection intent. |
| `scheduled` | Scheduled | An enabled effective schedule exists. |
| `manual_only` | Manual only | Workload can run on demand but has no active schedule. |
| `paused` | Protection paused | Future scheduled work is intentionally paused. |
| `overdue` | Schedule overdue | A run required by policy is late under a defined rule. |
| `unavailable` | State unavailable | Effective configuration could not be determined. |

### 3. Operation state

| Code | Terminal | Meaning |
| --- | --- | --- |
| `pending_dispatch` | No | Durable request exists; dispatch has not been confirmed. |
| `dispatched` | No | Delivery to execution infrastructure is recorded. |
| `running` | No | A worker owns the current fenced attempt. |
| `retrying` | No | A retry is durably scheduled or active. |
| `reconciling` | No | Provider outcome is being resolved safely. |
| `manual_review` | No | Automation cannot safely decide; conflicting mutation is frozen. |
| `complete` | Yes | The operation's own completion contract passed. |
| `partial` | Yes | Some required operation outputs failed or remain incomplete. |
| `failed` | Yes | The operation reached its terminal failure contract. |
| `cancelled` | Yes | Cancellation is durably confirmed under the backend contract. |

Operation type is separate: backup, snapshot, logical export, copy, verification,
restore, rehearsal, cleanup, or reconciliation.

### 4. Copy/evidence state

| Code | Meaning |
| --- | --- |
| `pending` | Expected evidence is not terminal. |
| `verifying` | Verification is in progress. |
| `verified` | The defined artifact/copy verification contract passed. |
| `failed` | The defined copy/verification contract failed. |
| `expired` | Evidence/copy is no longer eligible under retention. |
| `unavailable` | Evidence cannot be determined. |

Provider-native point availability and off-site destination-copy verification are
different evidence facts.

### 5. Recovery posture

Only enabled after objectives and required evidence contracts exist.

| Code | Label | Minimum meaning |
| --- | --- | --- |
| `verified_ready` | Verified recovery ready | Current objective-compliant point/copies/isolation and non-expired recovery proof all pass. |
| `protected_not_rehearsed` | Protected, not restore-tested | Current point/copy requirements pass, but required recovery proof is absent/expired. |
| `at_risk` | At risk | At least one configured critical recovery objective is currently violated. |
| `unknown` | Unknown | Required configuration or evidence is absent, stale beyond rule, unauthorized, or unavailable. |

No numeric “confidence score” is part of the contract.

### 6. Freshness

| Code | Meaning |
| --- | --- |
| `fresh` | Generated within the contract's freshness window from available sources. |
| `stale` | Last-known result is shown beyond the window or after refresh failure. |
| `unavailable` | No safe usable result exists. |

Freshness applies to the view and may also apply to individual evidence fields.

## Central state presenter

Templates and browser code receive a presenter object:

~~~json
{
  "axis": "operation",
  "code": "reconciling",
  "label": "Reconciling provider outcome",
  "tone": "attention",
  "icon": "reconcile",
  "description": "The provider may have completed the operation.",
  "action_policy": "review_only"
}
~~~

Requirements:

- exhaustive server-side mapping for known model states;
- explicit unknown fallback;
- one mapping reused across list, detail, dashboard, toasts, and exports;
- no template substring checks;
- no direct color decision based on raw provider/model text;
- snapshot/unit tests for every enumerated state;
- presenter text does not contain secret or provider-response payloads.

## Operation summary

The current durable execution serialization already exposes much of the required
material. Normalize it into a safe summary:

~~~json
{
  "operation_ref": "op_opaque",
  "correlation_ref": "CORR-SAFE",
  "workload": {
    "ref": "wl_opaque",
    "label": "prod-postgres",
    "type": "database"
  },
  "operation_type": "backup",
  "state": {"axis": "operation", "code": "running", "label": "Running"},
  "phase": {
    "code": "destination_upload",
    "label": "Uploading destination copy"
  },
  "progress": {
    "mode": "determinate",
    "completed": 68,
    "total": 100,
    "unit": "percent"
  },
  "attempt": {"current": 2, "maximum": 5},
  "retry_at": null,
  "requested_at": "2026-08-12T15:30:00Z",
  "started_at": "2026-08-12T15:30:08Z",
  "updated_at": "2026-08-12T15:42:10Z",
  "trigger": {"type": "schedule", "label": "Nightly policy"},
  "safe_error": null,
  "reconciliation": null,
  "links": {"detail": "/console/operations/op_opaque/"}
}
~~~

If total progress is unknown, use:

~~~json
{
  "progress": {
    "mode": "phase_only",
    "completed": null,
    "total": null,
    "unit": null
  }
}
~~~

Never estimate a percentage from elapsed time.

## Findings contract

### Purpose

A Finding is a current deterministic condition, not a copy of a failed log row.

### Proposed shape

~~~json
{
  "finding_ref": "f_opaque",
  "fingerprint": "safe-stable-hash",
  "rule_code": "provider_outcome_unknown",
  "lifecycle": "open",
  "severity": "critical",
  "headline": "Provider outcome requires review",
  "summary": "Starting another snapshot could create a duplicate.",
  "affected_objects": [
    {"type": "workload", "ref": "wl_opaque", "label": "billing-volume"}
  ],
  "first_observed_at": "2026-08-12T15:30:00Z",
  "last_observed_at": "2026-08-12T15:42:10Z",
  "resolved_at": null,
  "evidence_refs": ["ev_opaque"],
  "recommended_action": {
    "code": "review_evidence",
    "label": "Review evidence",
    "href": "/console/operations/op_opaque/"
  }
}
~~~

### Lifecycle

    absent -> open -> resolved
                  \-> superseded, only when the rule contract requires it

Rules:

- fingerprint is stable for the same condition and scoped object;
- repeated observations update `last_observed_at`;
- exact count is number of current authorized open findings;
- resolution requires deterministic evidence;
- history retains opened/updated/resolved events;
- a preview has a separate exact total;
- acknowledgement/dismissal are not aliases for resolution.

### Initial deterministic finding candidates

Only implement after exact rules and test fixtures exist:

- provider outcome unknown / mutation freeze;
- operation manual review;
- configured schedule overdue;
- current required point missing/stale against objective;
- required verified copy missing;
- required recovery proof missing/expired;
- destination validation failure affecting an effective policy;
- connection validation failure affecting protection.

Historical individual backup failures are not automatically current findings when later
evidence resolves the condition.

## Evidence contract

Evidence references are typed, timestamped, immutable or append-only where required, and
safe to expose:

| Type | Proves |
| --- | --- |
| Request evidence | User/system intent was durably accepted. |
| Provider-operation evidence | Provider resource/outcome correlation. |
| Artifact evidence | Source artifact exists and passed defined validation. |
| Copy evidence | Specific destination copy passed defined verification. |
| Restore evidence | Restore operation reached its completion contract. |
| Assertion evidence | Workload-specific post-restore assertion result. |
| Cleanup evidence | Rehearsal target cleanup or retained exception. |
| Recovery proof | Required assertion set and cleanup policy passed within freshness. |

Every evidence item includes:

- opaque reference;
- type and schema version;
- subject references;
- observed/recorded timestamps;
- result and rule version;
- safe summary;
- retention/expiry when applicable;
- provenance without raw secret/provider payload;
- links authorized for the current principal.

## Deterministic readiness rule

The complete rule is implemented server-side and versioned. Conceptually:

    verified_ready =
      objectives_configured
      AND current_recovery_point_within_rpo
      AND required_copies_verified
      AND required_isolation_evidence_satisfied
      AND non_expired_recovery_proof_passed
      AND no_rule_defined_blocking_condition

Precedence:

1. If required configuration/evidence cannot be evaluated, `unknown`.
2. Else if a critical configured requirement is violated, `at_risk`.
3. Else if point/copy requirements pass but required proof does not,
   `protected_not_rehearsed`.
4. Else if all rule requirements pass, `verified_ready`.

The endpoint returns rule version, evaluated-at time, and per-stage evidence links.
Client code must not reproduce the algorithm.

## Transitional current-data mapping

Slice 2 can ship before readiness models using these honest facts:

| UI fact | Current source direction | Required caveat |
| --- | --- | --- |
| Visible workload count | Canonical scoped Workload/Node queryset | Include every supported workload family exactly once. |
| Latest completed point | Latest applicable completed backup/snapshot execution | Completed does not imply verified restore. |
| Source artifact verified | Durable artifact/source verification evidence where present | Unknown if the provider path has no equivalent evidence. |
| Destination copies verified | Durable copy/artifact records | Provider-native snapshots are not off-site copies. |
| Restore record available | Applicable completed restore record | Not Recovery proof. |
| Live operation | Non-terminal durable execution/request state | Never Celery-only. |
| Current exception preview | Exact deterministic query or temporarily label Recent failures | Do not call capped history Open findings. |
| Next scheduled | Effective enabled schedule in member timezone | Show unconfigured/overdue explicitly. |

If current models cannot support a fact consistently across providers, the value is
`unknown` and the capability/coverage response explains why.

## Privacy and redaction

Never expose through overview, HTML attributes, telemetry, client errors, or exported
fixtures:

- credentials, secrets, tokens, session IDs, signed URLs, or private keys;
- raw provider request/response bodies;
- internal hostnames/endpoints outside authorized detail;
- filenames/object keys that contain customer-sensitive data;
- raw environment variables;
- Celery task IDs as customer correlation;
- hidden workload names/counts or cross-workspace identifiers;
- stack traces or unreviewed exception text.

Safe error object:

~~~json
{
  "code": "destination_write_failed",
  "message": "The destination did not accept the copy.",
  "detail_available": true,
  "retry_safety": "review_required"
}
~~~

## Errors and degraded responses

Top-level failures use the established API error envelope plus a request reference.
Partial success is explicit:

~~~json
{
  "freshness": {
    "state": "stale",
    "last_successful_generated_at": "2026-08-12T15:40:00Z"
  },
  "partial": {
    "is_partial": true,
    "unavailable_sections": ["destination_costs"],
    "safe_message": "Cost data could not be refreshed."
  }
}
~~~

Rules:

- retain last-known values where safe;
- label the timestamp;
- never substitute zero;
- do not fail Recovery because an optional cost module failed;
- return section capability/availability so the template does not infer it;
- log internal detail under a safe request/correlation reference.

## Performance budget

Create a deterministic fixture representing at least:

- 1,000 visible workloads across supported families;
- active and historical operations;
- multiple destinations and policies;
- restricted group memberships;
- findings/evidence with long histories.

Initial targets:

- Recovery overview p95 server response below 2 seconds in the agreed test environment;
- bounded query count documented and enforced with regression tests;
- no per-row provider/network calls;
- first response returns only the coverage rows needed for the screen;
- deep lists use server pagination/cursors;
- live-operation updates visible within 10 seconds under normal demo conditions;
- browser main-thread work does not rebuild a thousand-row table on each poll.

The team must record fixture size, database engine, machine/container allocation, cold vs
warm cache, query count, and measurement method with any performance claim.

## Cache and refresh

- Cache only the scoped read result or safe sub-aggregates with explicit scope keys.
- Persist or retain the last successful generation timestamp.
- Invalidate/refresh after relevant durable state changes; polling remains a fallback.
- Conditional requests/ETags are encouraged for unchanged data.
- Live rows and aggregate summaries must converge without displaying a mix of
  incompatible schema versions.
- A deploy/version change can invalidate the cache safely.
- Never cache permission checks only in browser state.

## Mutation contracts

The redesign does not introduce new provider mutation semantics. Any new UI action must
call an existing or separately reviewed endpoint that provides:

- authorization;
- validation;
- confirmation/impact contract;
- durable request creation;
- idempotency/deduplication key;
- provider mutation fencing;
- safe lost-response reconciliation;
- audit evidence;
- a queryable operation reference.

An attractive button is not authorization to bypass these contracts.

## Versioning and compatibility

- Include `schema_version` in new aggregate/read envelopes.
- Add fields compatibly within a version; do not silently change state meaning.
- Unknown enum values render via the explicit fallback and generate observability.
- Template/client behavior tests use the same contract fixtures.
- Keep existing endpoint behavior until all known consumers and callbacks are migrated.
- Route aliases do not authorize broader scope.
- Remove compatibility paths only after telemetry/tests show no required consumer.

## Required test suite

### Scope

- owner/full workspace;
- restricted member with one group;
- member in multiple groups;
- no-group/no-assignment member;
- hidden workload direct reference;
- cross-workspace reference;
- membership change during polling;
- exact aggregate/list/detail parity.

### States

- every normalized connection, protection, operation, copy, posture, and freshness value;
- unknown future enum;
- later success resolving a finding;
- repeat failure updating one finding;
- capped preview with exact total greater than preview;
- partial provider coverage;
- stale and unavailable data.

### Reliability

- request accepted before dispatch;
- duplicate submit;
- worker crash/restart;
- broker delay;
- lost provider response;
- reconciliation;
- manual review/freeze;
- terminal partial;
- safe retry/resume;
- restore assertions and cleanup.

### Privacy

- response snapshots contain no credentials/secrets/raw payloads;
- restricted aggregates leak no hidden counts;
- safe errors contain approved fields only;
- cached response cannot cross principal/workspace scope.

### Performance

- query budget for 1,000-workload fixture;
- pagination/cursor behavior;
- update endpoint bounded to changed/visible operations;
- stale fallback timing;
- no provider network call during overview request.

Slice 0 exits only when scope/count/state tests are green. Slice 2 exits only when the
transitional contract accurately labels its evidence. Full Recovery Ledger posture waits
for the readiness and proof contracts in Slice 4.
