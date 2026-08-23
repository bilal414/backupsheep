# Agent workstreams and backlog

This is the execution board for implementation agents. Each epic has one accountable
owner. Supporting agents may review or add isolated tests, but must not edit the owner’s
hotspot files concurrently.

## 1. Working protocol

Every agent handoff must include:

```text
Epic and task IDs:
Base branch and exact SHA:
Branch/worktree:
Files changed:
Migrations added:
Feature flags/defaults:
Tests run and exact results:
Tests not run and reason:
Security/data review performed:
Known limitations:
Follow-up tasks:
```

Required start sequence:

1. `git fetch origin develop`.
2. Confirm `develop...origin/develop` and record divergence.
3. Read this README, the architecture contract, and all upstream epic handoffs.
4. Inspect `git status`; preserve unrelated changes.
5. Create a dedicated branch/worktree from the approved base.
6. Reconfirm model/migration/API paths because `develop` is changing quickly.

Required finish sequence:

1. Run the epic’s focused tests.
2. Run `python manage.py check` and migration-drift check in the supported Docker path.
3. Run `git diff --check` and a credential/canary scan.
4. Run the full `apps.tests` suite for any shared-model, serializer, settings, queue, or
   permission change.
5. Review every output/log field for prohibited data.
6. Update contracts and the handoff before requesting integration.

No agent may deploy, mutate a live provider, rotate credentials, change licensing, or
create the hosted control-plane repository without separate authorization.

## 2. Integration ownership

| Hotspot | Single owner during implementation |
| --- | --- |
| `apps/console/models.py`, intelligence models, migrations | E1 owner |
| `apps/console/intelligence/facts.py`, evidence schema | E1 owner |
| `apps/console/intelligence/rules.py` | E2 owner |
| `apps/api/v1/intelligence/**`, `apps/api/v1/urls.py` | E4 owner |
| Intelligence templates/JS and console URL wiring | E4 owner |
| `backupsheep/settings.py`, `docker-compose.yml`, task routing | E3 owner |
| Inference sidecar/gateway package and image | E3 owner |
| Evaluation fixtures and red-team runner | E7 owner |
| Public product/security/configuration documentation | E8 owner |
| Separate hosted control-plane/IaC repository | H-series owner after authorization |

If two epics require the same hotspot, the upstream owner lands first; the downstream
agent rebases and makes the follow-up edit. Do not solve coordination with copy/pasted
parallel versions.

## 3. Epic E0 — governance and frozen contracts

**Branch:** `codex/ai-e0-governance`

**Depends on:** none

**Blocks:** all implementation epics

### E0-01 — Architecture decision records

Deliver ADRs for:

- Recovery Intelligence positioning and deterministic/AI boundary;
- Community, Cloud cell, hosted control plane, and Fleet boundaries;
- data classification and model-facing allowlist;
- AI modes and provider-retention requirements;
- no-action v1 decision;
- dedicated-cell hosted topology;
- GPL identifier/contributor/trademark decisions requiring legal review.

Acceptance:

- Each ADR records decision, alternatives, consequences, rollback, and owner.
- Every proposed external data flow has a controller, processor, retention, deletion,
  region, and training-use answer.
- No implementation begins with an unresolved P0 data-flow decision.

### E0-02 — Versioned schemas

Freeze JSON Schema documents for:

- `bs.ai.facts.v1`;
- `bs.readiness.v1`;
- `bs.ai.failure-investigation.v1`;
- `bs.ai.readiness-brief.v1`;
- safe evidence references and remediation catalog.

Acceptance:

- Positive and negative schema fixtures exist.
- Size, nesting, item-count, string-length, enum, and timestamp limits are explicit.
- Compatibility policy defines additive minor changes and breaking schema versions.
- The schemas contain no free-form action, URL, SQL, command, or arbitrary metadata field.

### E0-03 — Threat model and data matrix

Acceptance:

- Covers prompt injection, sensitive disclosure, excessive agency, cross-account scope,
  stale state, poisoned evidence, malicious model output, SSRF, duplicate billing,
  inference outage, and compromised hosted control plane.
- Maps every existing candidate field to `allowed`, `derived-only`, or `prohibited`.
- Security and product owners approve the matrix before E1 fact projection.

### E0-04 — Evaluation specification

Acceptance:

- Golden labels, sampling, reviewers, disagreement resolution, thresholds, and release
  decision authority are documented.
- The initial corpus can run without production customer data.
- Historical customer data is excluded unless a later explicit opt-in process is approved.

## 4. Epic E1 — recovery objectives, evidence, and scoped facts

**Branch:** `codex/ai-e1-evidence`

**Depends on:** E0

**Blocks:** E2, E3, E4, E5

### E1-01 — Additive persistence

Implement the models in the architecture contract:

- `CoreRecoveryObjective`;
- `CoreRecoveryEvidence`;
- `CoreIntelligenceSetting`;
- `CoreIntelligenceSnapshot`;
- `CoreReadinessFinding`;
- `CoreIntelligenceRun`;
- `CoreIntelligenceOutput`;
- `CoreIntelligenceFeedback`.

Likely files:

- `apps/console/intelligence/models.py`;
- `apps/console/models.py`;
- one or more new `apps/_migrations/00xx_*.py` files;
- model/admin fixtures only if explicitly approved.

Acceptance:

- Clean migration from the prior `develop` head and fresh database both pass.
- Migration is additive and reversible without touching execution state.
- Constraints prevent account/node mismatch, duplicate current settings, duplicate run
  request hashes, and multiple output rows per run.
- Indexes cover pending-run recovery, account/purpose/time, current findings, and expiry.
- Model `__str__`/admin/log output cannot expose facts or provider identifiers.

### E1-02 — Evidence registry

Build normalized evidence adapters for:

- source artifact integrity;
- destination artifact integrity;
- schedule and recovery-objective state;
- air-gap and immutable-retention evidence;
- backup execution status and categorized errors;
- restore completion;
- workload verification when an explicit assertion exists.

Acceptance:

- Artifact verification never becomes workload-recovery proof.
- Missing data stays `unknown` rather than silently passing.
- Evidence IDs and hashes are stable for identical canonical evidence.
- Generic relations cannot resolve across accounts.

### E1-03 — Recipient-scoped fact projector

Implement projection only after resolving current account and `visible_nodes()`.

Acceptance:

- The same user and facts produce canonical JSON and the same facts hash.
- A scope/permission change invalidates reuse.
- Provider operation IDs, fingerprints, manifests, resource IDs, keys, checksums,
  filenames, hostnames, IPs, notes, raw errors, and raw logs never appear.
- Existing durable identity is represented only as safe booleans/categories.
- Fact generation performs no provider, storage, SSH, or model I/O.
- Property tests insert secret canaries into every prohibited source field and prove none
  enter the snapshot.
- p95 target is under one second for 1,000 visible sources in the agreed test environment.

### E1-04 — Data preview and expiry services

Provide service-layer methods, not yet public routing, for:

- exact outbound-data preview;
- snapshot freshness/expiry;
- deterministic deletion according to account/deployment retention;
- safe audit events.

Acceptance:

- Preview uses the exact serialized bytes/hash used for inference.
- Expired facts cannot be used for a new or displayed model result.
- Deletion never cascades into backup/restore data.

## 5. Epic E2 — deterministic readiness and diagnosis

**Branch:** `codex/ai-e2-readiness-rules`

**Depends on:** E0, E1

**Blocks:** E4, E5, E6

### E2-01 — Recovery policy validator

Implement explicit objectives with no hidden defaults.

Acceptance:

- RPO, copy count, rehearsal age, air gap, and immutability values have safe documented
  ranges.
- Null/unconfigured objectives return `unknown`, not `pass`.
- Time calculations use UTC instants and account display timezone only for rendering.
- DST, leap-day, exact-boundary, and clock-skew fixtures pass.

### E2-02 — Readiness rule engine

Rule families:

- `COVERAGE_*`;
- `RPO_*`;
- `ARTIFACT_INTEGRITY_*`;
- `VERIFIED_COPY_*`;
- `AIR_GAP_*`;
- `IMMUTABILITY_*`;
- `EXECUTION_HEALTH_*`;
- `RECONCILIATION_*`;
- `RESTORE_REHEARSAL_*`;
- optional `COST_EXPOSURE_*` with stricter authorization.

Acceptance:

- Same rule version + facts produces the same findings/fingerprint/order.
- Posture follows the four-state contract; no model dependency exists.
- Every finding has evidence IDs and an allowlisted remediation code.
- Every rule has boundary, missing-data, contradictory-data, and resolved-state tests.
- Golden corpus agreement is 100%.

### E2-03 — Deterministic failure diagnosis

Map safe error/status/reconciliation/resume combinations to:

- current-state explanation;
- prohibitions/warnings;
- cause-code candidates;
- allowlisted next checks/remediation codes.

Required hard rules:

- unresolved provider outcome/reconciliation -> no new provider mutation;
- ownership mismatch, zero/duplicate ambiguous matches -> stop/manual review;
- scheduled retry -> do not recommend manual replay;
- artifact integrity failure -> do not restore that copy;
- safe durable resume proof only -> expose existing same-row resume workflow;
- authentication failure -> rotate/reconfigure through the normal settings workflow,
  never paste credentials into an explanation.

Acceptance:

- Existing safe error-code catalogs have complete coverage or an explicit `unknown` path.
- Rules do not parse prose error messages.
- Provider-specific behavior is derived from safe typed facts, not provider response bodies.

### E2-04 — Finding lifecycle

Acceptance:

- Findings open, persist, change, and resolve deterministically by fingerprint.
- Repeated scans do not duplicate current findings.
- History remains queryable for the configured retention window.
- Resolving a finding never changes an execution or objective.

## 6. Epic E3 — durable, isolated intelligence runtime

**Branch:** `codex/ai-e3-runtime`

**Depends on:** E0 and E1 contracts

**Blocks:** E5 and managed inference

### E3-01 — Provider-neutral adapter

Define an interface for structured generation with:

- schema identifier;
- exact facts hash;
- idempotency/request hash;
- timeout;
- model/provider version;
- maximum input/output bytes;
- usage and safe error result.

Acceptance:

- `off` adapter always provides deterministic fallback.
- Fake adapter supports success, timeout, rate limit, malformed JSON, schema violation,
  stale hash, duplicate result, and injected secret fixtures.
- No adapter has access to backup/restore models or provider SDKs.

### E3-02 — Durable run/outbox and recovery

Copy the row-first/stable-task principles of `CoreBackupRequest` without coupling to it.

Acceptance:

- Database row commits before broker publish.
- Stable task and request hashes survive broker loss/server restart.
- Dispatch lease and periodic recovery prevent unbounded concurrent dispatch.
- API idempotency returns the same active/completed logical run.
- Duplicate model results produce one visible output.
- State remains queryable through crashes.

### E3-03 — Queue and container isolation

Likely hotspots:

- `backupsheep/settings.py`;
- `docker-compose.yml`;
- `docs/scaling.md` and `docs/configuration.md`;
- new intelligence task modules;
- new inference sidecar package/image.

Acceptance:

- Inference container has no application DB credentials, provider credentials, SSH keys,
  `_storage`, or `/backups` mounts.
- Only sanitized messages enter `intelligence_inference`.
- Network egress is restricted to the configured inference endpoint where deployment
  capabilities allow it.
- Model credentials are not present in application/browser payloads or normal logs.
- An inference container compromise cannot invoke a provider or decrypt cell credentials.

### E3-04 — Result validation

Validate, in order:

1. message size and JSON parse;
2. output schema/version;
3. run/snapshot/facts hash;
4. snapshot freshness and current access scope;
5. all evidence/finding/remediation/cause references;
6. forbidden fields, URL/command/action patterns, and secret canaries;
7. claims requiring deterministic qualifiers;
8. bounded strings and final canonical output hash.

Acceptance:

- Only validated output is persisted/displayed.
- Invalid raw output is not stored in Sentry, logs, database, or error response.
- Bounded retry cannot exceed configured cost/attempt/time limits.
- Validation failure returns the deterministic explanation with a safe reason code.

### E3-05 — Runtime chaos suite

Kill the prepare, dispatch, inference, and result workers:

- before row commit;
- after commit/before publish;
- after publish/before acknowledgement;
- after model acceptance/before result publish;
- after result publish/before persistence;
- after persistence/before acknowledgement.

Also recreate RabbitMQ, restart the server, inject model timeout/rate limit, and corrupt
one response hash.

Acceptance:

- Same logical run recovers; one output is visible.
- No provider-operation count changes.
- Backup, restore, scheduler, dashboard, and normal API latency remain within agreed
  non-regression bounds.

## 7. Epic E4 — Recovery Readiness API and console

**Branch:** `codex/ai-e4-readiness-ui`

**Depends on:** E1, E2

**Can proceed without:** E3/model runtime

### E4-01 — Permissions and APIs

Implement the deterministic readiness, evidence, preview, objective, and settings APIs.

Acceptance:

- Querysets apply current-account and `visible_nodes()` scoping.
- Wrong-account, newly revoked, deleted, and restricted-node access returns the project’s
  non-enumerating response behavior.
- `intelligence_use` and `intelligence_manage` follow existing primary-member bypass and
  group-permission conventions.
- Cost facts remain primary/explicitly authorized only.
- API pagination and query counts are tested for large accounts.

### E4-02 — Dashboard and drill-down

UI requirements:

- counts for `verified_ready`, `protected_not_rehearsed`, `at_risk`, and `unknown`;
- clear `as of` time;
- top deterministic priorities;
- one row/card per visible source;
- objective, latest verified recovery point, copy/air-gap/immutability evidence, and
  rehearsal evidence;
- finding detail with evidence and normal product workflow link;
- no “AI verified” or “guaranteed recoverable” copy.

Acceptance:

- Works completely with intelligence mode `off`.
- Responsive and keyboard/screen-reader review covers phone, tablet, and desktop.
- Empty, unconfigured, loading, stale, and high-volume states are designed/tested.

### E4-03 — Objective setup

Acceptance:

- User explicitly sets objectives and sees unconfigured fields as unknown.
- Validation explains the relationship between schedule cadence and RPO without silently
  changing schedules.
- Saving an objective does not invoke a provider or model.
- Activity log records a safe change event.

## 8. Epic E5 — read-only Failure Investigator

**Branch:** `codex/ai-e5-failure-investigator`

**Depends on:** E1, E2, E3; may begin deterministic UI after E2

### E5-01 — Deterministic panel

On failed, partial, retrying, timeout, reconciliation, and manual-review runs show:

- current phase/status;
- safe error and provider/reconciliation state;
- retry timing and attempts;
- artifact status;
- deterministic warnings and next checks;
- safe correlation reference;
- available existing same-row resume/retry control, rendered by existing authorization
  logic rather than model advice.

Acceptance:

- It remains useful with AI disabled.
- It never exposes raw execution metadata, leases, worker names, provider identifiers,
  restore parameters, or secret-bearing errors.

### E5-02 — Explanation request and polling

Acceptance:

- Request accepts only an authorized execution reference, not free-form prompt text.
- `Idempotency-Key` replay returns the same logical run.
- UI distinguishes queued, deterministic fallback, validated output, expired, failed,
  and disabled states.
- Stale output cannot be displayed as current without an explicit historical label.

### E5-03 — Evidence-linked explanation

Acceptance:

- Confirmed facts, hypotheses, next steps, warnings, and missing evidence are visually
  separate.
- Each operational claim opens an evidence reference.
- Confidence is categorical and never presented as deterministic probability.
- User can report helpful, incorrect, misleading, or unsafe output.

### E5-04 — Shadow and alpha gates

Acceptance:

- Shadow output passes all hard evaluation thresholds before users see it.
- Design-partner enablement is per account and reversible.
- Deterministic output remains the fallback on every model/runtime failure.

## 9. Epic E6 — readiness briefs and notifications

**Branch:** `codex/ai-e6-briefs`

**Depends on:** E2, E4; AI narrative additionally depends on E3/E5 gates

Tasks:

- deterministic daily/weekly change summary;
- recipient-specific snapshot at send time;
- optional validated narrative;
- web, email, Slack, and Telegram rendering using the same findings;
- delivery state and rate limits;
- unsubscribe/disable control.

Acceptance:

- A restricted member never receives account-wide or hidden-node content.
- Initially only the primary member receives scheduled account-wide briefs.
- Notification retry cannot regenerate different findings for the same snapshot.
- AI failure sends a deterministic brief or no brief according to explicit preference.
- No credentials, filenames, raw errors, provider IDs, or cost data leak into messages.

## 10. Epic E7 — evaluation, security, and observability

**Branch:** `codex/ai-e7-evals`

**Depends on:** E0 schemas; evolves alongside E1–E6

**Authority:** can block release

Tasks:

- golden deterministic corpus;
- Failure Investigator labelled corpus;
- red-team and secret-canary generator;
- schema/reference/claim-support graders;
- cross-account and restricted-node suite;
- performance/load fixtures;
- model/prompt regression report;
- safe operational metrics and alerts;
- incident kill switch and runbook.

Acceptance and thresholds are defined in
[`03-evaluation-security-and-privacy.md`](03-evaluation-security-and-privacy.md).

E7 must not “fix” failing evals by weakening thresholds or labels. Any threshold change is
an ADR reviewed independently from the model/prompt change.

## 11. Epic E8 — product and operator documentation

**Branch:** `codex/ai-e8-docs`

**Depends on:** landed contracts

Tasks:

- configuration/modes and default-off behavior;
- exact data sent/not sent;
- objective/readiness semantics;
- artifact integrity vs restore completion vs workload verification;
- provider/model retention and deletion;
- local/BYOK setup and troubleshooting;
- AI outage/disable/remove procedure;
- permissions and audit events;
- security policy and incident reporting;
- source/build/license notices.

Also reconcile existing documentation with code. For example, current code uses standard
CSRF-protected session authentication, while `SECURITY.md` still describes cookie API CSRF
as disabled. That documentation correction is separate from claiming the whole hosted
security posture complete.

Acceptance:

- A new operator can disable/remove AI without affecting core service.
- A user can preview exactly what leaves the installation.
- Documentation contains no hosted promise not backed by implemented operations.
- Security limitations and current beta/GA status are explicit.

## 12. Hosted H-series epics

These belong in a separately authorized hosted-control-plane effort:

- **H0:** repository/product/licensing contract;
- **H1:** managed-cell capability and readiness endpoints;
- **H2:** dedicated-cell infrastructure;
- **H3:** idempotent provisioner/control plane;
- **H4:** identity, credentials, KMS, and support access;
- **H5:** signed releases and upgrade controller;
- **H6:** metadata backup and disaster recovery;
- **H7:** observability, incident response, and support operations;
- **H8:** outbound read-only Fleet connector;
- **H9:** customer migration/export/deletion and legal documentation.

Detailed gates are in [`04-community-cloud-and-fleet.md`](04-community-cloud-and-fleet.md).

## 13. Integration sequence

1. Land E0 contracts.
2. Land E1 models/facts after independent data review.
3. E2 rules and E3 runtime proceed in parallel on rebased branches.
4. Land E2 before E4; E4 proves the product is useful without AI.
5. Land E3 only after chaos/isolation review.
6. Land E5 in shadow mode.
7. E7 signs the shadow report before E5 customer visibility.
8. Land E6 only after recipient-scope tests.
9. E8 updates user/operator docs for each enabled cohort.
10. H-series work never blocks Community backup/recovery behavior and does not begin
    broad hosted rollout before its own security/DR gates.
