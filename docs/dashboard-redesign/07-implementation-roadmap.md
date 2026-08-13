# Implementation roadmap

## Current status

| Area | Status as of 2026-08-12 | Evidence |
| --- | --- | --- |
| Live desktop/mobile review | Complete for planning | Overview, Activity, Workloads/Sources, workload detail, integration/setup, Settings, and drawer reviewed on the authenticated demo. |
| Repository/route/template audit | Complete for planning | Findings recorded in [01-current-state-audit.md](01-current-state-audit.md). |
| Product direction and vocabulary | Proposed, awaiting maintainer approval | Recovery Ledger, Workload terminology, navigation and posture bands. |
| Information architecture and screen behavior | Planned | Documents 02–04. |
| Design system | Planned | Document 05; no tokens/components/assets implemented. |
| Data/state contract | Proposed | Document 06; no new endpoint/model implemented. |
| Application code | **Not started** | The planning pass intentionally changed documentation only. |
| Database/API migrations | **Not started** | None authorized by the original planning request. |
| Demo UI deployment | **Not performed** | The user explicitly directed that nothing be deployed; the running interface remains unchanged by this planning artifact. |

The next agent must not interpret “design complete” as “implementation started.”

## Delivery strategy

Use vertical, reversible slices. Correctness work lands before semantic UI claims.
Foundation work lands before parallel page rewrites. Existing routes remain usable until
their replacement has scope, behavior, and callback coverage.

Recommended sequence:

    Slice 0: truth and scope
      -> Slice 1: foundation and component contract
        -> Slice 2: shell + transitional Recovery dashboard
          -> Slice 3: Workloads and Operations
            -> Slice 4: deterministic readiness and findings
              -> Slice 5: guided recovery and proof
                -> Slice 6: optional explanation and Fleet

Slices 2 and 3 can partially overlap only after Slice 1 primitives and Slice 0 state
contracts are stable. Slice 4 cannot be simulated in client code to accelerate a demo.

## Slice 0 — truth, scope, and state

### Outcome

All existing counts, rows, drill-downs, and status labels are based on one proven
authorization scope and explicit state axes.

### Work

1. Inventory current model status values and transitions for:
   - Workload/Node and Connection;
   - schedules/protection;
   - backup/snapshot/copy executions;
   - restore executions;
   - durable request/execution/artifact records;
   - destination validation.
2. Define or consolidate the canonical visible-workload queryset/service.
3. Apply it consistently to server-rendered list/detail, API, Activity, and dashboard.
4. Prove restricted-member behavior with request and browser tests.
5. Fix displayed Workload totals so every supported family is included once.
6. Replace misleading headline calculations:
   - do not call a four-item preview “Open exceptions”;
   - temporarily use “Recent failed runs” if exact current findings do not yet exist;
   - remove any recovery-safe headline inferred from that preview.
7. Implement the central server-side state presenter with explicit axes and fallback.
8. Add exact total + bounded preview conventions.
9. Document safe customer error/correlation fields.
10. Add query-count baselines and the 1,000-workload performance fixture.

### Likely files

- `apps/console/home/views.py`
- `apps/console/node/views.py`
- `apps/console/log/views.py`
- `apps/api/v1/utils/api_helpers.py`
- relevant serializers and model managers/query services
- `apps/tests/test_dashboard.py`
- `apps/tests/test_backend_scope_remediation.py`
- new focused console scope/state tests

Paths are starting points, not permission to mix unrelated model changes into one PR.

### Exit gates

- Full, restricted, multi-group, no-assignment, hidden-direct-reference, and
  cross-workspace tests pass for list/detail/count/drill-down.
- Displayed totals exactly equal the scoped union across workload families.
- No template or inline script maps raw status through string matching.
- Exact total is distinct from preview length.
- Current copy does not assert recoverability from connection/node presence.
- Query-count baseline exists and has no per-row provider/network calls.

### Rollback

State presenters/query services can be introduced behind existing templates first.
Rollback changes rendering only; it must not restore known scope defects.

## Slice 1 — frontend foundation

### Outcome

One build toolchain, one semantic token layer, reusable accessible components, and a
renderable state gallery support future page work.

### Work

1. Choose the root Tailwind 4 toolchain as the recommended authority or document another
   single supported path.
2. Remove/deprecate the nested Tailwind 3 ambiguity only after CI/build equivalence is
   proven.
3. Define semantic tokens from [05-design-system.md](05-design-system.md).
4. Self-host approved Instrument Sans/IBM Plex Mono files and licenses, or retain system
   faces until asset approval.
5. Eliminate runtime font and Alpine dependencies on public CDNs.
6. Replace the obsolete MFA QR runtime source with a reviewed local dependency.
7. Add reusable Django primitives:
   - application shell;
   - page header;
   - state badge;
   - finding/operation record;
   - data table + narrow record;
   - evidence chain;
   - empty/stale/restricted/unavailable state;
   - buttons/forms;
   - overlays and toast/live region.
8. Add one behavior module/controller for menu, drawer, dialog, focus, Escape, inerting,
   scroll lock, and focus restoration.
9. Add skip link, reduced-motion contract, target-size and focus styles.
10. Build a component gallery with all required state fixtures.
11. Select/create correct mark-only and horizontal logo assets; normalize provider
    asset loading separately.

### Likely files

- `package.json`, lockfile, and Tailwind build configuration
- `apps/console/_static/console/css/styles.css`
- new reviewed console static behavior modules
- `apps/console/_templates/console/_master.html`
- `apps/console/_templates/console/_sidebar.html`
- `apps/console/_templates/console/_header.html`
- new shared component partials/template tags
- static font/icon/logo assets and license notices
- component gallery route restricted to development/staff as agreed

### PR boundaries

Prefer:

1. toolchain and deterministic CSS build;
2. tokens/fonts/assets;
3. shell/overlay accessibility;
4. component primitives/gallery.

Do not combine the shell rewrite, every page migration, and status contract into one PR.

### Exit gates

- Fresh checkout/container produces byte-consistent or intentionally reproducible CSS.
- There is one documented CSS build command.
- No external runtime is required for core console navigation/forms.
- Closed drawer/menu/dialog is absent from focus and accessibility trees.
- Keyboard, Escape, focus trap/restore, 200% zoom, and reduced motion pass.
- Component gallery covers every state in the design-system checklist.
- No page-level one-off color/status recipe is needed for Slice 2.

## Slice 2 — shell and transitional Recovery dashboard

### Outcome

The new information architecture and Recovery Ledger visual direction ship using only
current evidence that can be stated honestly.

### Work

1. Introduce grouped navigation:
   - Recovery;
   - Workloads;
   - Operations entry only if its read route is ready, otherwise label as planned/omit;
   - Protection policies only if meaningful;
   - Connections;
   - Destinations;
   - Activity;
   - Settings.
2. Show workspace/scope in the shell and use contextual primary actions.
3. Rebuild `/console/` as the transitional Recovery view.
4. Expose observed evidence stages:
   - latest completed point;
   - source artifact verified;
   - destination copies verified;
   - restore record available.
5. Show the objective-unconfigured notice and no recovery-ready band if unsupported.
6. Show durable live operations where the existing contract is provider-complete.
7. Use exact current findings only if implemented; otherwise clearly label recent
   failed runs.
8. Replace current generic card grid with contiguous ruled modules.
9. Implement stale, partial, unavailable, restricted, setup, and narrow states.
10. Preserve current route and deep links.
11. Instrument approved UX/performance metrics without sensitive values.

### Exit gates

- Every displayed dashboard value traces to a documented current contract.
- Missing data shows Unknown/Unavailable, not zero.
- Restricted counts/links pass parity tests.
- A source with active connection and failed protection no longer appears simply
  “healthy.”
- First actionable/risk record appears in the first narrow-screen viewport.
- Recovery works with JavaScript enhancement unavailable where the existing server
  rendering supports it, or degraded behavior is explicit and tested.
- WCAG 2.2 AA screen checks and supported browser matrix pass.
- 1,000-workload overview p95 is below the agreed two-second server target in the
  recorded environment.

### Feature rollout

Recommended flag: `CONSOLE_RECOVERY_UI_V1`, resolved server-side per environment or
workspace. The exact mechanism must use the project's established configuration pattern.

Stages:

1. automated fixtures/tests;
2. local/staff component gallery;
3. demo/internal owner accounts;
4. selected design partners;
5. default on with old overview fallback;
6. remove fallback after stability/usage gates.

## Slice 3 — Workloads, Operations, and decomposed detail

### Outcome

Current and historical backup/restore work has a first-class, scoped home, while the
5,000-line workload detail page is replaced incrementally with route-backed views.

### Workstream A: Operations read model

1. Inventory every backup and restore model family.
2. Define a normalized, safe operation summary/detail adapter.
3. Reuse durable correlation, phase, retry, progress, artifact, reconciliation, and
   provider-status evidence already available where correct.
4. Add `/console/operations/` and safe detail routes.
5. Implement Live, Needs review, and History filters.
6. Add bounded incremental refresh for visible live rows.
7. Preserve focus/order and mark stale refresh.

### Workstream B: Workloads index

1. Relabel Node/Source presentation as Workload while retaining internal model names.
2. Replace tall type cards with compact posture/protection summary.
3. Add server-side URL filters and risk-first default ordering.
4. Render table on wide screens and labelled records on narrow screens.
5. Add restricted/new/filter-empty distinctions.

### Workstream C: Workload detail decomposition

Before editing, inventory every provider branch, field, modal, network call, and action in
the current detail template. Add characterization tests.

Then extract in this order:

1. shared summary header;
2. Recovery route/tab;
3. Runs;
4. Protection;
5. Configuration;
6. Activity;
7. route-backed recover/setup/destructive flows;
8. remove obsolete inline controllers only after parity tests.

Keep the old detail URL as the Recovery/Summary alias during migration.

### Exit gates

- All operation families either map explicitly or show Unsupported/Unknown; none vanish.
- Active work survives worker/server restart in the UI because durable state remains.
- Double submit returns the matching durable operation and creates no duplicate provider
  mutation.
- Workload list/detail/operation scope parity passes.
- Browser refresh/deep links/back-forward preserve tab and filters.
- No replacement page recreates the monolith with copied inline behavior.
- Provider-specific backup/restore reliability tests remain green.

## Slice 4 — deterministic readiness and current findings

### Outcome

The full four-band Recovery Ledger is enabled by configured objectives, deterministic
findings, and versioned evidence—not by UI inference.

### Dependencies

- agreed RPO/copy/isolation/recovery-proof semantics;
- recovery evidence snapshot/read model;
- finding lifecycle and fingerprint rules;
- permission-scoped evidence detail;
- objective configuration UX;
- provider coverage matrix with explicit abstention/Unknown rules.

### Work

1. Implement versioned Recovery Objective configuration.
2. Implement deterministic evidence projection/snapshot.
3. Add lifecycle-aware Finding records or a proven equivalent.
4. Evaluate versioned readiness rules server-side.
5. Add exact finding totals and evidence drill-down.
6. Enable four posture bands:
   - Verified recovery ready;
   - Protected, not restore-tested;
   - At risk;
   - Unknown.
7. Resolve findings on qualifying later evidence while retaining Activity history.
8. Add audit/export evidence as a separate, permission-aware deliverable if authorized.
9. Keep AI disabled in all correctness tests.

### Exit gates

- Every band has a deterministic rule version and evidence references.
- Unknown is used when required evidence/provider coverage is absent.
- A completed backup alone can never create Recovery proof.
- Finding count remains exact under preview limits.
- Open -> resolved sequences pass realistic operation timelines.
- Community works fully with AI unavailable.
- Product/engineering approve provider coverage and abstention semantics.

## Slice 5 — guided recovery and proof

### Outcome

Operators can select a recovery point, preflight, confirm, track, assert, clean up, and
produce a workload-level Recovery proof through a resumable safe workflow.

### Work

1. Route-backed recovery-point/copy selection.
2. Non-mutating target preflight.
3. Explicit impact/overwrite confirmation.
4. Durable idempotent restore request.
5. Restore operation detail with provider/reconciliation states.
6. Workload-specific assertion framework.
7. Rehearsal target isolation and cleanup contract.
8. Recovery proof generation/expiry.
9. Unknown-outcome freeze and lost-response recovery.
10. Downloadable/readable evidence report if product-approved.

### Exit gates

- Supported live provider restore scenarios pass with auditable evidence.
- Provider completion and assertion/proof outcomes are visibly separate.
- Lost response, worker restart, duplicate submit, and cleanup failure pass.
- Cleanup does not delete an unowned/ambiguous resource.
- Proof expires or becomes invalid under defined objective/configuration changes.
- Unsupported providers clearly abstain.

## Slice 6 — optional explanation and Fleet

### Outcome

Only after deterministic readiness is stable, add optional evidence-grounded
explanations and later multi-instance aggregation.

Guardrails:

- AI may summarize evidence or draft a remediation explanation.
- AI never decides readiness, mutates providers, selects a destructive action, or hides
  the deterministic rule.
- Input/output is scoped, redacted, schema-validated, and auditable.
- The UI has a complete non-AI path.
- Fleet aggregates signed/versioned instance evidence; it does not convert Community
  into a shared-database hosted dependency.

This slice is not required to complete the dashboard redesign.

## Cross-slice workstreams

### Accessibility

- automated semantic/contrast checks;
- keyboard walkthrough per primary flow;
- screen-reader checks on macOS and at least one additional agreed platform;
- 200% zoom and 320px reflow;
- reduced motion and high contrast;
- target size and focus-not-obscured;
- error identification and live announcements.

Automated tools support but do not replace manual checks.

### Responsive and browser QA

Minimum view matrix:

| Context | Width/example | Priority |
| --- | --- | --- |
| Narrow phone | 320–390 CSS px | All primary flows. |
| Large phone | 430 CSS px | Forms and records. |
| Tablet portrait | 768–834 CSS px | Drawer, tables/records, settings. |
| Tablet landscape/small laptop | 1024–1180 CSS px | Navigation threshold and density. |
| Desktop | 1280–1440 CSS px | Main operating view. |
| Wide desktop | 1600+ CSS px | Ledger without excessive line length. |

Test Chrome/Chromium, Safari/WebKit, and Firefox versions in the supported product
matrix.

### Performance

- server timing and query counts for overview/list/detail;
- CSS/JS/font/provider-image payload budgets;
- no below-fold provider assets blocking first content;
- live-refresh payload bounded by visible/changed operations;
- no layout shifts from missing intrinsic asset dimensions;
- no external runtime dependency for console usability.

### Security and privacy

- route/API authorization parity;
- cache isolation;
- CSRF and idempotency behavior;
- no secrets in DOM/URL/log/telemetry;
- content escaping and long untrusted names;
- safe external links;
- destructive impact/confirmation;
- no provider mutation from read-model generation.

### Content

Maintain one glossary and state-message catalogue. Product copy review is required when a
state claim changes, not merely for visual polish.

## Pull request plan

Suggested independent PR series:

1. Scope parity and count correctness.
2. State presenter and current copy correction.
3. Frontend build authority.
4. Tokens/assets/component gallery.
5. Accessible shell and grouped navigation behind flag.
6. Scoped overview read model.
7. Transitional Recovery dashboard.
8. Workloads index.
9. Operations read model/index/detail.
10. Workload detail route extraction, one tab/behavior at a time.
11. Policy/Connections/Destinations surfaces.
12. Objective/evidence/finding models and deterministic evaluator.
13. Full Recovery Ledger.
14. Guided recovery stages.

Each PR:

- states its contract and non-goals;
- lists touched model/provider paths;
- includes rollback behavior;
- includes permission and edge-state tests;
- updates this status document or an implementation tracker;
- provides before/after captures at agreed widths for visual changes;
- does not absorb unrelated dirty-worktree files.

## Metrics

### Product outcome

- median time from landing to opening the highest-severity current finding;
- percentage of open findings with a deterministic safe action;
- workloads with configured objectives;
- workloads in each posture band;
- recovery-proof coverage/freshness;
- successful rehearsal completion and cleanup;
- mean time to resolve manual-review findings.

### Reliability and truth

- duplicate provider mutation count: target zero;
- operation requests without a queryable durable state: target zero;
- provider-unknown outcomes reconciled within policy window;
- dashboard/list/detail scope parity defects: target zero;
- stale overview duration and refresh failure rate;
- finding total/preview mismatch defects: target zero;
- presenter unknown-enum occurrences.

### Experience

- first useful Recovery response p50/p95;
- user success on finding triage and recovery-point selection;
- setup completion rate by step;
- accessibility defects by severity;
- narrow-screen horizontal overflow on primary flows: target zero;
- external runtime load failures affecting core console: target zero.

Do not measure success by page views, card count, or an unvalidated “confidence” score.

## Release gates

### Demo/internal

- exact commit/deploy provenance recorded;
- database migrations reviewed and reversible;
- scope/state/reliability tests green;
- demo fixtures include healthy, risk, unknown, restricted, stale, and active operation;
- smoke walkthrough on desktop and mobile;
- no unrelated worktree content in the artifact.

### Design partner

- provider coverage disclosed;
- accessibility critical/high defects closed;
- performance budget met;
- support runbook and rollback tested;
- data retention/redaction reviewed;
- no known duplicate-mutation or hidden-operation path.

### Default on

- stable metrics through agreed observation window;
- no unresolved P0/P1 truth or authorization defect;
- all supported provider backup/restore workflows retain regression coverage;
- old route/deep-link compatibility proven;
- operator documentation and release notes complete;
- maintainer explicitly approves the posture vocabulary and visual system.

## Hard stop conditions

Stop the affected release rather than papering over:

- aggregate/detail scope mismatch;
- a readiness claim without objective/evidence;
- a duplicate provider mutation path;
- an operation that becomes invisible after worker/restart;
- unknown provider outcome exposed with a blind retry;
- secret/provider payload exposed to client or telemetry;
- inaccessible destructive confirmation;
- migration without rollback/recovery procedure;
- deployment whose source commit or environment ownership is unclear;
- performance result measured only on tiny demo data.

## Resume checkpoint

When implementation is authorized, begin here:

1. Read [README.md](README.md), this roadmap, and
   [AGENT-README.md](AGENT-README.md).
2. Re-record branch, HEAD, upstream, worktree status, demo commit, and current live
   screenshots; the 2026-08-12 evidence may have changed.
3. Get maintainer decisions on vocabulary, palette/type, routes, and readiness semantics.
4. Create Slice 0 issue/PR boundaries.
5. Run the existing backend and console baseline before modifying code.
6. Prove scope parity first.
7. Do not begin the visual dashboard implementation until Slice 0 exit gates pass.

At the end of this planning pass, every implementation slice remains. The finished work
is the audited, testable plan and agent handoff—not a deployed interface.
