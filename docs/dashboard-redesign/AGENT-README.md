# Agent handoff for the dashboard redesign

## Read this first

This directory is a completed **planning package** and an unstarted implementation
program.

The planning work:

- inspected the authenticated live demo on desktop and mobile;
- audited routes, templates, CSS/tooling, durable-state surfaces, and access scope;
- selected the Recovery Ledger product and visual direction;
- specified the information architecture, screens, flows, design system, data contract,
  sequencing, tests, metrics, and exit gates;
- changed documentation only.

It did **not**:

- edit console templates, CSS, JavaScript, Python, models, APIs, tests, migrations, or
  infrastructure;
- change or deploy the live dashboard;
- implement recovery objectives, findings, readiness, or Recovery proof;
- authorize a future agent to make provider mutations.

Do not report that the redesign is implemented because these documents exist.

## Required reading order

Before touching code:

1. [README.md](README.md)
2. [01-current-state-audit.md](01-current-state-audit.md)
3. [02-information-architecture.md](02-information-architecture.md)
4. [06-data-and-state-contracts.md](06-data-and-state-contracts.md)
5. [07-implementation-roadmap.md](07-implementation-roadmap.md)
6. the screen, flow, and design documents relevant to the assigned slice

If implementing recovery/readiness, also read the repository's current reliability and
AI implementation plans. This package is authoritative for interface meaning; durable
orchestration/provider-safety plans remain authoritative for mutation correctness.

## Non-negotiable invariants

1. Durable records, not Celery state, drive current operations and crash recovery.
2. Repeated intent must not create a duplicate provider mutation.
3. Unknown provider outcome freezes conflicting mutation until reconciliation/manual
   review clears it.
4. Canonical visible-workload scope is applied before aggregate, list, detail, filter,
   export, cache, and live-update work.
5. Connection, protection, operation, copy/evidence, recovery posture, and freshness are
   separate state axes.
6. Unknown/unavailable/stale is never converted into zero, success, healthy, protected,
   or ready.
7. Provider completion, copy verification, restore completion, assertion success, and
   Recovery proof are distinct claims.
8. AI is optional explanation only; it never establishes readiness or mutates a
   provider.
9. Community remains useful without AI, public runtime CDNs, or a hosted control plane.
10. Existing provider reliability, route, callback, and authorization behavior may not
    regress during interface migration.

## Resume procedure

### 1. Establish provenance

Run and record:

    git status --short --branch
    git rev-parse HEAD
    git rev-parse origin/develop
    git remote -v

Then identify:

- the user's authorized branch/worktree;
- whether other agents or humans are changing the shared checkout;
- the exact demo commit and deployment mechanism, if a later deploy is authorized;
- untracked and tracked files unrelated to this slice;
- current migrations and runtime dependencies.

Do not reset, clean, stash, stage, commit, or overwrite unrelated changes. If a target
file has overlapping uncommitted changes of unclear ownership, stop and coordinate.

### 2. Refresh the evidence

The planning snapshot is dated 2026-08-12. Before implementation:

- compare current routes/templates/models with the audit;
- capture current Recovery/Overview, Activity, Workloads, detail, setup, Settings, and
  mobile shell;
- verify the current demo commit;
- re-check the suspected server-rendered Workload scope mismatch;
- re-run displayed count/state evidence;
- record new or stale findings in the implementation PR.

Do not treat live demo counts or named workloads as fixtures.

### 3. Confirm product decisions

Get maintainer approval or find an existing recorded decision for:

- Recovery as landing label;
- Workload replacing Node/Source in customer copy;
- Recovery Ledger name and evidence-stage structure;
- four named posture bands and no numeric score;
- wool/ink/blue/teal/amber/red palette;
- local typeface assets;
- navigation and route-alias strategy;
- current versus new objective/readiness semantics.

If only styling is authorized, stop before inventing models, endpoints, or claims. If
only correctness is authorized, preserve the current UI while completing Slice 0.

### 4. Choose one bounded slice

Start with Slice 0 unless it is already proven complete. Write the PR contract:

- outcome;
- files/models/provider paths in scope;
- explicitly excluded work;
- data/state authority;
- permission cases;
- test plan;
- rollback;
- feature flag/rollout where relevant.

Do not assign several agents to edit the same base template or monolithic detail page.

## Workstream ownership

These boundaries reduce collisions. They do not override code ownership or review.

| Workstream | Primary surface | May proceed when | Avoid |
| --- | --- | --- | --- |
| Scope/count correctness | Query services, views, serializers, scope tests | Immediately in Slice 0 | Visual rewrite and model-wide rename |
| State presenter | Server-side mapping and fixtures | State inventory complete | Template string heuristics |
| Frontend toolchain | Package/build/scan/CI | Build owner assigned | Page redesign |
| Tokens/assets/gallery | CSS, local assets, component fixtures | Toolchain stable | Provider behavior |
| Shell/accessibility | Master/header/sidebar/nav/overlays | Component contract agreed | Dashboard data logic |
| Recovery read model | Scoped service/serializer/tests | Slice 0 green | Client-side joins |
| Recovery screen | Overview template/presenter/tests | Read model and foundation stable | Readiness inference |
| Operations | Normalized read adapters/routes/templates | Durable-family inventory complete | Provider mutation changes |
| Workloads | Index/detail route extraction | Scope and primitives stable | Big-bang monolith rewrite |
| Policies/connections/destinations | Their own routes/presenters | Backend capabilities confirmed | Combining source and storage again |
| Objectives/findings/readiness | Versioned domain/data work | Product semantics approved | AI scoring |
| Guided recovery | Restore workflow/evidence/assertions | Provider safety proven | Modal-only mutation |

When parallelizing, assign ownership by file/domain and integrate through agreed fixture
contracts. One agent owns shared shell/tokens at a time.

## Current high-risk areas

### Scope

The dashboard/API/log code and server-rendered Workload list/detail do not appear to use
one consistent group-aware scope. Treat this as a suspected authorization/correctness
blocker until request tests prove the result.

### Misleading dashboard semantics

The current Open exceptions headline is based on a bounded failure preview, and a clean
headline is inferred from that set. Fix the data/copy contract before redesigning the
module.

### Monolithic detail

The current Workload/Node detail template is roughly 5,000 lines with many inline
network calls and dialogs. Characterize behavior and extract routes incrementally. Do
not rewrite it in one pass.

### Status drift

The same raw state can render differently across templates and inline JavaScript. A live
workload can show Active configuration beside failed operations. Implement explicit
state axes and central presenters.

### Frontend build ambiguity

Root and nested console manifests represent different Tailwind generations. Choose and
test one authority before multiple template agents depend on generated CSS.

### Overlay/accessibility behavior

The current mobile sidebar is translated off-screen but may remain focusable. Menus and
dialogs do not share a complete focus/Escape/ARIA contract. Fix through a shared tested
primitive.

## Implementation conventions

- Keep internal model names stable unless a separate migration/refactor is approved.
- Change customer-visible vocabulary in presenters/templates/routes incrementally.
- Use Django URL names, not hard-coded console paths.
- Keep provider OAuth callback routes compatible.
- Prefer server-rendered truth with progressive enhancement.
- Put filters, sort, page, and tab state in the URL.
- Map status on the server; browser code renders presenter output.
- Add reusable partials/template tags instead of copying long utility strings.
- Add small named behavior modules instead of page-sized inline Alpine objects.
- Use project CSRF/auth conventions.
- Use idempotency and durable request endpoints for mutations.
- Never call a provider while constructing the dashboard read model.
- Keep secrets out of DOM attributes, URLs, storage, errors, and screenshots.
- Use `Unknown` for unsupported provider evidence and record capability coverage.

## File map

### Existing shell and pages

- `apps/console/_templates/console/_master.html`
- `apps/console/_templates/console/_sidebar.html`
- `apps/console/_templates/console/_header.html`
- `apps/console/_templates/console/_console_nav.html`
- `apps/console/_templates/console/home/index.html`
- `apps/console/_templates/console/log/index.html`
- `apps/console/_templates/console/node/index.html`
- `apps/console/_templates/console/node/detail.html`
- `apps/console/_templates/console/integration/`
- `apps/console/_templates/console/setting/`

### Existing styling/build

- `apps/console/_static/console/css/styles.css`
- `apps/console/_static/console/css/compiled.css`
- root `package.json` and lockfile
- nested console package/config files that must be reconciled

### Existing correctness starting points

- `apps/console/home/views.py`
- `apps/console/node/views.py`
- `apps/console/log/views.py`
- `apps/api/v1/utils/api_helpers.py`
- `apps/tests/test_dashboard.py`
- `apps/tests/test_backend_scope_remediation.py`

Reconfirm paths before editing. This is an audit map, not a guarantee that files remain
unchanged.

## Test baseline

Use the repository's current documented environment. Docker is preferred when local
PostgreSQL/services are unavailable.

Initial focused commands to verify against current project docs:

    python manage.py check
    python manage.py makemigrations --check --dry-run
    python manage.py test apps.tests apps.console.onboarding
    npm run build:css

Do not claim the entire suite is green from focused tests. Record:

- exact command;
- environment/container;
- database/provider fixtures;
- passed/failed/skipped count;
- duration;
- commit SHA.

### Required per-slice tests

Slice 0:

- owner/restricted/multi-group/no-assignment/cross-workspace scope;
- count/list/detail parity;
- state presenter enumeration;
- exact total versus preview;
- query budget.

Foundation:

- CSS build reproducibility;
- component fixture rendering;
- overlay keyboard/focus behavior;
- accessibility automation plus manual checks.

Dashboard:

- healthy/risk/unknown/setup/restricted/stale/partial/unavailable;
- 1,000-workload response/query/render;
- links preserve scope and filters.

Operations/workloads:

- every operation family;
- durable restart/retry/reconciliation/manual review;
- duplicate submit;
- deep-link and route authorization;
- narrow-record equivalence.

Readiness/recovery:

- objective version/evaluation;
- finding lifecycle;
- evidence redaction;
- provider success with lost response;
- restore assertion and cleanup;
- proof freshness/expiry.

## Visual QA capture

For every visible PR, capture at minimum:

- 390×844 narrow phone;
- 834×1112 tablet portrait;
- around 1180px navigation threshold on both sides;
- 1440px desktop;
- 200% zoom;
- reduced motion.

Include:

- normal populated;
- at risk/manual review;
- empty/restricted;
- stale/unavailable;
- long name/identifier;
- open menu/drawer/dialog with focus position.

Use stable fixtures, not customer secrets or unredacted live provider data.

## Deployment discipline

The 2026-08-12 wrap-up explicitly did **not** deploy this documentation or any code to
the demo.

Before any later authorized demo deployment:

1. identify the exact local commit;
2. ensure the commit contains only authorized files;
3. ensure the remote branch contains that commit;
4. verify demo checkout, branch, and current commit;
5. inspect migrations and environment changes;
6. use the repository's documented procedure and known compose override;
7. never build from an ambiguous dirty checkout;
8. run pre-deploy tests proportional to the slice;
9. deploy;
10. verify health, routes, assets, console flows, mobile, and commit provenance;
11. record rollback command and prior commit.

A docs-only commit does not change the running interface and must not be represented as a
UI deployment.

## Definition of a safe handoff

At the end of each implementation turn, update a tracker with:

### Provenance

- branch;
- commits and push state;
- demo commit/runtime image provenance if deployed;
- working-tree state and unrelated files preserved.

### Completed

- user-visible behavior;
- data/model/API contract;
- migrations;
- permissions;
- providers covered;
- feature-flag state.

### Validation

- exact test commands/results;
- query/performance measurement;
- accessibility checks;
- viewport/browser checks;
- live/demo smoke checks;
- anything explicitly not verified.

### Remaining

- next smallest slice;
- blockers/decisions;
- provider or edge-state gaps;
- rollback/fallback still active;
- docs, fixtures, and tests to update.

### Evidence boundary

State what checks prove and do not prove. A successful build, health endpoint, or
container restart is not blanket recovery correctness or release approval.

## Stop and ask

Stop rather than infer permission when:

- branch, demo server, compose override, or resource ownership is unclear;
- dirty changes overlap the assigned files and their owner is unknown;
- work would broaden visible scope or alter provider mutation outside the approved slice;
- readiness/objective meaning lacks a decision;
- deployment requires secrets, migration, or destructive action not authorized;
- a test would touch a live customer/provider resource without an approved fixture;
- rollback cannot be described;
- the same scope, duplicate, or unknown-outcome safety failure remains unresolved.

## Immediate next task

The first implementation task is **Slice 0: scope and state correctness**, not the new
dashboard markup.

Deliver a focused PR that:

1. proves one canonical Workload visibility scope across dashboard, API, Activity, list,
   and detail;
2. fixes exact counts and capped-preview language;
3. establishes separate normalized state presenters;
4. adds permission and count-contract regression tests;
5. records query budget on a representative fixture;
6. leaves provider mutation behavior and visual redesign out of scope.

Only after those gates pass should another agent begin the shell/component foundation.
