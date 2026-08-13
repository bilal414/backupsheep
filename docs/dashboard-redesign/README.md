# BackupSheep dashboard redesign plan

> **Status: planning only.** This directory is an implementation brief for future
> agents. It does not authorize application, API, database, infrastructure,
> deployment, or provider changes. The planning pass added documentation only.

## Decision

Redesign the console as a **recovery operations workspace**, not as another generic
backup statistics dashboard.

The default screen must let an operator answer this question in under 30 seconds:

> What can I recover right now, what evidence proves it, and what needs my attention
> next?

The visual and interaction concept is **Recovery Ledger**: a quiet, ruled operating
surface that connects each workload's recovery point, verified copies, isolation or
immutability evidence, and recovery proof. This replaces both the current collection of
floating metric cards and the earlier ornamental “command center” direction.

The signature relationship is:

```text
current recovery point -> verified copies -> isolation / immutability -> recovery proof
```

Each stage is evidence-backed. Missing evidence is shown as missing or unknown; it is
never silently converted into success.

## Why a new system is needed

The live demo is clean and technically responsive, but the product meaning is weaker
than the styling suggests:

- A source can be labelled `Active` while recent backup or restore attempts have failed.
- “Open exceptions” is currently the length of a query capped at four records, not a
  lifecycle-aware count.
- “Protected source” can mean only that a node exists, not that a fresh, verified,
  recoverable copy exists.
- Backup runs, restore runs, schedules, connections, and destinations do not have clear
  first-class homes in the information architecture.
- The source-detail page holds too many unrelated workflows and thousands of lines of
  inline behavior.
- The visual language is dominated by the same white rounded card, slate text, and
  indigo action recipe used by many unrelated SaaS products.

The redesign therefore starts with truth, scope, and workflow before changing pixels.

## Audience

Primary audience:

- the owner/operator of a self-hosted BackupSheep installation;
- a small infrastructure, agency, or SaaS team managing roughly 10–50 workloads;
- a person who needs to find and act on recovery risk without being a dedicated backup
  engineer.

Secondary audience:

- scoped team or client members who may see only assigned workloads;
- auditors or stakeholders who need evidence without provider credentials or raw logs;
- future BackupSheep Cloud and Fleet operators, without making the Community console
  depend on hosted services.

## Product principles

1. **Recovery confidence before backup volume.** Lead with recoverability and evidence,
   not counts of objects or bytes.
2. **Separate state axes.** Connection state, protection state, operation state, and
   recovery posture are different facts and must never share a vague “health” label.
3. **Evidence before assertion.** `Complete`, `verified copy`, `restore completed`, and
   `workload recovery proven` are distinct claims.
4. **Current work before history.** A deduplicated action queue and live operations come
   before the audit log.
5. **Safe under uncertainty.** Unknown provider outcomes, stale heartbeats, missing
   policy, and stale dashboard data are explicit states. The UI must never replace them
   with zero or green.
6. **One vocabulary.** The customer-facing terms are Workload, Recovery point, Copy,
   Operation, Destination, Policy, Finding, and Recovery proof. Internal model names can
   remain unchanged during migration.
7. **Permission-aware by construction.** Scope data before aggregation with the canonical
   visibility contract; do not aggregate account-wide and filter afterward.
8. **Useful without AI.** Deterministic posture, findings, and recovery workflows must be
   complete with every AI feature disabled or unavailable.
9. **Responsive behavior, not merely reflow.** Dense comparison tables become labelled
   operational records on narrow screens; critical actions remain reachable by keyboard
   and touch.
10. **Self-hosted resilience.** The console should not require third-party font or
    runtime CDNs to remain usable.

## Canonical vocabulary

| Current or ambiguous term | New UI term | Meaning |
| --- | --- | --- |
| Node / source | **Workload** | A server, volume, website, database, or application being protected. |
| Backup / snapshot record | **Recovery point** | A point-in-time candidate that may be used for recovery. |
| Storage point / artifact | **Copy** | One materialized copy of a recovery point at a destination or provider. |
| Backup or restore job | **Operation** | A durable requested, running, retrying, reconciling, or terminal unit of work. |
| Storage integration | **Destination** | Where website, database, or application copies are stored. |
| Source/provider integration | **Connection** | Credentials and configuration used to discover or access workloads. |
| Schedule plus retention controls | **Protection policy** | When protection runs and what copy/retention objectives apply. |
| Failure item | **Finding** | A current deterministic condition with evidence, severity, and remediation. |
| Successful restore row | **Restore completed** | The provider or logical restore operation reached its completion contract. |
| Verified rehearsal | **Recovery proof** | Explicit workload-level assertions passed after recovery, with freshness and cleanup evidence. |

“Recovery ready” is reserved for a deterministic posture backed by configured objectives
and non-expired evidence. It must not be used as a synonym for an active connection or a
completed backup.

## Proposed primary navigation

```text
RECOVER
  Recovery

PROTECT
  Workloads
  Operations
  Protection policies

INFRASTRUCTURE
  Connections
  Destinations

WORKSPACE
  Activity
  Settings
```

The current URLs should remain valid during the migration. Labels and shared shell can
change first; new account-wide routes arrive only with scoped read models and tests.

## Plan map

Future agents must read this README, the current-state audit, and the document for their
workstream before editing code:

1. [`01-current-state-audit.md`](01-current-state-audit.md) — live-demo observations,
   repository evidence, semantic defects, strengths, and migration risks.
2. [`02-information-architecture.md`](02-information-architecture.md) — navigation,
   object model, route transition, settings organization, roles, and responsive shell.
3. [`03-screen-specifications.md`](03-screen-specifications.md) — Recovery dashboard,
   Workloads, Operations, Policies, Connections, Destinations, Activity, and Settings.
4. [`04-user-flows-and-edge-states.md`](04-user-flows-and-edge-states.md) — setup,
   triage, live-operation inspection, recovery, permissions, destructive actions, and
   degraded states.
5. [`05-design-system.md`](05-design-system.md) — the Recovery Ledger visual direction,
   tokens, typography, density, components, motion, accessibility, and assets.
6. [`06-data-and-state-contracts.md`](06-data-and-state-contracts.md) — scoped overview
   read model, state grammar, findings, evidence, freshness, privacy, and performance.
7. [`07-implementation-roadmap.md`](07-implementation-roadmap.md) — sequencing,
   dependencies, PR boundaries, feature rollout, metrics, QA matrix, and hard exit gates.
8. [`AGENT-README.md`](AGENT-README.md) — execution checklist, file ownership,
   non-negotiable invariants, testing, and handoff format.

## Delivery slices

The target design cannot be safely delivered as one template rewrite.

| Slice | Outcome | Important constraint |
| --- | --- | --- |
| 0. Correctness | Canonical scope, counts, status presenters, and terminology | No visual claim may outrun the underlying data. |
| 1. Foundation | One frontend toolchain, semantic tokens, reusable primitives, accessible overlays | Existing URLs and behavior remain intact. |
| 2. Shell and evidence dashboard | New navigation and Recovery screen using only evidence that exists today | Missing objectives render Unknown; no invented readiness score. |
| 3. Operations and workload center | First-class operation history/detail and decomposed workload pages | Durable state and duplicate suppression remain authoritative. |
| 4. Deterministic readiness | Objectives, findings, evidence drill-down, and full Recovery Ledger | Rules are deterministic and evidence-linked with AI off. |
| 5. Guided recovery | Route-based preflight, restore tracking, assertions, cleanup, and recovery proof | Proof requires workload assertions, not provider completion alone. |
| 6. Optional explanation and Fleet | Read-only explanations and later cross-instance views | No AI decision or provider mutation. |

## Non-goals for the first implementation

- A generic chatbot or AI-generated health score.
- Autonomous retry, restore, delete, retention, or provider operations.
- A shared-database multi-tenant SaaS shell.
- A dark “network operations center” theme.
- Decorative gauges, orbit diagrams, or percentages without configured objectives.
- Rebranding internal Django model names in the same change as the interface migration.
- A big-bang rewrite of the 5,000-line workload-detail template.
- Removing existing routes before aliases, deep links, docs, and callbacks are migrated.

## Baseline and evidence boundary

The planning audit was performed on 2026-08-12 against:

- repository: `/Users/bilal/Projects/BackupSheep/backupsheep`;
- branch: `develop`;
- committed UI baseline: `b7d44b9151bf3bec2db9a296a6af2c6463f89abf`;
- live site: `https://demo.backupsheep.com` in an authenticated owner session;
- desktop and 390×844 mobile views of Overview, Activity, Sources, source detail,
  integration selection/setup, Settings, and mobile navigation.

At the start of the audit, the worktree already contained unrelated changes in
`apps/console/node/models.py`,
`apps/tests/test_upcloud_server_firewall_reliability.py`, and
`docs/ai-implementation-plan/`. Other agents and workstreams changed the shared
worktree while this package was being written. None of those unrelated files are part of
the dashboard-planning commit; future agents must inspect the current status rather than
resetting, overwriting, or silently absorbing it.

Immediately before the documentation-only wrap-up, `origin/develop` and the demo
checkout both resolved to `5a5542e061ef72fb0b76a12acff4dcb2d312808e`. The user
explicitly directed that nothing be deployed to the demo. No pull, build, restart, or
runtime deployment was performed, so the live UI was not changed by this plan.

Live counts and names in the audit are observations, not fixtures or permanent product
facts. The demo showed nine sources, zero active schedules, four displayed exceptions,
and 290.1 KB of destination footprint at the time of review.

## Decisions still requiring maintainer approval

| Decision | Recommended default |
| --- | --- |
| Default landing label | Recovery |
| Customer term replacing Node | Workload |
| Signature component name | Recovery Ledger |
| Readiness display | Four named posture bands; no opaque number |
| Visual direction | Wool/charcoal evidence workspace with ruled ledger surfaces |
| UI typefaces | Locally hosted Instrument Sans + IBM Plex Mono |
| Global primary action | Contextual `Add workload`; no universal action on every page |
| Narrow-screen navigation | Accessible drawer, not a crowded bottom bar |
| Initial route strategy | Preserve current URLs, add aliases/new routes incrementally |
| Current production design contract | Remains active until Slice 1 is approved and replaces it |

## Global definition of done

The redesign is not complete because screenshots look polished. It is complete only when:

- every count and link is derived from the same permission-scoped workload set;
- a later success resolves the current finding without erasing history;
- no UI state falsely claims protection or recoverability;
- every active operation remains visible through worker and broker interruption;
- repeated user actions do not create duplicate provider mutations;
- the full backup/restore reliability suite remains green;
- all primary workflows pass keyboard-only, screen-reader, 200% zoom, reduced-motion,
  mobile, tablet, and desktop QA;
- the console meets WCAG 2.2 AA, including visible unobscured focus and minimum target
  size expectations;
- the agreed 1,000-workload dashboard fixture meets its query and render budgets;
- last-known data is explicitly time-stamped and never becomes a misleading zero on
  refresh failure;
- Community remains fully useful with AI disabled and without external CDNs.
