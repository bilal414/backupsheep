# Current-state dashboard audit

## Scope and method

This audit combines three evidence sources:

1. Authenticated visual inspection of `https://demo.backupsheep.com` at the default
   desktop viewport and at 390×844.
2. Read-only inspection of Django routes, views, models, serializers, templates, CSS,
   JavaScript embedded in templates, tests, and product documentation.
3. Git history review of the recent console redesigns to distinguish current
   implementation from retired `.bs-*` custom-CSS guidance.

No forms were submitted, no provider actions were triggered, no settings were saved, and
no application code or external resource was changed.

## Executive assessment

The current console is coherent enough to operate, and its shell is more responsive and
accessible than the implementation it replaced. It is nevertheless below the product
standard BackupSheep now needs because the interface emphasizes inventory and recent rows
instead of recoverability, current work, and evidence.

The central issue is semantic, not cosmetic:

```text
Current UI: connected + recent rows -> appears healthy
Needed UI: objective + durable state + verified evidence + recovery proof -> explicit posture
```

The new design must not preserve inaccurate labels simply to avoid backend work.

## Live-demo snapshot

Observed on 2026-08-12 in an owner account. These values are transient demo evidence, not
test expectations.

| Surface | What was visible | Assessment |
| --- | --- | --- |
| Overview | 9 protected sources, 0 active schedules, 4 open exceptions, 290.1 KB; recent runs, exception queue, activity, source cards, storage economics | Too much equal-weight content; counts precede recovery meaning. |
| Activity | 307 events, three filters, a wide five-column table | Useful audit data, but raw messages and `n/a` values dominate; backup/restore operations are mixed with audit events. |
| Sources | Five type-count cards, five filter fields, action-heavy table | Clean desktop layout, but setup counts consume mobile screens before any workload state appears. |
| Source detail | Active badge, action panel, notification switches, node/integration facts, schedules, backups/restores | One page mixes recovery, protection, configuration, notification, and destructive actions. |
| Add source | Source providers and storage platforms in a single long catalogue | Two different jobs share one label and route family. |
| Database setup | Large modal over an already complex provider page | Long configuration workflows are trapped in overlays and compete with background content. |
| Settings | Eight horizontal tabs plus cards and forms | Personal security, workspace policy, access control, and channels are flattened into one row. |
| Mobile | Functional drawer and stacked cards; wide Activity table remains horizontally scrollable | Reflow works, but information priority and comparison behavior do not. |

One concrete contradiction was visible on the UpCloud server detail page: the workload
showed an `Active` node-health badge while its history contained two failed snapshots.
The connection may indeed be active, but the presentation makes it look like a single
overall health verdict.

## What should be preserved

The redesign should retain these strengths:

- Server-rendered Django pages with progressive Alpine enhancement.
- Durable backup request, execution, artifact, retry, reconciliation, and progress data.
- Tenant-aware `visible_nodes(member)` behavior already used by the dashboard, logs, and
  API code.
- Existing explicit restore confirmation and idempotent backend operations.
- `<main id="main-content">`, labelled navigation, `aria-current`, headings, table
  scopes, `<time datetime>`, live regions, and labelled icon controls.
- Current mobile drawer concept, after focus/inert behavior is corrected.
- Stable current URLs while new read models and page routes are introduced.
- Redacted public execution-status serializers rather than exposing raw provider state.
- Owner-only destination cost information.
- Existing no-duplicate and crash-recovery reliability contracts.

## Findings by priority

### P0 — correctness and trust

#### 1. “Open exceptions” is not an open-exception count

`apps/console/home/views.py` requests failed backups with `limit=4`, then
`home/index.html` displays `failed_backups|length` as the account's open-exception count.

Consequences:

- the maximum displayed count is four;
- historical failures can remain after a later successful run;
- multiple failed attempts for one workload can inflate the queue;
- there is no finding lifecycle or resolution state;
- the clean-state headline is based on the same capped list.

Required resolution: introduce an exact, deduplicated, current-state finding contract.
Until that exists, label a bounded list as “Recent failed runs” and do not present its
length as an account-wide exception total.

#### 2. Protection language exceeds available evidence

The dashboard calls every visible node a protected source and can say the infrastructure
has an active recovery path when the failure list is empty. A node may lack:

- an active schedule;
- a configured recovery objective;
- a recent successful recovery point;
- verified destination copies;
- an immutable or isolated copy;
- a completed or workload-verified recovery rehearsal.

Required resolution: distinguish inventory, configured protection, current recovery
point, verified copies, completed restore, and recovery proof.

#### 3. Suspected server-rendered scope mismatch

The dashboard and log view use `visible_nodes(member)`. `NodeView` and `NodeDetailView`
currently filter by `connection__account=current_account`, which appears broader for
non-owner members. API scope tests explicitly expect guessed hidden-node IDs to return
404.

This is a suspected authorization inconsistency, not a publicly confirmed vulnerability:
it still needs a non-owner browser/runtime test. It is nevertheless a Phase 0 blocker.

Required resolution:

- use one canonical scoped queryset for every console aggregate, list, detail, action,
  and lookup;
- test owner, unrestricted group, assigned group, no-group, cross-account, and guessed-ID
  cases;
- return a non-enumerating 404 for an out-of-scope object.

#### 4. Status meaning drifts across pages

Source, backup, restore, and provider states are mapped repeatedly in templates and
client-side JavaScript. The same numeric state can receive different tones on the source
index, detail page, dashboard, and JavaScript presenter.

Required resolution: separate typed presenters for connection/configuration state,
protection state, backup execution, restore execution, reconciliation, copy integrity,
and recovery posture.

### P1 — workflow and information architecture

#### 5. Important operational objects do not have first-class pages

Persistent navigation exposes only Overview, Activity, Sources, Add source, and Settings.
There is no account-wide home for:

- backup and restore operations;
- schedules and policies;
- recovery points;
- restores;
- source connections;
- storage destinations.

The result is that operational history and recovery actions are buried in a workload
detail page or a generic audit table.

#### 6. Source and destination setup are conflated

`/console/integration/` contains cloud, database, website, SaaS, and storage providers.
The page is titled “Connect an integration” even though an operator may be trying either
to access a workload or choose where copies are stored.

Required resolution: provide explicit “What do you want to protect?” and “Where should
copies be stored?” entry paths, then branch setup based on workload type.

#### 7. The workload detail page is an overloaded monolith

`apps/console/_templates/console/node/detail.html` is about 5,025 lines, contains roughly
32 `fetch()` call sites and about 12 dialogs, and combines:

- on-demand backup/snapshot;
- schedule creation and editing;
- notification preferences;
- integration facts and validation;
- recovery-point history;
- restore, download, retry, cancel, and delete;
- provider-specific restore behavior;
- configuration and destructive workload actions.

Required resolution: extract behavior and split the user experience into route-backed
Recovery, Runs, Protection, Configuration, and Activity tabs. Large workflows should be
pages or drawers; dialogs should be limited to short confirmations.

#### 8. Settings mixes incompatible concerns

The same eight-link tab bar is duplicated across settings templates and combines:

- personal profile;
- password and MFA;
- workspace configuration;
- workspace notification policy;
- members, invites, and groups;
- Slack and Telegram channels.

Required resolution: group Personal, Workspace, and Access administration with a shared
settings navigation partial and permission-aware entries.

#### 9. Activity is used as both audit trail and operations history

The Activity page is valuable for governance but is not an effective run monitor. It
contains raw prose, error text, actors, and heterogeneous event types; operations need
durable phase, progress, retry, reconciliation, correlation, and safe next-action data.

Required resolution: create an Operations page and keep Activity as the immutable human
and system audit trail.

### P1 — responsive and accessibility behavior

#### 10. Mobile priority is dominated by repeated cards and filters

At 390px, Overview shows four large statistic cards before recent work. Sources shows up
to five type cards before filters and workloads. Settings tabs clip horizontally. The
Activity table has an internal scroll width around 989px inside a 356px wrapper.

Required resolution:

- put recovery posture and current action first;
- collapse secondary counts into one compact summary;
- use labelled operational records on narrow screens;
- make filters a summary button/drawer when more than two fields are needed;
- preserve desktop tables only where column comparison is the job.

#### 11. Closed mobile navigation can remain focusable

The sidebar is translated off-screen but not removed from the accessibility tree or made
inert. Keyboard focus can reach links that are not visible.

Required resolution: shared drawer behavior with `x-show` or inert/aria state, focus
trap, Escape, backdrop close, scroll lock, and opener focus restoration.

#### 12. Overlay and menu behavior is inconsistent

Many dialogs have `role="dialog"` and `aria-modal`, but there is no shared focus manager.
Dropdowns often lack Escape handling and focus restoration. The header user button has a
static `aria-expanded="false"`, and its mobile accessible name is weak.

Required resolution: one tested overlay/menu controller; state-bound ARIA; unique labels
and IDs; background inerting; visible focus; no focus loss after close.

#### 13. Contrast and motion gaps remain

`text-slate-400` is used for real small text on white at insufficient normal-text
contrast. The console has transitions and spinners but no reduced-motion contract.

Required resolution: semantic text tokens that meet AA, a two-pixel visible focus
indicator, no color-only meaning, and `prefers-reduced-motion` behavior. WCAG 2.2 AA is
the release target; see the [W3C WCAG 2.2 Recommendation](https://www.w3.org/TR/WCAG22/).

### P1 — maintainability and delivery risk

#### 14. The design “system” is copied recipes, not reusable components

The current internal design guide instructs agents to copy Tailwind snippets and keep a
hidden scan-only template synchronized. This produces consistency by repetition, not by
composition. A static scan found hundreds of repeated rounded-card, shadow, text, and
button recipes.

Required resolution: reusable Django partials/template tags plus a renderable internal
component gallery with state fixtures.

#### 15. Frontend toolchain has two versions

The root manifest uses Tailwind 4.3, while
`apps/console/_static/console/package.json` still declares Tailwind 3.4-era dependencies
and `tailwind.config.js` remains v3-shaped.

Required resolution: one authoritative manifest, lockfile, build command, scan contract,
and CI check before multiple agents edit templates.

#### 16. Runtime behavior lives inline in templates

There are no reusable console JavaScript modules. High-risk pages combine markup, Alpine
controllers, network calls, status mapping, and overlay behavior in one file.

Required resolution: extract named, tested static modules by behavior before splitting
the pages they control.

### P2 — product polish and content

#### 17. Logo treatment is distorted and redundant

The current `logo.webp` is a very wide wordmark but is forced into a square and followed
by the product name in text. The live sidebar visibly compresses it.

Required resolution: create or select a true mark-only asset for compact contexts and a
separate horizontal lockup; do not crop or distort one into the other.

#### 18. Provider catalogue is heavy

The integration page renders dozens of provider images, several of which are large raster
payloads embedded inside SVG. Images are not consistently lazy-loaded.

Required resolution: normalize provider marks, set dimensions, lazy-load below the fold,
use asynchronous decoding, and retain text labels when an asset fails.

#### 19. Copy exposes internal language

Examples include `NodeBackupFailedError`, uppercase event codes, repeated `n/a`, raw
backup identifiers, and “Node url” inside human-facing messages.

Required resolution: keep codes available in an evidence/details layer while the primary
copy says what happened, what is known, and what the operator can safely do.

#### 20. Stale or incomplete surfaces exist

`console/connection/index.html` references a namespace that is not currently routed, and
`setting/team.html` is empty. The Sources displayed total also omits the separately
counted SaaS category in one template expression.

Required resolution: inventory and explicitly delete, revive, or redirect stale
surfaces; add route and count-contract tests.

## Recent visual history and lessons

Git history shows three important stages:

1. An earlier conventional console.
2. A bespoke “command center” with custom `.bs-*` CSS, orbit/posture graphics, multiple
   typefaces, and control-room copy.
3. The current Tailwind-only refresh, which deleted the 6,000-line custom stylesheet and
   standardized the whole console around Inter, slate, white cards, and indigo.

The next design must learn from both attempts:

- do not return to decorative metaphors, glyph icons, or a huge override stylesheet;
- do not mistake a generic component recipe for a product identity;
- spend visual distinctiveness on one subject-specific structure—the evidence ledger;
- put semantics in shared presenters and components so style cannot drift from truth.

## Risks that must be validated before implementation

| Risk | Validation needed | Gate |
| --- | --- | --- |
| Server-rendered restricted-member scope | Browser and request tests with assigned, hidden, unrestricted, and no-group workloads | Slice 0 cannot exit without parity. |
| Exact current findings | Define lifecycle and resolution rules against real run sequences | Do not ship an “open” count until exact. |
| Unified operations | Map all backup and restore model families to a safe common read model | No client-side joins or raw provider fields. |
| Readiness | Agree recovery objectives and evidence semantics | Unknown when unconfigured; no inferred policy. |
| Workload-detail decomposition | Characterize every API call, modal, field, and provider branch | Split only behind behavior tests. |
| Tailwind build | Confirm one supported v4 configuration and lockfile | All agents must generate identical CSS. |
| External assets | License and bundle fonts/runtime/provider assets | Community console must work without CDNs. |
| Performance | Build 1,000-workload fixture and query budgets | p95 dashboard target is under two seconds. |

## Audit conclusion

The existing UI should not receive another surface-only reskin. The safe path is:

1. correct scope, counts, and state vocabulary;
2. establish reusable and accessible foundations;
3. reorganize around Recovery, Workloads, Operations, Policies, Connections, and
   Destinations;
4. ship an evidence-honest dashboard using current durable data;
5. add full deterministic readiness and recovery proof only when their contracts exist.
