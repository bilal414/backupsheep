# Screen specifications

## Shared screen rules

Every operational screen must show:

- the current workspace or account;
- whether the view is full-account or restricted scope;
- an `as of` timestamp or live-update indicator when state can change;
- a clear route title owned by the shell;
- one primary task, not a repeated global setup button;
- loading, empty, error, stale, permission-limited, and populated states;
- links that preserve the active scope and filters.

Every status display combines label, icon/shape, and color. Identifiers, timestamps, and
codes use the utility typeface and wrap without changing layout width.

## 1. Recovery dashboard

### Job

Within 30 seconds, answer:

1. What is currently recoverable?
2. What evidence supports that answer?
3. What requires intervention?
4. What work is running or waiting?
5. What is the safest next action?

### Desktop composition

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Recovery                              Scope: 42 workloads · As of 10:42:18   │
│ Know what can be recovered and why.                           [Add workload] │
├──────────────────────────────────────────────────────────────────────────────┤
│ RECOVERY LEDGER                                      │ ACT NOW               │
│                                                     │                       │
│ Posture band       Point   Copies   Isolation  Proof│ [Critical] 2          │
│ Verified ready       18      18        18       18  │ Provider outcome ...  │
│ Protected, untested  11      11        11        0  │ [High] 5              │
│ At risk               7       4         2        1  │ RPO missed ...        │
│ Unknown               6       ?         ?        ?  │ [Unknown] 6           │
│                                                     │ [Review all findings] │
├─────────────────────────────────────────────────────┴────────────────────────┤
│ LIVE OPERATIONS                                                              │
│ Workload          Operation       Phase/progress       Updated   Next action │
│ prod-db           Backup          Upload 68%           12s       Open        │
│ billing-volume    Snapshot        Reconciling          1m        Do not retry│
├────────────────────────────────────────────┬─────────────────────────────────┤
│ RECOVERY COVERAGE                          │ NEXT 24 HOURS                   │
│ Highest-risk workloads first               │ Scheduled protection/rehearsal │
├────────────────────────────────────────────┴─────────────────────────────────┤
│ Destination health / recently resolved / setup checklist as applicable      │
└──────────────────────────────────────────────────────────────────────────────┘
```

This is a contiguous operating surface. Use spacing and ruled separators to create
hierarchy; do not turn every block into a detached white card.

### Mobile composition

```text
[menu] Recovery                    [attention] [member]
Scope: 12 assigned · Updated 10:42

RECOVERY POSTURE
[At risk 3] [Unknown 2] [Protected 7]

Evidence chain
Current point ━ Verified copies ━ Isolation ━ Proof
9 known          8                 5            2

ACT NOW (3)
[critical finding record]
[next finding record]
[Review all]

LIVE OPERATIONS (2)
[labelled operation record]

[Coverage] [Next 24h] [Destinations]
```

At narrow widths, lead with at-risk/unknown states. Do not render four full-height stat
cards before the first actionable item.

### Recovery Ledger

The Recovery Ledger is the signature component.

#### Full deterministic version

Rows are posture bands or selected workload groups. Columns are evidence stages:

1. **Current point** — recovery-point freshness against an explicit objective.
2. **Verified copies** — verified required copies, with partial/failing detail.
3. **Isolation** — immutability/air-gap evidence only if configured and actually known.
4. **Recovery proof** — non-expired workload-level recovery rehearsal.

Each cell provides:

- a count or `Unknown`, never a misleading zero for unavailable data;
- a short state label;
- evidence age;
- a link to the filtered workload list;
- an accessible explanation of the rule.

Posture bands:

- **Verified recovery ready**
- **Protected, not restore-tested**
- **At risk**
- **Unknown**

Do not use a donut, speedometer, opaque score, or animated orbit.

#### Transitional version using current evidence

Before recovery objectives and rehearsal proof exist, keep the same visual structure but
label stages exactly:

- Latest completed point
- Source artifact verified
- Destination copies verified
- Restore record available

Show an inline notice:

> Recovery objectives are not configured. These are observed facts, not a recovery-ready
> assessment.

This permits the new shell and visual system to ship without inventing readiness.

### Act now

A lifecycle-aware queue of current deterministic findings, ranked by:

1. mutation freeze/manual review;
2. severity;
3. number or importance of affected workloads;
4. age;
5. stable rule ordering.

Finding record contents:

- severity and specific headline;
- affected workload(s);
- observed fact and age;
- applicable objective/rule;
- safe primary action;
- evidence link;
- owner/permission note when the viewer cannot act.

Example:

```text
Manual review · billing-volume
The provider outcome is unknown. A second snapshot could create a duplicate.
Observed 7 minutes ago · reconciliation_required
[Review evidence]
```

Do not show the same unresolved condition as multiple failures. Later success resolves
the finding and moves the lifecycle event to Activity/Recently resolved.

### Live operations

Show only durable active or manual-review states, not Celery result state.

Columns/fields:

- workload;
- operation type and trigger;
- state and durable phase;
- progress if total is known, otherwise phase + elapsed time;
- last update/heartbeat age;
- next retry or reconciliation state;
- correlation ID in details;
- safe next action.

Copy examples:

- `Request saved; waiting for a worker.`
- `Retry scheduled for 10:48.`
- `Provider outcome is being reconciled.`
- `Manual review required. Do not start another operation.`
- `A matching request already exists. View operation.`

### Recovery coverage

Desktop comparison columns:

| Workload | Latest point | RPO state | Verified copies | Recovery proof | Posture |
| --- | --- | --- | --- | --- | --- |

Default ordering: manual-review freeze, critical risk, high risk, unknown, protected,
verified ready. Users can change sorting; the initial state must not bury risk under
alphabetical order.

Mobile records show the same facts as labelled rows. They do not hide copy count or proof
age just to fit.

### Secondary modules

Render only when relevant:

- **Next 24 hours:** scheduled operations with local timezone and overdue state.
- **Destination health:** failed validation, capacity/footprint, and affected workload
  count; costs only for authorized users.
- **Recently resolved:** up to five current-finding resolutions with time and cause.
- **Setup checklist:** new or incomplete installations; replaces empty analytics.

The generic audit stream and shortcut tiles do not belong on the primary dashboard.

## 2. Workloads index

### Job

Find a workload and compare recovery/protection posture across the visible scope.

### Header

- Title: `Workloads`
- Scope summary: `42 workloads in this workspace` or `12 workloads assigned to you`
- Primary action: `Add workload` when authorized
- Search by workload, provider/connection, endpoint-safe label, or tag when tags exist

### Compact summary

Use one segmented posture summary, not five tall type cards:

```text
At risk 7 | Unknown 6 | Protected, untested 11 | Verified ready 18 | Paused 2
```

Workload type is a filter, not the first hierarchy.

### Desktop table

Recommended columns:

- Workload (name, type, provider)
- Recovery posture
- Latest recovery point + freshness
- Verified copies
- Recovery proof age
- Active operation or next scheduled run
- Actions

Actions: open; run backup if permitted; more menu. Do not put Logs, Open, Backup,
Pause, Modify, and Delete as equal buttons in every row.

### Mobile record

```text
prod-postgres                         [At risk]
Database · PostgreSQL connection
Latest point   3h ago · RPO missed by 1h
Copies         1 of 2 verified
Recovery proof None
[Open workload]                         [More]
```

### Empty variants

- Owner/new workspace: guided `Add first workload` flow.
- Restricted member/no assignments: `No workloads are assigned to your access groups.`
  No setup CTA unless permissions allow it.
- Filtered empty: show active filters and `Clear filters`; do not show onboarding.

## 3. Workload detail

### Persistent summary header

- workload name with safe wrapping;
- type + provider/connection;
- recovery posture, not generic node health;
- connection/config state shown separately;
- latest evidence timestamp;
- primary action appropriate to tab and permission;
- `More` menu for pause, modify, and delete.

Tabs are routes, not hidden mega-page panels.

### Recovery tab

- current posture with rule summary;
- evidence chain for the selected/latest point;
- current findings;
- recovery-point list with copy availability;
- latest recovery proof and expiry;
- `Recover` action starts a route-based preflight flow.

### Runs tab

- live operation first;
- backup/snapshot and restore history;
- durable phase, progress, retry/reconciliation;
- correlation/evidence detail;
- no raw unsafe log in the primary row.

### Protection tab

- schedule(s);
- retention;
- required destinations/copies;
- recovery objectives when available;
- notification policy;
- downstream impact if a policy/destination is paused.

### Configuration tab

- source resource and connection;
- last validation;
- backup server facts appropriate to permission;
- provider-specific options;
- modify/validate controls;
- no credentials shown after save.

### Activity tab

Filtered audit events for the workload, with actor, event category, message, and timestamp.

## 4. Operations

### Index

Tabs/filters:

- Live
- Needs review
- History
- All / Backup / Snapshot / Restore / Rehearsal

Desktop table:

| Workload | Operation | State | Phase/progress | Started/updated | Trigger | Action |
| --- | --- | --- | --- | --- | --- | --- |

Use server-side filters, URL state, pagination, and periodic refresh of only visible live
rows. Preserve focus and scroll position during refresh.

### Operation detail

Header:

- operation type;
- workload;
- current state;
- correlation ID;
- trigger/requester;
- requested, started, and last-updated timestamps.

Durable timeline example:

```text
Request committed
  -> Dispatched
  -> Worker claimed
  -> Source capture/export
  -> Source artifact verified
  -> Destination copy 1 verified
  -> Destination copy 2 retrying
  -> Completed / partial / manual review
```

Timeline steps must come from persisted evidence. Do not synthesize a completed step from
elapsed time or a progress animation.

Detail sections:

- safe status explanation;
- retries/reconciliation;
- copy outcomes;
- related finding;
- activity/audit events;
- permitted actions: cancel, retry/resume, or review evidence only when backend safety
  contracts allow them.

## 5. Protection policies

### Index

Show:

- name/workload;
- schedule and timezone;
- retention;
- destinations/required copy count;
- next run;
- status and impacted findings.

Until reusable policy objects exist, call these “Protection settings” at the workload
level or clearly state that each policy applies to one workload.

### Detail/editor

Group fields by intent:

1. When to run
2. Where copies go
3. What to retain
4. Recovery objectives
5. Notifications

Preview the next three run times in the selected timezone. Validate contradictory or
unachievable objectives explicitly.

## 6. Connections

### Index

Group by workload family rather than a promotional tile wall. Each record includes:

- provider/name;
- validation state and age;
- visible/total workload count as permitted;
- region or safe endpoint class;
- active findings;
- add-workload and manage actions.

### Add flow

Provider selection uses searchable compact rows/cards with:

- provider mark and name;
- supported workload types;
- where recovery points live;
- required credentials/prerequisites;
- status such as available or coming later.

Do not repeat generic marketing paragraphs for every provider.

## 7. Destinations

### Index

Each destination record shows:

- name/type;
- validation state and last successful validation;
- affected workloads and policies;
- verified-copy count and current failures;
- footprint/cost where authorized;
- immutability/air-gap evidence if supported and configured.

### Detail

Sections:

- Health and latest validation probe
- Workloads/policies using this destination
- Recent copy outcomes
- Capacity, footprint, lifecycle, and cost
- Immutability/retention evidence
- Configuration and credentials metadata without secret values
- Pause/delete impact summary

## 8. Activity

### Job

Answer who or what changed, when, and what object was affected.

Recommended columns:

- time;
- event/category;
- object;
- message;
- actor;
- details action.

Move error codes and long raw-safe messages into an expandable detail row or event detail
page. Replace `n/a` with omitted fields or `Not recorded` when that distinction matters.

Mobile events are a vertical timeline/record list, not a horizontally scrolled table.

## 9. Settings

Desktop uses a narrow settings navigation column and one content pane. Mobile uses a
labelled section selector/drawer. Each page has one save boundary and a sticky action bar
only when edits are dirty.

- Personal/Profile: identity and timezone.
- Personal/Password: password change with clear success/failure.
- Personal/MFA: enrollment, verification, recovery guidance, revoke.
- Workspace/General: name and workspace-level behavior.
- Workspace/Notification policy: defaults and delivery semantics.
- Workspace/Channels: email configuration status, Slack, Telegram.
- Access/Members: memberships and roles.
- Access/Invitations: sent and received invites.
- Access/Roles and groups: permissions and workload scope.

Do not use long modal forms for group/role management on mobile; use route-backed create
and edit pages or a full-height accessible drawer.

## 10. Component and content behavior

### Loading

- Skeleton only when layout is known and delay is perceptible.
- Durable submitted work says `Request saved; waiting for a worker`, not generic
  `Loading... Don't refresh page.`
- Never animate a percentage when total progress is unknown.

### Success

- Action and toast use the same verb: `Policy saved` / `Destination validated`.
- A successful connection validation does not imply backup or recovery success.

### Failure

- State what failed, what remains safe, and the next deterministic action.
- Keep safe error codes in a details layer for support.
- Never ask a user to paste credentials into a chat or generic error form.

### Destructive actions

- Use explicit object name and impact.
- Show affected workloads/policies/copies.
- Separate delete-record behavior from provider-resource deletion.
- Require confirmation and an idempotency key.
- If provider outcome becomes unknown, freeze further mutation and link the active
  reconciliation operation.

## Screen-level acceptance

Every screen ships with fixtures or tests for:

- populated healthy;
- at risk/manual review;
- empty/new installation;
- restricted/no assignments;
- loading/live update;
- API failure/stale last-known state;
- long provider/workload names;
- missing optional facts;
- permission-limited actions;
- mobile, tablet, and desktop;
- keyboard, screen reader, 200% zoom, and reduced motion.
