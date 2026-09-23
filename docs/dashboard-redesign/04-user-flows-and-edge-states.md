# User flows and edge states

## Purpose

This document defines the interaction behavior behind the screen specifications. It is
not enough for the redesigned console to render the happy path. BackupSheep must remain
truthful when access is restricted, a worker disappears, a provider outcome is unknown,
data becomes stale, or a destructive request is retried.

These flows use the vocabulary and state grammar in
[06-data-and-state-contracts.md](06-data-and-state-contracts.md). Existing provider
behavior remains authoritative until a later implementation explicitly changes it.

## Global flow rules

1. **Commit intent before background work.** A backup, restore, retry, or validation
   request is not shown as accepted until a durable request or operation exists.
2. **Navigate by stable identity.** Operation links use a safe correlation reference,
   not a Celery task identifier or provider secret.
3. **Make uncertainty visible.** Unknown provider outcome, unavailable evidence, and
   stale read models are distinct from failure and from zero.
4. **Prevent duplicate mutation.** Repeated clicks, browser refresh, and network retries
   resolve to the existing request when the idempotency contract says they are the same.
5. **Scope before display.** Counts, rows, filters, links, exports, live updates, and
   drill-down pages use the same canonical visible-workload scope.
6. **Separate safe reads from mutations.** Viewing evidence is always distinct from
   retrying, deleting, restoring, or changing a policy.
7. **Preserve place.** Filter state lives in the URL. Returning from detail restores
   filters, sort, page, focus target, and appropriate scroll position.
8. **Explain what remains safe.** Errors say what is known, what did not happen, what may
   still be happening, and the next safe action.

## Flow 1 — first useful recovery view

### Entry conditions

- The member is authenticated.
- Workspace membership and visible workload scope have been resolved.
- The account may be new, partially configured, fully configured, or restricted.

### Main sequence

1. Open Recovery.
2. Render the shell immediately with page title and workspace/scope.
3. Load one versioned, permission-scoped overview contract.
4. Show its generation timestamp and freshness state.
5. If readiness objectives are unavailable, render the transitional evidence ledger and
   the explicit “observed facts” notice.
6. Rank current findings and durable live operations.
7. Put the safest contextual action beside the affected record.

### Branches

| Condition | Recovery response |
| --- | --- |
| No connections or workloads | Setup checklist: add connection, discover/add workload, configure protection, run first operation. |
| Connection exists, no workload | Explain that no workload has been selected; offer Add workload when permitted. |
| Workload exists, no schedule | Show Manual only or Not configured; do not call it protected. |
| Workloads exist, no completed points | Show No completed recovery point and the relevant next action. |
| Completed point exists, no objectives | Show observed artifact/copy facts; readiness is Unknown. |
| Restricted member, no assignments | Explain that no workloads are assigned; do not expose account totals or offer setup without permission. |
| Read model stale | Keep last-known values, mark every affected section As of, and expose Retry refresh. |
| Read model unavailable with no cache | Render an unavailable state, not zero-filled metrics. |

### Acceptance

- First useful content does not wait for secondary activity or cost queries.
- A restricted member cannot infer hidden workload counts from totals, empty states,
  pagination, filters, URLs, or live-update events.
- The initial screen contains an actionable or explanatory next step without requiring
  horizontal scrolling at 390px.

## Flow 2 — add a workload

### Route-based sequence

1. From Workloads or setup state, select **Add workload**.
2. Choose an existing Connection or **Add connection**.
3. Select provider/workload family in a searchable catalogue.
4. Enter or confirm connection information on its own route.
5. Validate access without persisting raw credentials into browser-visible state.
6. Discover resources or enter the resource locator required by that provider.
7. Select one or more workloads if the provider supports discovery.
8. Review:
   - connection;
   - selected resources;
   - protection capability;
   - where provider-native points live;
   - destination requirement for logical backups;
   - default/manual protection behavior.
9. Submit once with an idempotency key.
10. Land on the new workload's Configuration or Protection tab with a setup checklist.

### Rules

- Source Connections and storage Destinations are separate entry paths.
- Provider prerequisites appear before the credential form.
- Long database/server forms use progressive sections, not a viewport-height modal.
- The validation step states exactly what was tested. “Credentials accepted” is not
  “backup ready.”
- Browser back/forward preserves non-secret selections; secret values are never placed
  in query strings, local storage, telemetry, or error copy.
- Provider OAuth callbacks retain state and return to the correct workspace and step.

### Edge states

- **Validation timeout:** say validation did not finish; do not claim credentials are
  invalid. Allow a safe retry using the existing pending validation where supported.
- **Partial discovery:** show discovered resources plus an explicit partial-results
  warning. Never silently present a partial list as complete.
- **Resource already protected:** link to the existing workload instead of creating a
  duplicate.
- **Permission changes mid-flow:** preserve safe progress, block submission, explain the
  lost capability, and provide a non-mutating exit.
- **Connection created but workload selection fails:** keep the connection and offer
  Resume setup; do not create a hidden orphan without a visible recovery path.

## Flow 3 — triage a finding

### Main sequence

1. Select a record in **Act now**.
2. Open finding detail or a filtered workload/operation view.
3. Show:
   - current lifecycle state;
   - deterministic rule and severity;
   - affected visible objects;
   - first and last observed times;
   - evidence references;
   - what remains protected or unknown;
   - safe actions allowed to this member.
4. Follow the recommended action.
5. Refresh or subscribe to the finding lifecycle.
6. When evidence satisfies the resolution rule, mark the finding resolved and retain the
   lifecycle event in Activity.

### Finding behavior

- One stable fingerprint represents one current condition. Repeated observations update
  it rather than adding duplicate cards.
- A later successful operation resolves an applicable finding only when the rule's
  evidence requirement is satisfied.
- Dismissal, acknowledgement, and resolution are different concepts. Do not ship
  dismissal until its persistence and authorization semantics are defined.
- Severity color never carries the meaning alone.
- Members who cannot mutate see **View evidence**, not a disabled unexplained Retry
  button.

### Unknown provider outcome

This state has special safety behavior:

1. Mark the operation Manual review or Reconciling.
2. State that the provider may have completed the mutation.
3. Freeze any conflicting mutation for the same protected resource.
4. Link the correlation reference and reconciliation evidence.
5. Do not offer “Try again” until the backend safety contract explicitly clears it.
6. When reconciled, transition the same operation and finding; do not invent a second
   historical run.

## Flow 4 — monitor a live operation

### Main sequence

1. A user or schedule creates a durable request.
2. The UI confirms **Request saved** and links the operation.
3. Operations Live shows the persisted state and phase.
4. Incremental refresh updates only the affected row/detail regions.
5. Retry, reconciliation, partial completion, terminal success, or terminal failure is
   reflected from durable state.
6. On terminal state, focus and screen-reader announcement update without forcibly
   moving the user.

### Refresh behavior

- Prefer server events/polling against safe operation summaries, not Celery result
  backends.
- Use backoff when the page is hidden or the endpoint fails.
- Do not replace the whole table, steal focus, collapse expanded evidence, or reorder a
  focused row.
- Show the age of the last durable update.
- If live refresh stops, mark data stale while preserving the last-known record.
- Reduced-motion mode removes progress animation; the numeric/phase state still changes.

### Progress behavior

| Available evidence | Display |
| --- | --- |
| Known completed and total units | Determinate progress with phase and count. |
| Known phase, unknown total | Phase plus elapsed time; no percentage. |
| Retry scheduled | Retry time and attempt count within safe limits. |
| Reconciliation active | Reconciliation label and mutation warning. |
| Heartbeat stale | Stale update warning; do not automatically label failed. |
| Worker/server restarted | Same durable operation remains visible and resumes/reconciles. |

## Flow 5 — start an on-demand backup

1. Select **Run backup** from a workload or policy context.
2. Show a compact preflight:
   - workload;
   - operation type;
   - destination/provider behavior;
   - existing active request if present;
   - impact/cost warning when known;
   - permission.
3. Submit an idempotent request.
4. If a matching active request exists, return it and say **A matching request already
   exists**.
5. Navigate to or reveal the durable operation.
6. Preserve an obvious path back to the workload.

Do not make the button appear to complete the backup. Confirmation means the request was
saved, not that provider work succeeded.

## Flow 6 — recover a workload

Recovery is a route-backed, resumable workflow. It must not be buried in a modal inside
the workload mega-page.

### Step 1: choose a point and copy

- List eligible recovery points newest first.
- Show verification, destination/provider, age, retention/expiry, and copy availability.
- Explain why an ineligible or unverified point cannot be selected.
- If two copies are equivalent, recommend through deterministic policy, not an opaque AI
  choice.

### Step 2: preflight

Show:

- source workload and selected point;
- target and target existence;
- restore mode and overwrite behavior;
- prerequisites and credential/connection validation;
- available space or provider capacity where verifiable;
- estimated duration/cost labelled as estimates;
- current conflicting operations;
- cleanup policy;
- required confirmation.

Preflight reads must be safe and should not mutate the provider.

### Step 3: confirm

- Name the target and consequence in the confirmation.
- For overwrite or provider deletion, require typed confirmation only when it materially
  reduces risk; do not use it for routine non-destructive restores.
- Create the durable restore request with an idempotency key.
- Record requester, scope, selected point/copy, target, and confirmation facts.

### Step 4: track

Use the same operation state grammar as backup work. Show provider mutation, data
transfer, service start, assertions, and cleanup as distinct evidence stages where
applicable.

### Step 5: assert and prove

Provider completion alone is not recovery proof. Workload-specific assertions may
include:

- target exists and is reachable;
- database opens and expected schema/query checks pass;
- website/application health endpoint and content checks pass;
- file count/manifest or selected checksum checks pass;
- restored resource is isolated when rehearsal requires it;
- cleanup completed or an explicit retained-target exception exists.

Create Recovery proof only after the defined required assertions pass. Otherwise show
Restore completed, assertions failed/incomplete.

### Step 6: completion

- Present what was restored, which assertions passed, and cleanup status.
- Link evidence and Activity.
- Offer next actions such as Open workload, Download report, or Resolve incident only
  when those capabilities exist.

### Recovery edge states

| State | UI behavior |
| --- | --- |
| Selected copy disappears before submit | Stop and ask for a new selection; retain safe preflight input. |
| Target validation becomes stale | Re-run preflight before enabling confirmation. |
| Submit response lost | Re-query by idempotency/correlation reference; never blindly resubmit. |
| Provider outcome unknown | Freeze conflicting target mutations and enter reconciliation/manual review. |
| Restore complete, assertion fails | Keep operation outcome and proof outcome separate; provide failed assertion evidence. |
| Cleanup fails | Mark proof incomplete or exception per policy; show retained resource and safe cleanup action. |
| Member loses permission | Continue backend operation safely; viewer sees only what current scope allows. |

## Flow 7 — change protection

1. Open Workload Protection or a Protection policy.
2. Edit schedule, timezone, retention, destinations/copy requirement, objectives, and
   notifications in intent-based sections.
3. Preview the next three occurrences and downstream impact.
4. Validate impossible or conflicting combinations.
5. Save atomically using version/optimistic concurrency.
6. Confirm the new effective configuration and next run.
7. Record the change in Activity.

### Concurrent edit

If the policy changed after the form loaded:

- do not overwrite it silently;
- show what changed and by whom when allowed;
- offer Reload or Review differences;
- retain the user's draft locally only if it contains no secret values.

### Pause

Pausing protection must say:

- which future operations stop;
- whether existing recovery points/copies remain;
- retention/expiry implications;
- whether an in-progress operation continues;
- resulting posture/finding behavior.

## Flow 8 — manage a connection or destination

### Validate

Validation reports each supported probe separately. For a destination this may include
write, read, and delete of a dedicated harmless probe object. For a connection it may
include authentication, resource listing, and necessary capability checks.

Do not label an integration Healthy based only on saved credentials.

### Rotate credentials

1. Open an explicit Rotate credentials flow.
2. Show affected visible workloads/policies and current operation impact.
3. Accept new secrets in protected fields.
4. Validate before activation where provider behavior permits.
5. Swap atomically or retain the old credential until the new one is proven.
6. Never echo the old or new secret after submit.
7. Record a redacted audit event.

### Delete

Before deleting, show:

- exact connection/destination name;
- affected visible workloads and policies;
- hidden-impact notice if the member may act but lacks visibility to every object;
- effect on existing recovery points/copies;
- whether this deletes only BackupSheep configuration or provider resources;
- active-operation conflicts.

The default must never delete provider resources. Any future provider deletion is a
separate, explicit operation with its own safety and idempotency contract.

## Flow 9 — settings and access

- Each settings page has one save boundary and clear dirty state.
- Changing workspace context refreshes scope before new page data is requested.
- Member, role, group, and invitation flows use route-backed screens on narrow devices.
- Revoking access invalidates future reads and live subscriptions immediately; existing
  provider work continues according to backend policy.
- Empty group assignment produces a restricted empty state, not an account-wide
  fallback.
- A user cannot grant a role or scope broader than their own authorization contract
  allows.

## Cross-cutting edge-state matrix

Every page owner must fill this matrix with page-specific copy and actions before
implementation:

| State | Preserve | Display | Allowed action | Forbidden behavior |
| --- | --- | --- | --- | --- |
| Loading | Shell, route, known filters | Labelled skeleton or progress | Cancel navigation where applicable | Indefinite spinner with no context |
| Empty | Scope and filters | Why empty + relevant next step | Setup or clear filters by permission | Account-wide totals for restricted users |
| Partial | Successful records | Explicit partial-results warning | Retry missing segment | Present partial as complete |
| Stale | Last-known data | As-of time + stale cause | Retry refresh | Replace with zero/green |
| Unavailable | Safe local context | What could not be loaded | Retry/support details | Guess status |
| Permission-limited | Visible safe data | Scope note | Request access path if product supports it | Leak hidden counts/names |
| Long-running | Durable operation | Phase, elapsed, update age | View evidence | Fake percentage |
| Duplicate request | Existing operation | Matching-operation explanation | Open operation | Create another provider mutation |
| Unknown outcome | Durable evidence | Manual review/freeze | Reconcile/review only | Blind retry |
| Terminal failure | Completed evidence | Cause, safe state, next action | Allowed remediation | Erase prior successful points |
| Offline/reconnect | Last-known safe state | Connectivity and timestamp | Reconnect/retry | Queue destructive mutations silently |

## Copy patterns

Preferred:

- **Request saved. Waiting for a worker.**
- **Last updated 3 minutes ago. Live refresh is unavailable.**
- **The provider outcome is not known. Do not start another snapshot.**
- **No workloads are assigned to your access groups.**
- **Restore completed. Two required checks did not pass.**
- **Destination validation tested write and read; delete was not tested.**

Avoid:

- Active, Healthy, Protected, or Ready without naming the state axis;
- Something went wrong;
- Please try again when a duplicate or unknown mutation is possible;
- zero as a substitute for unavailable;
- success messages based only on an HTTP 200 response;
- raw exception class names as the headline.

## Flow QA requirements

For each mutating flow, tests must cover:

- double click and repeated keyboard activation;
- HTTP retry and lost response;
- browser reload and back/forward;
- two tabs submitting the same intent;
- concurrent configuration edit;
- member permission or group assignment change;
- worker restart and broker delay;
- provider success with lost local response;
- provider timeout with later reconciliation;
- long names, localized timezones, and missing optional evidence;
- keyboard-only, screen reader, reduced motion, and 200% zoom;
- mobile viewport without clipped confirmation or unreachable action.

No flow is accepted from a visual fixture alone. It requires a real permission-scoped
request path and the relevant durable-state tests.
