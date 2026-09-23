# Recovery Ledger design system

## Direction

The new console should feel like a calm recovery operations ledger: precise, durable,
and evidence-led. Its character comes from ordered relationships, disciplined density,
clear language, and a small number of deliberate visual signals—not from dark-theme
theatre, decorative diagrams, or another grid of rounded SaaS cards.

Three words guide every choice:

- **Trustworthy:** claims are visibly tied to evidence and time.
- **Operational:** priority, sequence, scope, and next action are obvious.
- **Human:** technical facts are translated without hiding uncertainty.

The signature element is the Recovery Ledger, a ruled matrix connecting recovery point,
verified copies, isolation/immutability, and recovery proof. Other surfaces should
support that structure rather than compete with it.

## Reference mood

Think:

- a carefully typeset incident ledger;
- high-quality scientific equipment with readable labels;
- paper-white operating surfaces inside a warm gray workspace;
- ink, evidence blue, verified teal, restrained amber, and incident red;
- compact timestamps and identifiers in a utility mono face.

Do not imitate:

- a generic analytics dashboard with four KPI cards;
- a black network-operations screen with neon accents;
- newspaper/broadsheet decoration;
- luxury cream-and-serif branding;
- glassmorphism, gradients, glowing graphs, or orbit visualizations;
- playful mascots inside failure and recovery workflows.

## Color

### Foundation palette

| Token | Value | Use |
| --- | --- | --- |
| Wool 50 | `#F4F7F6` | Application canvas. |
| Paper 0 | `#FFFFFF` | Primary working surface. |
| Ink 950 | `#17201F` | Primary text and strongest rules. |
| Ink 800 | `#2C3937` | Secondary headings. |
| Ink 650 | `#53615F` | Secondary text that still meets contrast. |
| Ink 500 | `#707D7B` | Large/secondary metadata only after contrast verification. |
| Rule 200 | `#D7DFDD` | Section and row dividers. |
| Rule 100 | `#E8EEEC` | Subtle internal dividers and hover boundaries. |

### Semantic palette

| Token | Value | Meaning |
| --- | --- | --- |
| Evidence blue | `#245F88` | Selected/navigation state, links, evidence/info. |
| Verified teal | `#0F6B58` | Verified evidence or completed contract. |
| Attention amber | `#92520A` | Degraded, overdue, retrying, or user attention. |
| Incident red | `#A43A3A` | Failed, blocked, destructive, or critical risk. |
| Unknown slate | `#53615F` | Unknown, unavailable, or not configured. |

Against white, the proposed ink, blue, teal, amber, and red foregrounds all exceed a
4.5:1 normal-text contrast target. Implementation must re-check every derived
background/border combination rather than assuming a base color guarantees compliance.

### Color rules

- Color is never the only state signal. Pair it with a shape/icon and plain-language
  label.
- Green/teal means a specific verified contract, not generic “active.”
- Blue means evidence, selection, or information—not success.
- Amber includes retry, overdue, partial, and attention; copy must disambiguate them.
- Red is reserved for failures, critical risks, blocked operations, and destructive
  controls.
- Unknown and unavailable are visible neutral states, never faded until unreadable.
- Provider brand colors may appear only inside provider marks.
- Dark mode is out of scope for the first delivery. Do not create untested automatic
  color inversion.

## Typography

### Proposed families

- **Instrument Sans:** interface text, headings, controls, labels, and explanatory copy.
- **IBM Plex Mono:** timestamps, durations, counts in ledger cells, safe identifiers,
  phases, and error codes.
- **System fallbacks:** use a stable sans/monospace stack while font assets load or if
  local font files are unavailable.

Implementation requirements:

- self-host pinned WOFF2 subsets;
- retain license files and attribution in the repository;
- preload only the most-used normal UI face;
- use `font-display: swap`;
- never rely on Google Fonts or another runtime CDN;
- verify tabular numerals and long Urdu/non-Latin fallback behavior even though the
  initial console copy is English.

### Scale

| Role | Desktop | Narrow | Weight / line height |
| --- | --- | --- | --- |
| Page title | 28px | 24px | 650 / 1.2 |
| Operational headline | 22px | 20px | 620 / 1.3 |
| Section title | 15px | 15px | 650 / 1.35, slight tracking |
| Body | 14px | 14px | 450 / 1.5 |
| Dense row | 13px | 14px | 450 / 1.45 |
| Label | 12px | 12px | 650 / 1.35, limited uppercase |
| Utility data | 12–13px | 12–13px | 500 / 1.4, mono |

Rules:

- Use sentence case. Uppercase is limited to short section/group labels.
- Do not use ultra-light text weights.
- Avoid more than three visual type levels in one module.
- Counts use tabular numerals. Durations include units.
- User-created names wrap; identifiers wrap anywhere or truncate with an accessible full
  value and a deliberate copy action.

## Layout

### Shell

| Range | Navigation | Content behavior |
| --- | --- | --- |
| 1440px and wider | 256px fixed column | Max readable working width around 1480px; ledger may use full available width. |
| 1180–1439px | 248px fixed column if content remains usable | Reduce gutters before reducing data density. |
| Below about 1180px | Off-canvas drawer | Full-width content; no icon-only rail. |
| 768–1179px | Drawer | Two-column modules may remain where facts fit. |
| Below 768px | Drawer | One-column labelled records; no desktop table forced into viewport. |

Breakpoints are behavior thresholds, not device labels. Test at widths just above and
below each threshold and at 200% zoom.

### Page geometry

- Desktop page gutter: 32px; tablet: 24px; narrow: 16px.
- Maximum prose/form width: about 720px.
- Data surfaces may fill the page.
- Main section spacing: 32px desktop, 24px narrow.
- Internal row padding: 12–16px.
- Keep vertical rhythm on an 8px base with 4px adjustments for dense labels.
- Do not center the primary dashboard in a narrow marketing-style column.

### Surfaces

There are three levels:

1. **Canvas:** Wool background.
2. **Working surface:** white with one-pixel rule, usually contiguous across related
   modules.
3. **Raised transient:** menu, popover, drawer, or modal with a restrained shadow.

Persistent dashboard modules generally do not need shadows. Borders and spacing carry
structure. Use a 6–8px radius for working surfaces and controls; 12px is reserved for
larger overlays. Avoid pill containers except compact status/filter tokens.

## The Recovery Ledger

### Anatomy

1. Section header with scope and evidence timestamp.
2. Column headers naming evidence stages.
3. Posture-band or workload rows.
4. Ledger cells with count/state, evidence age, and drill-down affordance.
5. Inline objective/unavailable notice when the full posture contract is absent.
6. Accessible explanation or details for each rule.

### Visual behavior

- Strong horizontal rules connect the evidence sequence.
- A small directional connector may appear between stages, but the table remains
  understandable without it.
- The posture label anchors each row; evidence stages read left to right.
- Verified cells receive a subtle teal edge/marker, not a full green wash.
- Risk cells use a red/amber marker and text; unknown uses a neutral hatch/icon only if
  that pattern survives high contrast and does not reduce readability.
- Hover/focus reveals that a cell is a link; the entire interactive hit area is at least
  the minimum target size.
- At narrow widths, transpose the matrix into an evidence chain per posture summary or
  workload. Do not horizontally scroll the primary recovery answer.

### Evidence cell content

Preferred order:

1. state/count;
2. short label;
3. age or as-of time;
4. optional details affordance.

Never put an unlabeled score, percentage, sparkline, or decorative progress ring in a
cell.

## Core components

Future agents should implement these as reusable Django partials, template tags, or
small behavior modules, then render all states in an internal component gallery.

### 1. Application shell

- product mark/lockup;
- grouped navigation;
- active route;
- workspace/scope;
- contextual primary action;
- member menu;
- accessible narrow-screen drawer;
- skip link and main landmark.

### 2. Page header

- route title;
- optional operational description;
- freshness/scope metadata;
- one primary and optional secondary action;
- never duplicates a second identical H1 below it.

### 3. State badge

Inputs:

- canonical state axis;
- state code;
- presenter-provided label/tone/icon;
- optional description.

Output is never based on ad hoc substring matching in the template.

Shapes should help distinguish axes:

- connection/configuration: outlined lozenge;
- live operation: dot + label;
- recovery posture: left-edge marker + label;
- severity: compact diamond/triangle icon + label.

### 4. Finding record

- severity;
- lifecycle state;
- headline;
- affected object;
- observation age;
- evidence/rule summary;
- permission-aware action.

The compact record works in both the Recovery rail and a full finding list.

### 5. Operation record

- workload and operation type;
- durable state and phase;
- determinate/indeterminate-safe progress;
- update age;
- retry/reconciliation summary;
- open action.

One semantic component renders desktop row and narrow labelled-record variants from the
same presenter.

### 6. Evidence chain

- point;
- copy/copies;
- isolation/immutability;
- proof;
- rule/goal;
- per-stage timestamps and states.

The chain may render inside the dashboard or workload detail without changing its
meaning.

### 7. Data table / record list

Desktop:

- true table markup with caption or accessible name;
- sortable headers with current direction;
- sticky header only when it does not obscure focused content;
- row selection only if a batch workflow genuinely exists;
- pagination and filters in URL.

Narrow:

- labelled records preserving essential columns;
- no ambiguous unlabeled value stack;
- one obvious primary action and a More menu;
- no reliance on a 1,000px horizontal scroll area.

### 8. Empty, unavailable, stale, and restricted states

These are separate components or variants with consistent iconography, copy order, and
action rules. A zero-result filtered list is not the same as a new workspace or an API
failure.

### 9. Overlay primitives

- menu/listbox;
- confirmation dialog;
- form dialog only for short contained edits;
- drawer;
- tooltip for supplemental, never essential, content;
- toast/live-region notice.

One behavior layer owns focus trap, Escape, click outside, background inerting, scroll
lock, ARIA state, focus restore, and nesting rules.

### 10. Form primitives

- label, hint, control, error, and status are programmatically related;
- secrets support show/hide and password-manager/autocomplete semantics;
- destructive controls are visually separated;
- long provider setup uses routes/sections, not a single tall modal;
- save bars appear only when dirty and never cover the focused field.

### 11. Evidence details

A disclosure or detail page for:

- safe codes;
- correlation reference;
- rule definition;
- source timestamps;
- copy/assertion results;
- redacted technical message;
- links to related operation/activity.

It must not expose raw credentials, provider response payloads, hostnames hidden by
scope, or unsafe logs.

## Controls and interaction states

Every control has:

- default;
- hover where hover exists;
- focus visible;
- active/pressed;
- disabled with a programmatic state and nearby reason where material;
- loading/committing;
- success/failure response.

Buttons:

- Primary: evidence blue fill, white text.
- Secondary: paper fill, ink text, rule border.
- Quiet: text/icon with visible hover/focus surface.
- Destructive: incident red, used only at final confirmation or clear destructive
  action.

Avoid multiple primary buttons in a row. Use verb + object labels such as **Add
destination**, **Review evidence**, and **Run backup**. Avoid generic **Submit**,
**Continue** when the consequence can be named, and icon-only controls without a stable
accessible name.

## Icons and imagery

- Use one locally bundled, coherent outline icon family at 16, 20, and 24px.
- Reuse an existing repository-compatible family if it covers the required meanings;
  otherwise document and license the selected set before adoption.
- Status icons use familiar forms: check, clock, pause, warning triangle, error, question,
  and reconciliation arrows.
- Never use emoji or arbitrary Unicode glyphs as operational icons.
- Provider marks remain supplemental to provider names.
- Produce a true square BackupSheep mark plus a horizontal lockup. Never force the wide
  current wordmark into a square.
- Normalize provider assets to bounded dimensions, remove unnecessary embedded raster
  payloads where feasible, set intrinsic size, lazy-load below the fold, and preserve a
  text fallback.
- No stock illustration is needed for the operating console.

## Charts and visualization

Default to tables, sequences, and exact comparisons. A visualization is justified only
when it makes trend or distribution easier to understand.

Allowed later:

- recovery-point freshness distribution over a defined interval;
- operation duration trend by workload/type;
- destination footprint/cost trend;
- finding open/resolved trend.

Requirements:

- accessible data table or text summary;
- defined denominator and time window;
- no red/green-only encoding;
- no 3D, decorative donut, radial gauge, or opaque score;
- empty/unavailable distinction;
- labels usable at 200% zoom.

No chart is required for the first Recovery dashboard.

## Motion

Motion is functional and sparse:

- drawer and menu transition: roughly 120–180ms;
- focus movement: no animation;
- live operation progress: only when progress is real;
- refreshed values: subtle highlight at most, with a screen-reader announcement only
  for material changes;
- success/error toast: no bouncing or celebratory movement.

With `prefers-reduced-motion: reduce`:

- eliminate transforms and progress shimmer;
- make drawer/menu state changes immediate;
- retain clear static progress and state labels;
- never depend on animation to indicate completion or failure.

## Accessibility contract

Release target: WCAG 2.2 AA.

Required:

- skip link to main content;
- one H1 and a logical heading outline;
- visible, unobscured focus indicator at least two CSS pixels thick with strong local
  contrast;
- at least 24×24 CSS pixel pointer targets where the WCAG exception does not apply, with
  40–44px preferred for primary narrow-screen controls;
- keyboard access and logical tab order;
- drawer/dialog focus containment and restoration;
- closed overlays removed from the focus and accessibility trees;
- current route, expanded state, selected state, sort direction, and live-update state
  expressed programmatically;
- status never communicated by color alone;
- form errors summarized and attached to fields;
- live announcements are concise and do not repeat on every poll;
- 200% zoom without loss of content or function;
- reflow at 320 CSS pixels except genuinely two-dimensional secondary data tables;
- OS high-contrast and reduced-motion verification;
- meaningful page titles and landmarks.

Do not use a tooltip to satisfy an accessible name or to contain essential recovery
facts.

## Content voice

Tone is calm, specific, and non-blaming.

Structure operational messages as:

1. state;
2. observed evidence and time;
3. impact/what remains safe;
4. next safe action;
5. technical detail link.

Examples:

- **Two destination copies could not be verified.** The provider recovery point is still
  available. Last checked 8 minutes ago. **Review copy evidence.**
- **This view is 14 minutes old.** Live refresh failed; displayed values have not been
  replaced. **Retry refresh.**
- **The provider outcome is unknown.** Another snapshot could create a duplicate.
  **Review reconciliation evidence.**

Avoid “Oops,” blame, vague reassurance, and artificial urgency.

## Component gallery and token governance

Slice 1 must include a development-only/internal gallery containing:

- every token and type style;
- shell at representative breakpoints;
- every button/control state;
- all state axes and labels;
- Recovery Ledger full/transitional/narrow variants;
- finding and operation records;
- tables and narrow records;
- form fields with hint/error/disabled/loading;
- empty, restricted, stale, unavailable, and partial states;
- menus, dialogs, drawers, toasts;
- long names, missing data, and high-count fixtures.

Token and presenter changes require gallery review plus affected integration tests.
Agents must not add one-off hexadecimal colors, shadows, radii, z-indexes, status labels,
or animation timings in page templates.

## Visual review checklist

- Is the Recovery Ledger the strongest structure without becoming decoration?
- Does the first viewport show risk/action before secondary metrics?
- Can every green/teal claim name its evidence contract?
- Are connection, protection, operation, and recovery states visually distinct?
- Does the layout remain coherent with 1,000 workloads and with none?
- Do long names and localized timestamps wrap safely?
- Does narrow layout preserve meaning without horizontal scrolling?
- Are stale, partial, unknown, and restricted states as deliberate as success?
- Is focus always visible and unobscured?
- Does the interface remain usable with fonts/images/CDNs unavailable?
- Does every page still look like BackupSheep without relying on a giant logo?

If the answer depends on a screenshot rather than a named component, state contract, or
acceptance check, the design is not implementation-ready.
