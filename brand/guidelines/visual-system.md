# BackupSheep Visual System

## 1. Creative direction

The visual system is based on **The Sentinel Sheep**: a calm, geometric guardian overseeing distributed infrastructure.

The system must balance:

- operational seriousness;
- open-source approachability;
- memorable character;
- high information density in the console;
- excellent dark and light mode behavior;
- accessibility.

The mascot is not the interface. Brand character should be concentrated in the mark, marketing, onboarding, documentation, empty states, community material, and selected illustrations.

---

## 2. Logo system specification

Final master artwork should include:

1. **Primary horizontal lockup** — symbol + BackupSheep wordmark.
2. **Compact horizontal lockup** — reduced spacing for navigation and README use.
3. **Stacked lockup** — symbol above wordmark for square/portrait placements.
4. **Symbol only** — repository avatar, favicon, app icon, social avatar.
5. **Wordmark only** — constrained horizontal placements.
6. **Monochrome positive** — dark mark on light background.
7. **Monochrome reverse** — light mark on dark background.

### Symbol construction requirements

- Geometric sheep silhouette/head.
- Minimal internal detail.
- Recognizable at 16×16.
- No gradients required for recognition.
- No text embedded in symbol.
- No literal cloud, database, padlock, shield, floppy disk, or server-rack glyph.
- Rounded geometry should feel controlled, not bubbly.
- Expression neutral/alert rather than smiling cartoon.

### Clear space

Use the height of one ear or approximately 20% of symbol width as minimum clear space around the lockup. No provider logo, headline, border, or UI element should enter this zone.

### Minimum sizes

- Symbol digital: 16 px absolute minimum; 24 px preferred.
- Horizontal lockup digital: 96 px width minimum.
- Print lockup: 24 mm width minimum.

At sizes below the preferred threshold, remove fine internal features rather than scaling detail until it becomes noisy.

---

## 3. Color system

The proposed palette intentionally moves BackupSheep away from generic indigo SaaS styling.

### Core brand colors

| Token | Hex | Role |
| --- | --- | --- |
| Night | `#111827` | Primary dark foundation, headings, dark surfaces |
| Night Deep | `#080D14` | Hero/footer/high-contrast dark background |
| Wool | `#F7F4EC` | Warm primary light background |
| Wool White | `#FFFDF8` | Cards and high-light surfaces |
| Meadow | `#27AE78` | Primary brand accent and interactive emphasis |
| Meadow Dark | `#167A53` | Accessible accent text/hover on light backgrounds |
| Sky | `#5AA7C8` | Secondary informational accent |
| Stone | `#667085` | Secondary text |

### Operational colors

Operational semantics must not depend on the brand accent alone.

| Meaning | Suggested value | Use |
| --- | --- | --- |
| Success | `#16835B` | Completed backup/restore |
| Warning | `#B7791F` | Waiting, partial attention, degraded state |
| Danger | `#C2414B` | Failed run, destructive action |
| Info | `#3579A8` | Informational state |

### Color principles

1. Brand green does not automatically mean “success.” Context and icon/label must distinguish brand actions from successful run state.
2. Never encode backup status by color alone.
3. Warm Wool surfaces should replace sterile pure-gray expanses in marketing; dense console tables may remain neutral for legibility.
4. Dark mode should use Night/Deep foundations rather than pure black.
5. Provider brand colors belong only to provider identity marks, not to surrounding BackupSheep UI chrome.

---

## 4. Typography

### Recommended system

**Display / marketing:** Manrope or a similarly engineered humanist/geometric sans.

**Interface / documentation:** Inter.

**Technical/code:** system monospace stack.

Manrope adds a recognizable headline voice while Inter preserves the current product's excellent interface legibility and minimizes migration cost.

### Hierarchy

- Display XL: 64–72 px desktop, tight tracking, 700 weight.
- H1 product: 30–36 px, 700.
- H2: 24–30 px, 650–700.
- H3: 18–20 px, 650.
- Body marketing: 18–20 px, 400–500.
- Body UI: 14–16 px, 400–500.
- Labels: 12–13 px, 600.
- Data values: tabular numerals where supported.

### Typography principles

- Sentence case by default.
- Uppercase only for small eyebrow labels and status microcopy.
- Avoid excessive tracking in body copy.
- Avoid monospace as a branding gimmick.
- Keep technical values, IDs, commands, paths, and code visually distinct.

---

## 5. Shape language

The shape system combines technical geometry with restrained softness.

- Cards: 12–16 px radius.
- Buttons/inputs: 8–10 px radius.
- Pills: full radius only for statuses/tags.
- Diagram nodes: rounded rectangles/circles with consistent stroke.
- Illustration wool motif: scalloped groups of circles, simplified heavily.
- Avoid excessive glassmorphism, floating blobs, and gradient mesh backgrounds.

The visual impression should be **stable, quiet, and deliberate**.

---

## 6. Iconography

Use simple outline icons with consistent 1.5–2 px optical stroke.

Custom brand icons should cover:

- source;
- destination;
- backup run;
- restore;
- schedule;
- retention;
- protected copy;
- immutable retention;
- activity log;
- team/client group.

Do not redraw third-party provider logos into the BackupSheep icon style. Preserve official provider marks inside a consistent neutral container.

---

## 7. Illustration system

### Primary illustration language

Abstract infrastructure scenes featuring:

- Sentinel mascot;
- small protected-resource nodes;
- paths to destinations;
- archive layers;
- return/recovery paths;
- restrained status markers.

### Illustration modes

**Hero mode:** high polish, larger mascot, minimal product metaphor.

**Documentation mode:** simplified line diagrams, little or no mascot.

**Empty-state mode:** small friendly scene with one clear action.

**Community mode:** most expressive mascot treatment.

### Never use mascot illustration for

- destructive confirmation;
- failed backup alert;
- failed restore alert;
- credential/security warning;
- urgent operational incident.

Those contexts should prioritize clarity.

---

## 8. Photography

BackupSheep does not need stock photography as a core brand device.

If photography is used for founder/community stories, prefer real people, workspaces, infrastructure, and events. Do not use generic server-room photography, hooded-hacker imagery, disaster scenes, or staged cybersecurity visuals.

---

## 9. Diagram system

Architecture and product-flow diagrams are a major brand surface.

Canonical flow:

**Sources → BackupSheep → Destinations → Recovery**

Rules:

- Sources use neutral outlined containers.
- BackupSheep is the visually strongest node.
- Destinations use consistent provider containers.
- Solid path = active data/operation flow.
- Dotted return path = recovery path.
- Brand Meadow highlights control-plane actions.
- Operational state colors are used only when the diagram represents actual state.
- Keep provider count examples small enough to scan.

Mermaid diagrams in the README should eventually be styled or supplemented with a branded static/SVG diagram for social and documentation use.

---

## 10. Motion

Motion should reinforce quiet vigilance and return.

Recommended behaviors:

- subtle path tracing from source to destination;
- a completed copy settling into place;
- a return path reversing direction for restore;
- small status pulse while a run is active;
- mascot blink/head turn only in marketing or onboarding.

Avoid bouncing sheep, confetti on routine backups, elastic UI motion, or dramatic alarm animation.

Respect `prefers-reduced-motion`.

---

## 11. Console application

The console should remain an operations product.

Apply the identity through:

- new logo lockup;
- Night/Meadow/Wool token system;
- selected navigation treatment;
- buttons and focus states;
- headings;
- status components;
- branded empty states;
- small onboarding illustrations;
- architecture/provider-selection graphics.

Do not turn every card into a branded surface. Most data-heavy components should remain quiet.

### Dashboard

- Keep operational pulse first.
- Brand accent for primary action and navigation selection.
- Operational colors for run status.
- Night panel can be used for “Next up” or recovery readiness summaries.
- Add mascot only when the dashboard has no configured resources.

### Restore UI

Use Night/Wool neutrals, clear warnings, explicit source/backup/destination labels, and danger color only for destructive options. No mascot.

---

## 12. Accessibility

- Target WCAG 2.2 AA contrast for text and interactive controls.
- Visible keyboard focus on every interactive element.
- Status always includes text/icon in addition to color.
- Logo has text alternative “BackupSheep.”
- Decorative mascot artwork uses empty alt text.
- Avoid text baked into raster illustrations.
- Motion honors reduced-motion preferences.
- Minimum touch target approximately 44×44 CSS px where practical.

---

## 13. Dark mode

Dark mode is a first-class expression of the brand.

- Background: Night Deep.
- Elevated surface: Night.
- Primary text: warm near-white.
- Secondary text: cool/warm gray with AA contrast.
- Brand Meadow becomes slightly lighter for contrast on dark backgrounds.
- Provider marks should use official dark-mode variants where available or neutral white containers.

The sheep symbol should have a purpose-built reverse version rather than a naive inversion.
