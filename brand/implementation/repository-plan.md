# BackupSheep Repository Implementation Plan

This phase translates the approved identity into the codebase. It intentionally separates **brand documentation**, **master artwork**, and **production assets**.

## 1. Branch and review model

Perform brand implementation on a dedicated branch and merge through a pull request.

Recommended implementation sequence:

1. Brand documentation.
2. Master logo/mascot artwork.
3. Exported production assets.
4. Shared design tokens and font setup.
5. README/GitHub surfaces.
6. Shared console chrome.
7. Auth/onboarding.
8. Dashboard and feature screens.
9. Documentation diagrams.
10. Email/notification assets.
11. QA and release.

Do not mix unrelated backup-engine changes into the brand implementation PR.

## 2. Proposed repository structure

```text
brand/
├── README.md
├── strategy/
├── concepts/
├── guidelines/
├── assets/
│   ├── logo/
│   ├── icons/
│   ├── mascot/
│   ├── illustrations/
│   ├── diagrams/
│   └── social/
├── rollout/
└── implementation/
```

Production web assets remain under the application's static directory. `brand/assets` contains the source-of-truth exports and masters intended for reuse.

## 3. Existing production files to replace after approval

Current logo-related production assets are under:

```text
apps/console/_static/console/images/
```

Known current files include logo PNG/WebP/SVG variants and favicon assets.

Replacement plan:

- preserve existing filenames temporarily where doing so avoids template churn;
- add new explicit filenames once the new system is stable;
- update README references;
- update sidebar/header references;
- update login/auth references;
- update favicon references;
- remove legacy logo files only after a repository-wide reference search.

## 4. Shared templates

Review at minimum:

- console master template;
- authentication master/template;
- sidebar;
- header;
- footer;
- notifications;
- loading treatment;
- onboarding base template.

The objective is to move brand decisions into shared primitives instead of restyling every page independently.

## 5. CSS/Tailwind implementation

Translate the approved palette into semantic tokens.

Required semantic groups:

- background;
- elevated surface;
- text primary;
- text secondary;
- border;
- primary action;
- primary action hover;
- focus;
- success;
- warning;
- failure;
- information.

Do not mechanically replace every current `indigo-*` class with a green class. Review whether each use represents brand action, selection, information, or status.

### Important semantic distinction

**Brand accent ≠ success state.**

A selected navigation item and a completed backup must not become visually identical merely because both previously used an accent color.

## 6. Typography implementation

- Retain Inter for product UI.
- Add the selected display face only where needed for marketing/auth/onboarding if loading cost is justified.
- Prefer self-hosted or privacy-conscious font delivery for the self-hosted product; document licensing and packaging requirements before bundling any font.
- Never commit a font file to the repository unless its license explicitly permits redistribution.

## 7. README implementation

Update only after final visual assets exist.

Tasks:

- replace old logo artwork;
- update opening category statement;
- add branded architecture diagram;
- add current product screenshot if it materially helps comprehension;
- keep beta status explicit;
- preserve quick-start prominence;
- keep provider/feature details discoverable below the opening narrative.

## 8. Console implementation order

### Shared chrome

1. favicon;
2. logo;
3. sidebar selection;
4. primary buttons;
5. links;
6. focus states;
7. surfaces and borders.

### Authentication

- new lockup;
- updated product descriptor;
- restrained brand background;
- verify form contrast and autofill states.

### Onboarding

- new step header/lockup;
- Sentinel illustrations where useful;
- public-facing terminology review;
- source/destination distinction.

### Dashboard

- preserve operational information architecture;
- replace generic indigo brand accents;
- verify semantic state colors;
- add empty-state artwork only when account has no resources.

### Restore

- no mascot;
- test destructive-option hierarchy;
- verify keyboard flow;
- make copy/source/date/destination explicit;
- ensure loading and completion states are not ambiguous.

## 9. Documentation implementation

Create reusable SVG diagrams rather than exporting every diagram as raster.

Required diagrams:

- architecture overview;
- website backup flow;
- database backup flow;
- cloud snapshot flow;
- website restore flow;
- database restore flow;
- immutable-copy/lifecycle flow;
- worker/scaling topology.

Keep text in diagrams editable and accessible where the publishing system permits.

## 10. Image optimization

- SVG for marks, icons, and diagrams.
- WebP/AVIF where supported for large illustrations.
- PNG only where transparency/compatibility requires it.
- Do not ship 4K mascot artwork into the console for a 240 px empty state.
- Define responsive image sizes for website hero artwork.

## 11. Accessibility QA

Before merge:

- automated contrast scan;
- keyboard navigation through login, onboarding, dashboard, and restore;
- visible focus review;
- screen-reader labels for logo and icon-only buttons;
- status semantics checked without color;
- reduced-motion check;
- 200% browser zoom review;
- mobile touch-target review.

## 12. Visual QA matrix

Test:

- Chrome, Firefox, Safari;
- desktop and mobile widths;
- light and dark system preferences where supported;
- empty account;
- healthy account;
- failed backup state;
- active run;
- restore in progress;
- long provider/resource names;
- large numeric storage values;
- no external font/network access if the self-hosted console must remain usable offline from third-party CDNs.

## 13. Repository QA

Before removing old assets:

1. Search for every old logo filename.
2. Search for old indigo-specific brand classes.
3. Search metadata and email templates for old descriptors.
4. Search documentation screenshots for old branding.
5. Verify README image paths on GitHub.
6. Run Django checks and tests.
7. Build static assets from a clean checkout.
8. Verify Docker image build.

## 14. Release plan

Recommended release sequence:

1. Merge identity/documentation foundation.
2. Publish updated GitHub social preview and repository avatar.
3. Release website/README update.
4. Release console brand migration.
5. Publish open-source identity announcement.
6. Follow with provider/integration announcement graphics using the new system.

## 15. Definition of done

Brand implementation is complete when:

- all production logo uses reference approved masters;
- favicon works at 16 and 32 px;
- README and website share the same positioning hierarchy;
- console uses semantic brand/status tokens;
- auth and onboarding use the new identity;
- critical operational screens remain clear and mascot-free where appropriate;
- documentation diagrams use the new visual grammar;
- old logo references are removed;
- accessibility QA passes;
- application tests/builds pass;
- the brand directory contains enough guidance for a future contributor to create a new asset without guessing the system.
