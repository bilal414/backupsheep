# BackupSheep Brand Asset Inventory

This is the production checklist for the selected Sentinel identity.

## 1. Logo masters

Create as vector-first artwork.

| Asset | Formats | Notes |
| --- | --- | --- |
| Primary horizontal lockup | SVG, PDF, PNG, WebP | Symbol + wordmark |
| Compact horizontal lockup | SVG, PNG, WebP | Console/header use |
| Stacked lockup | SVG, PNG | Square/portrait applications |
| Symbol | SVG, PNG | Smallest recognizable mark |
| Wordmark | SVG, PNG | Horizontal constraints |
| Monochrome dark | SVG, PNG | Single-color production |
| Monochrome reverse | SVG, PNG | Dark surfaces |

PNG exports should include 1x, 2x, and 4x where raster delivery is needed.

## 2. Application icons

- favicon.ico with 16, 32, and 48 px layers;
- favicon.svg;
- favicon-16x16.png;
- favicon-32x32.png;
- apple-touch-icon 180×180;
- PWA icons 192×192 and 512×512 if/when a web manifest is used;
- GitHub repository avatar master 512×512;
- social avatar 1024×1024.

The symbol must be optically simplified at 16 and 32 px rather than relying on the full large-scale drawing.

## 3. GitHub assets

- README brand lockup;
- repository social preview 1280×640;
- architecture overview SVG;
- Source → BackupSheep → Destination → Recovery diagram;
- optional dashboard screenshot frame/template;
- contributor/community banner.

## 4. Website assets

- hero Sentinel illustration, wide desktop;
- hero Sentinel illustration, compact/mobile crop;
- control-plane architecture illustration;
- source/destination provider-grid treatment;
- recovery-path illustration;
- reliability/validation illustration;
- open-source ownership illustration;
- footer symbol;
- social share card template;
- blog/release cover template.

## 5. Product assets

- sidebar compact logo;
- auth/login lockup;
- onboarding mark;
- empty-state illustration: no sources;
- empty-state illustration: no destinations;
- empty-state illustration: no schedules;
- empty-state illustration: no runs;
- setup-complete illustration;
- provider icon container component;
- branded loading mark, only if motion is subtle and nonblocking.

Do not create playful mascot art for operational failure or restore-confirmation screens.

## 6. Documentation assets

- documentation header lockup;
- canonical architecture diagram;
- backup-flow diagram;
- restore-flow diagram;
- immutable-copy/lifecycle diagram;
- deployment diagram;
- scaling/worker diagram;
- diagram legend and icon set.

## 7. Mascot library

Create a small intentional library rather than dozens of inconsistent poses.

### Core poses

1. **Sentinel / neutral** — default brand pose.
2. **Watching the flock** — infrastructure overview.
3. **Following a return path** — recovery education.
4. **Checking a list** — onboarding/setup.
5. **At a terminal** — contributor/developer content.
6. **Holding an open-source flag/mark** — community only, used sparingly.
7. **Resting calmly** — “all configured” or quiet community moment.

### Expressions

- neutral;
- focused;
- subtle satisfied expression.

Avoid exaggerated panic, crying, angry, superhero, or childish expressions.

## 8. Social and community templates

- release announcement 1600×900;
- GitHub milestone 1600×900;
- new-provider integration card 1600×900;
- contributor thank-you card 1600×900;
- documentation/tutorial card 1600×900;
- square social card 1080×1080;
- community avatar/banner variants.

Every template should reserve a predictable area for version/provider/title text so new graphics can be produced without redesigning the composition.

## 9. Email and notification assets

- email header lockup;
- monochrome email-safe logo;
- optional tiny status icons;
- no mascot inside urgent failure email header;
- notification preview template for documentation/marketing.

Email assets should remain lightweight and work when images are blocked.

## 10. Source-file organization

Recommended structure after artwork is approved:

```text
brand/assets/
├── logo/
│   ├── master/
│   ├── svg/
│   ├── png/
│   └── webp/
├── icons/
├── mascot/
│   ├── master/
│   └── exports/
├── illustrations/
├── diagrams/
├── social/
└── templates/
```

Do not commit proprietary font files. Reference font family names and licensing/source information in documentation instead.

## 11. Export QA

Every master must be checked on:

- Wool light background;
- pure white background;
- Night background;
- GitHub light and dark UI;
- 16 px favicon;
- 32 px favicon;
- 40–48 px sidebar/navigation size;
- 320 px README width;
- large hero size;
- grayscale;
- high-DPI screen.

Check SVGs for unnecessary editor metadata and raster images for oversized file weight before production use.
