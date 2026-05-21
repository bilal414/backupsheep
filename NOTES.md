# Session handoff notes (tracked so they survive across sessions)

## Goal
Converting from the SaaS codebase (`bilal414/app_backupsheep_com`) to a
self-hosted / individual codebase (`bilal414/backupsheep`) so users can set it
up for their own use. **Import all functionality but remove everything
SaaS-related (billing, AppSumo, BackupSheep-hosted storage, etc.)** so users can
self-host without complicated setup.

## Working branch
`claude/resume-previous-session-YiGg4` — merged in PR #19's import-fix work
(`claude/update-requirements-ARh42`) as the base, then continued below.

## Done so far
### From PR #19 (import wiring)
1. `requirements.txt` — bumped all outdated deps to latest; pinned `setuptools<81`
   (legacy `gcloud` needs the removed `pkg_resources`).
2. Console templates: `/api/proxy/` → `/api/v1/` (17 calls, 8 files).
3. API imports: `apps.console.api.v1` → `apps.api.v1` (260 files).
4. `_tasks` imports → `apps._tasks` (50 files).

### This session
5. Added the two missing API utils (copied verbatim from the source repo, both
   self-contained — only rest_framework/django imports):
   - `apps/api/v1/utils/api_permissions.py` (`MemberPermissions`, `WebhookPermissions`)
   - `apps/api/v1/utils/api_filters.py` (`DateRangeFilter`)
6. SaaS billing removal (stripped, not ported):
   - 15 `apps/_tasks/integration/*.py` — dropped dead `CoreBilling` import (import-only).
   - `apps/api/v1/incoming/` — removed the Stripe subscription webhook
     (`APIIncomingStripe`) + its route; module kept as an empty placeholder.
   - `apps/api/v1/account/views.py` — removed `CorePlan` + `billing_sync_all`
     imports and the `sync_billing` action (no template/JS callers).
   - `apps/api/v1/callback/views.py` — removed `import stripe`, `CorePayPalCredit`
     import, and the entire `APICallbackPaypal` IPN view; removed its `callback/urls.py` route.
7. Added missing deps to `requirements.txt`: `requests-toolbelt==1.0.0`, `twilio==9.10.9`.
8. Fixed 3 wrong import paths `apps.utils.api_exceptions` →
   `apps.api.v1.utils.api_exceptions` (schedule/views, callback/views,
   backup/website/views). `ExceptionDefault` lives there and is byte-identical to
   the source repo's `apps/utils/api_exceptions.py` (which was not ported).

9. Storage models (3 unported models referenced by the API) — resolved:
   - `CoreStorageStatus` (storage/serializers.py) and `CoreStorageDefault`
     (schedule/serializers.py) were **dead imports** (never used) → dropped.
   - `CoreStorageBS` ("BackupSheep storage" — BS-hosted buckets/NAS with internal
     `move_node_hel_*`/`fsn_*` datacenter flags) is **SaaS** and was never ported.
     Removed the two API modules built on it: `apps/api/v1/storage/bs/` and
     `apps/api/v1/storage/backupsheep/`, plus their includes in `storage/urls.py`.

## Verification status
AST import check over `apps/api/v1` (all level-0 `from apps... import`, checking
module file + top-level symbol existence): **0 missing modules, 0 missing
symbols** across 1179 imports. The ported API import graph is fully resolved.
NOT yet run: full `python manage.py check`/`runserver` (needs deps installed +
a real `.env`).

## Next steps
1. Full `python manage.py check` on a **python3.12** venv (`/usr/bin/python3.12`;
   Django 6 requires py>=3.12) with `pip install -r requirements.txt` + a real
   `.env` (see `.env_sample`). PyPI is reachable in this env.
2. Remaining SaaS-storage leftovers OUTSIDE the API URLconf (don't block API
   import, but break celery): `CoreStorageBS` is still imported in
   `apps/_tasks/integration/storage/backblaze_b2_old.py`,
   `apps/_tasks/integration/backup/incremental_restic.py`,
   `apps/_tasks/helper/tasks.py`. Strip these (SaaS storage migration logic).
3. Console UI (`apps/console/...`) likely still has a "BackupSheep storage"
   setup page/links pointing at the removed `bs`/`backupsheep` endpoints — audit
   and remove those too.
4. Broader AppSumo removal (e.g. the commented appsumo block + `UtilAppSumoCode`
   in `apps/api/v1/account/views.py`).

## How to verify imports resolve (no DB / no deps needed)
Run an `ast`-based script over `apps/api/v1` checking each level-0 `ImportFrom`
target module + symbol exists as a first-party file/top-level name.
