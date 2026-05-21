# Session handoff notes (gitignored — local scratch)

## Goal
Converting from the SaaS codebase (`bilal414/app_backupsheep_com`) to a
self-hosted / individual codebase (`bilal414/backupsheep`) so users can set it
up for their own use. **Remove everything SaaS-related (billing, AppSumo, etc.).**

## Working branch
`claude/update-requirements-ARh42` (pushed through commit `a88c2d1`)

## Done so far
1. `requirements.txt` — bumped all outdated deps to latest; pinned `setuptools==80.10.2`
   (`<81`) because legacy `gcloud` needs the removed `pkg_resources`.
   - NOTE: missing-from-requirements (used in code): `requests_toolbelt`, `twilio`.
2. Console templates: `/api/proxy/` → `/api/v1/` (17 calls, 8 files).
3. API imports: `apps.console.api.v1` → `apps.api.v1` (260 files). The API was
   moved out of console during the port; code lives in `apps/api/v1/`.
4. `_tasks` imports → `apps._tasks` (50 files). All imported symbols verified to
   exist EXCEPT `billing_sync_all` (SaaS billing — to be removed, not ported).

## Access note
- GitHub `get_file_contents` is blocked unless the SESSION allowlist includes the
  repo. `app_backupsheep_com` must be allowlisted BEFORE the session starts.
- `search_code` works cross-repo but returns only truncated fragments.

## Next steps
1. Copy verbatim from `app_backupsheep_com` (NOT SaaS — needed by the API):
   - `apps/console/api/v1/utils/api_permissions.py` → `apps/api/v1/utils/api_permissions.py`
     (`MemberPermissions` — DRF permission, tenant isolation; do NOT guess)
   - `apps/console/api/v1/utils/api_filters.py` → `apps/api/v1/utils/api_filters.py`
     (`DateRangeFilter` — extends `BaseFilterBackend`)
2. SaaS/billing removal (strip, don't port):
   - `billing_sync_all` (original: `apps/console/api/v1/_tasks/helper/tasks.py`,
     depends on `CoreBilling` from `apps.console.billing.models`).
   - `CoreBilling` / `console.billing` referenced in 18 files in this repo
     (e.g. `apps/api/v1/incoming/views.py`, `apps/api/v1/account/views.py`,
     `apps/api/v1/callback/views.py`, several `apps/_tasks/integration/*.py`).
   - Map every SaaS/billing reference first, then remove in reviewable chunks.
3. After the above, attempt to boot the app (Django `check` / `runserver`) on
   Python 3.12 venv; Django 6 requires py>=3.12.

## How to verify imports resolve (no DB needed)
Run a small `ast`-based script over `apps/api/v1` checking each `ImportFrom`
target module/symbol exists. (Used previously to confirm `_tasks` symbols.)
