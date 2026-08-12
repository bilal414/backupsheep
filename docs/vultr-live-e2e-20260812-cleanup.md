# Vultr live E2E test report

- Run: `bs-e2e-vultr-20260812-f3b9d1a7`
- Mode: `LIVE_PROVIDER`
- Started: `2026-08-12T15:14:41.687822+00:00`
- Finished: `2026-08-12T15:14:45.078514+00:00`
- API endpoint: `https://api.vultr.com/v2`
- Credentials: supplied through `VULTR_API_KEY`; not recorded.

## Safety and baseline

Only resources created by this run were eligible for cleanup. Provider snapshots and managed-database backup metadata were deleted only after exact ownership checks; provider-managed database backups were never deleted.

```json
{
  "account": null,
  "baseline": null
}
```

## Live acceptance matrix

| ID | Result | Evidence |
|---|---|---|

## Resource ledger

| Service | Class | Provider ID | Ownership proof | Cleanup allowed |
|---|---|---|---|---|

## Cleanup

```json
{
  "errors": [],
  "pending_intents": [],
  "remaining": [],
  "status": "PASS",
  "unresolved_intents": []
}
```

## Limitations

- Celery redelivery was exercised by repeating the durable adapter operation; a physical host reboot was not performed.
- Vultr managed-database backup metadata is provider-owned; the harness never deletes it.
