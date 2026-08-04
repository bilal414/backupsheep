# Vultr live E2E test report

- Run: `bs-vultr-e2e-20260804133752-91b44d`
- Mode: `LIVE_PROVIDER`
- Started: `2026-08-04T13:37:52.959308+00:00`
- Finished: `2026-08-04T13:59:36.869432+00:00`
- API endpoint: `https://api.vultr.com/v2`
- Credentials: supplied through `VULTR_API_KEY`; not recorded.

## Safety and baseline

Only resources created by this run were eligible for cleanup. Provider snapshots and managed-database backup metadata were deleted only after exact ownership checks; provider-managed database backups were never deleted.

```json
{
  "account": {
    "acl_count": 16,
    "authenticated": true
  },
  "baseline": {
    "collisions": {
      "backups": [],
      "block_snapshots": [],
      "blocks": [],
      "databases": [],
      "instances": [],
      "object_storages": [],
      "snapshots": []
    },
    "counts": {
      "backups": 0,
      "block_snapshots": 0,
      "blocks": 5,
      "databases": 0,
      "instances": 0,
      "object_storages": 0,
      "snapshots": 0
    }
  }
}
```

## Live acceptance matrix

| ID | Result | Evidence |
|---|---|---|
| VUL-04 | **PASS** | `{"local": {"backup_id": 25, "status": "Complete"}, "provider": {"matches": 1, "snapshot_id": "f9d75d31-3332-497a-a19b-ffa15003cc9d", "source_field_omitted": true, "state": "complete"}, "status": "PASS"}` |
| VUL-06-instance | **PASS** | `{"provider_snapshot_count": 1, "status": "PASS"}` |
| VUL-07 | **PASS** | `{"local": {"phase": "complete", "restore_id": 31, "status": "Complete"}, "provider": {"matches": 1, "restore_id": "e13e21a1-141c-4263-baf7-3ca15b609537", "status": null}, "status": "PASS"}` |
| VUL-05 | **PASS** | `{"local": {"backup_id": 26, "status": "Complete"}, "provider": {"matches": 1, "snapshot_id": "b67ac17d-f3bb-4edc-ae3d-0de8fed83428", "state": "COMPLETE"}, "status": "PASS"}` |
| VUL-08-block | **PASS** | `{"local": {"phase": "complete", "restore_id": 32, "status": "Complete"}, "provider": {"matches": 1, "restore_id": "85226034-8c23-4535-a01b-6342be6e0dbc"}, "status": "PASS"}` |
| VUL-09 | **PASS** | `{"provider": {"automatic_backup_count": 0, "read_only": true}, "status": "PASS"}` |
| VUL-10 | **PASS** | `{"local": {"first_identity": ["\"2f03acb9576d5e75292be7faf07e1b2e\"", null, "bs-vultr-e2e-20260804133752-91b44d/bs-vultr-e2e-20260804133752-91b44d-file-backup.zip"], "first_metadata": {"etag": "\"2f03acb9576d5e75292be7faf07e1b2e\"", "object_key": "bs-vultr-e2e-20260804133752-91b44d/bs-vultr-e2e-20260804133752-91b44d-file-backup.zip", "sha256": "1d1febf7433b2802c40a1153669e890025ffc9bbc03e2a038ae55e19994d2390", "size_bytes": 42, "version_id": null}, "second_identity": ["\"2f03acb9576d5e75292be7faf07e1b2e\"", null, "bs-vultr-e2e-20260804133752-91b44d/bs-vultr-e2e-20260804133752-91b44d-file-backup.zip"], "second_metadata": {"etag": "\"2f03acb9576d5e75292be7faf07e1b2e\"", "object_key": "bs-vultr-e2e-20260804133752-91b44d/bs-vultr-e2e-20260804133752-91b44d-file-backup.zip", "sha256": "1d1febf7433b2802c40a1153669e890025ffc9bbc03e2a038ae55e19994d2390", "size_bytes": 42, "version_id": null}, "sha256": "1d1febf7433b2802c40a1153669e890025ffc9bbc03e2a038ae55e19994d2390", "size_bytes": 42, "status": 3, "status_display": "Upload Complete", "storage_point_id": 18}, "provider": {"bucket": "bs-vultr-e2e-20260804133752-91b44d-bucket", "etag": "\"2f03acb9576d5e75292be7faf07e1b2e\"", "key": "bs-vultr-e2e-20260804133752-91b44d/bs-vultr-e2e-20260804133752-91b44d-file-backup.zip", "version_id": null}, "status": "PASS"}` |
| VUL-11 | **PASS** | `{"local": {"backup_id": 5, "marker": "vultr-db:a0284c26-315a-4157-b78b-c47d77cbe001:2026-08-04", "status": "Complete"}, "provider": {"provider_backup_id": "2026-08-04", "provider_status": "complete", "source_database_id": "a0284c26-315a-4157-b78b-c47d77cbe001"}, "status": "PASS"}` |
| VUL-12 | **PASS** | `{"local": {"marker": "bs-restore-2bc8976e67c147279c0f", "restore_id": 3, "status": "Complete"}, "provider": {"matching_targets": 1, "restore_id": "2663ab6a-3a0d-41e7-be06-12012a78c25f", "source_id": "a0284c26-315a-4157-b78b-c47d77cbe001", "source_label_unchanged": true}, "status": "PASS"}` |

## Resource ledger

| Service | Class | Provider ID | Ownership proof | Cleanup allowed |
|---|---|---|---|---|
| Vultr Compute | source | `e7457ecb-9780-4363-b244-ac2b1cd5f922` | `{"id": "e7457ecb-9780-4363-b244-ac2b1cd5f922", "tags": ["bs-vultr-e2e-20260804133752-91b44d"]}` | False |
| Vultr Block Storage | source | `6325a0b0-3161-4175-b1da-4b5480d638a8` | `{"id": "6325a0b0-3161-4175-b1da-4b5480d638a8", "label": "bs-vultr-e2e-20260804133752-91b44d-source-block"}` | False |
| Vultr Block Storage | restore-target | `85226034-8c23-4535-a01b-6342be6e0dbc` | `{"id": "85226034-8c23-4535-a01b-6342be6e0dbc", "label": "backupsheep-restore-32-cfa29a41e88840d2"}` | True |
| Vultr Object Storage | source | `629bfdf9-b4b7-4b00-87e3-41a31cf76750` | `{"id": "629bfdf9-b4b7-4b00-87e3-41a31cf76750", "label": "bs-vultr-e2e-20260804133752-91b44d-object-storage"}` | True |
| Vultr Managed Database | source | `a0284c26-315a-4157-b78b-c47d77cbe001` | `{"id": "a0284c26-315a-4157-b78b-c47d77cbe001", "label": "bs-vultr-e2e-20260804133752-91b44d-database"}` | False |
| Vultr Managed Database | restore-target | `2663ab6a-3a0d-41e7-be06-12012a78c25f` | `{"id": "2663ab6a-3a0d-41e7-be06-12012a78c25f", "label": "bs-restore-2bc8976e67c147279c0f"}` | True |

## Cleanup

```json
{
  "errors": [],
  "local_account_id": 48,
  "remaining": {
    "block_snapshots": [],
    "blocks": [],
    "databases": [],
    "instances": [],
    "object_storages": [],
    "snapshots": []
  },
  "status": "PASS"
}
```

## Limitations

- Celery redelivery was exercised by repeating the durable adapter operation; a physical host reboot was not performed.
- Vultr managed-database backup metadata is provider-owned; the harness never deletes it.
