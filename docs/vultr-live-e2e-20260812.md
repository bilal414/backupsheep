# Vultr live E2E test report

- Run: `bs-e2e-vultr-20260812-f3b9d1a7`
- Mode: `LIVE_PROVIDER`
- Started: `2026-08-12T15:05:54.733821+00:00`
- Finished: `2026-08-12T15:07:15.253111+00:00`
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
      "block_snapshots": 6,
      "blocks": 9,
      "databases": 2,
      "instances": 7,
      "object_storages": 2,
      "snapshots": 6
    }
  }
}
```

## Live acceptance matrix

| ID | Result | Evidence |
|---|---|---|
| VUL-04 | **PASS** | `{"local": {"backup_id": 33, "status": "Complete"}, "provider": {"matches": 1, "snapshot_id": "25bbf758-e02d-47df-8265-596c9b2fe713", "source_field_omitted": true, "state": "complete"}, "status": "PASS"}` |
| VUL-06-instance | **PASS** | `{"provider_snapshot_count": 1, "status": "PASS"}` |
| VUL-07 | **PASS** | `{"local": {"phase": "pending", "restore_id": 46, "status": "Pending"}, "provider": {"matches": 1, "restore_id": "9e71cbdd-107a-4768-8036-e9eab335ab76", "status": null}, "status": "PASS"}` |
| VUL-05 | **PASS** | `{"local": {"backup_id": 34, "status": "Complete"}, "provider": {"matches": 1, "snapshot_id": "63dbe70e-e379-466d-ad6a-656ab20c7e82", "state": "COMPLETE"}, "status": "PASS"}` |
| VUL-08-block | **PASS** | `{"local": {"phase": "pending", "restore_id": 47, "status": "Pending"}, "provider": {"matches": 1, "restore_id": "6235cf7c-ff40-4d0a-a7c8-28047a175566"}, "status": "PASS"}` |
| VUL-09 | **PASS** | `{"provider": {"automatic_backup_count": 0, "read_only": true}, "status": "PASS"}` |
| VUL-10 | **PASS** | `{"local": {"first_identity": ["\"2f03acb9576d5e75292be7faf07e1b2e\"", "", "bs-e2e-vultr-20260812-f3b9d1a7/bs-e2e-vultr-20260812-f3b9d1a7-file-backup.zip"], "first_metadata": {"checksum_algorithm": "sha256", "etag": "\"2f03acb9576d5e75292be7faf07e1b2e\"", "object_key": "bs-e2e-vultr-20260812-f3b9d1a7/bs-e2e-vultr-20260812-f3b9d1a7-file-backup.zip", "phase": "committed", "provider_checksum_sha256": null, "sha256": "1d1febf7433b2802c40a1153669e890025ffc9bbc03e2a038ae55e19994d2390", "size_bytes": 42, "version_id": ""}, "second_identity": ["\"2f03acb9576d5e75292be7faf07e1b2e\"", "", "bs-e2e-vultr-20260812-f3b9d1a7/bs-e2e-vultr-20260812-f3b9d1a7-file-backup.zip"], "second_metadata": {"checksum_algorithm": "sha256", "etag": "\"2f03acb9576d5e75292be7faf07e1b2e\"", "object_key": "bs-e2e-vultr-20260812-f3b9d1a7/bs-e2e-vultr-20260812-f3b9d1a7-file-backup.zip", "phase": "committed", "provider_checksum_sha256": null, "sha256": "1d1febf7433b2802c40a1153669e890025ffc9bbc03e2a038ae55e19994d2390", "size_bytes": 42, "version_id": ""}, "sha256": "1d1febf7433b2802c40a1153669e890025ffc9bbc03e2a038ae55e19994d2390", "size_bytes": 42, "status": 3, "status_display": "Upload Complete", "storage_point_id": 21}, "provider": {"bucket": "bs-e2e-vultr-20260812-f3b9d1a7-bucket", "etag": "\"2f03acb9576d5e75292be7faf07e1b2e\"", "key": "bs-e2e-vultr-20260812-f3b9d1a7/bs-e2e-vultr-20260812-f3b9d1a7-file-backup.zip", "version_id": null}, "status": "PASS"}` |
| VUL-11 | **PASS** | `{"local": {"backup_id": 7, "marker": "vultr-db:b37dda91-52c3-472f-982b-e1328dc4eb15:2026-08-12", "status": "Complete"}, "provider": {"provider_backup_id": "2026-08-12", "provider_status": "complete", "source_database_id": "b37dda91-52c3-472f-982b-e1328dc4eb15"}, "status": "PASS"}` |
| VUL-12 | **PASS** | `{"local": {"marker": "bs-restore-54108422fce242be8cf1", "restore_id": 5, "status": "Complete"}, "provider": {"matching_targets": 1, "restore_id": "1f708cbc-9264-40ca-971a-a1af1abb527c", "source_id": "b37dda91-52c3-472f-982b-e1328dc4eb15", "source_label_unchanged": true}, "status": "PASS"}` |

## Resource ledger

| Service | Class | Provider ID | Ownership proof | Cleanup allowed |
|---|---|---|---|---|
| Vultr | source-instance | `60fca58c-ce86-4c87-ac1f-019dfc1f25ee` | `{"hostname": "bs-e2e-vultr-20260812-f3b9d1a7-source", "label": "bs-e2e-vultr-20260812-f3b9d1a7-source-instance", "os_id": 2284, "plan": "vc2-1c-1gb", "region": "ewr", "request_fingerprint": "83982806a1152ac2f1672e1c898d3896677f7ed9e325a8570a4762a722bf0c56", "role": "source-instance", "run_id": "bs-e2e-vultr-20260812-f3b9d1a7", "tags": ["bs-e2e-vultr-20260812-f3b9d1a7"]}` | True |
| Vultr | source-block | `8eccc7f0-98b6-4ba1-9358-85d6ed2f521a` | `{"label": "bs-e2e-vultr-20260812-f3b9d1a7-source-block", "region": "ewr", "request_fingerprint": "42e4ab80860eb93e44b5c460520ab71cd359cdd6149a6d04428e51bb5a2b8169", "role": "source-block", "run_id": "bs-e2e-vultr-20260812-f3b9d1a7", "size_gb": 10}` | True |
| Vultr | instance-snapshot | `25bbf758-e02d-47df-8265-596c9b2fe713` | `{"description": "bs-e2e-vultr-20260812-f3b9d1a7-instance-snapshot", "instance_id": "60fca58c-ce86-4c87-ac1f-019dfc1f25ee", "request_fingerprint": "1c256162031e53de6cf88b5ae05efe1dd630ae619c669ebe6023328a5a923cac", "role": "instance-snapshot", "run_id": "bs-e2e-vultr-20260812-f3b9d1a7"}` | True |
| Vultr | restore-instance | `9e71cbdd-107a-4768-8036-e9eab335ab76` | `{"os_id": 2284, "plan": "vc2-1c-1gb", "region": "ewr", "request_fingerprint": "24965ffc5bd84c472c6b8e3c658f6ccb9d2fbed270f8e2482a767455d0c6b8ac", "restore_marker": "backupsheep-restore-40", "role": "restore-instance", "run_id": "bs-e2e-vultr-20260812-f3b9d1a7", "snapshot_id": "25bbf758-e02d-47df-8265-596c9b2fe713", "tags": ["backupsheep-restore-40"]}` | True |
| Vultr | block-snapshot | `63dbe70e-e379-466d-ad6a-656ab20c7e82` | `{"block_id": "8eccc7f0-98b6-4ba1-9358-85d6ed2f521a", "description": "bs-e2e-vultr-20260812-f3b9d1a7-block-snapshot", "request_fingerprint": "56f097773d06175b5f1ccb0b35956ece166fe13b7a27ca7fec3cd9af1552181d", "role": "block-snapshot", "run_id": "bs-e2e-vultr-20260812-f3b9d1a7"}` | True |
| Vultr | restore-block | `6235cf7c-ff40-4d0a-a7c8-28047a175566` | `{"label": "backupsheep-restore-41", "region": "ewr", "request_fingerprint": "a9b65f3daa15fb507e88e4fdf005f34cb8c69dc49cf09cc79282ad57815de7c6", "restore_marker": "backupsheep-restore-41", "role": "restore-block", "run_id": "bs-e2e-vultr-20260812-f3b9d1a7", "size_gb": 10, "snapshot_id": "63dbe70e-e379-466d-ad6a-656ab20c7e82"}` | True |
| Vultr | object-storage | `017e0847-dee1-48bc-bed0-bdd11c89d405` | `{"cluster_id": 2, "label": "bs-e2e-vultr-20260812-f3b9d1a7-object-storage", "region": "ewr", "request_fingerprint": "441c19ccfcac7127c7b6a3c92ae23ed8686e876031d7464ccc66a68374c59c63", "role": "object-storage", "run_id": "bs-e2e-vultr-20260812-f3b9d1a7", "s3_hostname": "ewr1.vultrobjects.com"}` | True |
| Vultr | object-bucket-marker | `bs-e2e-vultr-20260812-f3b9d1a7-bucket/bs-e2e-vultr-20260812-f3b9d1a7/ownership.json` | `{"bucket": "bs-e2e-vultr-20260812-f3b9d1a7-bucket", "etag": "\"ef724f4c66b1ada3468561ef0aaa2096\"", "key": "bs-e2e-vultr-20260812-f3b9d1a7/ownership.json", "request_fingerprint": "366507139e6bda58fa034e9b931f92ae0638b98552d861a1dd2b3de73f45a5df", "role": "object-bucket-marker", "run_id": "bs-e2e-vultr-20260812-f3b9d1a7", "sha256": "ddfc3f2f647dd7186f3d8098c4891664b8516e4de0743f9c844e764b74919755", "size_bytes": 105, "version_id": ""}` | True |
| Vultr | object-bucket | `bs-e2e-vultr-20260812-f3b9d1a7-bucket` | `{"bucket": "bs-e2e-vultr-20260812-f3b9d1a7-bucket", "marker_key": "bs-e2e-vultr-20260812-f3b9d1a7/ownership.json", "marker_sha256": "ddfc3f2f647dd7186f3d8098c4891664b8516e4de0743f9c844e764b74919755", "request_fingerprint": "18e62ff9bb57f9b4b5cb0cc65fe1240a931f49a9fd41b334383d0ca39106ea92", "role": "object-bucket", "run_id": "bs-e2e-vultr-20260812-f3b9d1a7"}` | True |
| Vultr | source-database | `b37dda91-52c3-472f-982b-e1328dc4eb15` | `{"database_engine": "pg", "database_engine_version": "16", "label": "bs-e2e-vultr-20260812-f3b9d1a7-database", "plan": "vultr-dbaas-startup-cc-1-55-2", "region": "ewr", "request_fingerprint": "c2d688caf60ea88e3d68d9d3e163d5c5148276f0f66bfab0d0db2d71515a90ed", "role": "source-database", "run_id": "bs-e2e-vultr-20260812-f3b9d1a7"}` | True |
| Vultr | restore-database | `1f708cbc-9264-40ca-971a-a1af1abb527c` | `{"database_engine": "pg", "database_engine_version": "16", "label": "bs-restore-54108422fce242be8cf1", "plan": "vultr-dbaas-startup-cc-1-55-2", "region": "ewr", "request_fingerprint": "fc7089d7b478a87992fd964ab0431f1cfb998c2d139d97f87d66935e836f4e47", "restore_marker": "bs-restore-54108422fce242be8cf1", "role": "restore-database", "run_id": "bs-e2e-vultr-20260812-f3b9d1a7", "source_id": "b37dda91-52c3-472f-982b-e1328dc4eb15"}` | True |

## Cleanup

```json
{
  "errors": [],
  "provider_resources_considered": [],
  "status": "NOT_REQUESTED"
}
```

## Limitations

- Celery redelivery was exercised by repeating the durable adapter operation; a physical host reboot was not performed.
- Vultr managed-database backup metadata is provider-owned; the harness never deletes it.
