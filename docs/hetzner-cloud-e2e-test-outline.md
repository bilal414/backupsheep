# Hetzner Cloud E2E test outline

This outline accompanies [`scripts/hetzner_cloud_e2e.py`](../scripts/hetzner_cloud_e2e.py).
It is intentionally limited to behavior present in the checked-in BackupSheep
integration and the current Hetzner Cloud API.

## Capability boundary

The BackupSheep Hetzner integration currently supports:

- server snapshot creation through `POST /v1/servers/{id}/actions/create_image`;
- polling the resulting action/image until the snapshot image is available;
- restoring a snapshot by creating a new server with the snapshot image; and
- polling the new server until it is running.

The current Hetzner Cloud API reference lists server image/snapshot operations,
but the Cloud Volume API lists volume CRUD and volume actions without a native
volume snapshot or volume-restore operation. The harness therefore does not
invent or probe a volume snapshot endpoint. Instead, its volume case constructs
only a local BackupSheep volume fixture and asserts that the provider integration
rejects the operation with its explicit unsupported-capability error. See the
[official Hetzner Cloud API reference](https://docs.hetzner.cloud/reference/cloud).

If Hetzner later adds a Cloud Volume snapshot API, add a separate implementation
and test path only after the application provider code supports it; do not turn
the current guard into a guessed HTTP request.

## Safety contract

The harness must preserve these invariants:

1. Credentials come only from `HCLOUD_TOKEN`; no token is written to source,
   fixture rows, JSON output, or exception output.
2. The first provider operation is read-only inventory of servers, snapshot
   images, and volumes. Any resource whose name/description or ownership label
   collides with the random prefix aborts the run before mutation.
3. The source and restored servers use names and the label
   `backupsheep.com/e2e=<run-prefix>`. The snapshot uses an exact deterministic
   description under the same prefix.
4. The harness records every returned provider ID and, after partial create
   failures, may recover IDs only by exact name/description plus the ownership
   label. It never deletes a merely similar resource.
5. Cleanup runs from `finally`, in restore-server → source-server → snapshot
   order. Each deletion re-fetches the resource and proves exact ID, expected
   name/description, type, and label ownership before issuing `DELETE`.
6. A cleanup ownership failure is itself a failed test result; it is never
   silently ignored.

## Test matrix

| ID | Case | Evidence | Expected result |
| --- | --- | --- | --- |
| HZ-01 | Token and project preflight | Read-only server type, location, image, and resource inventory | Fail before writes if credentials/configuration/collision is invalid |
| HZ-02 | Source server readiness | Created server has the requested type/location/image and reaches `running` | PASS |
| HZ-03 | Server snapshot | BackupSheep `CoreHetzner.create_snapshot()` creates an image with exact snapshot description; `CoreHetznerBackup.poll_status()` reaches `Complete` | PASS |
| HZ-04 | Snapshot artifact verification | Direct read-only image lookup confirms `type=snapshot`, exact description, and `status=available` | PASS |
| HZ-05 | Duplicate snapshot recovery | Calling the existing provider create method again re-discovers the exact image rather than creating another one | Same image ID; PASS |
| HZ-06 | Server restore | BackupSheep `restore_snapshot()` creates a new server from the image; `check_restore()` reaches `Complete` | New exact-prefix server is `running` |
| HZ-07 | Volume capability guard | Local `CoreNode.Type.VOLUME` fixture calls `CoreHetzner.create_snapshot()` | Explicit `Hetzner Cloud does not provide native volume snapshots`; no provider write |
| HZ-08 | Prefix-scoped cleanup | Re-fetch each tracked/recovered ID, prove ownership, then delete; inspect cleanup status | No matching test resources remain; any ambiguity fails safely |

## Run contract

Run from the application environment with a disposable Hetzner project/token:

```bash
HCLOUD_TOKEN=' supplied outside the repository ' \
HETZNER_E2E_SERVER_TYPE=cx23 \
HETZNER_E2E_LOCATION=fsn1 \
HETZNER_E2E_IMAGE=ubuntu-24.04 \
python scripts/hetzner_cloud_e2e.py
```

The image, server type, and location are required inputs rather than silently
selected defaults. The harness verifies each one with a read-only API call,
which makes architecture/availability mismatches fail before a server is
created. Use a short-lived token with only the project permissions required for
the test. Do not paste a real token into this document or commit a local env
file.

The JSON report contains the random prefix, non-secret resource IDs, test
results, and cleanup errors. A non-zero exit code means the test or cleanup
failed. A failed run should be investigated from the provider console/API using
the printed prefix before any manual cleanup; only exact-prefix resources from
this run are in scope.

## Recorded live run

The create-only run completed successfully on 2026-08-03 using server type
`cpx12`, location `fsn1`, and system image `161547269` (`ubuntu-24.04`). The
random run prefix was `bs-e2e-260803132052-4bdc84`; HZ-01 through HZ-08 all
passed. The run created and then removed source server `158609486`, restore
server `158609606`, and snapshot image `415841791`. Cleanup reported no
remaining exact-prefix servers or snapshot images. The run never modified any
pre-existing project resource.

## Deliberate non-coverage

- No provider volume is created: the current integration/API has no native
  volume snapshot/restore path to exercise.
- No SSH login or guest-data marker is used. The test validates the provider
  image lifecycle and BackupSheep state transitions, not filesystem contents
  inside the guest.
- No existing server, volume, image, firewall, SSH key, network, or other
  project resource is modified.
- The harness does not call `GET /v1/actions` as a global token check; the
  application already uses the authenticated server collection because the
  global actions endpoint was removed from the current API.

## Follow-up when volume support is implemented

Add application support first, including an explicit volume snapshot model/API
mapping, polling, restore target creation, status failure handling, and
prefix-safe deletion. Then extend this outline and the harness with a
provider-created uniquely labeled volume, a marker written through a guest or
block-storage test path, snapshot/restore verification, and exact-prefix
cleanup. Until that work exists, an explicit failure is the correct result.
