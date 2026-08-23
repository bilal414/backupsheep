# DigitalOcean enterprise backup/restore reliability handoff

Date: 2026-08-12
Branch: `develop`
Starting commit: `05f2ebeb9c2e1d997c9fb248149c040ec1e85ff1`
Live validation checkpoint: `28ee48d5483f501de6b3838eb0f3b230df1a0c45`

## Evidence boundary

The first implementation pass described by this document was deliberately
offline. A later controlled live pass used only the required Personal team,
created a run-ledgered Droplet, volume, firewall, and versioned Spaces bucket,
and drove native plus website/database backup and restore workflows through
`demo.backupsheep.com`.

The live pass completed Droplet and volume snapshots, safe-fork Droplet and
volume restores, versioned Spaces uploads with persisted SHA-256, byte count,
ETag, and version ID, and website/PostgreSQL restores. The exact rows, provider
IDs, integrity witnesses, deployment snapshot, and remaining cleanup/credential
rotation gates are recorded in
`docs/provider-live-e2e-resume-handoff-20260812.md`.

Live success does not waive the ownership boundary: final cleanup remains
blocked until the hardened harness performs a fresh direct readback of every
exact ID and revalidates the complete creation fingerprint. The offline test
matrix and original UI plan below are retained as design and regression history.

## Provider contracts used

The code follows DigitalOcean's current official contracts:

- [Snapshots](https://docs.digitalocean.com/reference/api/reference/snapshots/)
  identify the exact source with `resource_id` and `resource_type`.
- [Droplet actions](https://docs.digitalocean.com/products/droplets/reference/api/droplet-actions/)
  are asynchronous and must be polled separately from the resulting snapshot.
- [Block Storage](https://docs.digitalocean.com/reference/api/reference/block-storage/)
  creates volume snapshots under the source volume and creates a restored volume
  from `snapshot_id`.
- [Account](https://docs.digitalocean.com/reference/api/reference/account/)
  exposes the active account/team witness used by the Personal-team safety gate.
- [Firewalls](https://docs.digitalocean.com/reference/api/reference/firewalls/)
  support exact Droplet-ID assignments, which the payload harness uses instead
  of a tag-wide assignment.
- [Spaces Keys](https://docs.digitalocean.com/reference/api/reference/spaces-keys/)
  currently supports list/create/get/delete through `/v2/spaces/keys`. Key create
  requires `spaces_key:create_credentials`; deletion requires
  `spaces_key:delete`. The create response returns the secret once inside the
  `key` response object.
- [Spaces S3 API](https://docs.digitalocean.com/reference/api/spaces/) supports
  private buckets, object metadata, ETags, version IDs, version inventory,
  multipart-upload inventory, and exact object-version deletion.

DigitalOcean's Droplet, volume, snapshot, and Spaces-key lists are page based,
but responses expose an opaque provider `links.pages.next` URL. BackupSheep
follows that validated URL rather than inventing a next page number.

## Implemented reliability behavior

### Bounded authentication and discovery

`CoreAuthDigitalOcean` now:

- treats personal access-token connections as non-refreshing;
- validates OAuth token endpoints as HTTPS-only, credential-free, port-free
  URLs before sending a refresh token;
- uses explicit connect/read timeouts and closes token/account responses;
- stores a rotated refresh token before the account witness read, so a transient
  account failure cannot lose a one-time refresh token;
- rejects empty, non-Bearer, and CR/LF-bearing credentials;
- distinguishes authentication, rate-limit, timeout, transient, malformed, and
  terminal provider outcomes without storing or echoing response bodies;
- persists `info_name`, `info_email`, and the provider team/account UUID; and
- discovers Droplets and volumes through the complete bounded inventory helper.

`apps/api/v1/connection/digitalocean/client.py` supplies a common read contract:

- explicit timeouts on every request;
- HTTPS and same-origin validation for every provider next link;
- no bearer forwarding to a foreign origin;
- bounded page and item counts;
- repeated-page and duplicate-resource detection;
- stable `meta.total` and final-count proof; and
- exact snapshot selection by marker + source ID + resource type.

### Crash-safe snapshot create

Before entering the provider adapter, the Celery callback persists an immutable,
non-secret request envelope containing:

- BackupSheep marker;
- account, connection, and node IDs;
- DigitalOcean source ID;
- exact type (`droplet` or `volume`); and
- a canonical SHA-256 request fingerprint.

The current durable create lease is bound to all backup saves. A replay with a
persisted request envelope and no provider pointer is reconciliation-only: it
reads the complete snapshot inventory and adopts exactly one marker/source/type
match. It does not submit another snapshot request. A changed source, foreign
same-name resource, duplicate exact match, incomplete inventory, or exhausted
zero-match window fails closed for manual review.

The DigitalOcean model validates the exact source ID before mutation, gives
every provider call a timeout, validates the returned action/snapshot ownership,
and persists action or snapshot IDs only after strict response validation.

### Crash-safe fork restore

Droplet and volume restores use one immutable restore identity:

- durable restore marker;
- source snapshot ID;
- target kind;
- exact normalized target name;
- `backupsheep-restore-<kind>` tag; and
- SHA-256-derived source tag when the provider response does not expose direct
  snapshot linkage.

A restore target is owned only when exact provider ID, name, marker tag, kind
tag, and snapshot linkage all agree. If a provider accepted a create and the
worker lost the response, the replay traverses the complete marker inventory,
adopts one exact target, rejects foreign/duplicate targets, and never issues a
second create while the outcome is unknown.

Polling reads the exact provider ID first. It treats active/creating states as
in progress, success states as complete, known terminal states as failed, and
unknown/malformed states as manual review. A 404, 429, authentication failure,
timeout, transient outage, or terminal provider failure is not silently mapped
to `IN_PROGRESS`.

### Strict snapshot polling and deletion

`CoreDigitalOceanBackup.poll_status` now verifies one durable witness across the
backup row and `CoreBackupExecution`. A conflicting local snapshot/action
pointer fails before any provider read. Polling uses direct IDs first and only
falls back to complete exact reconciliation when the provider pointer is absent.

Deletion now has a durable leased checkpoint containing the immutable snapshot,
source, marker, type, account, and connection witness. Before DELETE it performs
an exact GET and refuses a foreign or weakly witnessed snapshot. A timeout,
connection loss, accepted response, or 5xx is an unknown outcome; replay checks
the exact ID and treats 404 as success only after the durable ownership and
delete-intent proofs exist. It never discovers a resource and promotes it into
delete authority.

### Disabled deterministic crash hook

The narrow provider-accepted/pre-persist window can be tested without relying on
timing. The hook is disabled unless both settings are exact:

```text
DIGITALOCEAN_ENABLE_TEST_FAULTS=True
DIGITALOCEAN_FAULT_AFTER_ACCEPT=<operation>:<marker>
```

Supported operations are `snapshot-droplet`, `snapshot-volume`,
`restore-droplet`, `restore-volume`, and `delete-snapshot`. The hook is executed
only after a successful provider response has passed ownership validation. It
must remain disabled outside a controlled acceptance worker.

## Live harness safety model

`scripts/digitalocean_live_e2e.py` is read-only by default and has three
independent mutation domains.

### Common provider gates

Every mutation requires:

- token only in `DIGITALOCEAN_TOKEN`;
- exact active team name `Personal`;
- exact allow-listed Personal team UUID;
- a DNS-safe unique run ID;
- a durable fsynced resource ledger and mutation-intent store; and
- `BACKUPSHEEP_E2E_APPLY=YES`.

Cleanup additionally requires `BACKUPSHEEP_E2E_CLEANUP=YES`. Discovery is never
delete authority. Only exact IDs already in this run's ledger can be deleted,
and each receives a direct ownership read-back before deletion.

### Deterministic source payload and minimal firewall

Cloud-init writes a deterministic bounded payload and starts a sandboxed Python
HTTP service on port 8080. It serves only `/healthz` and `/payload`. The harness
creates a unique Cloud Firewall assigned by the exact source Droplet ID and
allows inbound TCP 8080 only from caller-supplied host CIDRs (`/32` for IPv4 or
`/128` for IPv6). It never opens SSH and rejects `0.0.0.0/0`, `::/0`, or broader
networks.

Before a UI backup, the harness proves source Droplet status, one exact public
IPv4, health marker, SHA-256, and byte count. The durable ledger stores only the
expected hash and byte count, never cloud-init payload bytes or credentials.

For a UI-restored Droplet it verifies:

- exact provider ID supplied from the BackupSheep restore row;
- exact target name;
- unique durable restore-marker tag;
- target-kind tag;
- source snapshot through the provider image field, or the source hash tag when
  direct linkage is absent; and
- the same bounded payload bytes/hash after exact firewall attachment.

The restored volume uses the same exact ID/name/marker/kind/source proof. The
harness rejects missing, duplicate, or foreign marker witnesses. It records the
verified target into the same ledger before it can be cleaned.

### Spaces setup mode

Spaces setup is intentionally separate and additionally requires:

```text
BACKUPSHEEP_E2E_SPACES_APPLY=YES
```

The mode:

1. Creates one uniquely named full-access test key through
   `POST /v2/spaces/keys`.
2. Creates one deterministic, high-entropy, private test bucket in the selected
   region.
3. Enables bucket versioning.
4. Uploads and read-backs one deterministic ownership object with run metadata.
5. Persists only the access-key SHA-256 in the ledger.
6. Writes endpoint, region, bucket, access key, and secret key atomically to a
   mode-0600 runtime file under `.git/backupsheep-e2e-secrets/` by default.

The credential file is outside the Git worktree, rejects symlinks, has a
mode-0700 parent, and is never included in JSON stdout or the ledger. A custom
path is accepted only outside the worktree or inside `.git`.

If the token is denied at key list/create/delete, the mode returns a secret-free
`scope_rejected` result naming the required capability and exits non-zero. That
does not disable or weaken Droplet/volume verification.

### Spaces UI upload verification

After BackupSheep has run one website backup and one database backup through the
UI, export a non-secret manifest from their durable `CoreBackupArtifact` rows.
The shared DigitalOcean Spaces uploader already records object key, SHA-256,
byte count, ETag, and version ID. The manifest shape is:

```json
{
  "objects": [
    {
      "kind": "website",
      "key": "prefix/website-backup.zip",
      "version_id": "provider-version-id",
      "sha256": "64-lowercase-hex-characters",
      "byte_count": 12345,
      "etag": "provider-etag-without-quotes",
      "metadata": {
        "backupsheep-sha256": "64-lowercase-hex-characters",
        "backupsheep-size": "12345",
        "backupsheep-backup-id": "123"
      }
    },
    {
      "kind": "database",
      "key": "prefix/database-backup.zip",
      "version_id": "provider-version-id",
      "sha256": "64-lowercase-hex-characters",
      "byte_count": 6789,
      "etag": "provider-etag-without-quotes",
      "metadata": {
        "backupsheep-sha256": "64-lowercase-hex-characters",
        "backupsheep-size": "6789",
        "backupsheep-backup-id": "456"
      }
    }
  ]
}
```

The verifier first proves that the protected credential file matches the exact
ledgered bucket/team/run/region/key hash/endpoint/versioning witness. For each
exact object version it then verifies HEAD byte count, ETag, version ID, and
custom metadata; performs a bounded streaming download; recomputes SHA-256 and
byte count; and records the exact version in the ledger. It requires at least
one website and one database object and rejects credential-like fields in the
manifest.

This provider round trip proves the upload is readable and exact. A successful
website/database restore must still be launched through the BackupSheep UI and
validated against the seeded source dataset as a separate application-level
test.

### Spaces cleanup mode

Spaces cleanup additionally requires:

```text
BACKUPSHEEP_E2E_CLEANUP=YES
BACKUPSHEEP_E2E_SPACES_CLEANUP=YES
```

It can adopt only a pending resource with this run's exact durable create intent
and request fingerprint. It deletes only exact ledgered object versions after a
metadata read-back. Before bucket deletion it completely inventories object
versions, delete markers, current objects, and multipart uploads with repeated
page/item and upper-bound checks. Any unledgered item stops cleanup; the harness
never empties or deletes it. Only an empty exact bucket is deleted. The exact
ledgered key is then verified by name, full-access grant, direct read-back, and
access-key hash before deletion. The runtime secret file is removed only after
key absence is proven.

## Offline regression matrix

The DigitalOcean-focused tests cover:

1. provider-next pagination, stable total, same-origin validation, repeated
   page/item defense, incomplete inventory, and configured page bounds;
2. marker + source + type exact snapshot matching, foreign markers, and
   duplicate exact matches;
3. stable request envelope persistence and source-identity drift;
4. lost create response and worker replay without duplicate snapshot mutation;
5. deterministic post-accept snapshot, restore, and delete crashes followed by
   exact adoption/absence reconciliation without duplicate mutation;
6. exact restore target selection plus missing, duplicate, foreign, and
   foreign-run-ledger witnesses;
7. 404, rate-limit, timeout, transient, malformed, authentication, and terminal
   poll outcomes;
8. conflicting durable provider pointers and ownership-refused deletion;
9. bounded OAuth refresh and team-witness persistence;
10. complete UI object discovery and invalid object-type rejection;
11. deterministic payload/cloud-init, exact host-CIDR firewall policy, and
    bounded source/restored HTTP payload verification;
12. mode-0600 secret persistence, key-scope rejection without provider-body
    leakage, and ledger access-key hashing;
13. website/database version metadata plus bounded download verification; and
14. refusal to delete a Spaces bucket containing any unledgered version,
    delete marker, object, or multipart upload.

Canonical focused command:

```bash
./backupsheep-compose build db app
./backupsheep-compose --allow-reviewed-runtime-overrides run --rm --no-deps \
  -e DJANGO_SERVER=test \
  --entrypoint python app manage.py test \
  apps.tests.test_digitalocean_adapter_reliability \
  apps.tests.test_provider_polling_reliability \
  apps.tests.test_non_vultr_restore_reliability \
  --keepdb --noinput
```

Final offline evidence:

- focused DigitalOcean/provider reliability suite: **65 tests passed** in
  **7.231 seconds**;
- broad backup/restore/orchestration/UI regression suite: **298 tests passed**
  in **47.927 seconds**;
- Django system checks: **0 issues** in both runs; and
- scoped Python compilation and `git diff --check`: passed.

## Personal-team-only UI E2E procedure (executed; retained for regression)

Do not begin mutation until the deployed commit and every safety gate are
recorded.

1. Deploy the final `develop` commit to `demo.backupsheep.com`; record its Git
   SHA and verify worker/web processes run the same SHA.
2. Load the token into `DIGITALOCEAN_TOKEN` without printing it. Never place it
   in shell history, CLI arguments, the ledger, screenshots, or reports.
3. Choose a new run ID and ignored durable ledger path. Run the harness
   read-only to capture the current Personal team UUID, then restart with that
   exact UUID allow-listed. Stop on any team mismatch.
4. Supply the runner's exact public host CIDR and provision one source Droplet,
   one source volume, one firewall, and one run tag. Wait until the source
   payload hash/bytes are durably proven.
5. In the demo UI, add/revalidate only this DigitalOcean connection. Confirm
   `info_name=Personal` and the exact allow-listed `info_uuid`.
6. Through Cloud Servers and Volumes, attach only the exact source IDs from the
   ledger. Confirm complete discovery and no interaction with unledgered rows.
7. Start one Droplet snapshot and one volume snapshot through the UI. Confirm an
   immediate durable in-progress row. Repeat the click/API delivery and prove
   one logical backup and one provider operation per marker.
8. Exercise normal worker loss during create and poll. Then use a dedicated
   acceptance worker with the exact deterministic post-accept fault selector,
   restart the worker, and prove adoption of the same action/snapshot ID.
9. Give the harness each UI backup marker plus its exact ledgered source ID.
   Require exactly one provider snapshot with the correct source/type and record
   its ID into the ledger.
10. Restore both snapshots through the UI to unique names. From each durable
    restore row give the harness the exact provider target ID, name, restore
    marker, and source snapshot ID. Require exact target linkage and the restored
    Droplet payload hash/bytes.
11. Repeat restore delivery and the deterministic post-accept crash. Prove the
    original target is adopted and no duplicate target exists.
12. Run controlled mocked/provider-safe status cases for 404, 429, timeout,
    transient 5xx, malformed response, and terminal failure. Verify the UI shows
    retry/manual-review/failed semantics rather than indefinite in-progress.
13. Enable Spaces setup using the separate gate. If the token returns scoped
    rejection, record the capability and continue the compute/volume plan; do
    not broaden cleanup behavior.
14. Enter the protected runtime Spaces credentials into the demo UI without
    copying them into the test report. Configure only the exact test bucket.
15. Create deterministic website and database datasets, run both backups through
    the UI, and export their `CoreBackupArtifact` metadata to the non-secret
    manifest. Run provider-side exact version verification.
16. Restore website and database backups through the UI. Compare restored files,
    row counts, schema/data fixtures, SHA-256 values, and negative cases for a
    changed/missing object version. Provider download proof alone is not enough.
17. Capture row IDs, task/correlation IDs, provider action/snapshot/target IDs,
    hashes, byte counts, ETags, version IDs, timestamps, fault-selector used,
    retry states, and cleanup outcomes. Never capture token or Spaces secrets.
18. Cleanup in dependency order: UI-restored targets, UI-created snapshots,
    source volume, source Droplet, firewall, run tag, exact Spaces object
    versions, empty bucket, and exact Spaces key. Require provider absence after
    every exact deletion. Stop for manual review on any mismatch or unledgered
    inventory.
19. Rotate the acceptance token and retain the non-secret ledger/report.

## Remaining operational gates

The Personal-team compute, volume, Spaces, website, and PostgreSQL UI workflows
have been run successfully against the deployed checkpoint, including restored
application-content validation. The remaining operational gates are narrower:

- integrate the independent manifest-prefix, creation-fingerprint, firewall,
  and cleanup-intent harness hardening;
- keep the focused and broad regression suites green after all concurrent
  provider changes settle;
- run the controlled DigitalOcean lost-response/worker-crash cases against the
  final deployed SHA and prove exactly one provider target;
- perform a fresh exact-ID ownership inventory before cleanup, then prove each
  exact-owned resource absent; and
- rotate the exposed acceptance token after the last provider call.

The exact live evidence and current acceptance matrix are maintained in
`docs/provider-live-e2e-resume-handoff-20260812.md`. Enterprise DigitalOcean
acceptance remains conditional until the remaining crash, cleanup, and rotation
gates are evidenced.
