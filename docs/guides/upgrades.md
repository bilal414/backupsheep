# Upgrades and rollback

Treat an application upgrade as a coordinated code, image and PostgreSQL schema change.
The verified installer deliberately never changes an existing checkout to another commit;
this runbook is the operator-controlled manual upgrade path. The `migrate` and security
`preflight` one-shots must complete before the new app, workers or Beat can start.

## Before the change

1. Read release notes and compare the exact current and target revisions.
2. Verify the checkout has no unexplained changes:

   **Pre-hardening identity gate:** before initializing the new wrapper, check whether
   `.env` already has one stable 64-hex `BACKUPSHEEP_INSTALLATION_ID` and the project has
   its matching `installation_identity` sentinel. If either is absent, do not run the
   wrapper block below. Use the old exact model only for read-only inventory and a
   controlled stop, check out the reviewed target, then run the mandatory installer
   identity bootstrap shown in
   [Upgrade to the exact reviewed commit](#upgrade-to-the-exact-reviewed-commit). For a
   live 3.13 broker, continue directly with the
   [RabbitMQ migration gate](rabbitmq-upgrade.md); for an old `compose down`, use its
   linked explicit four-volume adoption branch.

   ```bash
   cd /opt/backupsheep
   git status --short --branch
   git rev-parse HEAD

   BS_COMPOSE=("$PWD/backupsheep-compose")
   # If and only if this installation has a reviewed deployment override, add:
   # BS_COMPOSE+=(--approved-compose-file "$PWD/docker-compose.override.yml")
   bs_compose() { "${BS_COMPOSE[@]}" "$@"; }
   bs_compose config --quiet
   ```

   Stop if the worktree is dirty or ownership of a file is unclear. Do not discard local
   overrides or user changes. Review an existing override before adding the exact flag;
   the wrapper refuses to ignore or auto-load it. Keep `BS_COMPOSE` and `bs_compose` in
   this same maintenance shell for every command below. The shipped wrapper validates
   private files and the final model, pins project/env/file selection, and removes ambient
   interpolation, profile, Bake and orphan-removal controls.

3. Record the exact 40-character target commit and current image/configuration provenance.
   Preserve the existing 64-hex `BACKUPSHEEP_INSTALLATION_ID`; confirm the empty
   `installation_identity` volume carries that same label and stop if Compose project,
   path or resource ownership is ambiguous. Never rotate or copy the ID to make a foreign
   project pass ownership checks.
4. Check the console for active backups, uploads, deletes and restores.
5. Stop Beat first, inventory active/reserved/scheduled work, and drain or reconcile it
   without discarding broker messages. Before changing code or schema, stop the web app
   and every exact old-image worker as well:

   ```bash
   bs_compose stop beat
   bs_compose --profile operations exec -T worker-cloud celery -A backupsheep inspect active
   bs_compose --profile operations exec -T worker-cloud celery -A backupsheep inspect reserved
   bs_compose --profile operations exec -T worker-cloud celery -A backupsheep inspect scheduled
   bs_compose --profile operations stop \
     app worker-cloud worker-database worker-files worker-storage worker-logs beat

   RUNNING_APPLICATION_SERVICES="$({
     bs_compose --profile operations ps --status running --services
   } | grep -Ev '^(db|rabbitmq|app-egress-guard|cloud-egress-guard|database-egress-guard|files-egress-guard|storage-egress-guard|logs-egress-guard)$' || true)"
   test -z "${RUNNING_APPLICATION_SERVICES}"

   BROKER_QUEUE_STATE="$({
     bs_compose exec -T rabbitmq rabbitmqctl -q list_queues \
       name consumers messages_unacknowledged
   })"
   printf '%s\n' "${BROKER_QUEUE_STATE}"
   test "$({
     printf '%s\n' "${BROKER_QUEUE_STATE}" |
       awk '{ consumers += $2; unacked += $3 } END { print consumers ":" unacked }'
   })" = '0:0'
   ```

   The queue listing may still contain ready messages; preserve them for the reviewed
   recovery path. The required invariant is zero consumers and zero unacknowledged work.
   A Compose profile controls creation/selection, not the restart policy of an existing
   container, so omitting `--profile operations` does not stop an old worker.

6. Create and verify a PostgreSQL dump; copy `.env`, the complete `.secrets` directory and
   local Compose overrides to an encrypted recovery location. Back up Local Storage and
   critical work-volume material. Then remove the complete container/network topology so
   no guard can be replaced beneath an old namespace; ordinary `down` preserves named
   data and identity volumes:

   ```bash
   bs_compose --profile operations down --timeout 300
   ```

   Never add `--volumes`.
7. Confirm free disk for both old/new image layers and migration work.

If the release changes the pinned RabbitMQ generation, stop here and follow the dedicated
[RabbitMQ migration gate](rabbitmq-upgrade.md). `BACKUPSHEEP_RABBITMQ_DATA_GENERATION`
is an installer-owned witness, not a version switch; never edit it to make an old volume
appear migrated.

See [Disaster recovery](disaster-recovery.md#back-up-the-control-plane) for the backup
commands.

## One-time legacy SSH trust and shared-identity retirement

This gate applies to releases that used a global `known_hosts` file, an `ssh_trust` volume,
or one managed private key across the app/database/files roles. Those artifacts are legacy
rollback evidence only. The current release deliberately does not import them into its
account-scoped approval ledger and does not reuse the shared private identity.

The staging layout-v2 witness and dedicated `ssh_trust` volume existed only on the
prerelease development line. Moving to layout v3 requires the explicit
`migrate-empty-legacy-v3` intent; v2 is never treated as equivalent evidence. The
installer accepts a develop-era trust volume only when its canonical project ownership,
physical name and labels pass the complete resource validator. It leaves that volume
detached for rollback evidence. The v3 provisioner has no trust mount or group, and the
wrapper rejects every `--volume` override, so neither that volume nor an exported global
trust file can be mounted or imported through the supported command path. Any ownership,
name or label ambiguity stops the upgrade.

1. Stop Beat, drain active SSH work, and stop every operations service. Create and verify
   the normal encrypted control-plane rollback set. If policy requires retaining the old
   global trust file or shared private key, copy it only into that encrypted, access-audited
   rollback set without printing it. Do not copy either artifact into a current container,
   database row, work volume, or current secret file. Leave any validated develop-era
   `ssh_trust` volume detached until the approved rollback-retention period ends.
2. Review the account count. Managed identities are supported only when the installation
   contains exactly one account. For a multi-account installation, leave both managed-key
   secret files empty and configure customer-supplied, account-scoped private keys instead.
3. For an eligible single-account installation, create two new, distinct Ed25519 identities:
   one for database SSH tunnels and one for files/SFTP. Store the private halves as
   `.secrets/ssh_managed_database_private_key` and
   `.secrets/ssh_managed_files_private_key`, each owner-owned, non-linked and mode `0444`
   beneath the mode-`0700` secret directory. Never derive either new identity by copying or
   converting the old shared key. The installer derives and canonicalizes the matching
   `SSH_MANAGED_DATABASE_PUBLIC_KEY` and `SSH_MANAGED_FILES_PUBLIC_KEY` settings and refuses
   non-Ed25519, mismatched or identical identities.
4. Clear legacy `SSH_MANAGED_PRIVATE_KEY_PATH` and `SSH_MANAGED_PUBLIC_KEY` values. A
   non-empty `.secrets/ssh_managed_private_key` is rejected because its account/lane scope
   cannot be proven. After preserving approved rollback evidence, remove that legacy file;
   the installer may retire only the exact empty, regular, single-link placeholder.
5. Upgrade and start only the core. Existing SSH-managed connections are fenced pending.
   For every SSH endpoint, use the signed-in preview, verify the displayed fingerprint over
   an independent channel, and explicitly approve the exact account/host/port/key. A changed
   key requires the explicit replacement flow. Stock Compose stores approvals and
   append-only audit events in PostgreSQL; it has no trust volume or global `known_hosts`.
6. Install only the database public key on database-tunnel sources and only the files public
   key on SFTP/file sources. Verify that `worker-database` receives only its private source,
   `worker-files` receives only its private source, the app receives neither, and each
   operation creates then removes its exact mode-`0600` private-runtime trust file.
7. Enable operations only after preflight, connection revalidation, and a disposable backup
   and restore rehearsal pass. Retain or dispose of legacy rollback artifacts under the
   organization's approved encrypted-media retention process.

## One-time non-root volume migration to private staging layout v3

Do not manually mount, classify, copy, relabel or recursively change ownership on the
historical `backup_workdir`. It can contain mixed plaintext, credentials, partial artifacts
and logs with no trustworthy lane marker. The v3 provisioner deliberately refuses to guess.

Before checking out the reviewed target, stop and drain every provider operation as described
above and create the verified encrypted rollback set. The historical `backup_workdir` must be
empty. If it is not empty, keep operations disabled and quarantine or reconcile the entire
volume under an approved incident/data-handling process; do not move its entries into a new
lane volume. When constructing `INSTALL_ARGS` in the next section, append the one-time
authorization alongside any required identity-migration arguments:

```bash
INSTALL_ARGS+=(--migrate-staging-layout)
./install.sh "${INSTALL_ARGS[@]}"
```

The installer records the installation-bound `migrate-empty-legacy-v3` intent. Its networkless
root one-shot first proves that `database_workdir`, `files_workdir`, `storage_workdir`, the two
source-specific forward-transfer volumes and `restore_ciphertext_transfer` are dedicated and
empty. It accepts a populated `backup_storage` only when that tree contains private regular
files/directories with unambiguous historical-or-storage ownership, then assigns it solely to
UID/GID `10004:10004`. It assigns each new private/transfer root its exact lane ownership and
mode and commits a root-only durable v3 witness. A witnessed rerun verifies the layout; it does
not repair drift.

The prerelease v2 witness is never accepted as v3 evidence. A canonical develop-era
`ssh_trust` volume may be validated and retained only as detached rollback evidence; no current
runtime mounts it or imports its global trust data. Any ambiguous resource name, label,
ownership, non-empty new target, or unsafe Local Storage tree stops the upgrade.

## Upgrade to the exact reviewed commit

Fetch only the reviewed commit, verify it is the requested object and detach the checkout.
Do not pull a mutable branch or tag. Preserve `.env` and `.secrets`; stop if Git would
overwrite or delete an unexplained local file. The wrapper intentionally discards an
ambient `BACKUPSHEEP_IMAGE`, so atomically persist the exact tag in the already protected
deployment `.env` *before* rendering or building the model:

This release replaces the prerelease artifact key-provider model with two local-file
keyrings. An existing installation that records a blank, development-only or retired
provider may transition only through `--migrate-artifact-key-provider-empty`. The
current runtime provider registry contains only production `local-file` and
development/test-only `local-development`; the historical `aws-kms` identifier is
recognized only by this migration/rollback gate and cannot be selected by current code.
This is an exact-empty adoption, not a KMS decrypt/rewrap conversion. The
`migrate` one-shot applies schema changes and then performs a fresh current-state query;
it succeeds only when `CoreBackupEncryptionEnvelope` and `CoreBackupKeyWrap` each contain
exactly zero rows, including orphan, retired, pending and manual-review rows;
`CoreBackupArtifact` contains no `legacy_zip` row of any role; and all historical
database/files backup and storage-point tables are empty:
`core_website_backup`, `core_website_backup_mtm_storage_points`,
`core_basecamp_backup`, `core_basecamp_backup_mtm_storage_points`,
`core_database_backup`, `core_database_backup_mtm_storage_points`,
`core_wordpress_backup`, and `core_wordpress_backup_mtm_storage_points`. The last two
remain as retained database tables even after WordPress runtime removal. The unmanaged
historical `core_hosting_backup` table must also be empty when it exists. A previously
recorded schema migration cannot bypass this current-state proof. Any wrap, plaintext
artifact, or unledgered historical backup/storage point blocks the transition: neither
the installer nor migration invents a cryptographic conversion or silently retires a
recorded backup.

The same exact-empty boundary introduces internal BSE1 format version 2. Version 2 keeps
the plaintext and context digests inside its authenticated encrypted terminal payload and
uses an independent random envelope UUID for each `.bse1` object name. Version 1 is a
prerelease format and is rejected rather than heuristically converted. The explicit
legacy-only runtime keeps historical plaintext `.zip` read/delete naming only for records
that have not entered the encrypted provider migration; new encrypted uploads never reuse
those paths or their backup-UUID ownership metadata. A mixed, mismatched or ambiguous
legacy/encrypted identity stops reconciliation and deletion.

Migration `0049_local_file_artifact_key_provider` is immutable historical schema and may
already have been applied by a prerelease installation; it continues to describe the
format-v1 constraint it originally shipped with. Migration
`0050_bse2_private_terminal_metadata` performs the format-v2 transition. Before changing
the default or constraint in either direction, `0050` enumerates every envelope and wrap
and refuses when even one orphan, pending, manual, retired, or otherwise unreferenced row
exists. This makes an already-applied empty `0049` database upgrade safely while preventing
schema history from being mistaken for proof that no v1 custody data exists. Do not fake,
delete, or edit migration-history rows to bypass this gate.

Preserve the old release, database, credentials, key service, legacy archive objects and
ciphertext as encrypted rollback evidence. If any wrap or legacy record exists,
restore/reseal, export, or explicitly retire it under the old release in a separately
reviewed migration before trying again. Verify the corresponding remote/local object and
retention evidence before retirement. A backup row without a BSE1 artifact ledger is not
proof that no remote ZIP exists; it must be exported or retired under the old release too.
Never edit provider names, artifact formats,
generation or witness values in `.env` or PostgreSQL; labels do not transform wrapped key
material.

```bash
TARGET_COMMIT='<40-character-reviewed-release-commit>'
CURRENT_DOMAIN='<existing-public-hostname>'
git fetch --no-tags --depth=1 origin "${TARGET_COMMIT}"
test "$(git rev-parse 'FETCH_HEAD^{commit}')" = "${TARGET_COMMIT}"
git checkout --detach "${TARGET_COMMIT}"
test "$(git rev-parse HEAD)" = "${TARGET_COMMIT}"

# Mandatory once when upgrading a pre-hardening deployment with no installation
# ID/sentinel. This proves the complete legacy resource inventory before creating only
# the sentinel. It is expected to stop at the live 3.13/blank-generation RabbitMQ gate.
INSTALL_ARGS=(
  --ref "${TARGET_COMMIT}"
  --install-dir "$PWD"
  --project-name backupsheep
  --domain "${CURRENT_DOMAIN}"
  --skip-start
)
# A retained Debian/UID-999 pgdata volume with exact identity generation 2 requires
# both one-time flags in the same invocation:
# INSTALL_ARGS+=(--migrate-postgres-runtime --migrate-database-identities)
# A retained Debian/UID-999 pgdata volume already sealed at identity generation 3
# requires only the runtime flag:
# INSTALL_ARGS+=(--migrate-postgres-runtime)
# A blank shared-superuser identity generation is intentionally unsupported by the
# runtime migrator. Keep that project stopped/intact and create a clean install
# directory under a new exact Compose project namespace; do not set either marker.
# Existing pre-v3 staging layouts also require the one-time gate documented above:
# INSTALL_ARGS+=(--migrate-staging-layout)
# An installation without BACKUPSHEEP_EGRESS_POLICY_GENERATION=2 requires the
# reviewed fail-closed reset documented below:
# INSTALL_ARGS+=(--migrate-egress-policy)
# An existing shared RabbitMQ login also requires the coordinated pending gate:
# INSTALL_ARGS+=(--migrate-rabbitmq-identities)
# A blank/development/retired artifact provider requires the exact-empty archive-inventory gate:
# INSTALL_ARGS+=(--migrate-artifact-key-provider-empty)
# If and only if the reviewed deployment override exists:
# INSTALL_ARGS+=(--approved-compose-file "$PWD/docker-compose.override.yml")
./install.sh "${INSTALL_ARGS[@]}"
# If old `compose down` left only the exact four legacy volumes, rerun that one
# bootstrap with: --adopt-legacy-project backupsheep
# The expected 3.13 refusal is valid only after every earlier selected gate passes.
# STOP this runbook there and complete docs/guides/rabbitmq-upgrade.md. Do not execute
# the normal already-hardened image-switch block below during that coordinated transition.
```

If the staging run used `--skip-start`, an artifact-provider transition intentionally
remains at installation-bound generation `1-pending-empty`; web, workers, Beat and security
preflight stay disabled. After completing any database/broker prerequisites, rerun the same
installer arguments with `--skip-start` removed and keep
`--migrate-artifact-key-provider-empty`. The installer starts only the core, waits for the
fresh `migrate_and_verify_artifact_provider` proof, then seals generation `1` while
retaining `.secrets/artifact_provider_transition_rollback` and any prior credential files.
They are retired only after the rendered model, authenticated security preflight and
healthy core succeed while operations remain disabled. The migration flag cannot be
combined with `--enable-operations`. A failed/interrupted retry retains the
installation-bound rollback policy, both generated keyrings and prior credentials
byte-for-byte; keep operations down and retry with the same flag. After accepted cleanup,
review the provider configuration and rerun without the migration flag and with
`--enable-operations`; source-worker startup then proves the database/files keyring mount,
lane and retained-key-ID boundaries. Preserve an independent encrypted off-host recovery
copy even after successful cleanup. Do not invoke a long-lived service or edit pending
metadata by hand.

A crash can occur after generation `1` is activated but before local rollback/credential
cleanup. In that state the protected `artifact_provider_transition_rollback` file remains,
and the next installer run refuses ordinary startup. Keep operations disabled and rerun
the same reviewed target with `--migrate-artifact-key-provider-empty`; the installer
revalidates the rollback digest, sealed local-file database state, rendered model,
authenticated preflight and healthy core before cleanup. Do not delete the marker or
legacy credential files, edit generation/witness values, or rerun without the flag to
force activation.

Accepted installer cleanup retires only the validated local legacy credential files and
rollback policy; it cannot revoke anything in AWS. As a separate post-retirement operator
action, disable/revoke the legacy IAM access keys or role access, remove AWS KMS grants and
key-policy permissions, and verify the remote identities no longer authorize use. Scope
that action to the exact retired artifact-KMS principal; do not revoke credentials still
used by an explicitly configured AWS source, storage destination, or Amazon SES. Do not
disable or schedule deletion of a KMS key while any approved old-release rollback,
retention, legal-hold, or recovery set still depends on it; key deletion is a separate
destructive decision with its own evidence and approval.

For an eligible generation-2 database, that pre-hardening bootstrap must stage every
applicable database generation-3, staging-v3, RabbitMQ identity-generation-2 and
task-auth-generation-3 transition in the same pending state. A blank shared-superuser
database instead requires the separate fresh-project boundary described above. The
[RabbitMQ migration guide](rabbitmq-upgrade.md) owns the exact
3.13 -> 4.2 -> 4.3 wrapper validation and final installer reconciliation; do not splice
the normal upgrade commands below into it.

The egress flag is a one-time, availability-impacting authorization. It accepts only an
older stock policy in which all six roles are uniformly public with blank lists, blank
with blank lists, or deny with blank lists. It resets every role to `deny`, clears all
address-only and generation-2 lists, and writes `BACKUPSHEEP_EGRESS_POLICY_GENERATION=2`.
Internet-dependent operations will remain blocked until reviewed exact IPv4
`CIDR:port`/IPv6 `[CIDR]:port` tuples and exact DNS names are configured. A mixed or
customized legacy policy is never translated: preserve the old `.env` in the encrypted
recovery copy, review its dependencies, manually reset all roles and lists to the stock
deny state, and then authorize the migration. Do not reuse the flag after generation 2;
the installer rejects it.

For an installation already at staging layout v3, PostgreSQL identity generation 3,
RabbitMQ data generation 4.3, RabbitMQ identity generation 2 and task-auth generation 3,
continue with the normal exact-release image switch:

```bash
TARGET_IMAGE="backupsheep:${TARGET_COMMIT}"
TARGET_POSTGRES_IMAGE="backupsheep-postgres:${TARGET_COMMIT}"
TARGET_EGRESS_IMAGE="backupsheep-egress:${TARGET_COMMIT}"
ENV_TEMPORARY="$(mktemp "${PWD}/.env.backupsheep.XXXXXX")"
chmod 0600 "${ENV_TEMPORARY}"
awk \
  -v app_replacement="BACKUPSHEEP_IMAGE='${TARGET_IMAGE}'" \
  -v postgres_replacement="BACKUPSHEEP_POSTGRES_IMAGE='${TARGET_POSTGRES_IMAGE}'" \
  -v egress_replacement="BACKUPSHEEP_EGRESS_IMAGE='${TARGET_EGRESS_IMAGE}'" '
  BEGIN { replaced = 0; postgres_replaced = 0; egress_replaced = 0 }
  /^[[:space:]]*BACKUPSHEEP_IMAGE=/ {
    if (!replaced) print app_replacement
    replaced = 1
    next
  }
  /^[[:space:]]*BACKUPSHEEP_POSTGRES_IMAGE=/ {
    if (!postgres_replaced) print postgres_replacement
    postgres_replaced = 1
    next
  }
  /^[[:space:]]*BACKUPSHEEP_EGRESS_IMAGE=/ {
    if (!egress_replaced) print egress_replacement
    egress_replaced = 1
    next
  }
  { print }
  END {
    if (!replaced) print app_replacement
    if (!postgres_replaced) print postgres_replacement
    if (!egress_replaced) print egress_replacement
  }
' .env > "${ENV_TEMPORARY}"
mv -f -- "${ENV_TEMPORARY}" .env
unset ENV_TEMPORARY
test "$(stat -c %a .env)" = 600

bs_compose config --quiet
RENDERED_IMAGES="$(bs_compose --profile operations config --images)"
test -n "$({ printf '%s\n' "${RENDERED_IMAGES}" | grep -Fx "${TARGET_IMAGE}"; })"
test -n "$({ printf '%s\n' "${RENDERED_IMAGES}" | grep -Fx "${TARGET_POSTGRES_IMAGE}"; })"
test -n "$({ printf '%s\n' "${RENDERED_IMAGES}" | grep -Fx "${TARGET_EGRESS_IMAGE}"; })"
test -z "$({
  printf '%s\n' "${RENDERED_IMAGES}" |
    awk -v expected="${TARGET_IMAGE}" '/^backupsheep:/ && $0 != expected { print }'
})"
test -z "$({
  printf '%s\n' "${RENDERED_IMAGES}" |
    awk -v expected="${TARGET_POSTGRES_IMAGE}" \
      '/^backupsheep-postgres:/ && $0 != expected { print }'
})"
test -z "$({
  printf '%s\n' "${RENDERED_IMAGES}" |
    awk -v expected="${TARGET_EGRESS_IMAGE}" \
      '/^backupsheep-egress:/ && $0 != expected { print }'
})"
bs_compose build db app app-egress-guard
BUILT_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "${TARGET_IMAGE}")"
BUILT_POSTGRES_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "${TARGET_POSTGRES_IMAGE}")"
BUILT_EGRESS_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "${TARGET_EGRESS_IMAGE}")"
test -n "${BUILT_IMAGE_ID}"
test -n "${BUILT_POSTGRES_IMAGE_ID}"
test -n "${BUILT_EGRESS_IMAGE_ID}"
```

The `migrate`, web, worker and Beat roles all resolve the same image reference. Their
`pull_policy: never` setting requires this explicit local build and prevents a missing
image from being silently replaced from a registry. The database and egress guards have
the same local-only contract. Do not use mutable tags or change any tag between migration
and application startup. Record `BUILT_IMAGE_ID`, `BUILT_POSTGRES_IMAGE_ID` and
`BUILT_EGRESS_IMAGE_ID` in the deployment receipt.

Run migration and preflight explicitly, then start only the profile-less core:

```bash
bs_compose run --rm migrate
bs_compose run --rm preflight
bs_compose up --detach --no-build --no-deps --force-recreate \
  app-egress-guard app
```

The profile-less rollout starts only the core. Once migration, preflight and durable
recovery/queue state are verified, explicitly restore provider execution:

```bash
bs_compose --profile operations up --detach --no-build --no-deps \
  --force-recreate \
  cloud-egress-guard database-egress-guard files-egress-guard \
  storage-egress-guard logs-egress-guard \
  worker-cloud worker-database worker-files worker-storage worker-logs
bs_compose --profile operations up --detach --no-build --no-deps beat
```

That command can resume queued or recoverable provider mutations immediately.

Compose's one-shot preflight is not the only startup check. The immutable image entrypoint
re-validates the runtime and runs `docker_preflight` before each web, worker or Beat
process, including a later automatic restart. Do not override the image entrypoint in the
normal rollout. Preflight also requires Django's migration plan to contain no unapplied
migrations; a refusal indicates a weakened or incomplete runtime/configuration that must
be fixed, not bypassed.

## Verify the deployment

```bash
bs_compose --profile operations ps --all
bs_compose logs --tail=200 db-provision migrate preflight app
bs_compose exec -T app python manage.py check
curl -fsS http://127.0.0.1:8000/healthz/
DB_CONTAINER="$(bs_compose ps -q db)"
test -n "${DB_CONTAINER}"
test "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' \
  "${DB_CONTAINER}")" = healthy
bs_compose exec -T rabbitmq rabbitmq-diagnostics -q ping
bs_compose --profile operations exec -T worker-cloud celery -A backupsheep inspect ping
```

The database assertion reuses the stock image's authenticated file-backed healthcheck;
`pg_isready` alone only proves that a server is listening. Verify that `migrate` and
`preflight` exited `0` and every intentionally enabled worker answers. Then:

1. check login and the dashboard through the public HTTPS URL;
2. inspect existing schedules, storage and source records;
3. re-enable Beat/schedules;
4. observe recovery of any interrupted durable work;
5. run a disposable on-demand backup and restore rehearsal for affected providers;
6. keep the pre-upgrade recovery set until the observation window closes.

`/healthz/` returning `ok` is not a database, broker, worker or provider acceptance test.

## Configuration changes between versions

Compare the new `.env_sample` with the existing `.env` without printing secrets into logs.
Add new non-secret/default keys deliberately and preserve existing values. Keep all direct
stock secret values and the two legacy shared managed-key settings blank in `.env`, and
validate the corresponding `.secrets` files; never copy them back into environment
variables for convenience. Because settings also read
`.env_sample` as defaults, a missing optional key may still boot, but that does not mean
its production default was reviewed.

Validate Compose with `bs_compose config --quiet`; do not publish the expanded
configuration, which may contain credentials.

## Rollback

A container rollback alone is safe only when the older code supports the already-migrated
schema. Do not assume Django migrations are reversible or that an older application can
read a newer database.

The reliable rollback unit is:

- the previous code revision/image;
- its exact `.env`, `.secrets` and deployment overrides;
- the pre-upgrade PostgreSQL dump;
- the matching Local Storage/work-volume state when the upgrade changed them.

For a migration-related rollback:

1. stop `app`, all workers and Beat;
2. preserve the failed-upgrade database and logs for diagnosis;
3. restore the pre-upgrade database into a clean/replacement instance;
4. check out/build the recorded previous revision;
5. restore matching configuration and volume data;
6. start the stack and perform the full dependency and recovery verification.

Do not run `migrate <app> <older-number>` against production merely to force a rollback;
data migrations and application changes may not have a safe reverse path.

## PostgreSQL major-version changes

The stock image uses PostgreSQL 18.6 on Alpine 3.24, UID/GID `70:70`, ICU `und`, and the
installation-witnessed `postgres_data_v1` volume. It never mounts the retired
Debian/UID-999 `pgdata` volume. Follow the explicit
[PostgreSQL Alpine/ICU migration gate](postgres-runtime-migration.md) for that one-time
transition. The automatic gate accepts only exact witnessed generation-2 or
generation-3 sources; blank shared-superuser sources require a clean installation
directory and new Compose project namespace, with the old project retained offline.
Other major-version or non-stock database changes require a separately
reviewed logical dump/restore or supported `pg_upgrade` plan; never change an image tag
against an old data directory. Rehearse on a copy and preserve the old volume and exact
image until database verification and a restore test pass.

## Upgrade completion record

Record:

- old and new commit/image identifiers;
- backup artifact names and verification results;
- migration exit and Django check result;
- dependency/worker health results;
- first successful backup and restore rehearsal after upgrade;
- any deferred provider or accessibility checks;
- rollback-set retention deadline.
