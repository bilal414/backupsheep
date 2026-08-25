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
   } | grep -Ev '^(db|rabbitmq)$' || true)"
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
   critical work-volume material.
7. Confirm free disk for both old/new image layers and migration work.

If the release changes the pinned RabbitMQ generation, stop here and follow the dedicated
[RabbitMQ migration gate](rabbitmq-upgrade.md). `BACKUPSHEEP_RABBITMQ_DATA_GENERATION`
is an installer-owned witness, not a version switch; never edit it to make an old volume
appear migrated.

See [Disaster recovery](disaster-recovery.md#back-up-the-control-plane) for the backup
commands.

## One-time SSH trust and managed-key separation

Releases with the dedicated `ssh_trust` volume deliberately remove `backup_workdir` from
the web app. Before replacing the legacy app container, explicitly migrate its old
`/code/_storage/ssh_known_hosts` file and any managed private key stored under
`_storage`. The installer will not infer or copy private-key material.

1. While the old app container still exists and is running, make a private staging
   directory and resolve that exact container:

   ```bash
   umask 077
   SSH_MIGRATION_DIR="$(mktemp -d "${PWD}/.backupsheep-ssh-migration.XXXXXX")"
   LEGACY_APP="$(bs_compose ps -q app)"
   test -n "${LEGACY_APP}"
   test "$(docker inspect --format '{{.State.Running}}' "${LEGACY_APP}")" = true
   ```

2. If the legacy known-hosts file exists, require a regular non-symlink file and copy it
   without printing its contents:

   ```bash
   if docker exec "${LEGACY_APP}" test -e /code/_storage/ssh_known_hosts; then
     docker exec "${LEGACY_APP}" test -f /code/_storage/ssh_known_hosts
     docker exec "${LEGACY_APP}" test ! -L /code/_storage/ssh_known_hosts
     docker cp \
       "${LEGACY_APP}:/code/_storage/ssh_known_hosts" \
       "${SSH_MIGRATION_DIR}/known_hosts"
     chmod 0444 "${SSH_MIGRATION_DIR}/known_hosts"
   fi
   ```

3. Read the current `SSH_MANAGED_PRIVATE_KEY_PATH` locally without logging it. If it is
   non-empty, resolve a relative value from `/code`, confirm the resulting absolute
   container path is exactly the key intended for this installation, then copy it to the
   private staging directory. Replace the placeholder below only after that review:

   ```bash
   LEGACY_KEY_CONTAINER_PATH='/code/_storage/replace-with-reviewed-key-path'
   docker exec "${LEGACY_APP}" test -f "${LEGACY_KEY_CONTAINER_PATH}"
   docker exec "${LEGACY_APP}" test ! -L "${LEGACY_KEY_CONTAINER_PATH}"
   docker cp \
     "${LEGACY_APP}:${LEGACY_KEY_CONTAINER_PATH}" \
     "${SSH_MIGRATION_DIR}/managed_private_key"
   chmod 0600 "${SSH_MIGRATION_DIR}/managed_private_key"
   ```

   Skip this step when the legacy setting is blank. Stop if the path is ambiguous or
   points outside the expected BackupSheep data; do not guess based on a filename.

4. After checking out/building the new release, install the optional source secret. A
   pre-existing non-empty destination requires manual reconciliation; never overwrite a
   different key. If there was no legacy key, create the required empty sentinel instead:

   ```bash
   if test -f "${SSH_MIGRATION_DIR}/managed_private_key"; then
     if test -e .secrets/ssh_managed_private_key; then
       test -f .secrets/ssh_managed_private_key
       test ! -L .secrets/ssh_managed_private_key
       test "$(stat -c %h .secrets/ssh_managed_private_key)" = 1
     fi
     test ! -s .secrets/ssh_managed_private_key
     install -m 0444 \
       "${SSH_MIGRATION_DIR}/managed_private_key" \
       .secrets/.ssh_managed_private_key.new
     mv .secrets/.ssh_managed_private_key.new .secrets/ssh_managed_private_key
   elif test ! -e .secrets/ssh_managed_private_key; then
     : > .secrets/ssh_managed_private_key
     chmod 0444 .secrets/ssh_managed_private_key
   fi
   ```

   Clear the legacy `SSH_MANAGED_PRIVATE_KEY_PATH` value in `.env`. Stock Compose owns
   the runtime path: it mounts the mode-`0444` source only in app/database/files, and the
   entrypoint copies a valid, unencrypted, non-empty key (maximum 64 KiB) into private
   tmpfs as `/run/backupsheep/ssh/managed_private_key`, mode `0600`. Empty means disabled.
   Never point SSH directly at `/run/secrets/ssh_managed_private_key`.

5. After the new image and secret files exist but before enabling operations, populate
   the new trust volume from the staged file. This reviewed one-off intentionally
   overrides the entrypoint for data migration only; normal services must retain it:

   ```bash
   if test -f "${SSH_MIGRATION_DIR}/known_hosts"; then
     bs_compose --allow-reviewed-runtime-overrides run --rm --no-deps \
       --entrypoint /bin/sh \
       --volume "${SSH_MIGRATION_DIR}/known_hosts:/migration/known_hosts:ro" \
       app -ceu '
         umask 077
         test -f /migration/known_hosts
         target=/var/lib/backupsheep/ssh-trust/known_hosts
         temporary=/var/lib/backupsheep/ssh-trust/.known_hosts.new
         test ! -e "${target}"
         cp /migration/known_hosts "${temporary}"
         chmod 0600 "${temporary}"
         mv "${temporary}" "${target}"
         test "$(stat -c %u:%g:%a "${target}")" = 10001:10001:600
       '
   fi
   ```

6. Start the core normally. A non-empty invalid, encrypted, non-regular, NUL-containing
   or oversized key now fails closed in the entrypoint. Verify the trust file (when one
   was migrated), runtime key ownership/mode and public-key derivation without printing
   private material. Then retain the staging directory only in the encrypted rollback
   set or remove it through the operator's approved secure-cleanup process.

The resulting boundary is app read/write and database/files read-only for `ssh_trust`;
only app/database/files receive and stage the optional key. No other role receives either
the key or trust volume.

## One-time non-root volume migration

The application image runs as UID/GID `10001:10001`. Fresh stock named volumes inherit
that ownership from the image. This procedure deliberately uses the **new** image and
wrapper. First complete the exact checkout, protected `.env` tag update, model validation,
and image build in [Upgrade to the exact reviewed commit](#upgrade-to-the-exact-reviewed-commit).
Do not run the commands below from the old checkout. Before starting migrations or any new
application role, stop every application writer, snapshot both application volumes, and
change the existing volume ownership once:

```bash
bs_compose --profile operations stop app worker-cloud worker-database worker-files worker-storage worker-logs beat
bs_compose --allow-reviewed-runtime-overrides --profile operations run --rm --no-deps \
  --user 0:0 \
  --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE \
  --entrypoint sh worker-storage -ceu '
    chown -R 10001:10001 /code/_storage /backups
    find /code/_storage /backups -type d -exec chmod 0700 {} +
    find /code/_storage /backups -type f -exec chmod 0600 {} +
  '
bs_compose --profile operations run --rm --no-deps worker-storage sh -ceu '
  for directory in /code/_storage /backups; do
    probe="$directory/.backupsheep-nonroot-probe"
    : > "$probe"
    test "$(stat -c %u:%g:%a "$probe")" = "10001:10001:600"
    rm -f "$probe"
  done
'
```

Run this only during the maintenance window and only against the two resolved BackupSheep
volumes. For bind mounts, NFS, EFS or other shared filesystems, establish an equivalent
UID/GID or ACL policy through that storage system instead; do not recursively `chown` an
unverified shared path. Stop if ownership or volume identity is unclear.

## Upgrade to the exact reviewed commit

Fetch only the reviewed commit, verify it is the requested object and detach the checkout.
Do not pull a mutable branch or tag. Preserve `.env` and `.secrets`; stop if Git would
overwrite or delete an unexplained local file. The wrapper intentionally discards an
ambient `BACKUPSHEEP_IMAGE`, so atomically persist the exact tag in the already protected
deployment `.env` *before* rendering or building the model:

```bash
TARGET_COMMIT='<40-character-reviewed-release-commit>'
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
  --skip-start
)
# When and only when this installation still predates PostgreSQL identity generation 2,
# first complete docs/guides/database-identity-migration.md and then add:
# INSTALL_ARGS+=(--migrate-database-identities)
# If and only if the reviewed deployment override exists:
# INSTALL_ARGS+=(--approved-compose-file "$PWD/docker-compose.override.yml")
./install.sh "${INSTALL_ARGS[@]}"
# If old `compose down` left only the exact four legacy volumes, rerun that one
# bootstrap with: --adopt-legacy-project backupsheep
# Continue only after the expected RabbitMQ refusal and a verified matching sentinel;
# then follow docs/guides/rabbitmq-upgrade.md before any 4.3 start.

TARGET_IMAGE="backupsheep:${TARGET_COMMIT}"
TARGET_POSTGRES_IMAGE="backupsheep-postgres:${TARGET_COMMIT}"
ENV_TEMPORARY="$(mktemp "${PWD}/.env.backupsheep.XXXXXX")"
chmod 0600 "${ENV_TEMPORARY}"
awk \
  -v app_replacement="BACKUPSHEEP_IMAGE='${TARGET_IMAGE}'" \
  -v postgres_replacement="BACKUPSHEEP_POSTGRES_IMAGE='${TARGET_POSTGRES_IMAGE}'" '
  BEGIN { replaced = 0 }
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
  { print }
  END {
    if (!replaced) print app_replacement
    if (!postgres_replaced) print postgres_replacement
  }
' .env > "${ENV_TEMPORARY}"
mv -f -- "${ENV_TEMPORARY}" .env
unset ENV_TEMPORARY
test "$(stat -c %a .env)" = 600

bs_compose config --quiet
RENDERED_IMAGES="$(bs_compose --profile operations config --images)"
test -n "$({ printf '%s\n' "${RENDERED_IMAGES}" | grep -Fx "${TARGET_IMAGE}"; })"
test -n "$({ printf '%s\n' "${RENDERED_IMAGES}" | grep -Fx "${TARGET_POSTGRES_IMAGE}"; })"
test -z "$({
  printf '%s\n' "${RENDERED_IMAGES}" |
    awk -v expected="${TARGET_IMAGE}" '/^backupsheep:/ && $0 != expected { print }'
})"
test -z "$({
  printf '%s\n' "${RENDERED_IMAGES}" |
    awk -v expected="${TARGET_POSTGRES_IMAGE}" \
      '/^backupsheep-postgres:/ && $0 != expected { print }'
})"
bs_compose build db app
BUILT_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "${TARGET_IMAGE}")"
BUILT_POSTGRES_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "${TARGET_POSTGRES_IMAGE}")"
test -n "${BUILT_IMAGE_ID}"
test -n "${BUILT_POSTGRES_IMAGE_ID}"
```

If this is the first upgrade from a root-running BackupSheep image, stop here and perform
the [one-time non-root volume migration](#one-time-non-root-volume-migration) with this
just-built exact image. Do not start `migrate`, `preflight`, `app`, a worker, or Beat until
that ownership probe passes.

The `migrate`, web, worker and Beat roles all resolve the same image reference. Their
`pull_policy: never` setting requires this explicit local build and prevents a missing
image from being silently replaced from a registry. The database has the same local-only
contract. Do not use mutable tags or change either tag between migration and application
startup. Record `BUILT_IMAGE_ID` and `BUILT_POSTGRES_IMAGE_ID` in the deployment receipt.

Run migration and preflight explicitly, then start only the profile-less core:

```bash
bs_compose run --rm migrate
bs_compose run --rm preflight
bs_compose up --detach app
```

The profile-less rollout starts only the core. Once migration, preflight and durable
recovery/queue state are verified, explicitly restore provider execution:

```bash
bs_compose --profile operations up --detach
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
bs_compose exec -T db sh -c \
  'pg_isready --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"'
bs_compose exec -T rabbitmq rabbitmq-diagnostics -q ping
bs_compose --profile operations exec -T worker-cloud celery -A backupsheep inspect ping
```

Verify that `migrate` and `preflight` exited `0` and every intentionally enabled worker
answers. Then:

1. check login and the dashboard through the public HTTPS URL;
2. inspect existing schedules, storage and source records;
3. re-enable Beat/schedules;
4. observe recovery of any interrupted durable work;
5. run a disposable on-demand backup and restore rehearsal for affected providers;
6. keep the pre-upgrade recovery set until the observation window closes.

`/healthz/` returning `ok` is not a database, broker, worker or provider acceptance test.

## Configuration changes between versions

Compare the new `.env_sample` with the existing `.env` without printing secrets into logs.
Add new non-secret/default keys deliberately and preserve existing values. Keep the four
required stock installation values and the legacy managed-key path blank in `.env`, and
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

The stock image currently uses PostgreSQL 18 and mounts `/var/lib/postgresql`, whose
versioned layout differs from older images. A major PostgreSQL change requires a logical
dump/restore or a supported `pg_upgrade` plan, not just changing the image tag against an
old data directory. Rehearse it on a copy and preserve the old volume until the new
database and restore tests pass.

## Upgrade completion record

Record:

- old and new commit/image identifiers;
- backup artifact names and verification results;
- migration exit and Django check result;
- dependency/worker health results;
- first successful backup and restore rehearsal after upgrade;
- any deferred provider or accessibility checks;
- rollback-set retention deadline.
