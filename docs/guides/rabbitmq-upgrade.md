# RabbitMQ 3.13 to 4.3 migration gate

The stock Compose target is the digest-pinned RabbitMQ 4.3.5 image. That target is safe
for a fresh volume, but **must not be started directly against an existing 3.13 volume**.
RabbitMQ's supported path is 3.13.x to 4.2.x, enable all feature flags, then 4.3.x.
See RabbitMQ's upstream [feature-flag guidance](https://www.rabbitmq.com/docs/feature-flags)
for the version-specific migration contract; the wrapper enforces the stricter stock
BackupSheep invariants described below.

Legacy `RABBITMQ_DEFAULT_*` values initialize only a blank broker database. Changing a
secret file does not rotate credentials in an existing `rabbitmq_data` volume. After
the data-format transition, complete the separate
[generation-2 identity migration](rabbitmq-identity-migration.md); its one-shot
provisioner performs the exact credential and permission reconciliation. `install.sh`
refuses to open an existing volume when it cannot prove the exact pinned broker target; it never runs
the version migration automatically. Complete this operator-run migration before
allowing the pinned 4.3 service to open a legacy volume.

`BACKUPSHEEP_RABBITMQ_DATA_GENERATION` is a wrapper/installer-owned data-format witness, not a
version-selection switch. Leave it blank unless the verified installer has set it. For a
new project with no RabbitMQ container or volume, the installer records `4.3` before first
start. For existing resources with a blank witness, only the explicit wrapper transition
may record it because that path attests the pinned image reference and local image ID as
well as server/Khepri state. A volume
without a live container, a stopped/unhealthy broker, duplicate resources, an unknown
witness, or a 3.13/4.2 result stops installation. Never type `4.3` merely to bypass that
refusal; doing so does not migrate or validate broker data.

## Required upgrade sequence

Before using the hardened wrapper against a pre-hardening deployment, run the installer
from the exact reviewed target checkout once. This is an identity bootstrap, not a broker
upgrade: with legacy containers present it proves the exact project, installation path,
base/approved-override config history, known services and canonical networks/volumes,
then creates and re-inspects only the installation-identity sentinel. It is expected to
stop at the blank-generation/3.13 gate without building or starting 4.3:

```bash
TARGET_COMMIT="$(git rev-parse HEAD)"
test "${#TARGET_COMMIT}" = 40
INSTALL_ARGS=(
  --ref "${TARGET_COMMIT}"
  --install-dir "$PWD"
  --project-name backupsheep
  --skip-start
)
# If and only if this installation has the reviewed deployment override:
# INSTALL_ARGS+=(--approved-compose-file "$PWD/docker-compose.override.yml")
./install.sh "${INSTALL_ARGS[@]}"
```

Do not continue unless the only failure is the documented live legacy RabbitMQ
generation refusal and the new `.env` contains one stable installation ID. If an old
`compose down` removed all containers and networks, use the explicit
[`--adopt-legacy-project` four-volume branch](installation.md#one-time-legacy-compose-down-adoption)
on this bootstrap invocation. It accepts only the exact stock legacy volume set and
creates the same sentinel after its independent proof.

Then schedule the broker maintenance window and stop if any gate cannot be proven:

```bash
BS_COMPOSE=("$PWD/backupsheep-compose")
# If this deployment has a reviewed override, add it before the migration hop:
# BS_COMPOSE+=(--approved-compose-file "$PWD/docker-compose.override.yml")
bs_compose() { "${BS_COMPOSE[@]}" "$@"; }
bs_compose config --quiet
```

The shipped wrapper deliberately strips `COMPOSE_PROFILES`, `COMPOSE_BAKE`,
`BUILDX_BAKE_FILE`, application interpolation and orphan-removal controls while retaining
only the reviewed Docker transport, proxy and CA context.

1. Record the current image ID/version, node health, enabled feature flags, users, vhosts,
   queue names, durable flag, ready/unacknowledged message counts and consumer counts.
2. Stop Beat from scheduling new work, stop producers, and let workers finish or safely
   requeue their in-flight jobs. Export broker definitions and take a recoverable snapshot
   of the `rabbitmq_data` volume. Do not use `docker compose down --volumes`.
3. While still on 3.13, retain the dedicated legacy `backupsheep` user and vhost long
   enough to complete the data-format hop. Generation-2 identity migration later
   deletes that shared login and creates the lane-specific users. Through a trusted
   server console, grant the legacy user configure/write/read permissions only on that
   vhost. Put the matching value in the protected legacy secret file, leave direct
   `RABBITMQ_PASSWORD` blank in `.env`, and
   verify all app roles reconnect. Do not put the password in documentation, tickets,
   process arguments or unattended logs.
4. On 3.13, enable every stable and required feature flag and confirm the node is healthy.
   The wrapper queries `name stability state` as the named `rabbitmq` account and refuses ambiguous,
   duplicate, empty or disabled stable/required rows. Resolve any disabled/deprecated
   feature before continuing. It also requires exactly one `khepri_db` row in the
   `disabled` state. If experimental Khepri was enabled on 3.13, stop: that node cannot
   take this in-place 4.x path; use a separately rehearsed blue-green migration instead.
5. Start the compatibility image using the reviewed overlay:

   ```bash
   bs_compose \
     --allow-rabbitmq-generation-transition=4.2 \
     --approved-compose-file "$PWD/deploy/rabbitmq/upgrade-4.2.9.compose.yml" \
     up --detach --no-deps rabbitmq
   ```

   The 4.2 image is independently resolved from base plus the compatibility overlay as
   exactly one tag-and-digest reference. Before the next hop, the wrapper requires the
   container's configured reference and image ID to match that isolated model. Confirm it
   reports RabbitMQ 4.2.9, enable every stable and required 4.2 feature flag, explicitly
   enable `khepri_db`, and wait for the Khepri migration to finish. Re-run the node,
   vhost, permission, durable-queue, message and consumer evidence checks. Take another
   recoverable volume snapshot.
6. Remove the temporary overlay from the command and start the pinned 4.3.5 target:

   ```bash
   bs_compose --allow-rabbitmq-generation-transition=4.3 \
     up --detach --no-deps rabbitmq
   ```

   After Compose succeeds, the wrapper re-inventories the exact project, requires the
   recreated RabbitMQ container to use the base model and current installation ID, waits
   for healthy `4.3.5`, proves exactly one enabled `khepri_db` record, and attests both
   `.Config.Image` and `.Image` against the base model's single tag-and-SHA256-pinned
   image. The post-hop gate requires all required flags and Khepri enabled but permits
   stable flags introduced by 4.3 to remain disabled long enough to complete the hop.
   Only then does it atomically record the `4.3` generation witness. Enable every other
   stable 4.3 feature flag immediately and repeat the same evidence checks.

7. Confirm `.env` now contains exactly one
   `BACKUPSHEEP_RABBITMQ_DATA_GENERATION='4.3'` line and preserve that file with the
   matching broker-volume recovery set. If Compose completed but the shell was interrupted
   before the witness write, rerun the exact step 6 command: reconciliation is accepted
   only for healthy `4.3.5` with every required flag and Khepri enabled, the exact base model and matching pinned
   image reference/ID. A different 4.3 release is refused before Compose, preventing an
   accidental downgrade to 4.3.5. Then explicitly restart
   the operations profile with `bs_compose --profile operations up --detach`, run a
   scheduled-backup smoke test, and verify one durable request, one broker delivery and
   one terminal backup result.

If a hop or post-transition attestation fails, the generation witness remains blank.
Stop and restore the volume snapshot with the exact prior image. Do not
attempt a downgrade against a data directory already migrated by a newer RabbitMQ release.
