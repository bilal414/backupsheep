# RabbitMQ 3.13 to 4.3 migration gate

This runbook is only for a reviewed `local-build` installation. Signed-release
installations are fresh-only: `install.sh --release-tag` rejects legacy-project and
legacy-node adoption, and `backupsheep-compose` rejects every RabbitMQ transition flag.
To retain data while moving to a signed release, restore a separately verified recovery
set into another fresh signed project and preserve the old project unchanged.

The steady-state target is BackupSheep's patched RabbitMQ 4.3.5 derivative, rooted in an
exact digest-pinned upstream image. It **must not be started directly** on a 3.13 data
directory. The upstream compatibility class is 3.13.x to 4.2.x and then
4.3.x; this repository narrows those hops to the exact patch releases below. The only
in-place path implemented here is:

1. inspect and reopen the exact old node with the pinned 3.13.7 source image;
2. convert only the broker volume's UID/GID and start pinned 4.2.9;
3. enable every 4.2 feature flag, including Khepri, then start pinned 4.3.5;
4. prove the canonical 4.3 model before committing the installer-owned generation.

RabbitMQ's [feature-flag guidance](https://www.rabbitmq.com/docs/feature-flags) remains
the upstream compatibility contract. The wrapper adds stricter BackupSheep identity,
ownership, topology, image, configuration, and crash-recovery checks.
`install.sh` refuses to open an existing volume when it cannot prove the applicable
fresh or migration state. Invoking a transition overlay with raw `docker compose` skips
the wrapper's protected evidence and is unsupported.

Every compatibility broker is intentionally disposable and isolated: the 3.13.7,
4.2.9, and transition-mode 4.3.5 services have `network_mode: none`, no Compose
networks, no mounted secrets, no enabled RabbitMQ plugins, no dependent services, and
`restart: "no"`. They can communicate only over their own loopback interface while the
wrapper drives the vendor CLI with `docker exec`. Only the final, re-attested 4.3.5
canonical service regains the private product networks and RabbitMQ bootstrap secret.

RabbitMQ 4.2.9 remains in the affected range for multiple upstream advisories,
including the
[Web STOMP pre-authentication memory-exhaustion advisory](https://github.com/rabbitmq/rabbitmq-server/security/advisories/GHSA-cfqc-c682-93mm),
which is fixed in 4.2.10. RabbitMQ lists that patched 4.2 build as Enterprise Support;
as of 2026-08-30 its public GitHub binary/signature links and official Docker
`rabbitmq:4.2.10-alpine` tag were unavailable, while the public 4.2 tag still resolved
to 4.2.9. BackupSheep therefore does not represent 4.2.9 as vulnerability-free. The
transition disables every plugin (including Web
STOMP and Prometheus), mounts no secret, has no network namespace connectivity, accepts
only a drained single-node data set, and exists only long enough to enable and attest
feature flags and Khepri before the 4.3.5 hop. These controls make the cited remote
plugin path unreachable within the supported migration command, but they do not erase
the upstream advisory. Rebase this derivative and its exact attestations to 4.2.10 or a
later supported 4.2 patch as soon as an official image is available. An operator who
cannot accept even this short, local compatibility hop must use reviewed blue-green
export/import or recovery instead of in-place migration.

## Supported legacy source

In-place adoption is deliberately narrow. The retained 3.13 volume must be the exact old
single-node stock model:

- its only virtual host is `/`;
- its only user is `guest` with the `administrator` tag;
- every queue has zero ready messages, zero unacknowledged messages, and zero consumers;
- the durable node host is either `rabbitmq` or the unique, reviewed 12-character
  lowercase hexadecimal hostname assigned by Docker to the old container;
- its Mnesia tree contains exactly that one node and the expected single-node shutdown,
  schema, table, cookie, and feature-flag records, all owned by `999:999`; and
- the tree contains no symlinks, special files, hard-linked regular files,
  group/world-writable entries, foreign node records, or unclean-shutdown PID record.

The wrapper checks these conditions; it does not infer intent from a nonempty directory.
An unexpected user or vhost, a queue that was not drained, a custom/clustered layout, an
ambiguous or multiple node tree, or an unsupported node hostname requires a separately
reviewed blue-green export/import or restore. Do not delete an extra tree merely to make
the in-place predicate pass.

`BACKUPSHEEP_RABBITMQ_NODE_HOST` permanently retains the selected node identity through
3.13.7, 4.2.9, 4.3.5, and steady state. Changing it can make RabbitMQ open a new Mnesia
database beside the real one. Never hand-edit it after installation.

## Protected transition state

`BACKUPSHEEP_RABBITMQ_DATA_GENERATION` is an installer/wrapper-owned witness, not a
version selector. It stays blank throughout the migration. Before each Docker mutation,
the wrapper atomically writes the owner-only, mode-`0600`
`.backupsheep-rabbitmq-transition-state` ledger. That ledger binds the installation ID,
project, exact source evidence, target image reference and local image ID, and target
configuration hash. Its only valid progress states are:

| Short name | Ledger state | Meaning |
| --- | --- | --- |
| P313 | `prepared:legacy-volume:3.13.7` | exact detached legacy volume may be opened by the pinned source |
| A313 | `attested:3.13.7:3.13.7` | exact healthy 3.13.7 source and stock identity were proved |
| P42 | `prepared:3.13.7:4.2.9` | exact attested 3.13.7 source may be recovered, cleanly stopped and inspected |
| source-clean 4.2 | `source-clean:3.13.7:4.2.9` | exact 3.13.7 source was cleanly stopped and inspected; source detachment and idempotent UID conversion are authorized |
| target-ready 4.2 | `target-ready:3.13.7:4.2.9` | UID conversion, detachment and exact 4.2 clean-layout inspection passed; exact 4.2 target creation/recovery is authorized |
| A42 | `attested:4.2.9:4.2.9` | exact healthy 4.2.9 target with every feature flag and Khepri enabled was proved |
| P43 | `prepared:4.2.9:4.3.5` | exact attested 4.2.9 source with all flags/Khepri enabled may take the 4.3 hop |
| target-ready 4.3 | `target-ready:4.2.9:4.3.5` | exact 4.2.9 source was cleanly stopped and inspected; source detachment and exact 4.3 target creation/recovery are authorized |
| A43 | `attested:4.3.5:4.3.5` | exact healthy 4.3.5 transition target was proved |

The broker-writable pending/final record in `rabbitmq_data` is only a secondary completion
witness. It never authorizes recreation, repair, or a generation commit by itself. After
A43, the wrapper durably finalizes that record, recreates the canonical non-transition
4.3 model, re-attests it, atomically commits
`BACKUPSHEEP_RABBITMQ_DATA_GENERATION='4.3'` in `.env`, and only then removes the protected
ledger. Preserve `.env`, this ledger when present, `rabbitmq_data`, exact image evidence,
and matching secrets as one recovery set.

## Required upgrade sequence

### 1. Quiesce and capture the old node identity

Stop Beat and every producer. Let workers complete, or explicitly reconcile and requeue
their in-flight jobs. The in-place path intentionally discards the old `/` vhost when the
new per-lane topology is provisioned, so **every legacy queue must be fully drained**.
Record users, vhosts, queues, consumers, server version, node name, image ID, and feature
flags, then take an encrypted, restorable snapshot of the complete control plane and all
four old named volumes.

While the exact old broker is still healthy, identify its one reviewed container and
capture its hostname. Do not derive this value after the container has been removed:

```bash
PROJECT='backupsheep'
OLD_RABBIT_CONTAINER='<exact-reviewed-old-rabbitmq-container-id-or-name>'
LEGACY_NODE_HOST="$(docker inspect --format '{{.Config.Hostname}}' \
  "${OLD_RABBIT_CONTAINER}")"
printf '%s\n' "${LEGACY_NODE_HOST}" | grep -Eq '^(rabbitmq|[0-9a-f]{12})$' || {
  printf '%s\n' 'unsupported legacy RabbitMQ hostname' >&2
  exit 1
}
```

Confirm the node reports `rabbit@${LEGACY_NODE_HOST}`, only `/` and
`guest [administrator]`, and zero ready/unacknowledged/consumer counts. Enable every
stable and required 3.13 feature flag while Khepri remains disabled. If Khepri is already
enabled on 3.13, stop and use reviewed blue-green recovery.

### 2. Remove the old runtime, preserving every volume

Use the exact old deployment checkout/model to remove the whole Compose runtime. Do not
use `--volumes`, an orphan-removal flag, Docker prune, or a guessed new model:

```bash
# Run from the exact old deployment checkout.
docker compose --project-name "${PROJECT}" down

test -z "$(docker ps --all --quiet \
  --filter "label=com.docker.compose.project=${PROJECT}")"
test -z "$(docker network ls --quiet \
  --filter "label=com.docker.compose.project=${PROJECT}")"
```

The source-adoption command requires **all** project application, worker, scheduler,
database, guard, provisioner, and one-shot containers to be absent, and requires zero
project networks. The four reviewed legacy data volumes remain. If another container
attaches the RabbitMQ volume, stop; the wrapper will not detach it by guess.

### 3. Bootstrap the reviewed local checkout without starting it

Run the exact reviewed target checkout's installer. For the old `compose down` four-volume
layout, explicitly adopt both the project and the captured node host. The stopped-volume
exception requires `--legacy-rabbitmq-node-host HOST --skip-start`; it is unavailable in
signed-release mode:

```bash
TARGET_COMMIT="$(git rev-parse HEAD)"
test "${#TARGET_COMMIT}" = 40
CURRENT_DOMAIN='<existing-public-hostname>'
BASE_INSTALL_ARGS=(
  --ref "${TARGET_COMMIT}"
  --install-dir "$PWD"
  --project-name "${PROJECT}"
  --domain "${CURRENT_DOMAIN}"
)
# If and only if this installation has a reviewed deployment override:
# BASE_INSTALL_ARGS+=(--approved-compose-file "$PWD/docker-compose.override.yml")
BOOTSTRAP_ARGS=(
  "${BASE_INSTALL_ARGS[@]}"
  --migrate-staging-layout
  --migrate-database-identities
  --migrate-rabbitmq-identities
)
./install.sh "${BOOTSTRAP_ARGS[@]}" \
  --adopt-legacy-project "${PROJECT}" \
  --legacy-rabbitmq-node-host "${LEGACY_NODE_HOST}" \
  --skip-start
```

This one-time adoption accepts only the exact stock four-volume names and labels, with
zero project containers/networks and no prior installation sentinel. It persists the
project, installation ID, and durable node host but does not open the broker. On later
installer runs, omit `--adopt-legacy-project` and `--legacy-rabbitmq-node-host`; their
protected values must already match.

If this is an already identified project rather than the four-volume compose-down case,
do not use `--adopt-legacy-project`. A stopped blank-generation volume still requires the
explicit reviewed node-host argument and `--skip-start` on the first target-checkout run.
An ambiguous/multiple node tree is not made safe by selecting one host: use blue-green
recovery.

### 4. Build the reviewed 3.13.7 security derivative

Do not run the historical upstream 3.13.7 image against production data. It contains
packages with known High findings. The hardened wrapper instead builds the repository's
commit-tagged `Dockerfile.rabbitmq-legacy-source` derivative from the exact historical
base digest. It replaces the historical OTP patch with exact OTP 26.2.5.21 and replaces
the Erlang-loaded `/opt/openssl` tree with exact OpenSSL 3.5.8, using two immutable donor
index digests. It also applies the reviewed Ubuntu package updates and attests its
immutable image ID, both donor labels, exact OTP and RabbitMQ versions, actual loaded
crypto library, package versions, absent `gosu`, and non-root identity before opening
the volume. The source overlay remains `pull_policy: never`, so the resulting runtime
cannot be replaced by a registry pull.

RabbitMQ 3.13.7's published compatibility ceiling is OTP 26.2.x. OTP 26 has no release
containing fixes for eight later network/ETF advisories that Grype associates with the
umbrella Erlang binary package. BackupSheep therefore does not call this derivative
vulnerability-free. `deploy/rabbitmq/legacy-source-otp26.vex-policy.json` records the
reviewed decision inputs for exactly those eight CVEs and exactly
`pkg:generic/erlang@26.2.5.21`. CI materializes the OpenVEX document only after the
unsuppressed scan: its product tag and SHA-256 hash bind the statement to that exact
legacy image manifest, with Erlang as the named subcomponent. The gate requires the
ignored High/Critical set, package, version, image digest, and VEX rule to match
exactly. Any additional ignored or active High/Critical finding fails.

That decision depends on the enforced runtime model, not on the age of the software:
the one-time source has `network_mode: none`, no mounted secrets, no enabled plugins,
no peer process, no application traffic, and cannot start until every old queue is
proven drained with zero consumers or unacknowledged deliveries. Those constraints make
the cited Megaco, SCTP, epmd, TLS, certificate, and attacker-controlled external-term
paths unreachable. Do not reuse this image for a networked broker or steady-state
service; doing so invalidates the VEX analysis.

Without an exact protected transition ledger, the first explicit preparation command
always performs a base-only `--pull --no-cache` rebuild and then attests the resulting
image ID; a pre-existing mutable tag is never accepted as provenance. The same rule
applies to the 4.2 migration derivative, while the ordinary installer always rebuilds
and attests the steady-state 4.3 derivative. Crash recovery reuses a derivative only
when the exact protected ledger binds its image reference and immutable ID. Do not
pre-tag another image under any of these protected commit-tagged references.

### 5. Prepare and attest the networkless 3.13 source

Use only the wrapper's exact command shape. It injects
`deploy/rabbitmq/source-3.13.7.compose.yml`; do not pass that overlay yourself:

```bash
BS_COMPOSE=("$PWD/backupsheep-compose")
# Root-owned installations instead begin this array with:
# BS_COMPOSE=("$PWD/backupsheep-compose" --allow-root-install)
# Add a reviewed deployment override, when present, before the transition flag:
# BS_COMPOSE+=(--approved-compose-file "$PWD/docker-compose.override.yml")
bs_compose() { "${BS_COMPOSE[@]}" "$@"; }

bs_compose --prepare-rabbitmq-3.13-source \
  up --detach --no-deps rabbitmq
```

The wrapper re-inspects the detached volume without networking as UID/GID `999:999`,
writes P313, and starts only the attested 3.13.7 security derivative with
`network_mode: none`, no secrets, no restart, and the retained hostname/node name.
Postflight proves the image reference and ID, model hash, healthy 3.13.7 version, exact
node, stock user/vhost, and drained queues before writing A313.

If preparation refuses the legacy layout, preserve it and use blue-green recovery. Do
not rename node directories, change ownership, or manufacture schema/shutdown markers.

### 6. Run the isolated UID conversion and 4.2.9 hop

```bash
bs_compose \
  --allow-rabbitmq-generation-transition=4.2 \
  --approved-compose-file "$PWD/deploy/rabbitmq/upgrade-4.2.9.compose.yml" \
  up --detach --no-deps rabbitmq
```

The wrapper first proves A313 and all stable/required 3.13 flags with Khepri disabled,
writes P42, cleanly stops and read-only inspects the exact source, then writes
`source-clean`. The stopped source may still exist at that checkpoint. It removes the
source, proves full volume detachment, and runs a named, networkless, read-only, bounded
helper with only `CHOWN`, `DAC_OVERRIDE`, and `FOWNER` to convert exact `999:999` entries
to `100:101`. The helper rejects foreign owners, links, special files, and unsafe
permissions; it does not start RabbitMQ or create a 4.3 witness. After detachment and the
exact converted 4.2 clean layout are proved, the wrapper writes `target-ready`, starts
only pinned 4.2.9 with no networks, secrets, or enabled plugins, enables every feature
flag including `khepri_db`, validates them all enabled, and writes A42. No application,
worker, Beat, provisioner, or externally reachable broker exists during this hop.

Recheck node identity, flags, health, vhosts, and empty queue state, then take a
coordinated snapshot including A42. The 4.3 preflight refuses any disabled flag or a
Khepri state other than enabled. The commands below are an operator recheck; the wrapper
has already run the same all-feature enablement and validation before A42.

Resolve exactly one current project broker before running the vendor CLI as its
unprivileged identity:

```bash
RABBIT_42_CONTAINERS="$(docker ps --quiet \
  --filter "label=com.docker.compose.project=${PROJECT}" \
  --filter 'label=com.docker.compose.service=rabbitmq')"
test -n "${RABBIT_42_CONTAINERS}"
test "${RABBIT_42_CONTAINERS}" = "${RABBIT_42_CONTAINERS%%$'\n'*}"
docker exec --user rabbitmq "${RABBIT_42_CONTAINERS}" \
  rabbitmqctl -q -n "rabbit@${LEGACY_NODE_HOST}" enable_feature_flag all
docker exec --user rabbitmq "${RABBIT_42_CONTAINERS}" \
  rabbitmqctl -q -n "rabbit@${LEGACY_NODE_HOST}" enable_feature_flag khepri_db
docker exec --user rabbitmq "${RABBIT_42_CONTAINERS}" \
  rabbitmqctl -q -n "rabbit@${LEGACY_NODE_HOST}" \
  list_feature_flags name stability state
```

### 7. Run the 4.3.5 hop and canonical commit

```bash
bs_compose --allow-rabbitmq-generation-transition=4.3 \
  up --detach --no-deps rabbitmq
```

Do not add a 4.3 overlay. The wrapper injects the exact
`deploy/rabbitmq/transition-4.3.compose.yml`, proves A42 and the live 4.2 source, writes
P43, cleanly stops and inspects that exact source, then writes `target-ready`. The stopped
source may still exist at that checkpoint. After source removal and full volume
detachment, it starts only the exact networkless, secretless, plugin-free 4.3.5
transition target. It requires healthy 4.3.5, required flags, enabled Khepri, the retained
node host, and the exact image/model before writing A43. It then finalizes the secondary
volume witness, force-recreates the canonical base model without transition mode,
repeats the full attestation (including the zero-enabled-plugin check), commits `.env`
last, and removes A43.

Confirm `.env` contains exactly one line for each value:

```text
BACKUPSHEEP_RABBITMQ_DATA_GENERATION='4.3'
BACKUPSHEEP_RABBITMQ_NODE_HOST='<retained-reviewed-host>'
```

### 8. Complete identity provisioning and enable operations deliberately

Complete the pending installer transaction with the same base inputs, retaining only
the database migration flag. Do not repeat already committed staging or RabbitMQ identity
migration flags:

```bash
FINAL_INSTALL_ARGS=("${BASE_INSTALL_ARGS[@]}" --migrate-database-identities)
./install.sh "${FINAL_INSTALL_ARGS[@]}"
```

The installer builds the local images, runs the broker provisioner, removes `guest`,
retains `/` only when it is inaccessible and exactly empty, and reconciles the dedicated
`backupsheep` vhost, per-lane credentials, explicitly classic bounded queues, exchanges
and permissions. Provisioning also rejects unexpected runtime/global parameters, user or
vhost limits, metadata, policies, bindings and connections before credential rotation,
then re-inventories them afterwards. Core starts only after the other security gates pass.
Retain all one-shot results and verify same-lane access plus denied cross-lane access.
Only after core, queue, recovery, and signed-task evidence pass, opt in to provider work:

```bash
./install.sh "${BASE_INSTALL_ARGS[@]}" --enable-operations
```

Run a scheduled-backup smoke test and verify the durable request, broker delivery,
terminal backup result, artifact authentication, and restore before considering the
migration accepted.

## Crash recovery and retries

If a shell, client, daemon, or host interruption occurs, do not delete or edit the ledger,
do not set the generation manually, and do not mix snapshots. Re-run **the exact command
for the state that was in progress**:

- P313 or A313: rerun the step-5 source command. A313 is preserved when the exact source
  is already healthy; if it is absent, the same command may recreate only that source.
- P42: rerun step 6. The wrapper may recover only the exact 3.13 source, cleanly stop and
  inspect it, and then advance to `source-clean`.
- `source-clean` 4.2: rerun step 6. The source does not need recovery; the wrapper may
  detach it and resume only the idempotent UID conversion and exact converted-layout
  inspection before advancing to `target-ready`.
- `target-ready` 4.2 or A42: rerun step 6 to recreate/recover and live-attest only the
  exact 4.2 target when it is absent or interrupted. Then run step 7. A42 alone never
  authorizes a blind 4.3 hop.
- P43: rerun step 7. The wrapper may recover only the exact 4.2 source, cleanly stop and
  inspect it, and then advance to `target-ready`.
- `target-ready` 4.3: rerun step 7. The wrapper may detach the stopped source and
  create/recover only the exact 4.3 target bound by the ledger.
- A43 with blank `.env`: rerun step 7. The wrapper may repair the secondary pending/final
  witness, re-prove transition and canonical 4.3, then commit `.env` last.
- `.env` already at `4.3`: use only the steady canonical model. A matching leftover A43
  is cleanup residue and is removed only after the committed model and witness revalidate.

A healthy source or target that already matches its exact ledger checkpoint is not
recreated merely because the caller retries; postflight advances or completes the same
transaction. Cross-version target creation/recovery requires `target-ready` or the
matching attested state; P313 is the only prepared state that can open its pinned target
directly. Created, exited, unhealthy, or absent containers are recreated only when the
exact ledger binding authorizes them. Missing, malformed, impossible, changed, or
conflicting evidence fails closed.

When a crash leaves a same-version broker PID marker, recovery admits only the genuine
single-link `rabbit@HOST.pid` file owned by `999:999` for 3.13 or `100:101` for 4.2/4.3,
with mode `0600` or `0644`, one-byte size, and raw byte `1` (or no PID file). The reviewed
entrypoint's owner-only umask produces `0600`; stock/default-umask paths can produce
`0644`. Recovery starts only the ledger-bound same-version image/model, re-proves version,
node, legacy semantics and feature flags, cleanly stops and inspects it, then removes the
transient container before the cross-version flow continues. No PID-bearing volume is
admitted directly across a version boundary.

If a hop or postflight cannot be proved, restore `.env`, the protected transition ledger,
`rabbitmq_data`, exact image/evidence inputs, and matching secrets from one coordinated
pre-hop snapshot. Never downgrade a data directory already opened by a newer RabbitMQ.

## Host boundary

This procedure changes only repository-managed configuration, containers, networks,
images, and named volumes. It does not install or reconfigure Docker, edit the host OS,
firewall, kernel, daemon, reverse proxy, TLS, DNS, users, or mandatory-access-control
policy. Those remain the operator's responsibility. Docker-daemon access and write access
to the protected installation directory are host-administrator-equivalent trusted
capabilities and must not be delegated to an untrusted tenant.
