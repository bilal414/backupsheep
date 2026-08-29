# Installation

BackupSheep is designed to run as a Docker Compose stack. The repository also supports
an advanced, process-by-process installation, but the container image is the canonical
definition of the operating-system tools needed by database and file backups.

## Choose an installation path

| Path | Best for | What it manages |
| --- | --- | --- |
| Verified Docker installer | A host where the operator already manages Docker | Exact checkout, file-backed secrets, image build and core-only startup |
| Manual Docker Compose | Existing Docker hosts and local evaluation | The complete application stack from the checked-out repository |
| Manual processes | Operators who already manage Python, PostgreSQL, RabbitMQ and process supervision | Every web, worker and scheduler process separately |

The stock Compose stack contains PostgreSQL, RabbitMQ, the web application, five
specialized Celery workers, a scheduler, per-role namespace guards and networkless or
single-purpose provision/migrate/seal/preflight one-shots. It publishes the web
application on loopback TCP port `8000`;
PostgreSQL and RabbitMQ are not published to the host.

## Host prerequisites

For the verified installer:

- Git, Bash and ordinary Unix file utilities supplied and maintained by the host operator;
- Docker Engine **28.0.0 or newer** and Docker Compose **2.33.1 or newer**. The installer
  fails closed on older or unparseable versions because the reviewed network model uses
  newer routing controls;
- access to the intended Docker daemon either as the invoking non-root user or through
  an explicit effective-UID-0 installation. Docker access is a root-equivalent security
  boundary on a traditional rootful engine; choose the identity according to the host's
  own policy rather than changing groups or daemon settings for BackupSheep;
- an installation parent owned by that same effective invoking UID and not writable by
  group or other users;
- outbound HTTPS access to GitHub, registries and package sources used by the image build;
- a supported CPU architecture: `x86_64` or `aarch64` (the Dockerfile installs the
  Oracle MySQL 8.4 client for those two architectures);
- enough working disk for the image, PostgreSQL, RabbitMQ, the largest concurrent
  database/file backup, website incremental caches and any Local Storage archives.

Database and file backup workers can need substantially more memory and temporary disk
for large sources. Capacity planning remains a host-operator responsibility.

BackupSheep does not install packages, add apt repositories, enable/restart Docker, or
change firewall, kernel, daemon or service settings. Those are host responsibilities.
Verify the operator-provided tools before continuing:

```bash
git --version
docker version
docker compose version
```

## Verified Docker installer

Choose a reviewed release commit, download the installer from that exact immutable
commit, inspect it, and by default run it as the same unprivileged user that is already
authorized to use Docker:

```bash
COMMIT='<40-character-reviewed-release-commit>'
curl -fSLo install.sh \
  "https://raw.githubusercontent.com/bilal414/backupsheep/${COMMIT}/install.sh"
less install.sh
chmod 700 install.sh
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --project-name backupsheep \
  --domain backups.example.com
```

The installer generates independent 256-bit database/files artifact keyrings inside the
protected `.secrets` directory. No external key service or credential input is required.

Do not pipe a remote script into a shell. Without `--allow-root-install`, the installer
still refuses effective UID 0, including a root shell or `sudo`. The invoking non-root
user must already have access to the intended Docker daemon. The installer accepts no
branch, tag or abbreviated revision: it fetches the full commit from the canonical HTTPS
repository and then verifies that its own bytes match `install.sh` in that checkout
before invoking Docker. The default non-root installation directory is
`$XDG_DATA_HOME/backupsheep` or `$HOME/.local/share/backupsheep`; select another
user-writable path explicitly when needed:

```bash
./install.sh \
  --ref "${COMMIT}" \
  --domain backups.example.com \
  --install-dir "$HOME/backupsheep" \
  --project-name backupsheep
```

Supported options are:

| Option | Behavior |
| --- | --- |
| `--ref COMMIT` | Required full 40-character commit; mutable or abbreviated references are rejected |
| `--domain HOST` | Configures the accepted/public hostname while the listener remains on server loopback; defaults to `localhost` |
| `--install-dir PATH` | Uses an absolute path other than `/`, owned by the same effective UID that runs the installer |
| `--allow-root-install` | Explicitly permits effective UID 0 for a root-owned installation using an existing rootful daemon; defaults to `/opt/backupsheep` unless `--install-dir` is supplied |
| `--project-name NAME` | Pins and persists the Compose project name; every rerun must match that protected witness, and ambient Compose variables are ignored |
| `--adopt-legacy-project NAME` | One-time recovery for the exact stock four-volume layout left by an old `compose down`; see the guarded workflow below |
| `--approved-compose-file PATH` | Accepts only the private regular `INSTALL_DIR/docker-compose.override.yml`, rendered after the base file and included in exact ownership history |
| `--migrate-database-identities` | One-time conversion of an existing stock database to generation-3 bootstrap, owner and exact per-lane ACL/RLS identities |
| `--migrate-rabbitmq-identities` | One-time conversion of the shared broker login to generation-2 per-lane credentials/ACLs |
| `--rotate-celery-signing-keys` | Drained-queue generation-3 task-signing rotation; requires all publishers/consumers stopped and exact broker ownership |
| `--migrate-staging-layout` | One-time existing-install authorization for an empty legacy shared work volume and new layout-v3 witness |
| `--migrate-egress-policy` | One-time fail-closed reset of a uniform stock legacy egress policy to generation-2 deny defaults and blank exact endpoint/name lists; mixed/custom policy is refused |
| `--migrate-postgres-runtime` | One-time stop-the-world migration of the exact witnessed Debian PostgreSQL volume into the isolated Alpine/ICU generation; a blank legacy database-identity generation also requires `--migrate-database-identities` |
| `--migrate-artifact-key-provider-empty` | One-time transition from a blank, development-only or retired provider; the current migration run must prove zero wraps, plaintext artifact ledgers, and historical database/files backup or storage-point rows before generation 1 is sealed |
| `--rotate-artifact-keyring database\|files` | Operations-down, one-lane rotation that prepends a new key and retains every legacy key; every matching worker container must be removed and operations cannot start in the same run |
| `--expected-artifact-active-key-id lfk-...` | Required replay/staleness witness for artifact-keyring rotation; must equal the exact active ID inspected before the maintenance window |
| `--skip-start` | Verifies/configures the installation but does not build or start Compose |
| `--enable-operations` | After core health and security preflight pass, explicitly starts the provider workers and scheduler |

The script does not look up the server's public IP, configure DNS, open a firewall,
issue a TLS certificate or install a reverse proxy.

### Signed-release consumer mode

Local build remains the default and requires no release assets. To consume a published
official release, obtain both the exact tag and the 40-character commit to which that tag
points, download `install.sh` from that commit, and add `--release-tag`:

```bash
RELEASE_TAG='v1.2.3'
COMMIT='<40-character-commit-for-v1.2.3>'
./install.sh \
  --ref "${COMMIT}" \
  --release-tag "${RELEASE_TAG}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --project-name backupsheep \
  --domain backups.example.com
```

This mode downloads only three bounded GitHub release assets: the canonical V2 descriptor,
its Sigstore bundle, and the digest-bound release manifest. It does not install Cosign or
any host package. Instead it pulls BackupSheep's reviewed first-party verifier, built from
Cosign 3.1.3, by an exact index digest and binds the selected amd64/arm64 manifest and
configuration digest. It confirms its non-root user and entrypoint and runs it without the Docker
socket or network, with all capabilities dropped, `no-new-privileges`, a read-only root
filesystem, a private bounded tmpfs, and bounded PIDs/CPU/memory.

The descriptor signature must have the exact BackupSheep release-workflow identity, GitHub
Actions issuer, repository, source commit, tag ref, and `push` trigger. The installer then
strictly parses sixteen ordered ASCII lines without evaluating or sourcing them, checks the
manifest SHA-256, and verifies that descriptor bundle offline with a source-controlled,
hash-pinned Sigstore trusted root. The verifier assertion inside the descriptor must
byte-match the independently distributed bootstrap policy and cannot select its own verifier.
The release workflow verifies all five official image signatures online before signing the
descriptor; the Docker daemon then pulls only the five
authenticated immutable digest references. Local `RepoDigests`, image IDs, and OCI
source/revision/version labels are persisted under owner-only `.release-evidence` and are
re-attested by the installer and wrapper before mutation. The final Compose overlay is
always last, removes all three build definitions, restores the verified digest references,
and retains `pull_policy: never`. The five roles are application, PostgreSQL, egress guard,
RabbitMQ 4.3 runtime, and the RabbitMQ 4.2 upgrade helper. A wrong tag/commit/repository/digest, skipped signature,
duplicate line, existing evidence collision, missing image, or model override fails closed.

An installation cannot change between `local-build` and `signed-release`, or between
signed release tags. The current generic [upgrade and rollback runbook](upgrades.md) is
not a signed-release transition: it cannot atomically bind a new checkout, evidence,
configuration and database migration or restore the prior state after a crash. Use signed
mode only for a fresh project until the journaled signed-to-signed lifecycle is implemented.
Preserve `.release-evidence` with the complete control-plane recovery set.

### Explicit rootful-daemon mode

Use this mode only when the host policy intentionally keeps Docker access behind root or
`sudo`. BackupSheep does not add the user to a Docker group, install rootless Docker, or
edit the daemon. Root remains refused unless `--allow-root-install` is supplied.

Never run a user-owned installer directly as root. After reviewing the exact downloaded
file, copy it into a root-owned, mode-`0700` preparation directory without changing
ownership of the original:

```bash
sudo install -d -o root -g root -m 0700 /root/backupsheep-install
sudo install -o root -g root -m 0700 ./install.sh \
  /root/backupsheep-install/install.sh
sudo -H /root/backupsheep-install/install.sh \
  --allow-root-install \
  --ref "${COMMIT}" \
  --install-dir /opt/backupsheep \
  --project-name backupsheep \
  --domain backups.example.com
```

The root-owned installer generates the database and files keyrings once inside
`/opt/backupsheep/.secrets`; no external key service or host credential input is
required. Preserve their exact bytes with PostgreSQL in the encrypted recovery set
before enabling operations.

The source installer, its parent, the installation parent, checkout, `.env`, secrets and
any approved Compose override must all be owned by the real effective invoker: UID 0 in
this mode. The installer never derives ownership from `SUDO_USER`, never calls `chown`,
and never hands the resulting files back to another account. Do not alternate root and
non-root invocation modes for one installation. Use `sudo -H` so `HOME` resolves to a
root-owned directory; any explicit `DOCKER_CONFIG` or `DOCKER_CERT_PATH` directory must
also be absolute, root-owned, non-symlinked and not writable by group or other users.

The wrapper repeats this boundary. For a root-owned installation, run it as effective
UID 0 and put the explicit override first on every command:

```bash
sudo -H /opt/backupsheep/backupsheep-compose --allow-root-install config --quiet
sudo -H /opt/backupsheep/backupsheep-compose --allow-root-install ps --all
```

The wrapper refuses root without the override, refuses the override for non-root users,
and validates its own file, the installation directories, `.env`, Compose model and any
approved override against the same owner/mode/link rules before Docker is called. This
host-side mode does not change the Compose model: long-lived application, worker,
scheduler, database and broker processes retain their reviewed non-root container users,
capability drops and read-only filesystem boundaries.

On a new installation the script:

1. verifies Docker/Compose versions and access without changing the daemon;
2. fetches the exact commit through a configuration-isolated HTTPS Git process, verifies
   the resulting object database, rejects dirty/foreign/symlinked checkouts and compares
   the running installer with the committed copy;
3. creates `.env` as mode `0600` and `.secrets` as a mode `0700` directory;
4. generates independent Django, PostgreSQL bootstrap/migrator/per-lane, RabbitMQ
   bootstrap/per-lane, task-signing, onboarding and lane-specific artifact keyrings plus empty
   optional `ssh_managed_database_private_key` and
   `ssh_managed_files_private_key` files as mode `0444` inside that private directory,
   keeping values out of Compose inspection and staging storage;
5. creates and preserves a random 64-character lowercase hexadecimal installation ID.
   Service containers and an empty labeled sentinel volume carry that identity so a
   reused Compose project name cannot silently adopt another installation's resources,
   including after `compose down` removed its containers and networks. It also inventories
   every exact `${project}_${network-or-volume}` name and rejects an unlabeled/foreign
   collision that Compose could otherwise adopt with only a warning;
6. proves that a broker project is fresh or that its one running, healthy broker reports
   RabbitMQ 4.3 when diagnostics run as the named `rabbitmq` account, then records the
   installer-owned data-generation witness. It refuses orphaned, stopped, unhealthy,
   ambiguous, 3.13 or 4.2 broker state instead of guessing at a volume format;
7. validates Compose through explicit `--project-name`, `--env-file` and `-f` arguments;
8. in default mode builds commit-tagged PostgreSQL, application and namespace-guard images;
   in signed-release mode re-attests the five pre-pulled official digests and disables
   every corresponding Compose build; then starts only
   PostgreSQL/RabbitMQ, the volume/broker/staging/database provisioners, migrate/seal/
   preflight gates, app guard and web UI on `127.0.0.1:8000`;
9. waits up to five minutes for the `app` health check;
10. prints an SSH-tunnel command and an explicit server-side token retrieval command,
   without writing the token itself to install logs.

Provider workers and Beat do not start unless `--enable-operations` is explicitly
provided. Review provider credentials, queued/recoverable work and restore ownership
before opting in: enabling operations can execute durable work already present in the
database or broker. On every build/migration run the installer first removes the complete
container/network topology with ordinary `down` while preserving named data/identity
volumes; an explicit opt-in recreates operations only after core health and the security
preflight pass. Long-lived application roles use `restart: unless-stopped`, but
namespace guards use `restart: "no"`; the wrapper refuses an independent guard lifecycle
command and requires the workload/guard pair to be recreated together.

An existing directory is reused only when it is the clean canonical repository at the
same requested commit, with the expected ownership and permissions. The installer never
upgrades a checkout in place. It migrates existing direct installation secrets without
rotating them and then blanks their `.env` values. A pre-generation-3 stock database is
the deliberate exception: the operator must first stop work, make a verified encrypted
rollback, and pass `--migrate-database-identities` once. The installer preserves its
legacy credential only as the bootstrap credential and generates new independent
migrator/runtime credentials. See the
[database identity migration gate](database-identity-migration.md). It creates both optional
lane-specific managed SSH files empty for a new deployment. A legacy shared identity cannot
be assigned an account and worker lane safely, so the installer refuses any non-empty
`.secrets/ssh_managed_private_key` or legacy `SSH_MANAGED_PRIVATE_KEY_PATH` /
`SSH_MANAGED_PUBLIC_KEY` value. Follow the [upgrade gate](upgrades.md#one-time-legacy-ssh-trust-and-shared-identity-retirement)
to preserve rollback evidence and create distinct Ed25519 identities. It refuses ambiguous,
missing, mismatched, symlinked or hard-linked secret state. A failed start leaves containers
and volumes intact for evidence and recovery; it never performs an automatic destructive
rollback.

An existing installation without `BACKUPSHEEP_EGRESS_POLICY_GENERATION=2` must also use
`--migrate-egress-policy` once. The installer accepts only a uniform stock public/blank,
blank/blank or deny/blank legacy state, then resets all six roles to `deny` and clears old
and new lists. Internet-dependent operations remain blocked until reviewed exact TCP
tuples and DNS names are added. Preserve and review any customized/mixed legacy policy,
manually reset it to the stock deny state, and only then authorize the migration; the
installer never guesses a translation and rejects reuse of the flag after generation 2.

### One-time legacy compose-down adoption

Releases before the installation-identity sentinel can be left with only four named
volumes after `compose down`: `pgdata`, `rabbitmq_data`, `backup_workdir` and
`backup_storage`. With no exact-path container or sentinel, the installer cannot infer
that those volumes belong to the current installation. Do not work around this by
manually editing the persisted project-name witness.

After independently confirming the old Compose project name and recovery backups, run
the verified installer once with the value-bearing adoption option, preferably with
startup disabled for the first pass:

```bash
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --project-name backupsheep \
  --domain backups.example.com \
  --adopt-legacy-project backupsheep \
  --skip-start
```

This gate fails closed unless the existing installation has no persisted project witness,
the named project has zero containers and networks, and its complete labeled volume set
is exactly `${project}_{pgdata,rabbitmq_data,backup_workdir,backup_storage}` with the
standard Compose project/logical labels and no BackupSheep installation-ID labels. It
also rejects pre-existing `installation_identity` or legacy `ssh_trust` names, inventory or
inspection errors, missing volumes, extra volumes and label drift.

Only after those checks does the installer create
`${project}_installation_identity` with the exact Compose project/logical labels and the
new stable installation ID. It immediately re-inspects the name and all labels, then
persists `BACKUPSHEEP_COMPOSE_PROJECT_NAME`. The same generic ownership validator must
pass afterward. If any later independent gate (notably the RabbitMQ
generation gate) stops the run, retain the evidence, complete its documented runbook and
rerun without `--adopt-legacy-project`; adoption is deliberately one-time.

If the legacy containers still exist, no adoption flag is needed. Before any Compose
mutation, the installer proves every project container's exact installation path,
canonical config file and known service; proves every project network and volume has its
canonical physical and logical name; and requires all pre-hardening installation-ID
labels to be blank. Only after the entire inventory passes does it create and re-inspect
the identity sentinel. The wrapper then accepts the immutable blank container IDs only
under that matching sentinel so the reviewed Compose and RabbitMQ transition commands can
recreate them. Any nonblank partial identity, path/model/service drift, noncanonical name,
foreign sentinel or inspection failure stops without creating a Docker resource.

The exact four-volume adoption gate above is only for the older pre-sentinel layout;
do not use it to relabel a develop-era `ssh_trust` volume. Development layout v2 was
prerelease-only. When an already identified project contains its canonical labeled
`ssh_trust` volume, the ordinary ownership validator may accept it only after exact
project, physical-name, logical-name and installation-identity checks. It remains
detached as rollback evidence during the explicit `migrate-empty-legacy-v3` staging
transition. Layout v3 has no trust mount, trust group or provisioning path, and the
wrapper rejects every `--volume` override, so the retired global trust inventory cannot
be imported. Reapprove each exact account/host/port/key in PostgreSQL instead; any
ambiguous or foreign legacy volume stops installation.

An existing RabbitMQ data volume is a separate fail-closed gate. The installer never
performs the 3.13 -> 4.2 -> 4.3/Khepri migration. If the stored data-generation witness is
blank, it accepts only a new project with no broker resources. Existing broker data with
a blank witness must use the explicit wrapper migration/reconciliation path, which attests
the pinned image reference and image ID, exact server version, feature flags and Khepri.
A volume without that witness, a stopped/unhealthy broker, duplicate broker resources, or
another version requires the [operator-run RabbitMQ migration](rabbitmq-upgrade.md).

### Verify an installer deployment

```bash
cd "$HOME/.local/share/backupsheep"
./backupsheep-compose config --quiet
./backupsheep-compose ps --all
./backupsheep-compose logs --tail=100 \
  rabbitmq-volume-init rabbitmq-provision staging-provision \
  db-provision migrate db-seal preflight app-egress-guard app
curl -fsS http://127.0.0.1:8000/healthz/
```

For a root-owned installation, use `/opt/backupsheep` and invoke the wrapper as
`sudo -H /opt/backupsheep/backupsheep-compose --allow-root-install`; the override must
be the first wrapper argument.

The last command should print `ok`. This proves that the web process can answer a
request; it does not probe PostgreSQL, RabbitMQ or any provider. Complete the
[first-run setup](first-run.md), then follow the [production guide](production.md)
before exposing the instance publicly. When the operational preflight is complete, opt in
using the same exact installer:

The installer and hardened wrapper serialize every real control-plane mutation through
the same `${INSTALL_DIR}.backupsheep-mutation-lock` directory. Do not run two installer or
mutating wrapper commands concurrently. Read-only wrapper inspection remains available
while a mutation is active. If a crash leaves a stale lock, follow the exact inspection and
non-recursive recovery procedure in the
[operations runbook](operations.md#control-plane-mutation-lock); the tools never infer that
a recorded PID is safe to reap.

```bash
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --project-name backupsheep \
  --domain backups.example.com \
  --enable-operations
```

The preflight runs Django's deployment checks. Warning-level HTTPS findings are expected
only while the listener is deliberately limited to loopback and reached through an SSH
tunnel. Before public exposure, configure a real TLS proxy, set `DJANGO_HTTPS=true`,
`APP_PROTOCOL=https://`, the exact public `APP_DOMAIN` and allowed hosts, and review every
deployment warning. A passing error-level preflight does not make public HTTP safe.

### Artifact keyring custody and rotation

Treat `.secrets/artifact_local_file_database_keyring` and
`.secrets/artifact_local_file_files_keyring` as part of the minimum recovery set. Keep
encrypted, access-audited off-host copies with PostgreSQL. A database restore without the
same keyrings cannot decrypt existing BSE1 artifacts; generating replacement keys does not
recover them. The installer creates each file once with a 256-bit random key, validates
owner/mode/link/content on every rerun, and preserves the exact bytes. It refuses a missing
keyring in an existing installation. These are exportable software keys, not
non-exportable HSM/KMS keys: the matching source worker, Docker daemon, and host
administrators are inside the custody boundary. The stock runtime does not currently
provide a hardware-backed artifact-key provider.

Inspect IDs without printing key material, then stop all operations before rotating one
lane. Supply the observed active ID as a replay/staleness witness:

```bash
cd "$HOME/.local/share/backupsheep"
KEYRING="$PWD/.secrets/artifact_local_file_database_keyring"
INSTALLATION_ID='<the existing 64-hex BACKUPSHEEP_INSTALLATION_ID>'
python scripts/manage_artifact_keyring.py inspect \
  --path "$KEYRING" --lane database --installation-id "$INSTALLATION_ID"
OLD_ACTIVE='lfk-<32-lowercase-hex-from-inspect>'
./backupsheep-compose --profile operations down --timeout 300
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$PWD" \
  --project-name backupsheep \
  --domain backups.example.com \
  --rotate-artifact-keyring database \
  --expected-artifact-active-key-id "$OLD_ACTIVE" \
  --skip-start
```

The rotation atomically prepends a new random key and retains every old entry. Repeating
the same command fails because its expected active ID is stale. A keyring holds at most
eight keys; a full keyring refuses rotation rather than evicting recovery material.

Do **not** start the matching source worker yet. First copy the exact post-rotation
keyring (which now contains the new and all retained roots) to the approved encrypted,
access-audited off-host recovery system. Restore that copy into an isolated owner-mode
`0700` directory, set the file to owner-mode `0400`, compare its SHA-256 digest with the
live post-rotation file, and run `manage_artifact_keyring.py inspect` against the restored
copy with the same installation ID and lane. Record the digest, retained IDs and
successful isolated inspection in the change evidence. A pre-rotation backup alone
cannot recover backups first wrapped under the new active root. No matching source worker
may start and no new backup may use the key until this recovery gate passes.

After that gate, start the reviewed core normally, then run the database command from the matching source
service first without and then with `--apply` (use `worker-files` and `--lane files` for
the files keyring):

```bash
./backupsheep-compose --profile operations run --rm worker-database \
  python manage.py rotate_artifact_key_wraps \
  --expected-source-key-id "$OLD_ACTIVE" \
  --installation-id-witness '<64-hex-installation-id>' \
  --lane database
./backupsheep-compose --profile operations run --rm worker-database \
  python manage.py rotate_artifact_key_wraps \
  --expected-source-key-id "$OLD_ACTIVE" \
  --installation-id-witness '<64-hex-installation-id>' \
  --lane database --apply
```

Continue bounded batches until `remaining_source=0`. Retain the old key through the
maximum in-flight/retry/retention window. Rotation is not crypto-erasure: it retains the
old root and retired wraps for recovery. There is intentionally no automatic prune. Remove
a legacy key only in a separately reviewed change after a current complete database query
proves zero non-retired wraps (`pending`, `active`, or `manual_review`) in that lane
reference its ID. Pending/manual-review generations must be reconciled or explicitly
retired before pruning; checking active rows alone is insufficient and causes source
startup to fail closed. A later prune still does not erase copies in snapshots, recovery
sets, process memory, or exported material; dispose of them under a separately audited
retention/media-destruction policy.
After rewrapping, capture and verify a new coordinated recovery set containing PostgreSQL
and both exact lane keyrings. Keep the post-rotation and post-rewrap evidence together;
neither a database-only snapshot nor one lane keyring is a complete recovery set.

For non-Docker installations, create each keyring in a different mode-`0700` directory
owned by the exact source identity that will read it. Never put both lane keyrings in one
shared directory. For example, after creating the fixed service accounts described below:

```bash
install -d -o 10002 -g 10002 -m 0700 /srv/backupsheep-keys/database
install -d -o 10003 -g 10003 -m 0700 /srv/backupsheep-keys/files
setpriv --reuid=10002 --regid=10002 --clear-groups \
  python scripts/manage_artifact_keyring.py create \
  --path /srv/backupsheep-keys/database/keyring --lane database \
  --installation-id '<stable 64-hex installation ID>'
setpriv --reuid=10003 --regid=10003 --clear-groups \
  python scripts/manage_artifact_keyring.py create \
  --path /srv/backupsheep-keys/files/keyring --lane files \
  --installation-id '<the same stable 64-hex installation ID>'
python scripts/manage_artifact_keyring.py policy-witness \
  --installation-id '<the same stable 64-hex installation ID>' --generation 1
setpriv --reuid=10002 --regid=10002 --clear-groups \
  python scripts/manage_artifact_keyring.py rotate \
  --path /srv/backupsheep-keys/database/keyring --lane database \
  --installation-id '<the same stable 64-hex installation ID>' \
  --expected-active-key-id "$OLD_ACTIVE"
```

Put generation `1` and the emitted witness in the protected shared configuration as
`BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION` and
`BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS` before importing production settings. Every
long-lived production process receives the same pair. `1-pending-empty` is reserved for
the installer's stopped-operations adoption transaction and is not a fresh direct-install
shortcut. After direct rotation, apply the same mandatory off-host copy, digest and
isolated-inspection gate described above before restarting the matching source process;
then rewrap and capture PostgreSQL plus both keyrings as one recovery set.

The lifecycle tool serializes mutation, rejects unsafe directories/files/symlinks/hard
links, uses no-clobber creation and atomic replacement, retains all legacy keys, and emits
only IDs/counts. The keyring header is bound to the original installation ID; a foreign
same-lane keyring and a recovered keyring paired with a replacement ID are rejected. Set
`BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH` only in the matching database or files
process; every other role must omit it.

BSE1 sealing and restore require Linux `O_TMPFILE` and
`linkat(AT_EMPTY_PATH)` on the exact destination filesystems. Static settings/container
health checks do not prove those filesystem primitives. Before enabling operations, run a
disposable backup and isolated data-verified restore through each database/files lane on
its production mounts and worker identity; also prove cross-lane/keyring denial. Repeat
after a runtime, kernel, filesystem, volume-driver, or mount-option change. BackupSheep
fails closed instead of creating a named partial-plaintext fallback. Native non-Docker
workers therefore require Linux; a non-Linux host must supply the needed Linux semantics
through its container/VM.

## Manual Docker Compose installation

### 1. Let the verified installer stage the exact model

Directly cloning and inventing `.env`, secret files, identity generations or layout
witnesses is not a supported stock bootstrap. The model requires independent database and
broker lane credentials, task-signing keys, two artifact keyrings, an installation ID,
resource labels and the v3 staging witness as one fail-closed set. Use `--skip-start` when
you need to review or add a Compose override before the first build:

```bash
COMMIT='<40-character-reviewed-release-commit>'
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --project-name backupsheep \
  --domain backups.example.com \
  --skip-start
cd "$HOME/.local/share/backupsheep"
test "$(git rev-parse HEAD)" = "${COMMIT}"
```

Do not hand-edit the installer-owned identity/generation/witness values or add arbitrary
files beneath `.secrets`. Keep `.secrets/django_secret_key` stable. It signs sessions and
derives the key used for saved email credentials. See the
[configuration guide](configuration.md) and complete
[environment-variable reference](../reference/environment-variables.md).

If Local Storage must live on a capacity-managed bind/NFS filesystem, create and review
`docker-compose.override.yml` **before the first `up`**. Use the bind-volume example in
`docker-compose.yml`, resolve an absolute host path, and verify its ownership/capacity.
Then add the exact approval flag to the command array in step 2. The wrapper refuses to
auto-load the file. Docker volume driver options are immutable after creation, so a later
configuration edit does not move existing archive bytes or convert an existing named
volume.

### 2. Validate, build and start

```bash
BS_COMPOSE=("$PWD/backupsheep-compose")
# Root-owned installation only:
# BS_COMPOSE=(sudo -H "$PWD/backupsheep-compose" --allow-root-install)
# If and only if a reviewed pre-start override exists, add this active line:
# BS_COMPOSE+=(--approved-compose-file "$PWD/docker-compose.override.yml")
bs_compose() { "${BS_COMPOSE[@]}" "$@"; }
bs_compose config --quiet
bs_compose build db app app-egress-guard
# Fresh topology only: no guard/workload container may already exist.
bs_compose up --detach
bs_compose ps --all
```

The profile-less command starts only the core. Start provider workers and Beat only after
the security preflight and recovery review:

```bash
bs_compose --profile operations up --detach --no-build --no-deps \
  --force-recreate \
  cloud-egress-guard database-egress-guard files-egress-guard \
  storage-egress-guard logs-egress-guard \
  worker-cloud worker-database worker-files worker-storage worker-logs
bs_compose --profile operations up --detach --no-build --no-deps beat
```

After any pair exists, broad, guard-only and workload-only `up` operations are refused.
Use the exact paired force-recreation above; see the
[egress lifecycle contract](../../deploy/egress/README.md#paired-lifecycle-commands).

`db-provision`, `migrate` and `preflight` must all exit with code `0`. The provisioner
uses the bootstrap credential only on its dedicated internal bridge, creates or rotates
installation-marked migrator/runtime roles in one transaction, transfers the reviewed
public schema to the migrator and grants the runtime login DML without DDL or temporary
tables. The preflight independently proves the active Django login has that exact
least-privilege boundary, computes Django's migration plan and refuses any unapplied
migration. The application and
worker services wait for all three one-shot gates before starting. Migrations also seed the
integration/storage catalogs and create the database-backed cache table. Application,
PostgreSQL and egress-guard roles use `pull_policy: never`, so all three explicit builds
above are mandatory
and a missing local image cannot be replaced silently from a registry. The database build
uses `Dockerfile.postgres`: it verifies the digest-pinned official 18.6 entrypoint before
replacing its single `gosu` privilege drop with exact Alpine `su-exec=0.3-r0`, then
deletes `gosu` and declares UID/GID `70:70`. Stock Compose starts PostgreSQL directly as
that non-root identity with no capabilities and initializes the distinct
`postgres_data_v1` volume with ICU `und`. A wrong, unwitnessed, or legacy Debian volume
fails closed instead of being repaired or adopted. Existing installations must use the
one-time [PostgreSQL Alpine/ICU migration gate](postgres-runtime-migration.md).

Every application-image command still passes through the image entrypoint. It rejects a
root or weakened runtime, neutralizes shell/Python/dynamic-loader startup hooks and runs
the deployment preflight again before each web, worker or Beat process. This repeated
gate also covers an automatic container restart after the earlier one-shot preflight has
exited. Database identity provisioning, migration and the preflight command itself are
the only intentional exceptions.

An existing RabbitMQ 3.13 volume requires the supported 3.13 -> 4.2 -> 4.3 sequence before
this Compose file can be used. Follow the [RabbitMQ migration gate](rabbitmq-upgrade.md);
never start the 4.3 image directly against a 3.13 data directory.

If startup fails:

```bash
bs_compose logs --tail=200 db-provision migrate preflight app db rabbitmq
```

### 3. Retrieve the install token

Read the generated onboarding token only from the trusted host shell:

```bash
cat .secrets/onboarding_token
```

Open `http://localhost:8000/onboarding/` and enter that token when creating the first
account.

### 4. Migrate existing Local Storage off the Docker-managed disk

The Local Storage destination writes beneath `/backups`, which is the
`backup_storage` named volume by default. For important archives, place that volume on
capacity-managed storage. For an installation that already created the stock volume,
do not merely add an override: Compose will keep the existing volume's original driver
options and no bytes will move. Treat this as a host-storage migration. Stop app plus all
operations writers, resolve the one exact labeled `backup_storage` volume, take a
recoverable snapshot, copy its complete contents and metadata to the approved target,
compare file counts/sizes/hashes, and only then replace that exact old volume with the
reviewed bind-backed definition. Never use broad `down --volumes` or pruning. Re-run the
wrapper's rendered-model, ownership, storage-only write/read and authenticated restore checks before
operations resume. The repository intentionally does not automate deletion of the old
host volume.

## Manual process installation (advanced)

The repository can run as ordinary Django/Celery processes, but there is no bundled
systemd or supervisor definition. The operator must provide process supervision,
restart policy, log handling, equivalent lane-private work and ciphertext handoff
boundaries, Local Storage isolation and upgrades. A shared plaintext work directory is
not equivalent to stock Compose and must not be used.

Use Python 3.14 to match the image. Install PostgreSQL 14 or newer, RabbitMQ, the Python
requirements and the external tools listed in `Dockerfile`, including:

- `lftp`, OpenSSH, `zip` and `unzip` for website/file transfers;
- Oracle MySQL 8.4 `mysql`/`mysqldump` for MySQL targets;
- MariaDB client tools for MariaDB targets;
- PostgreSQL client tools 14 through 18 so the app can select a version-matched
  `pg_dump`/`pg_restore`.

Then create a virtual environment and install the dependencies:

```bash
python3.14 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Production BSE1 deliberately rejects a monolithic worker or several ordinary processes
sharing one host work directory. A non-Docker supervisor is supported only when it
reproduces the same process and mount namespaces. Create fixed primary identities
`web=10001:10001`, `database=10002:10002`, `files=10003:10003`,
`storage=10004:10004`, `logs=10005:10005`, `beat=10006:10006`,
`migration=10007:10007`, and `cloud=10008:10008`. The only supplemental groups allowed
are database `10989,10990,10994`; files `10991,10992,10993`; and storage
`10990,10992,10993,10994,10995`. Every other role has only its primary group.

Provision the shared ciphertext roots exactly once as root:

```bash
install -d -o root -g 10989 -m 3771 /var/lib/backupsheep/transfer/database
install -d -o root -g 10991 -m 3771 /var/lib/backupsheep/transfer/files
install -d -o root -g 10995 -m 3771 /var/lib/backupsheep/restore-transfer
install -d -o 10002 -g 10002 -m 0700 /srv/backupsheep-work/database
install -d -o 10003 -g 10003 -m 0700 /srv/backupsheep-work/files
install -d -o 10004 -g 10004 -m 0700 /srv/backupsheep-work/storage
```

Before the first production settings import, create the two installation-bound keyrings
and generation-`1` witness exactly as described in
[Artifact keyring custody and rotation](#artifact-keyring-custody-and-rotation). Put the
stable installation ID, `bse1` mode, `local-file` provider, enterprise/no-legacy policy,
generation and witness in the protected shared process environment. The migration
identity receives no keyring path. Run every production schema change through the fresh
artifact-custody verifier, even when Django reports that all migrations were applied:

```bash
env BACKUPSHEEP_RUNTIME_ROLE=migration \
  python manage.py migrate_and_verify_artifact_provider
env BACKUPSHEEP_RUNTIME_ROLE=migration \
  python manage.py collectstatic --noinput
```

Do not substitute plain `manage.py migrate` in production; it does not perform the
current-state proof. The current runtime registry contains only `local-file` and
development/test-only `local-development`; `aws-kms` survives solely as a historical
migration/rollback identifier. Direct non-Docker installs do not support an in-place
transition from a blank, `local-development` or historical `aws-kms` artifact provider.
Keep the old release
and its credentials available while an operator exports/reseals or explicitly retires
every old archive-backed record, then bootstrap the new direct deployment with empty
artifact, backup and storage-point inventories. Generation `1-pending-empty` and its
rollback transaction are installer-owned; never synthesize them in a direct process
environment.

The supervisor must give database, files, and storage different mount namespaces and bind
only that role's `/srv/backupsheep-work/<role>` at the immutable production path
`/code/_storage`. Database/files mount their matching forward-transfer root read/write,
storage mounts both forward roots read-only, and storage alone mounts reverse transfer
read/write; database/files mount reverse transfer read-only. No other role receives any
of those paths. A supervisor unable to create these namespaces is not a supported
production BSE1 deployment.

Run one process for each queue, plus web and Beat. The following shows the required
role/lane identity and source-only keyring variables; each supervisor unit must also
provide that lane's separate database, broker and Celery-signing credentials. Use an
equivalent numeric-user/group directive rather than a shell when implementing services:

```bash
env BACKUPSHEEP_RUNTIME_ROLE=web BACKUPSHEEP_CELERY_LANE=app \
  gunicorn backupsheep.wsgi:application --workers=4 --timeout=3600 --bind 127.0.0.1:8000
env BACKUPSHEEP_RUNTIME_ROLE=cloud BACKUPSHEEP_CELERY_LANE=cloud \
  celery -A backupsheep worker --loglevel=info --hostname=cloud@%h -Q cloud,default --concurrency=4
env BACKUPSHEEP_RUNTIME_ROLE=database BACKUPSHEEP_CELERY_LANE=database \
  BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH=/srv/backupsheep-keys/database/keyring \
  celery -A backupsheep worker --loglevel=info --hostname=database@%h -Q database --concurrency=1
env BACKUPSHEEP_RUNTIME_ROLE=files BACKUPSHEEP_CELERY_LANE=files \
  BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH=/srv/backupsheep-keys/files/keyring \
  celery -A backupsheep worker --loglevel=info --hostname=files@%h -Q files --concurrency=1
env BACKUPSHEEP_RUNTIME_ROLE=storage BACKUPSHEEP_CELERY_LANE=storage \
  celery -A backupsheep worker --loglevel=info --hostname=storage@%h -Q storage --concurrency=2
env BACKUPSHEEP_RUNTIME_ROLE=logs BACKUPSHEEP_CELERY_LANE=logs \
  celery -A backupsheep worker --loglevel=info --hostname=logs@%h -Q logs --concurrency=2
env BACKUPSHEEP_RUNTIME_ROLE=beat BACKUPSHEEP_CELERY_LANE=beat \
  celery -A backupsheep beat --loglevel=info --scheduler backupsheep.scheduler:BackupDatabaseScheduler
```

An equivalent non-Compose supervisor must preserve separate database/files/storage private
work roots and the two forward plus one reverse BSE1 handoff boundaries; one shared
plaintext `_storage` directory is not equivalent. `reset_incremental_cache` and files
run-log pruning execute in the files lane, while database run-log pruning executes in the
database lane and destination-upload run-log pruning executes in the storage lane.
UI-approved host keys and append-only approval events are account-scoped
PostgreSQL records. A database/files worker materializes only the exact approval for one
operation in a transient mode-`0600` private runtime file and removes it afterward; stock
Compose has no trust volume.

Optional `.secrets/ssh_managed_database_private_key` and
`.secrets/ssh_managed_files_private_key` sources are mounted mode `0444` only in their
matching workers. The app and all other roles receive neither private key. Each accepted
Ed25519 identity is copied into that worker's private tmpfs as
`/run/backupsheep/ssh/managed_private_key`, mode `0600`. The identities must be distinct and
managed-key mode is allowed only while the database contains exactly one account.
Multi-account installations use customer-supplied private keys.
`BS_LOCAL_STORAGE_PATH` is mounted read/write only by storage; every other role receives
no Local Storage mount and consumes restore bytes only through the reverse BSE1 handoff.

Keep one Beat process for the normal maintenance cadence. Backup schedule occurrences
have a transactional database claim, but duplicated Beat instances add needless
scheduler load and can duplicate ordinary maintenance dispatches.

## Next steps

1. Complete [first-run setup](first-run.md).
2. Move to [production HTTPS and hardening](production.md).
3. Establish [BackupSheep's own backup and recovery plan](disaster-recovery.md).
4. Use the [operations runbook](operations.md) for routine checks.
