# Installation

BackupSheep runs as a hardened Docker Compose stack. The canonical, maintained
instructions are in the [verified installation guide](guides/installation.md).

## Security boundary

The BackupSheep installer manages only its application checkout, configuration, secret
files, images, containers, networks and named volumes. It does **not** install Git or
Docker, add package repositories, enable or restart services, edit Docker daemon
configuration, open a firewall, change kernel settings, or create host users. The
default mode is non-root; an explicit root-owned mode is available for a host that keeps
its existing rootful Docker daemon behind `sudo`. The host operator must provide and
secure:

- Git and Bash;
- Docker Engine 28.0.0 or newer;
- Docker Compose 2.33.1 or newer;
- access to the intended Docker daemon through the chosen invoking identity;
- an installation path owned by that same effective UID and sufficient CPU, memory and
  storage;
- host/network/TLS policy, monitoring, patching and recovery.

## Verified installer

Download the installer from the exact release commit you intend to run. Never pipe a
mutable remote script into a privileged shell:

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

The installer generates independent database/files artifact keyrings locally; no external
key service, AWS account, or AWS credential is required for artifact encryption. AWS
credentials remain optional only for a configured AWS source, storage destination, or
Amazon SES email integration. Back up both keyrings before enabling work.

By default, run it as the same unprivileged user that is already authorized for the
intended Docker daemon. Root and `sudo` remain refused unless the operator supplies the
explicit `--allow-root-install` flag. This does not provision or reconfigure the host.

For an existing rootful daemon intentionally accessible only through root, first place
the reviewed installer in a protected root-owned directory, then run the root-owned copy
explicitly:

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

The installer creates both lane keyrings inside its protected root-owned secret
directory and never places root-key material in arguments or environment variables.
Back up their exact bytes with PostgreSQL before enabling operations, as shown in the
full [verified installation guide](guides/installation.md#explicit-rootful-daemon-mode).
The installer and wrapper never use `SUDO_USER` or `chown`: the checkout, configuration,
secrets, override and mutation lock remain owned by the real effective invoker. Every
later root-owned wrapper command must also run as UID 0 and begin with the approval flag:

```bash
sudo -H /opt/backupsheep/backupsheep-compose --allow-root-install ps --all
```

The flag changes only host-side installation ownership and Docker access. It does not
change the reviewed non-root user, capability or filesystem configuration inside any
long-lived container.

The installer fetches that exact commit from the canonical HTTPS repository, verifies
the checkout and its own bytes, creates protected file-backed secrets, explicitly builds
commit-tagged application, PostgreSQL and namespace-guard images, and starts only the core
database/broker, provision/migrate/seal/preflight gates, app guard and web UI. The web
listener stays on `127.0.0.1:8000`.
Application, PostgreSQL and egress-guard roles use `pull_policy: never`; the installer will
not substitute registry images if a reviewed local build is missing. The PostgreSQL build
starts from the digest-pinned official PostgreSQL 18.6 Alpine 3.24 image, verifies the
official entrypoint, installs exact `su-exec=0.3-r0`, replaces and deletes `gosu`, and
declares UID/GID `70:70`. Stock Compose starts it directly as that user with every Linux
capability dropped and an installation-bound ICU/storage-generation witness. Existing
Debian `pgdata` requires the explicit
[Alpine/ICU logical migration gate](guides/postgres-runtime-migration.md); the Alpine
image never mounts or auto-adopts that volume.

It also creates a stable random 64-hex installation ID and an empty labeled sentinel
volume, then verifies Compose resource ownership before mutation. It enumerates every
exact project network/volume name and rejects an unlabeled or foreign collision rather
than letting Compose adopt it. A project-name collision, foreign/missing ownership
evidence or ambiguous legacy resource fails closed. Existing RabbitMQ data is accepted
only with the installer-owned `4.3` generation witness or exactly one running, healthy
project broker. A blank witness on existing data requires the explicit wrapper migration
or reconciliation path so the pinned image and Khepri state are attested; the installer
never guesses at or migrates a 3.13/4.2 data directory.

An old stock deployment that was taken down before identity sentinels existed may have
only its four labeled data volumes left. Use the guarded one-time
`--adopt-legacy-project NAME` workflow in the
[verified installation guide](guides/installation.md#one-time-legacy-compose-down-adoption).
It accepts no containers, networks, extra project-prefixed volumes, newer volume names
or label drift, creates and re-inspects only the identity sentinel, and leaves the
ordinary ownership checks intact. Do not simulate adoption by editing `.env` directly.

When exact-path legacy containers are still present, the installer automatically creates
that sentinel only after the complete container, network and volume inventory passes its
exact path/model/service/logical-name/physical-name and blank-identity checks. The wrapper
uses the matching sentinel to permit those immutable blank container labels only until
the reviewed Compose commands recreate them; foreign or partial identities still fail
closed.

Development staging layout v2 was prerelease-only. Its canonical project-owned
`ssh_trust` volume may pass the ordinary exact ownership/name/label checks, but it is
preserved detached as rollback evidence during the explicit v3 migration. Layout v3 has
no shared trust mount, group or provisioning path, and the wrapper rejects every
`--volume` override. The retired global host-key inventory is never imported; operators
must reapprove each exact account/host/port/key in the PostgreSQL ledger. A foreign or
ambiguous legacy trust volume fails closed.

Provider workers and the scheduler are intentionally disabled by default. Review
credentials and durable recovery/queue state before explicitly enabling operations:

```bash
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --project-name backupsheep \
  --domain backups.example.com \
  --enable-operations
```

This opt-in can execute queued or recoverable provider work. The installer never
performs an in-place source upgrade and never deletes containers or volumes as an
automatic rollback.

## Secrets

The installer writes `.env` as mode `0600` and `.secrets` as a mode `0700` directory.
The Django key, database bootstrap/migrator/per-lane passwords, RabbitMQ
bootstrap/per-lane passwords, task-signing material, artifact lane keyrings and onboarding
token are separate mode-`0444` files inside it. Directory traversal protection keeps them
private on the host while Docker mounts each individual file read-only only in its granted
role. Their direct `.env` keys remain blank, so values do not appear in Compose-expanded
configuration or container inspection.

Optional `.secrets/ssh_managed_database_private_key` and
`.secrets/ssh_managed_files_private_key` files follow the same host mode; leave both empty
to disable managed identities. The database key is mounted only in `worker-database`, and
the files key only in `worker-files`; the app and other roles receive neither. The
entrypoint validates each non-empty Ed25519 key, copies the lane's source to private tmpfs
at `/run/backupsheep/ssh/managed_private_key` with mode `0600`, and never points SSH at the
mode-`0444` source. The two identities must be distinct and are supported only while the
installation has exactly one account. Multi-account deployments use customer-supplied
private keys. Existing installations must follow the explicit legacy-identity retirement
and host-key reapproval procedure in the [upgrade guide](guides/upgrades.md).

Retrieve the onboarding token only from the trusted host shell:

```bash
cd "$HOME/.local/share/backupsheep"
cat .secrets/onboarding_token
```

Then use an SSH tunnel to reach the loopback listener and complete first-run setup. See
the [production deployment guide](deployment.md) before exposing the service publicly.
Warning-level HTTPS findings from Django's deployment check are expected only in this
deliberate loopback HTTP/SSH-tunnel mode. Public access requires real TLS,
`DJANGO_HTTPS=true`, `APP_PROTOCOL=https://`, the exact public domain/allowed hosts, and
review of every deployment warning.

Every application-image command passes through the hardened entrypoint, which neutralizes
startup-loader hooks, verifies the runtime boundary and repeats the deployment preflight
before web, worker and Beat processes. Automatic restarts therefore do not rely only on a
previous one-shot preflight result, and any unapplied Django migration stops startup.
