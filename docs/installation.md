# Installation

BackupSheep runs as a hardened Docker Compose stack. The canonical, maintained
instructions are in the [verified installation guide](guides/installation.md).

## Security boundary

The BackupSheep installer manages only its application checkout, configuration, secret
files, images, containers, networks and named volumes. It does **not** install Git or
Docker, add package repositories, enable or restart services, edit Docker daemon
configuration, open a firewall, change kernel settings, create host users, or require
root. The host operator must provide and secure:

- Git and Bash;
- Docker Engine 28.0.0 or newer;
- Docker Compose 2.33.1 or newer;
- access to the intended Docker daemon;
- a user-owned installation path and sufficient CPU, memory and storage;
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
./install.sh --ref "${COMMIT}" --domain backups.example.com
```

Run it as the same unprivileged user that is already authorized for the intended Docker
daemon. The installer refuses root and `sudo`; it does not provision or reconfigure the
host.

The installer fetches that exact commit from the canonical HTTPS repository, verifies
the checkout and its own bytes, creates protected file-backed secrets, builds commit-tagged
application and PostgreSQL images, and starts only PostgreSQL, RabbitMQ, migrations, the deployment
preflight and web UI. The web listener stays on `127.0.0.1:8000`.
Application and PostgreSQL roles use `pull_policy: never`; the installer explicitly builds
both from the reviewed commit and will not substitute registry images if either local build
is missing. The PostgreSQL build starts from the digest-pinned official image, verifies the
official entrypoint, applies exact Debian security packages, replaces and deletes `gosu`,
and declares the fixed PostgreSQL UID/GID. Stock Compose starts it directly as that user
with every Linux capability dropped.

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

Provider workers and the scheduler are intentionally disabled by default. Review
credentials and durable recovery/queue state before explicitly enabling operations:

```bash
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --enable-operations
```

This opt-in can execute queued or recoverable provider work. The installer never
performs an in-place source upgrade and never deletes containers or volumes as an
automatic rollback.

## Secrets

The installer writes `.env` as mode `0600` and `.secrets` as a mode `0700` directory.
The Django key, database password, broker password and onboarding token are separate
mode-`0444` files inside it; directory traversal protection keeps them private on the
host while Docker can mount the individual files read-only for UID 10001. Their direct
`.env` keys remain blank, so values do not appear in Compose-expanded configuration or
container inspection.

An optional `.secrets/ssh_managed_private_key` file follows the same host mode; leave it
empty to disable the managed identity. Its mode-`0444` source is mounted only in
app/database/files. The entrypoint validates a non-empty unencrypted key no larger than
64 KiB, copies it to private tmpfs at `/run/backupsheep/ssh/managed_private_key` with mode
`0600`, and exports that runtime path. Do not point SSH directly at the
`/run/secrets/ssh_managed_private_key` source. Existing installations must follow the
explicit trust/key migration in the [upgrade guide](guides/upgrades.md).

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
