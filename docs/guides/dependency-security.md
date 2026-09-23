# Dependency security and reproducibility

`requirements.txt` is the reviewed list of direct Python constraints and
`requirements.lock` is the generated, fully pinned hash lock consumed by the image build.
The supply-chain workflow installs `pip-audit` and its complete CPython 3.14/Linux
dependency closure from the whole-file and artifact-hash-locked
`deploy/dependency-audit-requirements.lock`, then audits the exact application
`requirements.lock` with hash enforcement and dependency resolution disabled. It fails
when the locked runtime inventory has a known advisory. The root `package-lock.json`
remains the single frontend lock and is audited separately.

## Current hash-lock boundary

The Docker build verifies that the lock records the exact `requirements.txt` digest, then
downloads/builds the authenticated dependency set under pip's `--require-hashes` mode.
Locally built source-package wheels have new hashes, so the builder creates a second lock
over the exact platform wheelhouse. The final image installs that wheelhouse offline with
`--no-index --require-hashes` and runs `pip check`.

Regenerate the lock only as a reviewed dependency change. A changed direct-constraint
digest, missing artifact hash or unexpected dependency causes the image build to fail.

## Ubuntu runtime snapshot

The application and RabbitMQ migration images resolve their Ubuntu packages only from
the fixed, signed `20260831T131500Z` Ubuntu archive snapshot. Both source definitions
are AMD64-only, replace every inherited APT source, reject partial index updates, and
verify that every loaded package index came from the exact snapshot URI. The final
images retain neither an APT source nor the build-only CA bootstrap.
Each APT request uses at most three transport retries with a 30-second inactivity timeout,
only against that same immutable snapshot. Every snapshot-backed update, download, and
upgrade operation makes at most four whole attempts with 15-, 30-, and 60-second backoff.
Completed signed indexes and exact-version package downloads can be reused between attempts.
Exhausting either bound aborts the build; there is no fallback mirror, mutable repository,
unauthenticated package, or TLS exception. The retry configuration is build-only and is
removed with the temporary source and CA configuration.

A frozen snapshot prevents repository drift; it does not provide automatic patching.
For every release, review current Ubuntu Security Notices, advance the snapshot and
exact package pins together, and rerun the full image, SBOM, Trivy, and Grype gates.
Canonical currently commits to retaining snapshots for at least two years, so retain or
mirror the signed package artifacts required for longer historical rebuilds. See the
[Ubuntu Snapshot Service](https://snapshot.ubuntu.com/).

## Remaining reproducibility gate

Hash authentication is not byte-for-byte reproducibility. Locally built wheels can differ
by toolchain/date, and live signed Debian/PGDG repository inputs can change even though
the Dockerfile exact-version selects packages. Before calling a release fully reproducible:

1. build and test the exact commit on the sole supported platform, Linux `amd64`, with
   the pinned Dockerfile frontend/base image and compare the dependency inventory with
   the reviewed lock and prior release;
2. run Django plus PostgreSQL, MySQL, MariaDB, SFTP and enabled provider client smoke tests
   against the resulting image;
3. generate an SPDX or CycloneDX SBOM, attach it to the release, and sign the image digest
   and provenance;
4. retain or mirror the exact authenticated APT and upstream source artifacts required to
   rebuild after repositories move.

The native Linux AMD64 gate still matters because cloud SDK, cryptography and source-built
wheel outputs can differ by toolchain and build environment even on one architecture. A
lock generated on one developer machine is artifact authentication input, not sufficient
release reproducibility evidence. ARM64 and other architectures are outside the supported
release and test matrix.
