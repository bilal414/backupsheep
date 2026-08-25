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

## Remaining reproducibility gate

Hash authentication is not byte-for-byte reproducibility. Locally built wheels can differ
by toolchain/date, and signed Debian/PGDG repository snapshots can change even though the
Dockerfile exact-version selects packages. Before calling a release fully reproducible:

1. build and test the exact commit on Linux `amd64` and `arm64` with the pinned Dockerfile
   frontend/base image and compare dependency inventories;
2. run Django plus PostgreSQL, MySQL, MariaDB, SFTP and enabled provider client smoke tests
   against each resulting image;
3. generate an SPDX or CycloneDX SBOM, attach it to the release, and sign the image digest
   and provenance;
4. retain or mirror the exact authenticated APT and upstream source artifacts required to
   rebuild after repositories move.

The multi-architecture gate matters because cloud SDK, cryptography and source-built wheel
outputs can differ by platform. A lock generated on one developer machine is artifact
authentication input, not sufficient release reproducibility evidence.
