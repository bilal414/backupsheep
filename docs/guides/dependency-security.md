# Dependency security and reproducibility

`requirements.txt` is the reviewed list of direct Python constraints. The supply-chain
workflow resolves it on Python 3.14 and fails when `pip-audit` reports a known advisory.
The root `package-lock.json` remains the single frontend lock and is audited separately.

## Hash-lock adoption plan

Python transitive dependencies are not yet hash-locked. Do not label an image build
reproducible until this gate is complete:

1. Generate a fully pinned, hash-bearing lock from `requirements.txt` with a pinned
   `pip-tools` or `uv` release.
2. Resolve and install that candidate on Linux `amd64` and `arm64`, Python 3.14, using
   `pip install --require-hashes --only-binary=:all:`.
3. Run the Django test suite plus backup/restore client smoke tests for PostgreSQL,
   MySQL, MariaDB, SFTP and every enabled cloud SDK.
4. Make the Docker build install only the verified lock, keep `requirements.txt` as its
   human-reviewed input, and have CI fail when regeneration changes the lock.
5. Generate an SPDX or CycloneDX SBOM from the built image, attach it to the release,
   and sign both image digest and provenance.

The multi-architecture install gate matters: cloud SDK and cryptography wheels can differ
by platform. A lock generated and tested on only a developer Mac is not a production
reproducibility control.
