# Signed container releases

BackupSheep's release workflow is checked in but deliberately dormant. Merging it
does not build, sign, promote, or publish anything. An administrator must protect
the `signed-release` environment and set
`BACKUPSHEEP_SIGNED_RELEASES_ENABLED=true` before a SemVer tag can start it.

## Trust and promotion model

The workflow separates three permission domains:

1. `build_scan` can read source and write GHCR packages, but it has no OIDC token.
   It builds only into the explicit `*-quarantine` repositories.
2. `sign_promote` is protected by the `signed-release` environment. It installs
   hash-verified Cosign and ORAS binaries, revalidates all downloaded evidence,
   signs quarantine digests, and verifies them online. Only then does it copy the
   exact OCI index digest to an official SemVer tag. It signs the official digest
   separately and reruns the complete online verifier.
3. `publish_evidence` can write GitHub release contents but cannot write packages
   or request an OIDC token. It verifies the signed archive before publishing it.

A rejected candidate therefore remains in quarantine and never gets an official
repository tag. The official repositories receive no run tag, candidate tag, or
other mutable staging reference. Promotion refuses an existing SemVer tag and
treats authentication, network, TLS, and unexpected registry errors as failures,
not as evidence that a tag is absent.

The release set is atomic and contains three separately scanned and signed images:
the application, its PostgreSQL runtime, and the no-secret egress guard. A missing
or unverifiable image blocks promotion of the entire release set.

## Immutable inputs and real provenance

Every GitHub Action is pinned to a full commit. BuildKit and QEMU container images
are digest pinned. Cosign, ORAS, Syft, and Trivy are downloaded directly from exact
release asset URLs and installed only after their checked-in SHA-256 values match.
No release installer script from another repository is executed.

Each build uses the remote Git URL at the exact 40-character release commit rather
than the runner workspace. BuildKit is requested to emit SLSA v1 provenance with
`mode=max` and the release workflow as builder ID. The collector retrieves the raw
OCI index, each index-bound attestation manifest, and the actual in-toto provenance
blob. It does not synthesize a replacement predicate. The verifier requires:

- the retained raw index bytes to hash to the declared registry digest;
- exactly `linux/amd64` and `linux/arm64` child descriptors;
- exactly one attestation manifest bound to every child digest;
- the provenance blob digest to be a layer in that attestation manifest;
- an in-toto Statement v1 subject containing the exact child digest;
- the exact remote Git commit, Dockerfile, OCI labels, and workflow builder ID;
- complete BuildKit request and dependency metadata; and
- nonempty `mode=max` LLB, source, and layer data.

These fields follow BuildKit's documented [SLSA provenance
definition](https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md).

## Scanner and SBOM policy

Trivy and Syft run in a cleared environment with explicit trusted empty config
files. Trivy also receives an explicit empty ignore file. Repository-local
`.syft.yaml`, `trivy.yaml`, `.trivyignore`, environment overrides, and a hidden
`--ignore-unfixed` flag cannot silently weaken the gate.

Every exact platform child must have:

- a Syft source catalog whose input and manifest digest match the quarantine
  `repository@sha256` reference and whose artifact inventory is nonempty;
- an SPDX document with at least one package;
- a CycloneDX document with at least one component; and
- a structurally complete Trivy report with target/class/type metadata and a
  nonempty package inventory.

Any HIGH or CRITICAL vulnerability fails, including one without a vendor fix. The
checked-in policy has no allowlist. Scanner evidence, signing, registry lookup, and
consumer verification always use digest references; tags are never verification
boundaries.

## Evidence and independent verification

Both candidate and final workflow artifacts use GitHub's 90-day maximum retention.
After final registry verification, the workflow makes a deterministic archive of
the manifest, raw OCI objects, BuildKit provenance, SBOMs, Trivy reports, policy
snapshot, and Sigstore bundles. It signs that archive and publishes the archive,
checksum, signature bundle, release manifest, manifest bundle, and policy as assets
on the immutable Git tag's GitHub release.

With an extracted evidence archive and the policy-pinned Cosign and ORAS versions:

```bash
python3 scripts/verify_release.py \
  --policy deploy/release-policy.json \
  --manifest release-artifacts/release-manifest.json \
  --artifacts-dir release-artifacts \
  --manifest-bundle release-artifacts/release-manifest.bundle.json \
  --cosign /trusted/path/cosign \
  --oras /trusted/path/oras \
  --phase final
```

The default verifier is online and fail closed. It refetches the OCI index by
digest from both quarantine and official repositories, requires byte-for-byte
identity with retained evidence, and verifies the manifest, index, platform,
provenance, and SBOM signatures against the GitHub workflow/tag/commit identity.

`--offline` validates structure, completeness, OCI membership, source binding, and
file hashes only. Its success message states that registry state and signatures
were not checked. Offline success is not release authorization.

## Administrator-owned controls and remaining rollout gates

Repository code cannot enforce these external controls. Before opt-in:

- protect `main` and release tags against force-update and deletion;
- require reviewers on `signed-release` and disable administrator bypass;
- restrict Actions to reviewed full-commit-pinned actions;
- create/authorize both quarantine GHCR packages and official packages for the
  workflow token, while denying unnecessary human write access;
- configure quarantine lifecycle retention so rejected candidates are eventually
  removed without deleting official digests or referrers;
- protect official package/tag deletion through organization policy and audit it;
- make the release workflow a required release status; and
- mirror GitHub release evidence to organization-controlled immutable storage if
  policy requires retention beyond the life of the repository or GitHub account.

Run one protected pre-release tag as a controlled acceptance test before production
use. Confirm GitHub OIDC issuance, GHCR referrer behavior, ORAS graph copying,
BuildKit's complete `mode=max` fields for all three Dockerfiles, Cosign bundle
verification, official tag refusal on replay, and GitHub release asset publication.
This checked-in foundation does not itself configure those GitHub/GHCR controls and
has not published or deployed a release.

## WordPress connector publication hook

The WordPress connector under `integrations/wordpress/backupsheep-v2` has its own
package contract and publication lifecycle. This container workflow intentionally
does not publish a WordPress ZIP or imply that a container release also shipped the
plugin. A future plugin release job should run only after its focused package and
protocol tests, build from the exact Git tree with `scripts/build_wordpress_plugin.py`,
record the archive SHA-256 in a small plugin manifest, keyless-sign both files under
the same protected tag identity, and attach them to the GitHub release. WordPress.org
or marketplace publication remains a separately approved operation with separate
credentials and acceptance evidence.
