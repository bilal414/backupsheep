#!/usr/bin/env python3
"""Fetch an exact quarantine OCI index and its BuildKit provenance blobs."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import tempfile
from pathlib import Path

from verify_release import (
    MAX_CONTROL_FILE_BYTES,
    ReleaseVerificationError,
    _digest,
    _load_json,
    _parse_oci_index,
    _run_tool,
    _sha256_path,
    _validate_attestation_manifest,
    _validate_policy,
)


def _atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_stat = destination.parent.lstat()
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
        raise ReleaseVerificationError("evidence destination parent must be a real directory")
    os.chmod(destination.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_stream:
            for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, destination)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def collect(
    *, policy: dict, artifacts_dir: Path, image_name: str, index_digest: str, oras: str
) -> None:
    policy = _validate_policy(policy)
    if image_name not in policy["images"]:
        raise ReleaseVerificationError("image name is not authorized by policy")
    index_digest = _digest(index_digest, "index digest")
    repository = policy["images"][image_name]["quarantine_repository"]
    predicate_type = policy["attestations"]["provenance_predicate_type"]
    artifacts_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    artifacts_dir = artifacts_dir.resolve(strict=True)

    with tempfile.TemporaryDirectory(prefix=f"backupsheep-{image_name}-oci-") as temporary:
        temporary_dir = Path(temporary)
        fetched_index = temporary_dir / "index.json"
        _run_tool(
            oras,
            ["manifest", "fetch", "--output", str(fetched_index), f"{repository}@{index_digest}"],
            ("ORAS_",),
        )
        if _sha256_path(fetched_index) != index_digest:
            raise ReleaseVerificationError("fetched OCI index bytes do not match the requested digest")
        index_document = _load_json(fetched_index, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        _, attestation_digests = _parse_oci_index(
            index_document, policy["platforms"], f"{image_name} OCI index"
        )
        _atomic_copy(fetched_index, artifacts_dir / "oci" / f"{image_name}.index.json")

        for platform in policy["platforms"]:
            slug = platform.replace("/", "-")
            attestation_digest = attestation_digests[platform]
            fetched_attestation = temporary_dir / f"{slug}.attestation.json"
            _run_tool(
                oras,
                [
                    "manifest",
                    "fetch",
                    "--output",
                    str(fetched_attestation),
                    f"{repository}@{attestation_digest}",
                ],
                ("ORAS_",),
            )
            if _sha256_path(fetched_attestation) != attestation_digest:
                raise ReleaseVerificationError("fetched attestation manifest does not match its OCI digest")
            attestation_document = _load_json(
                fetched_attestation, maximum_bytes=MAX_CONTROL_FILE_BYTES
            )
            blob_digest = _validate_attestation_manifest(
                attestation_document,
                predicate_type,
                f"{image_name} {platform} attestation manifest",
            )
            fetched_provenance = temporary_dir / f"{slug}.intoto.json"
            _run_tool(
                oras,
                [
                    "blob",
                    "fetch",
                    "--output",
                    str(fetched_provenance),
                    f"{repository}@{blob_digest}",
                ],
                ("ORAS_",),
            )
            if _sha256_path(fetched_provenance) != blob_digest:
                raise ReleaseVerificationError("fetched provenance bytes do not match the OCI layer digest")
            _load_json(fetched_provenance, maximum_bytes=MAX_CONTROL_FILE_BYTES)
            _atomic_copy(
                fetched_attestation,
                artifacts_dir / "oci" / f"{image_name}-{slug}.attestation.json",
            )
            _atomic_copy(
                fetched_provenance,
                artifacts_dir / "provenance" / f"{image_name}-{slug}.intoto.json",
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--image", choices=("app", "postgres", "egress"), required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--oras", default="oras")
    arguments = parser.parse_args(argv)
    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        collect(
            policy=policy,
            artifacts_dir=arguments.artifacts_dir,
            image_name=arguments.image,
            index_digest=arguments.digest,
            oras=arguments.oras,
        )
        return 0
    except (OSError, ReleaseVerificationError) as exc:
        print(f"release evidence collection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
