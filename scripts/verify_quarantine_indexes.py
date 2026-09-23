#!/usr/bin/env python3
"""Re-fetch every quarantine and verifier manifest before OIDC signing."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from promote_release_images import _fetch_and_verify_index
from verify_release import (
    MAX_CONTROL_FILE_BYTES,
    MAX_EVIDENCE_FILE_BYTES,
    ReleaseVerificationError,
    _digest,
    _load_json,
    _mapping,
    _safe_artifact,
    validate_release,
)


def _embedded_manifest(
    artifacts_dir: Path,
    catalog_record: dict[str, Any],
    expected_digest: str,
    output: Path,
    label: str,
) -> Path:
    catalog_path = _safe_artifact(
        artifacts_dir,
        catalog_record["file"],
        f"{label} source catalog",
    )
    catalog = _mapping(
        _load_json(catalog_path, maximum_bytes=MAX_EVIDENCE_FILE_BYTES),
        f"{label} source catalog",
    )
    metadata = _mapping(
        _mapping(catalog.get("source"), f"{label} source").get("metadata"),
        f"{label} source metadata",
    )
    payload = metadata.get("manifest")
    if not isinstance(payload, str) or not payload:
        raise ReleaseVerificationError(f"{label} source catalog has no embedded manifest")
    try:
        decoded = base64.b64decode(payload, validate=True)
    except (TypeError, ValueError) as exc:
        raise ReleaseVerificationError(f"{label} embedded manifest is not canonical base64") from exc
    if len(decoded) > MAX_CONTROL_FILE_BYTES:
        raise ReleaseVerificationError(f"{label} embedded manifest exceeds the size limit")
    if "sha256:" + hashlib.sha256(decoded).hexdigest() != _digest(
        expected_digest, f"{label} digest"
    ):
        raise ReleaseVerificationError(f"{label} embedded manifest has the wrong digest")
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(decoded)
    return output


def verify(
    policy: dict[str, Any],
    manifest: dict[str, Any],
    artifacts_dir: Path,
    oras: str,
) -> None:
    validate_release(policy, manifest, artifacts_dir)
    with tempfile.TemporaryDirectory(prefix="backupsheep-pre-sign-manifests-") as temporary:
        scratch = Path(temporary)
        for image_name, image in manifest["images"].items():
            repository = image["quarantine_repository"]
            index_path = _safe_artifact(
                artifacts_dir,
                image["oci_index"]["file"],
                f"{image_name} OCI index",
            )
            _fetch_and_verify_index(
                oras,
                image["quarantine_reference"],
                index_path,
                image["digest"],
            )
            catalogs = {
                record["platform"]: record for record in image["source_catalogs"]
            }
            for platform, child_digest in image["platforms"].items():
                slug = platform.replace("/", "-")
                expected = _embedded_manifest(
                    artifacts_dir,
                    catalogs[platform],
                    child_digest,
                    scratch / f"{image_name}-{slug}.json",
                    f"{image_name} {platform}",
                )
                _fetch_and_verify_index(
                    oras,
                    f"{repository}@{child_digest}",
                    expected,
                    child_digest,
                )
            for position, record in enumerate(image["attestation_manifests"]):
                expected = _safe_artifact(
                    artifacts_dir,
                    record["file"],
                    f"{image_name} attestation manifest {position}",
                )
                _fetch_and_verify_index(
                    oras,
                    f"{repository}@{record['digest']}",
                    expected,
                    record["digest"],
                )

        verifier = manifest["consumer"]["cosign_image"]
        for record in verifier["platforms"]:
            platform = record["platform"]
            slug = platform.replace("/", "-")
            child_digest = record["manifest_digest"]
            expected = _embedded_manifest(
                artifacts_dir,
                record["source_catalog"],
                child_digest,
                scratch / f"release-verifier-{slug}.json",
                f"release verifier {platform}",
            )
            _fetch_and_verify_index(
                oras,
                f"{verifier['repository']}@{child_digest}",
                expected,
                child_digest,
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--oras", required=True)
    arguments = parser.parse_args(argv)
    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        manifest = _load_json(arguments.manifest, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        verify(
            _mapping(policy, "release policy"),
            _mapping(manifest, "release manifest"),
            arguments.artifacts_dir.resolve(strict=True),
            arguments.oras,
        )
        return 0
    except (OSError, KeyError, ValueError, json.JSONDecodeError, ReleaseVerificationError) as exc:
        print(f"pre-sign quarantine verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
