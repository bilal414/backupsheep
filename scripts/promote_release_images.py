#!/usr/bin/env python3
"""Promote verified quarantine OCI digests to immutable official SemVer tags."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from verify_release import (
    MAX_CONTROL_FILE_BYTES,
    ReleaseVerificationError,
    _load_json,
    _safe_artifact,
    _sha256_path,
    _validate_policy,
    validate_release,
)


def _oras(oras: str, arguments: list[str], *, allow_not_found: bool = False) -> str:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("ORAS_"):
            environment.pop(name, None)
    try:
        result = subprocess.run(
            [oras, *arguments],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseVerificationError(f"ORAS invocation failed: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        normalized = detail.lower()
        if allow_not_found and any(
            marker in normalized for marker in ("manifest_unknown", "manifest unknown", "not found", "404")
        ):
            return "NOT_FOUND"
        raise ReleaseVerificationError(f"ORAS failed closed: {detail[:1000]}")
    return result.stdout


def _fetch_and_verify_index(
    oras: str,
    reference: str,
    expected_path: Path,
    expected_digest: str,
    *,
    allow_not_found: bool = False,
) -> bool:
    """Return False only for an authenticated, definitive registry miss."""

    with tempfile.TemporaryDirectory(prefix="backupsheep-promote-") as temporary:
        fetched = Path(temporary) / "index.json"
        status = _oras(
            oras,
            ["manifest", "fetch", "--output", str(fetched), reference],
            allow_not_found=allow_not_found,
        )
        if status == "NOT_FOUND":
            return False
        if _sha256_path(fetched) != expected_digest:
            raise ReleaseVerificationError(f"official reference has the wrong OCI digest: {reference}")
        if fetched.read_bytes() != expected_path.read_bytes():
            raise ReleaseVerificationError(f"official reference has different OCI index bytes: {reference}")
        return True


def promote(policy: dict, manifest: dict, artifacts_dir: Path, oras: str) -> None:
    policy = _validate_policy(policy)
    validate_release(policy, manifest, artifacts_dir)
    tag = manifest["release"]["tag"]

    # Classify every destination before making the first write. An exact tag
    # from an interrupted earlier attempt is safe to resume; any mismatch,
    # timeout, authentication failure, or TLS failure stops the whole release.
    missing: set[str] = set()
    expected_indexes: dict[str, Path] = {}
    for image_name, image in manifest["images"].items():
        official_tag = f"{image['official_repository']}:{tag}"
        expected_path = _safe_artifact(
            artifacts_dir, image["oci_index"]["file"], f"{image_name} retained OCI index"
        )
        expected_indexes[image_name] = expected_path
        if not _fetch_and_verify_index(
            oras,
            official_tag,
            expected_path,
            image["digest"],
            allow_not_found=True,
        ):
            missing.add(image_name)

    for image_name, image in manifest["images"].items():
        source = image["quarantine_reference"]
        destination = f"{image['official_repository']}:{tag}"
        if image_name in missing:
            _oras(oras, ["cp", source, destination])
        for reference in (destination, image["official_reference"]):
            _fetch_and_verify_index(
                oras,
                reference,
                expected_indexes[image_name],
                image["digest"],
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--oras", default="oras")
    arguments = parser.parse_args(argv)
    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        manifest = _load_json(arguments.manifest, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        promote(policy, manifest, arguments.artifacts_dir.resolve(strict=True), arguments.oras)
        return 0
    except (OSError, ReleaseVerificationError) as exc:
        print(f"release promotion failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
