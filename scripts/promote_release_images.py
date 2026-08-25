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


def promote(policy: dict, manifest: dict, artifacts_dir: Path, oras: str) -> None:
    policy = _validate_policy(policy)
    validate_release(policy, manifest, artifacts_dir)
    tag = manifest["release"]["tag"]

    # Complete every absence check before making the first official write. A
    # timeout/auth/TLS failure is not treated as an absent tag.
    for image in manifest["images"].values():
        official_tag = f"{image['official_repository']}:{tag}"
        status = _oras(oras, ["manifest", "fetch", "--descriptor", official_tag], allow_not_found=True)
        if status != "NOT_FOUND":
            raise ReleaseVerificationError(f"refusing to replace existing official tag {official_tag}")

    for image_name, image in manifest["images"].items():
        source = image["quarantine_reference"]
        destination = f"{image['official_repository']}:{tag}"
        _oras(oras, ["cp", source, destination])
        expected_path = _safe_artifact(
            artifacts_dir, image["oci_index"]["file"], f"{image_name} retained OCI index"
        )
        for reference in (destination, image["official_reference"]):
            with tempfile.TemporaryDirectory(prefix="backupsheep-promote-") as temporary:
                fetched = Path(temporary) / "index.json"
                _oras(oras, ["manifest", "fetch", "--output", str(fetched), reference])
                if _sha256_path(fetched) != image["digest"]:
                    raise ReleaseVerificationError(f"promotion changed the OCI digest for {reference}")
                if fetched.read_bytes() != expected_path.read_bytes():
                    raise ReleaseVerificationError(f"promotion changed the OCI index bytes for {reference}")


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
