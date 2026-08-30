#!/usr/bin/env python3
"""Build the canonical signed-release V2 descriptor from verified evidence."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys

from verify_release import (
    MAX_CONTROL_FILE_BYTES,
    RELEASE_IMAGE_NAMES,
    ReleaseVerificationError,
    _load_json,
    _safe_artifact,
    _sha256_path,
    _validate_policy,
    validate_release,
)


DESCRIPTOR_MAGIC = "BACKUPSHEEP-SIGNED-RELEASE-V2"
MAX_DESCRIPTOR_BYTES = 4096


def descriptor_payload(policy: dict, manifest: dict, manifest_digest: str) -> bytes:
    policy = _validate_policy(policy)
    release = manifest["release"]
    consumer = manifest["consumer"]
    verifier = consumer["cosign_image"]
    platforms = {record["platform"]: record for record in verifier["platforms"]}
    lines = [
        DESCRIPTOR_MAGIC,
        f"release_tag={release['tag']}",
        f"source_commit={release['source_commit']}",
        f"release_manifest_sha256={manifest_digest}",
    ]
    for image_name in RELEASE_IMAGE_NAMES:
        lines.append(f"{image_name.replace('-', '_')}_image={manifest['images'][image_name]['official_reference']}")
    lines.extend(
        [
            f"release_verifier_image={verifier['reference']}",
            "release_verifier_runtime_contract_version="
            f"{verifier['runtime_contract_version']}",
            f"release_verifier_linux_amd64_manifest={platforms['linux/amd64']['manifest_digest']}",
            f"release_verifier_linux_amd64_config={platforms['linux/amd64']['config_digest']}",
            f"release_verifier_linux_arm64_manifest={platforms['linux/arm64']['manifest_digest']}",
            f"release_verifier_linux_arm64_config={platforms['linux/arm64']['config_digest']}",
            f"trusted_root_sha256={consumer['trusted_root']['sha256']}",
        ]
    )
    payload = ("\n".join(lines) + "\n").encode("ascii")
    if len(lines) != 16 or len(payload) > MAX_DESCRIPTOR_BYTES:
        raise ReleaseVerificationError("release descriptor does not have the exact V2 shape")
    return payload


def validate_descriptor_payload(
    policy: dict, manifest: dict, manifest_digest: str, payload: bytes
) -> None:
    expected = descriptor_payload(policy, manifest, manifest_digest)
    if payload != expected:
        raise ReleaseVerificationError("release descriptor is not the exact canonical V2 payload")


def _write_private_exclusive(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise ReleaseVerificationError("release descriptor output must not pre-exist")
    parent = path.parent.resolve(strict=True)
    metadata = parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseVerificationError("release descriptor parent must be a real directory")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        artifacts_dir = arguments.artifacts_dir.resolve(strict=True)
        manifest_path = _safe_artifact(
            artifacts_dir, "release-manifest.json", "canonical release manifest"
        )
        if arguments.manifest.resolve(strict=True) != manifest_path:
            raise ReleaseVerificationError("descriptor must bind the canonical release manifest")
        output = artifacts_dir / policy["consumer"]["descriptor_filename"]
        if (
            arguments.output.parent.resolve(strict=True) != artifacts_dir
            or arguments.output.name != output.name
        ):
            raise ReleaseVerificationError("descriptor output path is not canonical")
        manifest = _load_json(manifest_path, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        validate_release(policy, manifest, artifacts_dir)
        payload = descriptor_payload(policy, manifest, _sha256_path(manifest_path))
        if arguments.verify:
            descriptor_path = _safe_artifact(
                artifacts_dir,
                policy["consumer"]["descriptor_filename"],
                "canonical release descriptor",
            )
            if descriptor_path.stat().st_size > MAX_DESCRIPTOR_BYTES:
                raise ReleaseVerificationError("release descriptor is too large")
            validate_descriptor_payload(
                policy,
                manifest,
                _sha256_path(manifest_path),
                descriptor_path.read_bytes(),
            )
        else:
            _write_private_exclusive(output, payload)
        return 0
    except (OSError, UnicodeError, ReleaseVerificationError) as exc:
        print(f"release descriptor generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
