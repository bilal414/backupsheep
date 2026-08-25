#!/usr/bin/env python3
"""Copy verified images to non-SemVer official staging tags before signing."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from promote_release_images import _fetch_and_verify_index, _oras
from verify_release import (
    MAX_CONTROL_FILE_BYTES,
    ReleaseVerificationError,
    _load_json,
    _safe_artifact,
    _validate_policy,
    validate_release,
)


_STAGING_TAG = re.compile(r"staged-[0-9a-f]{40}-[1-9][0-9]*-[1-9][0-9]*\Z")


def stage(
    policy: dict,
    manifest: dict,
    artifacts_dir: Path,
    oras: str,
    staging_tag: str,
) -> None:
    policy = _validate_policy(policy)
    validate_release(policy, manifest, artifacts_dir)
    if not _STAGING_TAG.fullmatch(staging_tag):
        raise ReleaseVerificationError("the official staging tag is not canonical")
    if not staging_tag.startswith(f"staged-{manifest['release']['source_commit']}-"):
        raise ReleaseVerificationError("the official staging tag is not source-commit bound")

    missing: set[str] = set()
    expected_indexes: dict[str, Path] = {}
    for image_name, image in manifest["images"].items():
        reference = f"{image['official_repository']}:{staging_tag}"
        expected_path = _safe_artifact(
            artifacts_dir, image["oci_index"]["file"], f"{image_name} retained OCI index"
        )
        expected_indexes[image_name] = expected_path
        if not _fetch_and_verify_index(
            oras,
            reference,
            expected_path,
            image["digest"],
            allow_not_found=True,
        ):
            missing.add(image_name)

    for image_name, image in manifest["images"].items():
        staging_reference = f"{image['official_repository']}:{staging_tag}"
        if image_name in missing:
            _oras(oras, ["cp", image["quarantine_reference"], staging_reference])
        for reference in (staging_reference, image["official_reference"]):
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
    parser.add_argument("--staging-tag", required=True)
    parser.add_argument("--oras", default="oras")
    arguments = parser.parse_args(argv)
    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        manifest = _load_json(arguments.manifest, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        stage(
            policy,
            manifest,
            arguments.artifacts_dir.resolve(strict=True),
            arguments.oras,
            arguments.staging_tag,
        )
        return 0
    except (OSError, ReleaseVerificationError) as exc:
        print(f"release staging failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
