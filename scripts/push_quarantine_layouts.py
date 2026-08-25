#!/usr/bin/env python3
"""Push verified local OCI layouts to quarantine only after release approval."""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

from collect_release_evidence import _OCILayoutArchive, _OCILayoutDirectory
from promote_release_images import _fetch_and_verify_index, _oras
from verify_release import (
    MAX_CONTROL_FILE_BYTES,
    ReleaseVerificationError,
    _load_json,
    _safe_artifact,
    _validate_policy,
    validate_release,
)


_QUARANTINE_TAG = re.compile(r"candidate-[0-9a-f]{40}-[1-9][0-9]*-[1-9][0-9]*\Z")


def push(
    *,
    policy: dict,
    manifest: dict,
    artifacts_dir: Path,
    layouts_dir: Path,
    quarantine_tag: str,
    oras: str,
) -> None:
    policy = _validate_policy(policy)
    validate_release(policy, manifest, artifacts_dir)
    if not _QUARANTINE_TAG.fullmatch(quarantine_tag):
        raise ReleaseVerificationError("the quarantine tag is not canonical")
    if not quarantine_tag.startswith(f"candidate-{manifest['release']['source_commit']}-"):
        raise ReleaseVerificationError("the quarantine tag is not source-commit bound")
    if layouts_dir.is_symlink() or not layouts_dir.is_dir():
        raise ReleaseVerificationError("the OCI layouts root must be a real directory")
    layouts_root = layouts_dir.resolve(strict=True)

    inputs: dict[str, tuple[Path, Path]] = {}
    missing: set[str] = set()
    for image_name, image in manifest["images"].items():
        layout_candidate = layouts_root / image_name
        if layout_candidate.is_symlink():
            raise ReleaseVerificationError("an OCI layout cannot be a symbolic link")
        layout = layout_candidate.resolve(strict=True)
        try:
            layout.relative_to(layouts_root)
        except ValueError as exc:
            raise ReleaseVerificationError("an OCI layout escapes its trusted root") from exc
        expected_path = _safe_artifact(
            artifacts_dir, image["oci_index"]["file"], f"{image_name} retained OCI index"
        )
        reader = _OCILayoutDirectory(layout) if layout.is_dir() else _OCILayoutArchive(layout)
        with reader:
            with tempfile.TemporaryDirectory(prefix="backupsheep-layout-root-") as temporary:
                root_path = Path(temporary) / "index.json"
                root_path.write_bytes(
                    reader.read_member("index.json", maximum_bytes=MAX_CONTROL_FILE_BYTES)
                )
                root_path.chmod(0o600)
                root = _load_json(root_path, maximum_bytes=MAX_CONTROL_FILE_BYTES)
            manifests = root.get("manifests") if isinstance(root, dict) else None
            if not isinstance(manifests, list) or len(manifests) != 1:
                raise ReleaseVerificationError("an OCI layout has an ambiguous root index")
            descriptor = manifests[0]
            annotations = descriptor.get("annotations") if isinstance(descriptor, dict) else None
            if (
                not isinstance(annotations, dict)
                or descriptor.get("digest") != image["digest"]
                or annotations.get("org.opencontainers.image.ref.name") != quarantine_tag
                or annotations.get("io.containerd.image.name")
                != f"{image['quarantine_repository']}:{quarantine_tag}"
            ):
                raise ReleaseVerificationError("an OCI layout root is not bound to its quarantine target")
            if reader.blob(
                image["digest"], maximum_bytes=MAX_CONTROL_FILE_BYTES
            ) != expected_path.read_bytes():
                raise ReleaseVerificationError("an OCI layout index differs from retained evidence")
        inputs[image_name] = (layout, expected_path)

        destination = f"{image['quarantine_repository']}:{quarantine_tag}"
        if not _fetch_and_verify_index(
            oras,
            destination,
            expected_path,
            image["digest"],
            allow_not_found=True,
        ):
            missing.add(image_name)

    for image_name, image in manifest["images"].items():
        layout, expected_path = inputs[image_name]
        destination = f"{image['quarantine_repository']}:{quarantine_tag}"
        if image_name in missing:
            _oras(
                oras,
                ["cp", "--from-oci-layout", f"{layout}:{quarantine_tag}", destination],
            )
        for reference in (destination, image["quarantine_reference"]):
            _fetch_and_verify_index(
                oras,
                reference,
                expected_path,
                image["digest"],
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--layouts-dir", type=Path, required=True)
    parser.add_argument("--quarantine-tag", required=True)
    parser.add_argument("--oras", default="oras")
    arguments = parser.parse_args(argv)
    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        manifest = _load_json(arguments.manifest, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        push(
            policy=policy,
            manifest=manifest,
            artifacts_dir=arguments.artifacts_dir.resolve(strict=True),
            layouts_dir=arguments.layouts_dir,
            quarantine_tag=arguments.quarantine_tag,
            oras=arguments.oras,
        )
        return 0
    except (OSError, ReleaseVerificationError) as exc:
        print(f"quarantine layout push failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
