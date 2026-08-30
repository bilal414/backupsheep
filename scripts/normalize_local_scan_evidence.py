#!/usr/bin/env python3
"""Bind local OCI-layout scanner output to an exact retained child manifest."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from build_release_manifest import _platform_digests, _write_json
from verify_release import (
    CONSUMER_VERIFIER_IMAGE_NAME,
    MAX_CONTROL_FILE_BYTES,
    MAX_EVIDENCE_FILE_BYTES,
    RELEASE_IMAGE_NAMES,
    ReleaseVerificationError,
    _digest,
    _load_json,
    _mapping,
    _validate_policy,
)


def _decoded_json(value: object, label: str) -> tuple[bytes, dict]:
    if not isinstance(value, str) or not value:
        raise ReleaseVerificationError(f"{label} is missing")
    try:
        payload = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ReleaseVerificationError(f"{label} is not canonical base64") from exc
    if len(payload) > MAX_CONTROL_FILE_BYTES:
        raise ReleaseVerificationError(f"{label} is too large")
    with tempfile.TemporaryDirectory(prefix="backupsheep-scan-binding-") as temporary:
        path = Path(temporary) / "value.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
        document = _load_json(path, maximum_bytes=MAX_CONTROL_FILE_BYTES)
    return payload, _mapping(document, label)


def normalize(
    *,
    policy: dict,
    index_path: Path | None,
    image_name: str,
    platform: str,
    syft_path: Path,
    trivy_path: Path,
) -> None:
    policy = _validate_policy(policy)
    if platform not in policy["platforms"]:
        raise ReleaseVerificationError("the scan image or platform is not authorized")
    expected_config_digest: str | None = None
    if image_name == CONSUMER_VERIFIER_IMAGE_NAME:
        if index_path is not None:
            raise ReleaseVerificationError("the consumer verifier scan must not accept a release OCI index")
        verifier = policy["consumer"]["cosign_image"]
        child = verifier["platforms"][platform]
        child_digest = _digest(child["manifest_digest"], "consumer verifier child digest")
        expected_config_digest = _digest(
            child["config_digest"], "consumer verifier config digest"
        )
        reference = f"{verifier['repository']}@{child_digest}"
    else:
        if image_name not in policy["images"] or index_path is None:
            raise ReleaseVerificationError("the release scan requires an authorized image and OCI index")
        child_digest = _digest(
            _platform_digests(index_path, policy["platforms"])[platform],
            "child manifest digest",
        )
        reference = f"{policy['images'][image_name]['quarantine_repository']}@{child_digest}"

    syft = _mapping(
        _load_json(syft_path, maximum_bytes=MAX_EVIDENCE_FILE_BYTES), "Syft report"
    )
    source = _mapping(syft.get("source"), "Syft source")
    if source.get("type") != "image":
        raise ReleaseVerificationError("Syft did not scan an image")
    metadata = _mapping(source.get("metadata"), "Syft source metadata")
    if metadata.get("manifestDigest") != child_digest:
        raise ReleaseVerificationError("Syft did not scan the retained child manifest")
    manifest_bytes, manifest = _decoded_json(metadata.get("manifest"), "Syft embedded manifest")
    if "sha256:" + hashlib.sha256(manifest_bytes).hexdigest() != child_digest:
        raise ReleaseVerificationError("Syft embedded manifest has the wrong digest")
    config = _mapping(manifest.get("config"), "OCI child config")
    config_digest = _digest(config.get("digest"), "OCI child config digest")
    if expected_config_digest is not None and config_digest != expected_config_digest:
        raise ReleaseVerificationError("consumer verifier config does not match the policy trust record")
    if metadata.get("imageID") != config_digest:
        raise ReleaseVerificationError("Syft image ID does not match the child config")
    manifest_layers = manifest.get("layers")
    if not isinstance(manifest_layers, list) or not manifest_layers:
        raise ReleaseVerificationError("OCI child manifest has no layers")
    compressed_layers = [
        _digest(_mapping(layer, "OCI child layer").get("digest"), "OCI child layer digest")
        for layer in manifest_layers
    ]

    trivy = _mapping(
        _load_json(trivy_path, maximum_bytes=MAX_EVIDENCE_FILE_BYTES), "Trivy report"
    )
    trivy_metadata = _mapping(trivy.get("Metadata"), "Trivy metadata")
    if trivy_metadata.get("ImageID") != config_digest:
        raise ReleaseVerificationError("Trivy image ID does not match the child config")
    trivy_layers = trivy_metadata.get("Layers")
    if not isinstance(trivy_layers, list) or [
        _digest(_mapping(layer, "Trivy layer").get("Digest"), "Trivy layer digest")
        for layer in trivy_layers
    ] != compressed_layers:
        raise ReleaseVerificationError("Trivy layers do not match the retained child manifest")

    metadata["userInput"] = reference
    trivy["ArtifactName"] = reference
    _write_json(syft_path, syft)
    _write_json(trivy_path, trivy)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--index", type=Path)
    parser.add_argument(
        "--image",
        choices=(*RELEASE_IMAGE_NAMES, CONSUMER_VERIFIER_IMAGE_NAME),
        required=True,
    )
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), required=True)
    parser.add_argument("--syft", type=Path, required=True)
    parser.add_argument("--trivy", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        normalize(
            policy=policy,
            index_path=arguments.index,
            image_name=arguments.image,
            platform=arguments.platform,
            syft_path=arguments.syft,
            trivy_path=arguments.trivy,
        )
        return 0
    except (OSError, ReleaseVerificationError, json.JSONDecodeError) as exc:
        print(f"local scan evidence normalization failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
