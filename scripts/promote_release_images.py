#!/usr/bin/env python3
"""Promote verified quarantine OCI digests to immutable official SemVer tags."""

from __future__ import annotations

import argparse
import json
import os
import re
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


MAX_TAG_LIST_BYTES = 4 * 1024 * 1024
MAX_REPOSITORY_TAGS = 100_000
OCI_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")


def _oras(oras: str, arguments: list[str]) -> str:
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
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise ReleaseVerificationError(f"ORAS invocation failed: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise ReleaseVerificationError(f"ORAS failed closed: {detail[:1000]}")
    return result.stdout


def _fetch_and_verify_index(
    oras: str,
    reference: str,
    expected_path: Path,
    expected_digest: str,
) -> None:
    """Fetch one required reference and prove its exact retained index bytes."""

    with tempfile.TemporaryDirectory(prefix="backupsheep-promote-") as temporary:
        fetched = Path(temporary) / "index.json"
        status = _oras(
            oras,
            ["manifest", "fetch", "--output", str(fetched), reference],
        )
        if status:
            raise ReleaseVerificationError(
                f"ORAS emitted unexpected manifest output for {reference}"
            )
        if _sha256_path(fetched) != expected_digest:
            raise ReleaseVerificationError(f"official reference has the wrong OCI digest: {reference}")
        if fetched.read_bytes() != expected_path.read_bytes():
            raise ReleaseVerificationError(f"official reference has different OCI index bytes: {reference}")


def _repository_tags(oras: str, repository: str) -> set[str]:
    """Return a bounded, authenticated tag inventory from successful JSON output."""

    raw = _oras(oras, ["repo", "tags", "--format", "json", repository])
    try:
        encoded = raw.encode("utf-8")
    except UnicodeError as exc:
        raise ReleaseVerificationError("ORAS returned a non-UTF-8 tag inventory") from exc
    if not encoded or len(encoded) > MAX_TAG_LIST_BYTES:
        raise ReleaseVerificationError("ORAS returned an invalid-size tag inventory")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError(f"duplicate JSON key: {key}")
            document[key] = value
        return document

    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ReleaseVerificationError("ORAS returned malformed tag inventory JSON") from exc
    if not isinstance(document, dict) or set(document) != {"tags"}:
        raise ReleaseVerificationError("ORAS tag inventory has an unexpected schema")
    tags = document["tags"]
    if not isinstance(tags, list) or len(tags) > MAX_REPOSITORY_TAGS:
        raise ReleaseVerificationError("ORAS tag inventory has an invalid tag set")
    if any(not isinstance(tag, str) or OCI_TAG_RE.fullmatch(tag) is None for tag in tags):
        raise ReleaseVerificationError("ORAS tag inventory contains a malformed tag")
    if len(set(tags)) != len(tags):
        raise ReleaseVerificationError("ORAS tag inventory contains duplicate tags")
    return set(tags)


def promote(policy: dict, manifest: dict, artifacts_dir: Path, oras: str) -> None:
    policy = _validate_policy(policy)
    validate_release(policy, manifest, artifacts_dir)
    tag = manifest["release"]["tag"]

    # Classify every destination before making the first write. The earlier
    # staging phase must already have made the exact digest readable in every
    # official repository. A successful, structured repository inventory is the
    # only evidence accepted for tag absence; registries commonly mask denied
    # reads as a generic 404, so an error string can never authorize a write.
    missing: set[str] = set()
    expected_indexes: dict[str, Path] = {}
    for image_name, image in manifest["images"].items():
        official_tag = f"{image['official_repository']}:{tag}"
        expected_path = _safe_artifact(
            artifacts_dir, image["oci_index"]["file"], f"{image_name} retained OCI index"
        )
        expected_indexes[image_name] = expected_path
        _fetch_and_verify_index(
            oras,
            image["official_reference"],
            expected_path,
            image["digest"],
        )
        tags = _repository_tags(oras, image["official_repository"])
        if tag not in tags:
            missing.add(image_name)
        else:
            _fetch_and_verify_index(
                oras,
                official_tag,
                expected_path,
                image["digest"],
            )

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
