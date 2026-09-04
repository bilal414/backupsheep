#!/usr/bin/env python3
"""Export and verify the exact protected evidence inventory used by the signer."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from build_release_descriptor import MAX_DESCRIPTOR_BYTES, validate_descriptor_payload
from verify_release import (
    MAX_CONTROL_FILE_BYTES,
    MAX_EVIDENCE_FILE_BYTES,
    ReleaseVerificationError,
    _load_json,
    _mapping,
    _safe_artifact,
    _sha256_path,
    validate_release,
)


POLICY_FILENAME = "release-policy.json"
MANIFEST_FILENAME = "release-manifest.json"


def _manifest_files(value: Any) -> set[str]:
    files: set[str] = set()

    def visit(item: Any, label: str) -> None:
        if isinstance(item, dict):
            if "file" in item:
                filename = item["file"]
                if not isinstance(filename, str) or not filename:
                    raise ReleaseVerificationError(f"{label}.file is not a filename")
                pure = PurePosixPath(filename)
                if (
                    pure.is_absolute()
                    or not pure.parts
                    or any(part in {"", ".", ".."} for part in pure.parts)
                    or "\\" in filename
                ):
                    raise ReleaseVerificationError(f"{label}.file is not a safe relative path")
                if filename in files:
                    raise ReleaseVerificationError(
                        f"protected evidence references {filename} more than once"
                    )
                files.add(filename)
            for key, nested in item.items():
                visit(nested, f"{label}.{key}")
        elif isinstance(item, list):
            for position, nested in enumerate(item):
                visit(nested, f"{label}[{position}]")

    visit(value, "release manifest")
    return files


def _expected_files(policy: dict[str, Any], manifest: dict[str, Any]) -> set[str]:
    descriptor = policy["consumer"]["descriptor_filename"]
    if descriptor != manifest["consumer"]["descriptor_filename"]:
        raise ReleaseVerificationError("release descriptor filename differs from policy")
    return {
        POLICY_FILENAME,
        MANIFEST_FILENAME,
        descriptor,
        *_manifest_files(manifest),
    }


def _validate_root(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ReleaseVerificationError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseVerificationError(f"{label} must be a real directory")
    return path.resolve(strict=True)


def _expected_directories(files: set[str]) -> set[str]:
    directories: set[str] = set()
    for filename in files:
        parent = PurePosixPath(filename).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def _actual_inventory(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    for candidate in root.rglob("*"):
        metadata = candidate.lstat()
        relative = candidate.relative_to(root).as_posix()
        if stat.S_ISLNK(metadata.st_mode):
            raise ReleaseVerificationError(
                f"protected evidence contains a symbolic link: {relative}"
            )
        if stat.S_ISDIR(metadata.st_mode):
            directories.add(relative)
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ReleaseVerificationError(
                f"protected evidence contains a non-regular or linked file: {relative}"
            )
        if metadata.st_size > MAX_EVIDENCE_FILE_BYTES:
            raise ReleaseVerificationError(f"protected evidence file is too large: {relative}")
        files.add(relative)
    return files, directories


def _validate_descriptor(
    policy: dict[str, Any], manifest: dict[str, Any], root: Path
) -> None:
    manifest_path = _safe_artifact(root, MANIFEST_FILENAME, "protected release manifest")
    descriptor_path = _safe_artifact(
        root,
        policy["consumer"]["descriptor_filename"],
        "protected release descriptor",
    )
    if descriptor_path.stat().st_size > MAX_DESCRIPTOR_BYTES:
        raise ReleaseVerificationError("protected release descriptor is too large")
    validate_descriptor_payload(
        policy,
        manifest,
        _sha256_path(manifest_path),
        descriptor_path.read_bytes(),
    )


def verify(policy_path: Path, artifacts_dir: Path) -> set[str]:
    root = _validate_root(artifacts_dir, "protected evidence root")
    policy = _mapping(
        _load_json(policy_path, maximum_bytes=MAX_CONTROL_FILE_BYTES),
        "release policy",
    )
    archived_policy = _safe_artifact(root, POLICY_FILENAME, "protected release policy")
    if archived_policy.read_bytes() != policy_path.read_bytes():
        raise ReleaseVerificationError("protected release policy differs from trusted source")
    manifest = _mapping(
        _load_json(
            _safe_artifact(root, MANIFEST_FILENAME, "protected release manifest"),
            maximum_bytes=MAX_CONTROL_FILE_BYTES,
        ),
        "release manifest",
    )
    validate_release(policy, manifest, root)
    _validate_descriptor(policy, manifest, root)
    expected = _expected_files(policy, manifest)
    actual, actual_directories = _actual_inventory(root)
    expected_directories = _expected_directories(expected)
    if actual != expected or actual_directories != expected_directories:
        raise ReleaseVerificationError(
            "protected evidence does not have the exact manifest-derived inventory "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)}, "
            f"missing_directories={sorted(expected_directories - actual_directories)}, "
            f"unknown_directories={sorted(actual_directories - expected_directories)})"
        )
    return expected


def _copy_private(source: Path, destination: Path) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        destination,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            total = 0
            while True:
                chunk = input_stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_EVIDENCE_FILE_BYTES:
                    raise ReleaseVerificationError(
                        f"protected evidence source is too large: {source.name}"
                    )
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def export(policy_path: Path, source_dir: Path, output_dir: Path) -> set[str]:
    source = _validate_root(source_dir, "protected evidence source")
    if output_dir.exists() or output_dir.is_symlink():
        raise ReleaseVerificationError("protected evidence output must not pre-exist")
    parent = _validate_root(output_dir.parent, "protected evidence output parent")
    output = parent / output_dir.name

    policy = _mapping(
        _load_json(policy_path, maximum_bytes=MAX_CONTROL_FILE_BYTES),
        "release policy",
    )
    source_policy = _safe_artifact(source, POLICY_FILENAME, "candidate release policy")
    if source_policy.read_bytes() != policy_path.read_bytes():
        raise ReleaseVerificationError("candidate release policy differs from trusted source")
    manifest = _mapping(
        _load_json(
            _safe_artifact(source, MANIFEST_FILENAME, "protected release manifest"),
            maximum_bytes=MAX_CONTROL_FILE_BYTES,
        ),
        "release manifest",
    )
    validate_release(policy, manifest, source)
    _validate_descriptor(policy, manifest, source)
    expected = _expected_files(policy, manifest)

    output.mkdir(mode=0o700)
    for filename in sorted(expected):
        source_path = (
            policy_path
            if filename == POLICY_FILENAME
            else _safe_artifact(source, filename, f"protected evidence {filename}")
        )
        _copy_private(source_path, output.joinpath(*PurePosixPath(filename).parts))
    verify(policy_path, output)
    return expected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    export_parser = subparsers.add_parser("export")
    export_parser.add_argument("--policy", type=Path, required=True)
    export_parser.add_argument("--source-dir", type=Path, required=True)
    export_parser.add_argument("--output-dir", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--policy", type=Path, required=True)
    verify_parser.add_argument("--artifacts-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "export":
            export(arguments.policy, arguments.source_dir, arguments.output_dir)
        else:
            verify(arguments.policy, arguments.artifacts_dir)
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, ReleaseVerificationError) as exc:
        print(f"protected release evidence operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
