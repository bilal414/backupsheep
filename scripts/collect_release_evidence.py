#!/usr/bin/env python3
"""Fetch an exact quarantine OCI index and its BuildKit provenance blobs."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
import tarfile
import tempfile
from pathlib import Path

from verify_release import (
    MAX_CONTROL_FILE_BYTES,
    RELEASE_IMAGE_NAMES,
    ReleaseVerificationError,
    _digest,
    _load_json,
    _parse_oci_index,
    _run_tool,
    _sha256_path,
    _validate_attestation_manifest,
    _validate_policy,
)


MAX_OCI_LAYOUT_BYTES = 16 * 1024 * 1024 * 1024
MAX_OCI_LAYOUT_MEMBERS = 200_000
_BLOB_MEMBER = re.compile(r"blobs/sha256/[0-9a-f]{64}\Z")


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


def _write_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


class _OCILayoutArchive:
    """Bounded, link-free reader for a BuildKit OCI layout tar archive."""

    def __init__(self, path: Path):
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > MAX_OCI_LAYOUT_BYTES
        ):
            raise ReleaseVerificationError("OCI layout must be a bounded regular non-symlink file")
        self._archive = tarfile.open(path, mode="r:")
        members = self._archive.getmembers()
        if len(members) > MAX_OCI_LAYOUT_MEMBERS:
            self.close()
            raise ReleaseVerificationError("OCI layout contains too many members")
        self._members: dict[str, tarfile.TarInfo] = {}
        for member in members:
            name = member.name.rstrip("/")
            if name in self._members:
                self.close()
                raise ReleaseVerificationError("OCI layout contains a duplicate member")
            allowed_directory = name in {"blobs", "blobs/sha256"} and member.isdir()
            allowed_file = (
                name in {"index.json", "oci-layout"} or _BLOB_MEMBER.fullmatch(name)
            ) and member.isfile()
            if not allowed_directory and not allowed_file:
                self.close()
                raise ReleaseVerificationError("OCI layout contains an unsafe member")
            self._members[name] = member

    def close(self) -> None:
        self._archive.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def read_member(self, name: str, *, maximum_bytes: int) -> bytes:
        member = self._members.get(name)
        if member is None or not member.isfile() or member.size > maximum_bytes:
            raise ReleaseVerificationError(f"OCI layout member is missing or too large: {name}")
        source = self._archive.extractfile(member)
        if source is None:
            raise ReleaseVerificationError(f"OCI layout member cannot be read: {name}")
        with source:
            payload = source.read(maximum_bytes + 1)
        if len(payload) != member.size or len(payload) > maximum_bytes:
            raise ReleaseVerificationError(f"OCI layout member size changed: {name}")
        return payload

    def blob(self, digest: str, *, maximum_bytes: int) -> bytes:
        digest = _digest(digest, "OCI blob digest")
        payload = self.read_member(
            f"blobs/sha256/{digest.removeprefix('sha256:')}",
            maximum_bytes=maximum_bytes,
        )
        actual = "sha256:" + hashlib.sha256(payload).hexdigest()
        if actual != digest:
            raise ReleaseVerificationError("OCI layout blob bytes do not match their digest")
        return payload


class _OCILayoutDirectory:
    """Link-free reader for a BuildKit OCI layout directory."""

    def __init__(self, path: Path):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ReleaseVerificationError("OCI layout path must be a real directory")
        self._path = path
        count = 0
        total_bytes = 0
        for directory, directory_names, file_names in os.walk(path, followlinks=False):
            for name in [*directory_names, *file_names]:
                count += 1
                if count > MAX_OCI_LAYOUT_MEMBERS:
                    raise ReleaseVerificationError("OCI layout contains too many members")
                candidate = Path(directory) / name
                relative = candidate.relative_to(path).as_posix()
                item = candidate.lstat()
                allowed_directory = relative in {"blobs", "blobs/sha256"} and stat.S_ISDIR(
                    item.st_mode
                )
                allowed_file = (
                    relative in {"index.json", "oci-layout"}
                    or _BLOB_MEMBER.fullmatch(relative)
                ) and stat.S_ISREG(item.st_mode)
                if stat.S_ISLNK(item.st_mode) or not (allowed_directory or allowed_file):
                    raise ReleaseVerificationError("OCI layout contains an unsafe member")
                if allowed_file:
                    if item.st_nlink != 1:
                        raise ReleaseVerificationError("OCI layout contains a linked file")
                    total_bytes += item.st_size
                    if total_bytes > MAX_OCI_LAYOUT_BYTES:
                        raise ReleaseVerificationError("OCI layout is too large")

    def close(self) -> None:
        return None

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        return None

    def read_member(self, name: str, *, maximum_bytes: int) -> bytes:
        if name not in {"index.json", "oci-layout"} and not _BLOB_MEMBER.fullmatch(name):
            raise ReleaseVerificationError("OCI layout member name is unsafe")
        path = self._path / name
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > maximum_bytes
        ):
            raise ReleaseVerificationError(f"OCI layout member is unsafe or too large: {name}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_size) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
            ):
                raise ReleaseVerificationError(f"OCI layout member changed while opening: {name}")
            with os.fdopen(descriptor, "rb") as source:
                descriptor = -1
                payload = source.read(maximum_bytes + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(payload) != metadata.st_size or len(payload) > maximum_bytes:
            raise ReleaseVerificationError(f"OCI layout member size changed: {name}")
        return payload

    def blob(self, digest: str, *, maximum_bytes: int) -> bytes:
        digest = _digest(digest, "OCI blob digest")
        payload = self.read_member(
            f"blobs/sha256/{digest.removeprefix('sha256:')}",
            maximum_bytes=maximum_bytes,
        )
        if "sha256:" + hashlib.sha256(payload).hexdigest() != digest:
            raise ReleaseVerificationError("OCI layout blob bytes do not match their digest")
        return payload


def collect_layout(
    *, policy: dict, artifacts_dir: Path, image_name: str, index_digest: str, layout: Path
) -> None:
    policy = _validate_policy(policy)
    if image_name not in policy["images"]:
        raise ReleaseVerificationError("image name is not authorized by policy")
    index_digest = _digest(index_digest, "index digest")
    predicate_type = policy["attestations"]["provenance_predicate_type"]
    artifacts_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    artifacts_dir = artifacts_dir.resolve(strict=True)

    with tempfile.TemporaryDirectory(prefix=f"backupsheep-{image_name}-oci-") as temporary:
        temporary_dir = Path(temporary)
        resolved_layout = layout.resolve(strict=True)
        layout_reader = (
            _OCILayoutDirectory(resolved_layout)
            if resolved_layout.is_dir()
            else _OCILayoutArchive(resolved_layout)
        )
        with layout_reader as archive:
            root_path = temporary_dir / "layout-index.json"
            _write_private(
                root_path,
                archive.read_member("index.json", maximum_bytes=MAX_CONTROL_FILE_BYTES),
            )
            root = _load_json(root_path, maximum_bytes=MAX_CONTROL_FILE_BYTES)
            manifests = root.get("manifests") if isinstance(root, dict) else None
            if not isinstance(manifests, list) or len(manifests) != 1:
                raise ReleaseVerificationError("OCI layout root must identify exactly one image index")
            root_descriptor = manifests[0]
            if (
                not isinstance(root_descriptor, dict)
                or root_descriptor.get("digest") != index_digest
            ):
                raise ReleaseVerificationError("OCI layout root does not bind the requested digest")

            index_bytes = archive.blob(index_digest, maximum_bytes=MAX_CONTROL_FILE_BYTES)
            fetched_index = temporary_dir / "index.json"
            _write_private(fetched_index, index_bytes)
            index_document = _load_json(fetched_index, maximum_bytes=MAX_CONTROL_FILE_BYTES)
            _, attestation_digests = _parse_oci_index(
                index_document, policy["platforms"], f"{image_name} OCI index"
            )
            _atomic_copy(fetched_index, artifacts_dir / "oci" / f"{image_name}.index.json")

            for platform in policy["platforms"]:
                slug = platform.replace("/", "-")
                attestation_digest = attestation_digests[platform]
                fetched_attestation = temporary_dir / f"{slug}.attestation.json"
                _write_private(
                    fetched_attestation,
                    archive.blob(attestation_digest, maximum_bytes=MAX_CONTROL_FILE_BYTES),
                )
                attestation_document = _load_json(
                    fetched_attestation, maximum_bytes=MAX_CONTROL_FILE_BYTES
                )
                blob_digest = _validate_attestation_manifest(
                    attestation_document,
                    predicate_type,
                    f"{image_name} {platform} attestation manifest",
                )
                fetched_provenance = temporary_dir / f"{slug}.intoto.json"
                _write_private(
                    fetched_provenance,
                    archive.blob(blob_digest, maximum_bytes=MAX_CONTROL_FILE_BYTES),
                )
                _load_json(fetched_provenance, maximum_bytes=MAX_CONTROL_FILE_BYTES)
                _atomic_copy(
                    fetched_attestation,
                    artifacts_dir / "oci" / f"{image_name}-{slug}.attestation.json",
                )
                _atomic_copy(
                    fetched_provenance,
                    artifacts_dir / "provenance" / f"{image_name}-{slug}.intoto.json",
                )


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
    parser.add_argument("--image", choices=RELEASE_IMAGE_NAMES, required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--oras", default="oras")
    parser.add_argument("--oci-layout", type=Path)
    arguments = parser.parse_args(argv)
    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        if arguments.oci_layout is None:
            collect(
                policy=policy,
                artifacts_dir=arguments.artifacts_dir,
                image_name=arguments.image,
                index_digest=arguments.digest,
                oras=arguments.oras,
            )
        else:
            collect_layout(
                policy=policy,
                artifacts_dir=arguments.artifacts_dir,
                image_name=arguments.image,
                index_digest=arguments.digest,
                layout=arguments.oci_layout,
            )
        return 0
    except (OSError, ReleaseVerificationError) as exc:
        print(f"release evidence collection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
