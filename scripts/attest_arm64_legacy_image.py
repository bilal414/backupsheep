#!/usr/bin/env python3
"""Create or verify a strict evidence record for the native arm64 legacy image archive."""

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO


MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_JSON_MEMBER_BYTES = 4 * 1024 * 1024
MAX_TAR_MEMBERS = 512
MAX_LAYER_BYTES = 1024 * 1024 * 1024
MAX_UNCOMPRESSED_LAYER_BYTES = 2 * 1024 * 1024 * 1024
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$")
IMAGE_REF_RE = re.compile(
    r"^[a-z0-9][a-z0-9._/-]{0,199}:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)

EXPECTED_LABELS = {
    "com.backupsheep.rabbitmq.base-index-digest": (
        "sha256:87178a0ee3e2f52980ba356d38646ed1056705ff2d5ff281f8965456eaa0c1e3"
    ),
    "com.backupsheep.rabbitmq.enabled-plugins": "none",
    "com.backupsheep.rabbitmq.erlang-donor-index-digest": (
        "sha256:f9007e3e435761bd7f88aafa4bfab20fd4107baa88e3ff45e935ef2aa3e892d5"
    ),
    "com.backupsheep.rabbitmq.erlang-runtime-version": "26.2.5.21",
    "com.backupsheep.rabbitmq.openssl-donor-index-digest": (
        "sha256:f3aa266b9f3ee3d06c6658804aa3b8e4474bfc18880dcc20f469995a728c298b"
    ),
    "com.backupsheep.rabbitmq.openssl-runtime-version": "3.5.8",
    "com.backupsheep.rabbitmq.runtime-generation": (
        "3.13.7-otp26.2.5.21-openssl3.5.8-v3"
    ),
}


class EvidenceError(ValueError):
    """Raised when the transferred image archive is not the exact expected object."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("JSON contains a duplicate key")
        result[key] = value
    return result


def _load_json_bytes(payload: bytes, label: str) -> Any:
    try:
        return json.loads(payload, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{label} is not strict UTF-8 JSON") from exc


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"{label} must be a non-empty string")
    return value


def _regular_file(path: Path, maximum_bytes: int, label: str) -> os.stat_result:
    try:
        details = path.lstat()
    except OSError as exc:
        raise EvidenceError(f"{label} is unavailable") from exc
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise EvidenceError(f"{label} must be a single-link regular file")
    if details.st_size <= 0 or details.st_size > maximum_bytes:
        raise EvidenceError(f"{label} size is outside the accepted boundary")
    return details


def _sha256_stream(stream: BinaryIO, maximum_bytes: int, label: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum_bytes:
            raise EvidenceError(f"{label} exceeds the accepted size boundary")
        digest.update(chunk)
    return f"sha256:{digest.hexdigest()}", total


def _sha256_path(path: Path, maximum_bytes: int, label: str) -> tuple[str, int]:
    with path.open("rb") as stream:
        return _sha256_stream(stream, maximum_bytes, label)


def _safe_member_name(name: str) -> str:
    if not name or "\\" in name or any(ord(character) < 32 for character in name):
        raise EvidenceError("image archive contains an unsafe member name")
    pure = PurePosixPath(name)
    if pure.is_absolute() or name != pure.as_posix() or ".." in pure.parts:
        raise EvidenceError("image archive contains an unsafe member path")
    return name


def _member_bytes(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    maximum_bytes: int,
    label: str,
) -> bytes:
    if not member.isfile() or member.size < 0 or member.size > maximum_bytes:
        raise EvidenceError(f"{label} is not an accepted regular archive member")
    stream = archive.extractfile(member)
    if stream is None:
        raise EvidenceError(f"{label} cannot be read")
    payload = stream.read(maximum_bytes + 1)
    if len(payload) != member.size or len(payload) > maximum_bytes:
        raise EvidenceError(f"{label} size does not match its archive header")
    return payload


def _member_digest(
    archive: tarfile.TarFile, member: tarfile.TarInfo, label: str
) -> tuple[str, int]:
    if not member.isfile() or member.size < 0 or member.size > MAX_LAYER_BYTES:
        raise EvidenceError(f"{label} is not an accepted regular archive member")
    stream = archive.extractfile(member)
    if stream is None:
        raise EvidenceError(f"{label} cannot be read")
    digest, size = _sha256_stream(stream, MAX_LAYER_BYTES, label)
    if size != member.size:
        raise EvidenceError(f"{label} size does not match its archive header")
    return digest, size


def _layer_diff_id(
    archive: tarfile.TarFile, member: tarfile.TarInfo, label: str
) -> str:
    stream = archive.extractfile(member)
    if stream is None:
        raise EvidenceError(f"{label} cannot be read")
    magic = stream.read(2)
    stream = archive.extractfile(member)
    if stream is None:
        raise EvidenceError(f"{label} cannot be reopened")
    if magic == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=stream, mode="rb") as expanded:
                digest, _ = _sha256_stream(
                    expanded, MAX_UNCOMPRESSED_LAYER_BYTES, f"expanded {label}"
                )
                return digest
        except (EOFError, OSError) as exc:
            raise EvidenceError(f"{label} has invalid gzip content") from exc
    digest, _ = _sha256_stream(stream, MAX_UNCOMPRESSED_LAYER_BYTES, label)
    return digest


def _blob_member_name(digest: str) -> str:
    if not SHA256_RE.fullmatch(digest):
        raise EvidenceError("OCI descriptor digest is malformed")
    return f"blobs/sha256/{digest.removeprefix('sha256:')}"


def _validate_descriptor_blob(
    descriptor: dict[str, Any],
    members: dict[str, tarfile.TarInfo],
    member_records: dict[str, dict[str, Any]],
    label: str,
) -> str:
    digest = _string(descriptor.get("digest"), f"{label} digest")
    member_name = _blob_member_name(digest)
    record = member_records.get(member_name)
    if record is None or member_name not in members:
        raise EvidenceError(f"{label} blob is absent")
    size = descriptor.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size != record["size"]:
        raise EvidenceError(f"{label} size does not match its descriptor")
    if record["sha256"] != digest:
        raise EvidenceError(f"{label} digest does not match its blob")
    return member_name


def _oci_binding(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    member_records: dict[str, dict[str, Any]],
    expected_image_id: str,
    config_digest: str,
    config_size: int,
    layer_records: list[dict[str, Any]],
) -> dict[str, Any] | None:
    has_index = "index.json" in members
    has_layout = "oci-layout" in members
    if has_index != has_layout:
        raise EvidenceError("OCI archive metadata is incomplete")
    if not has_index:
        if expected_image_id != config_digest:
            raise EvidenceError("classic Docker image ID is not the config digest")
        return None

    layout = _mapping(
        _load_json_bytes(
            _member_bytes(
                archive, members["oci-layout"], MAX_JSON_MEMBER_BYTES, "OCI layout"
            ),
            "OCI layout",
        ),
        "OCI layout",
    )
    if layout != {"imageLayoutVersion": "1.0.0"}:
        raise EvidenceError("OCI layout version is not supported")
    index = _mapping(
        _load_json_bytes(
            _member_bytes(
                archive, members["index.json"], MAX_JSON_MEMBER_BYTES, "OCI index"
            ),
            "OCI index",
        ),
        "OCI index",
    )
    if index.get("schemaVersion") != 2:
        raise EvidenceError("OCI index schema is not supported")
    descriptors = _list(index.get("manifests"), "OCI index manifests")
    matching = [
        _mapping(descriptor, "OCI index descriptor")
        for descriptor in descriptors
        if isinstance(descriptor, dict) and descriptor.get("digest") == expected_image_id
    ]
    if len(matching) != 1:
        raise EvidenceError("Docker image ID is not uniquely bound by the OCI index")
    top_descriptor = matching[0]
    top_member = _validate_descriptor_blob(
        top_descriptor, members, member_records, "OCI top-level descriptor"
    )
    top_payload = _mapping(
        _load_json_bytes(
            _member_bytes(
                archive,
                members[top_member],
                MAX_JSON_MEMBER_BYTES,
                "OCI top-level descriptor",
            ),
            "OCI top-level descriptor",
        ),
        "OCI top-level descriptor",
    )

    media_type = top_descriptor.get("mediaType")
    if media_type == "application/vnd.oci.image.index.v1+json":
        child_descriptors = _list(
            top_payload.get("manifests"), "OCI image-index manifests"
        )
        platform_matches: list[dict[str, Any]] = []
        for raw_descriptor in child_descriptors:
            descriptor = _mapping(raw_descriptor, "OCI image-index descriptor")
            platform = descriptor.get("platform")
            if isinstance(platform, dict) and platform.get("os") == "linux" and platform.get(
                "architecture"
            ) == "arm64":
                platform_matches.append(descriptor)
        if len(platform_matches) != 1:
            raise EvidenceError("OCI image index does not contain one arm64 image")
        image_descriptor = platform_matches[0]
    elif media_type in {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }:
        image_descriptor = top_descriptor
    else:
        raise EvidenceError("OCI top-level descriptor media type is unsupported")

    image_manifest_member = _validate_descriptor_blob(
        image_descriptor, members, member_records, "OCI arm64 image manifest"
    )
    image_manifest = _mapping(
        _load_json_bytes(
            _member_bytes(
                archive,
                members[image_manifest_member],
                MAX_JSON_MEMBER_BYTES,
                "OCI arm64 image manifest",
            ),
            "OCI arm64 image manifest",
        ),
        "OCI arm64 image manifest",
    )
    if image_manifest.get("schemaVersion") != 2:
        raise EvidenceError("OCI image manifest schema is unsupported")
    config_descriptor = _mapping(
        image_manifest.get("config"), "OCI image config descriptor"
    )
    if config_descriptor.get("digest") != config_digest or config_descriptor.get(
        "size"
    ) != config_size:
        raise EvidenceError("OCI image manifest does not bind the expected config")
    oci_layers = _list(image_manifest.get("layers"), "OCI image layers")
    if len(oci_layers) != len(layer_records):
        raise EvidenceError("OCI and Docker layer counts differ")
    for index_number, (raw_descriptor, layer_record) in enumerate(
        zip(oci_layers, layer_records, strict=True)
    ):
        descriptor = _mapping(raw_descriptor, f"OCI layer {index_number}")
        if descriptor.get("digest") != layer_record["sha256"] or descriptor.get(
            "size"
        ) != layer_record["size"]:
            raise EvidenceError("OCI and Docker layer identities differ")
    return {
        "image_manifest_member": image_manifest_member,
        "image_manifest_sha256": image_descriptor["digest"],
        "top_level_member": top_member,
        "top_level_sha256": top_descriptor["digest"],
    }


def inspect_archive(
    archive_path: Path,
    *,
    expected_image_id: str,
    expected_image_ref: str,
    expected_owner: str,
    source_sha: str,
) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(expected_image_id):
        raise EvidenceError("expected image ID is malformed")
    if not IMAGE_REF_RE.fullmatch(expected_image_ref) or ".." in expected_image_ref:
        raise EvidenceError("expected image reference is unsafe")
    if not OWNER_RE.fullmatch(expected_owner):
        raise EvidenceError("expected ownership value is unsafe")
    if not SOURCE_SHA_RE.fullmatch(source_sha):
        raise EvidenceError("source SHA is malformed")

    before = _regular_file(archive_path, MAX_ARCHIVE_BYTES, "image archive")
    try:
        archive = tarfile.open(archive_path, mode="r:")
    except (OSError, tarfile.TarError) as exc:
        raise EvidenceError("image archive is not an uncompressed tar file") from exc
    with archive:
        tar_members = archive.getmembers()
        if not tar_members or len(tar_members) > MAX_TAR_MEMBERS:
            raise EvidenceError("image archive member count is outside the accepted boundary")
        members: dict[str, tarfile.TarInfo] = {}
        for member in tar_members:
            name = _safe_member_name(member.name)
            if name in members:
                raise EvidenceError("image archive contains duplicate member names")
            if not (member.isfile() or member.isdir()):
                raise EvidenceError("image archive contains a link or special member")
            members[name] = member
        manifest_member = members.get("manifest.json")
        if manifest_member is None:
            raise EvidenceError("Docker manifest.json is absent")

        member_records: dict[str, dict[str, Any]] = {}
        for name, member in sorted(members.items()):
            if not member.isfile():
                continue
            digest, size = _member_digest(archive, member, f"archive member {name}")
            member_records[name] = {"member": name, "sha256": digest, "size": size}
            if name.startswith("blobs/sha256/"):
                expected_blob_digest = f"sha256:{name.removeprefix('blobs/sha256/')}"
                if not SHA256_RE.fullmatch(expected_blob_digest) or digest != expected_blob_digest:
                    raise EvidenceError("OCI blob path does not match its content digest")

        manifest_payload = _member_bytes(
            archive, manifest_member, MAX_JSON_MEMBER_BYTES, "Docker manifest"
        )
        docker_manifest = _list(
            _load_json_bytes(manifest_payload, "Docker manifest"), "Docker manifest"
        )
        if len(docker_manifest) != 1:
            raise EvidenceError("Docker archive must contain exactly one image")
        manifest_entry = _mapping(docker_manifest[0], "Docker manifest entry")
        if set(manifest_entry) != {"Config", "RepoTags", "Layers"}:
            raise EvidenceError("Docker manifest entry shape is not canonical")
        repo_tags = _list(manifest_entry.get("RepoTags"), "Docker repository tags")
        if repo_tags != [expected_image_ref]:
            raise EvidenceError("Docker archive repository tag is not the expected exact tag")

        config_name = _safe_member_name(
            _string(manifest_entry.get("Config"), "Docker config member")
        )
        config_member = members.get(config_name)
        if config_member is None:
            raise EvidenceError("Docker config member is absent")
        config_payload = _member_bytes(
            archive, config_member, MAX_JSON_MEMBER_BYTES, "Docker image config"
        )
        config_digest = f"sha256:{hashlib.sha256(config_payload).hexdigest()}"
        config_record = member_records.get(config_name)
        if config_record is None or config_record["sha256"] != config_digest:
            raise EvidenceError("Docker image config digest is inconsistent")
        config_basename = PurePosixPath(config_name).name.removesuffix(".json")
        if config_basename != config_digest.removeprefix("sha256:"):
            raise EvidenceError("Docker config member name does not match its digest")
        config = _mapping(_load_json_bytes(config_payload, "Docker image config"), "Docker image config")
        if config.get("os") != "linux" or config.get("architecture") != "arm64":
            raise EvidenceError("Docker image config is not linux/arm64")
        runtime_config = _mapping(config.get("config"), "Docker runtime config")
        if runtime_config.get("User") != "999:999":
            raise EvidenceError("Docker image runtime user is not 999:999")
        labels = _mapping(runtime_config.get("Labels"), "Docker image labels")
        required_labels = dict(EXPECTED_LABELS)
        required_labels["com.backupsheep.ci-run"] = expected_owner
        for label, value in required_labels.items():
            if labels.get(label) != value:
                raise EvidenceError("Docker image security label contract differs")
        environment = _list(runtime_config.get("Env"), "Docker image environment")
        if environment.count("LD_LIBRARY_PATH=/opt/openssl/lib") != 1:
            raise EvidenceError("Docker image OpenSSL loader environment differs")

        layer_names = _list(manifest_entry.get("Layers"), "Docker layers")
        if not layer_names or len(layer_names) > 128 or len(layer_names) != len(set(layer_names)):
            raise EvidenceError("Docker layer list is empty, duplicate, or excessive")
        rootfs = _mapping(config.get("rootfs"), "Docker rootfs")
        diff_ids = _list(rootfs.get("diff_ids"), "Docker rootfs diff IDs")
        if rootfs.get("type") != "layers" or len(diff_ids) != len(layer_names):
            raise EvidenceError("Docker rootfs does not bind every layer")
        layer_records: list[dict[str, Any]] = []
        for index_number, (raw_name, raw_diff_id) in enumerate(
            zip(layer_names, diff_ids, strict=True)
        ):
            name = _safe_member_name(_string(raw_name, f"Docker layer {index_number}"))
            member = members.get(name)
            record = member_records.get(name)
            diff_id = _string(raw_diff_id, f"Docker layer {index_number} diff ID")
            if member is None or record is None or not SHA256_RE.fullmatch(diff_id):
                raise EvidenceError("Docker layer identity is incomplete")
            if _layer_diff_id(archive, member, f"Docker layer {index_number}") != diff_id:
                raise EvidenceError("Docker layer content does not match its rootfs diff ID")
            layer_records.append(
                {
                    "diff_id": diff_id,
                    "member": name,
                    "position": index_number,
                    "sha256": record["sha256"],
                    "size": record["size"],
                }
            )

        oci = _oci_binding(
            archive,
            members,
            member_records,
            expected_image_id,
            config_digest,
            len(config_payload),
            layer_records,
        )

    after = _regular_file(archive_path, MAX_ARCHIVE_BYTES, "image archive")
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise EvidenceError("image archive changed while it was inspected")
    archive_digest, archive_size = _sha256_path(
        archive_path, MAX_ARCHIVE_BYTES, "image archive"
    )
    if archive_size != before.st_size:
        raise EvidenceError("image archive size changed while it was hashed")
    return {
        "archive": {"sha256": archive_digest, "size": archive_size},
        "config": {
            "member": config_name,
            "sha256": config_digest,
            "size": len(config_payload),
        },
        "docker_image_id": expected_image_id,
        "docker_manifest": {
            "member": "manifest.json",
            "sha256": f"sha256:{hashlib.sha256(manifest_payload).hexdigest()}",
            "size": len(manifest_payload),
        },
        "image_reference": expected_image_ref,
        "layers": layer_records,
        "members": list(member_records.values()),
        "oci": oci,
        "ownership": expected_owner,
        "platform": "linux/arm64",
        "schema_version": 1,
        "source_sha": source_sha,
    }


def _write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    parent = path.parent
    try:
        parent_details = parent.lstat()
    except OSError as exc:
        raise EvidenceError("evidence parent directory is unavailable") from exc
    if not stat.S_ISDIR(parent_details.st_mode) or stat.S_ISLNK(parent_details.st_mode):
        raise EvidenceError("evidence parent must be a real directory")
    payload = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_EVIDENCE_BYTES:
        raise EvidenceError("evidence exceeds its size boundary")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise EvidenceError("refusing to replace the evidence output") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        try:
            os.chmod(path, 0o600, follow_symlinks=False)
        except OSError:
            pass


def attest(arguments: argparse.Namespace) -> str:
    evidence = inspect_archive(
        arguments.archive,
        expected_image_id=arguments.expected_image_id,
        expected_image_ref=arguments.expected_image_ref,
        expected_owner=arguments.expected_owner,
        source_sha=arguments.source_sha,
    )
    _write_evidence(arguments.evidence, evidence)
    return evidence["config"]["sha256"]


def _verified_evidence(arguments: argparse.Namespace) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(arguments.expected_archive_sha256):
        raise EvidenceError("expected archive SHA-256 is malformed")
    if not SHA256_RE.fullmatch(arguments.expected_evidence_sha256):
        raise EvidenceError("expected evidence SHA-256 is malformed")
    evidence_details = _regular_file(
        arguments.evidence, MAX_EVIDENCE_BYTES, "evidence file"
    )
    evidence_digest, evidence_size = _sha256_path(
        arguments.evidence, MAX_EVIDENCE_BYTES, "evidence file"
    )
    if evidence_digest != arguments.expected_evidence_sha256 or evidence_size != evidence_details.st_size:
        raise EvidenceError("evidence file does not match its producer job digest")
    with arguments.evidence.open("rb") as stream:
        recorded = _mapping(_load_json_bytes(stream.read(), "evidence file"), "evidence file")
    actual = inspect_archive(
        arguments.archive,
        expected_image_id=arguments.expected_image_id,
        expected_image_ref=arguments.expected_image_ref,
        expected_owner=arguments.expected_owner,
        source_sha=arguments.source_sha,
    )
    if actual["archive"]["sha256"] != arguments.expected_archive_sha256:
        raise EvidenceError("image archive does not match its producer job digest")
    if recorded != actual:
        raise EvidenceError("evidence does not exactly describe the downloaded image archive")
    return actual


def verify(arguments: argparse.Namespace) -> str:
    return _verified_evidence(arguments)["config"]["sha256"]


def _retag_archive(source_path: Path, target_path: Path, image_ref: str) -> None:
    if not IMAGE_REF_RE.fullmatch(image_ref) or ".." in image_ref:
        raise EvidenceError("target image reference is unsafe")
    if target_path.exists() or target_path.is_symlink():
        raise EvidenceError("retagged archive output must not pre-exist")
    parent_details = target_path.parent.lstat()
    if not stat.S_ISDIR(parent_details.st_mode) or stat.S_ISLNK(parent_details.st_mode):
        raise EvidenceError("retagged archive parent must be a real directory")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target_path, flags, 0o600)
    try:
        with tarfile.open(source_path, mode="r:") as source, os.fdopen(
            descriptor, "wb"
        ) as target_stream:
            descriptor = -1
            with tarfile.open(
                fileobj=target_stream, mode="w", format=tarfile.PAX_FORMAT
            ) as target:
                for member in source.getmembers():
                    copied = copy.copy(member)
                    if member.name == "manifest.json":
                        manifest = _list(
                            _load_json_bytes(
                                _member_bytes(
                                    source,
                                    member,
                                    MAX_JSON_MEMBER_BYTES,
                                    "Docker manifest",
                                ),
                                "Docker manifest",
                            ),
                            "Docker manifest",
                        )
                        if len(manifest) != 1:
                            raise EvidenceError(
                                "Docker archive must contain exactly one image"
                            )
                        entry = _mapping(manifest[0], "Docker manifest entry")
                        if set(entry) != {"Config", "RepoTags", "Layers"}:
                            raise EvidenceError(
                                "Docker manifest entry shape is not canonical"
                            )
                        entry = dict(entry)
                        entry["RepoTags"] = [image_ref]
                        payload = (
                            json.dumps(
                                [entry], separators=(",", ":"), sort_keys=True
                            )
                            + "\n"
                        ).encode("utf-8")
                        copied.size = len(payload)
                        target.addfile(copied, io.BytesIO(payload))
                    elif member.isfile():
                        source_stream = source.extractfile(member)
                        if source_stream is None:
                            raise EvidenceError("archive member cannot be copied")
                        target.addfile(copied, source_stream)
                    else:
                        target.addfile(copied)
            target_stream.flush()
            os.fsync(target_stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.chmod(target_path, 0o600, follow_symlinks=False)
        except OSError:
            pass


def retag(arguments: argparse.Namespace) -> str:
    source = _verified_evidence(arguments)
    _retag_archive(
        arguments.archive,
        arguments.target_archive,
        arguments.target_image_ref,
    )
    source_digest, source_size = _sha256_path(
        arguments.archive, MAX_ARCHIVE_BYTES, "source image archive"
    )
    if (
        source_digest != arguments.expected_archive_sha256
        or source_size != source["archive"]["size"]
    ):
        raise EvidenceError("source image archive changed while it was retagged")
    target = inspect_archive(
        arguments.target_archive,
        expected_image_id=arguments.expected_image_id,
        expected_image_ref=arguments.target_image_ref,
        expected_owner=arguments.expected_owner,
        source_sha=arguments.source_sha,
    )
    for key in (
        "config",
        "docker_image_id",
        "layers",
        "oci",
        "ownership",
        "platform",
        "source_sha",
    ):
        if target[key] != source[key]:
            raise EvidenceError("retagging changed immutable image content")
    source_members = {item["member"]: item for item in source["members"]}
    target_members = {item["member"]: item for item in target["members"]}
    if set(source_members) != set(target_members):
        raise EvidenceError("retagging changed the image archive member set")
    for name in source_members:
        if name != "manifest.json" and target_members[name] != source_members[name]:
            raise EvidenceError("retagging changed a non-manifest archive member")
    _write_evidence(arguments.target_evidence, target)
    target_evidence_sha256, _ = _sha256_path(
        arguments.target_evidence,
        MAX_EVIDENCE_BYTES,
        "retagged archive evidence",
    )
    receipt = {
        "config_sha256": target["config"]["sha256"],
        "docker_image_id": target["docker_image_id"],
        "operation": "replace-docker-repository-tag",
        "schema_version": 1,
        "source": {
            "archive_sha256": source["archive"]["sha256"],
            "docker_manifest_sha256": source["docker_manifest"]["sha256"],
            "evidence_sha256": arguments.expected_evidence_sha256,
            "image_reference": source["image_reference"],
        },
        "target": {
            "archive_sha256": target["archive"]["sha256"],
            "docker_manifest_sha256": target["docker_manifest"]["sha256"],
            "evidence_sha256": target_evidence_sha256,
            "image_reference": target["image_reference"],
        },
    }
    _write_evidence(arguments.receipt, receipt)
    return target["config"]["sha256"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("attest", "verify", "retag"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--archive", required=True, type=Path)
        subparser.add_argument("--evidence", required=True, type=Path)
        subparser.add_argument("--expected-image-id", required=True)
        subparser.add_argument("--expected-image-ref", required=True)
        subparser.add_argument("--expected-owner", required=True)
        subparser.add_argument("--source-sha", required=True)
        if command in {"verify", "retag"}:
            subparser.add_argument("--expected-archive-sha256", required=True)
            subparser.add_argument("--expected-evidence-sha256", required=True)
        if command == "retag":
            subparser.add_argument("--target-archive", required=True, type=Path)
            subparser.add_argument("--target-evidence", required=True, type=Path)
            subparser.add_argument("--target-image-ref", required=True)
            subparser.add_argument("--receipt", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "attest":
            config_digest = attest(arguments)
        elif arguments.command == "verify":
            config_digest = verify(arguments)
        else:
            config_digest = retag(arguments)
        print(config_digest)
        return 0
    except (EvidenceError, OSError, tarfile.TarError) as exc:
        print(f"arm64 legacy image evidence failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
