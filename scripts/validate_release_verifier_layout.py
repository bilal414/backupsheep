#!/usr/bin/env python3
"""Fail-closed validation for the stable multi-platform release verifier.

The input is a private BuildKit OCI layout plus raw Syft and Trivy reports for
each retained child.  Nothing in this gate trusts a mutable registry tag.  It
binds the layout, runtime filesystem, scanner inventories, and the reviewed
digest-locked Trivy database before rewriting the two scanner display names to
immutable ``repository@child-digest`` references.

The Trivy DB lock is reviewed and digest-locked evidence.  It is deliberately
not described as signed or authenticated, and an expired lock fails closed.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile
from typing import Any
from urllib.parse import quote
import zlib


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prepare_trivy_db import (  # noqa: E402
    TrivyDBError,
    load_evidence as load_trivy_db_evidence,
    load_lock as load_trivy_db_lock,
)


MAX_CONTROL_BYTES = 4 * 1024 * 1024
MAX_REPORT_BYTES = 128 * 1024 * 1024
MAX_LAYER_COMPRESSED_BYTES = 192 * 1024 * 1024
MAX_LAYER_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_LAYOUT_BYTES = 512 * 1024 * 1024
MAX_LAYOUT_BLOBS = 16
MAX_TAR_MEMBERS = 16
MAX_CERTIFICATE_BYTES = 4 * 1024 * 1024
MIN_CERTIFICATE_BYTES = 1024
MAX_VERIFIER_BYTES = 192 * 1024 * 1024
MIN_VERIFIER_BYTES = 1024 * 1024

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[1-9][0-9]{0,4})?/)?"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"

EXPECTED_PLATFORMS = ("linux/amd64", "linux/arm64")
EXPECTED_USER = "65532:65532"
EXPECTED_ENTRYPOINT = ["/ko-app/cosign"]
EXPECTED_ENV = [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/tmp",
]
EXPECTED_LABELS = {
    "org.opencontainers.image.title": "BackupSheep release verifier",
    "org.opencontainers.image.description": (
        "Minimal Cosign verifier rebuilt with reviewed security updates"
    ),
    "org.opencontainers.image.source": "https://github.com/bilal414/backupsheep",
    "org.opencontainers.image.licenses": "Apache-2.0",
    "com.backupsheep.release-verifier.upstream-version": "v3.1.3",
    "com.backupsheep.release-verifier.upstream-commit": (
        "11926fa5bbbbde47e88fc006b625a17769b743b2"
    ),
    "com.backupsheep.release-verifier.go-version": "go1.26.6",
    "com.backupsheep.release-verifier.module-graph-sha256": (
        "b913f70c7e494d63e88eef7da2b937d463085d120aac35a6bea66f5676cb920a"
    ),
}
EXPECTED_MODULE_GRAPH_SHA256 = EXPECTED_LABELS[
    "com.backupsheep.release-verifier.module-graph-sha256"
]
EXPECTED_GO_PACKAGE_COUNT = 253
# Canonical SHA-256 of all 253 reviewed scanner identities, one sorted
# ``name<TAB>version<LF>`` record each.  The main module uses an empty canonical
# version and stdlib uses ``go1.26.6`` in both scanner representations.
EXPECTED_GO_INVENTORY_SHA256 = (
    "e16ec12d4a7b87ad68878a26d96016f5da813b3066b77573991b30925b56b035"
)
EXPECTED_GO_IDENTITIES = {
    "stdlib": "go1.26.6",
    "golang.org/x/mod": "v0.40.0",
    "golang.org/x/text": "v0.41.0",
    "google.golang.org/grpc": "v1.83.1",
}
MAIN_MODULE = "github.com/sigstore/cosign/v3"
SYFT_MAIN_PLACEHOLDER = "UNKNOWN"
EXPECTED_SYFT_VERSION = "1.51.0"
EXPECTED_SYFT_SCHEMA = {
    "version": "16.1.10",
    "url": (
        "https://raw.githubusercontent.com/anchore/syft/main/schema/json/"
        "schema-16.1.10.json"
    ),
}
EXPECTED_TRIVY_VERSION = "0.74.0"
EXPECTED_BUILD_TIMESTAMP = "2026-09-04T00:00:00Z"
EXPECTED_LAYER_ANNOTATIONS = {"buildkit/rewritten-timestamp": "1788480000"}

EXPECTED_HISTORY = (
    (
        "LABEL "
        "org.opencontainers.image.title=BackupSheep release verifier "
        "org.opencontainers.image.description=Minimal Cosign verifier rebuilt with "
        "reviewed security updates "
        "org.opencontainers.image.source=https://github.com/bilal414/backupsheep "
        "org.opencontainers.image.licenses=Apache-2.0 "
        "com.backupsheep.release-verifier.upstream-version=v3.1.3 "
        "com.backupsheep.release-verifier.upstream-commit="
        "11926fa5bbbbde47e88fc006b625a17769b743b2 "
        "com.backupsheep.release-verifier.go-version=go1.26.6 "
        "com.backupsheep.release-verifier.module-graph-sha256="
        "b913f70c7e494d63e88eef7da2b937d463085d120aac35a6bea66f5676cb920a",
        True,
    ),
    (
        "COPY --chown=0:0 --chmod=a=r /etc/ssl/certs/ca-certificates.crt "
        "/etc/ssl/certs/ca-certificates.crt # buildkit",
        False,
    ),
    (
        "COPY --chown=0:0 --chmod=a=rx /out/cosign /ko-app/cosign # buildkit",
        False,
    ),
    ("ENV HOME=/tmp", True),
    ("USER 65532:65532", True),
    ('ENTRYPOINT ["/ko-app/cosign"]', True),
)


class ValidationError(RuntimeError):
    """Release-verifier evidence violated a fail-closed invariant."""


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    payload: bytes
    fingerprint: tuple[int, int, int, int]


@dataclass(frozen=True)
class RuntimeFile:
    path: str
    sha256: str
    size: int
    mode: int
    diff_id: str


@dataclass(frozen=True)
class PlatformImage:
    platform: str
    architecture: str
    manifest_digest: str
    manifest_bytes: bytes
    config_digest: str
    config_bytes: bytes
    config: dict[str, Any]
    compressed_layers: tuple[dict[str, Any], ...]
    diff_ids: tuple[str, ...]
    layer_uncompressed_sizes: tuple[int, ...]
    certificate: RuntimeFile
    verifier: RuntimeFile


@dataclass(frozen=True)
class ReportResult:
    document: dict[str, Any]
    snapshot: FileSnapshot
    inventory: dict[str, str]
    inventory_sha256: str
    package_count: int


def _fail(message: str) -> None:
    raise ValidationError(message)


def _reject_constant(value: str) -> None:
    raise ValidationError(f"non-finite JSON value is forbidden: {value}")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{label} must be a list")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        _fail(
            f"{label} has invalid keys "
            f"(missing={sorted(expected - set(value))}, "
            f"unknown={sorted(set(value) - expected)})"
        )


def _integer(
    value: Any, label: str, *, minimum: int = 0, maximum: int | None = None
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{label} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        _fail(f"{label} is outside the permitted range")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        _fail(f"{label} must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValidationError(f"{label} is not a valid timestamp") from exc
    return parsed.astimezone(timezone.utc)


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _read_regular(path: Path, *, maximum: int, label: str) -> FileSnapshot:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValidationError(f"cannot inspect {label}: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        _fail(f"{label} must be a bounded, single-link regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        fingerprint = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        )
        if fingerprint != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            _fail(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            payload = stream.read(maximum + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ValidationError(f"cannot re-inspect {label}: {exc}") from exc
    if (
        len(payload) != before.st_size
        or len(payload) > maximum
        or fingerprint
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        _fail(f"{label} changed while it was read")
    return FileSnapshot(path, payload, fingerprint)


def _json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            payload,
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    return _object(document, label)


def _load_json(path: Path, *, maximum: int, label: str) -> tuple[dict[str, Any], FileSnapshot]:
    snapshot = _read_regular(path, maximum=maximum, label=label)
    return _json_bytes(snapshot.payload, label), snapshot


def _decode_base64_json(value: Any, label: str) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(value, str) or not value:
        _fail(f"{label} is missing")
    try:
        payload = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"{label} is not canonical base64") from exc
    if not payload or len(payload) > MAX_CONTROL_BYTES:
        _fail(f"{label} is empty or oversized")
    if base64.b64encode(payload).decode("ascii") != value:
        _fail(f"{label} is not canonical base64")
    return payload, _json_bytes(payload, label)


def _secure_output(path: Path) -> Path:
    if path.name in {"", ".", ".."}:
        _fail("summary needs a plain final path component")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise ValidationError("summary parent does not exist") from exc
    if path.parent.absolute() != parent:
        _fail("summary parent must not traverse symlinks")
    if os.path.lexists(parent / path.name):
        _fail("summary destination must not pre-exist")
    return parent / path.name


def _atomic_replace_json(snapshot: FileSnapshot, document: dict[str, Any], label: str) -> None:
    if snapshot.path.parent.absolute() != snapshot.path.parent.resolve(strict=True):
        _fail(f"{label} parent must not traverse symlinks")
    try:
        current = snapshot.path.lstat()
    except OSError as exc:
        raise ValidationError(f"cannot re-inspect {label}: {exc}") from exc
    if snapshot.fingerprint != (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
    ):
        _fail(f"{label} changed before normalization")
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{snapshot.path.name}.", dir=snapshot.path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, snapshot.path)
        directory = os.open(snapshot.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _write_summary(path: Path, document: dict[str, Any]) -> None:
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )
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


def _validate_layout_root(layout: Path) -> tuple[Path, set[str]]:
    if not layout.is_absolute():
        _fail("OCI layout path must be absolute")
    try:
        root = layout.resolve(strict=True)
        metadata = layout.lstat()
    except OSError as exc:
        raise ValidationError(f"cannot inspect OCI layout: {exc}") from exc
    if root != layout or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        _fail("OCI layout must be an absolute real directory without symlink traversal")

    expected_directories = {".", "blobs", "blobs/sha256"}
    observed_directories: set[str] = set()
    observed_files: set[str] = set()
    total_bytes = 0
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        relative_directory = current.relative_to(root).as_posix()
        relative_directory = "." if relative_directory == "." else relative_directory
        observed_directories.add(relative_directory)
        for name in list(directories):
            child = current / name
            child_metadata = child.lstat()
            if stat.S_ISLNK(child_metadata.st_mode) or not stat.S_ISDIR(child_metadata.st_mode):
                _fail("OCI layout contains a symlink or non-directory in its directory tree")
        for name in files:
            child = current / name
            relative = child.relative_to(root).as_posix()
            child_metadata = child.lstat()
            if (
                stat.S_ISLNK(child_metadata.st_mode)
                or not stat.S_ISREG(child_metadata.st_mode)
                or child_metadata.st_nlink != 1
                or child_metadata.st_size <= 0
            ):
                _fail(f"OCI layout member is not a safe regular file: {relative}")
            observed_files.add(relative)
            total_bytes += child_metadata.st_size
            if total_bytes > MAX_LAYOUT_BYTES:
                _fail("OCI layout exceeds its maximum total size")
    if observed_directories != expected_directories:
        _fail(
            "OCI layout directory set is not exact: "
            f"{sorted(observed_directories)}"
        )
    if not {"index.json", "oci-layout"}.issubset(observed_files):
        _fail("OCI layout is missing index.json or oci-layout")
    blob_members = observed_files - {"index.json", "oci-layout"}
    if not 1 <= len(blob_members) <= MAX_LAYOUT_BLOBS:
        _fail("OCI layout has an invalid blob count")
    for member in blob_members:
        if not re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", member):
            _fail(f"OCI layout contains an unexpected member: {member}")
    return root, blob_members


def _descriptor(
    value: Any,
    *,
    label: str,
    media_type: str,
    maximum_size: int,
    extra_keys: set[str] | None = None,
) -> dict[str, Any]:
    result = _object(value, label)
    keys = {"mediaType", "digest", "size"} | (extra_keys or set())
    _exact_keys(result, keys, label)
    if result["mediaType"] != media_type:
        _fail(f"{label} has an unsupported media type")
    _digest(result["digest"], f"{label}.digest")
    _integer(result["size"], f"{label}.size", minimum=1, maximum=maximum_size)
    return result


def _blob_snapshot(
    root: Path,
    descriptor: dict[str, Any],
    *,
    maximum: int,
    label: str,
    referenced: set[str],
) -> FileSnapshot:
    digest = descriptor["digest"]
    relative = f"blobs/sha256/{digest.removeprefix('sha256:')}"
    # A byte-identical CA layer is legitimately shared by both architectures.
    # The graph is still closed exactly below by comparing this set with every
    # blob present in the layout.
    referenced.add(relative)
    snapshot = _read_regular(root / relative, maximum=maximum, label=label)
    if len(snapshot.payload) != descriptor["size"] or _sha256(snapshot.payload) != digest:
        _fail(f"{label} bytes do not match its exact descriptor")
    return snapshot


def _validate_history(config: dict[str, Any]) -> None:
    history = _list(config.get("history"), "image config history")
    if len(history) != len(EXPECTED_HISTORY):
        _fail("image config history is not the exact scratch-verifier history")
    created = _timestamp(config.get("created"), "image config created")
    expected_created = _timestamp(EXPECTED_BUILD_TIMESTAMP, "expected build timestamp")
    if created != expected_created:
        _fail("image config created timestamp is not reproducibly bound")
    for index, (raw, expected) in enumerate(zip(history, EXPECTED_HISTORY, strict=True)):
        item = _object(raw, f"image config history[{index}]")
        created_by, empty = expected
        expected_keys = {"created", "created_by", "comment"}
        if empty:
            expected_keys.add("empty_layer")
        _exact_keys(item, expected_keys, f"image config history[{index}]")
        when = _timestamp(item["created"], f"image config history[{index}].created")
        if when != expected_created:
            _fail("image config history timestamp is not reproducibly bound")
        if (
            item["created_by"] != created_by
            or item["comment"] != "buildkit.dockerfile.v0"
            or (empty and item.get("empty_layer") is not True)
        ):
            _fail(f"image config history[{index}] is not exact")


def _validate_config(
    payload: bytes, *, architecture: str, expected_diff_ids: tuple[str, ...]
) -> dict[str, Any]:
    config = _json_bytes(payload, f"linux/{architecture} image config")
    _exact_keys(
        config,
        {"architecture", "config", "created", "history", "os", "rootfs"},
        "image config",
    )
    if config["architecture"] != architecture or config["os"] != "linux":
        _fail("image config platform does not match its index descriptor")
    runtime = _object(config["config"], "runtime config")
    _exact_keys(runtime, {"User", "Env", "Entrypoint", "WorkingDir", "Labels"}, "runtime config")
    if runtime != {
        "User": EXPECTED_USER,
        "Env": EXPECTED_ENV,
        "Entrypoint": EXPECTED_ENTRYPOINT,
        "WorkingDir": "/",
        "Labels": EXPECTED_LABELS,
    }:
        _fail(
            "runtime config is not the exact non-root scratch verifier "
            "(Cmd, ports, volumes, healthchecks, and extra env/labels are forbidden)"
        )
    rootfs = _object(config["rootfs"], "image rootfs")
    _exact_keys(rootfs, {"type", "diff_ids"}, "image rootfs")
    if rootfs["type"] != "layers" or rootfs["diff_ids"] != list(expected_diff_ids):
        _fail("image rootfs DiffIDs do not match the two exact layers")
    _validate_history(config)
    return config


def _safe_tar_name(value: str) -> str:
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        _fail("runtime layer contains an unsafe path")
    normalized = value.rstrip("/")
    path = PurePosixPath(normalized)
    if normalized in {"", ".", ".."} or any(part in {"", ".", ".."} for part in path.parts):
        _fail("runtime layer contains path traversal or a non-canonical path")
    if path.as_posix() != normalized:
        _fail("runtime layer contains a non-canonical path")
    return normalized


def _inspect_layer(
    payload: bytes,
    *,
    expected_file: str,
    expected_mode: int,
    architecture: str,
) -> tuple[str, int, RuntimeFile]:
    uncompressed_hash = hashlib.sha256()
    uncompressed_size = 0
    temporary = tempfile.TemporaryFile()
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        for offset in range(0, len(payload), 1024 * 1024):
            chunk = decompressor.decompress(payload[offset : offset + 1024 * 1024])
            if chunk:
                uncompressed_size += len(chunk)
                if uncompressed_size > MAX_LAYER_UNCOMPRESSED_BYTES:
                    _fail("runtime layer expands beyond its maximum size")
                uncompressed_hash.update(chunk)
                temporary.write(chunk)
            if decompressor.unused_data:
                _fail("runtime layer contains concatenated or trailing compressed data")
        chunk = decompressor.flush()
        if chunk:
            uncompressed_size += len(chunk)
            if uncompressed_size > MAX_LAYER_UNCOMPRESSED_BYTES:
                _fail("runtime layer expands beyond its maximum size")
            uncompressed_hash.update(chunk)
            temporary.write(chunk)
    except zlib.error as exc:
        raise ValidationError(f"runtime layer is not a valid gzip stream: {exc}") from exc
    if not decompressor.eof or decompressor.unused_data or decompressor.unconsumed_tail:
        _fail("runtime layer gzip stream is truncated, concatenated, or has trailing data")
    if uncompressed_size < 1024:
        _fail("runtime layer tar stream is implausibly small")
    temporary.seek(0)
    try:
        archive = tarfile.open(fileobj=temporary, mode="r:")
    except (OSError, tarfile.TarError) as exc:
        raise ValidationError(f"runtime layer is not a valid tar archive: {exc}") from exc
    try:
        if archive.pax_headers:
            _fail("runtime layer has unexpected global PAX headers")
        members = archive.getmembers()
        if not 1 <= len(members) <= MAX_TAR_MEMBERS:
            _fail("runtime layer has an invalid member count")
        names: set[str] = set()
        expected_ancestors = {
            PurePosixPath(expected_file).parent.as_posix(),
        }
        parent = PurePosixPath(expected_file).parent
        while parent.as_posix() not in {".", ""}:
            expected_ancestors.add(parent.as_posix())
            parent = parent.parent
        regular: tarfile.TarInfo | None = None
        for member in members:
            name = _safe_tar_name(member.name)
            if name in names:
                _fail("runtime layer contains duplicate member paths")
            names.add(name)
            if member.pax_headers or member.linkname or member.issym() or member.islnk():
                _fail("runtime layer contains links or PAX metadata")
            if (
                member.uid != 0
                or member.gid != 0
                or member.uname not in {"", "root"}
                or member.gname not in {"", "root"}
            ):
                _fail("runtime layer members must be root-owned")
            if member.isdir():
                if (
                    name not in expected_ancestors
                    or stat.S_IMODE(member.mode) != 0o755
                    or member.size != 0
                ):
                    _fail(
                        "runtime layer contains an unexpected or unsafe directory "
                        f"(name={name!r}, mode={stat.S_IMODE(member.mode):04o}, "
                        f"size={member.size}, expected_file={expected_file!r})"
                    )
                continue
            if (
                not member.isfile()
                or name != expected_file
                or stat.S_IMODE(member.mode) != expected_mode
            ):
                _fail("runtime layer contains an unexpected file, type, or mode")
            if regular is not None:
                _fail("runtime layer contains more than one regular file")
            regular = member
        if regular is None:
            _fail(f"runtime layer does not contain {expected_file}")
        last_content_end = max(
            member.offset_data + ((member.size + 511) // 512) * 512
            for member in members
        )
        temporary.seek(last_content_end)
        trailer = temporary.read()
        if len(trailer) < 1024 or any(trailer):
            _fail("runtime layer does not have an exact zero-filled tar terminator")
        extracted = archive.extractfile(regular)
        if extracted is None:
            _fail("runtime layer file is unreadable")
        digest = hashlib.sha256()
        count = 0
        prefix = b""
        certificate_marker = False
        contains_nul = False
        with extracted:
            for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
                count += len(chunk)
                digest.update(chunk)
                if len(prefix) < 64:
                    prefix += chunk[: 64 - len(prefix)]
                if expected_file.endswith("ca-certificates.crt"):
                    certificate_marker = (
                        certificate_marker
                        or b"-----BEGIN CERTIFICATE-----" in chunk
                    )
                    contains_nul = contains_nul or b"\x00" in chunk
        if count != regular.size:
            _fail("runtime layer file size changed while it was read")
        if expected_file.endswith("ca-certificates.crt"):
            if (
                count < MIN_CERTIFICATE_BYTES
                or count > MAX_CERTIFICATE_BYTES
                or not certificate_marker
                or contains_nul
            ):
                _fail("CA bundle is not a bounded PEM certificate bundle")
        else:
            if count < MIN_VERIFIER_BYTES or count > MAX_VERIFIER_BYTES:
                _fail("release verifier ELF has an implausible size")
            _validate_elf(prefix, architecture)
        diff_id = "sha256:" + uncompressed_hash.hexdigest()
        return (
            diff_id,
            uncompressed_size,
            RuntimeFile(
                path="/" + expected_file,
                sha256=digest.hexdigest(),
                size=count,
                mode=expected_mode,
                diff_id=diff_id,
            ),
        )
    except tarfile.TarError as exc:
        raise ValidationError(f"runtime layer tar structure is invalid: {exc}") from exc
    finally:
        archive.close()
        temporary.close()


def _validate_elf(header: bytes, architecture: str) -> None:
    expected_machine = {"amd64": 62, "arm64": 183}[architecture]
    if (
        len(header) < 64
        or header[:4] != b"\x7fELF"
        or header[4:7] != b"\x02\x01\x01"
        or int.from_bytes(header[16:18], "little") != 2
        or int.from_bytes(header[18:20], "little") != expected_machine
        or int.from_bytes(header[20:24], "little") != 1
        or int.from_bytes(header[24:32], "little") == 0
        or int.from_bytes(header[54:56], "little") != 56
        or int.from_bytes(header[56:58], "little") == 0
    ):
        _fail(f"release verifier is not the expected static linux/{architecture} ELF")


def _validate_layout(
    *, layout: Path, index_digest: str, repository: str, tag: str
) -> tuple[dict[str, PlatformImage], str]:
    root, observed_blobs = _validate_layout_root(layout)
    referenced: set[str] = set()
    layout_document, layout_snapshot = _load_json(
        root / "oci-layout", maximum=1024, label="OCI layout marker"
    )
    if layout_document != {"imageLayoutVersion": "1.0.0"}:
        _fail("OCI layout marker is not exact")
    wrapper, wrapper_snapshot = _load_json(
        root / "index.json", maximum=MAX_CONTROL_BYTES, label="OCI layout index"
    )
    _exact_keys(
        wrapper,
        {"schemaVersion", "mediaType", "manifests"},
        "OCI layout index",
    )
    if wrapper["schemaVersion"] != 2 or wrapper["mediaType"] != OCI_INDEX:
        _fail("OCI layout index has an unsupported schema or media type")
    roots = _list(wrapper["manifests"], "OCI layout roots")
    if len(roots) != 1:
        _fail("OCI layout must contain exactly one root image index")
    root_descriptor = _descriptor(
        roots[0],
        label="OCI root descriptor",
        media_type=OCI_INDEX,
        maximum_size=MAX_CONTROL_BYTES,
        extra_keys={"annotations"},
    )
    if root_descriptor["digest"] != index_digest:
        _fail("OCI root descriptor does not match --index-digest")
    if root_descriptor["annotations"] != {
        "io.containerd.image.name": f"{repository}:{tag}",
        "org.opencontainers.image.created": EXPECTED_BUILD_TIMESTAMP,
        "org.opencontainers.image.ref.name": tag,
    }:
        _fail("OCI root descriptor is not bound to the requested repository and tag")
    root_snapshot = _blob_snapshot(
        root,
        root_descriptor,
        maximum=MAX_CONTROL_BYTES,
        label="OCI root image index blob",
        referenced=referenced,
    )
    index = _json_bytes(root_snapshot.payload, "OCI root image index")
    _exact_keys(index, {"schemaVersion", "mediaType", "manifests"}, "OCI root image index")
    if index["schemaVersion"] != 2 or index["mediaType"] != OCI_INDEX:
        _fail("OCI root image index schema or media type is unsupported")
    children = _list(index["manifests"], "OCI child descriptors")
    if len(children) != 2:
        _fail("OCI root must contain exactly two platform children and no attestations")

    platform_descriptors: dict[str, dict[str, Any]] = {}
    for position, raw_descriptor in enumerate(children):
        descriptor = _descriptor(
            raw_descriptor,
            label=f"OCI child descriptor[{position}]",
            media_type=OCI_MANIFEST,
            maximum_size=MAX_CONTROL_BYTES,
            extra_keys={"platform"},
        )
        platform = _object(descriptor["platform"], "OCI child platform")
        _exact_keys(platform, {"architecture", "os"}, "OCI child platform")
        platform_name = f"{platform.get('os')}/{platform.get('architecture')}"
        if platform_name not in EXPECTED_PLATFORMS or platform_name in platform_descriptors:
            _fail("OCI root has a duplicate or unauthorized platform child")
        platform_descriptors[platform_name] = descriptor
    if set(platform_descriptors) != set(EXPECTED_PLATFORMS):
        _fail("OCI root does not contain exactly linux/amd64 and linux/arm64")

    images: dict[str, PlatformImage] = {}
    for platform_name in EXPECTED_PLATFORMS:
        architecture = platform_name.split("/", 1)[1]
        child_descriptor = platform_descriptors[platform_name]
        child_snapshot = _blob_snapshot(
            root,
            child_descriptor,
            maximum=MAX_CONTROL_BYTES,
            label=f"{platform_name} manifest blob",
            referenced=referenced,
        )
        manifest = _json_bytes(child_snapshot.payload, f"{platform_name} manifest")
        _exact_keys(
            manifest,
            {"schemaVersion", "mediaType", "config", "layers"},
            f"{platform_name} manifest",
        )
        if manifest["schemaVersion"] != 2 or manifest["mediaType"] != OCI_MANIFEST:
            _fail(f"{platform_name} manifest schema or media type is unsupported")
        config_descriptor = _descriptor(
            manifest["config"],
            label=f"{platform_name} config descriptor",
            media_type=OCI_CONFIG,
            maximum_size=MAX_CONTROL_BYTES,
        )
        layer_values = _list(manifest["layers"], f"{platform_name} layers")
        if len(layer_values) != 2:
            _fail(f"{platform_name} must have exactly the CA and verifier layers")
        layer_descriptors = tuple(
            _descriptor(
                value,
                label=f"{platform_name} layer[{index}]",
                media_type=OCI_LAYER,
                maximum_size=MAX_LAYER_COMPRESSED_BYTES,
                extra_keys={"annotations"},
            )
            for index, value in enumerate(layer_values)
        )
        if any(
            descriptor["annotations"] != EXPECTED_LAYER_ANNOTATIONS
            for descriptor in layer_descriptors
        ):
            _fail(f"{platform_name} layers are not bound to the reproducible epoch")
        layer_results: list[tuple[str, int, RuntimeFile]] = []
        for position, (descriptor, expected_file, expected_mode) in enumerate(
            zip(
                layer_descriptors,
                ("etc/ssl/certs/ca-certificates.crt", "ko-app/cosign"),
                (0o444, 0o555),
                strict=True,
            )
        ):
            layer_snapshot = _blob_snapshot(
                root,
                descriptor,
                maximum=MAX_LAYER_COMPRESSED_BYTES,
                label=f"{platform_name} layer[{position}] blob",
                referenced=referenced,
            )
            layer_results.append(
                _inspect_layer(
                    layer_snapshot.payload,
                    expected_file=expected_file,
                    expected_mode=expected_mode,
                    architecture=architecture,
                )
            )
        diff_ids = tuple(item[0] for item in layer_results)
        config_snapshot = _blob_snapshot(
            root,
            config_descriptor,
            maximum=MAX_CONTROL_BYTES,
            label=f"{platform_name} config blob",
            referenced=referenced,
        )
        config = _validate_config(
            config_snapshot.payload,
            architecture=architecture,
            expected_diff_ids=diff_ids,
        )
        images[platform_name] = PlatformImage(
            platform=platform_name,
            architecture=architecture,
            manifest_digest=child_descriptor["digest"],
            manifest_bytes=child_snapshot.payload,
            config_digest=config_descriptor["digest"],
            config_bytes=config_snapshot.payload,
            config=config,
            compressed_layers=layer_descriptors,
            diff_ids=diff_ids,
            layer_uncompressed_sizes=tuple(item[1] for item in layer_results),
            certificate=layer_results[0][2],
            verifier=layer_results[1][2],
        )
    if referenced != observed_blobs:
        _fail(
            "OCI layout contains unreferenced or missing blobs: "
            f"unreferenced={sorted(observed_blobs - referenced)}, "
            f"missing={sorted(referenced - observed_blobs)}"
        )
    if images["linux/amd64"].certificate.sha256 != images["linux/arm64"].certificate.sha256:
        _fail("the two platform images do not contain the same reviewed CA bundle")
    if images["linux/amd64"].verifier.sha256 == images["linux/arm64"].verifier.sha256:
        _fail("the two architectures unexpectedly contain identical verifier binaries")
    layout_binding = hashlib.sha256(
        layout_snapshot.payload + b"\x00" + wrapper_snapshot.payload
    ).hexdigest()
    return images, layout_binding


def _owned_private_directory(directory: Path, label: str) -> Path:
    if not directory.is_absolute():
        _fail(f"{label} must be absolute")
    try:
        resolved = directory.resolve(strict=True)
        metadata = directory.lstat()
    except OSError as exc:
        raise ValidationError(f"cannot inspect {label}: {exc}") from exc
    if (
        resolved != directory
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail(f"{label} must be an owner-private real directory")
    return resolved


def _validate_scan_layout(
    scan_layout: Path,
    *,
    image: PlatformImage,
    scan_tag: str,
) -> str:
    root, observed_blobs = _validate_layout_root(scan_layout)
    marker, _ = _load_json(
        root / "oci-layout", maximum=1024, label=f"{image.platform} scan marker"
    )
    if marker != {"imageLayoutVersion": "1.0.0"}:
        _fail(f"{image.platform} scan layout marker is not exact")
    wrapper, _ = _load_json(
        root / "index.json",
        maximum=MAX_CONTROL_BYTES,
        label=f"{image.platform} scan index",
    )
    _exact_keys(
        wrapper,
        {"schemaVersion", "mediaType", "manifests"},
        f"{image.platform} scan index",
    )
    if wrapper["schemaVersion"] != 2 or wrapper["mediaType"] != OCI_INDEX:
        _fail(f"{image.platform} scan index has an unsupported schema or media type")
    roots = _list(wrapper["manifests"], f"{image.platform} scan roots")
    if len(roots) != 1:
        _fail(f"{image.platform} scan layout must contain exactly one child")
    descriptor = _descriptor(
        roots[0],
        label=f"{image.platform} scan descriptor",
        media_type=OCI_MANIFEST,
        maximum_size=MAX_CONTROL_BYTES,
        extra_keys={"annotations", "platform"},
    )
    platform = _object(descriptor["platform"], f"{image.platform} scan platform")
    _exact_keys(platform, {"architecture", "os"}, f"{image.platform} scan platform")
    if platform != {"architecture": image.architecture, "os": "linux"}:
        _fail(f"{image.platform} scan projection selected the wrong platform")
    if descriptor["annotations"] != {"org.opencontainers.image.ref.name": scan_tag}:
        _fail(f"{image.platform} scan projection has an unexpected reference")
    if (
        descriptor["digest"] != image.manifest_digest
        or descriptor["size"] != len(image.manifest_bytes)
    ):
        _fail(f"{image.platform} scan projection selected the wrong manifest")

    referenced: set[str] = set()
    manifest = _blob_snapshot(
        root,
        descriptor,
        maximum=MAX_CONTROL_BYTES,
        label=f"{image.platform} projected manifest",
        referenced=referenced,
    )
    if manifest.payload != image.manifest_bytes:
        _fail(f"{image.platform} projected manifest bytes changed")
    config_descriptor = {
        "mediaType": OCI_CONFIG,
        "digest": image.config_digest,
        "size": len(image.config_bytes),
    }
    config = _blob_snapshot(
        root,
        config_descriptor,
        maximum=MAX_CONTROL_BYTES,
        label=f"{image.platform} projected config",
        referenced=referenced,
    )
    if config.payload != image.config_bytes:
        _fail(f"{image.platform} projected config bytes changed")
    for position, layer_descriptor in enumerate(image.compressed_layers):
        _blob_snapshot(
            root,
            layer_descriptor,
            maximum=MAX_LAYER_COMPRESSED_BYTES,
            label=f"{image.platform} projected layer[{position}]",
            referenced=referenced,
        )
    if referenced != observed_blobs or len(referenced) != 4:
        _fail(f"{image.platform} scan projection graph is not exact")
    return str(root)


def preflight_source(
    *,
    layout: Path,
    index_digest: str,
    repository: str,
    tag: str,
) -> tuple[dict[str, PlatformImage], str]:
    if DIGEST_RE.fullmatch(index_digest) is None:
        _fail("--index-digest must be a lowercase SHA-256 digest")
    if REPOSITORY_RE.fullmatch(repository) is None or "@" in repository:
        _fail("--repository is not a canonical lowercase OCI repository")
    if TAG_RE.fullmatch(tag) is None:
        _fail("--tag is not a valid OCI tag")
    return _validate_layout(
        layout=layout,
        index_digest=index_digest,
        repository=repository,
        tag=tag,
    )


def preflight(
    *,
    layout: Path,
    index_digest: str,
    repository: str,
    tag: str,
    scan_layouts: dict[str, Path],
) -> tuple[dict[str, PlatformImage], str, dict[str, str]]:
    if set(scan_layouts) != set(EXPECTED_PLATFORMS):
        _fail("scan projections must cover exactly linux/amd64 and linux/arm64")
    images, layout_binding = preflight_source(
        layout=layout,
        index_digest=index_digest,
        repository=repository,
        tag=tag,
    )
    scan_root = _owned_private_directory(layout.parent / "scans", "scan root")
    identities: dict[str, str] = {}
    for platform in EXPECTED_PLATFORMS:
        architecture = platform.split("/", 1)[1]
        expected = scan_root / architecture
        if scan_layouts[platform] != expected:
            _fail(f"{platform} scan projection path is not canonical")
        _owned_private_directory(expected, f"{platform} scan projection")
        identities[platform] = _validate_scan_layout(
            expected,
            image=images[platform],
            scan_tag=f"scan-{architecture}",
        )
    return images, layout_binding, identities


def _canonical_inventory(inventory: dict[str, str]) -> tuple[str, bytes]:
    payload = "".join(
        f"{name}\t{version}\n" for name, version in sorted(inventory.items())
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), payload


def _check_inventory(inventory: dict[str, str], scanner: str) -> str:
    if len(inventory) != EXPECTED_GO_PACKAGE_COUNT:
        _fail(
            f"{scanner} Go inventory does not contain exactly "
            f"{EXPECTED_GO_PACKAGE_COUNT} identities"
        )
    observed_reviewed = {name: inventory.get(name) for name in EXPECTED_GO_IDENTITIES}
    if observed_reviewed != EXPECTED_GO_IDENTITIES:
        _fail(f"{scanner} reviewed Go identities are not exact: {observed_reviewed}")
    if inventory.get(MAIN_MODULE) != "":
        _fail(f"{scanner} main module placeholder did not normalize exactly once")
    digest, _ = _canonical_inventory(inventory)
    if digest != EXPECTED_GO_INVENTORY_SHA256:
        _fail(f"{scanner} complete Cosign Go inventory differs from the reviewed graph")
    return digest


def _syft_inventory(
    report: dict[str, Any], *, image: PlatformImage
) -> tuple[dict[str, str], int]:
    artifacts = _list(report.get("artifacts"), "Syft artifacts")
    inventory: dict[str, str] = {}
    main_count = 0
    for position, raw_artifact in enumerate(artifacts):
        artifact = _object(raw_artifact, f"Syft artifact[{position}]")
        name = artifact.get("name")
        version = artifact.get("version")
        if not isinstance(name, str) or not name or name in inventory:
            _fail("Syft Go inventory contains a missing or duplicate package name")
        if (
            artifact.get("type") != "go-module"
            or artifact.get("foundBy") != "go-module-binary-cataloger"
            or artifact.get("language") != "go"
        ):
            _fail(f"Syft package is not an exact Go-binary identity: {name}")
        locations = _list(artifact.get("locations"), f"Syft {name} locations")
        if len(locations) != 1:
            _fail(f"Syft package does not have exactly one verifier location: {name}")
        location = _object(locations[0], f"Syft {name} location")
        if (
            location.get("path") != "/ko-app/cosign"
            or location.get("accessPath") != "/ko-app/cosign"
            or location.get("layerID") != image.verifier.diff_id
            or location.get("annotations") != {"evidence": "primary"}
        ):
            _fail(f"Syft package is not bound to the exact verifier layer: {name}")
        purl = artifact.get("purl")
        metadata = _object(artifact.get("metadata"), f"Syft {name} metadata")
        if metadata.get("goCompiledVersion") != "go1.26.6":
            _fail(f"Syft package has the wrong compiled Go version: {name}")
        if name == MAIN_MODULE:
            main_count += 1
            if (
                version != SYFT_MAIN_PLACEHOLDER
                or purl != f"pkg:golang/{MAIN_MODULE}"
                or artifact.get("metadataType") != "go-module-buildinfo-entry"
                or metadata.get("mainModule") != MAIN_MODULE
                or metadata.get("architecture") != image.architecture
            ):
                _fail("Syft main module is not the one reviewed UNKNOWN placeholder")
            settings = metadata.get("goBuildSettings")
            if not isinstance(settings, list):
                _fail("Syft main module build settings are absent")
            setting_map: dict[str, str] = {}
            for value in settings:
                item = _object(value, "Syft Go build setting")
                _exact_keys(item, {"key", "value"}, "Syft Go build setting")
                key = item.get("key")
                setting = item.get("value")
                if not isinstance(key, str) or not isinstance(setting, str) or key in setting_map:
                    _fail("Syft Go build settings contain a duplicate or malformed entry")
                setting_map[key] = setting
            required = {
                "-buildmode": "exe",
                "-compiler": "gc",
                "-trimpath": "true",
                "CGO_ENABLED": "0",
                "GOARCH": image.architecture,
                "GOOS": "linux",
            }
            required[
                "GOAMD64" if image.architecture == "amd64" else "GOARM64"
            ] = ("v1" if image.architecture == "amd64" else "v8.0")
            if setting_map != required:
                _fail("Syft Go build settings are not the reviewed static target settings")
            inventory[name] = ""
        else:
            if not isinstance(version, str) or not version or version == SYFT_MAIN_PLACEHOLDER:
                _fail(f"Syft has an unauthorized missing package version: {name}")
            purl_version = version.removeprefix("go") if name == "stdlib" else version
            expected_purl = f"pkg:golang/{name}@{quote(purl_version, safe='.-_~')}"
            if purl != expected_purl:
                _fail(f"Syft package PURL does not match its exact identity: {name}")
            inventory[name] = version
    if main_count != 1:
        _fail("Syft must contain exactly one reviewed main-module placeholder")
    return inventory, len(artifacts)


def _validate_syft_file(report: dict[str, Any], image: PlatformImage) -> None:
    files = _list(report.get("files"), "Syft files")
    if len(files) != 1:
        _fail("Syft must identify exactly the verifier binary file")
    file_record = _object(files[0], "Syft verifier file")
    location = _object(file_record.get("location"), "Syft verifier file location")
    metadata = _object(file_record.get("metadata"), "Syft verifier file metadata")
    if location != {"path": "/ko-app/cosign", "layerID": image.verifier.diff_id}:
        _fail("Syft file record is not bound to the verifier layer")
    expected_metadata = {
        "mode": 555,
        "type": "RegularFile",
        "userID": 0,
        "groupID": 0,
        "mimeType": "application/x-executable",
        "size": image.verifier.size,
    }
    for key, value in expected_metadata.items():
        if metadata.get(key) != value:
            _fail(f"Syft verifier file metadata is wrong: {key}")
    digests = _list(file_record.get("digests"), "Syft verifier file digests")
    digest_map: dict[str, str] = {}
    for value in digests:
        item = _object(value, "Syft verifier file digest")
        algorithm = item.get("algorithm")
        digest = item.get("value")
        if (
            not isinstance(algorithm, str)
            or not isinstance(digest, str)
            or algorithm in digest_map
        ):
            _fail("Syft verifier file digests are malformed or duplicated")
        digest_map[algorithm] = digest
    if digest_map.get("sha256") != image.verifier.sha256:
        _fail("Syft verifier file SHA-256 does not match the OCI layer")
    executable = _object(file_record.get("executable"), "Syft verifier executable metadata")
    if (
        executable.get("format") != "elf"
        or executable.get("hasEntrypoint") is not True
        or executable.get("importedLibraries") != []
    ):
        _fail("Syft did not identify the verifier as a static ELF executable")


def _validate_syft(
    path: Path,
    *,
    image: PlatformImage,
    raw_identity: str,
    immutable_identity: str | None,
) -> ReportResult:
    report, snapshot = _load_json(
        path,
        maximum=MAX_REPORT_BYTES,
        label=f"{image.platform} Syft report",
    )
    _exact_keys(
        report,
        {
            "artifacts",
            "artifactRelationships",
            "descriptor",
            "schema",
            "source",
            "distro",
            "files",
        },
        "Syft report",
    )
    if report["schema"] != EXPECTED_SYFT_SCHEMA:
        _fail("Syft schema is not the pinned supported schema")
    descriptor = _object(report["descriptor"], "Syft descriptor")
    _exact_keys(descriptor, {"name", "version", "configuration"}, "Syft descriptor")
    if descriptor.get("name") != "syft" or descriptor.get("version") != EXPECTED_SYFT_VERSION:
        _fail("Syft tool identity is not pinned")
    if report["distro"] != {} or not isinstance(report["artifactRelationships"], list):
        _fail("scratch Syft report has a distro or malformed relationships")
    source = _object(report["source"], "Syft source")
    _exact_keys(source, {"id", "name", "version", "type", "metadata"}, "Syft source")
    expected_input = immutable_identity if immutable_identity is not None else raw_identity
    if (
        source["type"] != "image"
        or source["name"] != raw_identity
        or source["id"] != image.manifest_digest.removeprefix("sha256:")
        or source["version"] != image.manifest_digest
    ):
        _fail("Syft source is not the exact retained OCI child")
    metadata = _object(source["metadata"], "Syft source metadata")
    if metadata.get("userInput") != expected_input:
        _fail("Syft input identity is pre-normalized, unrelated, or malformed")
    if (
        metadata.get("manifestDigest") != image.manifest_digest
        or metadata.get("imageID") != image.config_digest
        or metadata.get("mediaType") != OCI_MANIFEST
    ):
        _fail("Syft metadata does not identify the retained child/config")
    manifest_bytes, manifest = _decode_base64_json(
        metadata.get("manifest"), "Syft embedded manifest"
    )
    config_bytes, config = _decode_base64_json(metadata.get("config"), "Syft embedded config")
    if manifest_bytes != image.manifest_bytes or _sha256(manifest_bytes) != image.manifest_digest:
        _fail("Syft embedded manifest bytes differ from the OCI child")
    if config_bytes != image.config_bytes or _sha256(config_bytes) != image.config_digest:
        _fail("Syft embedded config bytes differ from the OCI config")
    if (
        manifest != _json_bytes(image.manifest_bytes, "retained manifest")
        or config != image.config
    ):
        _fail("Syft embedded JSON differs from the retained OCI objects")
    # Syft's pinned OCI provider records each squashed layer by DiffID and
    # payload-file size here.  The embedded manifest above separately proves
    # the compressed descriptor digest and size.
    expected_layers = [
        {
            "mediaType": OCI_LAYER,
            "digest": image.diff_ids[0],
            "size": image.certificate.size,
        },
        {
            "mediaType": OCI_LAYER,
            "digest": image.diff_ids[1],
            "size": image.verifier.size,
        },
    ]
    if metadata.get("layers") != expected_layers:
        _fail("Syft DiffID/file-size layers do not match the retained OCI child")
    if metadata.get("imageSize") != image.certificate.size + image.verifier.size:
        _fail("Syft image size does not match the retained runtime files")
    if metadata.get("tags") not in ([], None):
        _fail("raw Syft layout scan unexpectedly carries mutable tags")
    if metadata.get("repoDigests") not in ([], None):
        _fail("raw Syft layout scan unexpectedly carries registry digests")
    if metadata.get("architecture") not in ("", image.architecture):
        _fail("Syft metadata architecture conflicts with the retained child")
    if metadata.get("os") not in ("", "linux"):
        _fail("Syft metadata OS conflicts with the retained child")
    if metadata.get("labels") != EXPECTED_LABELS:
        _fail("Syft runtime labels differ from the exact verifier labels")
    _validate_syft_file(report, image)
    inventory, count = _syft_inventory(report, image=image)
    inventory_sha256 = _check_inventory(inventory, "Syft")
    return ReportResult(report, snapshot, inventory, inventory_sha256, count)


def _trivy_inventory(
    report: dict[str, Any], *, image: PlatformImage
) -> tuple[dict[str, str], int]:
    results = _list(report.get("Results"), "Trivy results")
    if len(results) != 1:
        _fail("Trivy must contain exactly one Go-binary result")
    result = _object(results[0], "Trivy Go result")
    if (
        result.get("Target") != "ko-app/cosign"
        or result.get("Class") != "lang-pkgs"
        or result.get("Type") != "gobinary"
    ):
        _fail("Trivy result is not the exact verifier Go binary")
    for field in ("Vulnerabilities", "Misconfigurations", "Secrets"):
        if field in result and result[field] not in (None, []):
            _fail(f"Trivy reported forbidden {field.lower()}")
    packages = _list(result.get("Packages"), "Trivy Go packages")
    inventory: dict[str, str] = {}
    main_count = 0
    main_dependencies: list[str] | None = None
    for position, raw_package in enumerate(packages):
        package = _object(raw_package, f"Trivy package[{position}]")
        name = package.get("Name")
        version = package.get("Version")
        if not isinstance(name, str) or not name or name in inventory:
            _fail("Trivy Go inventory contains a missing or duplicate package name")
        layer = _object(package.get("Layer"), f"Trivy {name} layer")
        identifier = _object(package.get("Identifier"), f"Trivy {name} identifier")
        if (
            layer.get("DiffID") != image.verifier.diff_id
            or package.get("AnalyzedBy") != "gobinary"
        ):
            _fail(f"Trivy package is not bound to the exact verifier layer: {name}")
        purl = identifier.get("PURL")
        if name == MAIN_MODULE:
            main_count += 1
            if (
                version is not None
                or package.get("ID") != MAIN_MODULE
                or purl != f"pkg:golang/{MAIN_MODULE}"
                or package.get("Relationship") != "root"
            ):
                _fail("Trivy main module is not the one reviewed null-version placeholder")
            dependencies = package.get("DependsOn")
            if not isinstance(dependencies, list) or not all(
                isinstance(item, str) for item in dependencies
            ):
                _fail("Trivy main-module dependency graph is absent")
            main_dependencies = dependencies
            inventory[name] = ""
        else:
            if not isinstance(version, str) or not version:
                _fail(f"Trivy has an unauthorized missing package version: {name}")
            if package.get("ID") != f"{name}@{version}":
                _fail(f"Trivy package ID does not match its exact identity: {name}")
            expected_purl = (
                f"pkg:golang/{name.lower()}@{quote(version, safe='.-_~')}"
            )
            if purl != expected_purl:
                _fail(f"Trivy package PURL does not match its exact identity: {name}")
            inventory[name] = "go" + version.removeprefix("v") if name == "stdlib" else version
    if main_count != 1 or main_dependencies is None:
        _fail("Trivy must contain exactly one reviewed main-module placeholder")
    expected_dependencies = {
        f"{name}@{'v' + version.removeprefix('go') if name == 'stdlib' else version}"
        for name, version in inventory.items()
        if name != MAIN_MODULE
    }
    if (
        len(main_dependencies) != len(set(main_dependencies))
        or set(main_dependencies) != expected_dependencies
    ):
        _fail("Trivy main-module dependency closure differs from its package inventory")
    return inventory, len(packages)


def _validate_trivy(
    path: Path,
    *,
    image: PlatformImage,
    raw_identity: str,
    immutable_identity: str | None,
) -> ReportResult:
    report, snapshot = _load_json(
        path,
        maximum=MAX_REPORT_BYTES,
        label=f"{image.platform} Trivy report",
    )
    _exact_keys(
        report,
        {
            "SchemaVersion",
            "CreatedAt",
            "ArtifactName",
            "ArtifactType",
            "ArtifactID",
            "Metadata",
            "Results",
            "ReportID",
            "Trivy",
        },
        "Trivy report",
    )
    if report.get("SchemaVersion") != 2:
        _fail("Trivy report schema is not supported")
    tool = _object(report.get("Trivy"), "Trivy tool identity")
    if tool != {"Version": EXPECTED_TRIVY_VERSION}:
        _fail("Trivy tool identity is not pinned")
    _timestamp(report.get("CreatedAt"), "Trivy report CreatedAt")
    if not isinstance(report.get("ReportID"), str) or not report["ReportID"]:
        _fail("Trivy report ID is absent")
    expected_name = immutable_identity if immutable_identity is not None else raw_identity
    if (
        report.get("ArtifactName") != expected_name
        or report.get("ArtifactType") != "container_image"
        or report.get("ArtifactID") != image.config_digest
    ):
        _fail("Trivy artifact identity is pre-normalized, unrelated, or malformed")
    metadata = _object(report.get("Metadata"), "Trivy image metadata")
    if (
        metadata.get("ImageID") != image.config_digest
        or metadata.get("DiffIDs") != list(image.diff_ids)
        or metadata.get("ImageConfig") != image.config
        or metadata.get("Size") != sum(image.layer_uncompressed_sizes)
    ):
        _fail("Trivy metadata does not match the retained config and DiffIDs")
    layers = _list(metadata.get("Layers"), "Trivy image layers")
    if len(layers) != len(image.compressed_layers):
        _fail("Trivy layer count differs from the retained child")
    for position, (raw_layer, descriptor, diff_id, uncompressed_size) in enumerate(
        zip(
            layers,
            image.compressed_layers,
            image.diff_ids,
            image.layer_uncompressed_sizes,
            strict=True,
        )
    ):
        layer = _object(raw_layer, f"Trivy layer[{position}]")
        if layer.get("Digest") != descriptor["digest"] or layer.get("DiffID") != diff_id:
            _fail("Trivy layer identity differs from the retained OCI child")
        if "Size" in layer and layer["Size"] not in (descriptor["size"], uncompressed_size):
            _fail("Trivy layer size differs from both valid OCI size representations")
    if metadata.get("RepoTags") not in (None, []):
        _fail("raw Trivy layout scan unexpectedly carries mutable tags")
    if metadata.get("RepoDigests") not in (None, []):
        _fail("raw Trivy layout scan unexpectedly carries registry digests")
    if metadata.get("Reference") not in (None, ""):
        _fail("raw Trivy layout scan unexpectedly carries a mutable reference")
    inventory, count = _trivy_inventory(report, image=image)
    inventory_sha256 = _check_inventory(inventory, "Trivy")
    return ReportResult(report, snapshot, inventory, inventory_sha256, count)


def _database_binding(lock_path: Path, evidence_path: Path) -> dict[str, Any]:
    try:
        lock, lock_sha256 = load_trivy_db_lock(lock_path)
        evidence, evidence_sha256 = load_trivy_db_evidence(
            evidence_path, lock, lock_sha256
        )
    except TrivyDBError as exc:
        raise ValidationError(f"Trivy database evidence is invalid: {exc}") from exc
    return {
        "assurance": "reviewed digest-locked; not signed or authenticated",
        "repository": evidence["repository"],
        "manifest_digest": evidence["manifest_digest"],
        "layer_digest": evidence["layer_digest"],
        "layer_size": evidence["layer_size"],
        "database_schema_version": evidence["database_schema_version"],
        "db_sha256": evidence["db_sha256"],
        "db_size": evidence["db_size"],
        "metadata_sha256": evidence["metadata_sha256"],
        "metadata_size": evidence["metadata_size"],
        "updated_at": evidence["updated_at"],
        "next_update": evidence["next_update"],
        "prepared_at": evidence["prepared_at"],
        "lock_sha256": lock_sha256,
        "evidence_sha256": evidence_sha256,
    }


def validate(
    *,
    layout: Path,
    index_digest: str,
    repository: str,
    tag: str,
    scan_layouts: dict[str, Path],
    syft_paths: dict[str, Path],
    trivy_paths: dict[str, Path],
    trivy_db_lock: Path,
    trivy_db_evidence: Path,
    summary: Path,
) -> dict[str, Any]:
    if set(syft_paths) != set(EXPECTED_PLATFORMS) or set(trivy_paths) != set(EXPECTED_PLATFORMS):
        _fail("scanner inputs must cover exactly linux/amd64 and linux/arm64")
    all_inputs = [*syft_paths.values(), *trivy_paths.values(), trivy_db_lock, trivy_db_evidence]
    canonical_inputs = [path.resolve(strict=False) for path in all_inputs]
    if len(canonical_inputs) != len(set(canonical_inputs)):
        _fail("scanner and Trivy DB evidence paths must all be distinct")
    summary_path = _secure_output(summary)
    if summary_path.resolve(strict=False) in set(canonical_inputs):
        _fail("summary must not replace an input evidence file")

    images, layout_binding, raw_identities = preflight(
        layout=layout,
        index_digest=index_digest,
        repository=repository,
        tag=tag,
        scan_layouts=scan_layouts,
    )
    # Syft 1.51.0 canonicalizes ``oci-dir:/absolute/path`` to the bare path.
    # Trivy reports the same bare projected-layout input path.
    raw_reports: dict[str, tuple[ReportResult, ReportResult]] = {}
    for platform in EXPECTED_PLATFORMS:
        image = images[platform]
        immutable = f"{repository}@{image.manifest_digest}"
        syft = _validate_syft(
            syft_paths[platform],
            image=image,
            raw_identity=raw_identities[platform],
            immutable_identity=None,
        )
        trivy = _validate_trivy(
            trivy_paths[platform],
            image=image,
            raw_identity=raw_identities[platform],
            immutable_identity=None,
        )
        if syft.inventory != trivy.inventory:
            _fail(f"{platform} Syft and Trivy complete Go inventories differ")
        if syft.inventory_sha256 != trivy.inventory_sha256:
            _fail(f"{platform} scanner inventory digests differ")
        raw_reports[platform] = (syft, trivy)
    if raw_reports["linux/amd64"][0].inventory != raw_reports["linux/arm64"][0].inventory:
        _fail("the two platform verifier binaries do not have the same exact Go graph")

    database = _database_binding(trivy_db_lock, trivy_db_evidence)

    # Mutation happens only after every layout, report, graph, vulnerability,
    # and database check has passed.  Each replacement is same-directory and
    # atomic; the original object is re-proved immediately afterwards.
    for platform in EXPECTED_PLATFORMS:
        image = images[platform]
        immutable = f"{repository}@{image.manifest_digest}"
        syft, trivy = raw_reports[platform]
        syft.document["source"]["metadata"]["userInput"] = immutable
        trivy.document["ArtifactName"] = immutable
        _atomic_replace_json(syft.snapshot, syft.document, f"{platform} Syft report")
        _atomic_replace_json(trivy.snapshot, trivy.document, f"{platform} Trivy report")

    normalized: dict[str, tuple[ReportResult, ReportResult]] = {}
    for platform in EXPECTED_PLATFORMS:
        image = images[platform]
        immutable = f"{repository}@{image.manifest_digest}"
        syft = _validate_syft(
            syft_paths[platform],
            image=image,
            raw_identity=raw_identities[platform],
            immutable_identity=immutable,
        )
        trivy = _validate_trivy(
            trivy_paths[platform],
            image=image,
            raw_identity=raw_identities[platform],
            immutable_identity=immutable,
        )
        if syft.inventory != trivy.inventory:
            _fail(f"{platform} normalized scanner inventories differ")
        normalized[platform] = (syft, trivy)

    platform_summary: dict[str, Any] = {}
    for platform in EXPECTED_PLATFORMS:
        image = images[platform]
        syft, trivy = normalized[platform]
        platform_summary[platform] = {
            "reference": f"{repository}@{image.manifest_digest}",
            "manifest_digest": image.manifest_digest,
            "config_digest": image.config_digest,
            "layers": [
                {
                    "digest": descriptor["digest"],
                    "size": descriptor["size"],
                    "diff_id": diff_id,
                    "uncompressed_size": uncompressed_size,
                }
                for descriptor, diff_id, uncompressed_size in zip(
                    image.compressed_layers,
                    image.diff_ids,
                    image.layer_uncompressed_sizes,
                    strict=True,
                )
            ],
            "ca_bundle_sha256": image.certificate.sha256,
            "verifier_sha256": image.verifier.sha256,
            "go_inventory_sha256": syft.inventory_sha256,
            "go_package_count": syft.package_count,
            "syft_report_sha256": hashlib.sha256(syft.snapshot.payload).hexdigest(),
            "trivy_report_sha256": hashlib.sha256(trivy.snapshot.payload).hexdigest(),
            "high_critical_vulnerabilities": 0,
        }
    result = {
        "schema_version": 1,
        "repository": repository,
        "tag": tag,
        "tagged_reference": f"{repository}:{tag}",
        "index_digest": index_digest,
        "layout_control_sha256": layout_binding,
        "module_graph_sha256": EXPECTED_MODULE_GRAPH_SHA256,
        "scanner_versions": {
            "syft": EXPECTED_SYFT_VERSION,
            "trivy": EXPECTED_TRIVY_VERSION,
        },
        "platforms": platform_summary,
        "trivy_database": database,
    }
    _write_summary(summary_path, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--index-digest", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--scan-layout-amd64", type=Path, required=True)
    parser.add_argument("--scan-layout-arm64", type=Path, required=True)
    parser.add_argument("--syft-amd64", type=Path, required=True)
    parser.add_argument("--trivy-amd64", type=Path, required=True)
    parser.add_argument("--syft-arm64", type=Path, required=True)
    parser.add_argument("--trivy-arm64", type=Path, required=True)
    parser.add_argument("--trivy-db-lock", type=Path, required=True)
    parser.add_argument("--trivy-db-evidence", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        validate(
            layout=arguments.layout,
            index_digest=arguments.index_digest,
            repository=arguments.repository,
            tag=arguments.tag,
            scan_layouts={
                "linux/amd64": arguments.scan_layout_amd64,
                "linux/arm64": arguments.scan_layout_arm64,
            },
            syft_paths={
                "linux/amd64": arguments.syft_amd64,
                "linux/arm64": arguments.syft_arm64,
            },
            trivy_paths={
                "linux/amd64": arguments.trivy_amd64,
                "linux/arm64": arguments.trivy_arm64,
            },
            trivy_db_lock=arguments.trivy_db_lock,
            trivy_db_evidence=arguments.trivy_db_evidence,
            summary=arguments.summary,
        )
        return 0
    except (OSError, ValidationError, json.JSONDecodeError) as exc:
        print(f"release verifier layout validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
