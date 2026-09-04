#!/usr/bin/env python3
"""Fetch and prepare the one reviewed, digest-locked Trivy vulnerability DB."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAX_LOCK_BYTES = 64 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_LAYER_BYTES = 512 * 1024 * 1024
MAX_DATABASE_BYTES = 4 * 1024 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024
ORAS_TIMEOUT_SECONDS = 600
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
EXPECTED_REPOSITORY = "ghcr.io/aquasecurity/trivy-db"
EXPECTED_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
EXPECTED_ARTIFACT_TYPE = "application/vnd.aquasec.trivy.config.v1+json"
EXPECTED_CONFIG_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"
EXPECTED_LAYER_MEDIA_TYPE = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
EXPECTED_LAYER_TITLE = "db.tar.gz"


class TrivyDBError(RuntimeError):
    """A reviewed Trivy DB input failed closed validation."""


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TrivyDBError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise TrivyDBError(f"non-finite JSON value is forbidden: {value}")


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unknown = sorted(set(value) - expected)
        raise TrivyDBError(
            f"{label} has invalid keys (missing={missing}, unknown={unknown})"
        )


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TrivyDBError(f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise TrivyDBError(f"{label} must be a non-empty string")
    return value


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TrivyDBError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise TrivyDBError(f"{label} is outside the permitted range")
    return value


def _digest(value: Any, label: str) -> str:
    value = _string(value, label)
    if DIGEST_RE.fullmatch(value) is None:
        raise TrivyDBError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _hex_sha256(value: Any, label: str) -> str:
    value = _string(value, label)
    if HEX_SHA256_RE.fullmatch(value) is None:
        raise TrivyDBError(f"{label} must be lowercase SHA-256")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    value = _string(value, label)
    if UTC_RE.fullmatch(value) is None:
        raise TrivyDBError(f"{label} must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise TrivyDBError(f"{label} is not a valid UTC timestamp") from exc
    return parsed


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _secure_existing_parent(path: Path, label: str) -> Path:
    if path.name in {"", ".", ".."}:
        raise TrivyDBError(f"{label} destination needs a plain final path component")
    requested_parent = path.parent.absolute()
    try:
        parent = requested_parent.resolve(strict=True)
    except OSError as exc:
        raise TrivyDBError(f"{label} parent does not exist") from exc
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise TrivyDBError(f"{label} parent does not exist: {current}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise TrivyDBError(f"{label} parent chain contains a non-directory or symlink")
    return parent


def _read_regular(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise TrivyDBError(f"cannot inspect {label}: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum_bytes
    ):
        raise TrivyDBError(f"{label} must be a bounded, single-link regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise TrivyDBError(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            payload = stream.read(maximum_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) != before.st_size or len(payload) > maximum_bytes:
        raise TrivyDBError(f"{label} changed while it was read")
    return payload


def _hash_regular(
    path: Path, *, expected_size: int, maximum_bytes: int, label: str
) -> str:
    try:
        before = path.lstat()
    except OSError as exc:
        raise TrivyDBError(f"cannot inspect {label}: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size != expected_size
        or before.st_size <= 0
        or before.st_size > maximum_bytes
    ):
        raise TrivyDBError(f"{label} has an unsafe type, link count, or size")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    count = 0
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise TrivyDBError(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                count += len(chunk)
                if count > maximum_bytes:
                    raise TrivyDBError(f"{label} exceeds its maximum size")
                digest.update(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    after = path.lstat()
    if count != expected_size or (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
        raise TrivyDBError(f"{label} changed while it was hashed")
    return digest.hexdigest()


def _load_json(path: Path, *, maximum_bytes: int, label: str) -> tuple[Any, bytes]:
    payload = _read_regular(path, maximum_bytes=maximum_bytes, label=label)
    try:
        document = json.loads(
            payload,
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise TrivyDBError(f"{label} is not valid UTF-8 JSON: {exc}") from exc
    return document, payload


def validate_lock_document(document: Any) -> dict[str, Any]:
    lock = _object(document, "Trivy DB lock")
    _exact_keys(lock, {"schema_version", "repository", "manifest", "database"}, "Trivy DB lock")
    if _integer(lock["schema_version"], "lock.schema_version", minimum=1, maximum=1) != 1:
        raise TrivyDBError("unsupported Trivy DB lock schema")
    if _string(lock["repository"], "lock.repository") != EXPECTED_REPOSITORY:
        raise TrivyDBError("the Trivy DB lock must use the official GHCR repository")

    manifest = _object(lock["manifest"], "lock.manifest")
    _exact_keys(
        manifest,
        {"digest", "size", "media_type", "artifact_type", "created_at", "config", "layer"},
        "lock.manifest",
    )
    _digest(manifest["digest"], "lock.manifest.digest")
    _integer(manifest["size"], "lock.manifest.size", minimum=1, maximum=MAX_MANIFEST_BYTES)
    if manifest["media_type"] != EXPECTED_MANIFEST_MEDIA_TYPE:
        raise TrivyDBError("lock.manifest.media_type is unsupported")
    if manifest["artifact_type"] != EXPECTED_ARTIFACT_TYPE:
        raise TrivyDBError("lock.manifest.artifact_type is unsupported")
    created_at = _timestamp(manifest["created_at"], "lock.manifest.created_at")

    config = _object(manifest["config"], "lock.manifest.config")
    _exact_keys(config, {"mediaType", "digest", "size", "data"}, "lock.manifest.config")
    if config["mediaType"] != EXPECTED_CONFIG_MEDIA_TYPE:
        raise TrivyDBError("lock.manifest.config media type is unsupported")
    if _digest(config["digest"], "lock.manifest.config.digest") != (
        "sha256:" + _sha256_bytes(b"{}")
    ):
        raise TrivyDBError("lock.manifest.config does not identify the OCI empty object")
    if _integer(config["size"], "lock.manifest.config.size", minimum=2, maximum=2) != 2:
        raise TrivyDBError("lock.manifest.config size is not exact")
    if config["data"] != "e30=":
        raise TrivyDBError("lock.manifest.config data is not the OCI empty object")

    layer = _object(manifest["layer"], "lock.manifest.layer")
    _exact_keys(layer, {"mediaType", "digest", "size", "annotations"}, "lock.manifest.layer")
    if layer["mediaType"] != EXPECTED_LAYER_MEDIA_TYPE:
        raise TrivyDBError("lock.manifest.layer media type is unsupported")
    _digest(layer["digest"], "lock.manifest.layer.digest")
    _integer(layer["size"], "lock.manifest.layer.size", minimum=1, maximum=MAX_LAYER_BYTES)
    annotations = _object(layer["annotations"], "lock.manifest.layer.annotations")
    if annotations != {"org.opencontainers.image.title": EXPECTED_LAYER_TITLE}:
        raise TrivyDBError("lock.manifest.layer title is not exact")

    database = _object(lock["database"], "lock.database")
    _exact_keys(
        database,
        {
            "schema_version",
            "updated_at",
            "next_update",
            "downloaded_at",
            "metadata_sha256",
            "metadata_size",
            "db_sha256",
            "db_size",
        },
        "lock.database",
    )
    if _integer(database["schema_version"], "lock.database.schema_version", minimum=2, maximum=2) != 2:
        raise TrivyDBError("only Trivy DB schema 2 is supported")
    updated_at = _timestamp(database["updated_at"], "lock.database.updated_at")
    next_update = _timestamp(database["next_update"], "lock.database.next_update")
    downloaded_at = _timestamp(database["downloaded_at"], "lock.database.downloaded_at")
    if database["downloaded_at"] != "0001-01-01T00:00:00Z":
        raise TrivyDBError("the locked upstream metadata must not claim a local download time")
    if not updated_at <= created_at < next_update or downloaded_at >= updated_at:
        raise TrivyDBError("Trivy DB lock timestamps are inconsistent")
    _hex_sha256(database["metadata_sha256"], "lock.database.metadata_sha256")
    _integer(database["metadata_size"], "lock.database.metadata_size", minimum=1, maximum=MAX_METADATA_BYTES)
    _hex_sha256(database["db_sha256"], "lock.database.db_sha256")
    _integer(database["db_size"], "lock.database.db_size", minimum=1, maximum=MAX_DATABASE_BYTES)
    return lock


def require_fresh(lock: dict[str, Any], now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise TrivyDBError("freshness time must be timezone aware")
    now = now.astimezone(timezone.utc)
    created_at = _timestamp(lock["manifest"]["created_at"], "lock.manifest.created_at")
    next_update = _timestamp(lock["database"]["next_update"], "lock.database.next_update")
    if now < created_at:
        raise TrivyDBError("system clock predates the locked Trivy DB artifact")
    if now >= next_update:
        raise TrivyDBError(
            "the reviewed Trivy DB lock is stale; refresh and review the lock before scanning"
        )
    return now


def load_lock(
    path: Path, *, now: datetime | None = None, check_freshness: bool = True
) -> tuple[dict[str, Any], str]:
    document, payload = _load_json(path, maximum_bytes=MAX_LOCK_BYTES, label="Trivy DB lock")
    lock = validate_lock_document(document)
    if check_freshness:
        require_fresh(lock, now)
    return lock, _sha256_bytes(payload)


def _validate_manifest(path: Path, lock: dict[str, Any]) -> None:
    manifest, payload = _load_json(
        path, maximum_bytes=MAX_MANIFEST_BYTES, label="fetched Trivy DB manifest"
    )
    locked = lock["manifest"]
    if len(payload) != locked["size"]:
        raise TrivyDBError("fetched Trivy DB manifest size does not match the lock")
    if "sha256:" + _sha256_bytes(payload) != locked["digest"]:
        raise TrivyDBError("fetched Trivy DB manifest bytes do not match the lock")
    expected = {
        "schemaVersion": 2,
        "mediaType": locked["media_type"],
        "artifactType": locked["artifact_type"],
        "config": locked["config"],
        "layers": [locked["layer"]],
        "annotations": {"org.opencontainers.image.created": locked["created_at"]},
    }
    if manifest != expected:
        raise TrivyDBError("fetched Trivy DB manifest structure differs from the reviewed lock")


def _metadata_document(lock: dict[str, Any]) -> dict[str, Any]:
    database = lock["database"]
    return {
        "Version": database["schema_version"],
        "NextUpdate": database["next_update"],
        "UpdatedAt": database["updated_at"],
        "DownloadedAt": database["downloaded_at"],
    }


def _extract_database(layer_path: Path, destination: Path, lock: dict[str, Any]) -> None:
    layer = lock["manifest"]["layer"]
    actual_layer_hash = _hash_regular(
        layer_path,
        expected_size=layer["size"],
        maximum_bytes=MAX_LAYER_BYTES,
        label="fetched Trivy DB layer",
    )
    if actual_layer_hash != layer["digest"].removeprefix("sha256:"):
        raise TrivyDBError("fetched Trivy DB layer bytes do not match the lock")

    os.mkdir(destination, 0o700)
    expected_members = {
        "trivy.db": (
            lock["database"]["db_size"],
            lock["database"]["db_sha256"],
            MAX_DATABASE_BYTES,
        ),
        "metadata.json": (
            lock["database"]["metadata_size"],
            lock["database"]["metadata_sha256"],
            MAX_METADATA_BYTES,
        ),
    }
    try:
        with tarfile.open(layer_path, mode="r:gz") as archive:
            if archive.pax_headers:
                raise TrivyDBError("Trivy DB archive has unexpected global PAX headers")
            members = archive.getmembers()
            if len(members) != len(expected_members):
                raise TrivyDBError("Trivy DB archive must contain exactly two files")
            if len({member.name for member in members}) != len(members):
                raise TrivyDBError("Trivy DB archive contains duplicate members")
            for member in members:
                if (
                    member.name not in expected_members
                    or not member.isfile()
                    or member.issym()
                    or member.islnk()
                    or member.linkname
                    or member.pax_headers
                ):
                    raise TrivyDBError("Trivy DB archive contains an unsafe member")
                expected_size, expected_hash, maximum_size = expected_members[member.name]
                if member.size != expected_size or member.size > maximum_size:
                    raise TrivyDBError(f"Trivy DB archive member size is wrong: {member.name}")
                source = archive.extractfile(member)
                if source is None:
                    raise TrivyDBError(f"Trivy DB archive member is unreadable: {member.name}")
                target = destination / member.name
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o400,
                )
                digest = hashlib.sha256()
                count = 0
                try:
                    with source, os.fdopen(descriptor, "wb") as output:
                        descriptor = -1
                        for chunk in iter(lambda: source.read(1024 * 1024), b""):
                            count += len(chunk)
                            if count > maximum_size:
                                raise TrivyDBError(f"Trivy DB archive member is oversized: {member.name}")
                            digest.update(chunk)
                            output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                if count != expected_size or digest.hexdigest() != expected_hash:
                    raise TrivyDBError(f"Trivy DB archive member does not match the lock: {member.name}")
                os.chmod(target, 0o400)
    except (OSError, tarfile.TarError) as exc:
        raise TrivyDBError(f"Trivy DB layer is not a valid reviewed archive: {exc}") from exc

    metadata, _ = _load_json(
        destination / "metadata.json",
        maximum_bytes=MAX_METADATA_BYTES,
        label="extracted Trivy DB metadata",
    )
    if metadata != _metadata_document(lock):
        raise TrivyDBError("extracted Trivy DB metadata differs from the reviewed lock")
    os.chmod(destination, 0o500)


def _validate_executable(path: Path) -> None:
    if not path.is_absolute():
        raise TrivyDBError("pinned ORAS executable path must be absolute")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise TrivyDBError(f"cannot inspect pinned ORAS executable: {exc}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
        or not metadata.st_mode & stat.S_IXUSR
    ):
        raise TrivyDBError("pinned ORAS executable is not a safe owner-controlled regular file")


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def _run_oras(executable: Path, arguments: list[str], working: Path) -> None:
    isolated_home = working / "home"
    isolated_config = working / "config"
    isolated_docker = working / "docker-config"
    for path in (isolated_home, isolated_config, isolated_docker):
        if not path.exists():
            os.mkdir(path, 0o700)
    environment = {
        "HOME": str(isolated_home),
        "XDG_CONFIG_HOME": str(isolated_config),
        "DOCKER_CONFIG": str(isolated_docker),
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
    }
    process = subprocess.Popen(
        [str(executable), *arguments],
        cwd=working,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=ORAS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(process)
        raise TrivyDBError("pinned ORAS timed out while fetching the Trivy DB") from exc
    if process.returncode:
        detail = (stderr or stdout)[:4096].decode("utf-8", errors="replace").strip()
        raise TrivyDBError(f"pinned ORAS failed to fetch the Trivy DB: {detail}")


def evidence_for(lock: dict[str, Any], lock_sha256: str, prepared_at: datetime) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "lock_sha256": lock_sha256,
        "repository": lock["repository"],
        "manifest_digest": lock["manifest"]["digest"],
        "manifest_size": lock["manifest"]["size"],
        "layer_digest": lock["manifest"]["layer"]["digest"],
        "layer_size": lock["manifest"]["layer"]["size"],
        "database_schema_version": lock["database"]["schema_version"],
        "updated_at": lock["database"]["updated_at"],
        "next_update": lock["database"]["next_update"],
        "metadata_sha256": lock["database"]["metadata_sha256"],
        "metadata_size": lock["database"]["metadata_size"],
        "db_sha256": lock["database"]["db_sha256"],
        "db_size": lock["database"]["db_size"],
        "prepared_at": prepared_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def validate_evidence_document(
    document: Any,
    lock: dict[str, Any],
    lock_sha256: str,
    *,
    now: datetime | None = None,
    check_freshness: bool = True,
) -> dict[str, Any]:
    evidence = _object(document, "Trivy DB evidence")
    expected_keys = set(evidence_for(lock, lock_sha256, datetime.now(timezone.utc)))
    _exact_keys(evidence, expected_keys, "Trivy DB evidence")
    prepared_at = _timestamp(evidence["prepared_at"], "evidence.prepared_at")
    expected = evidence_for(lock, lock_sha256, prepared_at)
    if evidence != expected:
        raise TrivyDBError("Trivy DB evidence does not exactly match its reviewed lock")
    if check_freshness:
        effective_now = require_fresh(lock, now)
        created_at = _timestamp(lock["manifest"]["created_at"], "lock.manifest.created_at")
        if prepared_at < created_at or prepared_at > effective_now:
            raise TrivyDBError("Trivy DB evidence preparation time is inconsistent")
    return evidence


def load_evidence(
    path: Path,
    lock: dict[str, Any],
    lock_sha256: str,
    *,
    now: datetime | None = None,
    check_freshness: bool = True,
) -> tuple[dict[str, Any], str]:
    document, payload = _load_json(
        path, maximum_bytes=MAX_EVIDENCE_BYTES, label="Trivy DB evidence"
    )
    evidence = validate_evidence_document(
        document,
        lock,
        lock_sha256,
        now=now,
        check_freshness=check_freshness,
    )
    return evidence, _sha256_bytes(payload)


def _write_exclusive_json(path: Path, document: dict[str, Any]) -> None:
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
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


def prepare(
    *,
    lock_path: Path,
    oras_path: Path,
    cache_dir: Path,
    evidence_path: Path,
    now: datetime | None = None,
) -> None:
    lock, lock_sha256 = load_lock(lock_path, now=now)
    prepared_at = require_fresh(lock, now)
    _validate_executable(oras_path)
    cache_parent = _secure_existing_parent(cache_dir, "Trivy cache")
    evidence_parent = _secure_existing_parent(evidence_path, "Trivy evidence")
    cache_target = cache_parent / cache_dir.name
    evidence_target = evidence_parent / evidence_path.name
    if os.path.lexists(cache_target) or os.path.lexists(evidence_target):
        raise TrivyDBError("Trivy cache and evidence destinations must not pre-exist")

    staging = Path(tempfile.mkdtemp(prefix=f".{cache_dir.name}.stage-", dir=cache_parent))
    try:
        downloads = staging / "downloads"
        os.mkdir(downloads, 0o700)
        manifest_path = downloads / "manifest.json"
        layer_path = downloads / EXPECTED_LAYER_TITLE
        manifest_reference = f"{lock['repository']}@{lock['manifest']['digest']}"
        _run_oras(
            oras_path,
            ["manifest", "fetch", "--output", str(manifest_path), manifest_reference],
            staging,
        )
        _validate_manifest(manifest_path, lock)
        _run_oras(
            oras_path,
            [
                "blob",
                "fetch",
                "--output",
                str(layer_path),
                f"{lock['repository']}@{lock['manifest']['layer']['digest']}",
            ],
            staging,
        )
        # O_EXCL-like directory creation at the final name prevents a same-UID
        # race from making a verified staging tree replace an unexpected path.
        # A crash can leave a partial directory, which future runs refuse to reuse.
        os.mkdir(cache_target, 0o700)
        _extract_database(layer_path, cache_target / "db", lock)
        _write_exclusive_json(
            evidence_target, evidence_for(lock, lock_sha256, prepared_at)
        )
        verify_cache(
            lock_path=lock_path,
            cache_dir=cache_target,
            evidence_path=evidence_target,
            now=prepared_at,
        )
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def verify_cache(
    *,
    lock_path: Path,
    cache_dir: Path,
    evidence_path: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    cache_dir = _secure_existing_parent(cache_dir, "Trivy cache") / cache_dir.name
    evidence_path = (
        _secure_existing_parent(evidence_path, "Trivy evidence")
        / evidence_path.name
    )
    lock, lock_sha256 = load_lock(lock_path, now=now)
    evidence, evidence_sha256 = load_evidence(
        evidence_path, lock, lock_sha256, now=now
    )
    try:
        cache_stat = cache_dir.lstat()
        db_dir = cache_dir / "db"
        db_stat = db_dir.lstat()
    except OSError as exc:
        raise TrivyDBError(f"prepared Trivy cache is absent: {exc}") from exc
    if (
        stat.S_ISLNK(cache_stat.st_mode)
        or not stat.S_ISDIR(cache_stat.st_mode)
        or stat.S_ISLNK(db_stat.st_mode)
        or not stat.S_ISDIR(db_stat.st_mode)
    ):
        raise TrivyDBError("prepared Trivy cache contains a symlink or non-directory")
    if {path.name for path in db_dir.iterdir()} != {"trivy.db", "metadata.json"}:
        raise TrivyDBError("prepared Trivy DB directory has unexpected contents")
    database = lock["database"]
    if _hash_regular(
        db_dir / "trivy.db",
        expected_size=database["db_size"],
        maximum_bytes=MAX_DATABASE_BYTES,
        label="prepared trivy.db",
    ) != database["db_sha256"]:
        raise TrivyDBError("prepared trivy.db does not match the reviewed lock")
    if _hash_regular(
        db_dir / "metadata.json",
        expected_size=database["metadata_size"],
        maximum_bytes=MAX_METADATA_BYTES,
        label="prepared Trivy metadata",
    ) != database["metadata_sha256"]:
        raise TrivyDBError("prepared Trivy metadata does not match the reviewed lock")
    metadata, _ = _load_json(
        db_dir / "metadata.json",
        maximum_bytes=MAX_METADATA_BYTES,
        label="prepared Trivy metadata",
    )
    if metadata != _metadata_document(lock):
        raise TrivyDBError("prepared Trivy metadata fields differ from the reviewed lock")
    return {
        **evidence,
        "evidence_sha256": evidence_sha256,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare", help="fetch and prepare the locked DB")
    prepare_parser.add_argument("--lock", type=Path, required=True)
    prepare_parser.add_argument("--oras", type=Path, required=True)
    prepare_parser.add_argument("--cache-dir", type=Path, required=True)
    prepare_parser.add_argument("--evidence", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify", help="re-verify a prepared cache")
    verify_parser.add_argument("--lock", type=Path, required=True)
    verify_parser.add_argument("--cache-dir", type=Path, required=True)
    verify_parser.add_argument("--evidence", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "prepare":
            prepare(
                lock_path=arguments.lock,
                oras_path=arguments.oras,
                cache_dir=arguments.cache_dir,
                evidence_path=arguments.evidence,
            )
        else:
            verify_cache(
                lock_path=arguments.lock,
                cache_dir=arguments.cache_dir,
                evidence_path=arguments.evidence,
            )
        return 0
    except (OSError, TrivyDBError) as exc:
        print(f"Trivy DB preparation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
