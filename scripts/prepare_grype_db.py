#!/usr/bin/env python3
"""Prepare and verify one hash-locked Grype vulnerability database."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


MAX_CONTROL_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_DATABASE_BYTES = 4 * 1024 * 1024 * 1024
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
UTC_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
GRYPE_VERSION = "0.116.1"


class GrypeDBError(RuntimeError):
    """A Grype database input or output failed closed validation."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise GrypeDBError("the locked Grype database URL unexpectedly redirected")


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise GrypeDBError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GrypeDBError(f"cannot inspect {label}: {exc}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= MAX_CONTROL_BYTES
    ):
        raise GrypeDBError(f"{label} must be a bounded single-link regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise GrypeDBError(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            payload = stream.read(MAX_CONTROL_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) != metadata.st_size:
        raise GrypeDBError(f"{label} changed while it was read")
    try:
        document = json.loads(payload, object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GrypeDBError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise GrypeDBError(f"{label} must be a JSON object")
    return document, payload


def _exact(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise GrypeDBError(f"{label} has unexpected or missing keys")


def _integer(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
        raise GrypeDBError(f"{label} is outside its permitted range")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX_SHA256.fullmatch(value) is None:
        raise GrypeDBError(f"{label} must be lowercase SHA-256")
    return value


def _time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_TIMESTAMP.fullmatch(value) is None:
        raise GrypeDBError(f"{label} must be a whole-second UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise GrypeDBError(f"{label} is not a valid timestamp") from exc


def _validate_lock(lock: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    _exact(lock, {"schema_version", "archive", "database"}, "Grype DB lock")
    if lock["schema_version"] != 1:
        raise GrypeDBError("unsupported Grype DB lock schema")
    archive = lock["archive"]
    database = lock["database"]
    if not isinstance(archive, dict) or not isinstance(database, dict):
        raise GrypeDBError("Grype DB lock records must be objects")
    _exact(archive, {"url", "sha256", "size"}, "lock.archive")
    _exact(
        database,
        {
            "schema_version",
            "built_at",
            "valid_until",
            "sha256",
            "size",
            "import_metadata_sha256",
            "import_metadata_size",
        },
        "lock.database",
    )
    url = archive["url"]
    if not isinstance(url, str):
        raise GrypeDBError("lock.archive.url must be a string")
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
    archive_sha = _sha(archive["sha256"], "lock.archive.sha256")
    if (
        parsed.scheme != "https"
        or parsed.hostname != "grype.anchore.io"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.fragment
        or not re.fullmatch(r"/databases/v6/vulnerability-db_v6\.[0-9]+\.[0-9]+_[0-9TZ:-]+_[0-9]+\.tar\.zst", parsed.path)
        or query != {"checksum": [f"sha256:{archive_sha}"]}
    ):
        raise GrypeDBError("lock.archive.url is not the exact official Grype v6 archive form")
    _integer(archive["size"], "lock.archive.size", MAX_ARCHIVE_BYTES)
    if not isinstance(database["schema_version"], str) or re.fullmatch(
        r"v6\.[0-9]+\.[0-9]+", database["schema_version"]
    ) is None:
        raise GrypeDBError("lock.database.schema_version is not a Grype v6 schema")
    built = _time(database["built_at"], "lock.database.built_at")
    valid_until = _time(database["valid_until"], "lock.database.valid_until")
    if not built < valid_until or valid_until - built > timedelta(days=5):
        raise GrypeDBError("the Grype database freshness window is invalid")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if current < built or current >= valid_until:
        raise GrypeDBError("the reviewed Grype database lock is not currently fresh")
    _sha(database["sha256"], "lock.database.sha256")
    _integer(database["size"], "lock.database.size", MAX_DATABASE_BYTES)
    _sha(database["import_metadata_sha256"], "lock.database.import_metadata_sha256")
    _integer(database["import_metadata_size"], "lock.database.import_metadata_size", MAX_CONTROL_BYTES)
    return lock


def _hash_file(path: Path, size: int, maximum: int, label: str) -> str:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size != size
        or size > maximum
    ):
        raise GrypeDBError(f"{label} has an unsafe type, link count, or size")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise GrypeDBError(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    after = path.lstat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    ):
        raise GrypeDBError(f"{label} changed while it was hashed")
    return digest.hexdigest()


def _tool_env(cache_dir: Path, home: Path) -> dict[str, str]:
    return {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "GRYPE_DB_CACHE_DIR": str(cache_dir),
        "GRYPE_DB_AUTO_UPDATE": "false",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_DB_VALIDATE_AGE": "true",
        "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": "120h",
    }


def _tool_version(grype: Path, env: dict[str, str], home: Path) -> None:
    result = subprocess.run(
        [str(grype), "version"], cwd=home, env=env, check=True, capture_output=True, text=True, timeout=30
    )
    if not re.search(rf"^Version:\s+{re.escape(GRYPE_VERSION)}$", result.stdout, re.MULTILINE):
        raise GrypeDBError("the Grype binary does not match the reviewed version")


def _status(grype: Path, env: dict[str, str], home: Path, lock: dict[str, Any], cache_dir: Path) -> None:
    result = subprocess.run(
        [str(grype), "db", "status", "--output", "json"],
        cwd=home,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    try:
        status_document = json.loads(result.stdout, object_pairs_hook=_pairs)
    except json.JSONDecodeError as exc:
        raise GrypeDBError("Grype DB status is not valid JSON") from exc
    expected_path = (cache_dir / "6" / "vulnerability.db").resolve(strict=True)
    if status_document != {
        "schemaVersion": lock["database"]["schema_version"],
        "from": "manual import",
        "built": lock["database"]["built_at"],
        "path": str(expected_path),
        "valid": True,
    }:
        raise GrypeDBError("Grype DB status differs from the reviewed lock")


def _verify_cache(cache_dir: Path, lock: dict[str, Any]) -> None:
    schema_dir = cache_dir / "6"
    if cache_dir.is_symlink() or schema_dir.is_symlink() or not schema_dir.is_dir():
        raise GrypeDBError("the Grype cache layout is unsafe")
    files = {path.relative_to(cache_dir).as_posix() for path in cache_dir.rglob("*") if path.is_file()}
    if files != {"6/import.json", "6/vulnerability.db"}:
        raise GrypeDBError("the Grype cache contains unexpected files")
    database = lock["database"]
    if _hash_file(
        schema_dir / "vulnerability.db", database["size"], MAX_DATABASE_BYTES, "Grype database"
    ) != database["sha256"]:
        raise GrypeDBError("the prepared Grype database digest differs from the lock")
    if _hash_file(
        schema_dir / "import.json",
        database["import_metadata_size"],
        MAX_CONTROL_BYTES,
        "Grype import metadata",
    ) != database["import_metadata_sha256"]:
        raise GrypeDBError("the Grype import metadata digest differs from the lock")


def _write_evidence(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise GrypeDBError("refusing a pre-existing Grype evidence path")
    path.parent.resolve(strict=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def prepare(lock_path: Path, grype: Path, cache_dir: Path, evidence_path: Path) -> None:
    lock_document, lock_bytes = _load(lock_path, "Grype DB lock")
    lock = _validate_lock(lock_document)
    if cache_dir.exists() or cache_dir.is_symlink():
        raise GrypeDBError("refusing a pre-existing Grype cache path")
    cache_dir.parent.resolve(strict=True)
    cache_dir.mkdir(mode=0o700)
    home = cache_dir / ".home"
    home.mkdir(mode=0o700)
    env = _tool_env(cache_dir, home)
    _tool_version(grype.resolve(strict=True), env, home)
    archive = lock["archive"]
    descriptor, archive_name = tempfile.mkstemp(prefix="grype-db.", suffix=".tar.zst", dir=cache_dir.parent)
    archive_path = Path(archive_name)
    try:
        digest = hashlib.sha256()
        count = 0
        request = urllib.request.Request(archive["url"], headers={"User-Agent": "backupsheep-grype-db-lock/1"})
        opener = urllib.request.build_opener(_NoRedirect)
        with os.fdopen(descriptor, "wb") as output, opener.open(request, timeout=120) as response:
            if response.geturl() != archive["url"] or response.status != 200:
                raise GrypeDBError("the Grype database response identity is unexpected")
            length = response.headers.get("Content-Length")
            if length is None or int(length) != archive["size"]:
                raise GrypeDBError("the Grype database response size differs from the lock")
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                count += len(chunk)
                if count > MAX_ARCHIVE_BYTES:
                    raise GrypeDBError("the Grype database archive exceeds its size bound")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if count != archive["size"] or digest.hexdigest() != archive["sha256"]:
            raise GrypeDBError("the downloaded Grype database archive differs from the lock")
        subprocess.run(
            [str(grype.resolve(strict=True)), "db", "import", str(archive_path), "--quiet"],
            cwd=home,
            env=env,
            check=True,
            timeout=600,
        )
    finally:
        archive_path.unlink(missing_ok=True)
    home.rmdir()
    _verify_cache(cache_dir, lock)
    _status(grype.resolve(strict=True), env | {"HOME": str(cache_dir.parent)}, cache_dir.parent, lock, cache_dir)
    prepared_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    evidence = {
        "schema_version": 1,
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "grype_version": GRYPE_VERSION,
        "prepared_at": prepared_at,
        "archive_sha256": archive["sha256"],
        "archive_size": archive["size"],
        "database_schema_version": lock["database"]["schema_version"],
        "database_built_at": lock["database"]["built_at"],
        "database_sha256": lock["database"]["sha256"],
        "database_size": lock["database"]["size"],
    }
    _write_evidence(evidence_path, evidence)


def verify(
    lock_path: Path,
    grype: Path,
    cache_dir: Path,
    evidence_path: Path,
    *,
    now: datetime | None = None,
) -> None:
    effective_now = now or datetime.now(timezone.utc)
    if effective_now.tzinfo is None:
        raise GrypeDBError("freshness time must be timezone aware")
    effective_now = effective_now.astimezone(timezone.utc)
    lock_document, lock_bytes = _load(lock_path, "Grype DB lock")
    lock = _validate_lock(lock_document, now=effective_now)
    evidence, _ = _load(evidence_path, "Grype DB evidence")
    _exact(
        evidence,
        {
            "schema_version",
            "lock_sha256",
            "grype_version",
            "prepared_at",
            "archive_sha256",
            "archive_size",
            "database_schema_version",
            "database_built_at",
            "database_sha256",
            "database_size",
        },
        "Grype DB evidence",
    )
    expected = {
        "schema_version": 1,
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "grype_version": GRYPE_VERSION,
        "archive_sha256": lock["archive"]["sha256"],
        "archive_size": lock["archive"]["size"],
        "database_schema_version": lock["database"]["schema_version"],
        "database_built_at": lock["database"]["built_at"],
        "database_sha256": lock["database"]["sha256"],
        "database_size": lock["database"]["size"],
    }
    if {key: value for key, value in evidence.items() if key != "prepared_at"} != expected:
        raise GrypeDBError("Grype DB evidence differs from the lock")
    prepared = _time(evidence["prepared_at"], "evidence.prepared_at")
    built = _time(lock["database"]["built_at"], "lock.database.built_at")
    if not built <= prepared <= effective_now:
        raise GrypeDBError("Grype DB preparation time is inconsistent")
    _verify_cache(cache_dir, lock)
    home = cache_dir.parent
    env = _tool_env(cache_dir, home)
    _tool_version(grype.resolve(strict=True), env, home)
    _status(grype.resolve(strict=True), env, home, lock, cache_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "verify"))
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--grype", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.mode == "prepare":
            prepare(arguments.lock, arguments.grype, arguments.cache_dir, arguments.evidence)
        else:
            verify(arguments.lock, arguments.grype, arguments.cache_dir, arguments.evidence)
        return 0
    except (OSError, ValueError, urllib.error.URLError, subprocess.SubprocessError, GrypeDBError) as exc:
        print(f"Grype database preparation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
