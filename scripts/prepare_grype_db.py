#!/usr/bin/env python3
"""Lock, prepare, and verify one hash-locked Grype vulnerability database."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO


MAX_CONTROL_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_DATABASE_BYTES = 4 * 1024 * 1024 * 1024
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
UTC_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
GRYPE_VERSION = "0.116.1"
DATABASE_BASE_URL = "https://grype.anchore.io/databases/v6"
ARCHIVE_PATH = re.compile(
    r"/databases/v6/vulnerability-db_v6\.[0-9]+\.[0-9]+_[0-9TZ:-]+_[0-9]+\.tar\.zst"
)
# Matches GRYPE_DB_MAX_ALLOWED_BUILT_AGE in _tool_env.
MAX_BUILT_AGE = timedelta(days=5)


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
        or ARCHIVE_PATH.fullmatch(parsed.path) is None
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
    if not built < valid_until or valid_until - built > MAX_BUILT_AGE:
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


def _status_document(grype: Path, env: dict[str, str], home: Path) -> Any:
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
        return json.loads(result.stdout, object_pairs_hook=_pairs)
    except json.JSONDecodeError as exc:
        raise GrypeDBError("Grype DB status is not valid JSON") from exc


def _status(grype: Path, env: dict[str, str], home: Path, lock: dict[str, Any], cache_dir: Path) -> None:
    status_document = _status_document(grype, env, home)
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


def _download(
    url: str, output: BinaryIO, *, maximum: int, expected_size: int | None = None
) -> tuple[str, int]:
    """Stream one exact-URL, bounded response into output and return its SHA-256."""
    request = urllib.request.Request(url, headers={"User-Agent": "backupsheep-grype-db-lock/1"})
    opener = urllib.request.build_opener(_NoRedirect)
    digest = hashlib.sha256()
    count = 0
    with opener.open(request, timeout=120) as response:
        if response.geturl() != url or response.status != 200:
            raise GrypeDBError("the Grype database response identity is unexpected")
        length = response.headers.get("Content-Length")
        if (
            length is None
            or int(length) > maximum
            or (expected_size is not None and int(length) != expected_size)
        ):
            raise GrypeDBError("the Grype database response size is missing or unexpected")
        for chunk in iter(lambda: response.read(1024 * 1024), b""):
            count += len(chunk)
            if count > maximum:
                raise GrypeDBError("the Grype database response exceeds its size bound")
            digest.update(chunk)
            output.write(chunk)
    if count != int(length):
        raise GrypeDBError("the Grype database response was truncated")
    return digest.hexdigest(), count


def _write_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise GrypeDBError("refusing a pre-existing Grype output path")
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


def resolve_lock(lock_path: Path, grype: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Write a lock for the v6 database Anchore currently publishes as latest."""
    if lock_path.exists() or lock_path.is_symlink():
        raise GrypeDBError("refusing a pre-existing Grype DB lock path")
    parent = lock_path.parent.resolve(strict=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{lock_path.name}.resolve-", dir=parent))
    try:
        listing_payload = io.BytesIO()
        _download(f"{DATABASE_BASE_URL}/latest.json", listing_payload, maximum=MAX_CONTROL_BYTES)
        try:
            listing = json.loads(listing_payload.getvalue(), object_pairs_hook=_pairs)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise GrypeDBError("the latest Grype database listing is not valid UTF-8 JSON") from exc
        if not isinstance(listing, dict):
            raise GrypeDBError("the latest Grype database listing must be a JSON object")
        _exact(
            listing,
            {"status", "schemaVersion", "built", "path", "checksum"},
            "latest Grype database listing",
        )
        checksum = listing["checksum"]
        if (
            listing["status"] != "active"
            or not isinstance(checksum, str)
            or not isinstance(listing["path"], str)
        ):
            raise GrypeDBError("the latest Grype database listing is not an active archive")
        archive_sha = _sha(checksum.removeprefix("sha256:"), "latest listing checksum")
        url = (
            f"{DATABASE_BASE_URL}/{listing['path']}"
            f"?checksum={urllib.parse.quote(checksum, safe='')}"
        )
        if ARCHIVE_PATH.fullmatch(urllib.parse.urlsplit(url).path) is None:
            raise GrypeDBError("the latest Grype database listing does not name an official v6 archive")

        cache_dir = staging / "cache"
        home = staging / "home"
        cache_dir.mkdir(mode=0o700)
        home.mkdir(mode=0o700)
        env = _tool_env(cache_dir, home)
        tool = grype.resolve(strict=True)
        _tool_version(tool, env, home)
        archive_path = staging / "archive.tar.zst"
        descriptor = os.open(
            archive_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            archive_digest, archive_size = _download(url, output, maximum=MAX_ARCHIVE_BYTES)
        if archive_digest != archive_sha:
            raise GrypeDBError("the latest Grype database archive differs from its published checksum")
        subprocess.run(
            [str(tool), "db", "import", str(archive_path), "--quiet"],
            cwd=home,
            env=env,
            check=True,
            timeout=600,
        )
        status = _status_document(tool, env, home)
        if (
            not isinstance(status, dict)
            or status.get("from") != "manual import"
            or status.get("valid") is not True
            or status.get("schemaVersion") != listing["schemaVersion"]
        ):
            raise GrypeDBError("the imported Grype database status differs from the latest listing")
        built = _time(status.get("built"), "Grype DB status built")
        database = cache_dir / "6" / "vulnerability.db"
        import_metadata = cache_dir / "6" / "import.json"
        database_size = database.lstat().st_size
        import_metadata_size = import_metadata.lstat().st_size
        lock = {
            "schema_version": 1,
            "archive": {"url": url, "sha256": archive_sha, "size": archive_size},
            "database": {
                "schema_version": status["schemaVersion"],
                "built_at": status["built"],
                "valid_until": (built + MAX_BUILT_AGE).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "sha256": _hash_file(
                    database, database_size, MAX_DATABASE_BYTES, "Grype database"
                ),
                "size": database_size,
                "import_metadata_sha256": _hash_file(
                    import_metadata,
                    import_metadata_size,
                    MAX_CONTROL_BYTES,
                    "Grype import metadata",
                ),
                "import_metadata_size": import_metadata_size,
            },
        }
        _validate_lock(lock, now=now)
        _write_json(lock_path, lock)
        return lock
    finally:
        shutil.rmtree(staging, ignore_errors=True)


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
        with os.fdopen(descriptor, "wb") as output:
            archive_sha256, count = _download(
                archive["url"],
                output,
                maximum=MAX_ARCHIVE_BYTES,
                expected_size=archive["size"],
            )
            output.flush()
            os.fsync(output.fileno())
        if count != archive["size"] or archive_sha256 != archive["sha256"]:
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
    _write_json(evidence_path, evidence)


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
    parser.add_argument("mode", choices=("lock", "prepare", "verify"))
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--grype", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--evidence", type=Path)
    arguments = parser.parse_args(argv)
    if arguments.mode != "lock" and (arguments.cache_dir is None or arguments.evidence is None):
        parser.error(f"{arguments.mode} requires --cache-dir and --evidence")
    try:
        if arguments.mode == "lock":
            lock = resolve_lock(arguments.lock, arguments.grype)
            print(
                f"Locked Grype DB {lock['database']['schema_version']} "
                f"(built {lock['database']['built_at']})."
            )
        elif arguments.mode == "prepare":
            prepare(arguments.lock, arguments.grype, arguments.cache_dir, arguments.evidence)
        else:
            verify(arguments.lock, arguments.grype, arguments.cache_dir, arguments.evidence)
        return 0
    except (OSError, ValueError, urllib.error.URLError, subprocess.SubprocessError, GrypeDBError) as exc:
        print(f"Grype database preparation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
