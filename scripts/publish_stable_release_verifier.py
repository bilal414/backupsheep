#!/usr/bin/env python3
"""Publish one already-validated verifier OCI layout without replacing bytes.

This is deliberately narrower than the application release publisher.  It is
the one-time root-of-trust bootstrap for BackupSheep's patched Cosign runtime.
Every destination is classified before the first write; an exact interrupted
publication may resume, while an occupied tag with different bytes fails
closed.  The consumer trusts the resulting digest, never the tag.
"""

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
from pathlib import Path
from typing import Any


MAX_CONTROL_BYTES = 1024 * 1024
MAX_ORAS_OUTPUT_BYTES = 1024 * 1024
MAX_TAG_LIST_BYTES = 4 * 1024 * 1024
MAX_REPOSITORY_TAGS = 100_000
ORAS_TIMEOUT_SECONDS = 600
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
OCI_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
CANDIDATE_TAG_RE = re.compile(
    r"^bootstrap-[0-9a-f]{40}-[1-9][0-9]*-[1-9][0-9]*$"
)
EXPECTED_QUARANTINE_REPOSITORY = (
    "ghcr.io/bilal414/backupsheep-release-verifier-quarantine"
)
EXPECTED_OFFICIAL_REPOSITORY = "ghcr.io/bilal414/backupsheep-release-verifier"
EXPECTED_STABLE_TAG = "v3.1.3-backupsheep.1"
EXPECTED_ROOT_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
EXPECTED_BUILD_TIMESTAMP = "2026-08-29T00:00:00Z"


class PublicationError(RuntimeError):
    """The stable verifier could not be published without weakening trust."""


def _reject_constant(value: str) -> None:
    raise PublicationError(f"non-finite JSON value is forbidden: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PublicationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _validate_directory_chain(
    path: Path,
    *,
    label: str,
    final_mode: int | None = None,
) -> Path:
    """Reject symlinked, foreign-controlled, or replaceable ancestors."""

    if not path.is_absolute():
        raise PublicationError(f"{label} must be absolute")
    current = Path(path.anchor)
    identities: list[tuple[Path, tuple[int, int, int, int]]] = []
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise PublicationError(f"cannot inspect {label} ancestor: {exc}") from exc
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PublicationError(f"{label} chain contains a symlink or non-directory")
        if metadata.st_uid not in {0, os.geteuid()}:
            raise PublicationError(f"{label} chain contains a foreign-owned directory")
        if mode & 0o022 and not (
            metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
        ):
            raise PublicationError(f"{label} chain contains a replaceable directory")
        identities.append(
            (
                current,
                (metadata.st_dev, metadata.st_ino, metadata.st_uid, mode),
            )
        )
    if not identities:
        raise PublicationError(f"{label} cannot be the filesystem root")
    final_metadata = identities[-1][1]
    if final_mode is not None and (
        final_metadata[2] != os.geteuid() or final_metadata[3] != final_mode
    ):
        raise PublicationError(
            f"{label} must be owned by the effective user and mode {final_mode:04o}"
        )
    for ancestor, identity in identities:
        metadata = ancestor.lstat()
        if (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
        ) != identity:
            raise PublicationError(f"{label} chain changed during validation")
    return path


def _read_regular(path: Path, *, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise PublicationError(f"cannot inspect {label}: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise PublicationError(
            f"{label} must be a bounded, single-link regular file"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise PublicationError(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            payload = stream.read(maximum + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) != before.st_size or len(payload) > maximum:
        raise PublicationError(f"{label} changed while it was read")
    try:
        after = path.lstat()
    except OSError as exc:
        raise PublicationError(f"{label} disappeared after it was read: {exc}") from exc
    if (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_nlink,
    ) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_nlink,
    ):
        raise PublicationError(f"{label} changed while it was read")
    return payload


def _load_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PublicationError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise PublicationError(f"{label} must be a JSON object")
    return value


def _validated_layout_index(
    layout: Path,
    *,
    index_digest: str,
    repository: str,
    tag: str,
) -> bytes:
    _validate_directory_chain(
        layout,
        label="the OCI layout",
        final_mode=0o700,
    )
    _validate_directory_chain(
        layout / "blobs" / "sha256",
        label="the OCI blob directory",
    )
    layout_marker = _load_json(
        _read_regular(
            layout / "oci-layout",
            maximum=1024,
            label="OCI layout marker",
        ),
        "OCI layout marker",
    )
    if layout_marker != {"imageLayoutVersion": "1.0.0"}:
        raise PublicationError("the OCI layout marker is unsupported")
    root = _load_json(
        _read_regular(layout / "index.json", maximum=MAX_CONTROL_BYTES, label="OCI root index"),
        "OCI root index",
    )
    if (
        set(root) != {"schemaVersion", "mediaType", "manifests"}
        or root["schemaVersion"] != 2
        or root["mediaType"] != EXPECTED_ROOT_MEDIA_TYPE
    ):
        raise PublicationError("the OCI root index has an unsupported structure")
    manifests = root["manifests"]
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise PublicationError("the OCI root index must name exactly one image index")
    descriptor = manifests[0]
    if not isinstance(descriptor, dict) or set(descriptor) != {
        "mediaType",
        "digest",
        "size",
        "annotations",
    }:
        raise PublicationError("the OCI root descriptor is not exact")
    if (
        descriptor["mediaType"] != EXPECTED_ROOT_MEDIA_TYPE
        or descriptor["digest"] != index_digest
        or not isinstance(descriptor["size"], int)
        or isinstance(descriptor["size"], bool)
        or not 1 <= descriptor["size"] <= MAX_CONTROL_BYTES
        or descriptor["annotations"]
        != {
            "io.containerd.image.name": f"{repository}:{tag}",
            "org.opencontainers.image.created": EXPECTED_BUILD_TIMESTAMP,
            "org.opencontainers.image.ref.name": tag,
        }
    ):
        raise PublicationError("the OCI root descriptor is not bound to this publication")
    blob = _read_regular(
        layout / "blobs" / "sha256" / index_digest.removeprefix("sha256:"),
        maximum=MAX_CONTROL_BYTES,
        label="OCI image index blob",
    )
    if len(blob) != descriptor["size"] or _sha256(blob) != index_digest:
        raise PublicationError("the OCI image index bytes do not match the root descriptor")
    return blob


def _validated_oras(path: Path) -> Path:
    if not path.is_absolute():
        raise PublicationError("the ORAS path must be absolute")
    _validate_directory_chain(path.parent, label="the ORAS parent directory")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PublicationError(f"cannot inspect ORAS: {exc}") from exc
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or mode & 0o022
        or not mode & 0o100
    ):
        raise PublicationError("ORAS must be an owner-controlled executable regular file")
    return path


def _oras_environment() -> dict[str, str]:
    docker_config = os.environ.get("DOCKER_CONFIG", "")
    home = os.environ.get("HOME", "")
    if not docker_config or not os.path.isabs(docker_config):
        raise PublicationError("DOCKER_CONFIG must identify the isolated release credentials")
    if not home or not os.path.isabs(home):
        raise PublicationError("HOME must be absolute")
    docker_path = Path(docker_config)
    _validate_directory_chain(
        docker_path,
        label="the release Docker configuration directory",
        final_mode=0o700,
    )
    config = docker_path / "config.json"
    config_metadata = config.lstat()
    if (
        stat.S_ISLNK(config_metadata.st_mode)
        or not stat.S_ISREG(config_metadata.st_mode)
        or config_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(config_metadata.st_mode) != 0o600
        or config_metadata.st_nlink != 1
        or not 1 <= config_metadata.st_size <= MAX_CONTROL_BYTES
    ):
        raise PublicationError("the isolated release Docker config is unsafe")
    return {
        "DOCKER_CONFIG": docker_config,
        "HOME": home,
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _run_oras(oras: Path, arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            [str(oras), *arguments],
            check=False,
            capture_output=True,
            text=True,
            env=_oras_environment(),
            timeout=ORAS_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PublicationError(f"ORAS invocation failed: {exc}") from exc
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    if len(stdout.encode("utf-8", errors="replace")) > MAX_ORAS_OUTPUT_BYTES or len(
        stderr.encode("utf-8", errors="replace")
    ) > MAX_ORAS_OUTPUT_BYTES:
        raise PublicationError("ORAS emitted oversized output")
    if result.returncode:
        detail = (stderr or stdout).strip()
        raise PublicationError(f"ORAS failed closed: {detail[:1000]}")
    return stdout


def _fetch_exact(
    oras: Path,
    reference: str,
    expected: bytes,
) -> None:
    with tempfile.TemporaryDirectory(prefix="backupsheep-verifier-fetch-") as temporary:
        output = Path(temporary) / "manifest.json"
        status = _run_oras(
            oras,
            ["manifest", "fetch", "--output", str(output), reference],
        )
        if status:
            raise PublicationError(
                f"ORAS emitted unexpected manifest output for {reference}"
            )
        actual = _read_regular(
            output,
            maximum=MAX_CONTROL_BYTES,
            label=f"fetched manifest for {reference}",
        )
    if not secrets_compare(actual, expected):
        raise PublicationError(f"registry reference has different index bytes: {reference}")


def _repository_tags(oras: Path, repository: str) -> set[str]:
    """Return a bounded tag set only from a successful authenticated listing."""

    raw = _run_oras(oras, ["repo", "tags", "--format", "json", repository])
    try:
        encoded = raw.encode("utf-8")
    except UnicodeError as exc:
        raise PublicationError("ORAS returned a non-UTF-8 tag inventory") from exc
    if not encoded or len(encoded) > MAX_TAG_LIST_BYTES:
        raise PublicationError("ORAS returned an invalid-size tag inventory")
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PublicationError("ORAS returned malformed tag inventory JSON") from exc
    if not isinstance(document, dict) or set(document) != {"tags"}:
        raise PublicationError("ORAS tag inventory has an unexpected schema")
    tags = document["tags"]
    if not isinstance(tags, list) or len(tags) > MAX_REPOSITORY_TAGS:
        raise PublicationError("ORAS tag inventory has an invalid tag set")
    if any(
        not isinstance(tag, str) or OCI_TAG_RE.fullmatch(tag) is None
        for tag in tags
    ):
        raise PublicationError("ORAS tag inventory contains a malformed tag")
    if len(set(tags)) != len(tags):
        raise PublicationError("ORAS tag inventory contains duplicate tags")
    return set(tags)


def secrets_compare(left: bytes, right: bytes) -> bool:
    """Compare public manifest bytes without an early length-only shortcut."""

    import hmac

    return hmac.compare_digest(left, right)


def _write_evidence(path: Path, document: dict[str, Any]) -> None:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise PublicationError("the publication evidence path must be absolute")
    if path.exists() or path.is_symlink():
        raise PublicationError("refusing to overwrite publication evidence")
    parent = _validate_directory_chain(
        path.parent,
        label="the publication evidence parent",
        final_mode=0o700,
    )
    path = parent / path.name
    payload = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def publish(
    *,
    layout: Path,
    index_digest: str,
    quarantine_repository: str,
    candidate_tag: str,
    official_repository: str,
    stable_tag: str,
    oras: Path,
    evidence: Path,
) -> dict[str, Any]:
    if DIGEST_RE.fullmatch(index_digest) is None:
        raise PublicationError("the verifier image index digest is malformed")
    if quarantine_repository != EXPECTED_QUARANTINE_REPOSITORY:
        raise PublicationError("the verifier quarantine repository is not authorized")
    if official_repository != EXPECTED_OFFICIAL_REPOSITORY:
        raise PublicationError("the verifier official repository is not authorized")
    if CANDIDATE_TAG_RE.fullmatch(candidate_tag) is None:
        raise PublicationError("the verifier candidate tag is not source/run bound")
    if stable_tag != EXPECTED_STABLE_TAG:
        raise PublicationError("the verifier stable tag is not authorized")
    oras = _validated_oras(oras)
    index = _validated_layout_index(
        layout,
        index_digest=index_digest,
        repository=quarantine_repository,
        tag=candidate_tag,
    )
    quarantine_tag_reference = f"{quarantine_repository}:{candidate_tag}"
    quarantine_digest_reference = f"{quarantine_repository}@{index_digest}"
    official_tag_reference = f"{official_repository}:{stable_tag}"
    official_digest_reference = f"{official_repository}@{index_digest}"

    # Classify every mutable destination before the first write. Only a
    # successful, strict tag inventory can prove absence: registries commonly
    # mask denied reads as a generic 404, so an error string never authorizes a
    # tag write. Both package repositories must therefore exist before this
    # one-time publication ceremony starts.
    quarantine_tags = _repository_tags(oras, quarantine_repository)
    official_tags = _repository_tags(oras, official_repository)
    quarantine_exists = candidate_tag in quarantine_tags
    official_exists = stable_tag in official_tags
    if quarantine_exists:
        _fetch_exact(oras, quarantine_tag_reference, index)
    if official_exists:
        _fetch_exact(oras, official_tag_reference, index)

    if not quarantine_exists:
        # Recheck immediately before the mutable write. GHCR does not expose a
        # conditional tag-create primitive; repository write exclusivity and
        # workflow concurrency remain part of this bootstrap ceremony.
        quarantine_exists = candidate_tag in _repository_tags(
            oras, quarantine_repository
        )
        if quarantine_exists:
            _fetch_exact(oras, quarantine_tag_reference, index)
        else:
            _run_oras(
                oras,
                [
                    "cp",
                    "--from-oci-layout",
                    f"{layout}:{candidate_tag}",
                    quarantine_tag_reference,
                ],
            )
    _fetch_exact(oras, quarantine_tag_reference, index)
    _fetch_exact(oras, quarantine_digest_reference, index)

    if not official_exists:
        # Recheck immediately before the only official tag write. GHCR has no
        # conditional create operation; repository write access and workflow
        # concurrency are therefore part of this one-time ceremony boundary.
        official_exists = stable_tag in _repository_tags(oras, official_repository)
        if official_exists:
            _fetch_exact(oras, official_tag_reference, index)
        else:
            _run_oras(
                oras,
                ["cp", quarantine_digest_reference, official_tag_reference],
            )
    _fetch_exact(oras, official_tag_reference, index)
    _fetch_exact(oras, official_digest_reference, index)

    document = {
        "schema_version": 1,
        "candidate": {
            "repository": quarantine_repository,
            "tag": candidate_tag,
            "status": "already_exact" if quarantine_exists else "published",
        },
        "official": {
            "repository": official_repository,
            "tag": stable_tag,
            "status": "already_exact" if official_exists else "published",
        },
        "index_digest": index_digest,
        "index_sha256": hashlib.sha256(index).hexdigest(),
        "trust_contract": "consumer-pins-digest-not-tag",
    }
    _write_evidence(evidence, document)
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--index-digest", required=True)
    parser.add_argument("--quarantine-repository", required=True)
    parser.add_argument("--candidate-tag", required=True)
    parser.add_argument("--official-repository", required=True)
    parser.add_argument("--stable-tag", required=True)
    parser.add_argument("--oras", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        publish(
            layout=arguments.layout,
            index_digest=arguments.index_digest,
            quarantine_repository=arguments.quarantine_repository,
            candidate_tag=arguments.candidate_tag,
            official_repository=arguments.official_repository,
            stable_tag=arguments.stable_tag,
            oras=arguments.oras,
            evidence=arguments.evidence,
        )
        return 0
    except (OSError, PublicationError) as exc:
        print(f"stable verifier publication failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
