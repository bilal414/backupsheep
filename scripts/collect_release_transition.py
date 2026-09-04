#!/usr/bin/env python3
"""Collect the exact migration contract from the built release application image."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

import release_transition
from release_subprocess import run_text
from verify_release import (
    MAX_CONTROL_FILE_BYTES,
    ReleaseVerificationError,
    _digest,
    _load_json,
    _parse_oci_index,
    _safe_artifact,
    _sha256_path,
    _validate_policy,
)


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,254}:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
DOCKER_TIMEOUT_SECONDS = 180


def _atomic_write(path: Path, payload: bytes) -> None:
    if not payload or len(payload) > release_transition.MAX_JSON_BYTES:
        raise ReleaseVerificationError(f"{path.name} has an invalid size")
    parent = path.parent.resolve(strict=True)
    if path.exists() or path.is_symlink():
        raise ReleaseVerificationError(f"{path.name} already exists")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o600)
        os.link(temporary_name, path)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def _expected_amd64_config_digest(artifacts_dir: Path, oci_layout: Path) -> str:
    index_path = _safe_artifact(
        artifacts_dir,
        "oci/app.index.json",
        "application OCI index",
    )
    index = _load_json(index_path, maximum_bytes=MAX_CONTROL_FILE_BYTES)
    platforms, _ = _parse_oci_index(index, ["linux/amd64", "linux/arm64"], "application OCI index")
    manifest_digest = platforms["linux/amd64"]
    manifest_path = oci_layout / "blobs" / "sha256" / manifest_digest.removeprefix("sha256:")
    try:
        resolved_layout = oci_layout.resolve(strict=True)
        resolved_manifest = manifest_path.resolve(strict=True)
        resolved_manifest.relative_to(resolved_layout)
    except (FileNotFoundError, ValueError) as exc:
        raise ReleaseVerificationError("application amd64 manifest is absent from the OCI layout") from exc
    if _sha256_path(resolved_manifest) != manifest_digest:
        raise ReleaseVerificationError("application amd64 manifest blob digest mismatch")
    manifest = _load_json(resolved_manifest, maximum_bytes=MAX_CONTROL_FILE_BYTES)
    if (
        not isinstance(manifest, dict)
        or manifest.get("schemaVersion") != 2
        or manifest.get("mediaType")
        not in {
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        }
    ):
        raise ReleaseVerificationError("application amd64 manifest is malformed")
    config = manifest.get("config")
    if (
        not isinstance(config, dict)
        or set(config) - {"mediaType", "digest", "size", "annotations", "data"}
        or config.get("mediaType")
        not in {
            "application/vnd.oci.image.config.v1+json",
            "application/vnd.docker.container.image.v1+json",
        }
        or isinstance(config.get("size"), bool)
        or not isinstance(config.get("size"), int)
        or config["size"] <= 0
    ):
        raise ReleaseVerificationError("application amd64 config descriptor is malformed")
    config_digest = _digest(config.get("digest"), "application amd64 config digest")
    config_path = oci_layout / "blobs" / "sha256" / config_digest.removeprefix("sha256:")
    try:
        resolved_config = config_path.resolve(strict=True)
        resolved_config.relative_to(resolved_layout)
    except (FileNotFoundError, ValueError) as exc:
        raise ReleaseVerificationError("application amd64 config is absent from the OCI layout") from exc
    if _sha256_path(resolved_config) != config_digest:
        raise ReleaseVerificationError("application amd64 config blob digest mismatch")
    if resolved_config.stat().st_size != config["size"]:
        raise ReleaseVerificationError("application amd64 config blob size mismatch")
    return config_digest


def _inspect_release_image(
    *,
    docker: Path,
    image: str,
    expected_config_digest: str,
    source_repository: str,
    source_commit: str,
    release_tag: str,
    environment: dict[str, str],
) -> None:
    result = run_text(
        [str(docker), "image", "inspect", image],
        environment=environment,
        timeout=DOCKER_TIMEOUT_SECONDS,
    )
    if result.returncode != 0 or result.stderr:
        raise ReleaseVerificationError("could not inspect the local release application image")
    try:
        documents = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ReleaseVerificationError("Docker returned malformed image inspection JSON") from exc
    if not isinstance(documents, list) or len(documents) != 1 or not isinstance(documents[0], dict):
        raise ReleaseVerificationError("Docker returned an ambiguous image inspection")
    document = documents[0]
    config = document.get("Config")
    if (
        document.get("Id") != expected_config_digest
        or document.get("Os") != "linux"
        or document.get("Architecture") != "amd64"
        or not isinstance(config, dict)
        or config.get("User") != "10001:10001"
        or config.get("WorkingDir") != "/code"
    ):
        raise ReleaseVerificationError("local migration inventory image is not the exact release child")
    labels = config.get("Labels")
    expected_labels = {
        "org.opencontainers.image.source": f"https://github.com/{source_repository}",
        "org.opencontainers.image.revision": source_commit,
        "org.opencontainers.image.version": release_tag,
    }
    if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in expected_labels.items()):
        raise ReleaseVerificationError("local migration inventory image labels are not release-bound")


def collect(
    *,
    policy_path: Path,
    artifacts_dir: Path,
    oci_layout: Path,
    image: str,
    docker: Path,
    source_commit: str,
    release_tag: str,
    docker_environment: dict[str, str],
) -> dict[str, Any]:
    artifacts_stat = artifacts_dir.lstat()
    if (
        not stat.S_ISDIR(artifacts_stat.st_mode)
        or stat.S_ISLNK(artifacts_stat.st_mode)
        or artifacts_stat.st_uid != os.geteuid()
        or stat.S_IMODE(artifacts_stat.st_mode) & 0o077
    ):
        raise ReleaseVerificationError("release artifacts directory is not private")
    transition_dir = artifacts_dir / "transition"
    if transition_dir.exists() or transition_dir.is_symlink():
        raise ReleaseVerificationError("release transition directory already exists")
    repository_root = policy_path.parents[1]
    checked_policy_path = _safe_artifact(
        repository_root,
        "deploy/release-policy.json",
        "release policy source",
    )
    if checked_policy_path != policy_path:
        raise ReleaseVerificationError("release policy source path is not canonical")
    policy = _validate_policy(
        _load_json(checked_policy_path, maximum_bytes=MAX_CONTROL_FILE_BYTES)
    )
    if COMMIT_RE.fullmatch(source_commit) is None or TAG_RE.fullmatch(release_tag) is None:
        raise ReleaseVerificationError("release migration identity is malformed")
    if IMAGE_RE.fullmatch(image) is None:
        raise ReleaseVerificationError("local migration inventory image name is malformed")
    docker_stat = docker.stat()
    if not docker.is_absolute() or not stat.S_ISREG(docker_stat.st_mode) or docker_stat.st_mode & 0o022:
        raise ReleaseVerificationError("Docker client must be an immutable absolute regular file")
    if policy["transition"]["policy_path"] != "deploy/release-transition-policy.json":
        raise ReleaseVerificationError("transition policy source path is not canonical")
    reviewed_source = _safe_artifact(
        repository_root,
        policy["transition"]["policy_path"],
        "reviewed transition policy source",
    )
    release_transition.validate_transition_policy(release_transition.load_json(reviewed_source))
    reviewed_payload = reviewed_source.read_bytes()

    config_digest = _expected_amd64_config_digest(artifacts_dir, oci_layout.resolve(strict=True))
    _inspect_release_image(
        docker=docker,
        image=image,
        expected_config_digest=config_digest,
        source_repository=policy["source_repository"],
        source_commit=source_commit,
        release_tag=release_tag,
        environment=docker_environment,
    )

    command = policy["transition"]["migration_contract_command"]
    result = run_text(
        [
            str(docker),
            "run",
            "--rm",
            "--name",
            f"backupsheep-release-migrations-{source_commit[:16]}",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "128",
            "--memory",
            "512m",
            "--memory-swap",
            "512m",
            "--cpus",
            "1",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m",
            "--user",
            "10001:10001",
            "--workdir",
            "/code",
            "--entrypoint",
            "/usr/local/bin/python",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--log-driver",
            "none",
            config_digest,
            *command[1:],
        ],
        environment=docker_environment,
        timeout=DOCKER_TIMEOUT_SECONDS,
    )
    if result.returncode != 0 or result.stderr:
        raise ReleaseVerificationError("release application image rejected migration inventory")
    try:
        payload = result.stdout.encode("ascii")
        raw_contract = json.loads(payload)
    except (UnicodeEncodeError, json.JSONDecodeError) as exc:
        raise ReleaseVerificationError("release migration inventory is not canonical ASCII JSON") from exc
    contract = release_transition.validate_migration_contract(raw_contract)
    canonical = json.dumps(contract, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
    if payload != canonical:
        raise ReleaseVerificationError("release migration inventory has noncanonical serialization")

    if transition_dir.exists() or transition_dir.is_symlink():
        raise ReleaseVerificationError("release transition directory already exists")
    os.mkdir(transition_dir, mode=0o700)
    transition_stat = transition_dir.lstat()
    if (
        transition_dir.parent.resolve(strict=True) != artifacts_dir.resolve(strict=True)
        or not stat.S_ISDIR(transition_stat.st_mode)
        or stat.S_ISLNK(transition_stat.st_mode)
        or transition_stat.st_uid != os.geteuid()
        or stat.S_IMODE(transition_stat.st_mode) != 0o700
    ):
        raise ReleaseVerificationError("release transition directory identity is unsafe")
    _atomic_write(transition_dir / "reviewed-policy.json", reviewed_payload)
    _atomic_write(transition_dir / "django-migrations.json", canonical)
    return contract


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--oci-layout", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--release-tag", required=True)
    arguments = parser.parse_args(argv)
    try:
        docker_home_input = Path(os.environ["BACKUPSHEEP_RELEASE_DOCKER_HOME"])
        docker_home_lstat = docker_home_input.lstat()
        if stat.S_ISLNK(docker_home_lstat.st_mode):
            raise ReleaseVerificationError("release Docker HOME cannot be a symlink")
        docker_home = docker_home_input.resolve(strict=True)
        home_stat = docker_home.stat()
        mode = stat.S_IMODE(home_stat.st_mode)
        if (
            not docker_home.is_dir()
            or home_stat.st_uid != os.geteuid()
            or mode & 0o077
            or any(docker_home.iterdir())
        ):
            raise ReleaseVerificationError("release Docker HOME is not private")
        environment = {
            "HOME": str(docker_home),
            "DOCKER_CONFIG": str(docker_home),
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
        }
        collect(
            policy_path=arguments.policy.absolute(),
            artifacts_dir=arguments.artifacts_dir.absolute(),
            oci_layout=arguments.oci_layout.absolute(),
            image=arguments.image,
            docker=arguments.docker.resolve(strict=True),
            source_commit=arguments.source_commit,
            release_tag=arguments.release_tag,
            docker_environment=environment,
        )
        return 0
    except (KeyError, OSError, ValueError, ReleaseVerificationError, release_transition.TransitionContractError) as exc:
        print(f"release transition collection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
