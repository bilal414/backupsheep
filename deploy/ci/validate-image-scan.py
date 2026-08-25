#!/usr/bin/env python3
"""Fail-closed validation for recurring exact-image SBOM/vulnerability evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile


IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ARCHIVE_CONFIG_RE = re.compile(
    r"^(?:blobs/sha256/([0-9a-f]{64})|([0-9a-f]{64})\.json)$"
)
EXPECTED_APP_PACKAGES = {
    "backupsheep-mariadb-dump",
    "backupsheep-oracle-mysql-client",
    "backupsheep-postgresql-client-14",
    "backupsheep-postgresql-client-15",
    "backupsheep-postgresql-client-16",
    "backupsheep-postgresql-client-17",
    "backupsheep-postgresql-client-18",
}
EXPECTED_EGRESS_PACKAGES = {"iproute2-minimal", "nftables", "setpriv"}


def die(message: str) -> None:
    raise SystemExit(f"BackupSheep image scan validation failed: {message}")


def load_object(path: Path, description: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        die(f"{description} is not readable canonical JSON: {exc}")
    if not isinstance(value, dict):
        die(f"{description} root is not an object")
    return value


def normalized_scanner_path(value: str) -> Path:
    if value.startswith("docker-archive:"):
        value = value.removeprefix("docker-archive:")
    return Path(value).resolve(strict=False)


def archive_config_image_id(archive: Path, docker_image_id: str) -> str:
    """Bind one Docker/OCI archive to its local-store and config digests."""
    try:
        with tarfile.open(archive, mode="r:*") as bundle:
            members: dict[str, tarfile.TarInfo] = {}
            for member in bundle.getmembers():
                if member.name in members:
                    die(f"image archive contains a duplicate member: {member.name}")
                members[member.name] = member

            manifest_member = members.get("manifest.json")
            if (
                manifest_member is None
                or not manifest_member.isfile()
                or manifest_member.size > 1024 * 1024
            ):
                die("image archive manifest.json is absent, unsafe, or oversized")
            manifest_handle = bundle.extractfile(manifest_member)
            if manifest_handle is None:  # pragma: no cover - guarded by isfile
                die("image archive manifest.json is unreadable")
            manifest = json.load(manifest_handle)
            if not isinstance(manifest, list) or len(manifest) != 1:
                die("image archive must contain exactly one image manifest")
            entry = manifest[0]
            if not isinstance(entry, dict):
                die("image archive manifest entry is not an object")
            config_name = entry.get("Config")
            if not isinstance(config_name, str):
                die("image archive config member is absent")
            config_match = ARCHIVE_CONFIG_RE.fullmatch(config_name)
            if config_match is None:
                die("image archive config member name is unsafe or unsupported")
            config_digest = next(
                digest for digest in config_match.groups() if digest is not None
            )
            config_member = members.get(config_name)
            if (
                config_member is None
                or not config_member.isfile()
                or config_member.size > 16 * 1024 * 1024
            ):
                die("image archive config is absent, unsafe, or oversized")
            config_handle = bundle.extractfile(config_member)
            if config_handle is None:  # pragma: no cover - guarded by isfile
                die("image archive config is unreadable")
            config_bytes = config_handle.read(16 * 1024 * 1024 + 1)
            if len(config_bytes) != config_member.size:
                die("image archive config size is inconsistent")
            if hashlib.sha256(config_bytes).hexdigest() != config_digest:
                die("image archive config digest does not match its content")
            try:
                config = json.loads(config_bytes)
            except (UnicodeError, json.JSONDecodeError) as exc:
                die(f"image archive config is not valid JSON: {exc}")
            if not isinstance(config, dict):
                die("image archive config root is not an object")
            archive_image_id = f"sha256:{config_digest}"
            if docker_image_id == archive_image_id:
                return archive_image_id

            def verified_blob(digest: str) -> tuple[bytes, tarfile.TarInfo]:
                if not IMAGE_ID_RE.fullmatch(digest):
                    die("image archive descriptor digest is malformed")
                blob_name = f"blobs/sha256/{digest.removeprefix('sha256:')}"
                blob_member = members.get(blob_name)
                if (
                    blob_member is None
                    or not blob_member.isfile()
                    or blob_member.size > 16 * 1024 * 1024
                ):
                    die("image archive descriptor blob is absent, unsafe, or oversized")
                blob_handle = bundle.extractfile(blob_member)
                if blob_handle is None:  # pragma: no cover - guarded by isfile
                    die("image archive descriptor blob is unreadable")
                blob = blob_handle.read(16 * 1024 * 1024 + 1)
                if len(blob) != blob_member.size:
                    die("image archive descriptor blob size is inconsistent")
                if hashlib.sha256(blob).hexdigest() != digest.removeprefix("sha256:"):
                    die("image archive descriptor digest does not match its content")
                return blob, blob_member

            def descriptor_digest(descriptor: object) -> str:
                if not isinstance(descriptor, dict):
                    die("image archive contains a non-object descriptor")
                digest = descriptor.get("digest")
                if not isinstance(digest, str) or not IMAGE_ID_RE.fullmatch(digest):
                    die("image archive descriptor digest is absent or malformed")
                return digest

            index_member = members.get("index.json")
            if (
                index_member is None
                or not index_member.isfile()
                or index_member.size > 1024 * 1024
            ):
                die("Docker image ID differs from config ID without an OCI index")
            index_handle = bundle.extractfile(index_member)
            if index_handle is None:  # pragma: no cover - guarded by isfile
                die("image archive index.json is unreadable")
            index = json.load(index_handle)
            if not isinstance(index, dict) or index.get("schemaVersion") != 2:
                die("image archive OCI index is invalid")
            roots = index.get("manifests")
            if not isinstance(roots, list) or len(roots) != 1:
                die("image archive OCI index must contain exactly one root")
            if descriptor_digest(roots[0]) != docker_image_id:
                die("Docker image ID does not identify the image archive root")

            visited: set[str] = set()

            def reaches_config(digest: str, depth: int = 0) -> bool:
                if depth > 8 or len(visited) >= 64 or digest in visited:
                    die("image archive descriptor graph is cyclic or too large")
                visited.add(digest)
                document_bytes, _ = verified_blob(digest)
                try:
                    document = json.loads(document_bytes)
                except (UnicodeError, json.JSONDecodeError) as exc:
                    die(f"image archive descriptor is not valid JSON: {exc}")
                if not isinstance(document, dict) or document.get("schemaVersion") != 2:
                    die("image archive descriptor is not a version-2 object")
                manifests = document.get("manifests")
                if manifests is not None:
                    if not isinstance(manifests, list) or not 1 <= len(manifests) <= 32:
                        die("image archive index has an invalid manifest set")
                    return any(
                        reaches_config(descriptor_digest(item), depth + 1)
                        for item in manifests
                    )
                descriptor = document.get("config")
                if not isinstance(descriptor, dict):
                    return False
                candidate = descriptor_digest(descriptor)
                candidate_bytes, candidate_member = verified_blob(candidate)
                declared_size = descriptor.get("size")
                if (
                    not isinstance(declared_size, int)
                    or declared_size < 0
                    or declared_size != candidate_member.size
                    or len(candidate_bytes) != declared_size
                ):
                    die("image archive config descriptor size is invalid")
                return candidate == archive_image_id

            if not reaches_config(docker_image_id):
                die("Docker image archive root does not reach the scanned config")
            return archive_image_id
    except (OSError, tarfile.TarError, json.JSONDecodeError) as exc:
        die(f"image archive is not a readable Docker archive: {exc}")


def validate_syft(
    report: dict, image_kind: str, expected_image_id: str, archive: Path
) -> tuple[int, set[str]]:
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        die("Syft contains no package inventory")
    package_names: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            die("Syft package inventory contains a non-object")
        name = artifact.get("name")
        version = artifact.get("version")
        package_type = artifact.get("type")
        if not all(isinstance(value, str) and value for value in (name, version, package_type)):
            die("Syft package inventory contains an incomplete package identity")
        package_names.add(name)

    source = report.get("source")
    if not isinstance(source, dict) or source.get("type") != "image":
        die("Syft source is not an image")
    metadata = source.get("metadata")
    if not isinstance(metadata, dict):
        die("Syft image source metadata is absent")
    user_input = metadata.get("userInput")
    if not isinstance(user_input, str) or not user_input:
        die("Syft image source input is absent")
    if normalized_scanner_path(user_input) != archive.resolve(strict=True):
        die("Syft source input does not identify the exact image archive")
    if metadata.get("imageID") != expected_image_id:
        die("Syft source image ID does not match the exact archive config ID")

    if image_kind == "app":
        missing = EXPECTED_APP_PACKAGES - package_names
        if missing:
            die(f"application SBOM is missing attributed packages: {sorted(missing)}")
    elif image_kind == "postgres":
        postgres_versions = {
            str(artifact["version"])
            for artifact in artifacts
            if artifact.get("name") == "postgresql"
        }
        if not any(version == "18.6" or version.startswith("18.6-") for version in postgres_versions):
            die("PostgreSQL SBOM does not identify PostgreSQL 18.6")
    elif image_kind == "egress":
        missing = EXPECTED_EGRESS_PACKAGES - package_names
        if missing:
            die(f"egress SBOM is missing policy-runtime packages: {sorted(missing)}")
    else:  # pragma: no cover - argparse enforces the choices
        die("unknown image kind")
    return len(artifacts), package_names


def validate_trivy(report: dict, expected_image_id: str, archive: Path) -> tuple[int, int]:
    schema_version = report.get("SchemaVersion")
    if not isinstance(schema_version, int) or schema_version < 2:
        die("Trivy schema version is absent or unsupported")
    artifact_name = report.get("ArtifactName")
    if not isinstance(artifact_name, str) or not artifact_name:
        die("Trivy artifact identity is absent")
    if normalized_scanner_path(artifact_name) != archive.resolve(strict=True):
        die("Trivy artifact does not identify the exact image archive")
    if report.get("ArtifactType") != "container_image":
        die("Trivy artifact type is not a container image")
    metadata = report.get("Metadata")
    if not isinstance(metadata, dict) or metadata.get("ImageID") != expected_image_id:
        die("Trivy image ID does not match the exact archive config ID")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        die("Trivy contains no scan results")

    package_count = 0
    vulnerabilities: list[dict] = []
    for result in results:
        if not isinstance(result, dict):
            die("Trivy results contain a non-object")
        packages = result.get("Packages")
        if isinstance(packages, list):
            package_count += len(packages)
        found = result.get("Vulnerabilities")
        if found is not None:
            if not isinstance(found, list):
                die("Trivy vulnerabilities are not a list")
            vulnerabilities.extend(found)
    if package_count == 0:
        die("Trivy contains no package inventory")
    if vulnerabilities:
        identities = sorted(
            {
                str(item.get("VulnerabilityID", "unknown"))
                for item in vulnerabilities
                if isinstance(item, dict)
            }
        )
        die(f"Trivy reported HIGH/CRITICAL vulnerabilities: {identities}")
    return package_count, len(vulnerabilities)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        die(f"image archive is unreadable: {exc}")
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-kind", choices=("app", "postgres", "egress"), required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--syft", type=Path, required=True)
    parser.add_argument("--trivy", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    arguments = parser.parse_args()

    if not IMAGE_ID_RE.fullmatch(arguments.image_id):
        die("expected Docker image ID is malformed")
    if not arguments.archive.is_file() or arguments.archive.is_symlink():
        die("image archive is absent or is a symlink")
    archive_image_id = archive_config_image_id(
        arguments.archive, arguments.image_id
    )

    syft_count, _ = validate_syft(
        load_object(arguments.syft, "Syft report"),
        arguments.image_kind,
        archive_image_id,
        arguments.archive,
    )
    trivy_count, vulnerability_count = validate_trivy(
        load_object(arguments.trivy, "Trivy report"),
        archive_image_id,
        arguments.archive,
    )
    summary = {
        "archive_config_image_id": archive_image_id,
        "archive_sha256": sha256_file(arguments.archive),
        "docker_image_id": arguments.image_id,
        "image_kind": arguments.image_kind,
        "syft_package_count": syft_count,
        "trivy_high_critical_count": vulnerability_count,
        "trivy_package_count": trivy_count,
    }
    arguments.summary.write_text(
        json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    print(
        f"{arguments.image_kind}: Syft={syft_count} Trivy={trivy_count} "
        "HIGH/CRITICAL=0"
    )


if __name__ == "__main__":
    main()
