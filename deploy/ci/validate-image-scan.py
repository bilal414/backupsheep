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
DOCKER_REPOSITORY_RE = re.compile(r"^[a-z0-9_./-]{2,255}$")
DOCKER_TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
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
EXPECTED_RABBITMQ_SECURITY_PACKAGES = {
    "libcrypto3": "3.5.8-r0",
    "libssl3": "3.5.8-r0",
}
EXPECTED_OS_PACKAGE_TYPES = {
    "app": ("deb", "ubuntu"),
    "postgres": ("apk", "alpine"),
    "egress": ("apk", "alpine"),
    "rabbitmq": ("apk", "alpine"),
    "rabbitmq-upgrade": ("apk", "alpine"),
}
EXPECTED_SYFT_VERSION = "1.51.0"
EXPECTED_SYFT_SCHEMA_VERSION = "16.1.10"
EXPECTED_SYFT_SCHEMA_URL = (
    "https://raw.githubusercontent.com/anchore/syft/main/schema/json/"
    "schema-16.1.10.json"
)
EXPECTED_TRIVY_VERSION = "0.74.0"
EXPECTED_TRIVY_SCHEMA_VERSION = 2
LOCKED_REQUIREMENT_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\]+) \\$"
)
LOCKED_HASH_RE = re.compile(r"^[ \t]+--hash=sha256:[0-9a-f]{64}(?: \\)?$")
TOP_LEVEL_PYTHON_METADATA_RE = re.compile(
    r"^/?usr/local/lib/python3\.14/site-packages/(?:"
    r"[^/]+\.dist-info/METADATA|"
    r"[^/]+\.egg-info(?:/(?:PKG-INFO|METADATA))?|"
    r"[^/]+\.egg/EGG-INFO/PKG-INFO"
    r")$",
    re.IGNORECASE,
)
MAX_REQUIREMENTS_LOCK_SIZE = 4 * 1024 * 1024


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


def normalized_python_package_name(value: str) -> str:
    """Return the PEP 503 identity used to compare lock and scanner names."""
    return re.sub(r"[-_.]+", "-", value).lower()


def validate_syft_schema(report: dict) -> None:
    schema = report.get("schema")
    if (
        not isinstance(schema, dict)
        or schema.get("version") != EXPECTED_SYFT_SCHEMA_VERSION
        or schema.get("url") != EXPECTED_SYFT_SCHEMA_URL
    ):
        die("Syft report schema is absent or is not the pinned supported schema")
    descriptor = report.get("descriptor")
    if (
        not isinstance(descriptor, dict)
        or descriptor.get("name") != "syft"
        or descriptor.get("version") != EXPECTED_SYFT_VERSION
    ):
        die("Syft report tool identity is absent or is not the pinned version")


def validate_trivy_schema(report: dict) -> None:
    if report.get("SchemaVersion") != EXPECTED_TRIVY_SCHEMA_VERSION:
        die("Trivy schema version is absent or unsupported")
    tool = report.get("Trivy")
    if (
        not isinstance(tool, dict)
        or tool.get("Version") != EXPECTED_TRIVY_VERSION
    ):
        die("Trivy report tool identity is absent or is not the pinned version")
    artifact_id = report.get("ArtifactID")
    if not isinstance(artifact_id, str) or not IMAGE_ID_RE.fullmatch(artifact_id):
        die("Trivy artifact ID is absent or malformed")


def trivy_reference_context(reference: str) -> str:
    """Mirror Trivy 0.74's go-containerregistry weak tag context."""
    pieces = reference.split(":")
    repository = reference
    tag = "latest"
    if len(pieces) > 1 and "/" not in pieces[-1]:
        repository = ":".join(pieces[:-1])
        tag = pieces[-1]
    if not DOCKER_TAG_RE.fullmatch(tag):
        die("image archive contains a repository tag Trivy cannot identify")

    repository_parts = repository.split("/", 1)
    possible_registry = repository_parts[0]
    registry = "index.docker.io"
    repository_path = repository
    if len(repository_parts) == 2 and (
        possible_registry == "localhost"
        or "." in possible_registry
        or ":" in possible_registry
    ):
        registry = possible_registry
        repository_path = repository_parts[1]
    if registry == "docker.io":
        registry = "index.docker.io"
    if (
        not registry
        or any(character.isspace() for character in registry)
        or "/" in registry
        or not DOCKER_REPOSITORY_RE.fullmatch(repository_path)
    ):
        die("image archive contains a repository tag Trivy cannot identify")
    if registry == "index.docker.io" and "/" not in repository_path:
        repository_path = f"library/{repository_path}"
    return f"{registry}/{repository_path}"


def validate_trivy_artifact_identity(
    report: dict,
    expected_image_id: str,
    archive_repo_tags: tuple[str, ...],
) -> None:
    metadata = report.get("Metadata")
    if not isinstance(metadata, dict):
        die("Trivy image metadata is absent")
    report_repo_tags = metadata.get("RepoTags")
    report_reference = metadata.get("Reference")
    if archive_repo_tags:
        if report_repo_tags != list(archive_repo_tags):
            die("Trivy repository tags do not match the exact image archive")
        reference = archive_repo_tags[0]
        if report_reference != reference:
            die("Trivy repository reference does not match the exact image archive")
        context = trivy_reference_context(reference)
        expected_artifact_id = "sha256:" + hashlib.sha256(
            f"{expected_image_id}:{context}".encode("utf-8")
        ).hexdigest()
    else:
        if report_repo_tags not in (None, []):
            die("Trivy repository tags are present for an untagged image archive")
        if report_reference not in (None, ""):
            die("Trivy repository reference is present for an untagged image archive")
        expected_artifact_id = expected_image_id
    if report.get("ArtifactID") != expected_artifact_id:
        die("Trivy artifact ID does not match the exact image archive identity")


def load_python_requirements_lock(
    path: Path,
) -> tuple[dict[str, str], str, str]:
    """Load every hash-pinned Python identity from the build's source lock."""
    if not path.is_file() or path.is_symlink():
        die("Python requirements lock is absent or is a symlink")
    try:
        size = path.stat().st_size
        if size <= 0 or size > MAX_REQUIREMENTS_LOCK_SIZE:
            die("Python requirements lock is empty or oversized")
        raw = path.read_bytes()
    except OSError as exc:
        die(f"Python requirements lock is unreadable: {exc}")
    if len(raw) != size:
        die("Python requirements lock size changed while it was read")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        die(f"Python requirements lock is not UTF-8: {exc}")

    inventory: dict[str, str] = {}
    current_identity: str | None = None
    current_hash_count = 0

    def finish_requirement() -> None:
        if current_identity is not None and current_hash_count == 0:
            die(
                "Python requirement has no SHA-256 artifact hash: "
                f"{current_identity}"
            )

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        requirement = LOCKED_REQUIREMENT_RE.fullmatch(line)
        if requirement is not None:
            finish_requirement()
            name, version = requirement.groups()
            normalized_name = normalized_python_package_name(name)
            if normalized_name in inventory:
                die(
                    "Python requirements lock contains a duplicate normalized "
                    f"package name: {normalized_name}"
                )
            inventory[normalized_name] = version
            current_identity = f"{normalized_name}=={version}"
            current_hash_count = 0
            continue
        if LOCKED_HASH_RE.fullmatch(line) is not None:
            if current_identity is None:
                die(
                    "Python requirements lock contains a hash before a package "
                    f"at line {line_number}"
                )
            current_hash_count += 1
            continue
        die(
            "Python requirements lock contains an unsupported or unpinned line "
            f"at line {line_number}"
        )
    finish_requirement()
    if not inventory:
        die("Python requirements lock contains no package identities")

    canonical_inventory = "".join(
        f"{name}=={version}\n" for name, version in sorted(inventory.items())
    ).encode("utf-8")
    return (
        inventory,
        hashlib.sha256(raw).hexdigest(),
        hashlib.sha256(canonical_inventory).hexdigest(),
    )


def formatted_python_identities(
    identities: set[tuple[str, str]],
) -> list[str]:
    return sorted(f"{name}=={version}" for name, version in identities)


def validate_rabbitmq_security_packages(
    packages: dict[str, str], scanner: str
) -> None:
    observed = {
        name: packages.get(name) for name in EXPECTED_RABBITMQ_SECURITY_PACKAGES
    }
    if observed != EXPECTED_RABBITMQ_SECURITY_PACKAGES:
        die(
            f"{scanner} RabbitMQ OpenSSL package identities are not the exact "
            f"reviewed versions: {observed}"
        )


def validate_locked_python_inventory(
    observed: set[tuple[str, str]],
    expected: dict[str, str],
    scanner: str,
) -> int:
    expected_identities = set(expected.items())
    missing = expected_identities - observed
    if missing:
        die(
            f"application {scanner} Python inventory is missing locked "
            "top-level package identities: "
            f"{formatted_python_identities(missing)}"
        )
    unexpected = observed - expected_identities
    if unexpected:
        die(
            f"application {scanner} Python inventory contains unlocked "
            "top-level package identities: "
            f"{formatted_python_identities(unexpected)}"
        )
    return len(observed)


def archive_config_image_id(
    archive: Path, docker_image_id: str
) -> tuple[str, tuple[str, ...]]:
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
            raw_repo_tags = entry.get("RepoTags")
            if raw_repo_tags is None:
                repo_tags: tuple[str, ...] = ()
            elif (
                not isinstance(raw_repo_tags, list)
                or not raw_repo_tags
                or any(
                    not isinstance(tag, str) or not tag
                    for tag in raw_repo_tags
                )
                or len(set(raw_repo_tags)) != len(raw_repo_tags)
            ):
                die("image archive repository tags are invalid")
            else:
                repo_tags = tuple(raw_repo_tags)
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
                return archive_image_id, repo_tags

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
            return archive_image_id, repo_tags
    except (OSError, tarfile.TarError, json.JSONDecodeError) as exc:
        die(f"image archive is not a readable Docker archive: {exc}")


def validate_syft(
    report: dict,
    image_kind: str,
    expected_image_id: str,
    archive: Path,
    expected_python: dict[str, str],
) -> tuple[int, set[str], set[str], int, int, int]:
    validate_syft_schema(report)
    expected_os_type, _ = EXPECTED_OS_PACKAGE_TYPES[image_kind]
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        die("Syft contains no package inventory")
    package_names: set[str] = set()
    os_package_names: set[str] = set()
    os_package_versions: dict[str, str] = {}
    os_package_count = 0
    top_level_python_identities: set[tuple[str, str]] = set()
    python_package_count = 0
    top_level_python_package_count = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            die("Syft package inventory contains a non-object")
        name = artifact.get("name")
        version = artifact.get("version")
        package_type = artifact.get("type")
        if not all(
            isinstance(value, str) and value
            for value in (name, version, package_type)
        ):
            die("Syft package inventory contains an incomplete package identity")
        package_names.add(name)
        if package_type == expected_os_type:
            os_package_count += 1
            os_package_names.add(name)
            os_package_versions[name] = version
        if package_type == "python":
            python_package_count += 1
            locations = artifact.get("locations")
            if not isinstance(locations, list) or not locations:
                die("Syft Python package has no filesystem locations")
            top_level = False
            for location in locations:
                if not isinstance(location, dict):
                    die("Syft Python package location is not an object")
                path = location.get("path")
                if not isinstance(path, str) or not path:
                    die("Syft Python package location path is absent")
                if TOP_LEVEL_PYTHON_METADATA_RE.fullmatch(path):
                    top_level = True
            if top_level:
                top_level_python_package_count += 1
                top_level_python_identities.add(
                    (normalized_python_package_name(name), version)
                )
    if not os_package_names:
        die(f"Syft contains no {expected_os_type} OS package inventory")
    if os_package_count != len(os_package_names):
        die("Syft OS package inventory contains duplicate package names")

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

    matched_python_count = 0
    if image_kind == "app":
        missing = EXPECTED_APP_PACKAGES - package_names
        if missing:
            die(f"application SBOM is missing attributed packages: {sorted(missing)}")
        matched_python_count = validate_locked_python_inventory(
            top_level_python_identities, expected_python, "Syft"
        )
        if top_level_python_package_count != matched_python_count:
            die(
                "application Syft Python inventory contains duplicate top-level "
                "package identities"
            )
    elif image_kind == "postgres":
        postgres_versions = {
            str(artifact["version"])
            for artifact in artifacts
            if artifact.get("name") == "postgresql"
        }
        if not any(
            version == "18.6" or version.startswith("18.6-")
            for version in postgres_versions
        ):
            die("PostgreSQL SBOM does not identify PostgreSQL 18.6")
    elif image_kind == "egress":
        missing = EXPECTED_EGRESS_PACKAGES - package_names
        if missing:
            die(f"egress SBOM is missing policy-runtime packages: {sorted(missing)}")
    elif image_kind in {"rabbitmq", "rabbitmq-upgrade"}:
        validate_rabbitmq_security_packages(os_package_versions, "Syft")
    else:  # pragma: no cover - argparse enforces the choices
        die("unknown image kind")
    return (
        len(artifacts),
        package_names,
        os_package_names,
        python_package_count,
        top_level_python_package_count,
        matched_python_count,
    )


def validate_trivy(
    report: dict,
    image_kind: str,
    expected_image_id: str,
    archive: Path,
    archive_repo_tags: tuple[str, ...],
    expected_python: dict[str, str],
) -> tuple[int, int, set[str], int, int, int]:
    validate_trivy_schema(report)
    _, expected_os_type = EXPECTED_OS_PACKAGE_TYPES[image_kind]
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
    validate_trivy_artifact_identity(
        report, expected_image_id, archive_repo_tags
    )
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        die("Trivy contains no scan results")

    package_count = 0
    os_package_count = 0
    os_result_count = 0
    os_package_names: set[str] = set()
    os_package_versions: dict[str, str] = {}
    python_package_count = 0
    top_level_python_package_count = 0
    top_level_python_identities: set[tuple[str, str]] = set()
    vulnerabilities: list[dict] = []
    for result in results:
        if not isinstance(result, dict):
            die("Trivy results contain a non-object")
        result_class = result.get("Class")
        result_type = result.get("Type")
        if result_class == "os-pkgs":
            if result_type != expected_os_type:
                die("Trivy OS package result has an unexpected package type")
            os_result_count += 1
        packages = result.get("Packages")
        if packages is not None:
            if not isinstance(packages, list):
                die("Trivy package inventory is not a list")
            package_count += len(packages)
            for package in packages:
                if not isinstance(package, dict):
                    die("Trivy package inventory contains a non-object")
                name = package.get("Name")
                version = package.get("Version")
                if not all(
                    isinstance(value, str) and value for value in (name, version)
                ):
                    die("Trivy package inventory contains an incomplete identity")
                if result_class == "os-pkgs":
                    os_package_count += 1
                    os_package_names.add(name)
                    os_package_versions[name] = version
                if (
                    result_class == "lang-pkgs"
                    and result_type == "python-pkg"
                ):
                    python_package_count += 1
                    file_path = package.get("FilePath")
                    if not isinstance(file_path, str) or not file_path:
                        die("Trivy Python package filesystem path is absent")
                    if TOP_LEVEL_PYTHON_METADATA_RE.fullmatch(file_path):
                        top_level_python_package_count += 1
                        top_level_python_identities.add(
                            (normalized_python_package_name(name), version)
                        )
        found = result.get("Vulnerabilities")
        if found is not None:
            if not isinstance(found, list):
                die("Trivy vulnerabilities are not a list")
            vulnerabilities.extend(found)
    if package_count == 0:
        die("Trivy contains no package inventory")
    if os_result_count != 1 or not os_package_names:
        die(f"Trivy contains no unique {expected_os_type} OS package inventory")
    if os_package_count != len(os_package_names):
        die("Trivy OS package inventory contains duplicate package names")
    matched_python_count = 0
    if image_kind == "app":
        matched_python_count = validate_locked_python_inventory(
            top_level_python_identities, expected_python, "Trivy"
        )
        if top_level_python_package_count != matched_python_count:
            die(
                "application Trivy Python inventory contains duplicate top-level "
                "package identities"
            )
    elif image_kind in {"rabbitmq", "rabbitmq-upgrade"}:
        validate_rabbitmq_security_packages(os_package_versions, "Trivy")
    if vulnerabilities:
        identities = sorted(
            {
                str(item.get("VulnerabilityID", "unknown"))
                for item in vulnerabilities
                if isinstance(item, dict)
            }
        )
        die(f"Trivy reported HIGH/CRITICAL vulnerabilities: {identities}")
    return (
        package_count,
        len(vulnerabilities),
        os_package_names,
        python_package_count,
        top_level_python_package_count,
        matched_python_count,
    )


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
    parser.add_argument(
        "--image-kind",
        choices=("app", "postgres", "egress", "rabbitmq", "rabbitmq-upgrade"),
        required=True,
    )
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--syft", type=Path, required=True)
    parser.add_argument("--trivy", type=Path, required=True)
    parser.add_argument("--requirements-lock", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    arguments = parser.parse_args()

    if not IMAGE_ID_RE.fullmatch(arguments.image_id):
        die("expected Docker image ID is malformed")
    if not arguments.archive.is_file() or arguments.archive.is_symlink():
        die("image archive is absent or is a symlink")
    archive_image_id, archive_repo_tags = archive_config_image_id(
        arguments.archive, arguments.image_id
    )
    expected_python: dict[str, str] = {}
    requirements_lock_sha256 = ""
    expected_python_inventory_sha256 = ""
    if arguments.image_kind == "app":
        (
            expected_python,
            requirements_lock_sha256,
            expected_python_inventory_sha256,
        ) = load_python_requirements_lock(arguments.requirements_lock)

    (
        syft_count,
        _,
        syft_os_packages,
        syft_python_count,
        syft_top_level_python_count,
        syft_locked_python_count,
    ) = validate_syft(
        load_object(arguments.syft, "Syft report"),
        arguments.image_kind,
        archive_image_id,
        arguments.archive,
        expected_python,
    )
    (
        trivy_count,
        vulnerability_count,
        trivy_os_packages,
        trivy_python_count,
        trivy_top_level_python_count,
        trivy_locked_python_count,
    ) = validate_trivy(
        load_object(arguments.trivy, "Trivy report"),
        arguments.image_kind,
        archive_image_id,
        arguments.archive,
        archive_repo_tags,
        expected_python,
    )
    if syft_os_packages != trivy_os_packages:
        missing_from_trivy = sorted(syft_os_packages - trivy_os_packages)
        missing_from_syft = sorted(trivy_os_packages - syft_os_packages)
        die(
            "Syft and Trivy OS package inventories differ: "
            f"missing from Trivy={missing_from_trivy}, "
            f"missing from Syft={missing_from_syft}"
        )
    summary = {
        "archive_config_image_id": archive_image_id,
        "archive_sha256": sha256_file(arguments.archive),
        "docker_image_id": arguments.image_id,
        "image_kind": arguments.image_kind,
        "os_package_count": len(syft_os_packages),
        "syft_package_count": syft_count,
        "trivy_high_critical_count": vulnerability_count,
        "trivy_package_count": trivy_count,
    }
    if arguments.image_kind == "app":
        summary.update(
            {
                "expected_python_inventory_sha256": (
                    expected_python_inventory_sha256
                ),
                "expected_python_package_count": len(expected_python),
                "requirements_lock_sha256": requirements_lock_sha256,
                "syft_locked_python_package_count": syft_locked_python_count,
                "syft_python_package_count": syft_python_count,
                "syft_top_level_python_package_count": (
                    syft_top_level_python_count
                ),
                "trivy_locked_python_package_count": trivy_locked_python_count,
                "trivy_python_package_count": trivy_python_count,
                "trivy_top_level_python_package_count": (
                    trivy_top_level_python_count
                ),
            }
        )
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
