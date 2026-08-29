import base64
import copy
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
from unittest import TestCase, mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import prepare_trivy_db as trivy_db  # noqa: E402
import preflight_release_verifier_scan as scan_preflight  # noqa: E402
import validate_release_verifier_layout as verifier  # noqa: E402


def digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def compact(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


class VerifierFixture:
    repository = "ghcr.io/bilal414/backupsheep-release-verifier-quarantine"
    tag = "bootstrap-" + "a" * 40 + "-123-1"

    def __init__(self, root: Path):
        self.root = root
        self.layout = root / "layout"
        self.blobs = self.layout / "blobs" / "sha256"
        self.blobs.mkdir(parents=True)
        self.evidence = root / "evidence"
        self.evidence.mkdir()
        self.summary = self.evidence / "summary.json"
        self.syft_paths: dict[str, Path] = {}
        self.trivy_paths: dict[str, Path] = {}
        self.scan_layouts: dict[str, Path] = {}
        self.images: dict[str, dict] = {}
        self._build_layout()
        self._build_scan_layouts()
        self._build_reports()
        self._build_database()

    @staticmethod
    def _json(path: Path, document: object) -> None:
        path.write_bytes(compact(document))

    def _blob(self, payload: bytes) -> dict:
        value = digest(payload)
        path = self.blobs / value.removeprefix("sha256:")
        if not path.exists():
            path.write_bytes(payload)
        return {"mediaType": "", "digest": value, "size": len(payload)}

    @staticmethod
    def _elf(architecture: str) -> bytes:
        value = bytearray(verifier.MIN_VERIFIER_BYTES)
        value[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
        value[16:18] = (2).to_bytes(2, "little")
        value[18:20] = {"amd64": 62, "arm64": 183}[architecture].to_bytes(
            2, "little"
        )
        value[20:24] = (1).to_bytes(4, "little")
        value[24:32] = (0x400000).to_bytes(8, "little")
        value[52:54] = (64).to_bytes(2, "little")
        value[54:56] = (56).to_bytes(2, "little")
        value[56:58] = (2).to_bytes(2, "little")
        value[-16:] = architecture.encode("ascii").ljust(16, b"\x00")
        return bytes(value)

    @staticmethod
    def _layer(path: str, payload: bytes, mode: int) -> tuple[bytes, str, int]:
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            current = Path(path).parent
            ancestors: list[str] = []
            while current.as_posix() != ".":
                ancestors.append(current.as_posix())
                current = current.parent
            for name in reversed(ancestors):
                directory = tarfile.TarInfo(name)
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                directory.uid = 0
                directory.gid = 0
                archive.addfile(directory)
            member = tarfile.TarInfo(path)
            member.size = len(payload)
            member.mode = mode
            member.uid = 0
            member.gid = 0
            archive.addfile(member, io.BytesIO(payload))
        uncompressed = raw.getvalue()
        return gzip.compress(uncompressed, mtime=0), digest(uncompressed), len(uncompressed)

    @staticmethod
    def _history() -> list[dict]:
        result = []
        for created_by, empty in verifier.EXPECTED_HISTORY:
            item = {
                "created": verifier.EXPECTED_BUILD_TIMESTAMP,
                "created_by": created_by,
                "comment": "buildkit.dockerfile.v0",
            }
            if empty:
                item["empty_layer"] = True
            result.append(item)
        return result

    def _build_layout(self) -> None:
        self._json(self.layout / "oci-layout", {"imageLayoutVersion": "1.0.0"})
        certificate = (
            b"-----BEGIN CERTIFICATE-----\n"
            + b"QmFja3VwU2hlZXAtcmV2aWV3ZWQtQ0E=\n" * 40
            + b"-----END CERTIFICATE-----\n"
        )
        cert_layer, cert_diff_id, cert_uncompressed = self._layer(
            "etc/ssl/certs/ca-certificates.crt", certificate, 0o444
        )
        cert_descriptor = self._blob(cert_layer)
        cert_descriptor["mediaType"] = verifier.OCI_LAYER
        cert_descriptor["annotations"] = verifier.EXPECTED_LAYER_ANNOTATIONS

        child_descriptors = []
        for architecture in ("amd64", "arm64"):
            platform = f"linux/{architecture}"
            binary = self._elf(architecture)
            binary_layer, binary_diff_id, binary_uncompressed = self._layer(
                "ko-app/cosign", binary, 0o555
            )
            binary_descriptor = self._blob(binary_layer)
            binary_descriptor["mediaType"] = verifier.OCI_LAYER
            binary_descriptor["annotations"] = verifier.EXPECTED_LAYER_ANNOTATIONS
            config = {
                "architecture": architecture,
                "config": {
                    "User": verifier.EXPECTED_USER,
                    "Env": verifier.EXPECTED_ENV,
                    "Entrypoint": verifier.EXPECTED_ENTRYPOINT,
                    "WorkingDir": "/",
                    "Labels": verifier.EXPECTED_LABELS,
                },
                "created": verifier.EXPECTED_BUILD_TIMESTAMP,
                "history": self._history(),
                "os": "linux",
                "rootfs": {
                    "type": "layers",
                    "diff_ids": [cert_diff_id, binary_diff_id],
                },
            }
            config_bytes = json.dumps(
                config, sort_keys=True, separators=(",", ":")
            ).encode("ascii")
            config_descriptor = self._blob(config_bytes)
            config_descriptor["mediaType"] = verifier.OCI_CONFIG
            manifest = {
                "schemaVersion": 2,
                "mediaType": verifier.OCI_MANIFEST,
                "config": config_descriptor,
                "layers": [cert_descriptor, binary_descriptor],
            }
            manifest_bytes = json.dumps(
                manifest, sort_keys=True, separators=(",", ":")
            ).encode("ascii")
            manifest_descriptor = self._blob(manifest_bytes)
            manifest_descriptor["mediaType"] = verifier.OCI_MANIFEST
            manifest_descriptor["platform"] = {
                "architecture": architecture,
                "os": "linux",
            }
            child_descriptors.append(manifest_descriptor)
            self.images[platform] = {
                "binary": binary,
                "binary_sha256": hashlib.sha256(binary).hexdigest(),
                "binary_diff_id": binary_diff_id,
                "binary_uncompressed": binary_uncompressed,
                "certificate_size": len(certificate),
                "cert_diff_id": cert_diff_id,
                "cert_uncompressed": cert_uncompressed,
                "config": config,
                "config_bytes": config_bytes,
                "config_digest": config_descriptor["digest"],
                "manifest": manifest,
                "manifest_bytes": manifest_bytes,
                "manifest_digest": manifest_descriptor["digest"],
            }
        index = {
            "schemaVersion": 2,
            "mediaType": verifier.OCI_INDEX,
            "manifests": child_descriptors,
        }
        index_bytes = json.dumps(index, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        index_descriptor = self._blob(index_bytes)
        index_descriptor["mediaType"] = verifier.OCI_INDEX
        index_descriptor["annotations"] = {
            "io.containerd.image.name": f"{self.repository}:{self.tag}",
            "org.opencontainers.image.created": verifier.EXPECTED_BUILD_TIMESTAMP,
            "org.opencontainers.image.ref.name": self.tag,
        }
        self.index_digest = index_descriptor["digest"]
        self._json(
            self.layout / "index.json",
            {
                "schemaVersion": 2,
                "mediaType": verifier.OCI_INDEX,
                "manifests": [index_descriptor],
            },
        )

    def _build_scan_layouts(self) -> None:
        scan_root = self.root / "scans"
        scan_root.mkdir(mode=0o700)
        for platform in verifier.EXPECTED_PLATFORMS:
            architecture = platform.split("/", 1)[1]
            image = self.images[platform]
            scan_layout = scan_root / architecture
            scan_blobs = scan_layout / "blobs" / "sha256"
            scan_blobs.mkdir(parents=True, mode=0o700)
            scan_layout.chmod(0o700)
            self._json(
                scan_layout / "oci-layout", {"imageLayoutVersion": "1.0.0"}
            )
            self._json(
                scan_layout / "index.json",
                {
                    "schemaVersion": 2,
                    "mediaType": verifier.OCI_INDEX,
                    "manifests": [
                        {
                            "mediaType": verifier.OCI_MANIFEST,
                            "digest": image["manifest_digest"],
                            "size": len(image["manifest_bytes"]),
                            "annotations": {
                                "org.opencontainers.image.ref.name": (
                                    f"scan-{architecture}"
                                )
                            },
                            "platform": {
                                "architecture": architecture,
                                "os": "linux",
                            },
                        }
                    ],
                },
            )
            digests = {
                image["manifest_digest"],
                image["config_digest"],
                *(layer["digest"] for layer in image["manifest"]["layers"]),
            }
            for value in digests:
                shutil.copyfile(
                    self.blobs / value.removeprefix("sha256:"),
                    scan_blobs / value.removeprefix("sha256:"),
                )
            self.scan_layouts[platform] = scan_layout

    @staticmethod
    def _syft_artifact(
        *, name: str, version: str, architecture: str, binary_diff_id: str
    ) -> dict:
        metadata = {
            "goCompiledVersion": "go1.26.6",
            "architecture": "" if name == "stdlib" else architecture,
        }
        purl_version = version
        if name == verifier.MAIN_MODULE:
            metadata.update(
                {
                    "mainModule": verifier.MAIN_MODULE,
                    "goBuildSettings": [
                        {"key": "-buildmode", "value": "exe"},
                        {"key": "-compiler", "value": "gc"},
                        {"key": "-trimpath", "value": "true"},
                        {"key": "CGO_ENABLED", "value": "0"},
                        {"key": "GOARCH", "value": architecture},
                        {"key": "GOOS", "value": "linux"},
                        {
                            "key": "GOAMD64" if architecture == "amd64" else "GOARM64",
                            "value": "v1" if architecture == "amd64" else "v8.0",
                        },
                    ],
                }
            )
            purl_version = ""
        return {
            "id": hashlib.sha256(f"{name}@{version}".encode()).hexdigest()[:16],
            "name": name,
            "version": version,
            "type": "go-module",
            "foundBy": "go-module-binary-cataloger",
            "locations": [
                {
                    "path": "/ko-app/cosign",
                    "layerID": binary_diff_id,
                    "accessPath": "/ko-app/cosign",
                    "annotations": {"evidence": "primary"},
                }
            ],
            "licenses": [],
            "language": "go",
            "cpes": [],
            "purl": (
                f"pkg:golang/{name}"
                + (f"@{purl_version.removeprefix('go')}" if purl_version else "")
            ),
            "metadataType": "go-module-buildinfo-entry",
            "metadata": metadata,
        }

    @staticmethod
    def _trivy_package(
        *, name: str, version: str | None, binary_diff_id: str
    ) -> dict:
        if name == verifier.MAIN_MODULE:
            identifier = f"pkg:golang/{name}"
            package_id = name
        else:
            identifier = f"pkg:golang/{name.lower()}@{version}"
            package_id = f"{name}@{version}"
        result = {
            "ID": package_id,
            "Name": name,
            "Identifier": {"PURL": identifier, "UID": "reviewed-fixture"},
            "Layer": {"DiffID": binary_diff_id},
            "AnalyzedBy": "gobinary",
        }
        if name != verifier.MAIN_MODULE:
            result["Version"] = version
        return result

    def _inventory(self, platform: str) -> tuple[list[dict], list[dict]]:
        architecture = platform.split("/", 1)[1]
        image = self.images[platform]
        versions = {
            verifier.MAIN_MODULE: verifier.SYFT_MAIN_PLACEHOLDER,
            "stdlib": "go1.26.6",
            "golang.org/x/mod": "v0.40.0",
            "golang.org/x/text": "v0.41.0",
            "google.golang.org/grpc": "v1.82.1",
        }
        syft = [
            self._syft_artifact(
                name=name,
                version=version,
                architecture=architecture,
                binary_diff_id=image["binary_diff_id"],
            )
            for name, version in versions.items()
        ]
        trivy_versions = {
            verifier.MAIN_MODULE: None,
            "stdlib": "v1.26.6",
            "golang.org/x/mod": "v0.40.0",
            "golang.org/x/text": "v0.41.0",
            "google.golang.org/grpc": "v1.82.1",
        }
        trivy = [
            self._trivy_package(
                name=name,
                version=version,
                binary_diff_id=image["binary_diff_id"],
            )
            for name, version in trivy_versions.items()
        ]
        trivy[0]["Relationship"] = "root"
        trivy[0]["DependsOn"] = [package["ID"] for package in trivy[1:]]
        trivy[1]["Relationship"] = "direct"
        return syft, trivy

    def _build_reports(self) -> None:
        for platform in verifier.EXPECTED_PLATFORMS:
            architecture = platform.split("/", 1)[1]
            image = self.images[platform]
            syft_inventory, trivy_inventory = self._inventory(platform)
            layers = image["manifest"]["layers"]
            syft = {
                "artifacts": syft_inventory,
                "artifactRelationships": [],
                "descriptor": {
                    "name": "syft",
                    "version": verifier.EXPECTED_SYFT_VERSION,
                    "configuration": {},
                },
                "schema": verifier.EXPECTED_SYFT_SCHEMA,
                "source": {
                    "id": image["manifest_digest"].removeprefix("sha256:"),
                    "name": str(self.scan_layouts[platform]),
                    "version": image["manifest_digest"],
                    "type": "image",
                    "metadata": {
                        "userInput": str(self.scan_layouts[platform]),
                        "imageID": image["config_digest"],
                        "manifestDigest": image["manifest_digest"],
                        "mediaType": verifier.OCI_MANIFEST,
                        "tags": [],
                        "imageSize": image["certificate_size"] + len(image["binary"]),
                        "layers": [
                            {
                                "mediaType": verifier.OCI_LAYER,
                                "digest": image["cert_diff_id"],
                                "size": image["certificate_size"],
                            },
                            {
                                "mediaType": verifier.OCI_LAYER,
                                "digest": image["binary_diff_id"],
                                "size": len(image["binary"]),
                            },
                        ],
                        "manifest": base64.b64encode(image["manifest_bytes"]).decode(),
                        "config": base64.b64encode(image["config_bytes"]).decode(),
                        "repoDigests": [],
                        "architecture": architecture,
                        "os": "linux",
                        "labels": verifier.EXPECTED_LABELS,
                    },
                },
                "distro": {},
                "files": [
                    {
                        "id": "verifier-file",
                        "location": {
                            "path": "/ko-app/cosign",
                            "layerID": image["binary_diff_id"],
                        },
                        "metadata": {
                            "mode": 555,
                            "type": "RegularFile",
                            "userID": 0,
                            "groupID": 0,
                            "mimeType": "application/x-executable",
                            "size": len(image["binary"]),
                        },
                        "digests": [
                            {
                                "algorithm": "sha256",
                                "value": image["binary_sha256"],
                            }
                        ],
                        "executable": {
                            "format": "elf",
                            "hasExports": False,
                            "hasEntrypoint": True,
                            "importedLibraries": [],
                            "elfSecurityFeatures": {
                                "symbolTableStripped": True,
                                "nx": True,
                                "relRO": "none",
                                "pie": False,
                                "dso": False,
                            },
                        },
                    }
                ],
            }
            trivy = {
                "SchemaVersion": 2,
                "CreatedAt": "2026-08-29T15:02:00Z",
                "ArtifactName": str(self.scan_layouts[platform]),
                "ArtifactType": "container_image",
                "ArtifactID": image["config_digest"],
                "Metadata": {
                    "Size": sum(
                        image[key]
                        for key in ("cert_uncompressed", "binary_uncompressed")
                    ),
                    "ImageID": image["config_digest"],
                    "DiffIDs": [image["cert_diff_id"], image["binary_diff_id"]],
                    "ImageConfig": image["config"],
                    "Layers": [
                        {
                            "Digest": layer["digest"],
                            "DiffID": diff_id,
                            "Size": layer["size"],
                        }
                        for layer, diff_id in zip(
                            layers,
                            (image["cert_diff_id"], image["binary_diff_id"]),
                            strict=True,
                        )
                    ],
                },
                "Results": [
                    {
                        "Target": "ko-app/cosign",
                        "Class": "lang-pkgs",
                        "Type": "gobinary",
                        "Packages": trivy_inventory,
                    }
                ],
                "ReportID": "00000000-0000-0000-0000-000000000000",
                "Trivy": {"Version": verifier.EXPECTED_TRIVY_VERSION},
            }
            syft_path = self.evidence / f"{architecture}.syft.json"
            trivy_path = self.evidence / f"{architecture}.trivy.json"
            self._json(syft_path, syft)
            self._json(trivy_path, trivy)
            self.syft_paths[platform] = syft_path
            self.trivy_paths[platform] = trivy_path

    def _build_database(self, *, stale: bool = False) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        lock = json.loads((ROOT / "deploy" / "trivy-db-lock.json").read_text())
        lock["database"]["updated_at"] = (now - timedelta(hours=2)).isoformat().replace(
            "+00:00", "Z"
        )
        lock["manifest"]["created_at"] = (now - timedelta(hours=1)).isoformat().replace(
            "+00:00", "Z"
        )
        next_update = now - timedelta(minutes=1) if stale else now + timedelta(days=1)
        lock["database"]["next_update"] = next_update.isoformat().replace("+00:00", "Z")
        self.lock_path = self.evidence / "trivy-db-lock.json"
        self._json(self.lock_path, lock)
        validated, lock_sha256 = trivy_db.load_lock(
            self.lock_path, now=now, check_freshness=False
        )
        evidence = trivy_db.evidence_for(validated, lock_sha256, now)
        self.db_evidence_path = self.evidence / "trivy-db-evidence.json"
        self._json(self.db_evidence_path, evidence)

    def report(self, platform: str, scanner: str) -> dict:
        path = self.syft_paths[platform] if scanner == "syft" else self.trivy_paths[platform]
        return json.loads(path.read_text())

    def write_report(self, platform: str, scanner: str, value: dict) -> None:
        path = self.syft_paths[platform] if scanner == "syft" else self.trivy_paths[platform]
        self._json(path, value)

    def inventory_policy(self):
        syft = self.report("linux/amd64", "syft")
        inventory = {
            artifact["name"]: (
                "" if artifact["name"] == verifier.MAIN_MODULE else artifact["version"]
            )
            for artifact in syft["artifacts"]
        }
        inventory_hash, _ = verifier._canonical_inventory(inventory)
        return mock.patch.multiple(
            verifier,
            EXPECTED_GO_PACKAGE_COUNT=len(inventory),
            EXPECTED_GO_INVENTORY_SHA256=inventory_hash,
        )

    def validate(self):
        return verifier.validate(
            layout=self.layout,
            index_digest=self.index_digest,
            repository=self.repository,
            tag=self.tag,
            scan_layouts=self.scan_layouts,
            syft_paths=self.syft_paths,
            trivy_paths=self.trivy_paths,
            trivy_db_lock=self.lock_path,
            trivy_db_evidence=self.db_evidence_path,
            summary=self.summary,
        )


class ReleaseVerifierLayoutTests(TestCase):
    def setUp(self):
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.fixture = VerifierFixture(self.root)

    def tearDown(self):
        self.temporary.cleanup()
        super().tearDown()

    def assert_rejected(self, pattern: str):
        with self.fixture.inventory_policy(), self.assertRaisesRegex(
            verifier.ValidationError, pattern
        ):
            self.fixture.validate()

    def test_valid_layout_is_bound_normalized_and_summarized(self):
        with self.fixture.inventory_policy():
            summary = self.fixture.validate()
        self.assertEqual(summary["index_digest"], self.fixture.index_digest)
        self.assertEqual(
            summary["trivy_database"]["assurance"],
            "reviewed digest-locked; not signed or authenticated",
        )
        self.assertEqual(set(summary["platforms"]), set(verifier.EXPECTED_PLATFORMS))
        for platform in verifier.EXPECTED_PLATFORMS:
            immutable = (
                f"{self.fixture.repository}@"
                f"{self.fixture.images[platform]['manifest_digest']}"
            )
            self.assertEqual(
                self.fixture.report(platform, "syft")["source"]["metadata"]["userInput"],
                immutable,
            )
            self.assertEqual(
                self.fixture.report(platform, "trivy")["ArtifactName"], immutable
            )
        self.assertEqual(self.fixture.summary.stat().st_mode & 0o777, 0o600)

    def test_scan_preflight_binds_two_distinct_single_platform_projections(self):
        images, layout_binding, identities = verifier.preflight(
            layout=self.fixture.layout,
            index_digest=self.fixture.index_digest,
            repository=self.fixture.repository,
            tag=self.fixture.tag,
            scan_layouts=self.fixture.scan_layouts,
        )
        self.assertEqual(set(images), set(verifier.EXPECTED_PLATFORMS))
        self.assertEqual(len(layout_binding), 64)
        self.assertEqual(
            identities,
            {
                platform: str(self.fixture.scan_layouts[platform])
                for platform in verifier.EXPECTED_PLATFORMS
            },
        )
        self.assertNotEqual(
            images["linux/amd64"].manifest_digest,
            images["linux/arm64"].manifest_digest,
        )
        self.assertNotEqual(identities["linux/amd64"], identities["linux/arm64"])

    def test_scan_projection_paths_cannot_be_swapped_or_redirected(self):
        self.fixture.scan_layouts = {
            "linux/amd64": self.fixture.scan_layouts["linux/arm64"],
            "linux/arm64": self.fixture.scan_layouts["linux/amd64"],
        }
        self.assert_rejected("path is not canonical")

        self.fixture = VerifierFixture(self.root / "second")
        amd64 = self.fixture.scan_layouts["linux/amd64"]
        redirected = amd64.with_name("amd64-real")
        amd64.replace(redirected)
        amd64.symlink_to(redirected, target_is_directory=True)
        self.assert_rejected("owner-private real directory")

    def test_scan_projection_permissions_and_graph_tampering_fail_closed(self):
        amd64 = self.fixture.scan_layouts["linux/amd64"]
        amd64.chmod(0o755)
        self.assert_rejected("owner-private real directory")

        self.fixture = VerifierFixture(self.root / "second")
        amd64 = self.fixture.scan_layouts["linux/amd64"]
        (amd64 / "blobs" / "sha256" / ("f" * 64)).write_bytes(b"extra")
        self.assert_rejected("graph is not exact")

        self.fixture = VerifierFixture(self.root / "third")
        image = self.fixture.images["linux/arm64"]
        config = (
            self.fixture.scan_layouts["linux/arm64"]
            / "blobs"
            / "sha256"
            / image["config_digest"].removeprefix("sha256:")
        )
        config.write_bytes(config.read_bytes() + b" ")
        self.assert_rejected("bytes do not match")

    def test_pre_normalized_syft_input_is_rejected_without_mutating_trivy(self):
        platform = "linux/amd64"
        report = self.fixture.report(platform, "syft")
        report["source"]["metadata"]["userInput"] = (
            f"{self.fixture.repository}@{self.fixture.images[platform]['manifest_digest']}"
        )
        self.fixture.write_report(platform, "syft", report)
        before = self.fixture.trivy_paths[platform].read_bytes()
        self.assert_rejected("pre-normalized")
        self.assertEqual(self.fixture.trivy_paths[platform].read_bytes(), before)

    def test_wrong_root_digest_and_unreferenced_blob_fail_closed(self):
        self.fixture.index_digest = "sha256:" + "f" * 64
        self.assert_rejected("index-digest")

        self.fixture = VerifierFixture(self.root / "second")
        (self.fixture.blobs / ("f" * 64)).write_bytes(b"unreferenced")
        self.assert_rejected("unreferenced")

    def test_outer_layout_index_requires_the_exact_oci_media_type(self):
        path = self.fixture.layout / "index.json"
        wrapper = json.loads(path.read_text(encoding="ascii"))
        wrapper["mediaType"] = verifier.OCI_MANIFEST
        self.fixture._json(path, wrapper)
        self.assert_rejected("schema or media type")

    def test_root_descriptor_created_timestamp_is_reproducibly_bound(self):
        path = self.fixture.layout / "index.json"
        wrapper = json.loads(path.read_text(encoding="ascii"))
        wrapper["manifests"][0]["annotations"][
            "org.opencontainers.image.created"
        ] = "2026-08-29T15:55:04Z"
        self.fixture._json(path, wrapper)
        self.assert_rejected("not bound")

    def test_privileged_or_expanded_runtime_config_is_rejected(self):
        image = self.fixture.images["linux/amd64"]
        unsafe = copy.deepcopy(image["config"])
        unsafe["config"]["User"] = "0"
        unsafe["config"]["Cmd"] = ["shell"]
        with self.assertRaisesRegex(verifier.ValidationError, "runtime config"):
            verifier._validate_config(
                json.dumps(unsafe, separators=(",", ":")).encode(),
                architecture="amd64",
                expected_diff_ids=tuple(unsafe["rootfs"]["diff_ids"]),
            )

    def test_wall_clock_image_history_is_rejected(self):
        image = self.fixture.images["linux/amd64"]
        unsafe = copy.deepcopy(image["config"])
        unsafe["created"] = "2026-08-29T16:06:29Z"
        unsafe["history"][-1]["created"] = "2026-08-29T16:06:29Z"
        with self.assertRaisesRegex(verifier.ValidationError, "reproducibly bound"):
            verifier._validate_config(
                json.dumps(unsafe, separators=(",", ":")).encode(),
                architecture="amd64",
                expected_diff_ids=tuple(unsafe["rootfs"]["diff_ids"]),
            )

    def test_layer_path_traversal_link_and_wrong_elf_architecture_are_rejected(self):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as archive:
            member = tarfile.TarInfo("../ko-app/cosign")
            payload = self.fixture._elf("amd64")
            member.size = len(payload)
            member.mode = 0o555
            archive.addfile(member, io.BytesIO(payload))
        with self.assertRaisesRegex(verifier.ValidationError, "path traversal"):
            verifier._inspect_layer(
                gzip.compress(raw.getvalue(), mtime=0),
                expected_file="ko-app/cosign",
                expected_mode=0o555,
                architecture="amd64",
            )

        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as archive:
            link = tarfile.TarInfo("ko-app/cosign")
            link.type = tarfile.SYMTYPE
            link.linkname = "/host/cosign"
            link.mode = 0o555
            archive.addfile(link)
        with self.assertRaisesRegex(verifier.ValidationError, "links"):
            verifier._inspect_layer(
                gzip.compress(raw.getvalue(), mtime=0),
                expected_file="ko-app/cosign",
                expected_mode=0o555,
                architecture="amd64",
            )

        arm_layer, _, _ = self.fixture._layer(
            "ko-app/cosign", self.fixture._elf("arm64"), 0o555
        )
        with self.assertRaisesRegex(verifier.ValidationError, "linux/amd64 ELF"):
            verifier._inspect_layer(
                arm_layer,
                expected_file="ko-app/cosign",
                expected_mode=0o555,
                architecture="amd64",
            )

    def test_syft_embedded_manifest_and_trivy_layer_mismatches_are_rejected(self):
        platform = "linux/amd64"
        syft = self.fixture.report(platform, "syft")
        syft["source"]["metadata"]["manifest"] = base64.b64encode(b"{}").decode()
        self.fixture.write_report(platform, "syft", syft)
        self.assert_rejected("embedded manifest")

        self.fixture = VerifierFixture(self.root / "second")
        trivy = self.fixture.report(platform, "trivy")
        trivy["Metadata"]["Layers"][0]["Digest"] = "sha256:" + "e" * 64
        self.fixture.write_report(platform, "trivy", trivy)
        self.assert_rejected("layer identity")

    def test_scanner_inventory_drift_and_extra_missing_versions_are_rejected(self):
        platform = "linux/amd64"
        trivy = self.fixture.report(platform, "trivy")
        dependency = trivy["Results"][0]["Packages"][2]
        dependency["Version"] = "v0.39.0"
        dependency["ID"] = f"{dependency['Name']}@v0.39.0"
        dependency["Identifier"]["PURL"] = (
            f"pkg:golang/{dependency['Name']}@v0.39.0"
        )
        trivy["Results"][0]["Packages"][0]["DependsOn"][1] = dependency["ID"]
        self.fixture.write_report(platform, "trivy", trivy)
        self.assert_rejected("reviewed Go identities")

        self.fixture = VerifierFixture(self.root / "second")
        trivy = self.fixture.report(platform, "trivy")
        trivy["Results"][0]["Packages"][0]["Version"] = "UNKNOWN"
        self.fixture.write_report(platform, "trivy", trivy)
        self.assert_rejected("null-version placeholder")

        self.fixture = VerifierFixture(self.root / "third")
        syft = self.fixture.report(platform, "syft")
        syft["artifacts"][2]["version"] = "UNKNOWN"
        self.fixture.write_report(platform, "syft", syft)
        self.assert_rejected("unauthorized missing")

    def test_high_or_critical_vulnerability_is_rejected(self):
        trivy = self.fixture.report("linux/arm64", "trivy")
        trivy["Results"][0]["Vulnerabilities"] = [
            {"VulnerabilityID": "CVE-2099-0001", "Severity": "CRITICAL"}
        ]
        self.fixture.write_report("linux/arm64", "trivy", trivy)
        self.assert_rejected("vulnerabilities")

    def test_tampered_or_stale_database_evidence_is_rejected_before_normalization(self):
        evidence = json.loads(self.fixture.db_evidence_path.read_text())
        evidence["db_sha256"] = "f" * 64
        self.fixture._json(self.fixture.db_evidence_path, evidence)
        before = self.fixture.syft_paths["linux/amd64"].read_bytes()
        self.assert_rejected("database evidence")
        self.assertEqual(self.fixture.syft_paths["linux/amd64"].read_bytes(), before)

        self.fixture = VerifierFixture(self.root / "second")
        self.fixture._build_database(stale=True)
        self.assert_rejected("stale")

    def test_existing_summary_and_symlinked_report_fail_before_mutation(self):
        self.fixture.summary.write_text("occupied")
        self.assert_rejected("must not pre-exist")

        self.fixture = VerifierFixture(self.root / "second")
        target = self.fixture.syft_paths["linux/amd64"]
        replacement = target.with_suffix(".real")
        target.replace(replacement)
        target.symlink_to(replacement)
        self.assert_rejected("single-link regular file")

    def test_duplicate_platform_and_extra_attestation_are_rejected(self):
        root_index_path = self.fixture.blobs / self.fixture.index_digest.removeprefix(
            "sha256:"
        )
        root_index = json.loads(root_index_path.read_text())
        root_index["manifests"].append(copy.deepcopy(root_index["manifests"][0]))
        new_payload = json.dumps(
            root_index, sort_keys=True, separators=(",", ":")
        ).encode()
        root_index_path.unlink()
        self.fixture.index_digest = digest(new_payload)
        (self.fixture.blobs / self.fixture.index_digest.removeprefix("sha256:")).write_bytes(
            new_payload
        )
        wrapper = json.loads((self.fixture.layout / "index.json").read_text())
        wrapper["manifests"][0]["digest"] = self.fixture.index_digest
        wrapper["manifests"][0]["size"] = len(new_payload)
        self.fixture._json(self.fixture.layout / "index.json", wrapper)
        self.assert_rejected("exactly two")


class ReleaseVerifierValidatorCLIContractTests(TestCase):
    def setUp(self):
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.fixture = VerifierFixture(self.root)

    def tearDown(self):
        self.temporary.cleanup()
        super().tearDown()

    def test_cli_exposes_the_bootstrap_workflow_interface(self):
        source = (ROOT / "scripts" / "validate_release_verifier_layout.py").read_text()
        for argument in (
            "--layout",
            "--index-digest",
            "--repository",
            "--tag",
            "--scan-layout-amd64",
            "--scan-layout-arm64",
            "--syft-amd64",
            "--trivy-amd64",
            "--syft-arm64",
            "--trivy-arm64",
            "--trivy-db-lock",
            "--trivy-db-evidence",
            "--summary",
        ):
            self.assertIn(f'parser.add_argument("{argument}"', source)
        self.assertIn("reviewed digest-locked; not signed or authenticated", source)
        self.assertNotIn("subprocess", source)

        preflight = (
            ROOT / "scripts" / "preflight_release_verifier_scan.py"
        ).read_text(encoding="utf-8")
        for argument in (
            "--layout",
            "--index-digest",
            "--repository",
            "--tag",
            "--source-only",
            "--scan-layout-amd64",
            "--scan-layout-arm64",
        ):
            self.assertIn(f'parser.add_argument("{argument}"', preflight)
        self.assertNotIn("subprocess", preflight)

    def test_source_only_cli_validates_before_projection_and_rejects_mixed_modes(self):
        base = [
            "--layout",
            str(self.fixture.layout),
            "--index-digest",
            self.fixture.index_digest,
            "--repository",
            self.fixture.repository,
            "--tag",
            self.fixture.tag,
        ]
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            status = scan_preflight.main(["--source-only", *base])
        self.assertEqual(status, 0)
        evidence = json.loads(output.getvalue())
        self.assertEqual(evidence["index_digest"], self.fixture.index_digest)
        for platform in verifier.EXPECTED_PLATFORMS:
            self.assertNotIn("scan_identity", evidence["platforms"][platform])

        errors = io.StringIO()
        with mock.patch("sys.stderr", errors):
            status = scan_preflight.main(
                [
                    "--source-only",
                    *base,
                    "--scan-layout-amd64",
                    str(self.fixture.scan_layouts["linux/amd64"]),
                ]
            )
        self.assertEqual(status, 1)
        self.assertIn("cannot be combined", errors.getvalue())

    def test_bootstrap_scans_only_validated_single_platform_projections(self):
        workflow = (
            ROOT / ".github" / "workflows" / "bootstrap-release-verifier.yml"
        ).read_text(encoding="utf-8")
        scan_step = workflow.split(
            "      - name: Scan both exact child images and validate the complete layout\n",
            1,
        )[1].split("      - name: Authenticate only after all local evidence passes\n", 1)[0]
        for expected in (
            "python3 scripts/preflight_release_verifier_scan.py",
            "--source-only",
            'test ! -e "$SCAN_ROOT"',
            'test ! -L "$SCAN_ROOT"',
            'test ! -e "$scan_layout"',
            'test ! -L "$scan_layout"',
            '"$TOOL_DIR/oras" cp',
            "--from-oci-layout",
            "--to-oci-layout",
            '--platform "$platform"',
            '--concurrency 1',
            '--no-tty',
            '"$LAYOUT_DIR:$CANDIDATE_TAG"',
            '"$scan_layout:scan-$architecture"',
            "python3 scripts/preflight_release_verifier_scan.py",
            '--scan-layout-amd64 "$SCAN_ROOT/amd64"',
            '--scan-layout-arm64 "$SCAN_ROOT/arm64"',
            'scan "oci-dir:$scan_layout"',
            '--input "$scan_layout"',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, scan_step)
        self.assertLess(
            scan_step.index("--source-only"),
            scan_step.index('"$TOOL_DIR/oras" cp'),
        )
        self.assertLess(
            scan_step.rindex("python3 scripts/preflight_release_verifier_scan.py"),
            scan_step.index('"$TOOL_DIR/syft"'),
        )
        syft_invocation = scan_step.split('"$TOOL_DIR/syft"', 1)[1].split(
            "trivy_status=0", 1
        )[0]
        trivy_invocation = scan_step.split('"$TOOL_DIR/trivy"', 1)[1].split(
            "trivy_status=$?", 1
        )[0]
        self.assertNotIn("--platform", syft_invocation)
        self.assertNotIn("--platform", trivy_invocation)

    def test_bootstrap_removes_only_buildkits_empty_ingest_directory(self):
        workflow = (
            ROOT / ".github" / "workflows" / "bootstrap-release-verifier.yml"
        ).read_text(encoding="utf-8")
        scan_step = workflow.split(
            "      - name: Scan both exact child images and validate the complete layout\n",
            1,
        )[1].split("      - name: Authenticate only after all local evidence passes\n", 1)[0]
        self.assertIn(
            'if [ -e "$LAYOUT_DIR/ingest" ] || [ -L "$LAYOUT_DIR/ingest" ]; then',
            scan_step,
        )
        self.assertIn(
            'test -z "$(find "$LAYOUT_DIR/ingest" -mindepth 1 -print -quit)"',
            scan_step,
        )
        self.assertIn('rmdir -- "$LAYOUT_DIR/ingest"', scan_step)
        self.assertLess(
            scan_step.index('rmdir -- "$LAYOUT_DIR/ingest"'),
            scan_step.index('"$TOOL_DIR/syft"'),
        )

    def test_bootstrap_binds_export_name_and_reproducible_index_timestamp(self):
        workflow = (
            ROOT / ".github" / "workflows" / "bootstrap-release-verifier.yml"
        ).read_text(encoding="utf-8")
        build_step = workflow.split(
            "      - name: Build the patched multi-platform verifier into a private OCI layout\n",
            1,
        )[1].split(
            "      - name: Scan both exact child images and validate the complete layout\n",
            1,
        )[0]
        self.assertIn(
            "name=${{ env.QUARANTINE_REPOSITORY }}:${{ env.CANDIDATE_TAG }}",
            build_step,
        )
        self.assertIn(
            "index-descriptor:org.opencontainers.image.created="
            + verifier.EXPECTED_BUILD_TIMESTAMP,
            build_step,
        )
        self.assertIn('SOURCE_DATE_EPOCH: "1787961600"', build_step)
        self.assertIn("BUILDKIT_MULTI_PLATFORM=1", build_step)
        self.assertIn("rewrite-timestamp=true", build_step)
