import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import tarfile
import tempfile
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "attest_arm64_legacy_image",
    ROOT / "scripts" / "attest_arm64_legacy_image.py",
)
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


class Arm64LegacyImageEvidenceTests(TestCase):
    source_sha = "a" * 40
    owner = "arm64-123-456-1"
    image_ref = f"backupsheep-ci-rabbitmq-legacy-source-arm64:123-{'a' * 40}-456-1"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.archive = self.root / "image.tar"
        self.record = self.root / "evidence.json"

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def _json_bytes(value):
        return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()

    @staticmethod
    def _add_member(archive, name, payload, *, kind=None):
        member = tarfile.TarInfo(name)
        member.mode = 0o600
        member.size = len(payload)
        if kind is not None:
            member.type = kind
        archive.addfile(member, io.BytesIO(payload))

    def _config(self, layer_payload, *, architecture="arm64", diff_id=None):
        labels = dict(evidence.EXPECTED_LABELS)
        labels["com.backupsheep.ci-run"] = self.owner
        return {
            "architecture": architecture,
            "config": {
                "Env": ["PATH=/usr/bin", "LD_LIBRARY_PATH=/opt/openssl/lib"],
                "Labels": labels,
                "User": "999:999",
            },
            "os": "linux",
            "rootfs": {
                "diff_ids": [
                    diff_id
                    or f"sha256:{hashlib.sha256(layer_payload).hexdigest()}"
                ],
                "type": "layers",
            },
        }

    def _write_classic_archive(
        self,
        *,
        architecture="arm64",
        diff_id=None,
        extra_manifest=False,
        hostile_member=None,
        duplicate_layer=False,
    ):
        layer_payload = b"arm64 legacy source layer\n"
        config_payload = self._json_bytes(
            self._config(layer_payload, architecture=architecture, diff_id=diff_id)
        )
        config_digest = hashlib.sha256(config_payload).hexdigest()
        config_name = f"{config_digest}.json"
        layer_name = "layer/layer.tar"
        entry = {
            "Config": config_name,
            "Layers": [layer_name],
            "RepoTags": [self.image_ref],
        }
        manifest = [entry, entry] if extra_manifest else [entry]
        with tarfile.open(self.archive, "w") as archive:
            self._add_member(archive, config_name, config_payload)
            self._add_member(archive, layer_name, layer_payload)
            if duplicate_layer:
                self._add_member(archive, layer_name, layer_payload)
            if hostile_member is not None:
                name, kind = hostile_member
                self._add_member(archive, name, b"hostile", kind=kind)
            self._add_member(archive, "manifest.json", self._json_bytes(manifest))
        return f"sha256:{config_digest}"

    def _write_oci_archive(self):
        raw_layer = b"native arm64 compressed legacy layer\n"
        compressed_layer = gzip.compress(raw_layer, mtime=0)
        layer_digest = f"sha256:{hashlib.sha256(compressed_layer).hexdigest()}"
        diff_id = f"sha256:{hashlib.sha256(raw_layer).hexdigest()}"
        config_payload = self._json_bytes(self._config(raw_layer, diff_id=diff_id))
        config_digest = f"sha256:{hashlib.sha256(config_payload).hexdigest()}"
        image_manifest = {
            "config": {
                "digest": config_digest,
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": len(config_payload),
            },
            "layers": [
                {
                    "digest": layer_digest,
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "size": len(compressed_layer),
                }
            ],
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2,
        }
        image_manifest_payload = self._json_bytes(image_manifest)
        image_manifest_digest = (
            f"sha256:{hashlib.sha256(image_manifest_payload).hexdigest()}"
        )
        image_index = {
            "manifests": [
                {
                    "digest": image_manifest_digest,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "platform": {"architecture": "arm64", "os": "linux"},
                    "size": len(image_manifest_payload),
                }
            ],
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "schemaVersion": 2,
        }
        image_index_payload = self._json_bytes(image_index)
        image_id = f"sha256:{hashlib.sha256(image_index_payload).hexdigest()}"
        root_index = {
            "manifests": [
                {
                    "digest": image_id,
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "size": len(image_index_payload),
                }
            ],
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "schemaVersion": 2,
        }
        docker_manifest = [
            {
                "Config": f"blobs/sha256/{config_digest.removeprefix('sha256:')}",
                "Layers": [
                    f"blobs/sha256/{layer_digest.removeprefix('sha256:')}"
                ],
                "RepoTags": [self.image_ref],
            }
        ]
        members = {
            f"blobs/sha256/{config_digest.removeprefix('sha256:')}": config_payload,
            f"blobs/sha256/{image_id.removeprefix('sha256:')}": image_index_payload,
            f"blobs/sha256/{image_manifest_digest.removeprefix('sha256:')}": image_manifest_payload,
            f"blobs/sha256/{layer_digest.removeprefix('sha256:')}": compressed_layer,
            "index.json": self._json_bytes(root_index),
            "manifest.json": self._json_bytes(docker_manifest),
            "oci-layout": self._json_bytes({"imageLayoutVersion": "1.0.0"}),
        }
        with tarfile.open(self.archive, "w") as archive:
            for name, payload in members.items():
                self._add_member(archive, name, payload)
        return image_id

    def _attest(self, image_id):
        return evidence.attest(
            SimpleNamespace(
                archive=self.archive,
                evidence=self.record,
                expected_image_id=image_id,
                expected_image_ref=self.image_ref,
                expected_owner=self.owner,
                source_sha=self.source_sha,
            )
        )

    def _verify(self, image_id, archive_digest=None, evidence_digest=None):
        archive_digest = archive_digest or evidence._sha256_path(
            self.archive, evidence.MAX_ARCHIVE_BYTES, "test archive"
        )[0]
        evidence_digest = evidence_digest or evidence._sha256_path(
            self.record, evidence.MAX_EVIDENCE_BYTES, "test evidence"
        )[0]
        return evidence.verify(
            SimpleNamespace(
                archive=self.archive,
                evidence=self.record,
                expected_archive_sha256=archive_digest,
                expected_evidence_sha256=evidence_digest,
                expected_image_id=image_id,
                expected_image_ref=self.image_ref,
                expected_owner=self.owner,
                source_sha=self.source_sha,
            )
        )

    def test_classic_archive_attestation_binds_config_manifest_layers_and_owner(self):
        image_id = self._write_classic_archive()
        self.assertEqual(self._attest(image_id), image_id)
        self.assertEqual(self._verify(image_id), image_id)
        recorded = json.loads(self.record.read_text())
        self.assertEqual(recorded["docker_image_id"], image_id)
        self.assertEqual(recorded["platform"], "linux/arm64")
        self.assertEqual(recorded["ownership"], self.owner)
        self.assertEqual(recorded["config"]["sha256"], image_id)
        self.assertEqual(len(recorded["layers"]), 1)
        self.assertIsNone(recorded["oci"])
        self.assertEqual(stat.S_IMODE(self.record.stat().st_mode), 0o600)

    def test_containerd_oci_archive_binds_index_manifest_config_and_gzip_layer(self):
        image_id = self._write_oci_archive()
        config_digest = self._attest(image_id)
        self.assertEqual(self._verify(image_id), config_digest)
        recorded = json.loads(self.record.read_text())
        self.assertEqual(recorded["oci"]["top_level_sha256"], image_id)
        self.assertRegex(recorded["oci"]["image_manifest_sha256"], r"^sha256:")
        self.assertNotEqual(recorded["config"]["sha256"], image_id)
        self.assertEqual(config_digest, recorded["config"]["sha256"])

    def test_changed_archive_or_evidence_fails_producer_digest_binding(self):
        image_id = self._write_classic_archive()
        self._attest(image_id)
        archive_digest = evidence._sha256_path(
            self.archive, evidence.MAX_ARCHIVE_BYTES, "test archive"
        )[0]
        evidence_digest = evidence._sha256_path(
            self.record, evidence.MAX_EVIDENCE_BYTES, "test evidence"
        )[0]
        with self.archive.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(evidence.EvidenceError, "producer job digest"):
            self._verify(image_id, archive_digest, evidence_digest)

        self.archive.unlink()
        self.record.unlink()
        image_id = self._write_classic_archive()
        self._attest(image_id)
        archive_digest = evidence._sha256_path(
            self.archive, evidence.MAX_ARCHIVE_BYTES, "test archive"
        )[0]
        evidence_digest = evidence._sha256_path(
            self.record, evidence.MAX_EVIDENCE_BYTES, "test evidence"
        )[0]
        self.record.write_text('{"schema_version":1,"schema_version":1}\n')
        changed_evidence_digest = evidence._sha256_path(
            self.record, evidence.MAX_EVIDENCE_BYTES, "test evidence"
        )[0]
        with self.assertRaisesRegex(evidence.EvidenceError, "duplicate key"):
            self._verify(image_id, archive_digest, changed_evidence_digest)
        self.assertNotEqual(evidence_digest, changed_evidence_digest)

    def test_wrong_architecture_owner_config_or_layer_identity_fails_closed(self):
        image_id = self._write_classic_archive(architecture="amd64")
        with self.assertRaisesRegex(evidence.EvidenceError, "not linux/arm64"):
            self._attest(image_id)

        self.archive.unlink()
        image_id = self._write_classic_archive()
        with self.assertRaisesRegex(evidence.EvidenceError, "label contract"):
            evidence.inspect_archive(
                self.archive,
                expected_image_id=image_id,
                expected_image_ref=self.image_ref,
                expected_owner="arm64-wrong-owner",
                source_sha=self.source_sha,
            )

        with self.assertRaisesRegex(evidence.EvidenceError, "config digest"):
            evidence.inspect_archive(
                self.archive,
                expected_image_id="sha256:" + "f" * 64,
                expected_image_ref=self.image_ref,
                expected_owner=self.owner,
                source_sha=self.source_sha,
            )

        self.archive.unlink()
        image_id = self._write_classic_archive(diff_id="sha256:" + "f" * 64)
        with self.assertRaisesRegex(evidence.EvidenceError, "rootfs diff ID"):
            self._attest(image_id)

    def test_multiple_images_duplicate_members_traversal_and_links_are_rejected(self):
        scenarios = (
            ({"extra_manifest": True}, "exactly one image"),
            ({"duplicate_layer": True}, "duplicate member"),
            ({"hostile_member": ("../escape", None)}, "unsafe member path"),
            (
                {"hostile_member": ("hostile-link", tarfile.SYMTYPE)},
                "link or special member",
            ),
        )
        for options, diagnostic in scenarios:
            with self.subTest(options=options):
                if self.archive.exists():
                    self.archive.unlink()
                image_id = self._write_classic_archive(**options)
                with self.assertRaisesRegex(evidence.EvidenceError, diagnostic):
                    self._attest(image_id)

    def test_archive_and_evidence_symlinks_or_hardlinks_are_rejected(self):
        image_id = self._write_classic_archive()
        real_archive = self.root / "real-image.tar"
        self.archive.rename(real_archive)
        self.archive.symlink_to(real_archive)
        with self.assertRaisesRegex(evidence.EvidenceError, "single-link regular"):
            self._attest(image_id)

        self.archive.unlink()
        real_archive.rename(self.archive)
        self._attest(image_id)
        evidence_hardlink = self.root / "evidence-hardlink.json"
        os.link(self.record, evidence_hardlink)
        with self.assertRaisesRegex(evidence.EvidenceError, "single-link regular"):
            self._verify(image_id)

    def test_attestation_never_replaces_an_existing_output(self):
        image_id = self._write_classic_archive()
        self._attest(image_id)
        with self.assertRaisesRegex(evidence.EvidenceError, "refusing to replace"):
            self._attest(image_id)

    def test_retag_changes_only_manifest_tag_and_writes_a_hash_bound_receipt(self):
        image_id = self._write_oci_archive()
        config_digest = self._attest(image_id)
        source_archive_digest = evidence._sha256_path(
            self.archive, evidence.MAX_ARCHIVE_BYTES, "test archive"
        )[0]
        source_evidence_digest = evidence._sha256_path(
            self.record, evidence.MAX_EVIDENCE_BYTES, "test evidence"
        )[0]
        source_bytes = self.archive.read_bytes()
        target_archive = self.root / "digest-tagged.tar"
        target_evidence = self.root / "digest-tagged.evidence.json"
        receipt = self.root / "retag.receipt.json"
        target_ref = f"backupsheep-rabbitmq-legacy-source:manifest-{'b' * 64}"

        observed_config = evidence.retag(
            SimpleNamespace(
                archive=self.archive,
                evidence=self.record,
                expected_archive_sha256=source_archive_digest,
                expected_evidence_sha256=source_evidence_digest,
                expected_image_id=image_id,
                expected_image_ref=self.image_ref,
                expected_owner=self.owner,
                source_sha=self.source_sha,
                target_archive=target_archive,
                target_evidence=target_evidence,
                target_image_ref=target_ref,
                receipt=receipt,
            )
        )

        self.assertEqual(observed_config, config_digest)
        self.assertEqual(self.archive.read_bytes(), source_bytes)
        source_record = json.loads(self.record.read_text())
        target_record = json.loads(target_evidence.read_text())
        self.assertEqual(target_record["image_reference"], target_ref)
        for key in (
            "config",
            "docker_image_id",
            "layers",
            "oci",
            "ownership",
            "platform",
            "source_sha",
        ):
            self.assertEqual(target_record[key], source_record[key])
        transform = json.loads(receipt.read_text())
        self.assertEqual(transform["source"]["archive_sha256"], source_archive_digest)
        self.assertEqual(
            transform["target"]["archive_sha256"],
            target_record["archive"]["sha256"],
        )
        self.assertEqual(transform["target"]["image_reference"], target_ref)

    def test_retag_rejects_wrong_producer_digest_before_writing_outputs(self):
        image_id = self._write_classic_archive()
        self._attest(image_id)
        source_evidence_digest = evidence._sha256_path(
            self.record, evidence.MAX_EVIDENCE_BYTES, "test evidence"
        )[0]
        target_archive = self.root / "must-not-exist.tar"
        with self.assertRaisesRegex(evidence.EvidenceError, "producer job digest"):
            evidence.retag(
                SimpleNamespace(
                    archive=self.archive,
                    evidence=self.record,
                    expected_archive_sha256="sha256:" + "f" * 64,
                    expected_evidence_sha256=source_evidence_digest,
                    expected_image_id=image_id,
                    expected_image_ref=self.image_ref,
                    expected_owner=self.owner,
                    source_sha=self.source_sha,
                    target_archive=target_archive,
                    target_evidence=self.root / "must-not-exist.evidence.json",
                    target_image_ref=(
                        "backupsheep-rabbitmq-legacy-source:manifest-" + "b" * 64
                    ),
                    receipt=self.root / "must-not-exist.receipt.json",
                )
            )
        self.assertFalse(target_archive.exists())
