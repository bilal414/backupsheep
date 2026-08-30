import copy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
from unittest import TestCase, mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import prepare_trivy_db as trivy_db  # noqa: E402


class TrivyDatabaseLockTests(TestCase):
    def setUp(self):
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.now = datetime(2030, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
        self.lock = json.loads(
            (ROOT / "deploy" / "trivy-db-lock.json").read_text(encoding="utf-8")
        )
        self.lock["database"].update(
            {
                "updated_at": "2030-01-02T10:00:00Z",
                "next_update": "2030-01-03T10:00:00Z",
                "downloaded_at": "0001-01-01T00:00:00Z",
            }
        )
        self.lock["manifest"]["created_at"] = "2030-01-02T10:05:00Z"
        self.database_bytes = b"reviewed-fixture-database\x00\x01"
        self.metadata_bytes = json.dumps(
            {
                "Version": 2,
                "NextUpdate": self.lock["database"]["next_update"],
                "UpdatedAt": self.lock["database"]["updated_at"],
                "DownloadedAt": self.lock["database"]["downloaded_at"],
            },
            separators=(",", ":"),
        ).encode("ascii")
        self.lock["database"].update(
            {
                "db_sha256": hashlib.sha256(self.database_bytes).hexdigest(),
                "db_size": len(self.database_bytes),
                "metadata_sha256": hashlib.sha256(self.metadata_bytes).hexdigest(),
                "metadata_size": len(self.metadata_bytes),
            }
        )
        self.layer = self.root / "db.tar.gz"
        with tarfile.open(self.layer, mode="w:gz") as archive:
            for name, payload in (
                ("trivy.db", self.database_bytes),
                ("metadata.json", self.metadata_bytes),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(payload))
        self.lock["manifest"]["layer"].update(
            {
                "digest": "sha256:" + self._sha256(self.layer),
                "size": self.layer.stat().st_size,
            }
        )
        self.manifest = self.root / "manifest.json"
        self._write_manifest_and_lock()
        self.oras = self.root / "oras"
        self.oras.write_bytes(b"mock pinned oras")
        self.oras.chmod(0o500)
        self.cache = self.root / "cache"
        self.evidence = self.root / "evidence.json"

    def tearDown(self):
        self.temporary.cleanup()
        super().tearDown()

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _write_manifest_and_lock(self):
        manifest = {
            "schemaVersion": 2,
            "mediaType": self.lock["manifest"]["media_type"],
            "artifactType": self.lock["manifest"]["artifact_type"],
            "config": self.lock["manifest"]["config"],
            "layers": [self.lock["manifest"]["layer"]],
            "annotations": {
                "org.opencontainers.image.created": self.lock["manifest"]["created_at"]
            },
        }
        manifest_payload = json.dumps(manifest, separators=(",", ":")).encode("ascii")
        self.manifest.write_bytes(manifest_payload)
        self.lock["manifest"]["size"] = len(manifest_payload)
        self.lock["manifest"]["digest"] = "sha256:" + hashlib.sha256(
            manifest_payload
        ).hexdigest()
        self.lock_path = self.root / "lock.json"
        self.lock_path.write_text(
            json.dumps(self.lock, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )

    def _fake_oras(self, _executable, arguments, _working):
        output = Path(arguments[arguments.index("--output") + 1])
        source = self.manifest if arguments[:2] == ["manifest", "fetch"] else self.layer
        shutil.copyfile(source, output)

    def test_prepare_fetches_exact_digests_and_reverification_detects_tampering(self):
        with mock.patch.object(trivy_db, "_run_oras", side_effect=self._fake_oras) as run:
            trivy_db.prepare(
                lock_path=self.lock_path,
                oras_path=self.oras,
                cache_dir=self.cache,
                evidence_path=self.evidence,
                now=self.now,
            )
        self.assertEqual(run.call_count, 2)
        self.assertEqual((self.cache / "db" / "trivy.db").read_bytes(), self.database_bytes)
        binding = trivy_db.verify_cache(
            lock_path=self.lock_path,
            cache_dir=self.cache,
            evidence_path=self.evidence,
            now=self.now,
        )
        self.assertEqual(binding["manifest_digest"], self.lock["manifest"]["digest"])
        self.assertEqual(binding["db_sha256"], self.lock["database"]["db_sha256"])
        self.assertEqual(stat_mode(self.cache / "db" / "trivy.db"), 0o400)

        (self.cache / "db" / "trivy.db").chmod(0o600)
        (self.cache / "db" / "trivy.db").write_bytes(b"tampered")
        with self.assertRaisesRegex(trivy_db.TrivyDBError, "unsafe type, link count, or size"):
            trivy_db.verify_cache(
                lock_path=self.lock_path,
                cache_dir=self.cache,
                evidence_path=self.evidence,
                now=self.now,
            )

    def test_archive_reader_rejects_links_even_when_the_layer_digest_is_locked(self):
        unsafe_layer = self.root / "unsafe.tar.gz"
        with tarfile.open(unsafe_layer, mode="w:gz") as archive:
            link = tarfile.TarInfo("trivy.db")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            archive.addfile(link)
            metadata = tarfile.TarInfo("metadata.json")
            metadata.size = len(self.metadata_bytes)
            archive.addfile(metadata, io.BytesIO(self.metadata_bytes))
        unsafe_lock = copy.deepcopy(self.lock)
        unsafe_lock["manifest"]["layer"].update(
            {
                "digest": "sha256:" + self._sha256(unsafe_layer),
                "size": unsafe_layer.stat().st_size,
            }
        )
        with self.assertRaisesRegex(trivy_db.TrivyDBError, "unsafe member"):
            trivy_db._extract_database(unsafe_layer, self.root / "unsafe-db", unsafe_lock)

    def test_stale_lock_and_mismatched_evidence_fail_closed(self):
        stale_time = datetime(2030, 1, 3, 10, 0, 0, tzinfo=timezone.utc)
        with self.assertRaisesRegex(trivy_db.TrivyDBError, "lock is stale"):
            trivy_db.load_lock(self.lock_path, now=stale_time)

        lock, lock_sha256 = trivy_db.load_lock(self.lock_path, now=self.now)
        evidence = trivy_db.evidence_for(lock, lock_sha256, self.now)
        evidence["layer_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(trivy_db.TrivyDBError, "does not exactly match"):
            trivy_db.validate_evidence_document(
                evidence, lock, lock_sha256, now=self.now
            )

    def test_repository_lock_records_the_independently_verified_database(self):
        lock, _ = trivy_db.load_lock(
            ROOT / "deploy" / "trivy-db-lock.json",
            now=datetime(2026, 8, 29, 15, 0, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(
            lock["manifest"]["digest"],
            "sha256:b494387b91d0e201f9a8945709a02eb66558cba454efa265b4638e7edde45132",
        )
        self.assertEqual(
            lock["manifest"]["layer"]["digest"],
            "sha256:7ffd31523ebd6166c80630422336211c3fff6b069f97a31568d327de0d5f9f87",
        )
        self.assertEqual(
            lock["database"]["metadata_sha256"],
            "584992a9354fdba6e7f4e59da089e74a102ad19dbceb8045fdadffccb4dc5e77",
        )
        self.assertEqual(
            lock["database"]["db_sha256"],
            "9337bbaa4af21678daeebb746810a5802fab1eed2a58ead1d93a7d8c2586e932",
        )


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777
