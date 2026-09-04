from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from unittest import TestCase, mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import materialize_legacy_rabbitmq_vex  # noqa: E402
import prepare_grype_db  # noqa: E402


LOCK_PATH = ROOT / "deploy" / "grype-db-lock.json"
LEGACY_VEX_POLICY_PATH = (
    ROOT / "deploy" / "rabbitmq" / "legacy-source-otp26.vex-policy.json"
)
LEGACY_VEX_IDS = {
    "CVE-2026-42792",
    "CVE-2026-49759",
    "CVE-2026-55737",
    "CVE-2026-55952",
    "CVE-2026-55953",
    "CVE-2026-58227",
    "CVE-2026-59250",
    "CVE-2026-59251",
}


class GrypeDatabaseLockTests(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lock_bytes = LOCK_PATH.read_bytes()
        cls.lock = json.loads(cls.lock_bytes)

    def test_checked_in_lock_is_exact_and_fresh_at_evidence_cut(self) -> None:
        validated = prepare_grype_db._validate_lock(
            deepcopy(self.lock),
            now=datetime(2026, 9, 4, 3, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(validated["database"]["schema_version"], "v6.1.9")
        self.assertEqual(
            hashlib.sha256(self.lock_bytes).hexdigest(),
            "07fb19ba8d924fca629f0cedca97e8beec8dd9d73b1c19187ba263f484721dec",
        )

    def test_lock_expires_closed(self) -> None:
        with self.assertRaisesRegex(prepare_grype_db.GrypeDBError, "not currently fresh"):
            prepare_grype_db._validate_lock(
                deepcopy(self.lock),
                now=datetime(2026, 9, 8, 6, 30, 55, tzinfo=timezone.utc),
            )

    def test_archive_url_checksum_must_equal_locked_digest(self) -> None:
        altered = deepcopy(self.lock)
        altered["archive"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(prepare_grype_db.GrypeDBError, "official Grype"):
            prepare_grype_db._validate_lock(
                altered,
                now=datetime(2026, 9, 4, 3, 0, tzinfo=timezone.utc),
            )

    def test_archive_url_cannot_change_host_or_redirect_authority(self) -> None:
        for url in (
            self.lock["archive"]["url"].replace("grype.anchore.io", "example.com"),
            self.lock["archive"]["url"].replace("https://", "http://"),
            self.lock["archive"]["url"] + "#ignored",
        ):
            with self.subTest(url=url):
                altered = deepcopy(self.lock)
                altered["archive"]["url"] = url
                with self.assertRaisesRegex(prepare_grype_db.GrypeDBError, "official Grype"):
                    prepare_grype_db._validate_lock(
                        altered,
                        now=datetime(2026, 8, 30, 23, 0, tzinfo=timezone.utc),
                    )

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
            with self.assertRaisesRegex(prepare_grype_db.GrypeDBError, "duplicate JSON key"):
                prepare_grype_db._load(path, "test lock")

    def test_symlinked_control_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real.json"
            link = root / "link.json"
            real.write_text("{}\n", encoding="utf-8")
            link.symlink_to(real)
            with self.assertRaisesRegex(prepare_grype_db.GrypeDBError, "single-link"):
                prepare_grype_db._load(link, "test lock")

    @staticmethod
    def _tiny_lock() -> dict:
        archive_sha = "a" * 64
        return {
            "schema_version": 1,
            "archive": {
                "url": (
                    "https://grype.anchore.io/databases/v6/"
                    "vulnerability-db_v6.1.9_2026-08-30T00:35:40Z_1.tar.zst"
                    f"?checksum=sha256%3A{archive_sha}"
                ),
                "sha256": archive_sha,
                "size": 1,
            },
            "database": {
                "schema_version": "v6.1.9",
                "built_at": "2026-08-30T06:27:52Z",
                "valid_until": "2026-09-04T06:27:52Z",
                "sha256": hashlib.sha256(b"d").hexdigest(),
                "size": 1,
                "import_metadata_sha256": hashlib.sha256(b"i").hexdigest(),
                "import_metadata_size": 1,
            },
        }

    def test_verify_binds_cache_and_evidence_to_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            schema = cache / "6"
            schema.mkdir(parents=True)
            (schema / "vulnerability.db").write_bytes(b"d")
            (schema / "import.json").write_bytes(b"i")
            tool = root / "grype"
            tool.write_bytes(b"tool")
            lock = self._tiny_lock()
            lock_path = root / "lock.json"
            lock_payload = (json.dumps(lock, separators=(",", ":")) + "\n").encode()
            lock_path.write_bytes(lock_payload)
            evidence = {
                "schema_version": 1,
                "lock_sha256": hashlib.sha256(lock_payload).hexdigest(),
                "grype_version": "0.116.1",
                "prepared_at": "2026-08-30T23:00:00Z",
                "archive_sha256": lock["archive"]["sha256"],
                "archive_size": 1,
                "database_schema_version": "v6.1.9",
                "database_built_at": "2026-08-30T06:27:52Z",
                "database_sha256": lock["database"]["sha256"],
                "database_size": 1,
            }
            evidence_path = root / "evidence.json"
            evidence_path.write_text(json.dumps(evidence) + "\n", encoding="utf-8")
            with mock.patch.object(prepare_grype_db, "_tool_version"), mock.patch.object(
                prepare_grype_db, "_status"
            ):
                prepare_grype_db.verify(lock_path, tool, cache, evidence_path)
                evidence["database_sha256"] = "f" * 64
                evidence_path.write_text(json.dumps(evidence) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(prepare_grype_db.GrypeDBError, "differs from the lock"):
                    prepare_grype_db.verify(lock_path, tool, cache, evidence_path)

    def test_cache_rejects_any_unreviewed_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            schema = cache / "6"
            schema.mkdir(parents=True)
            (schema / "vulnerability.db").write_bytes(b"d")
            (schema / "import.json").write_bytes(b"i")
            (schema / "last_update_check").write_text("unexpected", encoding="utf-8")
            with self.assertRaisesRegex(prepare_grype_db.GrypeDBError, "unexpected files"):
                prepare_grype_db._verify_cache(cache, self._tiny_lock())

    def test_legacy_otp_vex_is_exact_image_component_and_cve_scoped(self) -> None:
        policy = json.loads(LEGACY_VEX_POLICY_PATH.read_bytes())
        self.assertNotIn("products", json.dumps(policy))
        digest = "sha256:" + "a" * 64
        document = materialize_legacy_rabbitmq_vex.materialize(policy, digest)
        materialize_legacy_rabbitmq_vex.validate_materialized(
            document, policy, digest
        )
        self.assertEqual(document["@context"], "https://openvex.dev/ns/v0.2.0")
        self.assertEqual(document["version"], 1)
        statements = document["statements"]
        self.assertEqual(len(statements), len(LEGACY_VEX_IDS))
        self.assertEqual(
            {statement["vulnerability"]["name"] for statement in statements},
            LEGACY_VEX_IDS,
        )
        for statement in statements:
            self.assertEqual(
                statement["products"],
                [
                    {
                        "@id": (
                            "pkg:oci/backupsheep-rabbitmq-legacy-source"
                            f"?tag=manifest-{digest.removeprefix('sha256:')}"
                        ),
                        "hashes": {"sha-256": digest.removeprefix("sha256:")},
                        "subcomponents": [
                            {"@id": "pkg:generic/erlang@26.2.5.21"}
                        ],
                    }
                ],
            )
            self.assertEqual(statement["status"], "not_affected")
            self.assertEqual(
                statement["justification"],
                "vulnerable_code_cannot_be_controlled_by_adversary",
            )
            impact = statement["impact_statement"].lower()
            self.assertTrue("network" in impact or "traffic" in impact or "peer" in impact)

        with self.assertRaisesRegex(
            materialize_legacy_rabbitmq_vex.ReleaseVerificationError,
            "not bound to the exact image and component",
        ):
            materialize_legacy_rabbitmq_vex.validate_materialized(
                document,
                policy,
                "sha256:" + "b" * 64,
            )
