import base64
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import validate_cosign_image_verification as verifier  # noqa: E402


class CosignVerificationEvidenceTests(TestCase):
    repository = "ghcr.io/bilal414/backupsheep-release-verifier"
    digest = "sha256:" + "a" * 64

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.verification = self.root / "verified.json"
        self.bundle = self.root / "bundle.json"
        self._write(self.verification, self._verification_document())
        self._write(self.bundle, self._bundle_document())

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def _write(path: Path, document: object) -> None:
        path.write_text(json.dumps(document), encoding="utf-8")
        path.chmod(0o600)

    def _verification_document(self) -> list[dict]:
        reference = f"{self.repository}@{self.digest}"
        return [
            {
                "critical": {
                    "identity": {"docker-reference": reference},
                    "image": {"docker-manifest-digest": self.digest},
                    "type": verifier.EXPECTED_PREDICATE_TYPE,
                },
                "optional": {},
            }
        ]

    def _bundle_document(self) -> dict:
        statement = {
            "_type": verifier.EXPECTED_STATEMENT_TYPE,
            "subject": [
                {
                    "digest": {"sha256": self.digest.removeprefix("sha256:")},
                    "annotations": {},
                }
            ],
            "predicateType": verifier.EXPECTED_PREDICATE_TYPE,
            "predicate": {},
        }
        return {
            "mediaType": verifier.EXPECTED_BUNDLE_MEDIA_TYPE,
            "verificationMaterial": {
                "certificate": {
                    "rawBytes": base64.b64encode(b"certificate" * 64).decode()
                },
                "tlogEntries": [{"retained": True}],
                "timestampVerificationData": {
                    "rfc3161Timestamps": [
                        {
                            "signedTimestamp": base64.b64encode(
                                b"timestamp" * 16
                            ).decode()
                        }
                    ]
                },
            },
            "dsseEnvelope": {
                "payload": base64.b64encode(
                    json.dumps(statement, separators=(",", ":")).encode()
                ).decode(),
                "payloadType": verifier.EXPECTED_PAYLOAD_TYPE,
                "signatures": [
                    {"sig": base64.b64encode(b"signature" * 8).decode()}
                ],
            },
        }

    def _main(self) -> tuple[int, str, str]:
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = verifier.main(
                [
                    "--verification",
                    str(self.verification),
                    "--bundle",
                    str(self.bundle),
                    "--repository",
                    self.repository,
                    "--digest",
                    self.digest,
                ]
            )
        return status, output.getvalue(), errors.getvalue()

    def test_accepts_subject_bound_cosign_evidence(self):
        status, output, errors = self._main()
        self.assertEqual(status, 0, errors)
        summary = json.loads(output)
        self.assertEqual(summary["reference"], f"{self.repository}@{self.digest}")
        self.assertEqual(summary["digest"], self.digest)
        self.assertEqual(summary["signature_count"], 1)
        self.assertRegex(summary["verification_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(summary["bundle_sha256"], r"^[0-9a-f]{64}$")

    def test_rejects_cosign_output_for_another_digest(self):
        document = self._verification_document()
        document[0]["critical"]["image"]["docker-manifest-digest"] = (
            "sha256:" + "b" * 64
        )
        self._write(self.verification, document)
        status, _, errors = self._main()
        self.assertEqual(status, 1)
        self.assertIn("different subject", errors)

    def test_rejects_local_bundle_for_another_digest(self):
        document = self._bundle_document()
        statement = json.loads(base64.b64decode(document["dsseEnvelope"]["payload"]))
        statement["subject"][0]["digest"]["sha256"] = "b" * 64
        document["dsseEnvelope"]["payload"] = base64.b64encode(
            json.dumps(statement).encode()
        ).decode()
        self._write(self.bundle, document)
        status, _, errors = self._main()
        self.assertEqual(status, 1)
        self.assertIn("different image subject", errors)

    def test_rejects_duplicate_json_members(self):
        self.verification.write_text(
            '[{"critical":{},"critical":{}}]', encoding="utf-8"
        )
        self.verification.chmod(0o600)
        status, _, errors = self._main()
        self.assertEqual(status, 1)
        self.assertIn("duplicate JSON member", errors)

    def test_rejects_group_readable_evidence(self):
        self.bundle.chmod(0o640)
        status, _, errors = self._main()
        self.assertEqual(status, 1)
        self.assertIn("group or other", errors)

    def test_rejects_symlinked_evidence(self):
        target = self.root / "target.json"
        self.bundle.rename(target)
        self.bundle.symlink_to(target)
        status, _, errors = self._main()
        self.assertEqual(status, 1)
        self.assertIn("non-symlink", errors)
