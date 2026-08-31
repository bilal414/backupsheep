import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "publish_stable_release_verifier.py"
SPEC = importlib.util.spec_from_file_location("publish_stable_release_verifier", SCRIPT)
publisher = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(publisher)


class StableReleaseVerifierPublisherTests(unittest.TestCase):
    candidate_tag = "bootstrap-" + "a" * 40 + "-123-1"
    quarantine = publisher.EXPECTED_QUARANTINE_REPOSITORY
    official = publisher.EXPECTED_OFFICIAL_REPOSITORY
    stable_tag = publisher.EXPECTED_STABLE_TAG

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        # macOS exposes /var as a symlink to /private/var. The production
        # helper intentionally rejects symlinked ancestors, so test through
        # the canonical real path rather than weakening that contract.
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.layout = self.root / "layout"
        (self.layout / "blobs" / "sha256").mkdir(parents=True)
        self.layout.chmod(0o700)
        (self.layout / "oci-layout").write_text(
            '{"imageLayoutVersion":"1.0.0"}', encoding="ascii"
        )
        self.index = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": publisher.EXPECTED_ROOT_MEDIA_TYPE,
                "manifests": [],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        self.digest = publisher._sha256(self.index)
        (self.layout / "blobs" / "sha256" / self.digest.removeprefix("sha256:")).write_bytes(
            self.index
        )
        root = {
            "schemaVersion": 2,
            "mediaType": publisher.EXPECTED_ROOT_MEDIA_TYPE,
            "manifests": [
                {
                    "mediaType": publisher.EXPECTED_ROOT_MEDIA_TYPE,
                    "digest": self.digest,
                    "size": len(self.index),
                    "annotations": {
                        "io.containerd.image.name": f"{self.quarantine}:{self.candidate_tag}",
                        "org.opencontainers.image.created": publisher.EXPECTED_BUILD_TIMESTAMP,
                        "org.opencontainers.image.ref.name": self.candidate_tag,
                    },
                }
            ],
        }
        (self.layout / "index.json").write_text(
            json.dumps(root, sort_keys=True, separators=(",", ":")),
            encoding="ascii",
        )
        self.oras = self.root / "oras"
        self.oras.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        self.oras.chmod(0o500)
        self.evidence = self.root / "evidence.json"

    def tearDown(self):
        self.temporary.cleanup()

    def publish(self):
        return publisher.publish(
            layout=self.layout,
            index_digest=self.digest,
            quarantine_repository=self.quarantine,
            candidate_tag=self.candidate_tag,
            official_repository=self.official,
            stable_tag=self.stable_tag,
            oras=self.oras,
            evidence=self.evidence,
        )

    def test_fresh_publication_copies_only_after_every_destination_is_classified(self):
        with mock.patch.object(
            publisher,
            "_repository_tags",
            side_effect=[set(), set(), set(), set()],
        ) as inventories, mock.patch.object(
            publisher, "_fetch_exact"
        ) as fetch, mock.patch.object(publisher, "_run_oras", return_value="") as run:
            result = self.publish()

        self.assertEqual(inventories.call_count, 4)
        self.assertEqual(fetch.call_count, 4)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[0].args[1],
            [
                "cp",
                "--from-oci-layout",
                f"{self.layout}:{self.candidate_tag}",
                f"{self.quarantine}:{self.candidate_tag}",
            ],
        )
        self.assertEqual(
            run.call_args_list[1].args[1],
            [
                "cp",
                f"{self.quarantine}@{self.digest}",
                f"{self.official}:{self.stable_tag}",
            ],
        )
        self.assertEqual(result["candidate"]["status"], "published")
        self.assertEqual(result["official"]["status"], "published")
        self.assertEqual(result["index_digest"], self.digest)
        self.assertEqual(
            json.loads(self.evidence.read_text(encoding="ascii")), result
        )
        self.assertEqual(self.evidence.stat().st_mode & 0o777, 0o600)

    def test_exact_interrupted_publication_is_idempotent(self):
        with mock.patch.object(
            publisher,
            "_repository_tags",
            side_effect=[{self.candidate_tag}, {self.stable_tag}],
        ) as inventories, mock.patch.object(
            publisher, "_fetch_exact"
        ) as fetch, mock.patch.object(publisher, "_run_oras") as run:
            result = self.publish()

        self.assertEqual(inventories.call_count, 2)
        self.assertEqual(fetch.call_count, 6)
        run.assert_not_called()
        self.assertEqual(result["candidate"]["status"], "already_exact")
        self.assertEqual(result["official"]["status"], "already_exact")

    def test_different_occupied_official_tag_stops_before_first_write(self):
        def classify(_oras, reference, _expected):
            if reference == f"{self.official}:{self.stable_tag}":
                raise publisher.PublicationError("different official bytes")

        with mock.patch.object(
            publisher,
            "_repository_tags",
            side_effect=[set(), {self.stable_tag}],
        ), mock.patch.object(
            publisher, "_fetch_exact", side_effect=classify
        ), mock.patch.object(publisher, "_run_oras") as run:
            with self.assertRaisesRegex(
                publisher.PublicationError, "different official bytes"
            ):
                self.publish()
        run.assert_not_called()
        self.assertFalse(self.evidence.exists())

    def test_masked_404_never_authorizes_a_tag_write(self):
        result = mock.Mock(returncode=1, stdout="", stderr="404 not found")
        with mock.patch.object(publisher, "_oras_environment", return_value={}), \
             mock.patch.object(publisher.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(publisher.PublicationError, "failed closed"):
                publisher._run_oras(
                    self.oras,
                    ["repo", "tags", "--format", "json", self.official],
                )

    def test_malformed_or_duplicate_tag_inventory_fails_before_any_write(self):
        invalid = (
            '{"tags":',
            '{"tags":[],"extra":true}',
            '{"tags":["stable","stable"]}',
            '{"tags":["bad tag"]}',
            '{"tags":[],"tags":[]}',
        )
        for raw in invalid:
            with self.subTest(raw=raw), mock.patch.object(
                publisher, "_run_oras", return_value=raw
            ):
                with self.assertRaises(publisher.PublicationError):
                    publisher._repository_tags(self.oras, self.official)

        with mock.patch.object(
            publisher,
            "_repository_tags",
            side_effect=publisher.PublicationError("malformed inventory"),
        ), mock.patch.object(publisher, "_run_oras") as run:
            with self.assertRaisesRegex(publisher.PublicationError, "malformed inventory"):
                self.publish()
        run.assert_not_called()

    def test_only_exact_repositories_and_stable_tag_are_authorized(self):
        cases = (
            {"quarantine_repository": "ghcr.io/example/other"},
            {"official_repository": "ghcr.io/example/other"},
            {"stable_tag": "latest"},
            {"candidate_tag": "bootstrap-not-bound"},
            {"index_digest": "sha256:" + "A" * 64},
        )
        defaults = {
            "layout": self.layout,
            "index_digest": self.digest,
            "quarantine_repository": self.quarantine,
            "candidate_tag": self.candidate_tag,
            "official_repository": self.official,
            "stable_tag": self.stable_tag,
            "oras": self.oras,
            "evidence": self.evidence,
        }
        for override in cases:
            with self.subTest(override=override):
                with self.assertRaises(publisher.PublicationError):
                    publisher.publish(**(defaults | override))

    def test_root_descriptor_must_bind_repository_tag_digest_and_bytes(self):
        root_path = self.layout / "index.json"
        document = json.loads(root_path.read_text(encoding="ascii"))
        document["manifests"][0]["annotations"]["io.containerd.image.name"] = (
            "ghcr.io/example/attacker:latest"
        )
        root_path.write_text(json.dumps(document), encoding="ascii")
        with self.assertRaisesRegex(publisher.PublicationError, "not bound"):
            self.publish()

    def test_root_descriptor_rejects_a_wall_clock_created_timestamp(self):
        root_path = self.layout / "index.json"
        document = json.loads(root_path.read_text(encoding="ascii"))
        document["manifests"][0]["annotations"][
            "org.opencontainers.image.created"
        ] = "2026-08-29T15:55:04Z"
        root_path.write_text(json.dumps(document), encoding="ascii")
        with self.assertRaisesRegex(publisher.PublicationError, "not bound"):
            self.publish()

    def test_outer_index_requires_the_exact_oci_media_type(self):
        root_path = self.layout / "index.json"
        document = json.loads(root_path.read_text(encoding="ascii"))
        document["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
        root_path.write_text(json.dumps(document), encoding="ascii")
        with self.assertRaisesRegex(publisher.PublicationError, "unsupported structure"):
            self.publish()

    def test_duplicate_root_json_key_is_rejected(self):
        (self.layout / "index.json").write_text(
            '{"schemaVersion":2,"schemaVersion":2,"manifests":[]}',
            encoding="ascii",
        )
        with self.assertRaisesRegex(publisher.PublicationError, "duplicate JSON key"):
            self.publish()

    def test_oras_must_be_an_absolute_owner_controlled_executable(self):
        self.oras.chmod(0o700)
        with self.assertRaisesRegex(publisher.PublicationError, "ORAS path must be absolute"):
            publisher._validated_oras(Path("oras"))
        self.oras.chmod(0o522)
        with self.assertRaisesRegex(publisher.PublicationError, "owner-controlled"):
            publisher._validated_oras(self.oras)

    def test_symlinked_and_foreign_owned_ancestors_are_rejected(self):
        real = self.root / "real"
        real.mkdir(mode=0o700)
        link = self.root / "link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(publisher.PublicationError, "symlink"):
            publisher._validate_directory_chain(link, label="test")

        # Simulate a root invocation walking through a non-root-owned 0700
        # directory. Write bits alone are not a sufficient ownership check.
        with mock.patch.object(publisher.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(publisher.PublicationError, "foreign-owned"):
                publisher._validate_directory_chain(self.root, label="test")

    def test_evidence_is_no_clobber(self):
        self.evidence.write_text("existing", encoding="ascii")
        with self.assertRaisesRegex(publisher.PublicationError, "overwrite"):
            publisher._write_evidence(self.evidence, {"schema_version": 1})
        self.assertEqual(self.evidence.read_text(encoding="ascii"), "existing")

    def test_registry_manifest_comparison_rejects_different_bytes(self):
        def fake_oras(_oras, arguments, **_kwargs):
            output = Path(arguments[arguments.index("--output") + 1])
            output.write_bytes(b"different")
            return ""

        with mock.patch.object(publisher, "_run_oras", side_effect=fake_oras):
            with self.assertRaisesRegex(publisher.PublicationError, "different index bytes"):
                publisher._fetch_exact(
                    self.oras,
                    f"{self.official}:{self.stable_tag}",
                    self.index,
                )

    def test_oras_environment_is_minimal_and_requires_isolated_config(self):
        environment = {
            "DOCKER_CONFIG": str(self.root / "docker"),
            "HOME": str(self.root),
            "AWS_ACCESS_KEY_ID": "must-not-pass",
            "COSIGN_PASSWORD": "must-not-pass",
            "ORAS_AUTH_TOKEN": "must-not-pass",
        }
        docker_config = self.root / "docker"
        docker_config.mkdir(mode=0o700)
        config = docker_config / "config.json"
        config.write_text('{"auths":{}}\n', encoding="ascii")
        config.chmod(0o600)
        with mock.patch.dict(os.environ, environment, clear=True):
            observed = publisher._oras_environment()
        self.assertEqual(
            observed,
            {
                "DOCKER_CONFIG": str(self.root / "docker"),
                "HOME": str(self.root),
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
        )


if __name__ == "__main__":
    unittest.main()
