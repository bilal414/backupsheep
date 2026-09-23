import hashlib
import json
import sys
import tempfile
import urllib.parse
from pathlib import Path
from unittest import TestCase, mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import publish_release_evidence as publisher  # noqa: E402


class FakeReleaseAPI:
    def __init__(self, repository: str, tag: str, commit: str):
        self.repository = repository
        self.tag = tag
        self.commit = commit
        self.api_root = f"https://api.github.com/repos/{repository}"
        self.release_id = 17
        self.release = None
        self.assets = {}
        self.next_asset_id = 100
        self.create_calls = 0
        self.patch_calls = 0
        self.upload_calls = []
        self.create_response_loss_once = False
        self.fail_upload_after_store_once = None
        self.patch_response_loss_once = False
        self.fail_post_publish_list_once = False

    @property
    def upload_url(self):
        return (
            f"https://uploads.github.com/repos/{self.repository}/releases/"
            f"{self.release_id}/assets{{?name,label}}"
        )

    @property
    def upload_root(self):
        return self.upload_url.split("{", 1)[0]

    def install_expected_release(self):
        self.release = {
            "id": self.release_id,
            "upload_url": self.upload_url,
            **publisher._expected_release_fields(self.tag, self.commit),
        }

    def _release_body(self):
        return json.dumps(self.release, sort_keys=True).encode("utf-8")

    def _asset_record(self, name, payload, *, state="uploaded"):
        asset_id = self.next_asset_id
        self.next_asset_id += 1
        return {
            "id": asset_id,
            "url": f"{self.api_root}/releases/assets/{asset_id}",
            "name": name,
            "label": None,
            "state": state,
            "content_type": "application/octet-stream",
            "size": len(payload),
            "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        }

    def add_asset(self, name, payload, *, state="uploaded"):
        self.assets[name] = self._asset_record(name, payload, state=state)
        return self.assets[name]

    def request(
        self,
        url,
        token,
        *,
        method="GET",
        payload=None,
        content_type="application/json",
    ):
        if token != "test-token":
            raise AssertionError("unexpected token")
        parsed = urllib.parse.urlsplit(url)
        assets_url = f"{self.api_root}/releases/{self.release_id}/assets"
        release_url = f"{self.api_root}/releases/{self.release_id}"

        if method == "GET" and parsed._replace(query="").geturl() == (
            f"{self.api_root}/releases"
        ):
            if parsed.query != "per_page=100&page=1":
                raise AssertionError("unexpected release pagination")
            releases = [] if self.release is None else [self.release]
            return 200, json.dumps(releases, sort_keys=True).encode("utf-8")

        if method == "POST" and url == f"{self.api_root}/releases":
            self.create_calls += 1
            if self.release is not None:
                raise publisher.ReleaseVerificationError("duplicate release")
            self.release = {
                "id": self.release_id,
                "upload_url": self.upload_url,
                **json.loads(payload),
            }
            if self.create_response_loss_once:
                self.create_response_loss_once = False
                raise publisher.ReleaseVerificationError(
                    "injected post-create response loss"
                )
            return 201, self._release_body()

        if method == "GET" and parsed._replace(query="").geturl() == assets_url:
            if parsed.query != "per_page=100&page=1":
                raise AssertionError("unexpected asset pagination")
            if (
                self.fail_post_publish_list_once
                and self.release is not None
                and self.release.get("draft") is False
            ):
                self.fail_post_publish_list_once = False
                raise publisher.ReleaseVerificationError(
                    "injected post-publish failure"
                )
            return 200, json.dumps(
                [self.assets[name] for name in sorted(self.assets)],
                sort_keys=True,
            ).encode("utf-8")

        if method == "POST" and parsed._replace(query="").geturl() == self.upload_root:
            if content_type != "application/octet-stream":
                raise AssertionError("unexpected upload content type")
            query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
            if sorted(query) != ["name"] or len(query["name"]) != 1:
                raise AssertionError("unexpected upload query")
            name = query["name"][0]
            if name in self.assets:
                raise publisher.ReleaseVerificationError("asset overwrite attempted")
            self.upload_calls.append(name)
            record = self.add_asset(name, payload)
            if self.fail_upload_after_store_once == len(self.upload_calls):
                self.fail_upload_after_store_once = None
                raise publisher.ReleaseVerificationError("injected upload response loss")
            return 201, json.dumps(record, sort_keys=True).encode("utf-8")

        if method == "PATCH" and url == release_url:
            self.patch_calls += 1
            if json.loads(payload) != {"draft": False}:
                raise AssertionError("unexpected publish request")
            self.release["draft"] = False
            if self.patch_response_loss_once:
                self.patch_response_loss_once = False
                raise publisher.RetryableGitHubRequestError(
                    "injected publish response loss"
                )
            return 200, self._release_body()

        raise AssertionError(f"unexpected request: {method} {url}")


class ReleasePublicationRecoveryTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.policy = json.loads((ROOT / "deploy" / "release-policy.json").read_text())
        cls.repository = cls.policy["source_repository"]
        cls.tag = "v1.2.3-rc.1"
        cls.commit = "a" * 40

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        asset_root = Path(self.temporary.name)
        self.assets = []
        for name, body in (
            ("release-manifest.json", b"manifest\n"),
            ("release-policy.json", b"policy\n"),
            ("signed-release-evidence.tar.gz", b"archive\n"),
        ):
            path = asset_root / name
            path.write_bytes(body)
            self.assets.append(path)

    def tearDown(self):
        self.temporary.cleanup()

    def _publish(self, api):
        with mock.patch.object(publisher, "_request", side_effect=api.request):
            publisher.publish(
                self.policy,
                self.tag,
                self.commit,
                self.assets,
                "test-token",
            )

    def test_failure_after_draft_create_resumes_without_replacing_release(self):
        api = FakeReleaseAPI(self.repository, self.tag, self.commit)
        api.create_response_loss_once = True
        with mock.patch.object(publisher, "_request", side_effect=api.request):
            with self.assertRaisesRegex(
                publisher.ReleaseVerificationError, "post-create response loss"
            ):
                publisher.publish(
                    self.policy,
                    self.tag,
                    self.commit,
                    self.assets,
                    "test-token",
                )
            self.assertTrue(api.release["draft"])
            self.assertEqual(api.assets, {})
            publisher.publish(
                self.policy,
                self.tag,
                self.commit,
                self.assets,
                "test-token",
            )
        self.assertEqual(api.create_calls, 1)
        self.assertEqual(sorted(api.upload_calls), sorted(path.name for path in self.assets))
        self.assertEqual(api.patch_calls, 1)
        self.assertFalse(api.release["draft"])

    def test_failure_mid_assets_reconciles_exact_upload_before_resuming(self):
        api = FakeReleaseAPI(self.repository, self.tag, self.commit)
        api.fail_upload_after_store_once = 1
        first_name = sorted(path.name for path in self.assets)[0]
        with mock.patch.object(publisher, "_request", side_effect=api.request):
            with self.assertRaisesRegex(
                publisher.ReleaseVerificationError, "upload response loss"
            ):
                publisher.publish(
                    self.policy,
                    self.tag,
                    self.commit,
                    self.assets,
                    "test-token",
                )
            self.assertEqual(list(api.assets), [first_name])
            publisher.publish(
                self.policy,
                self.tag,
                self.commit,
                self.assets,
                "test-token",
            )
        self.assertEqual(api.create_calls, 1)
        self.assertEqual(len(api.upload_calls), len(self.assets))
        self.assertEqual(len(set(api.upload_calls)), len(self.assets))
        self.assertEqual(api.patch_calls, 1)
        self.assertFalse(api.release["draft"])

    def test_existing_release_metadata_must_match_exact_draft(self):
        cases = {
            "target_commitish": "b" * 40,
            "tag_name": "v1.2.3-rc.2",
            "name": "Foreign release",
            "body": "Foreign body",
            "prerelease": False,
            "draft": "false",
        }
        for field, wrong_value in cases.items():
            with self.subTest(field=field):
                api = FakeReleaseAPI(self.repository, self.tag, self.commit)
                api.install_expected_release()
                api.release[field] = wrong_value
                with mock.patch.object(
                    publisher, "_request", side_effect=api.request
                ):
                    with self.assertRaisesRegex(
                        publisher.ReleaseVerificationError,
                        f"unexpected {field} value",
                    ):
                        publisher.publish(
                            self.policy,
                            self.tag,
                            self.commit,
                            self.assets,
                            "test-token",
                        )
                self.assertEqual(api.create_calls, 0)
                self.assertEqual(api.upload_calls, [])
                self.assertEqual(api.patch_calls, 0)

    def test_conflicting_managed_asset_fails_without_overwrite(self):
        api = FakeReleaseAPI(self.repository, self.tag, self.commit)
        api.install_expected_release()
        path = self.assets[0]
        record = api.add_asset(path.name, path.read_bytes())
        record["digest"] = f"sha256:{'0' * 64}"
        with mock.patch.object(publisher, "_request", side_effect=api.request):
            with self.assertRaisesRegex(
                publisher.ReleaseVerificationError, "unexpected digest"
            ):
                publisher.publish(
                    self.policy,
                    self.tag,
                    self.commit,
                    self.assets,
                    "test-token",
                )
        self.assertEqual(api.upload_calls, [])
        self.assertEqual(api.patch_calls, 0)

    def test_partial_exact_asset_fails_without_delete_or_reupload(self):
        api = FakeReleaseAPI(self.repository, self.tag, self.commit)
        api.install_expected_release()
        path = self.assets[0]
        record = api.add_asset(path.name, path.read_bytes()[:2], state="starter")
        with mock.patch.object(publisher, "_request", side_effect=api.request):
            with self.assertRaisesRegex(
                publisher.ReleaseVerificationError, "not completely uploaded"
            ):
                publisher.publish(
                    self.policy,
                    self.tag,
                    self.commit,
                    self.assets,
                    "test-token",
                )
        self.assertIs(api.assets[path.name], record)
        self.assertEqual(api.upload_calls, [])
        self.assertEqual(api.patch_calls, 0)

    def test_unmanaged_asset_fails_without_touching_it(self):
        api = FakeReleaseAPI(self.repository, self.tag, self.commit)
        api.install_expected_release()
        foreign = api.add_asset("foreign.txt", b"foreign")
        with mock.patch.object(publisher, "_request", side_effect=api.request):
            with self.assertRaisesRegex(
                publisher.ReleaseVerificationError, "unmanaged assets?"
            ):
                publisher.publish(
                    self.policy,
                    self.tag,
                    self.commit,
                    self.assets,
                    "test-token",
                )
        self.assertIs(api.assets["foreign.txt"], foreign)
        self.assertEqual(api.upload_calls, [])
        self.assertEqual(api.patch_calls, 0)

    def test_publish_patch_retries_idempotently_after_response_loss(self):
        api = FakeReleaseAPI(self.repository, self.tag, self.commit)
        api.patch_response_loss_once = True
        with (
            mock.patch.object(publisher, "_request", side_effect=api.request),
            mock.patch.object(publisher.time, "sleep") as sleep,
        ):
            publisher.publish(
                self.policy,
                self.tag,
                self.commit,
                self.assets,
                "test-token",
            )
        self.assertEqual(api.patch_calls, 2)
        sleep.assert_called_once_with(publisher.PUBLISH_RETRY_DELAYS[0])
        self.assertFalse(api.release["draft"])

    def test_rerun_recovers_exact_published_release_after_final_read_crash(self):
        api = FakeReleaseAPI(self.repository, self.tag, self.commit)
        api.fail_post_publish_list_once = True
        with mock.patch.object(publisher, "_request", side_effect=api.request):
            with self.assertRaisesRegex(
                publisher.ReleaseVerificationError, "post-publish failure"
            ):
                publisher.publish(
                    self.policy,
                    self.tag,
                    self.commit,
                    self.assets,
                    "test-token",
                )
            self.assertFalse(api.release["draft"])
            first_uploads = list(api.upload_calls)
            publisher.publish(
                self.policy,
                self.tag,
                self.commit,
                self.assets,
                "test-token",
            )
        self.assertEqual(api.create_calls, 1)
        self.assertEqual(api.upload_calls, first_uploads)
        self.assertEqual(api.patch_calls, 1)

    def test_published_release_must_be_complete_and_exact(self):
        for case in ("incomplete", "mismatched"):
            with self.subTest(case=case):
                api = FakeReleaseAPI(self.repository, self.tag, self.commit)
                api.install_expected_release()
                api.release["draft"] = False
                for path in self.assets:
                    api.add_asset(path.name, path.read_bytes())
                if case == "incomplete":
                    api.assets.pop(self.assets[-1].name)
                    expected_error = "missing managed assets"
                else:
                    api.release["body"] = "Foreign published release"
                    expected_error = "unexpected body value"
                with mock.patch.object(
                    publisher, "_request", side_effect=api.request
                ):
                    with self.assertRaisesRegex(
                        publisher.ReleaseVerificationError, expected_error
                    ):
                        publisher.publish(
                            self.policy,
                            self.tag,
                            self.commit,
                            self.assets,
                            "test-token",
                        )
                self.assertEqual(api.upload_calls, [])
                self.assertEqual(api.patch_calls, 0)
