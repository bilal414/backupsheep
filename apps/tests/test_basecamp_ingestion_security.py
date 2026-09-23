import os
import json
import tempfile
from unittest import mock

from django.test import SimpleTestCase, override_settings

from apps._tasks.integration.backup import basecamp as basecamp_backup


class _Response:
    def __init__(self, status_code=200, *, payload=None, headers=None, chunks=None):
        self.status_code = status_code
        self._payload = [] if payload is None else payload
        self.headers = headers or {}
        self._chunks = (
            [json.dumps(self._payload).encode("utf-8")]
            if chunks is None
            else list(chunks)
        )
        self.closed = False

    def json(self):
        return self._payload

    def iter_content(self, chunk_size):
        del chunk_size
        yield from self._chunks

    def close(self):
        self.closed = True


def _vault(identifier, *, title="Vault"):
    return {
        "title": title,
        "uploads_count": 0,
        "uploads_url": f"https://3.basecampapi.com/1/vaults/{identifier}/uploads.json",
        "vaults_url": f"https://3.basecampapi.com/1/vaults/{identifier}/vaults.json",
        "url": f"https://3.basecampapi.com/1/vaults/{identifier}.json",
    }


class BasecampPathSafetyTests(SimpleTestCase):
    def test_provider_names_cannot_escape_backup_root(self):
        component = basecamp_backup._safe_component(
            "../../etc\\passwd\x00/secret.txt"
        )
        self.assertNotIn("/", component)
        self.assertNotIn("\\", component)
        self.assertNotIn("\x00", component)
        self.assertNotIn("..", component)

        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(basecamp_backup.BasecampIngestionError):
                basecamp_backup._safe_join(root, "..")
            destination = basecamp_backup._unique_destination(
                root, "../../etc/passwd", root
            )
            real_root = os.path.realpath(root)
            self.assertEqual(os.path.commonpath((real_root, destination)), real_root)
            self.assertEqual(os.path.dirname(destination), real_root)

    def test_vault_titles_are_sanitized_before_becoming_path_parts(self):
        response = _Response(payload=[])
        item = _vault("root", title="../../private\\tokens")
        with mock.patch.object(
            basecamp_backup, "_basecamp_api_request", return_value=response
        ):
            result = basecamp_backup.collect_vaults_urls(item, "", {"Authorization": "secret"})

        path_part = result[0]["path_parts"][0]
        self.assertNotIn("/", path_part)
        self.assertNotIn("\\", path_part)
        self.assertNotIn("..", path_part)
        self.assertTrue(response.closed)


class BasecampTraversalBoundsTests(SimpleTestCase):
    def test_vault_cycle_is_rejected_before_a_second_request(self):
        item = _vault("same")
        response = _Response(payload=[item])
        with mock.patch.object(
            basecamp_backup, "_basecamp_api_request", return_value=response
        ) as request:
            with self.assertRaisesRegex(
                basecamp_backup.BasecampIngestionError, "cycle"
            ):
                basecamp_backup.collect_vaults_urls(item, "", {})
        request.assert_called_once()

    @override_settings(BASECAMP_BACKUP_MAX_VAULT_DEPTH=1)
    def test_vault_depth_is_bounded(self):
        root = _vault("root")
        child = _vault("child")
        grandchild = _vault("grandchild")
        responses = [
            _Response(payload=[child]),
            _Response(payload=[grandchild]),
        ]
        with mock.patch.object(
            basecamp_backup, "_basecamp_api_request", side_effect=responses
        ) as request:
            with self.assertRaisesRegex(
                basecamp_backup.BasecampIngestionError, "depth"
            ):
                basecamp_backup.collect_vaults_urls(root, "", {})
        self.assertEqual(request.call_count, 2)

    @override_settings(BASECAMP_BACKUP_MAX_METADATA_BYTES=4)
    def test_metadata_response_body_is_bounded_while_streaming(self):
        response = _Response(chunks=[b"[123", b"45]"])
        with self.assertRaisesRegex(
            basecamp_backup.BasecampIngestionError, "metadata.*size limit"
        ):
            basecamp_backup._response_json_list(response)

    def test_link_pagination_cycle_is_rejected_without_refetching(self):
        url = "https://3.basecampapi.com/1/vaults/1/uploads.json"
        response = _Response(
            payload=[{"id": 1}],
            headers={"Link": f'<{url}>; rel="next"'},
        )
        with mock.patch.object(
            basecamp_backup, "_basecamp_api_request", return_value=response
        ) as request:
            with self.assertRaisesRegex(
                basecamp_backup.BasecampIngestionError, "cycle"
            ):
                list(basecamp_backup._iter_linked_pages(url, {}))
        request.assert_called_once()

    @override_settings(BASECAMP_BACKUP_MAX_PAGES=2)
    def test_numbered_pagination_has_a_hard_page_limit(self):
        responses = [
            _Response(payload=[{"id": 1}]),
            _Response(payload=[{"id": 2}]),
        ]
        with mock.patch.object(
            basecamp_backup, "_basecamp_api_request", side_effect=responses
        ) as request:
            with self.assertRaisesRegex(
                basecamp_backup.BasecampIngestionError, "page limit"
            ):
                list(
                    basecamp_backup._iter_numbered_pages(
                        "https://basecamp.com/1/api/v1/attachments.json", {}
                    )
                )
        self.assertEqual(request.call_count, 2)


class BasecampRemoteTrustTests(SimpleTestCase):
    def test_untrusted_download_host_is_rejected_before_network(self):
        with mock.patch.object(basecamp_backup.requests, "request") as request:
            with self.assertRaisesRegex(
                basecamp_backup.BasecampIngestionError, "untrusted"
            ):
                basecamp_backup._download_response(
                    "https://attacker.example/attachment", {"Authorization": "Bearer secret"}
                )
        request.assert_not_called()

    def test_untrusted_redirect_is_rejected_without_forwarding_credentials(self):
        redirect = _Response(
            302, headers={"Location": "https://attacker.example/capture"}
        )
        with mock.patch.object(
            basecamp_backup.requests, "request", return_value=redirect
        ) as request:
            with self.assertRaisesRegex(
                basecamp_backup.BasecampIngestionError, "untrusted"
            ):
                basecamp_backup._download_response(
                    "https://basecamp.com/1/attachments/1/download",
                    {"Authorization": "Bearer secret"},
                )
        request.assert_called_once()
        self.assertEqual(
            request.call_args.kwargs["headers"]["Authorization"], "Bearer secret"
        )
        self.assertTrue(redirect.closed)

    def test_allowed_cdn_redirect_receives_no_oauth_headers(self):
        redirect = _Response(
            302,
            headers={
                "Location": "https://backup-object.s3.amazonaws.com/signed-object"
            },
        )
        download = _Response(200, chunks=[b"payload"])
        with mock.patch.object(
            basecamp_backup.requests,
            "request",
            side_effect=[redirect, download],
        ) as request:
            result = basecamp_backup._download_response(
                "https://3.basecampapi.com/1/attachments/1/download",
                {"Authorization": "Bearer secret", "content-type": "application/json"},
            )
        self.assertIs(result, download)
        self.assertEqual(
            request.call_args_list[0].kwargs["headers"]["Authorization"],
            "Bearer secret",
        )
        self.assertEqual(request.call_args_list[1].kwargs["headers"], {})
        self.assertFalse(request.call_args_list[0].kwargs["allow_redirects"])
        self.assertFalse(request.call_args_list[1].kwargs["allow_redirects"])

    def test_basecamp_two_asset_origin_keeps_authentication(self):
        download = _Response(200, chunks=[b"payload"])
        with mock.patch.object(
            basecamp_backup.requests,
            "request",
            return_value=download,
        ) as request:
            result = basecamp_backup._download_response(
                "https://asset12.basecamp.com/1/api/v1/attachments/2/file.bin",
                {"Authorization": "Bearer secret"},
            )
        self.assertIs(result, download)
        self.assertEqual(
            request.call_args.kwargs["headers"]["Authorization"],
            "Bearer secret",
        )

    def test_object_storage_host_is_allowed_only_after_basecamp_redirect(self):
        with mock.patch.object(basecamp_backup.requests, "request") as request:
            with self.assertRaisesRegex(
                basecamp_backup.BasecampIngestionError, "untrusted"
            ):
                basecamp_backup._download_response(
                    "https://attacker-bucket.s3.amazonaws.com/file.bin",
                    {"Authorization": "Bearer secret"},
                )
        request.assert_not_called()

    def test_oauth_headers_are_not_restored_after_a_storage_hop(self):
        responses = [
            _Response(
                302,
                headers={
                    "Location": "https://bucket.s3.amazonaws.com/signed-object"
                },
            ),
            _Response(
                302,
                headers={
                    "Location": "https://3.basecampapi.com/1/download/final"
                },
            ),
            _Response(200, chunks=[b"payload"]),
        ]
        with mock.patch.object(
            basecamp_backup.requests,
            "request",
            side_effect=responses,
        ) as request:
            result = basecamp_backup._download_response(
                "https://3.basecampapi.com/1/download/start",
                {"Authorization": "Bearer secret"},
            )
        self.assertIs(result, responses[-1])
        self.assertIn(
            "Authorization",
            request.call_args_list[0].kwargs["headers"],
        )
        self.assertEqual(request.call_args_list[1].kwargs["headers"], {})
        self.assertEqual(request.call_args_list[2].kwargs["headers"], {})

    def test_suffix_confusion_api_host_is_rejected(self):
        with self.assertRaises(basecamp_backup.BasecampIngestionError):
            basecamp_backup._validated_remote_url(
                "https://3.basecampapi.com.attacker.example/items", api_only=True
            )


class BasecampDownloadBoundsTests(SimpleTestCase):
    @override_settings(
        BASECAMP_BACKUP_MAX_FILE_BYTES=4,
        BASECAMP_BACKUP_MAX_TOTAL_BYTES=10,
        BASECAMP_BACKUP_MAX_FILES=2,
    )
    def test_declared_oversize_is_rejected_without_publishing_a_file(self):
        response = _Response(headers={"Content-Length": "5"}, chunks=[b"12345"])
        with tempfile.TemporaryDirectory() as root, mock.patch.object(
            basecamp_backup, "_download_response", return_value=response
        ):
            destination = os.path.join(root, "attachment.bin")
            with self.assertRaisesRegex(
                basecamp_backup.BasecampIngestionError, "file-size"
            ):
                basecamp_backup._download_to_file(
                    "https://basecamp.com/download",
                    destination,
                    root,
                    {},
                    basecamp_backup._DownloadBudget(),
                )
            self.assertFalse(os.path.exists(destination))
            self.assertFalse(os.path.lexists(f"{destination}.partial"))
            self.assertTrue(response.closed)

    @override_settings(
        BASECAMP_BACKUP_MAX_FILE_BYTES=4,
        BASECAMP_BACKUP_MAX_TOTAL_BYTES=10,
        BASECAMP_BACKUP_MAX_FILES=2,
    )
    def test_streamed_oversize_removes_partial_file(self):
        response = _Response(chunks=[b"123", b"45"])
        with tempfile.TemporaryDirectory() as root, mock.patch.object(
            basecamp_backup, "_download_response", return_value=response
        ):
            destination = os.path.join(root, "attachment.bin")
            with self.assertRaisesRegex(
                basecamp_backup.BasecampIngestionError, "file-size"
            ):
                basecamp_backup._download_to_file(
                    "https://basecamp.com/download",
                    destination,
                    root,
                    {},
                    basecamp_backup._DownloadBudget(),
                )
            self.assertFalse(os.path.exists(destination))
            self.assertFalse(os.path.lexists(f"{destination}.partial"))

    @override_settings(
        BASECAMP_BACKUP_MAX_FILE_BYTES=10,
        BASECAMP_BACKUP_MAX_TOTAL_BYTES=5,
        BASECAMP_BACKUP_MAX_FILES=3,
    )
    def test_total_budget_is_shared_across_files(self):
        first = _Response(headers={"Content-Length": "3"}, chunks=[b"123"])
        second = _Response(headers={"Content-Length": "3"}, chunks=[b"456"])
        budget = basecamp_backup._DownloadBudget()
        with tempfile.TemporaryDirectory() as root, mock.patch.object(
            basecamp_backup,
            "_download_response",
            side_effect=[first, second],
        ):
            first_path = os.path.join(root, "first.bin")
            second_path = os.path.join(root, "second.bin")
            basecamp_backup._download_to_file(
                "https://basecamp.com/first", first_path, root, {}, budget
            )
            with self.assertRaisesRegex(
                basecamp_backup.BasecampIngestionError, "total-size"
            ):
                basecamp_backup._download_to_file(
                    "https://basecamp.com/second", second_path, root, {}, budget
                )
            with open(first_path, "rb") as saved:
                self.assertEqual(saved.read(), b"123")
            self.assertFalse(os.path.exists(second_path))
