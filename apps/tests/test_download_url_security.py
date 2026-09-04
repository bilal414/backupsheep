from django.test import SimpleTestCase

from backupsheep.download_urls import (
    UnsafeBrowserDownloadTarget,
    validated_browser_download_target,
)


class BrowserDownloadTargetSecurityTests(SimpleTestCase):
    def test_allows_https_provider_links_local_streams_and_preparation_states(self):
        allowed = (
            "https://downloads.example.test/archive.zip?signature=a%2Fb#copy",
            "https://127.0.0.1:9443/archive.zip?signature=one",
            "/api/v1/storage/local/file/website/1/",
            "/api/v1/storage/local/file/database/22/",
            "/api/v1/storage/local/file/basecamp/4444/",
            "restore_requested",
            "restore_in_progress",
        )

        for value in allowed:
            with self.subTest(value=value):
                self.assertEqual(validated_browser_download_target(value), value)

    def test_rejects_active_content_insecure_and_malformed_targets(self):
        rejected = (
            "javascript:alert(document.domain)",
            "data:text/html,<script>alert(1)</script>",
            "http://downloads.example.test/archive.zip",
            "//downloads.example.test/archive.zip",
            "/api/v1/storage/local/file/website/1/?next=javascript:alert(1)",
            "/api/v1/storage/local/file/1/",
            "/api/v1/storage/local/file/website/0/",
            "/api/v1/storage/local/file/website/1/../2/",
            "/api/v1/storage/local/file/wordpress/333/",
            "https://user:password@downloads.example.test/archive.zip",
            "https://downloads.example.test\\@attacker.test/archive.zip",
            "https://downloads.example.test/archive.zip\njavascript:alert(1)",
            "https://downloads.example.test:0/archive.zip",
            "https://downloads.example.test:99999/archive.zip",
            "https://[not-an-ipv6-address]/archive.zip",
            "https://-invalid.example.test/archive.zip",
            "",
            None,
            {"url": "https://downloads.example.test/archive.zip"},
        )

        for value in rejected:
            with self.subTest(value=value):
                with self.assertRaises(UnsafeBrowserDownloadTarget):
                    validated_browser_download_target(value)
