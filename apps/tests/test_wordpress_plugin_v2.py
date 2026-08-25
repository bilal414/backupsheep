from pathlib import Path
import re
from unittest import TestCase


PLUGIN = (
    Path(__file__).resolve().parents[2]
    / "integrations"
    / "wordpress"
    / "backupsheep-v2"
    / "backupsheep.php"
)


class WordPressPluginV2SourceTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.source = PLUGIN.read_text(encoding="utf-8")

    def test_only_authenticated_post_v2_routes_are_registered(self):
        self.assertIn("'backupsheep/v2'", self.source)
        self.assertIn("'methods' => WP_REST_Server::CREATABLE", self.source)
        self.assertIn("'permission_callback' => 'backupsheep_v2_authorize'", self.source)
        self.assertNotIn("backupsheep/updraftplus", self.source)
        self.assertNotRegex(self.source, r"\$_(?:GET|REQUEST)\s*\[")

    def test_authentication_binds_exact_body_route_time_nonce_and_key_selector(self):
        for required in (
            "x-backupsheep-protocol",
            "x-backupsheep-key-id",
            "x-backupsheep-timestamp",
            "x-backupsheep-nonce",
            "x-backupsheep-route",
            "x-backupsheep-content-sha256",
            "x-backupsheep-signature",
            "hash_hmac('sha256', $canonical, $secret)",
            "hash_equals($expected, $signature)",
            "add_option($nonce_name",
        ):
            self.assertIn(required, self.source)

    def test_secret_is_never_rendered_and_legacy_option_is_deleted_after_migration(self):
        self.assertIn('type="password"', self.source)
        self.assertIn("value=\"\"", self.source)
        self.assertIn("delete_option('backupsheep_option_name')", self.source)
        self.assertNotIn("bs_wordpress_key_0'] ?>", self.source)

    def test_download_does_not_publish_or_redirect_backup_files(self):
        self.assertIn("fopen($file['path'], 'rb')", self.source)
        self.assertIn("fpassthru($stream)", self.source)
        self.assertIn("$opened['ino'] !== $current['ino']", self.source)
        self.assertNotIn("wp_redirect", self.source)
        self.assertNotIn("wp-content/backupsheep", self.source)

    def test_delete_requires_the_exact_updraft_backup_identifier_delimiter(self):
        self.assertIn(
            "strpos($file['name'], '_' . $backup_uuid . '-') === false",
            self.source,
        )
        self.assertIsNone(re.search(r"strpos\(\$file\['name'\], \$backup_uuid\)", self.source))
