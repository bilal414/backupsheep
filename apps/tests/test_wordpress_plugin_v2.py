import ast
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
WORDPRESS_TASK = (
    Path(__file__).resolve().parents[1]
    / "_tasks"
    / "integration"
    / "backup"
    / "wordpress.py"
)


class WordPressPluginV2SourceTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.source = PLUGIN.read_text(encoding="utf-8")

    def function_source(self, name):
        start = self.source.index(f"function {name}(")
        end = self.source.find("\nfunction ", start + 1)
        return self.source[start : end if end >= 0 else None]

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

    def test_download_requires_uuid_and_exact_run_file_membership_before_open(self):
        download = self.function_source("backupsheep_v2_download")
        ownership = self.function_source("backupsheep_v2_backup_owns_file")
        not_found = self.function_source("backupsheep_v2_file_not_found")

        self.assertIn("$backup_uuid = backupsheep_v2_backup_uuid($payload);", download)
        self.assertIn(
            "$owned = backupsheep_v2_backup_owns_file($file, $backup_uuid);",
            download,
        )
        self.assertIn("return backupsheep_v2_file_not_found();", download)
        self.assertLess(download.index("$backup_uuid ="), download.index("fopen("))
        self.assertLess(download.index("$owned ="), download.index("fopen("))

        self.assertIn("$updraft->get_logfile_name($backup_uuid)", ownership)
        self.assertIn("'/*_' . $backup_uuid . '-*'", ownership)
        self.assertIn("basename((string) $candidate) === $file['name']", ownership)
        self.assertIn("$candidate_path === $file['path']", ownership)
        self.assertIn("'backupsheep_v2_file_not_found'", not_found)
        self.assertIn("'The backup file was not found.'", not_found)
        self.assertIn("array('status' => 404)", not_found)

    def test_every_download_request_body_carries_the_backup_uuid(self):
        tree = ast.parse(WORDPRESS_TASK.read_text(encoding="utf-8"))
        downloads = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            if not isinstance(node.func, ast.Attribute) or node.func.attr != "request":
                continue
            route = node.args[0]
            if not isinstance(route, ast.Constant) or route.value != "download":
                continue
            params = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "params"),
                None,
            )
            self.assertIsInstance(params, ast.Dict)
            keys = {
                key.value
                for key in params.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            }
            downloads.append(keys)

        self.assertEqual(len(downloads), 2)
        for keys in downloads:
            self.assertIn("backup_file", keys)
            self.assertIn("backup_uuid", keys)

    def test_delete_requires_the_exact_updraft_backup_identifier_delimiter(self):
        self.assertIn(
            "strpos($file['name'], '_' . $backup_uuid . '-') === false",
            self.source,
        )
        self.assertIsNone(re.search(r"strpos\(\$file\['name'\], \$backup_uuid\)", self.source))
