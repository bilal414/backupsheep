import hashlib
import stat
import tempfile
from pathlib import Path
from unittest import TestCase
import zipfile

from scripts.build_wordpress_plugin import PluginBuildError, build_plugin


class WordPressPluginPackageTests(TestCase):
    def test_package_is_deterministic_bounded_and_replaces_the_legacy_slug(self):
        with tempfile.TemporaryDirectory(prefix="backupsheep-wordpress-package-") as root:
            first = Path(root) / "first.zip"
            second = Path(root) / "second.zip"
            build_plugin(first)
            build_plugin(second)

            self.assertEqual(
                hashlib.sha256(first.read_bytes()).digest(),
                hashlib.sha256(second.read_bytes()).digest(),
            )
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    archive.namelist(),
                    ["backupsheep/backupsheep.php", "backupsheep/readme.txt"],
                )
                for member in archive.infolist():
                    self.assertEqual(member.date_time, (1980, 1, 1, 0, 0, 0))
                    self.assertTrue(stat.S_ISREG(member.external_attr >> 16))
                    self.assertEqual(stat.S_IMODE(member.external_attr >> 16), 0o644)
                plugin = archive.read("backupsheep/backupsheep.php")
                self.assertIn(b"backupsheep/v2", plugin)
                self.assertNotIn(b"backupsheep/updraftplus", plugin)

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix="backupsheep-wordpress-package-") as root:
            output = Path(root) / "plugin.zip"
            output.write_bytes(b"do-not-overwrite")

            with self.assertRaisesRegex(PluginBuildError, "refusing to overwrite"):
                build_plugin(output)
            self.assertEqual(output.read_bytes(), b"do-not-overwrite")
