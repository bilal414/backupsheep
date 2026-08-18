import tempfile
import unittest
import unicodedata
import zipfile
from pathlib import Path

from apps._tasks.integration.backup._archive import (
    create_zip,
    validate_zip_archive,
)


class ArchiveValidationTests(unittest.TestCase):
    def test_validate_zip_checks_member_crc(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "backup.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("dump.sql", "select 1;\n")

            validate_zip_archive(archive_path, required_suffix=".sql")

    def test_validate_zip_rejects_archive_without_database_dump(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "backup.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("backupsheep.txt", "BackupSheep")

            with self.assertRaises(ValueError):
                validate_zip_archive(archive_path, required_suffix=".sql")

    def test_create_zip_validates_the_result(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_dir = Path(temp_dir) / "source"
            source_dir.mkdir()
            (source_dir / "site.txt").write_text("site content")
            archive_path = Path(temp_dir) / "backup.zip"

            create_zip(source_dir, archive_path, timeout=60)
            validate_zip_archive(archive_path)

    def test_create_zip_marks_utf8_names(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_dir = Path(temp_dir) / "source"
            source_dir.mkdir()
            composed = "caf\u00e9.txt"
            (source_dir / composed).write_text("composed", encoding="utf-8")
            (source_dir / "emoji-\U0001f642.txt").write_text(
                "emoji", encoding="utf-8"
            )
            (source_dir / "empty-\u76ee\u5f55").mkdir()
            archive_path = Path(temp_dir) / "backup.zip"

            create_zip(source_dir, archive_path, timeout=60)

            with zipfile.ZipFile(archive_path) as archive:
                infos = {info.filename: info for info in archive.infolist()}
                self.assertIn(composed, infos)
                self.assertIn("emoji-\U0001f642.txt", infos)
                self.assertIn("empty-\u76ee\u5f55/", infos)
                for name in (
                    composed,
                    "emoji-\U0001f642.txt",
                    "empty-\u76ee\u5f55/",
                ):
                    self.assertTrue(infos[name].flag_bits & 0x0800)
                self.assertIsNone(archive.testzip())

    def test_create_zip_preserves_distinct_unicode_normalization_forms(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_dir = Path(temp_dir) / "source"
            source_dir.mkdir()
            composed = "caf\u00e9.txt"
            decomposed = "cafe\u0301.txt"
            self.assertEqual(unicodedata.normalize("NFC", decomposed), composed)
            (source_dir / composed).write_text("composed", encoding="utf-8")
            (source_dir / decomposed).write_text("decomposed", encoding="utf-8")
            source_names = {path.name for path in source_dir.iterdir()}
            if source_names != {composed, decomposed}:
                self.skipTest(
                    "the test filesystem normalizes distinct Unicode filenames"
                )
            archive_path = Path(temp_dir) / "backup.zip"

            create_zip(source_dir, archive_path, timeout=60)

            with zipfile.ZipFile(archive_path) as archive:
                infos = {info.filename: info for info in archive.infolist()}
                self.assertEqual(set(infos), {composed, decomposed})
                self.assertTrue(infos[composed].flag_bits & 0x0800)
                self.assertTrue(infos[decomposed].flag_bits & 0x0800)
                self.assertIsNone(archive.testzip())


if __name__ == "__main__":
    unittest.main()
