import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
