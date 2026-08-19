import struct
import tempfile
import unittest
import unicodedata
import zipfile
from pathlib import Path
from unittest import mock

from apps._tasks.integration.backup import _archive as ARCHIVE
from apps._tasks.integration.backup._archive import (
    create_zip,
    mark_utf8_zip_names,
    validate_zip_archive,
)


class ArchiveValidationTests(unittest.TestCase):
    @staticmethod
    def _clear_utf8_name_flags(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            central_offset = archive.start_dir

        with open(archive_path, "r+b") as archive_file:
            for info in infos:
                archive_file.seek(central_offset)
                central = archive_file.read(46)
                filename_length, extra_length, comment_length = struct.unpack_from(
                    "<HHH", central, 28
                )
                central_flags = struct.unpack_from("<H", central, 8)[0]
                archive_file.seek(central_offset + 8)
                archive_file.write(struct.pack("<H", central_flags & ~0x0800))

                archive_file.seek(info.header_offset + 6)
                local_flags = struct.unpack("<H", archive_file.read(2))[0]
                archive_file.seek(info.header_offset + 6)
                archive_file.write(struct.pack("<H", local_flags & ~0x0800))
                central_offset += 46 + filename_length + extra_length + comment_length

    @staticmethod
    def _promote_eocd_to_zip64(archive_path):
        with open(archive_path, "r+b") as archive_file:
            content = archive_file.read()
            eocd_offset = content.rfind(b"PK\x05\x06")
            if eocd_offset < 0:
                raise AssertionError("test archive has no end record")
            fields = struct.unpack_from("<4s4H2LH", content, eocd_offset)
            (
                _signature,
                disk_number,
                central_disk,
                entries_on_disk,
                entry_count,
                central_size,
                central_offset,
                comment_length,
            ) = fields
            if disk_number or central_disk or comment_length:
                raise AssertionError("test helper expects a non-spanned commentless ZIP")
            zip64_eocd = struct.pack(
                "<4sQ2H2L4Q",
                b"PK\x06\x06",
                44,
                45,
                45,
                0,
                0,
                entries_on_disk,
                entry_count,
                central_size,
                central_offset,
            )
            zip64_locator = struct.pack(
                "<4sLQL", b"PK\x06\x07", 0, eocd_offset, 1
            )
            sentinel_eocd = struct.pack(
                "<4s4H2LH",
                b"PK\x05\x06",
                0,
                0,
                0xFFFF,
                0xFFFF,
                0xFFFFFFFF,
                0xFFFFFFFF,
                0,
            )
            archive_file.seek(eocd_offset)
            archive_file.truncate()
            archive_file.write(zip64_eocd)
            archive_file.write(zip64_locator)
            archive_file.write(sentinel_eocd)

    @staticmethod
    def _promote_central_local_offset_to_zip64(archive_path):
        with open(archive_path, "r+b") as archive_file:
            content = archive_file.read()
            central_offset = content.find(b"PK\x01\x02")
            eocd_offset = content.rfind(b"PK\x05\x06")
            if central_offset < 0 or eocd_offset < 0:
                raise AssertionError("test archive records are missing")

            central = bytearray(content[central_offset:central_offset + 46])
            filename_length, extra_length, comment_length = struct.unpack_from(
                "<HHH", central, 28
            )
            local_offset = struct.unpack_from("<L", central, 42)[0]
            filename_end = central_offset + 46 + filename_length
            extra_end = filename_end + extra_length
            entry_end = extra_end + comment_length
            zip64_extra = struct.pack("<HHQ", 0x0001, 8, local_offset)
            struct.pack_into("<H", central, 30, extra_length + len(zip64_extra))
            struct.pack_into("<L", central, 42, 0xFFFFFFFF)

            new_central = (
                bytes(central)
                + content[central_offset + 46:filename_end]
                + zip64_extra
                + content[filename_end:entry_end]
            )
            new_content = bytearray(
                content[:central_offset]
                + new_central
                + content[entry_end:eocd_offset]
                + content[eocd_offset:]
            )
            new_eocd_offset = eocd_offset + len(zip64_extra)
            central_size = struct.unpack_from(
                "<L", new_content, new_eocd_offset + 12
            )[0]
            struct.pack_into(
                "<L",
                new_content,
                new_eocd_offset + 12,
                central_size + len(zip64_extra),
            )
            archive_file.seek(0)
            archive_file.truncate()
            archive_file.write(new_content)

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

    def test_utf8_header_repair_does_not_materialize_zipfile_members(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "legacy.zip"
            original_name = "caf\u00e9-\u0645\u0631\u062d\u0628\u0627.txt"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(original_name, "payload")
            self._clear_utf8_name_flags(archive_path)

            with mock.patch.object(
                ARCHIVE.zipfile,
                "ZipFile",
                side_effect=AssertionError("infolist must not be used"),
            ):
                self.assertEqual(mark_utf8_zip_names(archive_path), 1)

            with zipfile.ZipFile(archive_path) as archive:
                self.assertTrue(archive.getinfo(original_name).flag_bits & 0x0800)
                self.assertEqual(archive.read(original_name), b"payload")

    def test_utf8_header_repair_supports_zip64_end_records(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "legacy-zip64.zip"
            original_name = "emoji-\U0001f642.txt"
            with zipfile.ZipFile(archive_path, "w", allowZip64=True) as archive:
                archive.writestr(original_name, "zip64 payload")
            self._clear_utf8_name_flags(archive_path)
            self._promote_eocd_to_zip64(archive_path)

            self.assertEqual(mark_utf8_zip_names(archive_path), 1)

            with zipfile.ZipFile(archive_path) as archive:
                self.assertTrue(archive.getinfo(original_name).flag_bits & 0x0800)
                self.assertEqual(archive.read(original_name), b"zip64 payload")

    def test_utf8_header_repair_supports_zip64_local_offsets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "legacy-zip64-entry.zip"
            original_name = "arabic-\u0645\u0631\u062d\u0628\u0627.txt"
            with zipfile.ZipFile(archive_path, "w", allowZip64=True) as archive:
                archive.writestr(original_name, "zip64 entry payload")
            self._clear_utf8_name_flags(archive_path)
            self._promote_central_local_offset_to_zip64(archive_path)

            self.assertEqual(mark_utf8_zip_names(archive_path), 1)

            with zipfile.ZipFile(archive_path) as archive:
                self.assertTrue(archive.getinfo(original_name).flag_bits & 0x0800)
                self.assertEqual(archive.read(original_name), b"zip64 entry payload")


if __name__ == "__main__":
    unittest.main()
