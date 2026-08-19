"""Small, dependency-free helpers for producing and validating backup archives."""

import errno
import os
import struct
import subprocess
import uuid
import zipfile


_ZIP_CENTRAL_HEADER_SIZE = 46
_ZIP_LOCAL_HEADER_SIZE = 30
_ZIP_CENTRAL_SIGNATURE = b"PK\x01\x02"
_ZIP_LOCAL_SIGNATURE = b"PK\x03\x04"
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP_CENTRAL_DIGITAL_SIGNATURE = b"PK\x05\x05"
_ZIP_UTF8_FLAG = 0x0800
_ZIP_UINT16_MAX = 0xFFFF
_ZIP_UINT32_MAX = 0xFFFFFFFF
_ZIP_EOCD_SIZE = 22
_ZIP_MAX_COMMENT_SIZE = 0xFFFF


class ArchiveSourcePolicyError(Exception):
    """A source member cannot be represented by the website ZIP contract."""

    def __init__(self, kind, *, relative_path=""):
        self.kind = str(kind or "unsupported")
        # Retain the path only for private diagnostics. The exception text is
        # deliberately stable and secret-free because workers may persist it.
        self.relative_path = str(relative_path or "")
        super().__init__("website archive source contains an unsupported member")


def _decode_output(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value or ""


def validate_zip_archive(archive_path, *, required_suffix=None):
    """Validate that *archive_path* is a readable, non-empty ZIP archive.

    ``zip`` can leave a zero-byte or otherwise incomplete output behind after a
    failed transfer.  Checking both the central directory and every member CRC
    catches those cases before the backup is made available for upload.

    ``required_suffix`` is used by logical database backups to ensure that the
    archive contains a real dump rather than only the placeholder file created
    for an empty working directory.
    """
    if not os.path.isfile(archive_path) or os.path.getsize(archive_path) <= 0:
        raise ValueError(f"Backup archive was not created: {archive_path}")

    try:
        with zipfile.ZipFile(archive_path) as archive:
            bad_member = archive.testzip()
            if bad_member:
                raise ValueError(f"Backup archive failed CRC validation: {bad_member}")

            if required_suffix and not any(
                name.lower().endswith(required_suffix.lower())
                for name in archive.namelist()
            ):
                raise ValueError(
                    f"Backup archive contains no {required_suffix} dump: {archive_path}"
                )
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"Backup archive is not a valid ZIP: {archive_path}") from exc

    return archive_path


def _staged_archive_path(archive_path):
    parent = os.path.dirname(archive_path) or "."
    name = os.path.basename(archive_path)
    return os.path.join(parent, f".{name}.{uuid.uuid4().hex}.partial.zip")


def _fsync_file(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_parent(path):
    descriptor = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            # Some network/pseudo filesystems do not support directory fsync.
            # The archive itself was still fsynced before the atomic rename.
            if error.errno not in (errno.EINVAL, errno.ENOTSUP, errno.EBADF):
                raise
    finally:
        os.close(descriptor)


def _find_zip_eocd(archive_file):
    """Return the validated EOCD offset and unpacked fixed fields."""
    archive_file.seek(0, os.SEEK_END)
    file_size = archive_file.tell()
    tail_size = min(file_size, _ZIP_EOCD_SIZE + _ZIP_MAX_COMMENT_SIZE)
    archive_file.seek(file_size - tail_size)
    tail = archive_file.read(tail_size)
    search_end = len(tail)
    while True:
        position = tail.rfind(_ZIP_EOCD_SIGNATURE, 0, search_end)
        if position < 0:
            raise ValueError("Backup archive end record is missing.")
        if position + _ZIP_EOCD_SIZE <= len(tail):
            fields = struct.unpack_from("<4s4H2LH", tail, position)
            comment_length = fields[-1]
            absolute = file_size - tail_size + position
            if absolute + _ZIP_EOCD_SIZE + comment_length == file_size:
                return absolute, fields
        search_end = position


def _zip_central_directory(archive_file):
    """Locate one non-spanned standard/Zip64 central directory in O(1) memory."""
    eocd_offset, fields = _find_zip_eocd(archive_file)
    (
        _signature,
        disk_number,
        central_disk,
        entries_on_disk,
        entry_count,
        central_size,
        central_offset,
        _comment_length,
    ) = fields
    has_maximum_standard_field = (
        entries_on_disk == _ZIP_UINT16_MAX
        or entry_count == _ZIP_UINT16_MAX
        or central_size == _ZIP_UINT32_MAX
        or central_offset == _ZIP_UINT32_MAX
    )
    directory_boundary = eocd_offset
    locator_offset = eocd_offset - 20
    locator = b""
    if locator_offset >= 0:
        archive_file.seek(locator_offset)
        locator = archive_file.read(20)
    has_zip64_locator = (
        len(locator) == 20 and locator[:4] == _ZIP64_LOCATOR_SIGNATURE
    )
    if has_zip64_locator:
        (
            _locator_signature,
            zip64_disk,
            zip64_eocd_offset,
            total_disks,
        ) = struct.unpack("<4sLQL", locator)
        if zip64_disk != 0 or total_disks != 1:
            raise ValueError("Spanned ZIP archives are not supported.")
        archive_file.seek(zip64_eocd_offset)
        fixed = archive_file.read(56)
        if len(fixed) != 56 or fixed[:4] != _ZIP64_EOCD_SIGNATURE:
            raise ValueError("Backup archive Zip64 end record is malformed.")
        (
            _zip64_signature,
            record_size,
            _version_made,
            _version_needed,
            disk_number,
            central_disk,
            entries_on_disk,
            entry_count,
            central_size,
            central_offset,
        ) = struct.unpack("<4sQ2H2L4Q", fixed)
        if record_size < 44 or zip64_eocd_offset + 12 + record_size != locator_offset:
            raise ValueError("Backup archive Zip64 end record has an invalid size.")
        directory_boundary = zip64_eocd_offset

    # The largest values represent either ordinary standard-ZIP maxima or Zip64
    # sentinels. A real Zip64 archive is identified by its mandatory locator;
    # accepting the standard maxima without one keeps exactly-65,535-member
    # archives valid while later bounds/count checks still reject corruption.
    if has_maximum_standard_field and not has_zip64_locator:
        directory_boundary = eocd_offset

    if disk_number != 0 or central_disk != 0 or entries_on_disk != entry_count:
        raise ValueError("Spanned ZIP archives are not supported.")
    if central_offset + central_size > directory_boundary:
        raise ValueError("Backup archive central directory is out of bounds.")
    return int(central_offset), int(central_size), int(entry_count)


def _zip64_local_header_offset(
    extra,
    *,
    compressed_size,
    uncompressed_size,
    local_offset,
    disk_start,
):
    """Read the local-header offset from a central Zip64 extra field."""
    if local_offset != _ZIP_UINT32_MAX and disk_start != _ZIP_UINT16_MAX:
        return local_offset
    position = 0
    while position + 4 <= len(extra):
        field_id, field_size = struct.unpack_from("<HH", extra, position)
        position += 4
        field_end = position + field_size
        if field_end > len(extra):
            raise ValueError("Backup archive extra field is truncated.")
        if field_id == 0x0001:
            cursor = position

            def consume(size):
                nonlocal cursor
                if cursor + size > field_end:
                    raise ValueError("Backup archive Zip64 extra field is truncated.")
                value = int.from_bytes(extra[cursor:cursor + size], "little")
                cursor += size
                return value

            if uncompressed_size == _ZIP_UINT32_MAX:
                consume(8)
            if compressed_size == _ZIP_UINT32_MAX:
                consume(8)
            resolved_offset = local_offset
            if local_offset == _ZIP_UINT32_MAX:
                resolved_offset = consume(8)
            if disk_start == _ZIP_UINT16_MAX:
                if consume(4) != 0:
                    raise ValueError("Spanned ZIP archives are not supported.")
            return resolved_offset
        position = field_end
    raise ValueError("Backup archive Zip64 local-header offset is missing.")


def _validate_central_directory_tail(archive_file, position, directory_end):
    """Allow only the optional central-directory digital-signature record."""
    remaining = directory_end - position
    if remaining == 0:
        return
    if remaining < 6:
        raise ValueError("Backup archive central directory is malformed.")
    archive_file.seek(position)
    header = archive_file.read(6)
    if header[:4] != _ZIP_CENTRAL_DIGITAL_SIGNATURE:
        raise ValueError("Backup archive central directory is malformed.")
    signature_size = struct.unpack_from("<H", header, 4)[0]
    if 6 + signature_size != remaining:
        raise ValueError("Backup archive central signature is malformed.")


def mark_utf8_zip_names(archive_path):
    """Mark Info-ZIP entries whose raw names are valid non-ASCII UTF-8.

    Info-ZIP 3.0 on Debian stores Unix filename bytes unchanged but leaves the
    language-encoding bit clear, even when its Unicode support and UTF-8 locale
    are enabled. Standard readers must then decode those bytes as CP437, which
    turns otherwise correct website names into mojibake during restore.

    Patch only the two general-purpose flag fields that describe the existing
    filename bytes: one in the local header and one in the central directory.
    File data, compression, CRCs, ZIP64 offsets, symlink representation, empty
    directories, and entry order remain untouched. Invalid UTF-8 byte names are
    deliberately left unmarked rather than guessed. The same header-only mutation is
    used for newly produced archives and for a downloaded working copy of
    historical BackupSheep archives; a committed storage object is never changed.
    """

    patched = 0
    with open(archive_path, "r+b") as archive_file:
        central_offset, central_size, entry_count = _zip_central_directory(
            archive_file
        )
        directory_start = central_offset
        directory_end = central_offset + central_size
        for _entry_index in range(entry_count):
            entry_offset = central_offset
            archive_file.seek(entry_offset)
            central = archive_file.read(_ZIP_CENTRAL_HEADER_SIZE)
            if (
                len(central) != _ZIP_CENTRAL_HEADER_SIZE
                or central[:4] != _ZIP_CENTRAL_SIGNATURE
            ):
                raise ValueError("Backup archive central directory is malformed.")

            central_flags = struct.unpack_from("<H", central, 8)[0]
            filename_length, extra_length, comment_length = struct.unpack_from(
                "<HHH", central, 28
            )
            raw_filename = archive_file.read(filename_length)
            if len(raw_filename) != filename_length:
                raise ValueError("Backup archive filename is truncated.")
            extra = archive_file.read(extra_length)
            if len(extra) != extra_length:
                raise ValueError("Backup archive extra field is truncated.")
            compressed_size, uncompressed_size = struct.unpack_from(
                "<LL", central, 20
            )
            disk_start = struct.unpack_from("<H", central, 34)[0]
            if disk_start not in (0, _ZIP_UINT16_MAX):
                raise ValueError("Spanned ZIP archives are not supported.")
            local_offset = _zip64_local_header_offset(
                extra,
                compressed_size=compressed_size,
                uncompressed_size=uncompressed_size,
                local_offset=struct.unpack_from("<L", central, 42)[0],
                disk_start=disk_start,
            )
            central_offset = (
                entry_offset
                + _ZIP_CENTRAL_HEADER_SIZE
                + filename_length
                + extra_length
                + comment_length
            )
            if central_offset > directory_end:
                raise ValueError("Backup archive central directory is truncated.")

            should_mark = False
            if not central_flags & _ZIP_UTF8_FLAG and any(
                byte >= 0x80 for byte in raw_filename
            ):
                try:
                    raw_filename.decode("utf-8", "strict")
                except UnicodeDecodeError:
                    pass
                else:
                    should_mark = True

            if should_mark:
                if local_offset >= directory_start:
                    raise ValueError(
                        "Backup archive local header is out of bounds."
                    )
                archive_file.seek(local_offset)
                local = archive_file.read(_ZIP_LOCAL_HEADER_SIZE)
                if (
                    len(local) != _ZIP_LOCAL_HEADER_SIZE
                    or local[:4] != _ZIP_LOCAL_SIGNATURE
                ):
                    raise ValueError("Backup archive local header is malformed.")
                local_flags = struct.unpack_from("<H", local, 6)[0]
                local_filename_length, local_extra_length = struct.unpack_from(
                    "<HH", local, 26
                )
                local_filename = archive_file.read(local_filename_length)
                if (
                    local_flags != central_flags
                    or local_filename != raw_filename
                    or local_offset
                    + _ZIP_LOCAL_HEADER_SIZE
                    + local_filename_length
                    + local_extra_length
                    > directory_start
                ):
                    raise ValueError(
                        "Backup archive local and central filenames do not match."
                    )

                archive_file.seek(local_offset + 6)
                archive_file.write(
                    struct.pack("<H", local_flags | _ZIP_UTF8_FLAG)
                )
                archive_file.seek(entry_offset + 8)
                archive_file.write(
                    struct.pack("<H", central_flags | _ZIP_UTF8_FLAG)
                )
                patched += 1
        _validate_central_directory_tail(
            archive_file, central_offset, directory_end
        )
    return patched


def _publish_archive(
    staged_path,
    archive_path,
    *,
    required_suffix=None,
    before_publish=None,
):
    validate_zip_archive(staged_path, required_suffix=required_suffix)
    _fsync_file(staged_path)
    if before_publish is not None:
        before_publish()
    os.replace(staged_path, archive_path)
    _fsync_parent(archive_path)
    return validate_zip_archive(archive_path, required_suffix=required_suffix)


def create_zip(
    source_dir,
    archive_path,
    *,
    timeout,
    required_suffix=None,
    before_publish=None,
):
    """Build, fsync, and atomically publish a validated ZIP archive."""
    archive_path = os.path.abspath(archive_path)
    staged_path = _staged_archive_path(archive_path)
    try:
        result = subprocess.run(
            ["zip", "-y", "-r", staged_path, ".", "-i", "*"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            cwd=source_dir,
        )
        if result.returncode != 0:
            stderr = _decode_output(result.stderr).strip()
            raise RuntimeError(
                f"zip failed with exit code {result.returncode}"
                + (f": {stderr[-1000:]}" if stderr else "")
            )
        mark_utf8_zip_names(staged_path)
        return _publish_archive(
            staged_path,
            archive_path,
            required_suffix=required_suffix,
            before_publish=before_publish,
        )
    finally:
        try:
            os.remove(staged_path)
        except FileNotFoundError:
            pass


def create_python_zip(
    source_dir,
    archive_path,
    *,
    required_suffix=None,
    before_publish=None,
):
    """Python ZIP writer with the same atomic publication contract as ``zip``."""
    archive_path = os.path.abspath(archive_path)
    staged_path = _staged_archive_path(archive_path)
    try:
        with zipfile.ZipFile(
            staged_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True
        ) as archive:
            for root, _dirs, files in os.walk(
                source_dir, onerror=None, followlinks=False
            ):
                for name in files:
                    path = os.path.join(root, name)
                    archive.write(path, os.path.relpath(path, source_dir))
        return _publish_archive(
            staged_path,
            archive_path,
            required_suffix=required_suffix,
            before_publish=before_publish,
        )
    finally:
        try:
            os.remove(staged_path)
        except FileNotFoundError:
            pass
