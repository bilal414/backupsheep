"""Small, dependency-free helpers for producing and validating backup archives."""

import errno
import hashlib
import os
import shutil
import stat
import struct
import subprocess
import tempfile
import time
import uuid
import zipfile
import zlib
from typing import NamedTuple


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
_ZIP_STREAM_CHUNK_SIZE = 1024 * 1024
_ZIP_STREAM_STORE_LIMIT = 64 * 1024
_ZIP_STREAM_FENCE_BATCH = 10000


class ArchiveSourcePolicyError(Exception):
    """A source member cannot be represented by the website ZIP contract."""

    def __init__(self, kind, *, relative_path=""):
        self.kind = str(kind or "unsupported")
        # Retain the path only for private diagnostics. The exception text is
        # deliberately stable and secret-free because workers may persist it.
        self.relative_path = str(relative_path or "")
        super().__init__("website archive source contains an unsupported member")


class ZipMember(NamedTuple):
    """Bounded central-directory metadata for one ZIP member."""

    filename: str
    raw_filename: bytes
    flag_bits: int
    compress_type: int
    CRC: int
    compress_size: int
    file_size: int
    external_attr: int
    header_offset: int
    central_offset: int


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
        suffix_found = not required_suffix
        member_count = 0
        suffix = str(required_suffix or "").lower()
        for member in iter_zip_members(archive_path):
            member_count += 1
            if suffix and member.filename.lower().endswith(suffix):
                suffix_found = True
        if not suffix_found:
            raise ValueError(
                f"Backup archive contains no {required_suffix} dump: {archive_path}"
            )

        # Info-ZIP reports its structurally valid zero-member archive as a warning
        # exit, so there is no payload CRC subprocess to run for an empty website.
        # The bounded central-directory reader above has still validated the whole
        # archive. For non-empty archives, stream payloads and CRC state without
        # creating one Python object per member.
        if member_count == 0:
            return archive_path
        process = subprocess.Popen(
            ["unzip", "-tqq", archive_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        process.wait()
        if process.returncode != 0:
            raise ValueError("Backup archive failed CRC validation.")
    except OSError as exc:
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


def _zip64_member_values(
    extra,
    *,
    compressed_size,
    uncompressed_size,
    local_offset,
    disk_start,
):
    """Resolve central size/offset/disk sentinels from a Zip64 extra field."""
    needs_zip64 = (
        compressed_size == _ZIP_UINT32_MAX
        or uncompressed_size == _ZIP_UINT32_MAX
        or local_offset == _ZIP_UINT32_MAX
        or disk_start == _ZIP_UINT16_MAX
    )
    if not needs_zip64:
        return compressed_size, uncompressed_size, local_offset, disk_start
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

            resolved_uncompressed = uncompressed_size
            if uncompressed_size == _ZIP_UINT32_MAX:
                resolved_uncompressed = consume(8)
            resolved_compressed = compressed_size
            if compressed_size == _ZIP_UINT32_MAX:
                resolved_compressed = consume(8)
            resolved_offset = local_offset
            if local_offset == _ZIP_UINT32_MAX:
                resolved_offset = consume(8)
            resolved_disk = disk_start
            if disk_start == _ZIP_UINT16_MAX:
                resolved_disk = consume(4)
            if resolved_disk != 0:
                raise ValueError("Spanned ZIP archives are not supported.")
            return (
                resolved_compressed,
                resolved_uncompressed,
                resolved_offset,
                resolved_disk,
            )
        position = field_end
    raise ValueError("Backup archive Zip64 metadata is missing.")


def _zip64_local_header_offset(
    extra,
    *,
    compressed_size,
    uncompressed_size,
    local_offset,
    disk_start,
):
    """Read the local-header offset from a central Zip64 extra field."""
    return _zip64_member_values(
        extra,
        compressed_size=compressed_size,
        uncompressed_size=uncompressed_size,
        local_offset=local_offset,
        disk_start=disk_start,
    )[2]


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


def iter_zip_members(archive_path):
    """Yield validated standard/Zip64 central entries in bounded memory."""
    with open(archive_path, "rb") as archive_file:
        central_offset, central_size, entry_count = _zip_central_directory(
            archive_file
        )
        directory_start = central_offset
        directory_end = central_offset + central_size
        if entry_count > central_size // _ZIP_CENTRAL_HEADER_SIZE:
            raise ValueError("Backup archive central entry count is invalid.")

        for _entry_index in range(entry_count):
            entry_offset = central_offset
            if entry_offset + _ZIP_CENTRAL_HEADER_SIZE > directory_end:
                raise ValueError("Backup archive central directory is truncated.")
            archive_file.seek(entry_offset)
            central = archive_file.read(_ZIP_CENTRAL_HEADER_SIZE)
            if (
                len(central) != _ZIP_CENTRAL_HEADER_SIZE
                or central[:4] != _ZIP_CENTRAL_SIGNATURE
            ):
                raise ValueError("Backup archive central directory is malformed.")

            flag_bits, compress_type = struct.unpack_from("<HH", central, 8)
            crc = struct.unpack_from("<L", central, 16)[0]
            compressed_size, uncompressed_size = struct.unpack_from(
                "<LL", central, 20
            )
            filename_length, extra_length, comment_length = struct.unpack_from(
                "<HHH", central, 28
            )
            disk_start = struct.unpack_from("<H", central, 34)[0]
            external_attr = struct.unpack_from("<L", central, 38)[0]
            local_offset = struct.unpack_from("<L", central, 42)[0]
            raw_filename = archive_file.read(filename_length)
            extra = archive_file.read(extra_length)
            if len(raw_filename) != filename_length:
                raise ValueError("Backup archive filename is truncated.")
            if len(extra) != extra_length:
                raise ValueError("Backup archive extra field is truncated.")
            (
                compressed_size,
                uncompressed_size,
                local_offset,
                resolved_disk,
            ) = _zip64_member_values(
                extra,
                compressed_size=compressed_size,
                uncompressed_size=uncompressed_size,
                local_offset=local_offset,
                disk_start=disk_start,
            )
            if resolved_disk != 0:
                raise ValueError("Spanned ZIP archives are not supported.")
            try:
                filename = raw_filename.decode(
                    "utf-8" if flag_bits & _ZIP_UTF8_FLAG else "cp437",
                    "strict",
                )
            except UnicodeDecodeError as error:
                raise ValueError("Backup archive filename encoding is invalid.") from error

            central_offset = (
                entry_offset
                + _ZIP_CENTRAL_HEADER_SIZE
                + filename_length
                + extra_length
                + comment_length
            )
            if central_offset > directory_end:
                raise ValueError("Backup archive central directory is truncated.")

            if local_offset >= directory_start:
                raise ValueError("Backup archive local header is out of bounds.")
            archive_file.seek(local_offset)
            local = archive_file.read(_ZIP_LOCAL_HEADER_SIZE)
            if (
                len(local) != _ZIP_LOCAL_HEADER_SIZE
                or local[:4] != _ZIP_LOCAL_SIGNATURE
            ):
                raise ValueError("Backup archive local header is malformed.")
            local_flags, local_compress_type = struct.unpack_from("<HH", local, 6)
            local_filename_length, local_extra_length = struct.unpack_from(
                "<HH", local, 26
            )
            local_filename = archive_file.read(local_filename_length)
            data_offset = (
                local_offset
                + _ZIP_LOCAL_HEADER_SIZE
                + local_filename_length
                + local_extra_length
            )
            if (
                local_flags != flag_bits
                or local_compress_type != compress_type
                or local_filename != raw_filename
                or data_offset + compressed_size > directory_start
            ):
                raise ValueError(
                    "Backup archive local and central headers do not match."
                )
            yield ZipMember(
                filename=filename,
                raw_filename=raw_filename,
                flag_bits=flag_bits,
                compress_type=compress_type,
                CRC=crc,
                compress_size=int(compressed_size),
                file_size=int(uncompressed_size),
                external_attr=external_attr,
                header_offset=int(local_offset),
                central_offset=entry_offset,
            )

        _validate_central_directory_tail(
            archive_file, central_offset, directory_end
        )


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


def _run_zip_writer(command, *, source_dir, timeout, stderr_dir, stdin=None):
    """Run Info-ZIP without retaining per-member console output in memory."""
    with tempfile.TemporaryFile(dir=stderr_dir) as stderr_file:
        process = subprocess.Popen(
            command,
            stdin=stdin,
            stdout=subprocess.DEVNULL,
            stderr=stderr_file,
            cwd=source_dir,
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        stderr_file.flush()
        stderr_file.seek(0, os.SEEK_END)
        stderr_size = stderr_file.tell()
        stderr_file.seek(max(0, stderr_size - 4096))
        stderr_tail = _decode_output(stderr_file.read()).strip()[-1000:]
    return process.returncode, stderr_tail


def _zip_dos_timestamp(timestamp):
    """Return bounded DOS and extended-Unix timestamps for one source member."""
    try:
        seconds = int(timestamp)
    except (TypeError, ValueError, OverflowError):
        seconds = 0
    extended = max(0, min(seconds, _ZIP_UINT32_MAX))
    try:
        value = time.localtime(seconds)
    except (OSError, OverflowError, ValueError):
        value = time.localtime(0)
    if value.tm_year < 1980:
        year, month, day, hour, minute, second = 1980, 1, 1, 0, 0, 0
    elif value.tm_year > 2107:
        year, month, day, hour, minute, second = 2107, 12, 31, 23, 59, 58
    else:
        year, month, day = value.tm_year, value.tm_mon, value.tm_mday
        hour, minute, second = value.tm_hour, value.tm_min, value.tm_sec
    dos_time = (hour << 11) | (minute << 5) | (second // 2)
    dos_date = ((year - 1980) << 9) | (month << 5) | day
    return dos_time, dos_date, extended


def _zip_extended_timestamp(timestamp):
    return struct.pack("<HHBI", 0x5455, 5, 1, timestamp)


def _deflate_bound(size):
    """The zlib deflateBound formula, used before reserving a local header."""
    size = max(0, int(size))
    return size + (size >> 12) + (size >> 14) + (size >> 25) + 13


def _streaming_member(source_root, raw_name):
    """Resolve and revalidate one strict UTF-8 member-list entry."""
    try:
        name = raw_name.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ArchiveSourcePolicyError("invalid_path") from error
    is_directory = name.endswith("/")
    relative = name[:-1] if is_directory else name
    components = relative.split("/")
    if (
        not relative
        or name.startswith("/")
        or "\\" in name
        or any(character in name for character in ("\x00", "\r", "\n"))
        or any(component in ("", ".", "..") for component in components)
        or len(raw_name) > _ZIP_UINT16_MAX
    ):
        raise ArchiveSourcePolicyError("invalid_path", relative_path=name)
    source_path = os.path.join(source_root, *components)
    observed = os.lstat(source_path)
    if stat.S_ISLNK(observed.st_mode):
        raise ArchiveSourcePolicyError("symlink", relative_path=name)
    if is_directory:
        if not stat.S_ISDIR(observed.st_mode):
            raise ArchiveSourcePolicyError("special", relative_path=name)
    elif not stat.S_ISREG(observed.st_mode):
        raise ArchiveSourcePolicyError("special", relative_path=name)
    return name, source_path, observed, is_directory


def _write_streaming_zip_member(
    archive,
    central,
    source_root,
    raw_name,
    *,
    deadline,
    timeout,
):
    """Write one local entry and disk-spool its central-directory record."""
    name, source_path, observed, is_directory = _streaming_member(
        source_root, raw_name
    )
    local_offset = archive.tell()
    dos_time, dos_date, unix_time = _zip_dos_timestamp(observed.st_mtime)
    timestamp_extra = _zip_extended_timestamp(unix_time)
    expected_size = 0 if is_directory else int(observed.st_size)
    method = 0 if is_directory or expected_size <= _ZIP_STREAM_STORE_LIMIT else 8
    size_bound = expected_size if method == 0 else _deflate_bound(expected_size)
    local_zip64 = size_bound > _ZIP_UINT32_MAX
    local_zip64_extra = (
        struct.pack("<HHQQ", 0x0001, 16, expected_size, 0)
        if local_zip64
        else b""
    )
    local_extra = local_zip64_extra + timestamp_extra
    version_needed = 45 if local_zip64 else 20
    flags = _ZIP_UTF8_FLAG
    archive.write(
        struct.pack(
            "<4s5H3L2H",
            _ZIP_LOCAL_SIGNATURE,
            version_needed,
            flags,
            method,
            dos_time,
            dos_date,
            0,
            _ZIP_UINT32_MAX if local_zip64 else 0,
            _ZIP_UINT32_MAX if local_zip64 else expected_size,
            len(raw_name),
            len(local_extra),
        )
    )
    archive.write(raw_name)
    archive.write(local_extra)

    crc = 0
    uncompressed_size = 0
    compressed_size = 0
    if not is_directory:
        flags_open = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source_path, flags_open)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != observed.st_dev
                or opened.st_ino != observed.st_ino
                or opened.st_size != observed.st_size
            ):
                raise RuntimeError(
                    "Website mirror changed during archive creation."
                )
            compressor = zlib.compressobj(level=6, wbits=-15) if method == 8 else None
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                while True:
                    if time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired(
                            "bounded-zip-writer",
                            timeout,
                        )
                    chunk = source.read(_ZIP_STREAM_CHUNK_SIZE)
                    if not chunk:
                        break
                    crc = zlib.crc32(chunk, crc)
                    uncompressed_size += len(chunk)
                    output = compressor.compress(chunk) if compressor else chunk
                    if output:
                        archive.write(output)
                        compressed_size += len(output)
                if compressor:
                    output = compressor.flush()
                    archive.write(output)
                    compressed_size += len(output)
            finished = os.fstat(descriptor)
            if (
                uncompressed_size != expected_size
                or finished.st_size != observed.st_size
                or finished.st_mtime_ns != observed.st_mtime_ns
            ):
                raise RuntimeError(
                    "Website mirror changed during archive creation."
                )
        finally:
            os.close(descriptor)

    end_offset = archive.tell()
    archive.seek(local_offset + 14)
    if local_zip64:
        archive.write(struct.pack("<L", crc & _ZIP_UINT32_MAX))
        archive.seek(local_offset + _ZIP_LOCAL_HEADER_SIZE + len(raw_name) + 4)
        archive.write(struct.pack("<QQ", uncompressed_size, compressed_size))
    else:
        if compressed_size > _ZIP_UINT32_MAX:
            raise RuntimeError("Website archive member unexpectedly exceeded ZIP32.")
        archive.write(
            struct.pack(
                "<LLL",
                crc & _ZIP_UINT32_MAX,
                compressed_size,
                uncompressed_size,
            )
        )
    archive.seek(end_offset)

    central_zip64 = bytearray()
    central_compressed = compressed_size
    central_uncompressed = uncompressed_size
    central_offset = local_offset
    if uncompressed_size > _ZIP_UINT32_MAX:
        central_uncompressed = _ZIP_UINT32_MAX
        central_zip64.extend(struct.pack("<Q", uncompressed_size))
    if compressed_size > _ZIP_UINT32_MAX:
        central_compressed = _ZIP_UINT32_MAX
        central_zip64.extend(struct.pack("<Q", compressed_size))
    if local_offset > _ZIP_UINT32_MAX:
        central_offset = _ZIP_UINT32_MAX
        central_zip64.extend(struct.pack("<Q", local_offset))
    zip64_extra = (
        struct.pack("<HH", 0x0001, len(central_zip64)) + bytes(central_zip64)
        if central_zip64
        else b""
    )
    central_extra = zip64_extra + timestamp_extra
    if central_zip64 or local_zip64:
        version_needed = 45
    external_attr = (int(observed.st_mode) & 0xFFFF) << 16
    if is_directory:
        external_attr |= 0x10
    central.write(
        struct.pack(
            "<4s6H3L5H2L",
            _ZIP_CENTRAL_SIGNATURE,
            (3 << 8) | version_needed,
            version_needed,
            flags,
            method,
            dos_time,
            dos_date,
            crc & _ZIP_UINT32_MAX,
            central_compressed,
            central_uncompressed,
            len(raw_name),
            len(central_extra),
            0,
            0,
            0,
            external_attr,
            central_offset,
        )
    )
    central.write(raw_name)
    central.write(central_extra)
    return expected_size


def _write_zip_end_records(archive, *, entry_count, central_size, central_offset):
    needs_zip64 = (
        entry_count >= _ZIP_UINT16_MAX
        or central_size > _ZIP_UINT32_MAX
        or central_offset > _ZIP_UINT32_MAX
    )
    if needs_zip64:
        zip64_offset = archive.tell()
        archive.write(
            struct.pack(
                "<4sQ2H2L4Q",
                _ZIP64_EOCD_SIGNATURE,
                44,
                45,
                45,
                0,
                0,
                entry_count,
                entry_count,
                central_size,
                central_offset,
            )
        )
        archive.write(
            struct.pack(
                "<4sLQL",
                _ZIP64_LOCATOR_SIGNATURE,
                0,
                zip64_offset,
                1,
            )
        )
    archive.write(
        struct.pack(
            "<4s4H2LH",
            _ZIP_EOCD_SIGNATURE,
            0,
            0,
            min(entry_count, _ZIP_UINT16_MAX),
            min(entry_count, _ZIP_UINT16_MAX),
            min(central_size, _ZIP_UINT32_MAX),
            min(central_offset, _ZIP_UINT32_MAX),
            0,
        )
    )


def _create_streaming_zip(
    source_dir,
    staged_path,
    member_list_path,
    *,
    timeout,
    expected_member_count=None,
    expected_member_list_sha256=None,
    expected_source_bytes=None,
    during_write=None,
):
    """Write a ZIP with O(1) resident member state and disk-spooled central data."""
    source_root = os.path.abspath(source_dir)
    parent = os.path.dirname(staged_path) or "."
    deadline = time.monotonic() + max(1, int(timeout))
    member_digest = hashlib.sha256()
    entry_count = 0
    source_bytes = 0
    with open(staged_path, "w+b") as archive, tempfile.TemporaryFile(
        dir=parent
    ) as central, open(member_list_path, "rb") as members:
        for line in members:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("bounded-zip-writer", timeout)
            if not line.endswith(b"\n"):
                raise ArchiveSourcePolicyError("invalid_path")
            member_digest.update(line)
            raw_name = line[:-1]
            source_bytes += _write_streaming_zip_member(
                archive,
                central,
                source_root,
                raw_name,
                deadline=deadline,
                timeout=timeout,
            )
            entry_count += 1
            if (
                during_write is not None
                and entry_count % _ZIP_STREAM_FENCE_BATCH == 0
            ):
                during_write()
        if expected_member_count is not None and entry_count != int(
            expected_member_count
        ):
            raise RuntimeError("Website archive member count changed before writing.")
        if (
            expected_member_list_sha256 is not None
            and member_digest.hexdigest() != str(expected_member_list_sha256)
        ):
            raise RuntimeError("Website archive member list changed before writing.")
        if expected_source_bytes is not None and source_bytes != int(
            expected_source_bytes
        ):
            raise RuntimeError("Website archive source size changed before writing.")
        if during_write is not None:
            during_write()
        central_offset = archive.tell()
        central.flush()
        central_size = central.tell()
        central.seek(0)
        shutil.copyfileobj(central, archive, _ZIP_STREAM_CHUNK_SIZE)
        _write_zip_end_records(
            archive,
            entry_count=entry_count,
            central_size=central_size,
            central_offset=central_offset,
        )
        archive.flush()
        os.fsync(archive.fileno())
    return entry_count


def create_zip(
    source_dir,
    archive_path,
    *,
    timeout,
    required_suffix=None,
    before_publish=None,
    member_list_path=None,
    expected_member_count=None,
    expected_member_list_sha256=None,
    expected_source_bytes=None,
    during_write=None,
):
    """Build, fsync, and atomically publish a validated ZIP archive."""
    archive_path = os.path.abspath(archive_path)
    staged_path = _staged_archive_path(archive_path)
    try:
        if member_list_path:
            _create_streaming_zip(
                source_dir,
                staged_path,
                member_list_path,
                timeout=timeout,
                expected_member_count=expected_member_count,
                expected_member_list_sha256=expected_member_list_sha256,
                expected_source_bytes=expected_source_bytes,
                during_write=during_write,
            )
        else:
            command = ["zip", "-q", "-y", "-r", staged_path, ".", "-i", "*"]
            returncode, stderr = _run_zip_writer(
                command,
                source_dir=source_dir,
                timeout=timeout,
                stderr_dir=os.path.dirname(staged_path) or ".",
            )
            if returncode != 0:
                raise RuntimeError(
                    f"zip failed with exit code {returncode}"
                    + (f": {stderr}" if stderr else "")
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
