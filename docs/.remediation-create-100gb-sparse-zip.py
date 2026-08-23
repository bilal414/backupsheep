#!/usr/bin/env python3
"""Create the exact-owned sparse Zip64 fixture for the 100 GB upload gate."""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import struct
import sys
import time
import zlib
from pathlib import Path


RUN_ID = "bs-remed-20260818-0d08dcf"
TARGET_ARCHIVE_BYTES = 107_421_554_763
MEMBER_NAME = b"bs-remediation-100gb-zero-payload.bin"


def crc32_zeros(length: int) -> int:
    """Return the zlib CRC-32 of length zero bytes without allocating the file."""
    library = ctypes.util.find_library("z")
    if library:
        combine = ctypes.CDLL(library).crc32_combine
        combine.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_longlong]
        combine.restype = ctypes.c_ulong
        chunk_length = 1024 * 1024
        chunk_crc = zlib.crc32(b"\0" * chunk_length) & 0xFFFFFFFF
        chunks, remainder = divmod(length, chunk_length)
        result = 0
        block_crc = chunk_crc
        block_length = chunk_length
        while chunks:
            if chunks & 1:
                result = combine(result, block_crc, block_length) & 0xFFFFFFFF
            chunks >>= 1
            if chunks:
                block_crc = combine(block_crc, block_crc, block_length) & 0xFFFFFFFF
                block_length *= 2
        if remainder:
            tail_crc = zlib.crc32(b"\0" * remainder) & 0xFFFFFFFF
            result = combine(result, tail_crc, remainder) & 0xFFFFFFFF
        return result

    block = b"\0" * (16 * 1024 * 1024)
    result = 0
    remaining = length
    while remaining:
        size = min(remaining, len(block))
        result = zlib.crc32(block[:size], result)
        remaining -= size
    return result & 0xFFFFFFFF


def zip_parts(payload_bytes: int, crc: int) -> tuple[bytes, bytes]:
    local_extra = struct.pack("<HHQQ", 0x0001, 16, payload_bytes, payload_bytes)
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        45,
        0,
        0,
        0,
        0,
        crc,
        0xFFFFFFFF,
        0xFFFFFFFF,
        len(MEMBER_NAME),
        len(local_extra),
    ) + MEMBER_NAME + local_extra

    central_offset = len(local) + payload_bytes
    central_extra = struct.pack(
        "<HHQQQ", 0x0001, 24, payload_bytes, payload_bytes, 0
    )
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        (3 << 8) | 45,
        45,
        0,
        0,
        0,
        0,
        crc,
        0xFFFFFFFF,
        0xFFFFFFFF,
        len(MEMBER_NAME),
        len(central_extra),
        0,
        0,
        0,
        0o100600 << 16,
        0xFFFFFFFF,
    ) + MEMBER_NAME + central_extra

    zip64_eocd_offset = central_offset + len(central)
    zip64_eocd = struct.pack(
        "<IQHHIIQQQQ",
        0x06064B50,
        44,
        (3 << 8) | 45,
        45,
        0,
        0,
        1,
        1,
        len(central),
        central_offset,
    )
    zip64_locator = struct.pack("<IIQI", 0x07064B50, 0, zip64_eocd_offset, 1)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        1,
        1,
        len(central),
        0xFFFFFFFF,
        0,
    )
    return local, central + zip64_eocd + zip64_locator + eocd


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} OUTPUT_DIR")
    output_dir = Path(sys.argv[1]).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / "bs-remediation-100gb-sparse.zip"
    partial = output.with_suffix(".zip.partial")
    record = output_dir / "fixture.json"

    # The footer size is independent of the payload value. Build it once to derive
    # the payload that makes the final archive exactly match the reported boundary.
    placeholder_local, placeholder_tail = zip_parts(1, 0)
    payload_bytes = TARGET_ARCHIVE_BYTES - len(placeholder_local) - len(placeholder_tail)
    if payload_bytes <= 0:
        raise RuntimeError("invalid target archive size")
    crc = crc32_zeros(payload_bytes)
    local, tail = zip_parts(payload_bytes, crc)
    if len(local) + payload_bytes + len(tail) != TARGET_ARCHIVE_BYTES:
        raise RuntimeError("Zip64 geometry did not produce the exact target size")

    started = time.time()
    descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, local)
        os.lseek(descriptor, payload_bytes, os.SEEK_CUR)
        os.write(descriptor, tail)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(partial, output)
    directory_fd = os.open(output_dir, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)

    stat = output.stat()
    evidence = {
        "schema": 1,
        "run_id": RUN_ID,
        "purpose": "100 GB multipart upload and resume acceptance fixture",
        "path": str(output),
        "archive_bytes": stat.st_size,
        "allocated_bytes": stat.st_blocks * 512,
        "member": MEMBER_NAME.decode("ascii"),
        "member_bytes": payload_bytes,
        "member_crc32": f"{crc:08x}",
        "creation_seconds": round(time.time() - started, 6),
    }
    record.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    os.chmod(record, 0o600)
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    main()
