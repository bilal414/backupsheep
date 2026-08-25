#!/usr/bin/env python3
"""Build the deterministic BackupSheep WordPress v2 replacement plugin ZIP."""

from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
import stat
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "integrations" / "wordpress" / "backupsheep-v2"
PLUGIN_FILES = ("backupsheep.php", "readme.txt")
ZIP_ROOT = "backupsheep"
MAX_SOURCE_BYTES = 2 * 1024 * 1024


class PluginBuildError(RuntimeError):
    pass


def _read_source(name: str) -> bytes:
    path = SOURCE_ROOT / name
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise PluginBuildError(f"plugin source is not one regular file: {name}")
    if metadata.st_size <= 0 or metadata.st_size > MAX_SOURCE_BYTES:
        raise PluginBuildError(f"plugin source has an invalid size: {name}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_ino != metadata.st_ino
            or opened.st_dev != metadata.st_dev
            or opened.st_nlink != 1
        ):
            raise PluginBuildError(f"plugin source changed while opening: {name}")
        chunks = []
        remaining = MAX_SOURCE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(payload) != opened.st_size:
        raise PluginBuildError(f"plugin source changed while reading: {name}")
    return payload


def build_plugin(output: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for name in PLUGIN_FILES:
            info = zipfile.ZipInfo(f"{ZIP_ROOT}/{name}", date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100644 << 16)
            info.flag_bits |= 0x800
            archive.writestr(info, _read_source(name), compresslevel=9)

    output = output.resolve(strict=False)
    output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(output, flags, 0o644)
    except FileExistsError as error:
        raise PluginBuildError(f"refusing to overwrite existing output: {output}") from error
    try:
        payload = memoryview(buffer.getvalue())
        while payload:
            written = os.write(descriptor, payload)
            if written <= 0:
                raise PluginBuildError("plugin package write made no progress")
            payload = payload[written:]
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        output.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        build_plugin(arguments.output)
    except (OSError, PluginBuildError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
