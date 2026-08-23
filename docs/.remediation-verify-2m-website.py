#!/usr/bin/env python3
"""Verify topology and deterministic samples for the 2M website fixture/restore."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path


EXPECTED_DIRECTORIES = 2_000
EXPECTED_FILES_PER_DIRECTORY = 1_000
EXPECTED_FILES = EXPECTED_DIRECTORIES * EXPECTED_FILES_PER_DIRECTORY


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} ROOT MANIFEST")
    root = Path(sys.argv[1]).resolve(strict=True)
    manifest_path = Path(sys.argv[2]).resolve(strict=True)
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("total_files") != EXPECTED_FILES:
        raise RuntimeError("manifest file count is not the exact 2M contract")
    sample = manifest.get("sample")
    if not isinstance(sample, dict) or len(sample) != manifest.get("sample_count"):
        raise RuntimeError("manifest sample is malformed")

    started = time.time()
    directory_count = 0
    file_count = 0
    for directory_index in range(EXPECTED_DIRECTORIES):
        directory = root / f"d{directory_index:04d}"
        entries = list(os.scandir(directory))
        if len(entries) != EXPECTED_FILES_PER_DIRECTORY:
            raise RuntimeError(f"unexpected entry count in {directory.name}")
        expected_first = directory_index * EXPECTED_FILES_PER_DIRECTORY
        observed = set()
        for entry in entries:
            if not entry.is_file(follow_symlinks=False):
                raise RuntimeError(f"non-file entry in {directory.name}")
            observed.add(entry.name)
        expected = {
            f"f{index:07d}.dat"
            for index in range(
                expected_first, expected_first + EXPECTED_FILES_PER_DIRECTORY
            )
        }
        if observed != expected:
            raise RuntimeError(f"filename topology mismatch in {directory.name}")
        directory_count += 1
        file_count += len(entries)

    top_level = list(os.scandir(root))
    if len(top_level) != EXPECTED_DIRECTORIES or any(
        not entry.is_dir(follow_symlinks=False) for entry in top_level
    ):
        raise RuntimeError("top-level directory topology mismatch")

    sample_witness = hashlib.sha256()
    for relative, expected in sorted(sample.items()):
        path = root / relative
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        size = path.stat().st_size
        if digest != expected.get("sha256") or size != expected.get("bytes"):
            raise RuntimeError(f"sample mismatch: {relative}")
        sample_witness.update(
            f"{relative}\0{size}\0{digest}\n".encode("utf-8")
        )

    result = {
        "root": str(root),
        "files": file_count,
        "directories": directory_count,
        "sample_count": len(sample),
        "sample_witness_sha256": sample_witness.hexdigest(),
        "elapsed_seconds": round(time.time() - started, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
