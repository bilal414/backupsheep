#!/usr/bin/env python3
"""Generate the exact-owned two-million-file SFTP acceptance fixture."""

from __future__ import annotations

import hashlib
import json
import os
import resource
import time
from pathlib import Path


RUN_ID = "bs-remed-20260818-0d08dcf"
TOTAL_FILES = 2_000_000
DIRECTORIES = 2_000
FILES_PER_DIRECTORY = TOTAL_FILES // DIRECTORIES
ROOT = Path(
    "/mnt/bs-remed-scale-0d08dcf/bs-remed-20260818-0d08dcf/website-2m"
)
SOURCE = ROOT / "source"
PROGRESS = ROOT / "generation-progress.json"
MANIFEST = ROOT / "source-sample-manifest.json"


def payload(index: int) -> bytes:
    return f"{RUN_ID}:{index:07d}\n".encode("ascii")


def relative_path(index: int) -> str:
    directory = index // FILES_PER_DIRECTORY
    return f"d{directory:04d}/f{index:07d}.dat"


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as destination:
        json.dump(value, destination, sort_keys=True, separators=(",", ":"))
        destination.write("\n")
        destination.flush()
        os.fsync(destination.fileno())
    os.replace(temporary, path)


def main() -> None:
    if TOTAL_FILES % DIRECTORIES:
        raise RuntimeError("fixture geometry is not integral")
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(ROOT, 0o700)
    SOURCE.mkdir(mode=0o700)
    if any(SOURCE.iterdir()):
        raise RuntimeError("the exact source directory is not empty")

    filesystem = os.statvfs(ROOT)
    free_bytes = filesystem.f_bavail * filesystem.f_frsize
    free_inodes = filesystem.f_favail
    if free_bytes < 20 * 1024**3:
        raise RuntimeError("less than 20 GiB is available for the 2M fixture")
    if free_inodes < TOTAL_FILES + DIRECTORIES + 200_000:
        raise RuntimeError("insufficient inode headroom for the 2M fixture")

    sample_indexes = set(range(0, TOTAL_FILES, max(1, TOTAL_FILES // 4096)))
    sample_indexes.update({0, TOTAL_FILES - 1})
    sample = {}
    logical_manifest = hashlib.sha256()
    started = time.time()
    created = 0

    for directory_index in range(DIRECTORIES):
        directory = SOURCE / f"d{directory_index:04d}"
        directory.mkdir(mode=0o700)
        first = directory_index * FILES_PER_DIRECTORY
        for offset in range(FILES_PER_DIRECTORY):
            index = first + offset
            contents = payload(index)
            relative = relative_path(index)
            descriptor = os.open(
                directory / f"f{index:07d}.dat",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                os.write(descriptor, contents)
            finally:
                os.close(descriptor)
            digest = hashlib.sha256(contents).hexdigest()
            logical_manifest.update(
                relative.encode("ascii") + b"\0" + digest.encode("ascii") + b"\n"
            )
            if index in sample_indexes:
                sample[relative] = {
                    "bytes": len(contents),
                    "sha256": digest,
                }
            created += 1

        if (directory_index + 1) % 25 == 0:
            write_json(
                PROGRESS,
                {
                    "schema": 1,
                    "run_id": RUN_ID,
                    "state": "creating",
                    "created_files": created,
                    "total_files": TOTAL_FILES,
                    "completed_directories": directory_index + 1,
                    "total_directories": DIRECTORIES,
                    "elapsed_seconds": round(time.time() - started, 3),
                    "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                },
            )

    elapsed = time.time() - started
    result = {
        "schema": 1,
        "run_id": RUN_ID,
        "purpose": "two-million-file website backup and restore acceptance",
        "source": str(SOURCE),
        "total_files": TOTAL_FILES,
        "total_directories": DIRECTORIES,
        "payload_bytes": sum(len(payload(i)) for i in range(TOTAL_FILES)),
        "logical_manifest_sha256": logical_manifest.hexdigest(),
        "sample_count": len(sample),
        "sample": sample,
        "generation_seconds": round(elapsed, 3),
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    write_json(MANIFEST, result)
    write_json(
        PROGRESS,
        {
            "schema": 1,
            "run_id": RUN_ID,
            "state": "complete",
            "created_files": TOTAL_FILES,
            "total_files": TOTAL_FILES,
            "completed_directories": DIRECTORIES,
            "total_directories": DIRECTORIES,
            "elapsed_seconds": round(elapsed, 3),
            "peak_rss_kib": result["peak_rss_kib"],
            "logical_manifest_sha256": result["logical_manifest_sha256"],
            "sample_count": result["sample_count"],
        },
    )
    print(json.dumps({key: result[key] for key in result if key != "sample"}, sort_keys=True))


if __name__ == "__main__":
    main()
