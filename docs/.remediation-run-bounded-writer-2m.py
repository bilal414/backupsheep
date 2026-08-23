import hashlib
import importlib.util
import json
import os
import stat
import sys
import time
from pathlib import Path


RUN_ID = "bs-remed-20260818-0d08dcf"
ROOT = Path("/mnt/bs-remed-scale-0d08dcf") / RUN_ID
SOURCE = ROOT / "website-2m" / "source"
EVIDENCE = ROOT / "website-2m" / "bounded-writer-candidate-20260819"
MEMBERS = EVIDENCE / "members.txt"
ARCHIVE = EVIDENCE / "website-2m-bounded.zip"
ARCHIVE_MODULE = EVIDENCE / "_archive_candidate.py"


def load_archive_module():
    spec = importlib.util.spec_from_file_location(
        "backupsheep_bounded_archive_candidate",
        ARCHIVE_MODULE,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


assert SOURCE.is_dir()
assert ARCHIVE_MODULE.is_file()
assert not MEMBERS.exists()
assert not ARCHIVE.exists()
EVIDENCE.mkdir(mode=0o700, parents=True, exist_ok=True)

started_at = time.monotonic()
member_digest = hashlib.sha256()
file_count = 0
directory_count = 0
logical_bytes = 0
with open(MEMBERS, "xb", buffering=1024 * 1024) as members:
    for root, directories, files in os.walk(SOURCE, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        for name in directories:
            path = Path(root) / name
            observed = path.lstat()
            assert stat.S_ISDIR(observed.st_mode)
            relative = path.relative_to(SOURCE).as_posix() + "/"
            line = (relative + "\n").encode("utf-8")
            members.write(line)
            member_digest.update(line)
            directory_count += 1
        for name in files:
            path = Path(root) / name
            observed = path.lstat()
            assert stat.S_ISREG(observed.st_mode)
            relative = path.relative_to(SOURCE).as_posix()
            line = (relative + "\n").encode("utf-8")
            members.write(line)
            member_digest.update(line)
            logical_bytes += observed.st_size
            file_count += 1
    members.flush()
    os.fsync(members.fileno())
enumeration_seconds = time.monotonic() - started_at

assert file_count == 2_000_000
assert directory_count == 2_000
assert logical_bytes == 68_000_000
expected_count = file_count + directory_count
expected_members_sha256 = member_digest.hexdigest()

archive_module = load_archive_module()
fence_checks = 0


def fence():
    global fence_checks
    fence_checks += 1


started_at = time.monotonic()
archive_module.create_zip(
    SOURCE,
    ARCHIVE,
    timeout=12 * 3600,
    member_list_path=MEMBERS,
    expected_member_count=expected_count,
    expected_member_list_sha256=expected_members_sha256,
    expected_source_bytes=logical_bytes,
    during_write=fence,
)
writer_seconds = time.monotonic() - started_at

observed_count = 0
observed_files = 0
observed_directories = 0
for member in archive_module.iter_zip_members(ARCHIVE):
    observed_count += 1
    if member.filename.endswith("/"):
        observed_directories += 1
    else:
        observed_files += 1
assert observed_count == expected_count
assert observed_files == file_count
assert observed_directories == directory_count

archive_digest = hashlib.sha256()
archive_bytes = 0
with open(ARCHIVE, "rb") as archive_file:
    while True:
        chunk = archive_file.read(8 * 1024 * 1024)
        if not chunk:
            break
        archive_digest.update(chunk)
        archive_bytes += len(chunk)

print(
    json.dumps(
        {
            "result": "PASS",
            "run_id": RUN_ID,
            "source": str(SOURCE),
            "file_count": file_count,
            "directory_count": directory_count,
            "logical_bytes": logical_bytes,
            "member_count": observed_count,
            "members_sha256": expected_members_sha256,
            "members_bytes": MEMBERS.stat().st_size,
            "archive": str(ARCHIVE),
            "archive_bytes": archive_bytes,
            "archive_sha256": archive_digest.hexdigest(),
            "enumeration_seconds": round(enumeration_seconds, 3),
            "writer_seconds": round(writer_seconds, 3),
            "fence_checks": fence_checks,
            "python": sys.version,
        },
        sort_keys=True,
    )
)
