import json
import re
import sys
from datetime import datetime
from pathlib import Path


UNIT = {
    "B": 1,
    "KB": 1000,
    "MB": 1000**2,
    "GB": 1000**3,
    "TB": 1000**4,
    "KiB": 1024,
    "MiB": 1024**2,
    "GiB": 1024**3,
    "TiB": 1024**4,
}


def byte_value(text):
    match = re.fullmatch(r"\s*([0-9.]+)([A-Za-z]+)\s*", text)
    if not match:
        return None
    return int(float(match.group(1)) * UNIT[match.group(2)])


def summarize(path):
    records = []
    for line in path.read_text().splitlines():
        fields = line.split("|")
        if len(fields) < 5:
            continue
        try:
            timestamp = datetime.fromisoformat(fields[0].replace("Z", "+00:00"))
            cpu = float(fields[1].strip().rstrip("%"))
            memory = byte_value(fields[2].split("/", 1)[0])
            block_read, block_write = (
                byte_value(value) for value in fields[3].split("/", 1)
            )
        except (ValueError, TypeError, KeyError):
            continue
        client_rss_kib = None
        client_cpu = None
        if len(fields) > 4 and fields[4].strip():
            client = fields[4].split(",")
            try:
                client_rss_kib = int(client[0])
                client_cpu = float(client[1])
            except (IndexError, ValueError):
                pass
        records.append(
            {
                "timestamp": timestamp,
                "cpu": cpu,
                "memory": memory,
                "block_read": block_read,
                "block_write": block_write,
                "client_rss_kib": client_rss_kib,
                "client_cpu": client_cpu,
            }
        )

    if not records:
        return {"path": str(path), "samples": 0}
    client_records = [row for row in records if row["client_rss_kib"] is not None]
    first = records[0]
    last = records[-1]
    return {
        "path": str(path),
        "samples": len(records),
        "started_at": first["timestamp"].isoformat(),
        "ended_at": last["timestamp"].isoformat(),
        "sample_span_seconds": (
            last["timestamp"] - first["timestamp"]
        ).total_seconds(),
        "worker_peak_cpu_percent": max(row["cpu"] for row in records),
        "worker_peak_memory_bytes": max(
            row["memory"] for row in records if row["memory"] is not None
        ),
        "worker_block_read_delta_bytes": (
            last["block_read"] - first["block_read"]
            if first["block_read"] is not None and last["block_read"] is not None
            else None
        ),
        "worker_block_write_delta_bytes": (
            last["block_write"] - first["block_write"]
            if first["block_write"] is not None and last["block_write"] is not None
            else None
        ),
        "client_samples": len(client_records),
        "client_peak_rss_kib": max(
            (row["client_rss_kib"] for row in client_records), default=None
        ),
        "client_peak_cpu_percent": max(
            (row["client_cpu"] for row in client_records), default=None
        ),
    }


for value in sys.argv[1:]:
    print(json.dumps(summarize(Path(value)), sort_keys=True))
