#!/usr/local/bin/python3
"""Fail health when an egress workload loses its current guard lease or peer set."""

from __future__ import annotations

import os
import socket
from pathlib import Path


def required_endpoint(host_key: str, port_key: str) -> tuple[str, int]:
    host = os.environ.get(host_key, "")
    port_text = os.environ.get(port_key, "")
    if not host or len(host) > 253 or any(character.isspace() for character in host):
        raise ValueError("invalid endpoint host")
    if not port_text.isascii() or not port_text.isdecimal():
        raise ValueError("invalid endpoint port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("invalid endpoint port")
    return host, port


def connect(endpoint: tuple[str, int]) -> None:
    with socket.create_connection(endpoint, timeout=1.5):
        pass


def main() -> int:
    try:
        role = os.environ.get("BACKUPSHEEP_RUNTIME_ROLE", "")
        if role == "web":
            connect(("127.0.0.1", 8000))
        elif role in {"cloud", "database", "files", "storage", "logs"}:
            ready_file = Path("/run/backupsheep/celery-ready")
            if (
                ready_file.is_symlink()
                or ready_file.read_text(encoding="ascii") != f"{role}\n"
            ):
                return 1
        else:
            return 1

        # These connections traverse the guard's current kernel-expiring exact
        # tuple set. A local web/worker process cannot remain healthy after the
        # guard exits, its lease expires, or either internal peer is revoked.
        connect(required_endpoint("DB_HOST", "DB_PORT"))
        connect(required_endpoint("RABBITMQ_HOST", "RABBITMQ_PORT"))
    except (OSError, UnicodeError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
