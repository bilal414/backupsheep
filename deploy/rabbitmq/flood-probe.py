#!/usr/bin/env python3
"""Prove RabbitMQ rejects a bounded queue flood using publisher confirms."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from amqp.exceptions import MessageNacked
from kombu import Connection, Exchange, Producer
from kombu.exceptions import OperationalError


def _arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="rabbitmq")
    parser.add_argument("--port", type=int, default=5672)
    parser.add_argument("--vhost", default="backupsheep")
    parser.add_argument("--user", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument(
        "--queue",
        choices=("default", "cloud", "database", "files", "storage", "logs"),
        required=True,
    )
    parser.add_argument("--payload-bytes", type=int, default=1024)
    parser.add_argument("--max-attempts", type=int, default=100)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    if not 1 <= args.payload_bytes <= 1024 * 1024:
        raise SystemExit("payload size must be between 1 byte and 1 MiB")
    if not 2 <= args.max_attempts <= 20000:
        raise SystemExit("max attempts must be between 2 and 20000")
    password_path = Path(args.password_file)
    if not password_path.is_file() or password_path.is_symlink():
        raise SystemExit("password file is unavailable")
    password = password_path.read_text(encoding="utf-8").rstrip("\n")
    if len(password) < 32:
        raise SystemExit("password file is invalid")

    published = 0
    rejected = False
    exchange = Exchange(
        f"backupsheep.{args.queue}",
        type="direct",
        durable=True,
        no_declare=True,
    )
    connection = Connection(
        hostname=args.host,
        port=args.port,
        virtual_host=args.vhost,
        userid=args.user,
        password=password,
        transport_options={"confirm_publish": True},
        connect_timeout=10,
    )
    password = ""
    try:
        connection.ensure_connection(max_retries=3)
        channel = connection.channel()
        producer = Producer(channel, exchange=exchange, routing_key=args.queue)
        payload = b"x" * args.payload_bytes
        for sequence in range(args.max_attempts):
            try:
                confirmed = producer.publish(
                    payload,
                    serializer="raw",
                    content_type="application/octet-stream",
                    content_encoding="binary",
                    delivery_mode=2,
                    mandatory=True,
                    retry=False,
                    headers={"probe": "backupsheep-capacity", "sequence": sequence},
                )
                if confirmed is False:
                    rejected = True
                    break
                published += 1
            except (MessageNacked, OperationalError):
                rejected = True
                break
        try:
            channel.queue_purge(args.queue)
        except Exception:
            # The disposable integration broker is removed after the probe. Never
            # hide a valid nack merely because cleanup raced a closed channel.
            pass
    finally:
        connection.release()

    print(
        json.dumps(
            {
                "queue": args.queue,
                "published_before_reject": published,
                "rejected": rejected,
            },
            separators=(",", ":"),
        )
    )
    return 0 if rejected else 1


if __name__ == "__main__":
    raise SystemExit(main())
