#!/usr/bin/env python3
"""Disposable raw DNS client for the Linux egress acceptance harness."""

from __future__ import annotations

import socket
import struct
import sys


def exact_read(stream: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.recv(length - len(chunks))
        if not chunk:
            raise RuntimeError("DNS-over-TCP response ended early")
        chunks.extend(chunk)
    return bytes(chunks)


def wire_name(name: str) -> bytes:
    labels = name.split(".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid test DNS name")
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"


def decoded_question(packet: bytes) -> tuple[str, int, int]:
    cursor = 12
    labels: list[str] = []
    while True:
        length = packet[cursor]
        cursor += 1
        if length == 0:
            break
        if length > 63:
            raise RuntimeError("compressed or malformed response question")
        labels.append(packet[cursor : cursor + length].decode("ascii"))
        cursor += length
    qtype, qclass = struct.unpack("!HH", packet[cursor : cursor + 4])
    return ".".join(labels), qtype, qclass


transport, name, qtype_text, expected_rcode_text = sys.argv[1:5]
qtype = int(qtype_text)
expected_rcode = int(expected_rcode_text)
transaction_id = 0xBEEF
# Deliberately include an EDNS OPT record. The strict proxy must never forward or
# reflect it; it constructs a minimal canonical upstream query instead.
query = (
    struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 1)
    + wire_name(name)
    + struct.pack("!HH", qtype, 1)
    + b"\0"
    + struct.pack("!HHIH", 41, 1232, 0, 0)
)

kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
with socket.socket(socket.AF_INET, kind) as client:
    client.settimeout(5)
    client.connect(("127.0.0.11", 53))
    if transport == "udp":
        client.sendall(query)
        response = client.recv(65535)
    elif transport == "tcp":
        client.sendall(struct.pack("!H", len(query)) + query)
        response_length = struct.unpack("!H", exact_read(client, 2))[0]
        response = exact_read(client, response_length)
    else:
        raise ValueError("transport must be udp or tcp")

if len(response) < 12:
    raise RuntimeError("short DNS response")
response_id, flags, questions, answers, authorities, additionals = struct.unpack(
    "!HHHHHH", response[:12]
)
if response_id != transaction_id:
    raise RuntimeError("the local client transaction ID was not restored")
if flags & 0xF != expected_rcode:
    raise RuntimeError(f"expected DNS rcode {expected_rcode}, received {flags & 0xF}")
if questions != 1:
    raise RuntimeError("the response did not contain one canonical question")
response_name, response_type, response_class = decoded_question(response)
if response_name != name.lower():
    raise RuntimeError("the proxy did not canonicalize mixed-case qname bits")
if response_type != qtype or response_class != 1:
    raise RuntimeError("the response question changed type or class")
if additionals != 0:
    raise RuntimeError("the proxy reflected or forwarded the EDNS covert channel")
if expected_rcode == 0 and qtype == 1 and answers < 1:
    raise RuntimeError("an exact approved name returned no address")
if expected_rcode != 0 and (answers != 0 or authorities != 0):
    raise RuntimeError("a rejected name returned an unexpected DNS record")
