#!/usr/bin/env python3
"""Validate Cosign's authenticated image-verification evidence.

Cosign performs the cryptographic verification.  This companion gate makes
the verified subject explicit and binds the retained local Sigstore bundle to
the same immutable image digest.  It deliberately accepts neither tags nor a
best-effort parse of malformed or duplicate-key JSON.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_SIGNATURES = 8
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[1-9][0-9]{0,4})?/)?"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
EXPECTED_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
EXPECTED_PAYLOAD_TYPE = "application/vnd.in-toto+json"
EXPECTED_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
EXPECTED_PREDICATE_TYPE = "https://sigstore.dev/cosign/sign/v1"


class EvidenceError(RuntimeError):
    """Retained verification evidence violated a fail-closed invariant."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _load_private_json(path: Path, *, label: str) -> tuple[Any, bytes]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise EvidenceError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise EvidenceError(f"{label} must be a regular non-symlink file")
    if before.st_nlink != 1:
        raise EvidenceError(f"{label} must have exactly one hard link")
    if before.st_uid != os.getuid():
        raise EvidenceError(f"{label} must be owned by the current user")
    if stat.S_IMODE(before.st_mode) & 0o077:
        raise EvidenceError(f"{label} must not be accessible by group or other")
    if before.st_size < 2 or before.st_size > MAX_EVIDENCE_BYTES:
        raise EvidenceError(f"{label} has an invalid size")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceError(f"cannot open {label}: {exc}") from exc
    try:
        current = os.fstat(descriptor)
        fingerprint = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if fingerprint != (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
        ):
            raise EvidenceError(f"{label} changed while it was opened")
        payload = b""
        while len(payload) <= MAX_EVIDENCE_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_EVIDENCE_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload += chunk
        if len(payload) != current.st_size:
            raise EvidenceError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)

    try:
        document = json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{label} is not canonical JSON input: {exc}") from exc
    return document, payload


def _exact_dict(value: Any, keys: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise EvidenceError(f"{label} must contain exactly {sorted(keys)}")
    return value


def _decode_base64(value: Any, *, label: str, minimum: int = 1) -> bytes:
    if not isinstance(value, str) or len(value) > MAX_EVIDENCE_BYTES:
        raise EvidenceError(f"{label} must be bounded base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EvidenceError(f"{label} is not valid base64") from exc
    if len(decoded) < minimum:
        raise EvidenceError(f"{label} is unexpectedly short")
    return decoded


def validate_verification(document: Any, *, reference: str, digest: str) -> int:
    if not isinstance(document, list) or not 1 <= len(document) <= MAX_SIGNATURES:
        raise EvidenceError("Cosign verification must return one to eight signatures")
    expected_critical = {
        "identity": {"docker-reference": reference},
        "image": {"docker-manifest-digest": digest},
        "type": EXPECTED_PREDICATE_TYPE,
    }
    for index, item in enumerate(document):
        if not isinstance(item, dict) or set(item) not in (
            {"critical"},
            {"critical", "optional"},
        ):
            raise EvidenceError(f"verification item {index} has unexpected members")
        if item.get("critical") != expected_critical:
            raise EvidenceError(f"verification item {index} is for a different subject")
        if "optional" in item and not isinstance(item["optional"], (dict, type(None))):
            raise EvidenceError(f"verification item {index} has invalid optional claims")
    return len(document)


def validate_bundle(document: Any, *, digest: str) -> None:
    bundle = _exact_dict(
        document,
        {"mediaType", "verificationMaterial", "dsseEnvelope"},
        label="Sigstore bundle",
    )
    if bundle["mediaType"] != EXPECTED_BUNDLE_MEDIA_TYPE:
        raise EvidenceError("unexpected Sigstore bundle media type")

    material = _exact_dict(
        bundle["verificationMaterial"],
        {"certificate", "tlogEntries", "timestampVerificationData"},
        label="verification material",
    )
    certificate = _exact_dict(material["certificate"], {"rawBytes"}, label="certificate")
    _decode_base64(certificate["rawBytes"], label="certificate", minimum=512)
    if not isinstance(material["tlogEntries"], list) or len(material["tlogEntries"]) != 1:
        raise EvidenceError("bundle must retain exactly one transparency-log entry")
    timestamps = _exact_dict(
        material["timestampVerificationData"],
        {"rfc3161Timestamps"},
        label="timestamp verification data",
    )["rfc3161Timestamps"]
    if not isinstance(timestamps, list) or len(timestamps) != 1:
        raise EvidenceError("bundle must retain exactly one RFC3161 timestamp")
    timestamp = _exact_dict(timestamps[0], {"signedTimestamp"}, label="RFC3161 timestamp")
    _decode_base64(timestamp["signedTimestamp"], label="RFC3161 timestamp", minimum=128)

    envelope = _exact_dict(
        bundle["dsseEnvelope"],
        {"payload", "payloadType", "signatures"},
        label="DSSE envelope",
    )
    if envelope["payloadType"] != EXPECTED_PAYLOAD_TYPE:
        raise EvidenceError("unexpected DSSE payload type")
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise EvidenceError("bundle must retain exactly one DSSE signature")
    signature = _exact_dict(signatures[0], {"sig"}, label="DSSE signature")
    _decode_base64(signature["sig"], label="DSSE signature", minimum=32)

    encoded_payload = _decode_base64(envelope["payload"], label="DSSE payload", minimum=32)
    try:
        statement = json.loads(encoded_payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"DSSE payload is not JSON: {exc}") from exc
    expected_statement = {
        "_type": EXPECTED_STATEMENT_TYPE,
        "subject": [
            {
                "digest": {"sha256": digest.removeprefix("sha256:")},
                "annotations": {},
            }
        ],
        "predicateType": EXPECTED_PREDICATE_TYPE,
        "predicate": {},
    }
    if statement != expected_statement:
        raise EvidenceError("local Sigstore bundle is for a different image subject")


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verification", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--digest", required=True)
    parsed = parser.parse_args(arguments)

    try:
        if not REPOSITORY_RE.fullmatch(parsed.repository):
            raise EvidenceError("repository is not a canonical lowercase OCI repository")
        if not DIGEST_RE.fullmatch(parsed.digest):
            raise EvidenceError("digest must be canonical sha256")
        reference = f"{parsed.repository}@{parsed.digest}"
        verification, verification_payload = _load_private_json(
            parsed.verification, label="Cosign verification output"
        )
        bundle, bundle_payload = _load_private_json(parsed.bundle, label="Sigstore bundle")
        signature_count = validate_verification(
            verification, reference=reference, digest=parsed.digest
        )
        validate_bundle(bundle, digest=parsed.digest)
        summary = {
            "bundle_sha256": hashlib.sha256(bundle_payload).hexdigest(),
            "digest": parsed.digest,
            "reference": reference,
            "signature_count": signature_count,
            "verification_sha256": hashlib.sha256(verification_payload).hexdigest(),
        }
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return 0
    except EvidenceError as exc:
        print(f"Cosign verification evidence rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
