"""BSE1 chunked AES-256-GCM-SIV backup artifact envelopes.

The format is deliberately small and rigid:

* a fixed preamble and canonical JSON header;
* independently authenticated, ordered data records; and
* one mandatory authenticated terminal record.

The terminal record and exact end-of-file check turn truncation, duplication,
reordering, and appended bytes into hard failures.  Decryption always targets a
private temporary file and publishes it atomically only after every check has
passed.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import struct
import tempfile
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from .context import ArtifactContext
from .errors import (
    ArtifactConfigurationError,
    ArtifactContextMismatchError,
    ArtifactDestinationExistsError,
    ArtifactFormatError,
    ArtifactIntegrityError,
    ArtifactSourceChangedError,
    ArtifactTruncatedError,
    UnsupportedArtifactFormatError,
)
from .providers.base import KeyProvider, WrappedDataKey, zeroize
from .providers.registry import ensure_provider_allowed

MAGIC = b"BSE1"
FORMAT_VERSION = 1
ALGORITHM = "AES-256-GCM-SIV"
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
MIN_CHUNK_SIZE = 64 * 1024
MAX_CHUNK_SIZE = 64 * 1024 * 1024
MAX_HEADER_SIZE = 64 * 1024
MAX_PLAINTEXT_SIZE = (1 << 64) - 1

_PREAMBLE = struct.Struct(">4sBBHI")
_RECORD = struct.Struct(">BQI")
_DATA_RECORD = 1
_FINAL_RECORD = 255
_TAG_SIZE = 16
_NONCE_PREFIX_SIZE = 4
_AAD_DOMAIN = b"BackupSheep/BSE1/record\x00"
_HEADER_FIELDS = frozenset(
    {
        "algorithm",
        "chunk_count",
        "chunk_size",
        "context_sha256",
        "envelope_id",
        "nonce_prefix",
        "plaintext_sha256",
        "plaintext_size",
        "version",
    }
)


@dataclass(frozen=True, slots=True)
class EnvelopeExpectation:
    envelope_id: uuid.UUID
    header_sha256: str
    plaintext_size: int
    plaintext_sha256: str


@dataclass(frozen=True, slots=True)
class EnvelopeDescriptor:
    envelope_id: uuid.UUID
    version: int
    algorithm: str
    chunk_size: int
    chunk_count: int
    plaintext_size: int
    plaintext_sha256: str
    context_sha256: str
    header_sha256: str
    header_size: int
    nonce_prefix: bytes
    ciphertext_size: int

    def expectation(self) -> EnvelopeExpectation:
        return EnvelopeExpectation(
            envelope_id=self.envelope_id,
            header_sha256=self.header_sha256,
            plaintext_size=self.plaintext_size,
            plaintext_sha256=self.plaintext_sha256,
        )


@dataclass(frozen=True, slots=True)
class SealedArtifact:
    envelope: EnvelopeDescriptor
    wrapped_data_key: WrappedDataKey


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _sha256_hex(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        return bytes.fromhex(value).hex() == value
    except ValueError:
        return False


def _read_exact(source: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = source.read(remaining)
        if not chunk:
            raise ArtifactTruncatedError(
                "The encrypted artifact ended before its terminal record."
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _open_regular_source(path: str | os.PathLike[str], *, encrypted: bool) -> BinaryIO:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            failure = ArtifactFormatError if encrypted else ArtifactConfigurationError
            raise failure("Artifact source symbolic links are not allowed.") from None
        raise
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            failure = ArtifactFormatError if encrypted else ArtifactConfigurationError
            raise failure("The artifact source must be a regular file.")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def _write_all(destination: BinaryIO, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = destination.write(view)
        if written is None or written <= 0:
            raise OSError("The artifact output could not be written.")
        view = view[written:]


def _new_cipher(data_key: bytes | bytearray) -> AESGCMSIV:
    if not isinstance(data_key, (bytes, bytearray)) or len(data_key) != 32:
        raise ArtifactConfigurationError(
            "A BSE1 artifact data key must be exactly 32 bytes."
        )
    try:
        return AESGCMSIV(bytes(data_key))
    except UnsupportedAlgorithm:
        raise ArtifactConfigurationError(
            "AES-256-GCM-SIV is unavailable in this cryptographic runtime."
        ) from None


def _validate_chunk_size(chunk_size: object) -> int:
    if (
        type(chunk_size) is not int
        or not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE
    ):
        raise ArtifactConfigurationError(
            "BSE1 chunk size must be between 64 KiB and 64 MiB."
        )
    return chunk_size


def _nonce(prefix: bytes, index: int) -> bytes:
    if len(prefix) != _NONCE_PREFIX_SIZE or not 0 <= index <= MAX_PLAINTEXT_SIZE:
        raise ArtifactFormatError("The BSE1 record nonce is invalid.")
    return prefix + index.to_bytes(8, "big")


def _aad(header_sha256: bytes, record_type: int, index: int, length: int) -> bytes:
    return _AAD_DOMAIN + header_sha256 + _RECORD.pack(record_type, index, length)


def _source_digest(source: BinaryIO) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_PLAINTEXT_SIZE:
            raise ArtifactConfigurationError(
                "The source artifact exceeds the BSE1 size limit."
            )
        digest.update(chunk)
    return size, digest.hexdigest()


def _header_bytes(
    *,
    envelope_id: uuid.UUID,
    chunk_size: int,
    plaintext_size: int,
    plaintext_sha256: str,
    context: ArtifactContext,
    nonce_prefix: bytes,
) -> bytes:
    chunk_count = (plaintext_size + chunk_size - 1) // chunk_size
    return _canonical_json(
        {
            "algorithm": ALGORITHM,
            "chunk_count": chunk_count,
            "chunk_size": chunk_size,
            "context_sha256": context.sha256,
            "envelope_id": str(envelope_id),
            "nonce_prefix": nonce_prefix.hex(),
            "plaintext_sha256": plaintext_sha256,
            "plaintext_size": plaintext_size,
            "version": FORMAT_VERSION,
        }
    )


def _parse_header(header_bytes: bytes, *, ciphertext_size: int) -> EnvelopeDescriptor:
    if not 1 <= len(header_bytes) <= MAX_HEADER_SIZE:
        raise ArtifactFormatError("The BSE1 header length is invalid.")
    try:
        header = json.loads(
            header_bytes.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON value")
            ),
        )
    except (UnicodeDecodeError, ValueError, TypeError):
        raise ArtifactFormatError(
            "The BSE1 header is not valid canonical JSON."
        ) from None
    if not isinstance(header, dict) or set(header) != _HEADER_FIELDS:
        raise ArtifactFormatError("The BSE1 header fields are invalid.")
    if _canonical_json(header) != header_bytes:
        raise ArtifactFormatError("The BSE1 header is not canonical.")

    version = header["version"]
    algorithm = header["algorithm"]
    if type(version) is not int or version != FORMAT_VERSION:
        raise UnsupportedArtifactFormatError(
            "The encrypted artifact version is not supported."
        )
    if not isinstance(algorithm, str) or algorithm != ALGORITHM:
        raise UnsupportedArtifactFormatError(
            "The encrypted artifact algorithm is not supported."
        )

    chunk_size = header["chunk_size"]
    if (
        type(chunk_size) is not int
        or not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE
    ):
        raise ArtifactFormatError("The BSE1 header chunk size is invalid.")
    plaintext_size = header["plaintext_size"]
    chunk_count = header["chunk_count"]
    if (
        type(plaintext_size) is not int
        or not 0 <= plaintext_size <= MAX_PLAINTEXT_SIZE
        or type(chunk_count) is not int
        or chunk_count != (plaintext_size + chunk_size - 1) // chunk_size
    ):
        raise ArtifactFormatError("The BSE1 header size or chunk count is invalid.")
    if not _sha256_hex(header["plaintext_sha256"]) or not _sha256_hex(
        header["context_sha256"]
    ):
        raise ArtifactFormatError("The BSE1 header digest is invalid.")
    nonce_prefix_hex = header["nonce_prefix"]
    if not isinstance(nonce_prefix_hex, str) or len(nonce_prefix_hex) != 8:
        raise ArtifactFormatError("The BSE1 nonce prefix is invalid.")
    try:
        nonce_prefix = bytes.fromhex(nonce_prefix_hex)
    except ValueError:
        raise ArtifactFormatError("The BSE1 nonce prefix is invalid.") from None
    if nonce_prefix.hex() != nonce_prefix_hex:
        raise ArtifactFormatError("The BSE1 nonce prefix is invalid.")
    envelope_id_value = header["envelope_id"]
    try:
        envelope_id = uuid.UUID(str(envelope_id_value))
    except (AttributeError, TypeError, ValueError):
        raise ArtifactFormatError("The BSE1 envelope identifier is invalid.") from None
    if str(envelope_id) != envelope_id_value:
        raise ArtifactFormatError("The BSE1 envelope identifier is invalid.")

    return EnvelopeDescriptor(
        envelope_id=envelope_id,
        version=version,
        algorithm=algorithm,
        chunk_size=chunk_size,
        chunk_count=chunk_count,
        plaintext_size=plaintext_size,
        plaintext_sha256=header["plaintext_sha256"],
        context_sha256=header["context_sha256"],
        header_sha256=hashlib.sha256(header_bytes).hexdigest(),
        header_size=len(header_bytes),
        nonce_prefix=nonce_prefix,
        ciphertext_size=ciphertext_size,
    )


def _read_header(source: BinaryIO, *, ciphertext_size: int) -> EnvelopeDescriptor:
    magic, preamble_version, flags, reserved, header_size = _PREAMBLE.unpack(
        _read_exact(source, _PREAMBLE.size)
    )
    if magic != MAGIC:
        raise UnsupportedArtifactFormatError("The artifact is not a BSE1 envelope.")
    if preamble_version != FORMAT_VERSION:
        raise UnsupportedArtifactFormatError(
            "The encrypted artifact version is not supported."
        )
    if flags != 0 or reserved != 0:
        raise ArtifactFormatError("The BSE1 preamble flags are invalid.")
    if not 1 <= header_size <= MAX_HEADER_SIZE:
        raise ArtifactFormatError("The BSE1 header length is invalid.")
    descriptor = _parse_header(
        _read_exact(source, header_size), ciphertext_size=ciphertext_size
    )
    if descriptor.version != preamble_version:
        raise ArtifactFormatError("The BSE1 version fields do not match.")
    expected_size = (
        _PREAMBLE.size
        + header_size
        + descriptor.plaintext_size
        + (descriptor.chunk_count * (_RECORD.size + _TAG_SIZE))
        + _RECORD.size
        + _TAG_SIZE
    )
    if ciphertext_size < expected_size:
        raise ArtifactTruncatedError(
            "The encrypted artifact ended before its terminal record."
        )
    if ciphertext_size > expected_size:
        raise ArtifactIntegrityError(
            "The encrypted artifact has unauthenticated trailing data."
        )
    return descriptor


def read_envelope_header(path: str | os.PathLike[str]) -> EnvelopeDescriptor:
    """Parse and structurally validate a header without claiming authenticity."""

    with _open_regular_source(path, encrypted=True) as source:
        source_stat = os.fstat(source.fileno())
        return _read_header(source, ciphertext_size=source_stat.st_size)


def _staging_file(destination: Path) -> tuple[int, Path]:
    destination.parent.mkdir(parents=False, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".bse-tmp", dir=destination.parent
    )
    os.fchmod(fd, 0o600)
    return fd, Path(temporary_name)


def _publish(temporary: Path, destination: Path, *, overwrite: bool) -> None:
    if overwrite:
        os.replace(temporary, destination)
    else:
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError:
            raise ArtifactDestinationExistsError(
                "The artifact destination already exists."
            ) from None
        os.unlink(temporary)
    directory_fd = os.open(
        destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _check_destination(destination: Path, *, overwrite: bool) -> None:
    if not overwrite and destination.exists():
        raise ArtifactDestinationExistsError("The artifact destination already exists.")


def _verify_expectation(
    descriptor: EnvelopeDescriptor, expected: EnvelopeExpectation | None
) -> None:
    if expected is None:
        return
    if (
        descriptor.envelope_id != expected.envelope_id
        or descriptor.header_sha256 != expected.header_sha256
        or descriptor.plaintext_size != expected.plaintext_size
        or descriptor.plaintext_sha256 != expected.plaintext_sha256
    ):
        raise ArtifactIntegrityError(
            "The encrypted artifact does not match its durable envelope record."
        )


def encrypt_file(
    source_path: str | os.PathLike[str],
    destination_path: str | os.PathLike[str],
    *,
    data_key: bytes | bytearray,
    context: ArtifactContext,
    envelope_id: uuid.UUID | str | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overwrite: bool = False,
) -> EnvelopeDescriptor:
    """Seal one regular file and atomically publish a BSE1 artifact."""

    chunk_size = _validate_chunk_size(chunk_size)
    cipher = _new_cipher(data_key)
    try:
        envelope_uuid = uuid.UUID(str(envelope_id)) if envelope_id else uuid.uuid4()
    except (AttributeError, TypeError, ValueError):
        raise ArtifactConfigurationError(
            "The BSE1 envelope identifier is invalid."
        ) from None
    destination = Path(destination_path)
    _check_destination(destination, overwrite=overwrite)

    temporary: Path | None = None
    try:
        with _open_regular_source(source_path, encrypted=False) as source:
            plaintext_size, plaintext_sha256 = _source_digest(source)
            source.seek(0)
            nonce_prefix = os.urandom(_NONCE_PREFIX_SIZE)
            header = _header_bytes(
                envelope_id=envelope_uuid,
                chunk_size=chunk_size,
                plaintext_size=plaintext_size,
                plaintext_sha256=plaintext_sha256,
                context=context,
                nonce_prefix=nonce_prefix,
            )
            header_digest = hashlib.sha256(header).digest()
            descriptor = _parse_header(header, ciphertext_size=0)

            fd, temporary = _staging_file(destination)
            with os.fdopen(fd, "wb") as output:
                _write_all(
                    output,
                    _PREAMBLE.pack(MAGIC, FORMAT_VERSION, 0, 0, len(header)),
                )
                _write_all(output, header)
                second_digest = hashlib.sha256()
                second_size = 0
                for index in range(descriptor.chunk_count):
                    expected_length = min(
                        chunk_size, plaintext_size - (index * chunk_size)
                    )
                    plaintext = source.read(expected_length)
                    if len(plaintext) != expected_length:
                        raise ArtifactSourceChangedError(
                            "The source artifact changed while it was being sealed."
                        )
                    second_digest.update(plaintext)
                    second_size += len(plaintext)
                    record_header = _RECORD.pack(_DATA_RECORD, index, len(plaintext))
                    ciphertext = cipher.encrypt(
                        _nonce(nonce_prefix, index),
                        plaintext,
                        _aad(header_digest, _DATA_RECORD, index, len(plaintext)),
                    )
                    _write_all(output, record_header)
                    _write_all(output, ciphertext)
                if source.read(1):
                    raise ArtifactSourceChangedError(
                        "The source artifact changed while it was being sealed."
                    )
                if (
                    second_size != plaintext_size
                    or second_digest.hexdigest() != plaintext_sha256
                ):
                    raise ArtifactSourceChangedError(
                        "The source artifact changed while it was being sealed."
                    )
                terminal_header = _RECORD.pack(_FINAL_RECORD, descriptor.chunk_count, 0)
                terminal = cipher.encrypt(
                    _nonce(nonce_prefix, descriptor.chunk_count),
                    b"",
                    _aad(
                        header_digest,
                        _FINAL_RECORD,
                        descriptor.chunk_count,
                        0,
                    ),
                )
                _write_all(output, terminal_header)
                _write_all(output, terminal)
                output.flush()
                os.fsync(output.fileno())
            ciphertext_size = temporary.stat().st_size
            _publish(temporary, destination, overwrite=overwrite)
            temporary = None
            return replace(descriptor, ciphertext_size=ciphertext_size)
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def decrypt_file(
    source_path: str | os.PathLike[str],
    destination_path: str | os.PathLike[str],
    *,
    data_key: bytes | bytearray,
    context: ArtifactContext,
    expected: EnvelopeExpectation | None = None,
    overwrite: bool = False,
) -> EnvelopeDescriptor:
    """Authenticate, decrypt, and atomically publish one BSE1 artifact."""

    cipher = _new_cipher(data_key)
    destination = Path(destination_path)
    _check_destination(destination, overwrite=overwrite)
    temporary: Path | None = None
    try:
        with _open_regular_source(source_path, encrypted=True) as source:
            source_stat = os.fstat(source.fileno())
            descriptor = _read_header(source, ciphertext_size=source_stat.st_size)
            _verify_expectation(descriptor, expected)
            if descriptor.context_sha256 != context.sha256:
                raise ArtifactContextMismatchError(
                    "The encrypted artifact context does not match this backup."
                )
            header_digest = bytes.fromhex(descriptor.header_sha256)

            fd, temporary = _staging_file(destination)
            digest = hashlib.sha256()
            plaintext_size = 0
            with os.fdopen(fd, "wb") as output:
                for expected_index in range(descriptor.chunk_count):
                    record_type, index, length = _RECORD.unpack(
                        _read_exact(source, _RECORD.size)
                    )
                    expected_length = min(
                        descriptor.chunk_size,
                        descriptor.plaintext_size
                        - (expected_index * descriptor.chunk_size),
                    )
                    if (
                        record_type != _DATA_RECORD
                        or index != expected_index
                        or length != expected_length
                    ):
                        raise ArtifactIntegrityError(
                            "The encrypted artifact record sequence is invalid."
                        )
                    ciphertext = _read_exact(source, length + _TAG_SIZE)
                    try:
                        plaintext = cipher.decrypt(
                            _nonce(descriptor.nonce_prefix, index),
                            ciphertext,
                            _aad(
                                header_digest,
                                _DATA_RECORD,
                                index,
                                length,
                            ),
                        )
                    except InvalidTag:
                        raise ArtifactIntegrityError(
                            "The encrypted artifact failed authentication."
                        ) from None
                    if len(plaintext) != length:
                        raise ArtifactIntegrityError(
                            "The encrypted artifact plaintext length is invalid."
                        )
                    _write_all(output, plaintext)
                    digest.update(plaintext)
                    plaintext_size += len(plaintext)

                record_type, index, length = _RECORD.unpack(
                    _read_exact(source, _RECORD.size)
                )
                if (
                    record_type != _FINAL_RECORD
                    or index != descriptor.chunk_count
                    or length != 0
                ):
                    raise ArtifactIntegrityError(
                        "The encrypted artifact terminal record is invalid."
                    )
                terminal = _read_exact(source, _TAG_SIZE)
                try:
                    terminal_plaintext = cipher.decrypt(
                        _nonce(descriptor.nonce_prefix, descriptor.chunk_count),
                        terminal,
                        _aad(
                            header_digest,
                            _FINAL_RECORD,
                            descriptor.chunk_count,
                            0,
                        ),
                    )
                except InvalidTag:
                    raise ArtifactIntegrityError(
                        "The encrypted artifact terminal record failed authentication."
                    ) from None
                if terminal_plaintext or source.read(1):
                    raise ArtifactIntegrityError(
                        "The encrypted artifact has unauthenticated trailing data."
                    )
                if (
                    plaintext_size != descriptor.plaintext_size
                    or digest.hexdigest() != descriptor.plaintext_sha256
                ):
                    raise ArtifactIntegrityError(
                        "The encrypted artifact plaintext digest is invalid."
                    )
                output.flush()
                os.fsync(output.fileno())
            _publish(temporary, destination, overwrite=overwrite)
            temporary = None
            return descriptor
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def seal_file(
    source_path: str | os.PathLike[str],
    destination_path: str | os.PathLike[str],
    *,
    provider: KeyProvider,
    context: ArtifactContext,
    enterprise_mode: bool = False,
    envelope_id: uuid.UUID | str | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overwrite: bool = False,
) -> SealedArtifact:
    """Generate a data key, seal the file, and return durable wrap metadata."""

    ensure_provider_allowed(provider, enterprise_mode=enterprise_mode)
    generated = provider.generate_data_key(context)
    try:
        descriptor = encrypt_file(
            source_path,
            destination_path,
            data_key=generated.plaintext,
            context=context,
            envelope_id=envelope_id,
            chunk_size=chunk_size,
            overwrite=overwrite,
        )
        return SealedArtifact(descriptor, generated.wrapped)
    finally:
        generated.destroy()


def unseal_file(
    source_path: str | os.PathLike[str],
    destination_path: str | os.PathLike[str],
    *,
    provider: KeyProvider,
    wrapped_data_key: WrappedDataKey,
    context: ArtifactContext,
    expected: EnvelopeExpectation | None = None,
    enterprise_mode: bool = False,
    overwrite: bool = False,
) -> EnvelopeDescriptor:
    """Unwrap a data key and authenticate/decrypt one artifact."""

    ensure_provider_allowed(provider, enterprise_mode=enterprise_mode)
    if wrapped_data_key.provider_name != provider.name:
        raise ArtifactConfigurationError(
            "The wrapped data key provider does not match the selected provider."
        )
    plaintext_key = provider.unwrap_data_key(wrapped_data_key, context)
    try:
        return decrypt_file(
            source_path,
            destination_path,
            data_key=plaintext_key,
            context=context,
            expected=expected,
            overwrite=overwrite,
        )
    finally:
        zeroize(plaintext_key)
