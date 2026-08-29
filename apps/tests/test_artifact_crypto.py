"""Focused security tests for BSE1 artifact envelopes and key providers."""

import hashlib
import json
import os
import stat
import struct
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from backupsheep.artifact_crypto import (
    ArtifactContext,
    EnvelopeExpectation,
    KeyProviderRegistry,
    LocalDevelopmentKeyProvider,
    LocalFileKeyProvider,
    WrappedDataKey,
    decrypt_file,
    encrypt_file,
    read_envelope_header,
    seal_file,
    unseal_file,
)
from backupsheep.artifact_crypto import envelope as envelope_module
from backupsheep.artifact_crypto.providers import local_file as local_file_module
from backupsheep.artifact_crypto.errors import (
    ArtifactConfigurationError,
    ArtifactContextMismatchError,
    ArtifactDestinationExistsError,
    ArtifactFormatError,
    ArtifactIntegrityError,
    ArtifactSourceChangedError,
    ArtifactTruncatedError,
    KeyProviderConfigurationError,
    KeyProviderIntegrityError,
    KeyProviderNotFoundError,
    UnsupportedArtifactFormatError,
)
from backupsheep.artifact_crypto.providers.base import GeneratedDataKey
from backupsheep.artifact_crypto.providers.local_file import canonical_keyring_bytes

CHUNK_SIZE = 64 * 1024
DATA_KEY = bytes(range(32))
ENVELOPE_ID = uuid.UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
LOCAL_KEY_V1 = "lfk-11111111111111111111111111111111"
LOCAL_KEY_V2 = "lfk-22222222222222222222222222222222"
INSTALLATION_ID = "a" * 64


def artifact_context(**overrides):
    values = {
        "installation_id": "a" * 64,
        "account_id": "account-17",
        "node_id": "node-29",
        "backup_id": "11111111-2222-4333-8444-555555555555",
        "backup_model": "apps.coredatabasebackup",
        "lane": "database",
    }
    values.update(overrides)
    return ArtifactContext(**values)


class ArtifactEnvelopeTests(SimpleTestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.context = artifact_context()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _source(self, payload, name="source.zip"):
        path = self.root / name
        path.write_bytes(payload)
        return path

    def _seal(self, payload, name="artifact.bse"):
        source = self._source(payload)
        destination = self.root / name
        descriptor = encrypt_file(
            source,
            destination,
            data_key=DATA_KEY,
            context=self.context,
            envelope_id=ENVELOPE_ID,
            chunk_size=CHUNK_SIZE,
        )
        return source, destination, descriptor

    def _decrypt_failure(self, source, error=ArtifactIntegrityError, **kwargs):
        destination = self.root / f"failed-{uuid.uuid4().hex}.zip"
        with self.assertRaises(error):
            decrypt_file(
                source,
                destination,
                data_key=kwargs.pop("data_key", DATA_KEY),
                context=kwargs.pop("context", self.context),
                **kwargs,
            )
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(f".{destination.name}.*.bse-tmp")), [])

    def test_round_trip_boundaries_and_private_permissions(self):
        sizes = [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 2 * CHUNK_SIZE + 17]
        for position, size in enumerate(sizes):
            with self.subTest(size=size):
                payload = bytes((index % 251 for index in range(size)))
                source = self._source(payload, f"source-{position}.zip")
                encrypted = self.root / f"encrypted-{position}.bse"
                restored = self.root / f"restored-{position}.zip"
                descriptor = encrypt_file(
                    source,
                    encrypted,
                    data_key=DATA_KEY,
                    context=self.context,
                    chunk_size=CHUNK_SIZE,
                )
                result = decrypt_file(
                    encrypted,
                    restored,
                    data_key=DATA_KEY,
                    context=self.context,
                    expected=descriptor.expectation(),
                )
                self.assertEqual(restored.read_bytes(), payload)
                self.assertEqual(result, descriptor)
                self.assertEqual(
                    descriptor.chunk_count, (size + CHUNK_SIZE - 1) // CHUNK_SIZE
                )
                self.assertEqual(os.stat(encrypted).st_mode & 0o777, 0o600)
                self.assertEqual(os.stat(restored).st_mode & 0o777, 0o600)

    def test_public_header_exposes_no_private_digest_or_backup_identity(self):
        payload = b"backup" * 1000
        _source, encrypted, descriptor = self._seal(payload)

        parsed = read_envelope_header(encrypted)
        raw = encrypted.read_bytes()
        preamble = raw[: envelope_module._PREAMBLE.size]
        _magic, _version, _flags, _reserved, header_size = (
            envelope_module._PREAMBLE.unpack(preamble)
        )
        header = json.loads(
            raw[
                envelope_module._PREAMBLE.size :
                envelope_module._PREAMBLE.size + header_size
            ]
        )

        self.assertEqual(parsed.envelope_id, ENVELOPE_ID)
        self.assertEqual(parsed.header_sha256, descriptor.header_sha256)
        self.assertFalse(hasattr(parsed, "plaintext_sha256"))
        self.assertFalse(hasattr(parsed, "context_sha256"))
        self.assertNotIn("plaintext_sha256", header)
        self.assertNotIn("context_sha256", header)
        self.assertNotIn(hashlib.sha256(payload).hexdigest().encode("ascii"), raw)
        self.assertNotIn(self.context.sha256.encode("ascii"), raw)
        self.assertNotIn(self.context.backup_id.encode("ascii"), raw)

    def test_equal_plaintexts_have_no_stable_public_equality_witness(self):
        payload = b"the same private backup" * 100
        first_source = self._source(payload, "equal-first.zip")
        second_source = self._source(payload, "equal-second.zip")
        first_path = self.root / "equal-first.bse1"
        second_path = self.root / "equal-second.bse1"

        first = encrypt_file(
            first_source,
            first_path,
            data_key=DATA_KEY,
            context=self.context,
            chunk_size=CHUNK_SIZE,
        )
        second = encrypt_file(
            second_source,
            second_path,
            data_key=DATA_KEY,
            context=self.context,
            chunk_size=CHUNK_SIZE,
        )

        first_public = read_envelope_header(first_path)
        second_public = read_envelope_header(second_path)
        self.assertEqual(first.plaintext_sha256, second.plaintext_sha256)
        self.assertNotEqual(first_public.envelope_id, second_public.envelope_id)
        self.assertNotEqual(first_public.nonce_prefix, second_public.nonce_prefix)
        self.assertNotEqual(first_public.header_sha256, second_public.header_sha256)
        self.assertNotEqual(
            hashlib.sha256(first_path.read_bytes()).digest(),
            hashlib.sha256(second_path.read_bytes()).digest(),
        )
        self.assertFalse(hasattr(first_public, "plaintext_sha256"))
        self.assertFalse(hasattr(second_public, "plaintext_sha256"))

    def test_normative_bse1_v2_vector_is_byte_for_byte_deterministic(self):
        vector_path = Path(__file__).with_name("fixtures") / "bse1-v2-vector.json"
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
        context = ArtifactContext.from_mapping(vector["context"])
        plaintext = bytes.fromhex(vector["plaintext_hex"])
        source = self._source(plaintext, "vector-source.zip")
        encrypted = self.root / "vector-generated.bse1"

        with mock.patch.object(
            envelope_module.os,
            "urandom",
            return_value=bytes.fromhex(vector["nonce_prefix_hex"]),
        ):
            descriptor = encrypt_file(
                source,
                encrypted,
                data_key=bytes.fromhex(vector["data_key_hex"]),
                context=context,
                envelope_id=vector["envelope_id"],
                chunk_size=vector["chunk_size"],
                trusted_source_root=self.root,
                trusted_destination_root=self.root,
            )

        self.assertEqual(encrypted.read_bytes(), bytes.fromhex(vector["envelope_hex"]))
        self.assertEqual(descriptor.header_sha256, vector["header_sha256"])
        self.assertEqual(descriptor.context_sha256, vector["context_sha256"])
        self.assertEqual(descriptor.plaintext_sha256, vector["plaintext_sha256"])
        self.assertEqual(descriptor.ciphertext_size, vector["ciphertext_size"])

        frozen = self.root / "vector-frozen.bse1"
        restored = self.root / "vector-restored.zip"
        frozen.write_bytes(bytes.fromhex(vector["envelope_hex"]))
        parsed = read_envelope_header(frozen, trusted_source_root=self.root)
        header_start = envelope_module._PREAMBLE.size
        self.assertEqual(
            frozen.read_bytes()[
                header_start : header_start + parsed.header_size
            ].decode("ascii"),
            vector["header_canonical_json"],
        )
        decrypt_file(
            frozen,
            restored,
            data_key=bytes.fromhex(vector["data_key_hex"]),
            context=context,
            expected=descriptor.expectation(),
            trusted_source_root=self.root,
            trusted_destination_root=self.root,
        )
        self.assertEqual(restored.read_bytes(), plaintext)

    def test_wrong_key_context_and_ledger_expectation_fail_without_plaintext(self):
        _source, encrypted, descriptor = self._seal(b"sensitive backup bytes")
        self._decrypt_failure(encrypted, data_key=b"x" * 32)
        self._decrypt_failure(
            encrypted,
            error=ArtifactContextMismatchError,
            context=artifact_context(node_id="different-node"),
        )
        mismatched = EnvelopeExpectation(
            envelope_id=uuid.uuid4(),
            header_sha256=descriptor.header_sha256,
            plaintext_size=descriptor.plaintext_size,
            plaintext_sha256=descriptor.plaintext_sha256,
        )
        self._decrypt_failure(encrypted, expected=mismatched)
        private_mismatch = EnvelopeExpectation(
            envelope_id=descriptor.envelope_id,
            header_sha256=descriptor.header_sha256,
            plaintext_size=descriptor.plaintext_size,
            plaintext_sha256="0" * 64,
        )
        self._decrypt_failure(encrypted, expected=private_mismatch)

    def test_header_and_ciphertext_tampering_fail_closed(self):
        _source, encrypted, _descriptor = self._seal(b"A" * (CHUNK_SIZE + 71))
        original = bytearray(encrypted.read_bytes())
        _magic, _version, _flags, _reserved, header_size = struct.unpack(
            ">4sBBHI", original[:12]
        )
        header_start = 12
        header_end = header_start + header_size

        header_tampered = bytearray(original)
        nonce_marker = header_tampered.find(
            b'"nonce_prefix":"', header_start, header_end
        )
        nonce_offset = nonce_marker + len(b'"nonce_prefix":"')
        header_tampered[nonce_offset] = (
            ord("0") if header_tampered[nonce_offset] != ord("0") else ord("1")
        )
        header_path = self.root / "header-tampered.bse"
        header_path.write_bytes(header_tampered)
        self._decrypt_failure(header_path)

        ciphertext_tampered = bytearray(original)
        ciphertext_tampered[header_end + 13 + 7] ^= 0x80
        ciphertext_path = self.root / "ciphertext-tampered.bse"
        ciphertext_path.write_bytes(ciphertext_tampered)
        self._decrypt_failure(ciphertext_path)

        terminal_tampered = bytearray(original)
        terminal_tampered[-1] ^= 0x01
        terminal_path = self.root / "terminal-tampered.bse"
        terminal_path.write_bytes(terminal_tampered)
        self._decrypt_failure(terminal_path)

    def test_swapped_authenticated_terminal_never_publishes_plaintext(self):
        first_source, first_path, _first = self._seal(
            b"first terminal payload", "terminal-first.bse1"
        )
        second_context = artifact_context(
            backup_id="66666666-7777-4888-8999-aaaaaaaaaaaa"
        )
        second_source = self._source(
            b"second terminal data!", "terminal-second.zip"
        )
        second_path = self.root / "terminal-second.bse1"
        encrypt_file(
            second_source,
            second_path,
            data_key=DATA_KEY,
            context=second_context,
            chunk_size=CHUNK_SIZE,
        )
        terminal_size = (
            envelope_module._RECORD.size
            + envelope_module._TERMINAL_PAYLOAD.size
            + envelope_module._TAG_SIZE
        )
        swapped = self.root / "terminal-swapped.bse1"
        swapped.write_bytes(
            first_path.read_bytes()[:-terminal_size]
            + second_path.read_bytes()[-terminal_size:]
        )

        self._decrypt_failure(swapped)
        self.assertTrue(first_source.exists())

    def test_truncation_at_every_format_boundary_never_publishes_plaintext(self):
        _source, encrypted, _descriptor = self._seal(b"B" * (CHUNK_SIZE + 29))
        original = encrypted.read_bytes()
        _magic, _version, _flags, _reserved, header_size = struct.unpack(
            ">4sBBHI", original[:12]
        )
        header_end = 12 + header_size
        first_record_end = header_end + 13 + CHUNK_SIZE + 16
        terminal_size = (
            envelope_module._RECORD.size
            + envelope_module._TERMINAL_PAYLOAD.size
            + envelope_module._TAG_SIZE
        )
        cuts = {
            0,
            1,
            11,
            12,
            header_end - 1,
            header_end,
            first_record_end - 1,
            first_record_end,
            len(original) - terminal_size,
            len(original) - 1,
        }
        for position, cut in enumerate(sorted(cuts)):
            with self.subTest(cut=cut):
                truncated = self.root / f"truncated-{position}.bse"
                truncated.write_bytes(original[:cut])
                self._decrypt_failure(truncated, error=ArtifactTruncatedError)

    def test_reordered_duplicated_and_appended_records_are_rejected(self):
        _source, encrypted, _descriptor = self._seal(b"C" * (2 * CHUNK_SIZE + 23))
        original = encrypted.read_bytes()
        _magic, _version, _flags, _reserved, header_size = struct.unpack(
            ">4sBBHI", original[:12]
        )
        first_start = 12 + header_size
        record_size = 13 + CHUNK_SIZE + 16
        first = original[first_start : first_start + record_size]
        second = original[first_start + record_size : first_start + (2 * record_size)]
        remainder = original[first_start + (2 * record_size) :]

        reordered = self.root / "reordered.bse"
        reordered.write_bytes(original[:first_start] + second + first + remainder)
        self._decrypt_failure(reordered)

        duplicated = self.root / "duplicated.bse"
        duplicated.write_bytes(
            original[:first_start] + first + first + second + remainder
        )
        self._decrypt_failure(duplicated)

        appended = self.root / "appended.bse"
        appended.write_bytes(original + b"unauthenticated")
        self._decrypt_failure(appended)

    def test_invalid_record_index_length_and_terminal_type_are_rejected(self):
        _source, encrypted, _descriptor = self._seal(b"D" * (CHUNK_SIZE + 5))
        original = bytearray(encrypted.read_bytes())
        _magic, _version, _flags, _reserved, header_size = struct.unpack(
            ">4sBBHI", original[:12]
        )
        first_start = 12 + header_size

        wrong_index = bytearray(original)
        wrong_index[first_start + 8] = 1
        wrong_index_path = self.root / "wrong-index.bse"
        wrong_index_path.write_bytes(wrong_index)
        self._decrypt_failure(wrong_index_path)

        wrong_length = bytearray(original)
        wrong_length[first_start + 12] ^= 1
        wrong_length_path = self.root / "wrong-length.bse"
        wrong_length_path.write_bytes(wrong_length)
        self._decrypt_failure(wrong_length_path)

        terminal_start = len(original) - (
            envelope_module._RECORD.size
            + envelope_module._TERMINAL_PAYLOAD.size
            + envelope_module._TAG_SIZE
        )
        wrong_terminal = bytearray(original)
        wrong_terminal[terminal_start] = 1
        wrong_terminal_path = self.root / "wrong-terminal.bse"
        wrong_terminal_path.write_bytes(wrong_terminal)
        self._decrypt_failure(wrong_terminal_path)

    def test_unknown_version_algorithm_noncanonical_and_oversized_header_rejected(self):
        _source, encrypted, _descriptor = self._seal(b"format")
        original = bytearray(encrypted.read_bytes())
        _magic, _version, _flags, _reserved, header_size = struct.unpack(
            ">4sBBHI", original[:12]
        )
        header_end = 12 + header_size

        unknown_version = bytearray(original)
        unknown_version[4] = 1
        version_path = self.root / "rejected-v1.bse"
        version_path.write_bytes(unknown_version)
        self._decrypt_failure(version_path, error=UnsupportedArtifactFormatError)

        header = json.loads(original[12:header_end])
        header["algorithm"] = "AES-256-GCM"
        altered_header = json.dumps(
            header, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        algorithm_path = self.root / "unknown-algorithm.bse"
        algorithm_path.write_bytes(
            struct.pack(">4sBBHI", b"BSE1", 2, 0, 0, len(altered_header))
            + altered_header
            + original[header_end:]
        )
        self._decrypt_failure(algorithm_path, error=UnsupportedArtifactFormatError)

        noncanonical = b" " + bytes(original[12:header_end])
        noncanonical_path = self.root / "noncanonical.bse"
        noncanonical_path.write_bytes(
            struct.pack(">4sBBHI", b"BSE1", 2, 0, 0, len(noncanonical))
            + noncanonical
            + original[header_end:]
        )
        self._decrypt_failure(noncanonical_path, error=ArtifactFormatError)

        oversized_path = self.root / "oversized-header.bse"
        oversized_path.write_bytes(struct.pack(">4sBBHI", b"BSE1", 2, 0, 0, 65537))
        self._decrypt_failure(oversized_path, error=ArtifactFormatError)

    def test_frozen_bse1_v1_envelope_is_rejected(self):
        vector_path = Path(__file__).with_name("fixtures") / "bse1-v1-vector.json"
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
        legacy = self.root / "legacy-v1.bse1"
        legacy.write_bytes(bytes.fromhex(vector["envelope_hex"]))

        self._decrypt_failure(legacy, error=UnsupportedArtifactFormatError)

    def test_no_clobber_preserves_existing_destination(self):
        source = self._source(b"source")
        destination = self.root / "already-there.bse"
        destination.write_bytes(b"keep-me")

        with self.assertRaises(ArtifactDestinationExistsError):
            encrypt_file(
                source,
                destination,
                data_key=DATA_KEY,
                context=self.context,
                chunk_size=CHUNK_SIZE,
            )

        self.assertEqual(destination.read_bytes(), b"keep-me")

    def test_source_symbolic_links_are_rejected_for_seal_and_open(self):
        source = self._source(b"source")
        source_link = self.root / "source-link.zip"
        source_link.symlink_to(source)
        with self.assertRaises(ArtifactConfigurationError):
            encrypt_file(
                source_link,
                self.root / "link-output.bse",
                data_key=DATA_KEY,
                context=self.context,
                chunk_size=CHUNK_SIZE,
            )

        _source, encrypted, _descriptor = self._seal(b"encrypted")
        encrypted_link = self.root / "encrypted-link.bse"
        encrypted_link.symlink_to(encrypted)
        self._decrypt_failure(encrypted_link, error=ArtifactFormatError)

    def test_source_change_between_hash_and_encryption_aborts_and_cleans_staging(self):
        source = self._source(b"before" * 1000)
        destination = self.root / "changed.bse"
        original_digest = envelope_module._source_digest

        def digest_then_mutate(handle):
            result = original_digest(handle)
            source.write_bytes(b"after" * 1000)
            return result

        with mock.patch.object(
            envelope_module, "_source_digest", side_effect=digest_then_mutate
        ):
            with self.assertRaises(ArtifactSourceChangedError):
                encrypt_file(
                    source,
                    destination,
                    data_key=DATA_KEY,
                    context=self.context,
                    chunk_size=CHUNK_SIZE,
                )

        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".changed.bse.*.bse-tmp")), [])

    def test_invalid_key_chunk_size_and_context_are_rejected(self):
        source = self._source(b"value")
        with self.assertRaises(ArtifactConfigurationError):
            encrypt_file(
                source,
                self.root / "bad-key.bse",
                data_key=b"too-short",
                context=self.context,
                chunk_size=CHUNK_SIZE,
            )
        with self.assertRaises(ArtifactConfigurationError):
            encrypt_file(
                source,
                self.root / "bad-chunk.bse",
                data_key=DATA_KEY,
                context=self.context,
                chunk_size=1024,
            )
        with self.assertRaises(ArtifactConfigurationError):
            artifact_context(installation_id="A" * 64)
        with self.assertRaises(ArtifactConfigurationError):
            artifact_context(backup_id="not-a-uuid")
        with self.assertRaises(ArtifactConfigurationError):
            artifact_context(lane="shared")
        with self.assertRaises(ArtifactConfigurationError):
            encrypt_file(
                source,
                self.root / "backup-id-envelope.bse",
                data_key=DATA_KEY,
                context=self.context,
                envelope_id=self.context.backup_id,
                chunk_size=CHUNK_SIZE,
            )

    def test_trusted_roots_reject_ancestor_symlinks_and_path_escape(self):
        source_directory = self.root / "source-directory"
        source_directory.mkdir()
        source = source_directory / "source.zip"
        source.write_bytes(b"source")
        source_link = self.root / "source-link-directory"
        source_link.symlink_to(source_directory, target_is_directory=True)

        with self.assertRaises(ArtifactConfigurationError):
            encrypt_file(
                source_link / "source.zip",
                self.root / "ancestor-source.bse",
                data_key=DATA_KEY,
                context=self.context,
                chunk_size=CHUNK_SIZE,
                trusted_source_root=self.root,
                trusted_destination_root=self.root,
            )

        trusted_target = self.root / "trusted-target"
        trusted_target.mkdir()
        trusted_source = trusted_target / "source.zip"
        trusted_source.write_bytes(b"source")
        trusted_root_link = self.root / "trusted-root-link"
        trusted_root_link.symlink_to(trusted_target, target_is_directory=True)
        with self.assertRaises(ArtifactConfigurationError):
            encrypt_file(
                trusted_root_link / "source.zip",
                self.root / "symlinked-root.bse",
                data_key=DATA_KEY,
                context=self.context,
                chunk_size=CHUNK_SIZE,
                trusted_source_root=trusted_root_link,
                trusted_destination_root=self.root,
            )

        destination_directory = self.root / "destination-directory"
        destination_directory.mkdir()
        destination_link = self.root / "destination-link-directory"
        destination_link.symlink_to(destination_directory, target_is_directory=True)
        with self.assertRaises(ArtifactConfigurationError):
            encrypt_file(
                source,
                destination_link / "artifact.bse",
                data_key=DATA_KEY,
                context=self.context,
                chunk_size=CHUNK_SIZE,
                trusted_source_root=self.root,
                trusted_destination_root=self.root,
            )

        with self.assertRaises(ArtifactConfigurationError):
            encrypt_file(
                source,
                self.root.parent / "escaped.bse",
                data_key=DATA_KEY,
                context=self.context,
                chunk_size=CHUNK_SIZE,
                trusted_source_root=self.root,
                trusted_destination_root=self.root,
            )

    def test_failed_terminal_authentication_never_creates_named_plaintext_staging(self):
        payload = b"private" * (4 * CHUNK_SIZE)
        _source, encrypted, _descriptor = self._seal(payload)
        damaged = bytearray(encrypted.read_bytes())
        damaged[-1] ^= 1
        encrypted.write_bytes(damaged)
        restored = self.root / "never-published.zip"
        observed_names = []
        original_write = envelope_module._write_all

        def observe_directory(destination, value):
            original_write(destination, value)
            observed_names.extend(path.name for path in self.root.iterdir())

        with mock.patch.object(
            envelope_module, "_write_all", side_effect=observe_directory
        ):
            with self.assertRaises(ArtifactIntegrityError):
                decrypt_file(
                    encrypted,
                    restored,
                    data_key=DATA_KEY,
                    context=self.context,
                    trusted_source_root=self.root,
                    trusted_destination_root=self.root,
                )

        self.assertFalse(restored.exists())
        self.assertFalse(
            any("never-published" in name for name in observed_names), observed_names
        )

    def test_unsupported_anonymous_staging_fails_without_named_partial_file(self):
        source = self._source(b"private")
        destination = self.root / "unsupported-staging.bse"

        with mock.patch.object(envelope_module.os, "O_TMPFILE", 0):
            with self.assertRaises(ArtifactConfigurationError):
                encrypt_file(
                    source,
                    destination,
                    data_key=DATA_KEY,
                    context=self.context,
                    chunk_size=CHUNK_SIZE,
                    trusted_source_root=self.root,
                    trusted_destination_root=self.root,
                )

        self.assertFalse(destination.exists())
        self.assertEqual(
            [
                path.name
                for path in self.root.iterdir()
                if "unsupported-staging" in path.name
            ],
            [],
        )


class KeyProviderTests(SimpleTestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.context = artifact_context()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_local_provider_wrap_is_context_bound_and_enterprise_rejected(self):
        provider = LocalDevelopmentKeyProvider(b"w" * 32, key_id="dev-key-v1")
        generated = provider.generate_data_key(self.context)
        plaintext = bytes(generated.plaintext)

        self.assertEqual(
            bytes(provider.unwrap_data_key(generated.wrapped, self.context)), plaintext
        )
        with self.assertRaises(KeyProviderIntegrityError):
            provider.unwrap_data_key(
                generated.wrapped, artifact_context(node_id="other-node")
            )
        registry = KeyProviderRegistry([provider])
        self.assertIs(registry.get("local-development"), provider)
        with self.assertRaises(KeyProviderConfigurationError):
            registry.get("local-development", enterprise_mode=True)
        generated.destroy()
        self.assertEqual(generated.plaintext, bytearray(32))

        provider.destroy()
        with self.assertRaises(KeyProviderConfigurationError):
            provider.generate_data_key(self.context)

    def test_seal_and_unseal_use_provider_and_zero_plaintext_key(self):
        source = self.root / "source.zip"
        encrypted = self.root / "source.bse"
        restored = self.root / "restored.zip"
        source.write_bytes(b"secret backup")

        class CapturingProvider:
            name = "capture"
            external = True
            enterprise_eligible = True

            def __init__(self):
                self.generated = None

            def generate_data_key(self, _context):
                self.generated = GeneratedDataKey(
                    plaintext=bytearray(DATA_KEY),
                    wrapped=WrappedDataKey("capture", "key-1", b"wrapped"),
                )
                return self.generated

            def unwrap_data_key(self, _wrapped, _context):
                return bytearray(DATA_KEY)

        provider = CapturingProvider()
        sealed = seal_file(
            source,
            encrypted,
            provider=provider,
            context=self.context,
            enterprise_mode=True,
            chunk_size=CHUNK_SIZE,
            trusted_source_root=self.root,
            trusted_destination_root=self.root,
        )
        self.assertEqual(provider.generated.plaintext, bytearray(32))

        unseal_file(
            encrypted,
            restored,
            provider=provider,
            wrapped_data_key=sealed.wrapped_data_key,
            context=self.context,
            expected=sealed.envelope.expectation(),
            enterprise_mode=True,
            trusted_source_root=self.root,
            trusted_destination_root=self.root,
        )
        self.assertEqual(restored.read_bytes(), b"secret backup")

    def test_registry_rejects_unknown_dynamic_and_duplicate_names(self):
        provider = LocalDevelopmentKeyProvider(b"k" * 32)
        registry = KeyProviderRegistry([provider])
        with self.assertRaises(KeyProviderConfigurationError):
            registry.get("package.module.Provider")
        with self.assertRaises(KeyProviderConfigurationError):
            registry.register(provider)

    def _write_keyring(
        self,
        lane="database",
        *,
        active=LOCAL_KEY_V1,
        keys=None,
        installation_id=INSTALLATION_ID,
    ):
        path = self.root / f"{lane}.keyring"
        entries = keys or [(active, "11" * 32)]
        path.write_bytes(
            canonical_keyring_bytes(
                installation_id=installation_id,
                lane=lane,
                active_key_id=active,
                keys=entries,
            )
        )
        path.chmod(0o400)
        return path

    def test_normative_bslw1_vector_encrypts_and_decrypts_exact_bytes(self):
        vector_path = Path(__file__).with_name("fixtures") / "bslw1-v1-vector.json"
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
        context = ArtifactContext.from_mapping(vector["context"])
        self.assertEqual(
            context.canonical_bytes().decode("ascii"),
            vector["context_canonical_json"],
        )
        self.assertEqual(context.sha256, vector["context_sha256"])
        keyring = self._write_keyring(
            lane=context.lane,
            active=vector["key_id"],
            keys=[(vector["key_id"], vector["root_key_hex"])],
            installation_id=context.installation_id,
        )
        provider = LocalFileKeyProvider(
            keyring,
            lane=context.lane,
            installation_id=context.installation_id,
        )
        self.assertEqual(
            provider._aad(context, vector["key_id"]),
            bytes.fromhex(vector["aad_hex"]),
        )
        with mock.patch.object(
            local_file_module.os,
            "urandom",
            side_effect=[
                bytes.fromhex(vector["data_key_hex"]),
                bytes.fromhex(vector["nonce_hex"]),
            ],
        ):
            generated = provider.generate_data_key(context)
        self.assertEqual(bytes(generated.plaintext), bytes.fromhex(vector["data_key_hex"]))
        self.assertEqual(
            generated.wrapped.ciphertext,
            bytes.fromhex(vector["payload_hex"]),
        )
        frozen = WrappedDataKey(
            vector["provider"],
            vector["key_id"],
            bytes.fromhex(vector["payload_hex"]),
        )
        self.assertEqual(
            bytes(provider.unwrap_data_key(frozen, context)),
            bytes.fromhex(vector["data_key_hex"]),
        )
        self.assertEqual(local_file_module.WRAP_ALGORITHM, vector["algorithm"])
        generated.destroy()
        provider.destroy()

    def test_local_file_wrap_is_context_bound_and_enterprise_eligible(self):
        provider = LocalFileKeyProvider(
            self._write_keyring(),
            lane="database",
            installation_id=INSTALLATION_ID,
        )
        generated = provider.generate_data_key(self.context)
        plaintext = bytes(generated.plaintext)

        self.assertEqual(generated.wrapped.provider_name, "local-file")
        self.assertEqual(generated.wrapped.wrapping_key_id, LOCAL_KEY_V1)
        self.assertEqual(
            bytes(provider.unwrap_data_key(generated.wrapped, self.context)), plaintext
        )
        self.assertIs(
            KeyProviderRegistry([provider]).get("local-file", enterprise_mode=True),
            provider,
        )
        with self.assertRaises(KeyProviderIntegrityError):
            provider.unwrap_data_key(
                generated.wrapped,
                artifact_context(node_id="other-node"),
            )
        with self.assertRaises(KeyProviderConfigurationError):
            provider.unwrap_data_key(
                generated.wrapped,
                artifact_context(lane="files"),
            )
        with self.assertRaises(KeyProviderConfigurationError):
            provider.unwrap_data_key(
                generated.wrapped,
                artifact_context(installation_id="b" * 64),
            )
        generated.destroy()
        provider.destroy()

    def test_local_file_gcm_siv_wrap_survives_forced_nonce_reuse(self):
        provider = LocalFileKeyProvider(
            self._write_keyring(),
            lane="database",
            installation_id=INSTALLATION_ID,
        )
        nonce = b"n" * 12
        with mock.patch.object(
            local_file_module.os,
            "urandom",
            side_effect=[b"a" * 32, nonce, b"b" * 32, nonce],
        ):
            first = provider.generate_data_key(self.context)
            second = provider.generate_data_key(self.context)

        self.assertEqual(local_file_module.WRAP_ALGORITHM, "AES-256-GCM-SIV")
        self.assertEqual(first.wrapped.ciphertext[5:17], nonce)
        self.assertEqual(second.wrapped.ciphertext[5:17], nonce)
        self.assertNotEqual(first.wrapped.ciphertext, second.wrapped.ciphertext)
        self.assertEqual(
            bytes(provider.unwrap_data_key(first.wrapped, self.context)),
            b"a" * 32,
        )
        self.assertEqual(
            bytes(provider.unwrap_data_key(second.wrapped, self.context)),
            b"b" * 32,
        )
        first.destroy()
        second.destroy()
        provider.destroy()

    def test_local_file_tamper_and_unknown_legacy_key_fail_closed(self):
        provider = LocalFileKeyProvider(
            self._write_keyring(),
            lane="database",
            installation_id=INSTALLATION_ID,
        )
        generated = provider.generate_data_key(self.context)
        tampered = bytearray(generated.wrapped.ciphertext)
        tampered[-1] ^= 1

        with self.assertRaises(KeyProviderIntegrityError):
            provider.unwrap_data_key(
                WrappedDataKey(
                    "local-file",
                    generated.wrapped.wrapping_key_id,
                    bytes(tampered),
                ),
                self.context,
            )
        with self.assertRaises(KeyProviderNotFoundError):
            provider.unwrap_data_key(
                WrappedDataKey(
                    "local-file",
                    "lfk-99999999999999999999999999999999",
                    generated.wrapped.ciphertext,
                ),
                self.context,
            )
        generated.destroy()
        provider.destroy()

    def test_local_file_rejects_relative_unsafe_and_linked_paths(self):
        with self.assertRaises(KeyProviderConfigurationError):
            LocalFileKeyProvider(
                "database.keyring",
                lane="database",
                installation_id=INSTALLATION_ID,
            )

        path = self._write_keyring()
        path.chmod(0o600)
        with self.assertRaises(KeyProviderConfigurationError):
            LocalFileKeyProvider(
                path,
                lane="database",
                installation_id=INSTALLATION_ID,
            )
        path.chmod(0o400)

        symlink = self.root / "linked.keyring"
        symlink.symlink_to(path)
        with self.assertRaises(KeyProviderConfigurationError):
            LocalFileKeyProvider(
                symlink,
                lane="database",
                installation_id=INSTALLATION_ID,
            )

        hardlink = self.root / "hardlinked.keyring"
        os.link(path, hardlink)
        with self.assertRaises(KeyProviderConfigurationError):
            LocalFileKeyProvider(
                path,
                lane="database",
                installation_id=INSTALLATION_ID,
            )

    def test_local_file_rejects_keyring_in_unprotected_parent(self):
        path = self._write_keyring()
        self.root.chmod(0o755)
        try:
            with self.assertRaises(KeyProviderConfigurationError):
                LocalFileKeyProvider(
                    path,
                    lane="database",
                    installation_id=INSTALLATION_ID,
                )
        finally:
            self.root.chmod(0o700)

    def test_local_file_accepts_rootful_compose_secret_with_host_uid(self):
        provider = object.__new__(LocalFileKeyProvider)
        provider.path = Path(
            "/run/secrets/artifact_local_file_database_keyring"
        )
        provider.lane = "database"
        file_metadata = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o444,
            st_nlink=1,
            st_uid=501,
        )
        parent_metadata = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755,
            st_uid=0,
        )
        self.assertTrue(provider._secure_metadata(file_metadata, parent_metadata))

        provider.path = Path("/tmp/copied-database.keyring")
        self.assertFalse(provider._secure_metadata(file_metadata, parent_metadata))

    def test_local_file_rejects_a_symlinked_ancestor(self):
        real_ancestor = self.root / "real-ancestor"
        real_ancestor.mkdir(mode=0o700)
        protected_parent = real_ancestor / "protected"
        protected_parent.mkdir(mode=0o700)
        keyring = protected_parent / "database.keyring"
        keyring.write_bytes(
            canonical_keyring_bytes(
                installation_id=INSTALLATION_ID,
                lane="database",
                active_key_id=LOCAL_KEY_V1,
                keys=[(LOCAL_KEY_V1, "11" * 32)],
            )
        )
        keyring.chmod(0o400)
        linked_ancestor = self.root / "linked-ancestor"
        linked_ancestor.symlink_to(real_ancestor, target_is_directory=True)

        with self.assertRaises(KeyProviderConfigurationError):
            LocalFileKeyProvider(
                linked_ancestor / "protected" / "database.keyring",
                lane="database",
                installation_id=INSTALLATION_ID,
            )

    def test_local_file_rejects_wrong_lane_and_noncanonical_content(self):
        path = self._write_keyring(lane="files")
        with self.assertRaises(KeyProviderConfigurationError):
            LocalFileKeyProvider(
                path,
                lane="database",
                installation_id=INSTALLATION_ID,
            )

        cases = (
            canonical_keyring_bytes(
                installation_id=INSTALLATION_ID,
                lane="database",
                active_key_id=LOCAL_KEY_V1,
                keys=[(LOCAL_KEY_V1, "11" * 32)],
            )
            + b"\n",
            canonical_keyring_bytes(
                installation_id=INSTALLATION_ID,
                lane="database",
                active_key_id=LOCAL_KEY_V2,
                keys=[(LOCAL_KEY_V1, "11" * 32), (LOCAL_KEY_V2, "22" * 32)],
            ),
            canonical_keyring_bytes(
                installation_id=INSTALLATION_ID,
                lane="database",
                active_key_id=LOCAL_KEY_V1,
                keys=[(LOCAL_KEY_V1, "11" * 32), (LOCAL_KEY_V2, "11" * 32)],
            ),
        )
        for position, content in enumerate(cases):
            with self.subTest(position=position):
                malformed = self.root / f"malformed-{position}.keyring"
                malformed.write_bytes(content)
                malformed.chmod(0o400)
                with self.assertRaises(KeyProviderConfigurationError):
                    LocalFileKeyProvider(
                        malformed,
                        lane="database",
                        installation_id=INSTALLATION_ID,
                    )

    def test_local_file_rejects_a_foreign_installation_keyring(self):
        path = self._write_keyring()

        with self.assertRaisesRegex(
            KeyProviderConfigurationError,
            "different installation",
        ):
            LocalFileKeyProvider(
                path,
                lane="database",
                installation_id="b" * 64,
            )

    def test_local_file_active_and_legacy_keys_support_safe_rotation(self):
        path = self._write_keyring()
        original = LocalFileKeyProvider(
            path,
            lane="database",
            installation_id=INSTALLATION_ID,
        )
        generated = original.generate_data_key(self.context)
        plaintext = bytes(generated.plaintext)
        original.destroy()

        path.chmod(0o600)
        path.write_bytes(
            canonical_keyring_bytes(
                installation_id=INSTALLATION_ID,
                lane="database",
                active_key_id=LOCAL_KEY_V2,
                keys=[(LOCAL_KEY_V2, "22" * 32), (LOCAL_KEY_V1, "11" * 32)],
            )
        )
        path.chmod(0o400)
        rotated = LocalFileKeyProvider(
            path,
            lane="database",
            installation_id=INSTALLATION_ID,
        )
        self.assertEqual(rotated.key_ids, (LOCAL_KEY_V2, LOCAL_KEY_V1))
        self.assertEqual(
            bytes(rotated.unwrap_data_key(generated.wrapped, self.context)), plaintext
        )
        rewrapped = rotated.rewrap_data_key(
            generated.wrapped,
            self.context,
            destination_key_id=LOCAL_KEY_V2,
        )
        self.assertEqual(rewrapped.wrapping_key_id, LOCAL_KEY_V2)
        self.assertEqual(
            bytes(rotated.unwrap_data_key(rewrapped, self.context)), plaintext
        )
        generated.destroy()
        rotated.destroy()

    def test_local_file_keyring_is_bounded_to_eight_unique_keys(self):
        keys = [
            (f"lfk-{index:032x}", f"{index + 1:064x}")
            for index in range(9)
        ]
        path = self._write_keyring(active=keys[0][0], keys=keys)
        with self.assertRaises(KeyProviderConfigurationError):
            LocalFileKeyProvider(
                path,
                lane="database",
                installation_id=INSTALLATION_ID,
            )

    def test_local_file_rejects_wrong_provider_key_id_and_ciphertext_shape(self):
        provider = LocalFileKeyProvider(
            self._write_keyring(),
            lane="database",
            installation_id=INSTALLATION_ID,
        )
        generated = provider.generate_data_key(self.context)
        cases = (
            WrappedDataKey(
                "local-development",
                generated.wrapped.wrapping_key_id,
                generated.wrapped.ciphertext,
            ),
            WrappedDataKey("local-file", "bad-key-id", generated.wrapped.ciphertext),
            WrappedDataKey("local-file", LOCAL_KEY_V1, b"too-short"),
        )
        for wrapped in cases:
            with self.subTest(wrapped=wrapped):
                with self.assertRaises(KeyProviderConfigurationError):
                    provider.unwrap_data_key(wrapped, self.context)
        generated.destroy()
        provider.destroy()

    def test_local_filesystem_preflight_happens_before_remote_key_operations(self):
        class CountingProvider:
            name = "counting"
            external = True
            enterprise_eligible = True

            def __init__(self):
                self.generate_calls = 0
                self.unwrap_calls = 0

            def generate_data_key(self, _context):
                self.generate_calls += 1
                return GeneratedDataKey(
                    bytearray(DATA_KEY), WrappedDataKey(self.name, "key", b"wrapped")
                )

            def unwrap_data_key(self, _wrapped, _context):
                self.unwrap_calls += 1
                return bytearray(DATA_KEY)

        provider = CountingProvider()
        with self.assertRaises(FileNotFoundError):
            seal_file(
                self.root / "missing.zip",
                self.root / "missing.bse",
                provider=provider,
                context=self.context,
                trusted_source_root=self.root,
                trusted_destination_root=self.root,
            )
        self.assertEqual(provider.generate_calls, 0)

        malformed = self.root / "malformed.bse"
        malformed.write_bytes(b"not-an-envelope")
        with self.assertRaises(UnsupportedArtifactFormatError):
            unseal_file(
                malformed,
                self.root / "malformed.zip",
                provider=provider,
                wrapped_data_key=WrappedDataKey(provider.name, "key", b"wrapped"),
                context=self.context,
                trusted_source_root=self.root,
                trusted_destination_root=self.root,
            )
        self.assertEqual(provider.unwrap_calls, 0)

    def test_enterprise_restore_requires_witness_and_trusted_roots(self):
        provider = LocalFileKeyProvider(
            self._write_keyring(),
            lane="database",
            installation_id=INSTALLATION_ID,
        )
        with self.assertRaises(ArtifactConfigurationError):
            unseal_file(
                self.root / "missing.bse",
                self.root / "missing.zip",
                provider=provider,
                wrapped_data_key=WrappedDataKey(
                    "local-file", LOCAL_KEY_V1, b"wrapped"
                ),
                context=self.context,
                enterprise_mode=True,
            )
