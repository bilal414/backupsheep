"""Focused security tests for BSE1 artifact envelopes and key providers."""

import hashlib
import json
import os
import struct
import tempfile
import uuid
from pathlib import Path
from unittest import mock

from botocore.exceptions import ClientError
from django.test import SimpleTestCase

from backupsheep.artifact_crypto import (
    AWSKMSConfig,
    AWSKMSKeyProvider,
    ArtifactContext,
    EnvelopeExpectation,
    KeyProviderRegistry,
    LocalDevelopmentKeyProvider,
    WrappedDataKey,
    decrypt_file,
    encrypt_file,
    read_envelope_header,
    seal_file,
    unseal_file,
)
from backupsheep.artifact_crypto import envelope as envelope_module
from backupsheep.artifact_crypto.errors import (
    ArtifactConfigurationError,
    ArtifactContextMismatchError,
    ArtifactDestinationExistsError,
    ArtifactFormatError,
    ArtifactIntegrityError,
    ArtifactSourceChangedError,
    ArtifactTruncatedError,
    KeyProviderAccessDeniedError,
    KeyProviderConfigurationError,
    KeyProviderIntegrityError,
    KeyProviderResponseError,
    UnsupportedArtifactFormatError,
)
from backupsheep.artifact_crypto.providers.base import GeneratedDataKey

CHUNK_SIZE = 64 * 1024
DATA_KEY = bytes(range(32))
ENVELOPE_ID = uuid.UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
KMS_SOURCE_ARN = "arn:aws:kms:us-east-1:123456789012:key/source-key"
KMS_DESTINATION_ARN = "arn:aws:kms:us-east-1:123456789012:key/destination-key"


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

    def test_header_reader_is_structural_and_exposes_durable_witness(self):
        payload = b"backup" * 1000
        _source, encrypted, descriptor = self._seal(payload)

        parsed = read_envelope_header(encrypted)

        self.assertEqual(parsed, descriptor)
        self.assertEqual(parsed.envelope_id, ENVELOPE_ID)
        self.assertEqual(parsed.plaintext_sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(parsed.context_sha256, self.context.sha256)

    def test_normative_bse1_v1_vector_is_byte_for_byte_deterministic(self):
        vector_path = Path(__file__).with_name("fixtures") / "bse1-v1-vector.json"
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
            expected=parsed.expectation(),
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

    def test_header_and_ciphertext_tampering_fail_closed(self):
        _source, encrypted, _descriptor = self._seal(b"A" * (CHUNK_SIZE + 71))
        original = bytearray(encrypted.read_bytes())
        _magic, _version, _flags, _reserved, header_size = struct.unpack(
            ">4sBBHI", original[:12]
        )
        header_start = 12
        header_end = header_start + header_size

        header_tampered = bytearray(original)
        digest_marker = header_tampered.find(
            b'"plaintext_sha256":"', header_start, header_end
        )
        digest_offset = digest_marker + len(b'"plaintext_sha256":"')
        header_tampered[digest_offset] = (
            ord("0") if header_tampered[digest_offset] != ord("0") else ord("1")
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

    def test_truncation_at_every_format_boundary_never_publishes_plaintext(self):
        _source, encrypted, _descriptor = self._seal(b"B" * (CHUNK_SIZE + 29))
        original = encrypted.read_bytes()
        _magic, _version, _flags, _reserved, header_size = struct.unpack(
            ">4sBBHI", original[:12]
        )
        header_end = 12 + header_size
        first_record_end = header_end + 13 + CHUNK_SIZE + 16
        terminal_size = 13 + 16
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

        terminal_start = len(original) - 29
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
        unknown_version[4] = 2
        version_path = self.root / "unknown-version.bse"
        version_path.write_bytes(unknown_version)
        self._decrypt_failure(version_path, error=UnsupportedArtifactFormatError)

        header = json.loads(original[12:header_end])
        header["algorithm"] = "AES-256-GCM"
        altered_header = json.dumps(
            header, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        algorithm_path = self.root / "unknown-algorithm.bse"
        algorithm_path.write_bytes(
            struct.pack(">4sBBHI", b"BSE1", 1, 0, 0, len(altered_header))
            + altered_header
            + original[header_end:]
        )
        self._decrypt_failure(algorithm_path, error=UnsupportedArtifactFormatError)

        noncanonical = b" " + bytes(original[12:header_end])
        noncanonical_path = self.root / "noncanonical.bse"
        noncanonical_path.write_bytes(
            struct.pack(">4sBBHI", b"BSE1", 1, 0, 0, len(noncanonical))
            + noncanonical
            + original[header_end:]
        )
        self._decrypt_failure(noncanonical_path, error=ArtifactFormatError)

        oversized_path = self.root / "oversized-header.bse"
        oversized_path.write_bytes(struct.pack(">4sBBHI", b"BSE1", 1, 0, 0, 65537))
        self._decrypt_failure(oversized_path, error=ArtifactFormatError)

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
        self.root = Path(self.temporary_directory.name)
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

    def test_aws_generate_decrypt_and_reencrypt_bind_exact_context(self):
        client = mock.Mock()
        client.generate_data_key.return_value = {
            "Plaintext": DATA_KEY,
            "CiphertextBlob": b"kms-wrapped-key",
            "KeyId": KMS_SOURCE_ARN,
        }
        client.decrypt.return_value = {
            "Plaintext": DATA_KEY,
            "KeyId": KMS_SOURCE_ARN,
        }
        client.re_encrypt.return_value = {
            "CiphertextBlob": b"rotated-key",
            "KeyId": KMS_DESTINATION_ARN,
            "SourceKeyId": KMS_SOURCE_ARN,
        }
        provider = AWSKMSKeyProvider(
            AWSKMSConfig(
                key_id="alias/backupsheep",
                region_name="us-east-1",
                allowed_key_ids=(KMS_SOURCE_ARN, KMS_DESTINATION_ARN),
            ),
            client=client,
        )

        generated = provider.generate_data_key(self.context)
        client.generate_data_key.assert_called_once_with(
            KeyId="alias/backupsheep",
            KeySpec="AES_256",
            EncryptionContext=self.context.key_provider_context(),
        )
        self.assertEqual(bytes(generated.plaintext), DATA_KEY)
        self.assertEqual(generated.wrapped.ciphertext, b"kms-wrapped-key")

        self.assertEqual(
            bytes(provider.unwrap_data_key(generated.wrapped, self.context)), DATA_KEY
        )
        client.decrypt.assert_called_once_with(
            CiphertextBlob=b"kms-wrapped-key",
            KeyId=KMS_SOURCE_ARN,
            EncryptionAlgorithm="SYMMETRIC_DEFAULT",
            EncryptionContext=self.context.key_provider_context(),
        )

        rotated = provider.rewrap_data_key(
            generated.wrapped,
            self.context,
            destination_key_id=KMS_DESTINATION_ARN,
        )
        self.assertEqual(rotated.ciphertext, b"rotated-key")
        client.re_encrypt.assert_called_once_with(
            CiphertextBlob=b"kms-wrapped-key",
            SourceKeyId=KMS_SOURCE_ARN,
            DestinationKeyId=KMS_DESTINATION_ARN,
            SourceEncryptionContext=self.context.key_provider_context(),
            DestinationEncryptionContext=self.context.key_provider_context(),
        )

    def test_aws_errors_are_typed_sanitized_and_not_chained(self):
        client = mock.Mock()
        client.generate_data_key.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "secret account and request details",
                }
            },
            "GenerateDataKey",
        )
        provider = AWSKMSKeyProvider(
            AWSKMSConfig(key_id="alias/backupsheep", region_name="us-east-1"),
            client=client,
        )

        with self.assertRaises(KeyProviderAccessDeniedError) as raised:
            provider.generate_data_key(self.context)

        self.assertNotIn("secret", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)

    def test_aws_invalid_response_and_endpoint_fail_closed(self):
        client = mock.Mock()
        client.generate_data_key.return_value = {
            "Plaintext": b"short",
            "CiphertextBlob": b"wrapped",
            "KeyId": "key",
        }
        provider = AWSKMSKeyProvider(
            AWSKMSConfig(key_id="key", region_name="us-east-1"), client=client
        )
        with self.assertRaises(KeyProviderResponseError):
            provider.generate_data_key(self.context)
        with self.assertRaises(KeyProviderConfigurationError):
            AWSKMSConfig(
                key_id="key",
                region_name="us-east-1",
                endpoint_url="http://kms.example.test",
            )

    def test_enterprise_kms_policy_rejects_custom_and_string_boolean_endpoints(self):
        with self.assertRaises(KeyProviderConfigurationError):
            AWSKMSConfig(
                key_id="key",
                region_name="us-east-1",
                endpoint_url="http://kms.example.test",
                allow_insecure_endpoint="false",
            )

        custom_provider = AWSKMSKeyProvider(
            AWSKMSConfig(
                key_id="key",
                region_name="us-east-1",
                allowed_key_ids=(KMS_SOURCE_ARN,),
                endpoint_url="https://kms.example.test",
            ),
            client=mock.Mock(),
        )
        with self.assertRaises(KeyProviderConfigurationError):
            KeyProviderRegistry([custom_provider]).get(
                "aws-kms", enterprise_mode=True
            )

        standard_provider = AWSKMSKeyProvider(
            AWSKMSConfig(
                key_id="alias/backupsheep",
                region_name="us-east-1",
                allowed_key_ids=(KMS_SOURCE_ARN,),
            ),
            client=mock.Mock(),
        )
        self.assertIs(
            KeyProviderRegistry([standard_provider]).get(
                "aws-kms", enterprise_mode=True
            ),
            standard_provider,
        )

    def test_aws_client_ignores_environment_and_shared_config_endpoints(self):
        provider = AWSKMSKeyProvider(
            AWSKMSConfig(
                key_id="alias/backupsheep",
                region_name="us-east-1",
                allowed_key_ids=(KMS_SOURCE_ARN,),
            )
        )
        client = mock.Mock()
        with mock.patch("boto3.client", return_value=client) as create_client:
            self.assertIs(provider.client, client)

        configuration = create_client.call_args.kwargs["config"]
        self.assertIs(configuration.ignore_configured_endpoint_urls, True)
        self.assertIsNone(create_client.call_args.kwargs["endpoint_url"])

    def test_kms_numeric_configuration_is_normalized_and_strict(self):
        config = AWSKMSConfig(
            key_id="key",
            region_name="us-east-1",
            connect_timeout_seconds="5",
            read_timeout_seconds="30",
            max_attempts="3",
        )
        self.assertIs(type(config.connect_timeout_seconds), int)
        self.assertIs(type(config.read_timeout_seconds), int)
        self.assertIs(type(config.max_attempts), int)
        for field, value in (
            ("connect_timeout_seconds", True),
            ("read_timeout_seconds", 5.5),
            ("max_attempts", "3.0"),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(KeyProviderConfigurationError):
                    AWSKMSConfig(
                        key_id="key",
                        region_name="us-east-1",
                        **{field: value},
                    )

    def test_kms_key_identity_is_pinned_for_generate_and_decrypt(self):
        unapproved_arn = "arn:aws:kms:us-east-1:123456789012:key/unapproved"
        client = mock.Mock()
        client.generate_data_key.return_value = {
            "Plaintext": DATA_KEY,
            "CiphertextBlob": b"wrapped",
            "KeyId": unapproved_arn,
        }
        provider = AWSKMSKeyProvider(
            AWSKMSConfig(
                key_id="alias/backupsheep",
                region_name="us-east-1",
                allowed_key_ids=(KMS_SOURCE_ARN,),
            ),
            client=client,
        )
        with self.assertRaises(KeyProviderIntegrityError):
            provider.generate_data_key(self.context)

        with self.assertRaises(KeyProviderIntegrityError):
            provider.unwrap_data_key(
                WrappedDataKey("aws-kms", unapproved_arn, b"wrapped"), self.context
            )
        client.decrypt.assert_not_called()

        client.decrypt.return_value = {
            "Plaintext": DATA_KEY,
            "KeyId": KMS_DESTINATION_ARN,
        }
        with self.assertRaises(KeyProviderIntegrityError):
            provider.unwrap_data_key(
                WrappedDataKey("aws-kms", KMS_SOURCE_ARN, b"wrapped"), self.context
            )

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
        provider = AWSKMSKeyProvider(
            AWSKMSConfig(
                key_id="alias/backupsheep",
                region_name="us-east-1",
                allowed_key_ids=(KMS_SOURCE_ARN,),
            ),
            client=mock.Mock(),
        )
        with self.assertRaises(ArtifactConfigurationError):
            unseal_file(
                self.root / "missing.bse",
                self.root / "missing.zip",
                provider=provider,
                wrapped_data_key=WrappedDataKey(
                    "aws-kms", KMS_SOURCE_ARN, b"wrapped"
                ),
                context=self.context,
                enterprise_mode=True,
            )
