# BackupSheep Encrypted Artifact Format (BSE1)

Status: version 1, frozen. Multibyte integers are unsigned, big-endian.

BSE1 is a chunked AES-256-GCM-SIV envelope. It authenticates the canonical
artifact identity, the complete ordered record sequence, and an explicit
terminal record. A reader must reject an unsupported field, malformed canonical
JSON, missing or repeated record, truncation, trailing byte, authentication
failure, context mismatch, or durable-ledger mismatch.

## Byte layout

The 12-byte preamble is `>4sBBHI`:

| Offset | Size | Value |
| --- | ---: | --- |
| 0 | 4 | ASCII `BSE1` |
| 4 | 1 | format version, `1` |
| 5 | 1 | flags, `0` |
| 6 | 2 | reserved, `0` |
| 8 | 4 | canonical JSON header byte length |

The preamble is followed by the ASCII header, zero or more data records, and
exactly one terminal record. A record header is the 13-byte structure `>BQI`:

| Field | Size | Data record | Terminal record |
| --- | ---: | --- | --- |
| type | 1 | `1` | `255` |
| index | 8 | zero-based chunk index | `chunk_count` |
| length | 4 | plaintext chunk length | `0` |

Each record header is followed by AES-GCM-SIV output: `length` ciphertext bytes
and a 16-byte tag for data, or only a 16-byte tag for the empty terminal
plaintext. No bytes may follow the terminal tag.

## Canonical header

The header is an ASCII JSON object encoded with keys sorted lexicographically,
no insignificant whitespace, no escaped non-ASCII input, and no duplicate keys.
It contains exactly:

- `algorithm`: `AES-256-GCM-SIV`
- `chunk_count`: `ceil(plaintext_size / chunk_size)`
- `chunk_size`: 65,536 through 67,108,864 bytes
- `context_sha256`: lowercase SHA-256 of canonical `ArtifactContext` JSON
- `envelope_id`: canonical lowercase UUID string
- `nonce_prefix`: four lowercase hexadecimal bytes
- `plaintext_sha256`: lowercase SHA-256 of the complete plaintext
- `plaintext_size`: integer from 0 through `2^64 - 1`
- `version`: `1`

The expected file size is:

```text
12 + header_size + plaintext_size
   + chunk_count * (13 + 16)
   + 13 + 16
```

Any smaller file is truncated; any larger file has unauthenticated trailing
data. The preamble version and header version must agree.

## Nonce and authenticated data

The 12-byte nonce for record index `i` is:

```text
nonce_prefix (4 bytes) || uint64_be(i)
```

The authenticated additional data is:

```text
ASCII("BackupSheep/BSE1/record") || 00
|| SHA256(canonical_header)       (32 raw bytes)
|| record_header                 (13 raw bytes)
```

The random four-byte prefix must be newly generated for every envelope under a
data key. BackupSheep generates a new 256-bit data key for every artifact. The
terminal record prevents a valid prefix of an artifact from being accepted as a
complete backup.

## Context and durable witness

`ArtifactContext` canonical JSON contains exactly `account_id`, `backup_id`,
`backup_model`, `installation_id`, `lane`, `node_id`, and `purpose`. Its values
are non-secret. The same persisted context is authenticated when the random data
key is wrapped by the lane-specific local-file root key using AES-256-GCM-SIV and
a fresh random 96-bit nonce. GCM-SIV preserves authentication even under an
accidental nonce collision during the lifetime of a retained root key. The versioned
`BSLW1` database-wrap payload names this exact GCM-SIV contract; it is not AES-GCM.
Restore must match the
BSE1 header against the durable envelope UUID,
header SHA-256, plaintext size, plaintext SHA-256, active wrapped-key generation,
and canonical context before publishing plaintext.

Plaintext output is staged in an unnamed `O_TMPFILE` inode with mode `0600`.
BackupSheep links or replaces it only after every record, the terminal tag, the
plaintext byte count, and the plaintext digest authenticate. A filesystem that
cannot provide anonymous staging is rejected rather than given a readable
partial-plaintext fallback.

## Deterministic interoperability vector

The normative BSE1 byte vector is
[`apps/tests/fixtures/bse1-v1-vector.json`](../../apps/tests/fixtures/bse1-v1-vector.json).
It fixes the key, context, UUID, nonce prefix, plaintext, canonical header,
header digest, and complete 463-byte envelope. Implementations must reproduce
`envelope_hex` exactly and decrypt it to `plaintext_hex`.

The independent BSLW1 root-key wrapping vector is
[`apps/tests/fixtures/bslw1-v1-vector.json`](../../apps/tests/fixtures/bslw1-v1-vector.json).
It freezes the 256-bit lane root key, 256-bit data key, 96-bit nonce, installation/lane
context, wrapping-key ID, canonical context JSON, and complete 65-byte database payload.
Implementations must reproduce `payload_hex` exactly with AES-256-GCM-SIV and unwrap it
to `data_key_hex`; changing its AAD domain, field ordering, or `BSLW1` framing is a
breaking recovery-format change.

The byte-level BSLW1 layout is exactly:

```text
offset  length  value
0       5       ASCII "BSLW1"
5       12      random AES-GCM-SIV nonce
17      48      AES-256-GCM-SIV ciphertext || 16-byte tag for the 32-byte data key
```

The authenticated associated data has no length prefixes and is exactly this
concatenation (the two `NUL` values are single `0x00` bytes):

```text
ASCII "BackupSheep/BSE1/local-file-wrap/v1" || NUL ||
ASCII wrapping_key_id || NUL || ArtifactContext canonical JSON bytes
```

The provider name and wrapping-key ID remain separate database columns; the ID is both
authenticated in the AAD and used to select the retained lane root key. The vector's
`aad_hex` freezes the complete associated-data encoding for independent implementations.
