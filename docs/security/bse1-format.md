# BackupSheep Encrypted Artifact Format (BSE1)

Status: format version 2, frozen. Multibyte integers are unsigned, big-endian.
Format version 1 is retired and readers must reject it; there is no downgrade or
compatibility path because the pre-release database transition requires an empty
artifact inventory.

BSE1 v2 is a chunked AES-256-GCM-SIV envelope. It authenticates the public
framing, the complete ordered record sequence, and a fixed encrypted terminal
payload containing the private integrity and context witnesses. A reader must
reject an unsupported field, malformed canonical JSON, missing or repeated
record, truncation, trailing byte, authentication failure, context mismatch, or
durable-ledger mismatch.

## Byte layout

The 12-byte preamble is `>4sBBHI`:

| Offset | Size | Value |
| --- | ---: | --- |
| 0 | 4 | ASCII `BSE1` |
| 4 | 1 | format version, `2` |
| 5 | 1 | flags, `0` |
| 6 | 2 | reserved, `0` |
| 8 | 4 | canonical JSON header byte length |

The preamble is followed by the ASCII header, zero or more data records, and
exactly one terminal record. A record header is the 13-byte structure `>BQI`:

| Field | Size | Data record | Terminal record |
| --- | ---: | --- | --- |
| type | 1 | `1` | `255` |
| index | 8 | zero-based chunk index | `chunk_count` |
| length | 4 | plaintext chunk length | `69` |

Each record header is followed by AES-GCM-SIV output: `length` ciphertext bytes
and a 16-byte tag. No bytes may follow the terminal tag.

## Public canonical header

The header is an ASCII JSON object encoded with keys sorted lexicographically,
no insignificant whitespace, no escaped non-ASCII input, and no duplicate keys.
It contains exactly:

- `algorithm`: `AES-256-GCM-SIV`
- `chunk_count`: `ceil(plaintext_size / chunk_size)`
- `chunk_size`: 65,536 through 67,108,864 bytes
- `envelope_id`: an independently generated canonical UUIDv4
- `nonce_prefix`: four lowercase hexadecimal bytes
- `plaintext_size`: integer from 0 through `2^64 - 1`
- `version`: `2`

The public header contains no backup UUID, canonical-context digest, or plaintext
digest. Public/header-only parsing therefore returns only structural metadata and
must not claim knowledge of either private digest.

The expected file size is:

```text
12 + header_size + plaintext_size
   + chunk_count * (13 + 16)
   + 13 + 69 + 16
```

Any smaller file is truncated; any larger file has unauthenticated trailing
data. The preamble version and header version must agree.

## Encrypted terminal payload

The terminal record encrypts one fixed 69-byte `>4sB32s32s` plaintext:

| Offset | Size | Value |
| --- | ---: | --- |
| 0 | 4 | ASCII `BSET` |
| 4 | 1 | terminal-payload version, `1` |
| 5 | 32 | raw SHA-256 of the complete plaintext artifact |
| 37 | 32 | raw SHA-256 of canonical `ArtifactContext` JSON |

The terminal payload is AEAD-authenticated like every data record. Restore first
decrypts all data into an unnamed private inode, authenticates and parses the
terminal, compares its context digest with the requested durable context, and
compares its plaintext digest with both the streamed plaintext and durable
ledger. Only then may it publish a plaintext filename. A corrupted, replayed, or
swapped terminal therefore cannot publish plaintext.

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
data key. BackupSheep generates a new 256-bit data key and random UUIDv4 for every
artifact. The envelope UUID must differ from the backup UUID and is the basename
for ciphertext handoff objects: `<envelope_uuid>.bse1`.

## Context and durable witness

`ArtifactContext` canonical JSON contains exactly `account_id`, `backup_id`,
`backup_model`, `installation_id`, `lane`, `node_id`, and `purpose`. It remains in
the durable database custody record and is authenticated when the random data key
is wrapped by the lane-specific local-file root key using AES-256-GCM-SIV and a
fresh random 96-bit nonce. It is not copied into the public BSE1 header.

Before key unwrap, storage/header validation can prove only the public envelope
UUID, header SHA-256, sizes, chunk framing, algorithm/version, ciphertext digest,
and object-name binding. The decrypting source lane proves the private plaintext
and context digests after authenticating the terminal record. Restore must match
both sets of witnesses against one durable envelope and active wrapped-key
generation before plaintext publication.

Plaintext output is staged in an unnamed `O_TMPFILE` inode with mode `0600`.
BackupSheep links or replaces it only after every data record, the terminal
payload, the plaintext byte count, and both private digests authenticate. A
filesystem that cannot provide anonymous staging is rejected rather than given a
readable partial-plaintext fallback.

`O_TMPFILE` and publication through `linkat(AT_EMPTY_PATH)` are Linux- and
filesystem-dependent. Production acceptance must exercise sealing and an
isolated, data-verified restore on each exact worker mount; a settings check or
health endpoint does not prove these primitives. Repeat that proof after changing
the runtime, kernel, filesystem, volume driver, or mount options.

### Deliberately public metadata

An untrusted storage destination necessarily learns ciphertext size, configured
chunk size/count, envelope UUID, nonce prefix, and transfer timing. BSE1 v2 does
not attempt length-hiding or traffic-analysis resistance. Independently encrypted
backups of equal plaintext expose no stable plaintext digest or context digest and
produce different envelope IDs, headers, ciphertext, and ciphertext digests.

## Deterministic interoperability vectors

The normative BSE1 v2 byte vector is
[`apps/tests/fixtures/bse1-v2-vector.json`](../../apps/tests/fixtures/bse1-v2-vector.json).
It fixes the key, private context, random envelope UUID, nonce prefix, plaintext,
canonical public header, encrypted terminal, header digest, and complete 362-byte
envelope. Implementations must reproduce `envelope_hex` exactly and decrypt it to
`plaintext_hex`. The retained v1 fixture is negative-test input only and must be
rejected as unsupported.

The independent BSLW1 root-key wrapping vector is
[`apps/tests/fixtures/bslw1-v1-vector.json`](../../apps/tests/fixtures/bslw1-v1-vector.json).
It freezes the 256-bit lane root key, 256-bit data key, 96-bit nonce,
installation/lane context, wrapping-key ID, canonical context JSON, and complete
65-byte database payload. Implementations must reproduce `payload_hex` exactly
with AES-256-GCM-SIV and unwrap it to `data_key_hex`; changing its AAD domain,
field ordering, or `BSLW1` framing is a breaking recovery-format change.

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

The provider name and wrapping-key ID remain separate database columns; the ID is
both authenticated in the AAD and used to select the retained lane root key. The
vector's `aad_hex` freezes the complete associated-data encoding for independent
implementations.
