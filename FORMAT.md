# File format

The `.hpqc` container and the key files. Why each field is there is in
[DESIGN.md](DESIGN.md).

## Container

A header followed by a payload. All integers are big-endian.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic, `HPQC` |
| 4 | 1 | format version, `1` |
| 5 | 1 | cipher suite id |
| 6 | 2 | flags; bit 0 signed, bit 1 chunked, bit 2 recipient list, bit 3 commitment |
| 8 | 8 | recipient key id (truncated SHA-256) |
| 16 | 16 | HKDF salt |
| 32 | 12 | AEAD nonce (chunked: first 7 bytes are the STREAM prefix) |
| 44 | 2 | length of the ephemeral DH public key (32, or 56) |
| 46 | 32 | ephemeral DH public key |
| 78 | 2 | length of the ML-KEM ciphertext (1088, or 1568) |
| 80 | 1088 | ML-KEM ciphertext |
| 1168 | ... | payload |

Offsets past 44 are those of suite `0x01`. Both lengths come from the suite
byte; a suite using X448 with ML-KEM-1024 makes them 56 and 1568, for a
1672-byte header.

### Suites

| Id | KEM | AEAD |
| --- | --- | --- |
| `0x01` | X25519 + ML-KEM-768 | ChaCha20-Poly1305 |
| `0x02` | X25519 + ML-KEM-768 | AES-256-GCM |
| `0x03` | X448 + ML-KEM-1024 | ChaCha20-Poly1305 |
| `0x04` | X448 + ML-KEM-1024 | AES-256-GCM |

### Payload shapes

With bit 1 clear the payload is one AEAD ciphertext followed by its 16-byte tag.
Fixed overhead is 1184 bytes per file whatever its size, or 6549 if it is
signed.

With bit 1 set the payload is a sequence of chunks, each `AEAD(64 KiB)` followed
by a 16-byte tag, every one full except the last. Nothing frames them; the
reader finds the boundaries by counting. Overhead is 1168 plus 16 per chunk.

### Recipient lists

With bits 2 and 3 set the file has more than one recipient, or one it declines
to name, and everything from offset 44 is replaced:

| Offset | Size | Field |
| ---: | ---: | --- |
| 44 | 32 | commitment to the file key every stanza wraps |
| 76 | 2 | recipient count, 1 to 1024 |
| 78 | ... | that many stanzas |
| ... | ... | payload |

Each stanza is:

| Size | Field |
| ---: | --- |
| 2 + 32 | ephemeral DH public key |
| 2 + 1088 | ML-KEM ciphertext |
| 2 + 48 | wrapped file key |

1174 bytes for suite `0x01`, 1678 for suite `0x03`, and nothing that identifies
the recipient. The key id at offset 8 is all zeros, and a non-zero value there
is refused: a fixed field nothing reads is a place to smuggle bytes past
everyone who looks at the file with `info`.

This makes the header the first field in the format whose length depends on its
own contents. The reader neither seeks nor trusts a length it has not checked:
it reads 4 KiB, parses, and when the parser runs out it reports how many bytes
the field it was reading is short by. At least that much is fetched and the
parse retried, up to a hard cap. Each round asks for at least as much again as
it already holds, because fetching only the shortfall would be correct and
quadratic in a count the file's writer chooses.

### Flag rules

Bits 2 and 3 must appear together or not at all. There is nothing for a
commitment to commit to without a file key, and a file key must never travel
without one. Either alone is refused.

Bits 0 and 1 together are refused as malformed, because this build never writes
a signed one-shot payload inside chunk framing.

Sender authentication claimed bit 0 of the reserved flags field, streaming
claimed bit 1, the recipient list claimed bit 2 and its commitment claimed bit
3. That is what the field was there for, so the format version has never had to
move. An older build meets a newer file, sees a flag bit it does not implement,
and refuses it by name rather than decrypting something it only half
understands.

Unknown flag bits are refused. Known ones are not a free pass, because the whole
header is associated data: setting bit 0 on an unsigned file gets past the flag
check and straight into a tag failure.

## Signature block

When bit 0 is set, the decrypted payload begins with:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | length of the sender Ed25519 verifying key (32) |
| 2 | 32 | sender Ed25519 verifying key |
| 34 | 2 | length of the sender ML-DSA-65 verifying key (1952) |
| 36 | 1952 | sender ML-DSA-65 verifying key |
| 1988 | 2 | length of the Ed25519 signature (64) |
| 1990 | 64 | Ed25519 signature |
| 2054 | 2 | length of the ML-DSA-65 signature (3309) |
| 2056 | 3309 | ML-DSA-65 signature |
| 5365 | ... | plaintext |

A chunked payload has the same block in the same place, with the plaintext
following it in the stream rather than inside it. The chunking code never learns
that signatures exist.

## STREAM nonce

Each chunk of a chunked payload is sealed under its own 12-byte nonce:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 7 | per-file nonce prefix, the header's nonce field |
| 7 | 4 | chunk counter, big-endian, from 0 |
| 11 | 1 | `0x01` on the last chunk, `0x00` on every other |

The counter is refused at 2^32 rather than allowed to wrap, which puts the
ceiling at 256 TiB per file.

## Key files

One base64 line with a human-readable prefix, plus comment lines the parser
ignores:

```
# hpqc public key -- safe to share
# algorithms: X25519 + ML-KEM-768 (FIPS 203)
# key id: dc367bffcdf81019
hpqc-pk1AS9ky...
```

| Prefix | Contents |
| --- | --- |
| `hpqc-pk1` | encryption public key |
| `hpqc-sk1` | encryption private key |
| `hpqc-spk1` | signing public key |
| `hpqc-ssk1` | signing private key |
| `hpqc-wsk1` | any private key, passphrase-wrapped |

The decoded blob starts with one type byte: 1 for X25519 + ML-KEM-768, 2 for
X448 + ML-KEM-1024. Signing keys have only ever had one algorithm pair, so their
leading byte is still a format version.

| Key | Blob layout | Bytes |
| --- | --- | ---: |
| Encryption public, type 1 | type, X25519 (32), ML-KEM-768 (1184) | 1217 |
| Encryption public, type 2 | type, X448 (56), ML-KEM-1024 (1568) | 1625 |
| Encryption private, type 1 | type, X25519 (32), ML-KEM seed (64) | 97 |
| Encryption private, type 2 | type, X448 (56), ML-KEM seed (64) | 121 |
| Signing public | version, Ed25519 (32), ML-DSA-65 (1952) | 1985 |
| Signing private | version, Ed25519 (32), ML-DSA seed (32) | 65 |

Private keys hold the ML-KEM seed, 64 bytes of FIPS 203 `d||z`, rather than the
expanded key. The expanded form is derived deterministically on load. The seed
is the same length for every parameter set, which is why the type byte cannot be
inferred from the blob's length.

Private key files are written at mode 0600 through a temporary file and a
rename, so an interrupted write cannot leave a key half-written or gone, and
writing over an existing key cannot inherit its permissions.

## Wrapped private keys

A passphrase-wrapped key is `hpqc-wsk1` plus a 37-byte header and a sealed blob:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | wrap format version, `1` |
| 1 | 1 | kind: 1 encryption identity, 2 signing identity |
| 2 | 1 | KDF id, 1 for scrypt |
| 3 | 1 | scrypt log2(N) |
| 4 | 1 | scrypt r |
| 5 | 1 | scrypt p |
| 6 | 1 | AEAD id, 1 for ChaCha20-Poly1305 |
| 7 | 16 | scrypt salt |
| 23 | 12 | AEAD nonce |
| 35 | 2 | length of the sealed blob |
| 37 | ... | ChaCha20-Poly1305 over the key blob |

The whole header is the AEAD's associated data, so the cost parameters cannot
be edited without the tag failing. They are also bounded before scrypt runs: a
file asking for more than 1 GiB is refused rather than allocated.

The kind byte says encryption or signing and nothing else. Which KEM an
encryption identity uses is the first byte of the sealed blob, so `hpqc info`
on a wrapped key does not name algorithms it cannot see.
