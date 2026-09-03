# hpqc — hybrid post-quantum file encryption

A small command-line tool that encrypts files and messages to a public key
using **X25519 + ML-KEM-768** together, derives one key from both with
**HKDF-SHA256**, and seals the payload with an **AEAD**
(ChaCha20-Poly1305 or AES-256-GCM).

```console
$ hpqc keygen -o alice
private key: alice.key  (mode 0600 -- keep it secret)
public key:  alice.pub   (share this)
key id:      dc367bffcdf81019

$ hpqc encrypt -r alice.pub report.pdf -o report.pdf.hpqc
$ hpqc decrypt -k alice.key report.pdf.hpqc -o report.pdf
```

## Why hybrid

An attacker recording your traffic today can store it until a
cryptographically relevant quantum computer exists, then decrypt it. That is
**harvest-now-decrypt-later**, and it makes today's X25519-only encryption a
problem for anything that must stay secret for a decade.

Switching to ML-KEM alone trades one risk for another: lattice cryptography is
far younger than elliptic curves, and its implementations are newer still.

Hybrid takes neither bet. Both KEMs run, both shared secrets feed the same key
derivation, and the file stays secret unless **both** are broken:

| Attacker | X25519 | ML-KEM-768 | hpqc |
| --- | --- | --- | --- |
| Classical, today | safe | safe | safe |
| Breaks ML-KEM (cryptanalysis) | safe | **broken** | safe |
| Has a quantum computer | **broken** | safe | safe |
| Breaks both | broken | broken | broken |

## Install

Requires Python 3.9+ and `cryptography` 46 or newer **built against OpenSSL
3.5+** — that is where ML-KEM lives. See [Backend requirements](#backend-requirements).

```console
python -m venv .venv && . .venv/bin/activate
pip install -e .
```

## Usage

```
hpqc keygen  [-o BASENAME] [--force]     write BASENAME.key + BASENAME.pub
hpqc encrypt -r RECIPIENT.pub [INPUT] [-o OUT] [--aead chacha20|aes]
hpqc decrypt -k IDENTITY.key  [INPUT] [-o OUT]
hpqc info    [INPUT]                     describe a container or a key file
```

`INPUT` defaults to stdin and `-o` to stdout, so everything pipes:

```console
$ echo "meet me at dawn" | hpqc encrypt -r alice.pub | hpqc decrypt -k alice.key
meet me at dawn
```

`hpqc info` reads a container's header without needing the private key:

```console
$ hpqc info report.pdf.hpqc
type:        hpqc container
version:     1
suite:       X25519+ML-KEM-768/ChaCha20-Poly1305 (0x01)
recipient:   key id dc367bffcdf81019
header:      1168 bytes (authenticated as AAD)
kem ct:      1088 bytes
payload:     100016 bytes (ciphertext + 16-byte tag)
```

## How it works

### Encryption

```
                 recipient.pub = (X25519 pk, ML-KEM-768 ek)
                                   |
       +---------------------------+---------------------------+
       |                                                       |
  X25519 ECDH                                          ML-KEM-768 Encaps
  ephemeral keypair                                    (FIPS 203)
       |                                                       |
   ss_x (32 B)  + epk (32 B, in header)      ss_m (32 B) + ct (1088 B, header)
       |                                                       |
       +----------------------+--------------------------------+
                              |
                    ikm = ss_m || ss_x   (64 B)
                              |
        HKDF-SHA256(ikm, salt=random 16 B, info=transcript) -> 32-byte key
                              |
              AEAD(key, nonce, plaintext, aad = entire header)
                              |
                     header || ciphertext || tag
```

Decryption is the mirror image: X25519 with the stored ephemeral public key,
ML-KEM decapsulation with the stored ciphertext, the same HKDF, then the tag
check.

### Three details that are easy to get wrong

**1. Raw Diffie-Hellman output is not a key.** X25519 gives you a uniformly
random *group element*, not uniformly random bits. Feeding it straight into a
cipher is a classic mistake. HKDF-Extract is what turns two structured secrets
into 32 uniform bytes — and it is also the only clean way to mix two secrets
from different families. See [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869).

**2. The transcript is bound into the derivation.** HKDF's `info` covers the
suite id, the ephemeral public key, the ML-KEM ciphertext, and both of the
recipient's public keys:

```
info = "hpqc-v1 hybrid x25519+ml-kem-768" || suite || epk || kem_ct
                                           || recipient_x25519_pk
                                           || recipient_mlkem_pk
```

Every field is fixed-length, so plain concatenation is unambiguous — there is
no way to shift a byte from one field into the next and land on the same
`info`. A key derived for one message cannot validate for another.

**3. The entire header is the AEAD's associated data.** Suite id, key id, salt,
nonce, ephemeral key, KEM ciphertext — all authenticated. An attacker cannot
downgrade the suite byte, swap in a different ML-KEM ciphertext, or retarget
the recipient without the tag check failing. Nothing in the header is trusted
before that check passes.

### Nonces

The AEAD key is unique per file: a fresh ephemeral X25519 key, a fresh ML-KEM
encapsulation, and a fresh HKDF salt all feed every derivation. So the nonce
is never reused under a given key — the catastrophic AEAD failure mode is
ruled out by key freshness, not by nonce bookkeeping. The random 12-byte nonce
in the header is defence in depth.

### Implicit rejection

ML-KEM decapsulation never reports failure. FIPS 203 specifies *implicit
rejection*: a corrupted ciphertext silently yields a different shared secret
rather than an error. That is deliberate — an explicit failure would hand the
attacker a decryption oracle. The AEAD tag is what actually rejects a bad
file, and it does so without revealing *which* part was wrong.

## File format

`.hpqc` containers are `header || AEAD ciphertext || 16-byte tag`. All
integers are big-endian.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic, `HPQC` |
| 4 | 1 | format version, `1` |
| 5 | 1 | cipher suite id |
| 6 | 2 | flags, reserved, must be 0 |
| 8 | 8 | recipient key id (truncated SHA-256) |
| 16 | 16 | HKDF salt |
| 32 | 12 | AEAD nonce |
| 44 | 2 | length of the ephemeral X25519 public key (32) |
| 46 | 32 | ephemeral X25519 public key |
| 78 | 2 | length of the ML-KEM-768 ciphertext (1088) |
| 80 | 1088 | ML-KEM-768 ciphertext |
| 1168 | … | AEAD ciphertext, then a 16-byte tag |

Fixed overhead is **1184 bytes** per file, whatever its size.

Suite ids: `0x01` = X25519+ML-KEM-768/ChaCha20-Poly1305,
`0x02` = X25519+ML-KEM-768/AES-256-GCM.

Variable-size fields carry a length prefix even though v1 only ever emits 32
and 1088, so a future ML-KEM-1024 suite drops in without a parser change.

The **key id** is a truncated SHA-256 over *both* public keys. It exists so the
tool can say "this file is not for that key" instead of failing with a generic
tag error. It is a usability hint, never an access control.

### Key files

One base64 line with a readable prefix, plus comment lines the parser ignores:

```
# hpqc public key -- safe to share
# algorithms: X25519 + ML-KEM-768 (FIPS 203)
# key id: dc367bffcdf81019
hpqc-pk1AR2VuZXJhdGVkLi4u...
```

Private key files are written with mode `0600` and hold the ML-KEM **seed**
(64 bytes, the FIPS 203 `d‖z`) rather than the 2400-byte expanded key — the
expanded form is derived deterministically on load. A private key file is
252 bytes; a public key file is 1740.

An identity is always *both* algorithms. They are generated, stored, and
fingerprinted as one unit, because letting them travel separately is exactly
how you end up shipping a "hybrid" scheme an attacker can downgrade.

## Backend requirements

ML-KEM comes from `cryptography.hazmat.primitives.asymmetric.mlkem`, which
needs `cryptography` ≥ 46 built against OpenSSL ≥ 3.5. To check:

```console
$ python -c "from cryptography.hazmat.backends.openssl.backend import backend; print(backend.openssl_version_text())"
OpenSSL 4.0.2 25 Aug 2026
$ python -c "from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey; print('ok')"
ok
```

If either fails, `hpqc` says so with an actionable message rather than an
ImportError from deep inside a key operation. Upgrade with
`pip install --upgrade 'cryptography>=46'`.

No `liboqs` build is required.

## Testing

```console
$ pip install -e '.[dev]'
$ pytest
98 passed
```

The suite is mostly negative tests, because that is where a crypto tool
actually fails. Among them:

- **Both shared secrets reach the key.** Flip a bit in either half of the
  keying material and the derived key must change. This is the test that
  catches a "hybrid" that quietly computes the post-quantum secret, stores it
  in the header, and then leaves it out of the derivation.
- **A valid foreign KEM ciphertext cannot be spliced in.** Substituting
  another *legitimate* encapsulation to the same recipient decapsulates
  cleanly, so nothing upstream complains — only the binding makes it fail.
- **Downgrading the suite byte fails.** It is covered by both the AAD and the
  HKDF transcript.
- **One flipped bit anywhere is caught**, at every header field and in the
  payload.
- **Truncated headers never read past the end**, at a range of lengths.
- **Low-order X25519 points are refused cleanly.** OpenSSL rejects the points
  that force an all-zero shared secret with a bare `ValueError`; a crafted
  header must produce an ordinary error message, not a traceback. Both the
  header field and a hostile `.pub` file are covered.
- **Mutation fuzzing.** Randomly corrupted and truncated containers must always
  fail as an `HpqcError` and never decrypt. This is the check that catches a
  future header field parsed without a bounds check — the kind of bug that
  passes every hand-written test while turning a malformed file into a crash.
- **Nothing is written on failure** — a rejected file leaves no partial
  plaintext behind.

## Scope and limitations

What this does: confidentiality and integrity of a file, to a recipient's
public key, against an attacker who records now and decrypts later.

What it does **not** do, by design in v1:

- **No sender authentication.** Anyone with your public key can produce a
  valid file. There is no signature, so "who sent this" is unanswered. Signing
  with ML-DSA is the natural v2.
- **No streaming.** The whole plaintext is held in memory. Chunked AEAD with a
  counter nonce and an explicit final-chunk marker is what the reserved
  `flags` field is for.
- **No passphrase on private keys.** They sit on disk protected only by file
  permissions, like `age` identity files.
- **Single recipient per file.**
- **Not audited.** This is a learning and portfolio project, written against
  the standards below. Read the code before trusting it with anything real.

## Roadmap

- [ ] ML-DSA-65 signatures for sender authentication
- [ ] Streaming / chunked AEAD for large files
- [ ] Passphrase-wrapped private keys (scrypt + AEAD)
- [ ] Multiple recipients per file
- [ ] ML-KEM-1024 suite
- [ ] Known-answer test vectors checked into the repo

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) — Elliptic Curves for Security (X25519)
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) — HKDF
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) — ChaCha20 and Poly1305
- [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) — a hybrid KEM combiner; `hpqc` uses the same `ss_m ‖ ss_x` ordering
- [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/) — hybrid key exchange in TLS 1.3

## License

MIT — see [LICENSE](LICENSE).
