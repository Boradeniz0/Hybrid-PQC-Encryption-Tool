# hpqc — hybrid post-quantum file encryption

[![CI](https://github.com/Boradeniz0/Hybrid-PQC-Encryption-Tool/actions/workflows/ci.yml/badge.svg)](https://github.com/Boradeniz0/Hybrid-PQC-Encryption-Tool/actions/workflows/ci.yml)

A small command-line tool that encrypts files and messages to a public key
using **X25519 + ML-KEM-768** together, derives one key from both with
**HKDF-SHA256**, and seals the payload with an **AEAD**
(ChaCha20-Poly1305 or AES-256-GCM). Sender authentication is optional and
hybrid in the same way: **Ed25519 + ML-DSA-65**, both required.

```console
$ hpqc keygen -o alice
private key: alice.key  (mode 0600 -- keep it secret)
public key:  alice.pub   (share this)
key id:      dc367bffcdf81019

$ hpqc encrypt -r alice.pub report.pdf -o report.pdf.hpqc
$ hpqc decrypt -k alice.key report.pdf.hpqc -o report.pdf
```

Signing, if you want to answer "who sent this" as well:

```console
$ hpqc signgen -o bob-sign
signing private key: bob-sign.key  (mode 0600 -- keep it secret)
signing public key:  bob-sign.pub   (give this to recipients)
key id:              1322446e7dc517ec

$ hpqc encrypt -r alice.pub report.pdf -o report.pdf.hpqc -s bob-sign.key
$ hpqc decrypt -k alice.key report.pdf.hpqc -o report.pdf --sender bob-sign.pub
signature ok: signed by key id 1322446e7dc517ec
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

Requires Python 3.9.2+ and `cryptography` 46 or newer **built against OpenSSL
3.5+** — that is where ML-KEM lives. See [Backend requirements](#backend-requirements).

To use the tool:

```console
pipx install git+https://github.com/Boradeniz0/Hybrid-PQC-Encryption-Tool
hpqc --help
```

To work on it:

```console
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

The floor is 3.9.**2**, not 3.9.0: `cryptography>=46` declares
`!=3.9.0,!=3.9.1`, so on those two patch releases the dependency cannot
resolve at all.

## Usage

```
hpqc keygen  [-o BASENAME] [--force]     write BASENAME.key + BASENAME.pub
hpqc signgen [-o BASENAME] [--force]     the same, for a signing key pair
hpqc encrypt -r RECIPIENT.pub [INPUT] [-o OUT] [--aead chacha20|aes]
                                         [-s SIGNING.key]
hpqc decrypt -k IDENTITY.key  [INPUT] [-o OUT] [--sender SIGNER.pub]
hpqc info    [INPUT]                     describe a container or a key file
```

Everything about a signature goes to **stderr**, never stdout: stdout may be
the plaintext, and a status line mixed into it would corrupt
`hpqc decrypt file > out`.

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
signed:      no
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

## Sender authentication

By default a `.hpqc` file proves nothing about who wrote it: anybody holding
your public key can produce one. Pass `-s SIGNING.key` and the payload is
signed; pass `--sender SIGNER.pub` when decrypting and the signature is
checked. Three choices in that design have a wrong version that looks fine.

### Hybrid again, but for one reason instead of two

The KEM is hybrid because of harvest-now-decrypt-later. That argument does not
apply to signatures — a forgery in 2040 cannot retroactively change what a
recipient verified today. The *other* half of the hybrid argument does apply:
ML-DSA is young, and if lattice signatures fall to cryptanalysis a PQ-only
signature becomes forgeable **now**. So Ed25519 and ML-DSA-65 both sign the
same message and both must verify. Either one failing rejects the file.

### Sign, then encrypt

The signature and the sender's public keys live *inside* the AEAD payload.
Signing the ciphertext instead would prove only who transmitted the bytes, and
would publish the sender's identity to anyone holding the file. This way the
signer is confidential — `hpqc info` genuinely cannot say who signed, and
neither can an eavesdropper:

```console
$ hpqc info report.pdf.hpqc | tail -1
signed:      yes (signer is encrypted; decrypt to see who)
```

### The recipient is bound into the signed message

Sign only the plaintext and you get **surreptitious forwarding**
(Davis, 2001): Bob receives a signed file from Alice, decrypts it, re-encrypts
the same plaintext *and the same signature* to Carol, and Carol sees a file
that verifies as "Alice wrote this to me". The AEAD cannot help — Bob builds a
fresh, perfectly valid one. So the recipient's public keys go inside what gets
signed:

```
signed message = "hpqc-v1 sender authentication" || suite
              || sender_ed25519_pk   || sender_mldsa_pk
              || recipient_x25519_pk || recipient_mlkem_pk
              || plaintext
```

Carol recomputes that with her own keys, gets a different message, and
verification fails. The sender's own keys are in there too, so a signature
cannot be lifted onto a different claimed identity.

### What a valid signature actually proves

**Nothing about identity, unless you supplied the sender's public key.** The
file carries the signer's keys, so a signature that verifies against *those*
proves only that whoever encrypted the file also held some signing key — which
they could have generated a second earlier. That is why `hpqc decrypt` says so
out loud:

```console
$ hpqc decrypt -k alice.key report.pdf.hpqc -o report.pdf
warning: signed by key id 1322446e7dc517ec; pass --sender to verify the signer's identity
```

With `--sender` the embedded keys are compared against the ones you pinned, and
a mismatch is an error. Getting that key to you is out of scope — hpqc has no
key distribution, no web of trust, no TOFU store. Asking for verification of an
unsigned file is also an error rather than a shrug: authentication requested and
not delivered fails closed.

### Cost

| | Unsigned | Signed |
| --- | ---: | ---: |
| Header | 1168 | 1168 |
| Signature block | — | 5365 |
| AEAD tag | 16 | 16 |
| **Total overhead** | **1184** | **6549** |

Post-quantum signatures are simply large: ML-DSA-65 alone is 3309 bytes of
that, and its verifying key another 1952.

## File format

`.hpqc` containers are `header || AEAD ciphertext || 16-byte tag`. All
integers are big-endian.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic, `HPQC` |
| 4 | 1 | format version, `1` |
| 5 | 1 | cipher suite id |
| 6 | 2 | flags; bit 0 = payload is signed, other bits reserved |
| 8 | 8 | recipient key id (truncated SHA-256) |
| 16 | 16 | HKDF salt |
| 32 | 12 | AEAD nonce |
| 44 | 2 | length of the ephemeral X25519 public key (32) |
| 46 | 32 | ephemeral X25519 public key |
| 78 | 2 | length of the ML-KEM-768 ciphertext (1088) |
| 80 | 1088 | ML-KEM-768 ciphertext |
| 1168 | … | AEAD ciphertext, then a 16-byte tag |

Fixed overhead is **1184 bytes** per file, whatever its size — 6549 if it is
signed.

Sender authentication claimed bit 0 of the reserved `flags` field, which is what
it was there for, so the format version did not have to move. An older build
meets a signed file, sees a flag bit it does not implement, and refuses it by
name rather than decrypting something it only half understands; this build still
reads every unsigned file written before signing existed. Unknown flag *bits*
are refused; known ones are not a free pass, because the whole header is
associated data — setting bit 0 on an unsigned file gets past the flag check and
straight into a tag failure.

When bit 0 is set, the decrypted payload begins with a signature block:

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
| 5365 | … | plaintext |

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

Signing keys are a separate pair of types with their own prefixes,
`hpqc-ssk1` and `hpqc-spk1`. They are deliberately not folded into the
encryption identity: a key should do one job, signing stays opt-in, and
existing encryption keys keep working untouched. Within a signing identity the
same all-or-nothing rule applies — Ed25519 and ML-DSA-65 travel together. The
private file holds the 32-byte ML-DSA seed and is 217 bytes; the public file is
2773. Both key ids are truncated SHA-256, under **different** domain strings,
so an encryption identity and a signing identity can never print the same one
and be mistaken for each other.

## Backend requirements

ML-KEM and ML-DSA come from `cryptography.hazmat.primitives.asymmetric`, which
needs `cryptography` ≥ 46 built against OpenSSL ≥ 3.5. To check:

```console
$ python -c "from cryptography.hazmat.backends.openssl.backend import backend; print(backend.openssl_version_text())"
OpenSSL 4.0.2 25 Aug 2026
$ python -c "from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey; print('ok')"
ok
$ python -c "from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey; print('ok')"
ok
```

If any of these fails, `hpqc` says so with an actionable message rather than an
ImportError from deep inside a key operation. Upgrade with
`pip install --upgrade 'cryptography>=46'`. The two are probed separately, so a
stack that can encrypt but not sign is refused only when you ask it to sign.

No `liboqs` build is required.

## Testing

```console
$ pip install -e '.[dev]'
$ pytest
222 passed
```

CI runs the same suite on Python 3.9, 3.11, 3.13 and 3.14, prints the OpenSSL
version and ML-KEM availability it actually tested against, and then drives the
*installed* `hpqc` binary through a keygen/encrypt/decrypt round trip — the
unit tests call click in-process, so they would still pass with a broken
console-script entry point.

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
- **Frozen known-answer vectors.** `tests/vectors/v1.json` holds containers
  produced by an earlier build together with the identity that opens them.
  Every other test checks that hpqc agrees with *itself*, which cannot catch
  the one change that matters most to anyone who already has encrypted files: a
  refactor that alters the header layout or the derivation in a way both sides
  agree on. Reverse the combiner to `ss_x ‖ ss_m` and every self-consistency
  test still passes — only the vectors notice. Encryption is not reproducible
  (nothing random in it is injectable), so the vectors are verified on the
  deterministic decryption side.
- **Both signatures are required.** Break the ML-DSA half of a payload and the
  file must still be refused; break the Ed25519 half and the same. Without both
  halves of this pair the scheme is hybrid-shaped rather than hybrid — the
  signature counterpart of the shared-secret test above.
- **Surreptitious forwarding is blocked.** A signature made for Bob, re-sealed
  to Alice byte for byte, must not verify — with or without a pinned sender
  key. Paired with a test that the original recipient *can* verify the same
  bytes, so it cannot pass because something is merely broken.
- **The signature block is fuzzed separately.** Corrupting a finished signed
  container trips the AEAD tag first, so those mutations never reach the
  signature parser. Mutating the payload *before* sealing it does — and that is
  also the realistic threat, since the sender chooses the payload.
- **The signed-message construction is pinned by digest.** Recorded signatures
  cannot do this; see below.
- **The signature notice never lands on stdout.** stdout is the plaintext.

## What building this turned up

Three bugs the tests and the packaging found. None is visible from reading the
happy path, which is the point.

**A private key file could stay world-readable.** The mode argument to
`os.open(path, ..., 0o600)` applies only to files it *creates*. So
`hpqc keygen --force` over a key that already existed as mode 0644 left it at
0644 — the new secret inherited the old file's permissions. The fix is an
explicit `os.fchmod` on the descriptor. The test that caught it creates a
world-readable file first and *then* overwrites it; a test that only checked a
fresh keygen would have passed forever.

**A crafted header could produce a traceback instead of an error.** X25519 has
low-order points — values that force an all-zero shared secret whatever the
private key is. OpenSSL refuses them, but it does so with a bare
`ValueError: Error computing shared key.`, and the ephemeral public key in a
`.hpqc` header is entirely attacker-controlled. 32 zero bytes at offset 46 was
enough to crash `hpqc decrypt` with a stack trace. That is not a break of
confidentiality, but a parser that crashes on chosen input is the wrong shape,
and a hostile `.pub` file reached the same code from the other direction. Both
now go through one `_exchange` helper that converts it to a `FormatError`.

**A frozen negative vector proved less than it looked.** Adding sender
authentication, I recorded a container whose signature was made for a different
recipient, expecting it to guard against surreptitious forwarding for good. It
does not. Deleting the recipient from the signed message — the exact regression
it was supposed to catch — left that vector still failing, because a signature
recorded under the old construction does not verify under a new one either. It
was rejecting the file for the wrong reason, and would have gone on "passing"
while the property it guarded was gone. A recorded *signature* cannot pin a
construction; only a recorded *digest of the signed message* can. So the vectors
now carry both, and the negative one is documented as guarding something
narrower: a build that accepts forwarded containers outright. Checking that a
test fails when you break the thing it tests is the only way to find this.

**The declared Python floor was wrong.** `requires-python = ">=3.9"` looked
fine and was not: `cryptography>=46` declares `!=3.9.0,!=3.9.1`, so on those
releases `pip install` fails in the resolver rather than with a useful message.
Setting up the CI matrix is what surfaced it.

## Scope and limitations

What this does: confidentiality and integrity of a file, to a recipient's
public key, against an attacker who records now and decrypts later — and,
optionally, authentication of who sent it.

What it does **not** do, by design in v1:

- **No key distribution.** Verifying a sender means already having their
  signing public key, obtained some other way. There is no web of trust, no
  TOFU store, no directory. A signature checked only against the key inside the
  file proves consistency, not identity, and the tool says so.
- **No streaming.** The whole plaintext is held in memory. Chunked AEAD with a
  counter nonce and an explicit final-chunk marker is the next flag bit.
- **No passphrase on private keys.** They sit on disk protected only by file
  permissions, like `age` identity files.
- **Single recipient per file.**
- **Not audited.** This is a learning and portfolio project, written against
  the standards below. Read the code before trusting it with anything real.

## Roadmap

- [x] ML-DSA-65 signatures for sender authentication
- [ ] Streaming / chunked AEAD for large files
- [ ] Passphrase-wrapped private keys (scrypt + AEAD)
- [ ] Multiple recipients per file
- [ ] ML-KEM-1024 suite
- [x] Known-answer test vectors checked into the repo

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — Module-Lattice-Based Digital Signature Standard (ML-DSA)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) — Elliptic Curves for Security (X25519)
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) — EdDSA (Ed25519)
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) — HKDF
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) — ChaCha20 and Poly1305
- [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) — a hybrid KEM combiner; `hpqc` uses the same `ss_m ‖ ss_x` ordering
- [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/) — hybrid key exchange in TLS 1.3
- Don Davis, *Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP, and XML* (USENIX Annual Technical Conference, 2001) — where surreptitious forwarding comes from

## License

MIT — see [LICENSE](LICENSE).
