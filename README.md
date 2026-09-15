# hpqc — hybrid post-quantum file encryption

[![CI](https://github.com/Boradeniz0/Hybrid-PQC-Encryption-Tool/actions/workflows/ci.yml/badge.svg)](https://github.com/Boradeniz0/Hybrid-PQC-Encryption-Tool/actions/workflows/ci.yml)

A small command-line tool that encrypts files and messages to a public key
using an elliptic curve **and** ML-KEM together, derives one key from both with
**HKDF-SHA256**, and seals the payload with an **AEAD**
(ChaCha20-Poly1305 or AES-256-GCM). Two parameter sets: **X25519 + ML-KEM-768**
by default, **X448 + ML-KEM-1024** on request. Sender authentication is optional and
hybrid in the same way: **Ed25519 + ML-DSA-65**, both required. Files larger
than a megabyte are encrypted as a chunked stream, so size is bounded by the
disk rather than by memory. A file can be addressed to several recipients at
once, and the header names none of them.

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

Several recipients, if the file is for more than one person:

```console
$ hpqc encrypt -r alice.pub -r bob.pub -r carol.pub minutes.txt -o minutes.hpqc
encrypted to 3 recipients; the file does not name them

$ hpqc info minutes.hpqc
recipients:  3 (the file does not name them)

$ hpqc decrypt -k bob.key minutes.hpqc -o minutes.txt
```

Private keys can be kept under a passphrase rather than file permissions alone:

```console
$ hpqc keygen -o alice --passphrase
passphrase for the new private key:
Repeat for confirmation:
private key: alice.key  (passphrase-protected -- keep it secret)
public key:  alice.pub   (share this)
key id:      dc367bffcdf81019
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
hpqc keygen  [-o BASENAME] [--force] [--kem mlkem768|mlkem1024]
                                         [-p | --passphrase-file F]
hpqc signgen [-o BASENAME] [--force] [-p | --passphrase-file F]
hpqc encrypt -r RECIPIENT.pub [-r ...] [INPUT] [-o OUT] [--aead chacha20|aes]
                                         [-s SIGNING.key] [--passphrase-file F]
                                         [--chunked | --one-shot]
                                         [--hide-recipients]
hpqc decrypt -k IDENTITY.key  [INPUT] [-o OUT] [--sender SIGNER.pub]
                                         [--passphrase-file F]
hpqc passwd  KEYFILE [--remove] [--passphrase-file F] [--new-passphrase-file F]
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
chunked:     no
signed:      no
```

For a streamed file it reports the framing instead, still without the key:

```console
$ hpqc info disk-image.hpqc
payload:     5001232 bytes
chunked:     yes, 77 chunk(s) of up to 64 KiB (+16-byte tag each)
plaintext:   5000000 bytes
signed:      no
```

And for a file with several recipients it reports how many there are, which is
all the file knows:

```console
$ hpqc info minutes.hpqc
recipients:  3 (the file does not name them)
header:      3600 bytes (authenticated as AAD)
kem ct:      1088 bytes x 3
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

A chunked file needs a nonce *per chunk*, and the same argument carries: the
counter only has to be unique within one file, because the key already is. See
[Large files](#large-files) for the construction.

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

When the file has a [recipient list](#several-recipients) there is no recipient
in it to bind, so the header is bound instead:

```
signed message = "hpqc-v1 sender authentication to a container" || suite
              || sender_ed25519_pk || sender_mldsa_pk
              || u32(len(header))  || header
              || plaintext
```

Two labels, so a signature made under one can never be presented as one made
under the other, and the header carries a length because it and the plaintext
are the only variable-length fields in the message.

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

## Passphrase-protected private keys

By default a private key file is protected by its mode alone, `0600`, like an
`age` identity file. That is a reasonable default and it is worth nothing the
moment the file leaves the machine — in a backup, a synced folder, a stolen
laptop. `--passphrase` (or `--passphrase-file`) derives a key from a passphrase
with **scrypt** and seals the private key under ChaCha20-Poly1305.

```console
$ hpqc info alice.key
type:       hpqc wrapped private key
contents:   X25519 + ML-KEM-768 private key
protection: scrypt N=2^17 r=8 p=1 (128 MiB)
key id:     unavailable without the passphrase
```

`hpqc passwd` adds, changes, or removes a passphrase. The key itself never
changes, so the public key and the key id stay exactly as they were — without
that, changing a passphrase would mean a new identity and everyone holding your
public key having to fetch a new one.

### A key file is untrusted input

The cost parameters travel inside the file, so raising the default later does not
strand keys written today, and someone on a small machine can turn it down with
`--scrypt-log-n`. That also means a *file* can claim any parameters it likes. A
key file asking for N=2²³ at r=8 wants 8 GiB of memory, and reading a key file
must not be a way to take a machine down — so the parameters are validated
against a memory ceiling **before** scrypt is called, not after.

The whole wrapper header is the AEAD's associated data, prefixed by a domain
label. Worth being precise about what that buys, because it is less than it first
appears: the scrypt parameters and the salt are covered twice over, since
changing them changes the derived key and the tag would fail regardless. What the
AAD *alone* protects are the fields that never reach the KDF — the kind byte, the
format version, the algorithm ids, the sealed length. Relabelling a wrapped
encryption identity as a signing key is the case that isolates it.

### Two details that would otherwise bite

**There is deliberately no `--passphrase VALUE` option.** Command lines are
visible to every user on the machine through `ps`. Prompting and
`--passphrase-file` are the two ways in.

**Passphrases are NFC-normalised** before being encoded to UTF-8. "é" is one
code point or two depending on where it was typed, so without normalisation a
key wrapped on one system would simply not open on another, with nothing in the
error to suggest why.

Defaults are N=2¹⁷, r=8, p=1 — 128 MiB and roughly a third of a second. A
wrapped identity file is 347 bytes against 252 unwrapped; a wrapped signing key
315 against 217.

## Large files

One-shot encryption has a ceiling that has nothing to do with cryptography:
`AEAD.encrypt` takes a `bytes`, so the whole plaintext *and* the whole
ciphertext are resident at once. Encrypting a 200 MB file that way costs
620 MB of memory. Past a megabyte, `hpqc` splits the plaintext into 64 KiB
chunks and seals each one separately:

| | peak memory | time |
| --- | ---: | ---: |
| 200 MB, streamed | **35 MB** | 0.26 s |
| 200 MB, `--one-shot` | 620 MB | 0.74 s |

35 MB is the interpreter and the library; a 5 MB file measures the same, so the
cost is flat in the size of the input. `--chunked` and `--one-shot` force
either shape, and decryption never needs to be told — the choice is a flag bit
in the header.

Chunking naively breaks three things the one-shot version had for free, and
each has a wrong version that looks like it works.

**A nonce per chunk that cannot collide.** Reusing one nonce across chunks
under one key is the catastrophic case for both AEADs here: it leaks the XOR of
the plaintexts and hands over the authentication key.

**Truncation has to be detectable.** Seal each chunk independently and an
attacker deletes the last one. Every remaining chunk still verifies and the
recipient gets a shorter file with *no error at all* — "transfer the first half
of the bank statement" is a complete forgery built with a text editor.

**Reordering and splicing have to be detectable.** Chunks are individually
valid ciphertexts, so swapping two, repeating one, or pasting one in from
another file encrypted to the same recipient must all fail.

All three are handled by the **STREAM** construction of Hoang, Reyhanitabar,
Rogaway and Vizár (CRYPTO 2015). The 12-byte nonce is built per chunk:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 7 | per-file nonce prefix (the header's nonce field) |
| 7 | 4 | chunk counter, big-endian, from 0 |
| 11 | 1 | `0x01` on the last chunk, `0x00` on every other |

That last byte is the whole of the truncation defence. Delete the final chunk
and the new last chunk was sealed as "not final" but must now be opened as
"final" — a different nonce, so the tag fails. Append one and the old final
chunk fails the same way in reverse. Swap two and the counters no longer match.
And the key is derived per file, so a chunk lifted from another container fails
regardless of what its counter says.

The counter is 32 bits, giving 2³² chunks of 64 KiB — 256 TiB per file. Reaching
it is refused rather than allowed to wrap, because wrapping means nonce reuse.

Overhead is 16 bytes per chunk on top of the 1168-byte header: 0.024%
asymptotically, and 0.025% on a 200 MB file — the header is what still
shows at 5 MB, where it comes to 0.048%.

### What streaming gives up

**Decryption releases plaintext before the whole file is authenticated.** Chunk
3 is written out before chunk 4 is known to verify. A one-shot container is
all-or-nothing; a stream cannot be, and no amount of engineering changes that —
it is what "streaming" means. What the tool can do is make sure the incomplete
output is never mistaken for the real thing, so `hpqc decrypt` writes to a
temporary file and renames it over the target only once the last chunk has
verified. A truncated file leaves no output at all. Decrypting to a pipe is the
case where the caveat still bites, and the tool says so on stderr.

**Signing a stream costs a second read, not the memory.** A signature is a
statement about a whole message, and a chunked writer never holds one. So it
signs a *digest* of the plaintext, computed in a first pass over the input —
which means the input has to be one that can be read twice:

| 200 MB, signed | encrypt peak RSS | decrypt + verify peak RSS |
| --- | ---: | ---: |
| streamed | **35 MB** | **34 MB** |
| `--one-shot` | 816 MB | 1010 MB |

The signature block goes **in front of** the plaintext, not in a trailer, and
that is the decision worth defending. A trailer buys a single pass and costs
the reader everything it could have known early: the claimed signer would
arrive only after the last chunk had already been written out, so `--sender`
could not refuse a file until the file had been delivered. With the block in
front, a reader checks the claimed identity before releasing a single byte:

```console
$ hpqc decrypt -k alice.key big.hpqc -o out.bin --sender impostor.pub
error: this file was signed by key id 94cb82d7..., but verification was
requested against d8fd44dc...
$ ls out.bin
ls: cannot access 'out.bin': No such file or directory
```

What still waits for the end is unavoidable, and it is the honest cost of
streaming anything: **plaintext is released before the signature over it has
been checked.** The mitigation is the one streaming already needed — decryption
writes to a temporary file and renames it only on success, so an unverified
stream never appears under the name you asked for. A pipe is where the caveat
bites, and the tool says so.

The digest is **SHA-512**, and that is deliberate. Signing a digest makes the
signature only as collision-resistant as the hash: find two plaintexts sharing
one digest and a single signature covers both. SHA-256 would put that at 2¹²⁸
classically and lower against a quantum collision search — a quiet halving of
the security of a scheme whose whole premise is being conservative about the
future.

**stdin is the one input that cannot be signed as a stream**, because it
arrives once:

```console
$ cat disk.img | hpqc encrypt -r bob.pub -s alice.key -o out.hpqc
note: signing a stream reads the input twice and stdin arrives once;
writing a one-shot container instead
```

## Several recipients

One file, several people who can open it. The obvious approach does not work:
the AEAD key is derived straight from the KEM output, and there is no way to
make two independent encapsulations, to two different public keys, arrive at
the same key. So the file gains one level of indirection, the same one PGP,
CMS and age all use:

1. Pick a random **file key**. This is what seals the payload.
2. For each recipient, run the hybrid KEM against their public key and derive a
   **wrapping key** from the result.
3. Seal the file key under each wrapping key. Each sealed copy is a **stanza**,
   and the header carries one per recipient.

```console
$ hpqc encrypt -r alice.pub -r bob.pub -r carol.pub minutes.txt -o minutes.hpqc
encrypted to 3 recipients; the file does not name them
```

### The stanzas do not say who they are for

There is no key id in a stanza. A recipient list in the clear tells anyone
holding the file who else was in the conversation, and for a group message that
is frequently worth more than the contents — it is proof that a particular set
of people were talking. So the reader instead *tries* each stanza in turn and
keeps the one that opens; the AEAD tag is the test.

What the file still leaks is **how many** recipients there are, which is why
`hpqc info` reports a count and nothing else:

```console
$ hpqc info minutes.hpqc
recipients:  3 (the file does not name them)
```

The cost is paid twice, and both halves are worth stating. Opening a file is
now O(recipients) decapsulations rather than O(1) — microseconds, and it does
not matter. And "wrong key" can no longer name the key the file was for,
because the file genuinely does not know:

```console
$ hpqc decrypt -k dave.key minutes.hpqc -o out.txt
error: none of this file's 3 recipient slot(s) could be opened with key id
26037352c3e3a2ce; it was encrypted for someone else
```

A single recipient keeps the older header, key id and all, because that shape
costs 84 bytes less and there is nothing to hide when there is one name. If you
want the same anonymity for one recipient, ask for it:

```console
$ hpqc encrypt -r alice.pub --hide-recipients report.pdf -o report.hpqc
```

### A wrapping key is used once, so its nonce is all zeros

A nonce exists to stop two messages being encrypted under one key. Every stanza
has a fresh ephemeral X25519 key and a fresh ML-KEM encapsulation behind it, so
its wrapping key is unique to that stanza and seals exactly one thing. A random
nonce here would add twelve bytes an attacker could fiddle with and buy nothing.

The wrapping key is derived under a **different HKDF label** from the payload
key, over the stanza's own ephemeral key and KEM ciphertext, the file's salt,
and the recipient's own two public keys. So a stanza cannot be moved to another
file or another recipient, and the key that wraps a file key can never collide
with the key that seals a payload.

### Every recipient gets the same file key, and the header proves it

ChaCha20-Poly1305 and AES-256-GCM are **not key-committing**. Given two keys, a
ciphertext can be built that decrypts successfully under both, to two different
plaintexts — the *invisible salamanders* result (Dodis, Grubbs, Ristenpart and
Woodage, CRYPTO 2018; Len, Grubbs and Ristenpart, USENIX 2021).

In a scheme like this one that hands a malicious **sender** something that looks
impossible. Wrap one file key to Bob and a different one to Carol, seal a single
crafted payload, and the two of them open the same file and read different
messages. Both see a valid tag. Signing does not help: the signature block is
inside the payload, so each view carries its own and both verify.

The fix is to take the choice away. The header carries a commitment to the file
key, and a recipient checks it the moment the key comes out of its stanza:

```
commitment = HKDF-SHA256(ikm=file_key, salt=header salt,
                         info="hpqc-v1 file key commitment" ‖ suite id)
```

Bob computes it over his file key, Carol over hers. Both have to equal the one
32-byte value in the header, which takes a collision in HKDF-SHA256 — so the
sender is forced to give everybody the same key, and the payload is then a
single message that either opens or does not. Whoever was handed the other key
is told what happened, rather than getting a tag failure that reads like
corruption:

```console
$ hpqc decrypt -k carol.key minutes.hpqc -o out.txt
error: this file's header does not commit to the key that came out of the
recipient list; the sender wrapped a different key for somebody else and may
have written them a different message
```

**It is mandatory, not offered.** A recipient list without the commitment is
refused rather than read as an older file, because the party who chooses
whether to commit is exactly the party this defends against. A defence the
attacker can decline to use is not a defence. The writer is held to the same
rule from the inside: no path through the library can produce an uncommitted
list.

That made every group container written before this change unreadable. They
were three commits old in an unreleased line, and the frozen vectors holding
them were kept exactly as they are — what they prove now is the refusal.

A single named recipient is untouched. One recipient means one KEM-derived key
and no file key at all, so the question does not arise, and every container
ever written to that shape still opens.

### Removing a recipient cannot be done quietly

The whole header is the payload's associated data, stanzas included. Strip
Bob's stanza to cut him out of a conversation and the file stops opening for
Alice too — she gets an authentication failure rather than a message that looks
exactly as it should. The attack is still a denial of service; what it is not
is silent.

### What it does not defend against

**Any recipient can re-send the file as if it came from you** — unless you sign
it. Everyone who can open the file has the file key, so any of them can decrypt
it, wrap the same key to somebody new, and produce a container the AEAD is
perfectly happy with. That is inherent to multi-recipient encryption; sender
authentication is the answer, and the next section is how it works when the
file names nobody.

### Signing a file that names no recipients

The usual anti-forwarding construction puts the recipient's public keys inside
the signed message (see [Sender authentication](#sender-authentication)). With
a recipient list there are none to put there, and the reader has none to
recompute with. Three things could go in their place:

- **One of the recipients.** Verifies for that person, fails for everybody
  else. Not a scheme.
- **The whole set, carried inside the AEAD.** Works, costs 1216 bytes per
  recipient, and tells every recipient who the others are — undoing the point
  of the shape. It is also only a *claim*: nothing would stop a sender listing
  two recipients and wrapping the file key for three.
- **The header itself, every stanza of it.** That is the delivery rather than a
  description of it, it costs nothing, and it cannot be a lie.

hpqc binds the header. Bob cannot re-address the file, because that means new
stanzas, a new salt and a new nonce, and Carol recomputes the signed message
over the header she actually received. He cannot strip a recipient, for the
same reason. And no recipient learns anything about the others.

The signature stops meaning "Alice wrote this to these people" and starts
meaning "**Alice wrote this, into this exact container**" — a narrower claim,
and the one that can actually be checked. The header is already the AEAD's
associated data, which is not the same thing: that binds it to the file key,
which every recipient holds. This binds it to Alice's signing key, which none
of them do.

```console
$ hpqc encrypt -r alice.pub -r bob.pub -r carol.pub minutes.txt \
    -o minutes.hpqc -s dave-sign.key
encrypted to 3 recipients; the file does not name them
signed by key id 1322446e7dc517ec

$ hpqc decrypt -k bob.key minutes.hpqc -o minutes.txt --sender dave-sign.pub
signature ok: signed by key id 1322446e7dc517ec
```

**Trial decryption is not constant time.** The loop stops at the first stanza
that opens, so how long a decryption takes reveals *which* slot is yours to
anyone able to measure it. Somebody holding only the file still learns nothing
but the count.

**The count is not padded.** Three recipients look like three recipients.
Padding the list to a fixed size would hide that too, at the cost of a header
sized for the largest group you ever send to.

## Two hybrid KEMs

| `--kem` | Diffie-Hellman | ML-KEM | NIST category | suite bytes |
| --- | --- | --- | ---: | --- |
| `mlkem768` (default) | X25519 | ML-KEM-768 | 3 | `0x01`, `0x02` |
| `mlkem1024` | X448 | ML-KEM-1024 | 5 | `0x03`, `0x04` |

```console
$ hpqc keygen -o alice --kem mlkem1024
private key: alice.key  (mode 0600 -- keep it secret)
public key:  alice.pub   (share this)
algorithms:  X448+ML-KEM-1024
key id:      ee3ad63ca7aa1000
```

**The classical half moves with the post-quantum half.** Pairing ML-KEM-1024
with X25519 would look like a stronger key and would not be one. The two halves
are combined so an attacker must break *both*, which means the pair is as
strong as its stronger half — so leaving the classical half at roughly 128 bits
while raising the lattice half to category 5 buys nothing against the attacker
the upgrade is meant for. X448 is what matches, and it costs 24 bytes of key
and one more scalar multiplication.

**`encrypt` has no `--kem`.** The KEM is not the sender's to choose: it is
whatever the recipient's key already is. `--aead` names an AEAD, the recipient's
key names a KEM, and the suite byte is where the two meet.

**One file, one KEM.** A container carries one suite byte, so it cannot be
addressed to an ML-KEM-768 recipient and an ML-KEM-1024 recipient at once:

```console
$ hpqc encrypt -r big.pub -r small.pub notes.txt -o notes.hpqc
Error: small.pub is X25519+ML-KEM-768 but big.pub is X448+ML-KEM-1024;
one file has one KEM, so these recipients need separate files
```

It *could* have been allowed — every stanza length-prefixes its own fields —
but only by letting a prefix **select** how the rest is read instead of being
checked against a value already known. That is the one thing this parser does
not do anywhere else, and the convenience is not worth the exception.

Which is the same reason the suite byte cannot be used to reinterpret a file.
It arrives unauthenticated — nothing has verified a tag when the parser reads
it — so relabelling a container fails on arithmetic, before a single key
operation runs:

```console
$ printf '\x01' | dd of=big.hpqc bs=1 seek=5 count=1 conv=notrunc
$ hpqc info big.hpqc
error: ephemeral X25519 public key is 56 bytes, expected 32 here
```

The field is named after the suite the file *claims*, because that is all the
parser has to go on — which is the point. It expected 32 bytes because byte 5
said X25519, and found 56.

**A key file says which it is, in one byte.** Type 1 is X25519 + ML-KEM-768;
type 2 is X448 + ML-KEM-1024. That byte was introduced as a *format version*
and never had a second value — and what a second parameter set needs it to say
is which key this is, not which revision. So it is a key type now, and type 1
is bit-for-bit what version 1 always was: every key file written before this
change still reads, unchanged.

The byte is not optional, either. A public key could be told apart by its
length, but a private key stores the ML-KEM **seed**, which FIPS 203 fixes at
64 bytes for every parameter set — so two private keys of different types
differ only in their Diffie-Hellman half, and length alone cannot separate
them.

## File format

`.hpqc` containers are a header followed by a payload in one of two shapes.
All integers are big-endian.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic, `HPQC` |
| 4 | 1 | format version, `1` |
| 5 | 1 | cipher suite id |
| 6 | 2 | flags; bit 0 = signed, bit 1 = chunked, bit 2 = recipient list, rest reserved |
| 8 | 8 | recipient key id (truncated SHA-256) |
| 16 | 16 | HKDF salt |
| 32 | 12 | AEAD nonce (chunked: first 7 bytes are the STREAM prefix) |
| 44 | 2 | length of the ephemeral DH public key (32, or 56) |
| 46 | 32 | ephemeral DH public key |
| 78 | 2 | length of the ML-KEM ciphertext (1088, or 1568) |
| 80 | 1088 | ML-KEM ciphertext |
| 1168 | … | payload |

Offsets past 44 are those of suite `0x01`. Both lengths come from the suite
byte, and a suite using X448 + ML-KEM-1024 makes them 56 and 1568, for a
1672-byte header.

With bit 1 clear the payload is one AEAD ciphertext followed by its 16-byte
tag, and fixed overhead is **1184 bytes** per file whatever its size — 6549 if
it is signed. With bit 1 set the payload is a sequence of chunks, each
`ChaCha20-Poly1305(64 KiB) || 16-byte tag`, every one of them full except the
last; overhead is 1168 plus 16 per chunk. Nothing frames the chunks, because a
length prefix would be attacker-controlled data read before authentication —
the reader knows the boundaries by counting.

With bit 2 set the file has more than one recipient (or one it declines to
name), and everything from offset 44 is replaced by a list:

| Offset | Size | Field |
| ---: | ---: | --- |
| 44 | 32 | commitment to the file key every stanza wraps |
| 76 | 2 | recipient count, 1…1024 |
| 78 | … | that many stanzas |
| … | … | payload |

Each stanza is `2+32` ephemeral X25519 public key, `2+1088` ML-KEM-768
ciphertext, `2+48` wrapped file key — 1174 bytes, and nothing that identifies
the recipient. The key id at offset 8 is all zeros, and a non-zero value there
is refused: a fixed field nothing reads is a place to smuggle bytes past
everyone who looks at the file with `info`.

That makes the header the first field in the format whose length depends on its
own contents. The reader neither seeks nor trusts a length it has not checked:
it reads 4 KiB, parses, and when the parser runs out it reports exactly how many
bytes the field it was reading is short by. At least that much is fetched and
the parse retried, up to a hard cap. Each round asks for at least as much again
as it already holds — fetching only the shortfall would be correct and
quadratic in a count the file's writer chooses.

Bit 2 and bit 3 must appear together or not at all: there is nothing for a
commitment to commit to without a file key, and a file key must never travel
without one. Either alone is refused. Bits 0 and 2 together are legal and change
which byte string the signatures cover — the recipient's public keys for a named
recipient, the whole header for a list.

Sender authentication claimed bit 0 of the reserved `flags` field, streaming
claimed bit 1, the recipient list claimed bit 2 and its file key commitment
claimed bit 3, which is what they were there for, so the format version has
never had to move. Bits 1 and 2 compose
without either knowing about the other — one is about the payload, the other
about the header — which is the payoff of putting both in the flags field
rather than in the version. An older build
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

A passphrase-protected private key uses one prefix for both kinds,
`hpqc-wsk1`, with a byte inside saying what it holds — one wrapper format
rather than a new key file type per key type:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | wrapper format version, `1` |
| 1 | 1 | inner key kind (1 = identity, 2 = signing identity) |
| 2 | 1 | KDF id, `1` = scrypt |
| 3 | 1 | scrypt log2(N) |
| 4 | 1 | scrypt r |
| 5 | 1 | scrypt p |
| 6 | 1 | AEAD id, `1` = ChaCha20-Poly1305 |
| 7 | 16 | scrypt salt |
| 23 | 12 | AEAD nonce |
| 35 | 2 | length of the sealed blob |
| 37 | … | sealed blob (ciphertext, then a 16-byte tag) |

The kind byte is in the clear on purpose. It costs nothing — the prefix already
said "private key" — and it lets `hpqc info` describe a file, and a wrong-file
mistake fail instantly, without a passphrase and without spending a third of a
second in the KDF first.

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
745 passed
```

CI runs the same suite on Python 3.9, 3.11, 3.13 and 3.14, prints the OpenSSL
version and ML-KEM availability it actually tested against, and then drives the
*installed* `hpqc` binary through a keygen/encrypt/decrypt round trip — the
unit tests call click in-process, so they would still pass with a broken
console-script entry point.

`tools/ci-local.sh` runs all of that, on every Python in the matrix, in docker:

```console
$ tools/ci-local.sh          # the whole matrix
$ tools/ci-local.sh 3.9      # just one
```

It reads the version list and the smoke test out of the workflow file rather
than restating them, so the local run cannot drift from the real one. One
Python is not a matrix, and finding that out from a red badge is slower than
finding it out here.

[TESTING.md](TESTING.md) walks through the same ground by hand, including the
cases that have to fail and a couple of deliberate breakages to watch the tests
catch.

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
  plaintext behind, including a stream that fails on its last chunk after
  writing everything before it.
- **Cut, paste and reorder a chunked file.** Truncating it, extending it,
  swapping two chunks, repeating one, and splicing in a chunk from a *different
  file encrypted to the same recipient* — five attacks that need no key and no
  cryptanalysis, only a text editor. Paired with a test that deliberately
  disables the final-chunk marker and asserts the truncation then *succeeds*,
  so the defence is named rather than assumed.
- **A failed stream never invents bytes.** Fuzzing a chunked container checks
  that whatever was released before the failure is a genuine prefix of the real
  plaintext, and never all of it.
- **Short reads are handled.** A pipe may return fewer bytes than asked for
  without being at EOF; the tests feed the reader seven bytes at a time, because
  a `BytesIO` would hide the bug and the symptom is a chunk split down the
  middle, which looks exactly like corruption.
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
- **And blocked on a file that names nobody, where the forger is a real
  recipient.** They hold the file key, so they can seal whatever they like
  under the header they received and the AEAD will not object — the test builds
  the forgery from the inside rather than by flipping bits. Two of them: the
  same signature re-addressed to somebody new, and a different message sealed
  under the original header. Both must fail; the original recipients must still
  succeed.
- **A signature cannot cross between the two constructions.** A classic
  signature replayed into a listed container, and the reverse.
- **The suite byte cannot reinterpret a container.** It arrives
  unauthenticated and decides how every field after it is read, so a
  relabelled file has to fail on arithmetic before a key operation runs — the
  test asserts decapsulation is never reached, and asserts it *is* reached on
  the untouched file so it cannot pass by never getting there. All 256 values
  of the byte are tried against containers of both parameter sets.
- **The KEM table is checked against the backend.** Every parser length is
  looked up from one table copied out of FIPS 203; a typo there produces a
  format that agrees with itself and with nothing else. The test generates a
  key of each parameter set and asserts the real sizes match the table.
- **A sender cannot hand two recipients two different file keys.** The
  container is assembled from the pieces, because the library refuses to build
  one: two stanzas wrapping two keys, and the header committing to one of them.
  The recipient whose key was not committed to must be refused *by name* rather
  than by a tag failure, in both orders, and with a commitment to neither key
  both must be refused. Paired with an honest container that passes the same
  check. What the tests do *not* build is the ciphertext that opens under both
  keys — that is real work in GF(2¹³⁰−5) and is not the property being checked;
  what is checked is the step that makes building it pointless.
- **Twenty-one frozen containers that must now be refused.** The recipient
  lists recorded before the commitment was required are kept byte for byte and
  asserted to fail, with a test that the list of them has not silently become
  empty — a refusal test over nothing passes forever.
- **Every value of the flags field**, all 65536 of them, against a named
  container and a listed one. Four bits are defined and two of them are not
  independent, which random mutation almost never lands on.
- **A recipient cannot forge a signed stream.** They hold the file key, so the
  three attacks are built from the inside: re-seal a changed message, a shorter
  one, or a longer one, each properly re-chunked so the final-chunk marker has
  nothing to say. Only the digest catches them. Paired with a test that the
  untouched container still opens.
- **A wrong `--sender` on a stream writes nothing at all.** The whole reason
  the signature block goes in front rather than in a trailer, asserted on a
  300 KB file where a trailer would have released every byte first.
- **A reader that stops early is not an error.** `hpqc decrypt big.hpqc | head`
  runs as a real subprocess against a real pipe, and must die of SIGPIPE with
  an empty stderr rather than exiting 1 in silence.
- **The signature block is fuzzed separately.** Corrupting a finished signed
  container trips the AEAD tag first, so those mutations never reach the
  signature parser. Mutating the payload *before* sealing it does — and that is
  also the realistic threat, since the sender chooses the payload.
- **The signed-message construction is pinned by digest.** Recorded signatures
  cannot do this; see below.
- **The STREAM nonce construction is pinned by table.** Recorded containers
  cannot do it either, for the same reason: widen the counter or move the
  final-chunk byte and the writer and reader move together, so the recorded
  file stops opening either way and the failure names no cause. The frozen
  (prefix, index, final) → nonce triples name it exactly.
- **A recipient list names nobody — and the same search finds the name in the
  shape that does publish it.** Asserting that eight bytes are absent from a
  container passes just as readily when the search itself is broken, so the
  test that looks for every recipient's key id in a listed file is paired with
  one that looks for it in a single-recipient file and requires it to be there.
- **Removing a recipient breaks the file for the others.** A stanza is cut on
  its exact boundary and the count fixed, so the header parses and claims one
  fewer recipient and every remaining stanza is genuine. Only the payload's
  associated data covering the whole list catches it.
- **The wrapping-key derivation is pinned by known answer.** Reuse the payload
  label, drop the file's salt from it, stop binding the recipient's own public
  keys — every one of those leaves the tool perfectly self-consistent and makes
  every file ever written unopenable, and all 410 non-vector tests pass through
  all of them. The frozen (ikm, salt, ephemeral key, KEM ciphertext, recipient)
  → key rows are what notice.
- **A lying recipient count.** All 65536 values the count field can hold, against
  a header sized for two, must be an `HpqcError` and never an allocation.
- **A header read off a pipe, seven bytes at a time.** The header is the first
  structure whose length depends on its own contents, so reading it is a loop,
  and the read loop is checked not to grow with the recipient count: a 47 KB
  header must arrive in a handful of reads, not one per stanza.
- **The signature notice never lands on stdout.** stdout is the plaintext.
- **A key file cannot make the machine allocate 8 GiB.** Cost parameters are
  refused before scrypt runs, so a corrupt or hostile key file is an error
  rather than an allocation. Fuzzing the wrapper covers the same ground over
  every byte of the header.
- **The key kind is checked before the KDF**, asserted by making the derivation
  fail loudly if it is reached rather than by timing it — a stopwatch would only
  say it was fast today.
- **`hpqc passwd` cannot lose a key.** It rewrites a private key in place, so a
  failure is tested to leave the original untouched and no temporary file behind.

## What building this turned up

Nine things the tests, the packaging and the CI matrix turned up. None is
visible from reading the happy path, which is the point.

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

**`hashlib.scrypt` is unusable at sensible parameters.** It inherits OpenSSL's
default 32 MiB memory limit, so anything past N=2¹⁴ fails with
`ValueError: [digital envelope routines] memory limit exceeded` — well below a
reasonable default, and with an error that does not hint at the `maxmem`
argument you were supposed to pass. `cryptography`'s `Scrypt` has no such
ceiling, which is what hpqc uses.

**An in-place rewrite of a private key can destroy it.** `hpqc passwd` writes
over an existing key file. A truncating write that fails halfway leaves no key
and no way back — and unlike a lost passphrase, this one is the tool's fault. Key
writes now go to a temporary file in the same directory and are renamed over the
target, so a reader sees either the old key or the new one. That also made the
original permission bug structurally impossible: the mode belongs to the new
inode, so there is no existing file's permissions left to inherit.

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

**"The header is associated data" was doing less work than it sounded.** I
wrote that every scrypt parameter in a wrapped key is authenticated, which is
true, and tested it by flipping bits in each. Then I removed the header from the
AAD to check the tests caught it — and the parameter tests kept passing. They
always would have: changing `log2(N)` changes the derived key, so the tag fails
whether or not the field is authenticated. The AAD is only load-bearing for the
fields that never reach the KDF. The claim and the tests now say which is which.
Same lesson as the vector above, from the other direction. Running the same
check over a chunked container later gave an exact answer: the only bytes whose
sole protection is the AAD are the five in the nonce field that chunked mode
does not feed into the nonce. Everything else is bound through HKDF or refused
by the parser.

**One byte is the whole difference between a stream and a forgery.** The
final-chunk marker looks like bookkeeping. To check it was load-bearing I made
every chunk claim to be final and re-ran the truncation test: deleting the last
chunk of a 3-chunk file then returned 128 KiB of correct plaintext with no
error whatsoever. Not a crash, not a warning — a shorter file that verifies. A
test asserting only "the attack fails today" would have passed under both
versions of the code and told me nothing about which byte was stopping it.

**A test hung forever on a version I never run.** Python 3.9 resolves click to
8.1, because 8.2 requires 3.10. In click 8.1's test runner, exhausted stdin
returns an empty string rather than raising, and `click.prompt` treats an empty
value as "ask again" — so a test that fed a mistyped passphrase confirmation and
expected the input to run out looped forever, writing prompts, at 100% CPU and
four gigabytes of resident memory. Locally, with click 8.5, the same test passes
in under a millisecond. Two fixes: the test now supplies the retry instead of
relying on what happens when input ends, which is the portable behaviour and the
part actually worth asserting; and the CI job has a `timeout-minutes` so the
next one of these fails in ten minutes instead of holding a runner. The same
pass found that three assertions used `result.stderr`, which on click 8.1 raises
`ValueError: stderr not separately captured` unless the runner is asked to
separate the streams — so the 3.9 job could not have been passing.

**A test that looks for what should not be there passes when it is broken.**
The recipient list exists so that a file names nobody, and the obvious test is
to search the container for each recipient's key id and require it to be
absent. That test passes if the search is wrong, if the key ids are the wrong
bytes, or if the container is empty. What makes it mean something is the twin
test: the same search, against the single-recipient shape that is *supposed* to
contain the key id, requiring it to be found. The CI smoke test needed the same
pairing, and needed `od` rather than `grep` to do it at all — a key id is
binary, so grepping the container as text would never have matched anything and
the check would have reported success forever.

**Only the frozen vectors noticed a change that broke every file.** Changing
the HKDF label the wrapping key is derived under leaves the tool perfectly
self-consistent: the writer and the reader move together, every round trip
still works, and every file anyone had already encrypted becomes permanently
unopenable. I ran it: 410 tests passed and not one of them was the vectors. The
same was true of reordering the stanza fields on the wire. That is the whole
argument for recording a derivation rather than a container — a container that
stops opening tells you something changed, and never which thing.

**The test for a portability fix was itself unportable.** Restoring SIGPIPE's
default needed a test with a real pipe and a real subprocess, so it hands
`head`'s stdin to hpqc, closes its own copy, and reads what comes out. Calling
`head.communicate()` after that raises `ValueError: flush of closed file` on
anything before Python 3.12 — it tries to flush a file it no longer owns. It
passed here, went out, and turned the CI red on the two oldest Pythons in the
matrix, which is exactly the version-specific behaviour the fix underneath it
was about. Reading `head.stdout` directly works everywhere. What the episode
actually produced is `tools/ci-local.sh`: the repository is private, so the CI
logs are not readable from a terminal, and a matrix you cannot run is a matrix
you find out about afterwards.

**I shipped a group-encryption feature with a hole in it, and found it by being
asked what was left.** Three commits after adding multiple recipients I went
looking for remaining work and reread the threat model instead of the code.
Every recipient unwraps a file key from their own stanza — and nothing made
those keys *the same* key. The AEADs here are not key-committing, so a sender
could wrap one key to Bob and another to Carol, seal one crafted payload, and
have them read different messages under a tag that verifies for both. I had
written, in that very section, that "any recipient can re-send the file as if it
came from you" and answered it with signing. I had not asked the mirrored
question: what can the *sender* do to a group that it cannot do to one person.
The fix is 32 bytes and a comparison. Finding it was rereading my own threat
model with the feature in front of me, which is not something a test suite can
do for you.

**A shell check that failed about one run in ten.** The CI smoke test is full
of lines like `hpqc info f.hpqc | grep -q '^recipients:  3'`. `grep -q` exits at
its first match, so if the writer still has a line to go it is killed by
SIGPIPE — and under `set -o pipefail` that turns a check which *passed* into a
failed script. It is a race, so it fails sometimes, which is exactly the shape
of thing that gets rerun and forgotten. Worse is the same pattern inside an
`if`: a SIGPIPE'd writer makes the status non-zero, the else branch runs, and a
check for a leaked key id reports it as absent. Every one of them now runs the
command, then greps the file it wrote.

**`hpqc decrypt big.hpqc | head` exited 1 and said nothing.** Chasing the
above, I found the real bug underneath it. Python ignores SIGPIPE and turns the
failed write into `BrokenPipeError`; `run()` had a handler for exactly that,
and it never ran, because click catches EPIPE first and calls `sys.exit(1)`
after silencing the flush. So the most ordinary pipeline in the world failed,
with an empty stderr and no explanation. Restoring SIGPIPE's default
disposition at startup makes hpqc behave like `cat`: the write that has nowhere
to go kills the process, the shell sees 141, and nothing is printed.

**I put a traceback into `hpqc info` while tidying it up.** Reading a header
from a stream meant taking the file's size from `stat()`, and I put the `stat()`
one line above the `open()` instead of one line below. `hpqc info nope.hpqc`
then raised `FileNotFoundError` instead of saying "cannot read nope.hpqc". Six
hundred tests did not catch it, because `info` is the one command that accepts
a path click cannot check with `exists=True` — it also reads stdin — and no
test had ever given it a path that was not there. The CI smoke script found it
within a minute of being run.

**A domain-separation label that nothing behavioural pins.** hpqc gives the
two signing constructions different labels, which is the standard hygiene. I
went to check the tests caught a shared label and they did not — all 557 other
tests passed with the two labels set equal. The reason is that the messages
already differ structurally: one carries 1216 bytes of recipient public keys
where the other carries a 4-byte length and a header, and no legal header is
1212 bytes long, so the two can never line up. That is an accident of two
constants, not a property to rely on — add a suite with a larger ML-KEM key and
it can stop holding while every test still passes. So the label is pinned by
direct assertion, next to a comment saying why it has to be. The honest version
of "the tests catch it" is sometimes "they cannot, and here is what I did
instead".

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
- **Signing a stream needs an input that can be read twice.** The signature
  covers a digest of the whole plaintext and has to exist before the first
  chunk is written. A file is fine; stdin falls back to a one-shot container
  and says so.
- **A stream releases plaintext before the file is fully authenticated** — and,
  when it is signed, before the signature over it has been checked. Inherent to
  streaming. Decrypting to a file is safe, because the output is renamed into
  place only on success; decrypting to a pipe hands data downstream before the
  end is checked.
- **No memory hygiene.** Passphrases and private keys are ordinary Python
  objects: they are not pinned, not zeroed after use, and may be copied by the
  interpreter or swapped to disk. A passphrase raises the cost of a stolen key
  file; it does not defend against something already reading this process.
- **A recipient list is not padded, and trial decryption is not constant
  time.** The file reveals how many people can open it, and the time taken to
  open it reveals which slot is yours to anyone who can measure it.
- **Any recipient of an unsigned file can re-send it as if it came from you.**
  They hold the file key. Signing is the answer; an unsigned file has no answer.
- **One KEM per file.** A container has one suite byte, so recipients using
  different parameter sets need different files.
- **Not audited.** This is a learning and portfolio project, written against
  the standards below. Read the code before trusting it with anything real.

## Roadmap

- [x] ML-DSA-65 signatures for sender authentication
- [x] Streaming / chunked AEAD for large files
- [x] Passphrase-wrapped private keys (scrypt + AEAD)
- [x] Multiple recipients per file
- [x] Signing to a recipient list (bind the container, not the recipient)
- [x] ML-KEM-1024 suite (with X448, so both halves move together)
- [x] Signing a streamed file — a digest signed up front, not a trailer
- [x] A file key commitment, so a sender cannot show two recipients two
      different messages
- [x] Known-answer test vectors checked into the repo

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — Module-Lattice-Based Digital Signature Standard (ML-DSA)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) — Elliptic Curves for Security (X25519)
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) — EdDSA (Ed25519)
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) — HKDF
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) — ChaCha20 and Poly1305
- [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914) — the scrypt password-based KDF
- Viet Tung Hoang, Reza Reyhanitabar, Phillip Rogaway, Damian Vizár, *Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance* (CRYPTO 2015) — the STREAM construction `hpqc` uses for chunked files
- [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) — a hybrid KEM combiner; `hpqc` uses the same `ss_m ‖ ss_x` ordering
- [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/) — hybrid key exchange in TLS 1.3
- Don Davis, *Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP, and XML* (USENIX Annual Technical Conference, 2001) — where surreptitious forwarding comes from

## License

MIT — see [LICENSE](LICENSE).
