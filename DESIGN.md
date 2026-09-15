# Design

How hpqc works, and why each decision went the way it did. For the byte layout
see [FORMAT.md](FORMAT.md); for what this does and does not protect against see
[THREAT-MODEL.md](THREAT-MODEL.md).

## Encryption

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

**Raw Diffie-Hellman output is not a key.** X25519 gives you a uniformly random
group element, not uniformly random bits. Feeding it straight into a cipher is a
common mistake. HKDF-Extract turns two structured secrets into 32 uniform bytes,
and it is also the clean way to mix two secrets from different families. See
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869).

**The transcript is bound into the derivation.** HKDF's `info` covers the suite
id, the ephemeral public key, the ML-KEM ciphertext, and both of the recipient's
public keys:

```
info = "hpqc-v1 hybrid x25519+ml-kem-768" || suite || epk || kem_ct
                                          || recipient_dh_pk
                                          || recipient_kem_pk
```

Every field has a fixed length once the suite byte is known, so plain
concatenation is unambiguous. No byte can be shifted from one field into the
next and produce the same `info`. A key derived for one message cannot validate
for another.

**The entire header is the AEAD's associated data.** Suite id, key id, salt,
nonce, ephemeral key, KEM ciphertext: all authenticated. An attacker cannot
downgrade the suite byte, swap in a different ML-KEM ciphertext, or retarget the
recipient without failing the tag check. Nothing in the header is trusted before
that check passes.

### Nonces

The AEAD key is unique per file. A fresh ephemeral key, a fresh ML-KEM
encapsulation and a fresh HKDF salt feed every derivation, so a nonce is never
reused under a given key. The catastrophic AEAD failure mode is ruled out by key
freshness, not by nonce bookkeeping. The random 12-byte nonce in the header is
defence in depth.

A chunked file needs a nonce per chunk and the same argument carries: the
counter only has to be unique within one file, because the key already is.

### Implicit rejection

ML-KEM decapsulation never reports failure. FIPS 203 specifies implicit
rejection: a corrupted ciphertext silently yields a different shared secret
rather than an error. This is deliberate. An explicit failure would give the
attacker a decryption oracle. The AEAD tag is what rejects a bad file, and it
does so without revealing which part was wrong.

## Sender authentication

By default a `.hpqc` file proves nothing about who wrote it. Anybody holding
your public key can produce one. Pass `-s SIGNING.key` to sign, and
`--sender SIGNER.pub` when decrypting to check the signature.

### Both signatures are required

The KEM is hybrid because of harvest-now-decrypt-later. That argument does not
apply to signatures: a forgery in 2040 cannot change what a recipient verified
today. The other half of the argument does apply. ML-DSA is young, and if
lattice signatures fall to cryptanalysis a PQ-only signature becomes forgeable
now. So Ed25519 and ML-DSA-65 both sign the same message and both must verify.
Either one failing rejects the file.

### Sign, then encrypt

The signature and the sender's public keys live inside the AEAD payload. Signing
the ciphertext instead would prove only who transmitted the bytes, and would
publish the sender's identity to anyone holding the file. This way the signer is
confidential: `hpqc info` cannot say who signed, and neither can an
eavesdropper. The cost is that you have to be the recipient to find out.

### The recipient is bound into the signed message

Sign only the plaintext and you get surreptitious forwarding (Davis, 2001). Bob
receives a signed file from Alice, decrypts it, re-encrypts the same plaintext
and the same signature to Carol, and Carol sees a file that verifies as "Alice
wrote this to me". The AEAD cannot help, because Bob builds a fresh one. So the
recipient's public keys go inside what gets signed:

```
signed message = "hpqc-v1 sender authentication" || suite
              || sender_ed25519_pk   || sender_mldsa_pk
              || recipient_x25519_pk || recipient_mlkem_pk
              || plaintext
```

Carol recomputes that with her own keys, gets a different message, and
verification fails. The sender's own keys are in there too, so a signature
cannot be lifted onto a different claimed identity.

There are three versions of this message, chosen by flags the reader has before
it opens anything. Each has its own label, so a signature made under one can
never be presented as one made under another.

| File shape | The signed message binds |
| --- | --- |
| One recipient, named | the recipient's public keys, and the plaintext |
| A recipient list | the whole header, and the plaintext |
| Chunked | the whole header, and a SHA-512 digest of the plaintext |

### What a valid signature proves

A signature that verifies against the key inside the file proves the file is
internally consistent. It proves nothing about who wrote it: that key could have
been generated a second earlier. Only a reader who pins the sender's public key,
obtained through some channel they trust, learns an identity. Without
`--sender`, `hpqc` says so rather than printing a reassuring tick:

```console
$ hpqc decrypt -k alice.key report.hpqc -o report.pdf
warning: signed by key id 1322446e7dc517ec; pass --sender to verify the
signer's identity
```

Asking to verify a file that carries no signature is an error, not a plaintext
with a caveat.

### Cost

A signature block is 5365 bytes: two verifying keys and two signatures, all
length-prefixed. ML-DSA-65's signature alone is 3309 of that. Post-quantum
signatures are simply large.

## Large files

Past a megabyte, hpqc seals the payload in 64 KiB chunks instead of holding the
whole file. The threshold is automatic; `--chunked` and `--one-shot` force it
either way.

| 200 MB file | encrypt peak RSS | decrypt peak RSS |
| --- | ---: | ---: |
| streamed | **35 MB** | **34 MB** |
| `--one-shot` | 620 MB | 620 MB |

The streamed figure does not change with the file size.

Chunking naively breaks three properties the one-shot format had for free, and
each has a wrong version that looks like it works.

1. **A nonce per chunk, never repeated.** The same key and nonce on two chunks
   leaks the XOR of the plaintexts and, for Poly1305 and GCM alike, hands over
   the authentication key.
2. **Truncation has to be detectable.** Seal each chunk on its own and an
   attacker can delete the last one. Every remaining chunk still verifies.
   "Transfer the first half of the bank statement" is a complete forgery built
   without touching a byte.
3. **Reordering and splicing have to be detectable.** Chunks are individually
   valid ciphertexts. Swapping two, or pasting one in from another file
   encrypted to the same recipient, must not verify.

All three are solved by the STREAM construction (Hoang, Reyhanitabar, Rogaway
and Vizar, CRYPTO 2015). The 12-byte nonce is built as:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 7 | per-file nonce prefix, from the header |
| 7 | 4 | chunk counter, big-endian, from 0 |
| 11 | 1 | `0x01` on the last chunk, `0x00` on every other |

That last byte closes the truncation hole. Delete the final chunk and the new
final chunk was sealed as "not final" but has to open as "final". Different
nonce, tag check fails. Append a chunk and the old final chunk fails the same
way in reverse. Swap two and the counters no longer match. The key is derived
per file, so a chunk lifted from another container fails whatever its counter
says.

Nothing frames the chunks. The reader knows the boundaries by counting, because
a length prefix would be attacker-controlled data read before authentication.
The 32-bit counter is refused at 2^32 chunks rather than allowed to wrap, which
puts the ceiling at 256 TiB per file.

Overhead is 16 bytes per chunk on top of the 1168-byte header: 0.024%
asymptotically, 0.025% on a 200 MB file, 0.048% on a 5 MB one.

### Signing a stream costs a second read, not memory

A signature is a statement about a whole message, and a chunked writer never
holds one. So it signs a digest of the plaintext, computed in a first pass over
the input. That means the input has to be one that can be read twice.

| 200 MB, signed | encrypt peak RSS | decrypt and verify peak RSS |
| --- | ---: | ---: |
| streamed | **35 MB** | **35 MB** |
| `--one-shot` | 816 MB | 620 MB |

The signature block goes in front of the plaintext, not in a trailer. A trailer
buys back the single pass and costs the reader everything it could have known
early: the claimed signer would arrive only after the last chunk had been
written out, so `--sender` could not refuse a file until the file had been
delivered. With the block in front, the reader checks the claimed identity
before releasing a single byte:

```console
$ hpqc decrypt -k alice.key big.hpqc -o out.bin --sender impostor.pub
error: this file was signed by key id 94cb82d7..., but verification was
requested against d8fd44dc...
$ ls out.bin
ls: cannot access 'out.bin': No such file or directory
```

The digest is SHA-512, not SHA-256. Signing a digest makes the signature only as
collision-resistant as the hash: find two plaintexts sharing one digest and a
single signature covers both. SHA-256 would put that at 2^128 classically and
lower against a quantum collision search, which would quietly halve the security
of a scheme whose premise is being conservative about the future.

stdin is the one input this cannot use, because it arrives once:

```console
$ cat disk.img | hpqc encrypt -r bob.pub -s alice.key -o out.hpqc
note: signing a stream reads the input twice and stdin arrives once;
writing a one-shot container instead
```

### What streaming gives up

**Decryption releases plaintext before the whole file is authenticated.** Chunk
3 is written out before chunk 4 is known to verify. A one-shot container is
all-or-nothing; a stream cannot be, and no amount of engineering changes that.
When the file is signed, this extends to the signature: the plaintext is out
before the signature over it has been checked.

What the tool can do is make sure the incomplete output is never mistaken for
the real thing. `hpqc decrypt` writes to a temporary file and renames it over
the target only once the last chunk has verified, so a truncated file leaves no
output at all. Decrypting to a pipe is where the caveat still bites, and the
tool says so on stderr.

## Several recipients

One file, several people who can open it. The obvious approach does not work:
the AEAD key is derived straight from the KEM output, and there is no way to
make two independent encapsulations to two different public keys arrive at the
same key. So the file gains one level of indirection, the same one PGP, CMS and
age use:

1. Pick a random **file key**. This is what seals the payload.
2. For each recipient, run the hybrid KEM against their public key and derive a
   **wrapping key** from the result.
3. Seal the file key under each wrapping key. Each sealed copy is a **stanza**,
   and the header carries one per recipient.

### The stanzas do not say who they are for

There is no key id in a stanza. A recipient list in the clear tells anyone
holding the file who else was in the conversation, and for a group message that
is often worth more than the contents. So the reader tries each stanza in turn
and keeps the one that opens. The AEAD tag is the test.

What the file still leaks is how many recipients there are, which is why
`hpqc info` reports a count and nothing else.

The cost is paid twice. Opening a file is O(recipients) decapsulations rather
than O(1), which is microseconds. And "wrong key" can no longer name the key the
file was for, because the file does not know:

```console
$ hpqc decrypt -k dave.key minutes.hpqc -o out.txt
error: none of this file's 3 recipient slot(s) could be opened with key id
26037352c3e3a2ce; it was encrypted for someone else
```

A single recipient keeps the older header, key id and all. That shape costs 84
bytes less and there is nothing to hide when there is one name. To get the same
anonymity for one recipient, ask for it:

```console
$ hpqc encrypt -r alice.pub --hide-recipients report.pdf -o report.hpqc
```

### A wrapping key is used once, so its nonce is all zeros

A nonce exists to stop two messages being encrypted under one key. Every stanza
has a fresh ephemeral key and a fresh ML-KEM encapsulation behind it, so its
wrapping key is unique to that stanza and seals exactly one thing. A random
nonce here would add twelve bytes an attacker could edit and buy nothing.

The wrapping key is derived under a different HKDF label from the payload key,
over the stanza's own ephemeral key and KEM ciphertext, the file's salt, and the
recipient's own two public keys. A stanza cannot be moved to another file or
another recipient, and the key that wraps a file key can never collide with the
key that seals a payload.

### Every recipient gets the same file key, and the header proves it

ChaCha20-Poly1305 and AES-256-GCM are not key-committing. Given two keys, a
ciphertext can be built that decrypts successfully under both, to two different
plaintexts. This is the invisible salamanders result (Dodis, Grubbs, Ristenpart
and Woodage, CRYPTO 2018; Len, Grubbs and Ristenpart, USENIX 2021).

In a scheme like this one it gives a malicious sender something that looks
impossible. Wrap one file key to Bob and a different one to Carol, seal a single
crafted payload, and the two of them open the same file and read different
messages. Both see a valid tag. Signing does not help, because the signature
block is inside the payload and each view carries its own.

The fix is to take the choice away. The header carries a commitment to the file
key, and a recipient checks it the moment the key comes out of its stanza:

```
commitment = HKDF-SHA256(ikm=file_key, salt=header salt,
                         info="hpqc-v1 file key commitment" || suite id)
```

Bob computes it over his file key, Carol over hers. Both have to equal the one
32-byte value in the header, which takes a collision in HKDF-SHA256. The sender
is forced to give everybody the same key, and the payload is then one message
that either opens or does not. Whoever was handed the other key is told what
happened, rather than getting a tag failure that reads like corruption:

```console
$ hpqc decrypt -k carol.key minutes.hpqc -o out.txt
error: this file's header does not commit to the key that came out of the
recipient list; the sender wrapped a different key for somebody else and may
have written them a different message
```

This is mandatory, not offered. A recipient list without the commitment is
refused rather than read as an older file, because the party who chooses whether
to commit is exactly the party this defends against. The writer is held to the
same rule from the inside: no path through the library can produce an
uncommitted list.

**This is the one deliberate compatibility break in the project's history.**
Every group container written before it became unreadable. They were three
commits old in an unreleased line, and the frozen test vectors holding them were
kept exactly as they are. What they prove now is the refusal. A single named
recipient is untouched: one recipient means one KEM-derived key and no file key
at all, so the question does not arise.

### Removing a recipient cannot be done quietly

The whole header is the payload's associated data, stanzas included. Strip Bob's
stanza to cut him out of a conversation and the file stops opening for Alice
too. She gets an authentication failure rather than a message that looks exactly
as it should. The attack is still a denial of service. What it is not is silent.

### Signing to a group

The usual anti-forwarding construction puts the recipient's public keys inside
the signed message. With a recipient list there are none to put there, and the
reader has none to recompute with. Three things could go in their place:

- **One of the recipients.** Verifies for that person, fails for everybody else.
- **The whole set, carried inside the AEAD.** Works, costs 1216 bytes per
  recipient, and tells every recipient who the others are. It is also only a
  claim: nothing would stop a sender listing two recipients and wrapping the
  file key for three.
- **The header itself, every stanza of it.** That is the delivery rather than a
  description of it, it costs nothing, and it cannot be a lie.

hpqc binds the header. Bob cannot re-address the file, because that means new
stanzas, a new salt and a new nonce, and Carol recomputes the signed message
over the header she actually received. He cannot strip a recipient for the same
reason. And no recipient learns anything about the others.

The signature stops meaning "Alice wrote this to these people" and starts
meaning "Alice wrote this, into this exact container". A narrower claim, and the
one that can be checked. The header is already the AEAD's associated data, which
is not the same thing: that binds it to the file key, which every recipient
holds. This binds it to Alice's signing key, which none of them do.

## Two hybrid KEMs

| `--kem` | Diffie-Hellman | ML-KEM | NIST category | suite bytes |
| --- | --- | --- | ---: | --- |
| `mlkem768` (default) | X25519 | ML-KEM-768 | 3 | `0x01`, `0x02` |
| `mlkem1024` | X448 | ML-KEM-1024 | 5 | `0x03`, `0x04` |

**The classical half moves with the post-quantum half.** Pairing ML-KEM-1024
with X25519 would look like a stronger key and would not be one. The two halves
are combined so an attacker must break both, which means the pair is as strong
as its stronger half. Leaving the classical half at roughly 128 bits while
raising the lattice half to category 5 buys nothing against the attacker the
upgrade is meant for. X448 is what matches, and it costs 24 bytes of key and one
more scalar multiplication.

**`encrypt` has no `--kem`.** The KEM is not the sender's to choose. It is
whatever the recipient's key already is. `--aead` names an AEAD, the recipient's
key names a KEM, and the suite byte is where the two meet.

**One file, one KEM.** A container carries one suite byte, so it cannot be
addressed to an ML-KEM-768 recipient and an ML-KEM-1024 recipient at once:

```console
$ hpqc encrypt -r big.pub -r small.pub notes.txt -o notes.hpqc
Error: small.pub is X25519+ML-KEM-768 but big.pub is X448+ML-KEM-1024;
one file has one KEM, so these recipients need separate files
```

It could have been allowed, since every stanza length-prefixes its own fields.
But only by letting a prefix select how the rest is read instead of being
checked against a value already known, and that is the one thing this parser
does not do anywhere else.

Which is the same reason the suite byte cannot be used to reinterpret a file. It
arrives unauthenticated, so relabelling a container fails on arithmetic before
any key operation runs:

```console
$ printf '\x01' | dd of=big.hpqc bs=1 seek=5 count=1 conv=notrunc
$ hpqc info big.hpqc
error: ephemeral X25519 public key is 56 bytes, expected 32 here
```

The field is named after the suite the file claims, because that is all the
parser has to go on. It expected 32 bytes because byte 5 said X25519, and found
56.

**A key file says which it is in one byte.** Type 1 is X25519 + ML-KEM-768, type
2 is X448 + ML-KEM-1024. That byte was introduced as a format version and never
had a second value. What a second parameter set needs it to say is which key
this is, not which revision, so it is a key type now, and type 1 is bit for bit
what version 1 always was. Every key file written before this change still
reads.

The byte is not optional. A public key could be told apart by its length, but a
private key stores the ML-KEM seed, which FIPS 203 fixes at 64 bytes for every
parameter set. Two private keys of different types differ only in their
Diffie-Hellman half, and length alone cannot separate them.

## Passphrase-protected private keys

A private key file is mode 0600, which protects it from other users on the
machine and from nothing else. A stolen disk, a backup, a copied file: the key
is in the clear. `--passphrase` wraps it:

```console
$ hpqc keygen -o alice --passphrase
$ hpqc info alice.key
type:       hpqc wrapped private key
contents:   encryption private key
protection: scrypt N=2^17 r=8 p=1 (128 MiB)
key id:     unavailable without the passphrase
```

scrypt derives a key from the passphrase, ChaCha20-Poly1305 seals the secret
under it. The parameters travel inside the file, so a key written with a
different cost still opens. The default is N=2^17, which is 128 MiB and about a
third of a second: enough that a guessing attack pays for memory as well as
time. `--scrypt-log-n` moves it.

`hpqc passwd` adds, changes or removes a passphrase without touching the key
itself, so the public key and key id stay exactly as they were. Without that,
changing a passphrase would mean generating a new identity and everyone holding
your public key would have to fetch a new one.

Note what `info` does not say above. The wrapper records whether the sealed blob
is an encryption identity or a signing one, and nothing else. Which KEM an
encryption identity uses is the first byte inside the sealed blob, which is what
the passphrase protects. So it names nothing it cannot see.

There is deliberately no `--passphrase VALUE` option anywhere. Command lines are
visible to every user on the machine through `ps`.

### A key file is untrusted input

A wrapped key carries its own scrypt parameters, which means a hostile file can
ask for an enormous allocation. The cost is bounded before scrypt runs, so a
corrupt or crafted key file is an error rather than 8 GiB of memory. The key
kind is checked before the derivation, not after, so handing `passwd` a signing
key where an identity was expected fails immediately instead of after a third of
a second of scrypt.

Passphrases are NFC-normalised before use. Without that the same passphrase
typed on two systems can arrive as different bytes, because "e with an accent"
is one code point or two depending on where it came from, and the key would
simply refuse to open with no way to tell why.

## Backend requirements

ML-KEM and ML-DSA come from `cryptography.hazmat.primitives.asymmetric`, which
needs `cryptography` 46 or newer built against OpenSSL 3.5 or newer. To check:

```console
$ python -c "from cryptography.hazmat.backends.openssl.backend import backend; print(backend.openssl_version_text())"
OpenSSL 4.0.2 25 Aug 2026
$ python -c "from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey; print('ok')"
ok
$ python -c "from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey; print('ok')"
ok
```

If any of these fails, hpqc says so with an actionable message rather than an
ImportError from deep inside a key operation. The two are probed separately, so
a stack that can encrypt but not sign is refused only when you ask it to sign.

The Python floor is 3.9.2, not 3.9.0. `cryptography>=46` declares
`!=3.9.0,!=3.9.1`, so on those two patch releases the dependency cannot resolve
at all.
