# Threat model

What hpqc protects, what it does not, and who each defence is aimed at. How the
defences work is in [DESIGN.md](DESIGN.md).

**hpqc has not been audited.** It is a learning and portfolio project, written
against the standards it cites. Read the code before trusting it with anything
real.

## What it protects

**Confidentiality and integrity of a file**, to one or more public keys, against
an attacker who records the file now and tries to decrypt it later. Breaking it
requires breaking both the elliptic curve and ML-KEM, not either one.

**Optionally, who sent it.** With `-s` on encryption and `--sender` on
decryption, the file carries an Ed25519 and an ML-DSA-65 signature, both
required. Without `--sender`, hpqc reports a signature but does not claim it
identifies anyone.

## Who the attacker is, per defence

Most of the interesting cases are not an eavesdropper. They are a *recipient* or
the *sender*, because those are the parties who hold a key.

| Attack | Attacker | Defence |
| --- | --- | --- |
| Read the file | anyone with the bytes | hybrid KEM, AEAD |
| Decrypt it in 2040 | anyone who recorded it | the ML-KEM half |
| Break ML-KEM by cryptanalysis | anyone | the elliptic curve half |
| Edit any header field | anyone with the bytes | whole header is associated data |
| Downgrade the suite byte | anyone with the bytes | associated data, and the HKDF transcript |
| Splice in a valid foreign KEM ciphertext | anyone with a key | the HKDF transcript binding |
| Truncate, extend, reorder or repeat chunks | anyone with the bytes | STREAM final-chunk marker |
| Paste a chunk in from another file | a recipient of that other file | per-file key derivation |
| Re-send a signed file as if you wrote it | a recipient | recipient or container bound into the signature |
| Cut a recipient out of a group file | anyone with the bytes | stanzas are associated data |
| Show two recipients two different messages | **the sender** | the file key commitment |
| Learn who else received a group file | a recipient, or anyone with the bytes | stanzas carry no key ids |
| Learn who signed a file | anyone without the private key | sign-then-encrypt |
| Brute-force a stolen key file | anyone with the file | scrypt, 128 MiB by default |
| Make a key file exhaust memory | whoever wrote the file | cost parameters bounded before scrypt runs |

## What it does not do

**No key distribution.** Verifying a sender means already having their signing
public key, obtained some other way. There is no web of trust, no TOFU store, no
directory. A signature checked only against the key inside the file proves the
file is self-consistent and nothing about who wrote it, and hpqc says so.

**Any recipient of an unsigned file can re-send it as if it came from you.**
Everyone who can open the file holds the file key, so any of them can decrypt
it, wrap the same key to somebody new, and produce a container the AEAD is
perfectly happy with. Signing is the answer. An unsigned file has no answer.

**A stream releases plaintext before the file is fully authenticated**, and when
it is signed, before the signature over it has been checked. This is inherent to
streaming. Decrypting to a file is safe, because the output is written to a
temporary file and renamed into place only on success. Decrypting to a pipe
hands data downstream before the end is checked, and hpqc says so on stderr.

**Signing a stream needs an input that can be read twice.** The signature covers
a digest of the whole plaintext and has to exist before the first chunk is
written. A file is fine. stdin falls back to a one-shot container and says so.

**A recipient list is not padded.** The file reveals how many people can open
it. Three recipients look like three recipients. Padding the list to a fixed
size would hide that, at the cost of a header sized for the largest group you
ever send to.

**Trial decryption is not constant time.** The reader stops at the first stanza
that opens, so how long a decryption takes reveals which slot is yours to anyone
able to measure it. Somebody holding only the file still learns nothing but the
count.

**No memory hygiene.** Passphrases and private keys are ordinary Python objects.
They are not pinned, not zeroed after use, and may be copied by the interpreter
or swapped to disk. A passphrase raises the cost of a stolen key file. It does
not defend against something already reading this process.

**One KEM per file.** A container carries one suite byte. Recipients using
different parameter sets need different files.

**Key ids are a user interface, not access control.** Eight bytes of truncated
SHA-256 are far too short to pin an identity on. Verification always compares
full public keys.

**No revocation, no expiry.** A key is valid until you stop using it.

## Things that are true but easy to misread

**`hpqc info` reads the header of a file it cannot decrypt.** Everything it
prints is what the file *claims*. The suite name, the recipient key id, the
flags: none of it is trusted until the AEAD tag verifies. Rewriting the suite
byte makes `info` report a different cipher and makes decryption fail.

**A wrapped private key does not say which algorithms it holds.** The wrapper
records whether the sealed blob is an encryption identity or a signing one.
Which KEM an encryption identity uses is inside the sealed blob, which is what
the passphrase protects.

**Mode 0600 protects a key from other users on the machine and nothing else.**
A stolen disk, a backup, or a copied file leaves the key in the clear. That is
what `--passphrase` is for.
