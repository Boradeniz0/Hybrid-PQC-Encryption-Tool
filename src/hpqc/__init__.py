"""hpqc -- hybrid post-quantum encryption for files and messages.

Key agreement is an elliptic-curve Diffie-Hellman combined with ML-KEM
(FIPS 203). Both shared secrets feed a single HKDF-SHA256 extraction, and the
resulting key drives an AEAD. Breaking the file requires breaking *both*
primitives, so it stays safe against a classical attacker who breaks ML-KEM and
against a quantum attacker who breaks the elliptic curve.

Two parameter sets: X25519 with ML-KEM-768 (the default, NIST category 3) and
X448 with ML-KEM-1024 (category 5). The classical half moves with the
post-quantum half, because raising only one of them raises nothing.

Sender authentication is optional and hybrid in the same way: Ed25519 with
ML-DSA-65 (FIPS 204), both required, signed before encryption so that who
signed a file is itself confidential.

Private keys can be kept under a passphrase -- scrypt to a key, ChaCha20-Poly1305
around the secret -- rather than relying on file permissions alone.

Files past a megabyte are sealed as a chunked stream (the STREAM construction:
a counter nonce per chunk and an explicit final-chunk marker), so the memory
cost is one chunk rather than the whole file. Signing one costs a second read
of the input instead of the memory: a signature covers the whole message, so
the plaintext is digested before the first chunk is written and the signature
travels in front of it.

A file can be addressed to several recipients at once. It is sealed under one
random file key, and each recipient gets a copy of that key wrapped under their
own hybrid KEM output. The header names none of them -- a reader finds its own
copy by trying each in turn -- so the file reveals how many people can open it
and not who they are. The header commits to that key, which is what stops a
sender handing two recipients two different messages under one tag. Signing such a file binds the header itself rather than a
recipient, because there is no recipient in it to bind.
"""

__version__ = "0.9.1"

__all__ = ["__version__"]
