"""hpqc -- hybrid post-quantum encryption for files and messages.

Key agreement is X25519 (classical ECDH) combined with ML-KEM-768 (FIPS 203).
Both shared secrets feed a single HKDF-SHA256 extraction, and the resulting key
drives an AEAD. Breaking the file requires breaking *both* primitives, so it
stays safe against a classical attacker who breaks ML-KEM and against a
quantum attacker who breaks X25519.

Sender authentication is optional and hybrid in the same way: Ed25519 with
ML-DSA-65 (FIPS 204), both required, signed before encryption so that who
signed a file is itself confidential.

Private keys can be kept under a passphrase -- scrypt to a key, ChaCha20-Poly1305
around the secret -- rather than relying on file permissions alone.
"""

__version__ = "0.3.0"

__all__ = ["__version__"]
