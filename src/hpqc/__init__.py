"""hpqc -- hybrid post-quantum encryption for files and messages.

Key agreement is X25519 (classical ECDH) combined with ML-KEM-768 (FIPS 203).
Both shared secrets feed a single HKDF-SHA256 extraction, and the resulting key
drives an AEAD. Breaking the file requires breaking *both* primitives, so it
stays safe against a classical attacker who breaks ML-KEM and against a
quantum attacker who breaks X25519.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
