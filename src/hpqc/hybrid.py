"""The hybrid KEM: X25519 + ML-KEM-768, combined through HKDF-SHA256.

Encapsulation produces two independent shared secrets:

  * ss_x  -- X25519(ephemeral_sk, recipient_x25519_pk), 32 bytes
  * ss_m  -- ML-KEM-768 encapsulation against the recipient, 32 bytes

Neither is used directly. Both are concatenated into the HKDF input keying
material, so the derived AEAD key is unpredictable unless the attacker can
break *both* KEMs. That is the entire point of hybrid: harvest-now-decrypt-
later is covered by ML-KEM, and a flaw in the newer lattice scheme is covered
by X25519.

Two details that are easy to get wrong and that this module gets right:

1. Raw Diffie-Hellman output is not a key. X25519 output is a uniformly random
   *group element*, not uniformly random bits, and ML-KEM's output is already
   hashed but says nothing about the X25519 half. HKDF-Extract fixes both.

2. The transcript is bound into HKDF's `info`. Suite byte, ephemeral public
   key, ML-KEM ciphertext, and both recipient public keys all go in, so a key
   derived for one message can never validate for another. Every field is
   fixed-length, so plain concatenation is unambiguous -- no length-prefix
   confusion is possible.
"""

from __future__ import annotations

from typing import Tuple

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import backend
from .errors import FormatError
from .keys import PrivateKey, PublicKey
from .suites import Suite

# Domain separation string. Bump it if the derivation ever changes shape --
# an old and a new build must never derive the same key from the same inputs.
HKDF_LABEL = b"hpqc-v1 hybrid x25519+ml-kem-768"

# The same derivation, run for a different purpose: turning a KEM output into
# a key that wraps a file key for one recipient (see recipients.py). It has to
# be a distinct label, because the two keys are derived from inputs that are
# otherwise identical in shape -- without this, the key that seals a payload
# and the key that seals a file key could be the same bytes.
WRAP_LABEL = b"hpqc-v1 file key wrap x25519+ml-kem-768"

MLKEM768_CIPHERTEXT_LEN = 1088
SHARED_SECRET_LEN = 32
SALT_LEN = 16


def _exchange(
    private: X25519PrivateKey, peer_public: bytes, *, what: str
) -> bytes:
    """X25519 with attacker-controlled input made safe to call.

    OpenSSL rejects low-order points -- the ones that force an all-zero shared
    secret -- with a bare ValueError. Both peer public keys we touch come from
    somewhere untrusted (a header field, or a .pub file), so that has to
    surface as a normal hpqc error instead of a traceback.
    """
    try:
        return private.exchange(X25519PublicKey.from_public_bytes(peer_public))
    except ValueError as exc:
        raise FormatError(f"invalid {what}: {exc}") from None


def _combine(ss_mlkem: bytes, ss_x25519: bytes) -> bytes:
    """Concatenate both shared secrets into HKDF input keying material.

    ML-KEM first, X25519 second -- the same order X-Wing uses. Both halves are
    exactly 32 bytes, so the split point is unambiguous.
    """
    return ss_mlkem + ss_x25519


def _transcript(
    suite: Suite,
    ephemeral_public: bytes,
    kem_ciphertext: bytes,
    recipient: PublicKey,
    label: bytes,
) -> bytes:
    """Everything the derivation must be bound to, as HKDF `info`."""
    return b"".join(
        (
            label,
            bytes([suite.id]),
            ephemeral_public,
            kem_ciphertext,
            recipient.x25519_bytes,
            recipient.mlkem_bytes,
        )
    )


def derive_key(
    ikm: bytes,
    salt: bytes,
    suite: Suite,
    ephemeral_public: bytes,
    kem_ciphertext: bytes,
    recipient: PublicKey,
    label: bytes = HKDF_LABEL,
) -> bytes:
    """HKDF-SHA256 the combined secrets down to one AEAD key.

    `label` selects what the key is *for*. The default derives the key that
    seals a payload directly; WRAP_LABEL derives the key that seals a file key
    for one recipient. Same inputs, different label, unrelated outputs.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=suite.key_len,
        salt=salt,
        info=_transcript(
            suite, ephemeral_public, kem_ciphertext, recipient, label
        ),
    ).derive(ikm)


def encapsulate(recipient: PublicKey) -> Tuple[bytes, bytes, bytes]:
    """Run both KEMs against a recipient.

    Returns (ephemeral_x25519_public, mlkem_ciphertext, ikm). The caller feeds
    ikm to derive_key and puts the two public values in the container header.
    """
    backend.require_mlkem()

    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes_raw()
    ss_x25519 = _exchange(
        ephemeral,
        recipient.x25519_bytes,
        what="recipient X25519 public key",
    )

    try:
        ss_mlkem, kem_ciphertext = recipient.mlkem().encapsulate()
    except UnsupportedAlgorithm as exc:  # pragma: no cover - stack dependent
        raise backend.wrap_unsupported(exc) from None

    return ephemeral_public, kem_ciphertext, _combine(ss_mlkem, ss_x25519)


def decapsulate(
    identity: PrivateKey, ephemeral_public: bytes, kem_ciphertext: bytes
) -> bytes:
    """Recover the same ikm from the header values and our private key.

    ML-KEM decapsulation never reports failure: FIPS 203 specifies implicit
    rejection, so a corrupt ciphertext silently yields a different shared
    secret. That is deliberate -- surfacing the failure here would leak a
    decryption oracle. The AEAD tag check downstream is what actually rejects
    the file.
    """
    backend.require_mlkem()

    ss_x25519 = _exchange(
        identity.x25519(),
        ephemeral_public,
        what="ephemeral X25519 public key in the header",
    )
    try:
        ss_mlkem = identity.mlkem().decapsulate(kem_ciphertext)
    except UnsupportedAlgorithm as exc:  # pragma: no cover - stack dependent
        raise backend.wrap_unsupported(exc) from None

    return _combine(ss_mlkem, ss_x25519)
