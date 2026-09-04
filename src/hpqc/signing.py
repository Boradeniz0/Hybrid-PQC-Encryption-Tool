"""Sender authentication: Ed25519 + ML-DSA-65, signed then encrypted.

v1 answers "can anyone but the recipient read this file". It does not answer
"who wrote it" -- anybody holding a public key can produce a valid container.
This module adds the second answer, and it makes three choices that are worth
stating out loud because each has a wrong version that looks fine.

**1. Hybrid here too, but for one reason instead of two.** The KEM is hybrid
because of harvest-now-decrypt-later: recorded traffic must survive a quantum
computer that arrives after the fact. That argument does *not* apply to
signatures -- a forgery in 2040 cannot retroactively change what the recipient
verified today. What does apply is the other half of the hybrid argument:
ML-DSA is young, and if lattice signatures fall to cryptanalysis, a PQ-only
signature becomes forgeable *now*. So both signatures are required, over the
same message, and either one failing rejects the file.

**2. Sign, then encrypt -- not the other way round.** The signature and the
sender's public keys live *inside* the AEAD payload. Signing the ciphertext
instead would prove only who transmitted the bytes, and would publish the
sender's identity to anyone holding the file. This way a container's signer is
confidential: `hpqc info` cannot see it, and neither can an eavesdropper. The
cost is that you must be the recipient to learn who signed.

**3. The recipient is bound into the signed message.** Sign only the plaintext
and you get *surreptitious forwarding* (Davis, 2001): Bob receives a signed
file from Alice, decrypts it, re-encrypts the same plaintext and the same
signature to Carol, and Carol sees a file that verifies as "Alice wrote this to
me". The AEAD layer cannot prevent it, because Bob builds a fresh one. The fix
is to put the recipient's public keys inside what gets signed, so Alice's
signature is valid only for the recipient she chose. Carol recomputes the
signed message with her own keys and verification fails.

Payload layout inside the AEAD when the signed flag is set:

    offset  size   field
    0       2      length of the sender Ed25519 verifying key (32)
    2       32     sender Ed25519 verifying key
    34      2      length of the sender ML-DSA-65 verifying key (1952)
    36      1952   sender ML-DSA-65 verifying key
    1988    2      length of the Ed25519 signature (64)
    1990    64     Ed25519 signature
    2054    2      length of the ML-DSA-65 signature (3309)
    2056    3309   ML-DSA-65 signature
    5365    ...    plaintext

That is 5365 bytes of overhead on top of the header's 1184. Post-quantum
signatures are simply large; ML-DSA-65 alone is 3309 bytes of it.
"""

from __future__ import annotations

from typing import Optional, Tuple

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

from . import backend
from .errors import SignatureError
from .keys import (
    ED25519_KEY_LEN,
    MLDSA65_PUBLIC_LEN,
    PublicKey,
    SigningPrivateKey,
    SigningPublicKey,
)
from .suites import Suite
from .wire import U16, Reader

# Domain separation. Distinct from the HKDF label so a signature and a derived
# key can never be computed over the same byte string.
SIG_LABEL = b"hpqc-v1 sender authentication"

ED25519_SIGNATURE_LEN = 64
MLDSA65_SIGNATURE_LEN = 3309

SIGNATURE_BLOCK_LEN = (
    U16.size + ED25519_KEY_LEN
    + U16.size + MLDSA65_PUBLIC_LEN
    + U16.size + ED25519_SIGNATURE_LEN
    + U16.size + MLDSA65_SIGNATURE_LEN
)


def signed_message(
    plaintext: bytes,
    sender: SigningPublicKey,
    recipient: PublicKey,
    suite: Suite,
) -> bytes:
    """The exact byte string both signatures are computed over.

    Every field before the plaintext is fixed-length, and the plaintext is
    last, so plain concatenation is unambiguous -- no field can borrow a byte
    from its neighbour and produce the same message.

    The sender's own keys are included so a signature cannot be lifted onto a
    different claimed identity, and the recipient's keys are included to stop
    surreptitious forwarding. See the module docstring.
    """
    return b"".join(
        (
            SIG_LABEL,
            bytes([suite.id]),
            sender.ed25519_bytes,
            sender.mldsa_bytes,
            recipient.x25519_bytes,
            recipient.mlkem_bytes,
            plaintext,
        )
    )


def sign_payload(
    plaintext: bytes,
    sender: SigningPrivateKey,
    recipient: PublicKey,
    suite: Suite,
) -> bytes:
    """Return `signature block || plaintext` for the AEAD to seal."""
    backend.require_mldsa()
    public = sender.public_key()
    message = signed_message(plaintext, public, recipient, suite)

    ed_signature = sender.ed25519().sign(message)
    try:
        mldsa_signature = sender.mldsa().sign(message)
    except UnsupportedAlgorithm as exc:  # pragma: no cover - stack dependent
        raise backend.wrap_unsupported(exc, "ML-DSA-65") from None

    return b"".join(
        (
            U16.pack(len(public.ed25519_bytes)),
            public.ed25519_bytes,
            U16.pack(len(public.mldsa_bytes)),
            public.mldsa_bytes,
            U16.pack(len(ed_signature)),
            ed_signature,
            U16.pack(len(mldsa_signature)),
            mldsa_signature,
            plaintext,
        )
    )


def open_payload(
    payload: bytes,
    recipient: PublicKey,
    suite: Suite,
    *,
    expected_sender: Optional[SigningPublicKey] = None,
) -> Tuple[bytes, SigningPublicKey]:
    """Verify a signed payload and return (plaintext, signer).

    `expected_sender` is what turns this from a consistency check into an
    identity check. Without it a valid signature proves only that whoever
    encrypted the file also held *some* signing key -- they could have
    generated it a second earlier. Pass the sender's public key, obtained
    through some channel you trust, and a mismatch is an error.
    """
    reader = Reader(payload, noun="signature block")
    ed25519_public = reader.take_prefixed(
        "sender Ed25519 verifying key", ED25519_KEY_LEN
    )
    mldsa_public = reader.take_prefixed(
        "sender ML-DSA-65 verifying key", MLDSA65_PUBLIC_LEN
    )
    ed_signature = reader.take_prefixed("Ed25519 signature", ED25519_SIGNATURE_LEN)
    mldsa_signature = reader.take_prefixed(
        "ML-DSA-65 signature", MLDSA65_SIGNATURE_LEN
    )
    plaintext = reader.rest()

    signer = SigningPublicKey(
        ed25519_bytes=ed25519_public, mldsa_bytes=mldsa_public
    )

    # Checked before the signatures so a wrong sender says so, rather than
    # reporting a cryptographic failure for what is really a key mix-up.
    if expected_sender is not None and signer != expected_sender:
        raise SignatureError(
            f"this file was signed by key id {signer.key_id_hex}, "
            f"but verification was requested against {expected_sender.key_id_hex}"
        )

    message = signed_message(plaintext, signer, recipient, suite)

    # Both must verify. Requiring only one would silently reduce the scheme to
    # whichever algorithm an attacker had broken.
    try:
        signer.ed25519().verify(ed_signature, message)
    except InvalidSignature:
        raise SignatureError(
            "Ed25519 signature does not verify: the file was not signed by "
            f"key id {signer.key_id_hex}, or it was signed for a different "
            "recipient"
        ) from None

    try:
        signer.mldsa().verify(mldsa_signature, message)
    except InvalidSignature:
        raise SignatureError(
            "ML-DSA-65 signature does not verify: the file was not signed by "
            f"key id {signer.key_id_hex}, or it was signed for a different "
            "recipient"
        ) from None

    return plaintext, signer
