"""Helpers shared between test modules.

`seal` exists because the adversary for a signature is the *sender*: whoever
encrypts a file chooses its payload, and the AEAD tag proves only that the
payload came from them. So testing the signature block means building a
perfectly valid container around arbitrary payload bytes, not flipping bits in
a finished file -- the tag would catch those long before any signature check.
"""

from __future__ import annotations

import os

from hpqc import container, hybrid
from hpqc.container import FLAG_SIGNED
from hpqc.keys import PublicKey
from hpqc.suites import DEFAULT_SUITE, Suite


def seal(
    payload: bytes,
    recipient: PublicKey,
    suite: Suite = DEFAULT_SUITE,
    *,
    flags: int = FLAG_SIGNED,
) -> bytes:
    """Build a valid container around an arbitrary payload."""
    ephemeral_public, kem_ciphertext, ikm = hybrid.encapsulate(recipient)
    header = container.Header(
        suite=suite,
        flags=flags,
        key_id=recipient.key_id,
        salt=os.urandom(hybrid.SALT_LEN),
        nonce=os.urandom(suite.nonce_len),
        ephemeral_public=ephemeral_public,
        kem_ciphertext=kem_ciphertext,
    )
    header_bytes = header.pack()
    key = hybrid.derive_key(
        ikm=ikm,
        salt=header.salt,
        suite=suite,
        ephemeral_public=ephemeral_public,
        kem_ciphertext=kem_ciphertext,
        recipient=recipient,
    )
    return header_bytes + suite.aead(key).encrypt(header.nonce, payload, header_bytes)
