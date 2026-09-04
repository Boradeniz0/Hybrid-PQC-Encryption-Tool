"""The .hpqc container format: header layout, encryption, decryption.

Byte layout (all integers big-endian):

    offset  size   field
    0       4      magic, b"HPQC"
    4       1      format version, 1
    5       1      cipher suite id  -> suites.by_id()
    6       2      flags; bit 0 = the payload is signed, other bits reserved
    8       8      recipient key id (truncated SHA-256, a UX hint only)
    16      16     HKDF salt
    32      12     AEAD nonce  (suite.nonce_len)
    44      2      length of the ephemeral X25519 public key (32)
    46      32     ephemeral X25519 public key
    78      2      length of the ML-KEM-768 ciphertext (1088)
    80      1088   ML-KEM-768 ciphertext
    1168    ...    AEAD ciphertext || 16-byte tag

Two properties matter more than the exact offsets:

* **The whole header is the AEAD's associated data.** Every byte above is
  authenticated. Flip the suite id to downgrade the file, swap in a different
  ML-KEM ciphertext, retarget the key id -- the tag check fails. Nothing in the
  header is trusted before the tag is verified.

* **Variable-size fields are length-prefixed.** v1 only ever emits 32 and 1088,
  but a future ML-KEM-1024 suite drops in without a parser change.

* **Unknown flag bits are refused, known ones are not.** Sender authentication
  was added by claiming bit 0 of the reserved `flags` field, which is what it
  was there for. An older build meets a signed file, sees a flag bit it does
  not implement, and refuses it by name instead of decrypting something it only
  half understands -- while this build still reads every unsigned file written
  before signing existed. The format version did not have to move.

Encryption is one-shot, so the whole plaintext is held in memory. Streaming
(chunked AEAD with a per-chunk counter nonce and an explicit final-chunk
marker) is the next flag bit.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag

from . import hybrid, signing, suites
from .errors import DecryptionError, FormatError, SignatureError, WrongRecipientError
from .hybrid import MLKEM768_CIPHERTEXT_LEN, SALT_LEN
from .keys import (
    KEY_ID_LEN,
    X25519_KEY_LEN,
    PrivateKey,
    PublicKey,
    SigningPrivateKey,
    SigningPublicKey,
)
from .suites import DEFAULT_SUITE, Suite
from .wire import U16, Reader

MAGIC = b"HPQC"
FORMAT_VERSION = 1

FLAGS_NONE = 0
FLAG_SIGNED = 0x0001  # the AEAD payload starts with a signature block
_KNOWN_FLAGS = FLAG_SIGNED

_PREAMBLE = struct.Struct(">4sBBH8s16s")  # magic, version, suite, flags, key id, salt


@dataclass(frozen=True)
class Header:
    """Parsed container header. Untrusted until the AEAD tag verifies."""

    suite: Suite
    flags: int
    key_id: bytes
    salt: bytes
    nonce: bytes
    ephemeral_public: bytes
    kem_ciphertext: bytes
    version: int = FORMAT_VERSION

    def pack(self) -> bytes:
        return b"".join(
            (
                _PREAMBLE.pack(
                    MAGIC,
                    self.version,
                    self.suite.id,
                    self.flags,
                    self.key_id,
                    self.salt,
                ),
                self.nonce,
                U16.pack(len(self.ephemeral_public)),
                self.ephemeral_public,
                U16.pack(len(self.kem_ciphertext)),
                self.kem_ciphertext,
            )
        )

    @property
    def key_id_hex(self) -> str:
        return self.key_id.hex()

    @property
    def signed(self) -> bool:
        """True if the payload begins with a signature block.

        Whether the signature *verifies* -- and who signed -- cannot be known
        from the header: the signature lives inside the AEAD, so it takes the
        recipient's private key to find out. That is deliberate; see signing.py.
        """
        return bool(self.flags & FLAG_SIGNED)


def parse_header(data: bytes) -> Tuple[Header, bytes, bytes]:
    """Split a container into (header, header_bytes, aead_ciphertext).

    `header_bytes` is returned verbatim rather than re-packed: it is the AEAD's
    associated data, and re-serialising could paper over a byte we did not
    round-trip faithfully.
    """
    reader = Reader(data)
    preamble = reader.take(_PREAMBLE.size, "header preamble")
    magic, version, suite_id, flags, key_id, salt = _PREAMBLE.unpack(preamble)

    if magic != MAGIC:
        raise FormatError(
            f"not an hpqc file: expected magic {MAGIC!r}, got {magic!r}"
        )
    if version != FORMAT_VERSION:
        raise FormatError(
            f"container format version {version} is not supported "
            f"(this build writes and reads version {FORMAT_VERSION})"
        )

    suite = suites.by_id(suite_id)

    unknown = flags & ~_KNOWN_FLAGS
    if unknown:
        # Refuse by name rather than ignoring the bit: an unknown flag means
        # the writer used a feature this build does not implement, and
        # decrypting half of what the file says would be worse than failing.
        raise FormatError(
            f"unknown header flags 0x{unknown:04x}; the file uses a feature "
            f"this build does not implement (known flags: 0x{_KNOWN_FLAGS:04x})"
        )

    nonce = reader.take(suite.nonce_len, "AEAD nonce")
    ephemeral_public = reader.take_prefixed(
        "ephemeral X25519 public key", X25519_KEY_LEN
    )
    kem_ciphertext = reader.take_prefixed(
        "ML-KEM-768 ciphertext", MLKEM768_CIPHERTEXT_LEN
    )

    header = Header(
        suite=suite,
        flags=flags,
        key_id=key_id,
        salt=salt,
        nonce=nonce,
        ephemeral_public=ephemeral_public,
        kem_ciphertext=kem_ciphertext,
        version=version,
    )
    return header, data[: reader.pos], reader.rest()


def encrypt(
    plaintext: bytes,
    recipient: PublicKey,
    suite: Suite = DEFAULT_SUITE,
    sender: Optional[SigningPrivateKey] = None,
) -> bytes:
    """Encrypt to a recipient, optionally signing as `sender`.

    Signing happens *before* encryption: the signature block is prepended to
    the plaintext and the whole thing is sealed, so the signer's identity is
    confidential and the signature covers what was actually written rather
    than the ciphertext. See signing.py for why that ordering matters.
    """
    ephemeral_public, kem_ciphertext, ikm = hybrid.encapsulate(recipient)

    payload = plaintext
    flags = FLAGS_NONE
    if sender is not None:
        payload = signing.sign_payload(plaintext, sender, recipient, suite)
        flags = FLAG_SIGNED

    header = Header(
        suite=suite,
        flags=flags,
        key_id=recipient.key_id,
        salt=os.urandom(SALT_LEN),
        # The AEAD key is unique per file (fresh ephemeral X25519 key, fresh
        # ML-KEM encapsulation, fresh salt), so this nonce is never reused
        # under it. A random nonce is belt-and-braces; the freshness of the
        # key is what actually rules out the catastrophic nonce-reuse case.
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
    ciphertext = suite.aead(key).encrypt(header.nonce, payload, header_bytes)
    return header_bytes + ciphertext


@dataclass(frozen=True)
class Opened:
    """The result of opening a container.

    `signer` is the signing key the file carries, or None if it is unsigned.
    `verified` says whether that key was checked against one the caller
    supplied: a signature that verifies against the key embedded in the file
    proves the file is internally consistent, not who wrote it. Only a caller
    who pinned the sender's public key gets `verified=True`, and only that
    caller has learned an identity.
    """

    plaintext: bytes
    signer: Optional[SigningPublicKey] = None
    verified: bool = False


def open_container(
    container: bytes,
    identity: PrivateKey,
    sender: Optional[SigningPublicKey] = None,
) -> Opened:
    """Decrypt a container and, if it is signed, check the signatures.

    Passing `sender` demands authentication: an unsigned file, a file signed by
    a different key, or a signature that does not verify all raise
    SignatureError rather than returning plaintext.
    """
    header, header_bytes, ciphertext = parse_header(container)

    recipient = identity.public_key()
    if header.key_id != recipient.key_id:
        raise WrongRecipientError(
            f"this file was encrypted for key id {header.key_id_hex}, "
            f"but the supplied identity is {recipient.key_id_hex}"
        )

    ikm = hybrid.decapsulate(
        identity, header.ephemeral_public, header.kem_ciphertext
    )
    key = hybrid.derive_key(
        ikm=ikm,
        salt=header.salt,
        suite=header.suite,
        ephemeral_public=header.ephemeral_public,
        kem_ciphertext=header.kem_ciphertext,
        recipient=recipient,
    )

    try:
        payload = header.suite.aead(key).decrypt(
            header.nonce, ciphertext, header_bytes
        )
    except InvalidTag:
        raise DecryptionError(
            "authentication failed: the file was modified, or it was not "
            "encrypted for this key"
        ) from None

    if not header.signed:
        if sender is not None:
            # Fail closed: the caller asked for authentication and this file
            # cannot provide it. Returning the plaintext with a shrug is how
            # "verified" quietly comes to mean nothing.
            raise SignatureError(
                "sender verification was requested, but this file is not signed"
            )
        return Opened(plaintext=payload)

    plaintext, signer = signing.open_payload(
        payload, recipient, header.suite, expected_sender=sender
    )
    return Opened(
        plaintext=plaintext, signer=signer, verified=sender is not None
    )


def decrypt(
    container: bytes,
    identity: PrivateKey,
    sender: Optional[SigningPublicKey] = None,
) -> bytes:
    """Decrypt a container and return just the plaintext.

    A thin wrapper over open_container for callers that do not care who signed.
    Note that it still *checks* a signature if one is present -- it only
    discards the answer about who produced it.
    """
    return open_container(container, identity, sender).plaintext
