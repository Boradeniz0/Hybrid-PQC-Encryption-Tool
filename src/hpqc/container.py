"""The .hpqc container format: header layout, encryption, decryption.

Byte layout (all integers big-endian):

    offset  size   field
    0       4      magic, b"HPQC"
    4       1      format version, 1
    5       1      cipher suite id  -> suites.by_id()
    6       2      flags, reserved, must be 0
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

v1 encrypts in one shot, so the whole plaintext is held in memory. Streaming
(chunked AEAD with a per-chunk counter nonce and an explicit final-chunk flag)
is the natural v2 -- the `flags` field is reserved for exactly that.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Tuple

from cryptography.exceptions import InvalidTag

from . import hybrid, suites
from .errors import DecryptionError, FormatError, WrongRecipientError
from .hybrid import MLKEM768_CIPHERTEXT_LEN, SALT_LEN
from .keys import KEY_ID_LEN, X25519_KEY_LEN, PrivateKey, PublicKey
from .suites import DEFAULT_SUITE, Suite

MAGIC = b"HPQC"
FORMAT_VERSION = 1
FLAGS_NONE = 0

_PREAMBLE = struct.Struct(">4sBBH8s16s")  # magic, version, suite, flags, key id, salt
_U16 = struct.Struct(">H")


class _Reader:
    """Bounds-checked forward cursor with error messages worth reading."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def take(self, n: int, what: str) -> bytes:
        end = self._pos + n
        if end > len(self._data):
            raise FormatError(
                f"truncated container: need {n} bytes for {what} at offset "
                f"{self._pos}, only {len(self._data) - self._pos} remain"
            )
        chunk = self._data[self._pos : end]
        self._pos = end
        return chunk

    def take_u16(self, what: str) -> int:
        return _U16.unpack(self.take(_U16.size, what))[0]

    def take_prefixed(self, what: str, expected: int) -> bytes:
        length = self.take_u16(f"{what} length")
        if length != expected:
            raise FormatError(
                f"{what} is {length} bytes, expected {expected} for this suite"
            )
        return self.take(length, what)

    @property
    def pos(self) -> int:
        return self._pos

    def rest(self) -> bytes:
        return self._data[self._pos :]


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
                _U16.pack(len(self.ephemeral_public)),
                self.ephemeral_public,
                _U16.pack(len(self.kem_ciphertext)),
                self.kem_ciphertext,
            )
        )

    @property
    def key_id_hex(self) -> str:
        return self.key_id.hex()


def parse_header(data: bytes) -> Tuple[Header, bytes, bytes]:
    """Split a container into (header, header_bytes, aead_ciphertext).

    `header_bytes` is returned verbatim rather than re-packed: it is the AEAD's
    associated data, and re-serialising could paper over a byte we did not
    round-trip faithfully.
    """
    reader = _Reader(data)
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

    if flags != FLAGS_NONE:
        raise FormatError(
            f"unknown header flags 0x{flags:04x}; the file likely uses a "
            "feature this build does not implement"
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
    plaintext: bytes, recipient: PublicKey, suite: Suite = DEFAULT_SUITE
) -> bytes:
    """Encrypt to a recipient. Returns the full container."""
    ephemeral_public, kem_ciphertext, ikm = hybrid.encapsulate(recipient)

    header = Header(
        suite=suite,
        flags=FLAGS_NONE,
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
    ciphertext = suite.aead(key).encrypt(header.nonce, plaintext, header_bytes)
    return header_bytes + ciphertext


def decrypt(container: bytes, identity: PrivateKey) -> bytes:
    """Decrypt a container with our identity. Raises on any tampering."""
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
        return header.suite.aead(key).decrypt(header.nonce, ciphertext, header_bytes)
    except InvalidTag:
        raise DecryptionError(
            "authentication failed: the file was modified, or it was not "
            "encrypted for this key"
        ) from None
