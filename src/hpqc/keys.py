"""Hybrid key pairs: an X25519 key and an ML-KEM-768 key travelling together.

A recipient is always *both* keys. Splitting them would let an attacker strip
the post-quantum half and downgrade the file to plain X25519, so they are
generated, stored, serialised, and identified as one unit.

On-disk armour is one base64 line with a human-readable prefix, plus comment
lines the parser ignores:

    # hpqc public key
    # key id: 6f1c2a...
    hpqc-pk1<base64>

Private key files are created with mode 0600 and hold the ML-KEM *seed*
(64 bytes, FIPS 203 d||z) rather than the 2400-byte expanded key -- the
expanded form is derived deterministically on load.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Union

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from . import backend
from .errors import FormatError

# Wire sizes, all fixed by the algorithms themselves.
X25519_KEY_LEN = 32
MLKEM768_PUBLIC_LEN = 1184
MLKEM768_SEED_LEN = 64

KEY_FORMAT_VERSION = 1
PUBLIC_PREFIX = "hpqc-pk1"
PRIVATE_PREFIX = "hpqc-sk1"

_PUBLIC_BLOB_LEN = 1 + X25519_KEY_LEN + MLKEM768_PUBLIC_LEN
_PRIVATE_BLOB_LEN = 1 + X25519_KEY_LEN + MLKEM768_SEED_LEN

KEY_ID_LEN = 8
_KEY_ID_DOMAIN = b"hpqc-key-id-v1"

PathLike = Union[str, "os.PathLike[str]"]


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(text: str) -> bytes:
    try:
        # validate=True so stray characters are an error, not silently dropped.
        return base64.b64decode(text, validate=True)
    except ValueError as exc:  # binascii.Error subclasses ValueError
        raise FormatError(f"key body is not valid base64: {exc}") from None


def _armour(prefix: str, blob: bytes, comments: "list[str]") -> str:
    lines = [f"# {c}" for c in comments]
    lines.append(prefix + _b64encode(blob))
    return "\n".join(lines) + "\n"


def _dearmour(text: str, prefix: str, kind: str) -> bytes:
    """Pull the single payload line out of an armoured key file."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(prefix):
            raise FormatError(
                f"expected an hpqc {kind} key starting with {prefix!r}, "
                f"got {line[:16]!r}..."
            )
        return _b64decode(line[len(prefix) :])
    raise FormatError(f"no hpqc {kind} key found (file has no payload line)")


def _key_id(x25519_public: bytes, mlkem_public: bytes) -> bytes:
    """Short, non-secret fingerprint of a recipient.

    Only used to tell the user "this file is not for that key" before spending
    a decapsulation; it is a UX affordance, never an access control.
    """
    digest = hashlib.sha256(_KEY_ID_DOMAIN + x25519_public + mlkem_public).digest()
    return digest[:KEY_ID_LEN]


@dataclass(frozen=True)
class PublicKey:
    """A recipient: X25519 public key + ML-KEM-768 encapsulation key."""

    x25519_bytes: bytes
    mlkem_bytes: bytes

    @property
    def key_id(self) -> bytes:
        return _key_id(self.x25519_bytes, self.mlkem_bytes)

    @property
    def key_id_hex(self) -> str:
        return self.key_id.hex()

    def x25519(self) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(self.x25519_bytes)

    def mlkem(self):
        """Return the live ML-KEM-768 public key object."""
        backend.require_mlkem()
        try:
            return backend.MLKEM768PublicKey.from_public_bytes(self.mlkem_bytes)
        except UnsupportedAlgorithm as exc:  # pragma: no cover - stack dependent
            raise backend.wrap_unsupported(exc) from None

    def to_bytes(self) -> bytes:
        return bytes([KEY_FORMAT_VERSION]) + self.x25519_bytes + self.mlkem_bytes

    @classmethod
    def from_bytes(cls, blob: bytes) -> "PublicKey":
        if len(blob) != _PUBLIC_BLOB_LEN:
            raise FormatError(
                f"public key must be {_PUBLIC_BLOB_LEN} bytes, got {len(blob)}"
            )
        if blob[0] != KEY_FORMAT_VERSION:
            raise FormatError(f"unsupported key format version {blob[0]}")
        return cls(
            x25519_bytes=blob[1 : 1 + X25519_KEY_LEN],
            mlkem_bytes=blob[1 + X25519_KEY_LEN :],
        )

    def encode(self) -> str:
        return _armour(
            PUBLIC_PREFIX,
            self.to_bytes(),
            [
                "hpqc public key -- safe to share",
                "algorithms: X25519 + ML-KEM-768 (FIPS 203)",
                f"key id: {self.key_id_hex}",
            ],
        )

    @classmethod
    def decode(cls, text: str) -> "PublicKey":
        return cls.from_bytes(_dearmour(text, PUBLIC_PREFIX, "public"))

    def write(self, path: PathLike) -> None:
        Path(path).write_text(self.encode(), encoding="ascii")

    @classmethod
    def read(cls, path: PathLike) -> "PublicKey":
        return cls.decode(Path(path).read_text(encoding="ascii"))


@dataclass(frozen=True)
class PrivateKey:
    """An identity: X25519 private key + ML-KEM-768 decapsulation seed."""

    x25519_bytes: bytes
    mlkem_seed: bytes

    @classmethod
    def generate(cls) -> "PrivateKey":
        backend.require_mlkem()
        try:
            mlkem_key = backend.MLKEM768PrivateKey.generate()
            seed = mlkem_key.private_bytes_raw()
        except UnsupportedAlgorithm as exc:  # pragma: no cover - stack dependent
            raise backend.wrap_unsupported(exc) from None
        if len(seed) != MLKEM768_SEED_LEN:  # pragma: no cover - backend contract
            raise FormatError(
                f"backend returned a {len(seed)}-byte ML-KEM key, "
                f"expected the {MLKEM768_SEED_LEN}-byte seed"
            )
        x25519_key = X25519PrivateKey.generate()
        return cls(
            x25519_bytes=x25519_key.private_bytes_raw(),
            mlkem_seed=seed,
        )

    def x25519(self) -> X25519PrivateKey:
        return X25519PrivateKey.from_private_bytes(self.x25519_bytes)

    def mlkem(self):
        """Rebuild the ML-KEM-768 private key from its stored seed."""
        backend.require_mlkem()
        try:
            return backend.MLKEM768PrivateKey.from_seed_bytes(self.mlkem_seed)
        except UnsupportedAlgorithm as exc:  # pragma: no cover - stack dependent
            raise backend.wrap_unsupported(exc) from None

    def public_key(self) -> PublicKey:
        return PublicKey(
            x25519_bytes=self.x25519().public_key().public_bytes_raw(),
            mlkem_bytes=self.mlkem().public_key().public_bytes_raw(),
        )

    @property
    def key_id_hex(self) -> str:
        return self.public_key().key_id_hex

    def to_bytes(self) -> bytes:
        return bytes([KEY_FORMAT_VERSION]) + self.x25519_bytes + self.mlkem_seed

    @classmethod
    def from_bytes(cls, blob: bytes) -> "PrivateKey":
        if len(blob) != _PRIVATE_BLOB_LEN:
            raise FormatError(
                f"private key must be {_PRIVATE_BLOB_LEN} bytes, got {len(blob)}"
            )
        if blob[0] != KEY_FORMAT_VERSION:
            raise FormatError(f"unsupported key format version {blob[0]}")
        return cls(
            x25519_bytes=blob[1 : 1 + X25519_KEY_LEN],
            mlkem_seed=blob[1 + X25519_KEY_LEN :],
        )

    def encode(self) -> str:
        return _armour(
            PRIVATE_PREFIX,
            self.to_bytes(),
            [
                "hpqc private key -- KEEP THIS SECRET",
                "algorithms: X25519 + ML-KEM-768 (FIPS 203)",
                f"key id: {self.key_id_hex}",
            ],
        )

    @classmethod
    def decode(cls, text: str) -> "PrivateKey":
        return cls.from_bytes(_dearmour(text, PRIVATE_PREFIX, "private"))

    def write(self, path: PathLike) -> None:
        """Write the key with mode 0600, tightening the file if it existed.

        The mode argument to os.open only applies to files it *creates*, so
        overwriting an existing key would otherwise inherit whatever
        permissions were already there -- world-readable included.
        """
        data = self.encode().encode("ascii")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            if hasattr(os, "fchmod"):  # POSIX; Windows has no mode to fix.
                os.fchmod(fd, 0o600)
            os.write(fd, data)
        finally:
            os.close(fd)

    @classmethod
    def read(cls, path: PathLike) -> "PrivateKey":
        return cls.decode(Path(path).read_text(encoding="ascii"))
