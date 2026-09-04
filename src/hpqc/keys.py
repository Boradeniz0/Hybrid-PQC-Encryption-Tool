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

Either private key can be written passphrase-protected instead of in the clear:
pass `passphrase=` to `encode`/`write` and the secret is sealed by wrapping.py.
Reading is symmetric, and mismatches fail loudly rather than silently -- a
passphrase supplied for an unprotected key is an error, not a no-op, because the
alternative is a file the user believes is protected and is not.

Signing identities (SigningPrivateKey / SigningPublicKey) are a separate pair
of types with their own armour prefixes. They are deliberately *not* folded
into the encryption identity: a key should do one job, and signing is opt-in,
so v1 encryption keys keep working unchanged. Within a signing identity the
same all-or-nothing rule applies -- Ed25519 and ML-DSA-65 travel together,
because a hybrid signature an attacker can strip down to one algorithm is not
a hybrid signature.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Union

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from . import backend, wrapping
from .armour import armour, dearmour
from .errors import FormatError, PassphraseError

# Wire sizes, all fixed by the algorithms themselves.
X25519_KEY_LEN = 32
MLKEM768_PUBLIC_LEN = 1184
MLKEM768_SEED_LEN = 64
ED25519_KEY_LEN = 32
MLDSA65_PUBLIC_LEN = 1952
MLDSA65_SEED_LEN = 32

KEY_FORMAT_VERSION = 1
PUBLIC_PREFIX = "hpqc-pk1"
PRIVATE_PREFIX = "hpqc-sk1"
SIGN_PUBLIC_PREFIX = "hpqc-spk1"
SIGN_PRIVATE_PREFIX = "hpqc-ssk1"

_PUBLIC_BLOB_LEN = 1 + X25519_KEY_LEN + MLKEM768_PUBLIC_LEN
_PRIVATE_BLOB_LEN = 1 + X25519_KEY_LEN + MLKEM768_SEED_LEN
_SIGN_PUBLIC_BLOB_LEN = 1 + ED25519_KEY_LEN + MLDSA65_PUBLIC_LEN
_SIGN_PRIVATE_BLOB_LEN = 1 + ED25519_KEY_LEN + MLDSA65_SEED_LEN

KEY_ID_LEN = 8
_KEY_ID_DOMAIN = b"hpqc-key-id-v1"
# A separate domain, so an encryption identity and a signing identity can
# never print the same key id and be mistaken for each other.
_SIGN_KEY_ID_DOMAIN = b"hpqc-sign-key-id-v1"

PathLike = Union[str, "os.PathLike[str]"]


def _decode_secret(cls, text: str, passphrase, *, kind: int, prefix: str, noun: str):
    """Decode a private key file, wrapped or not.

    Both mismatches are errors on purpose. A wrapped key with no passphrase
    cannot be opened, and a passphrase handed to an unwrapped key means the
    caller believes the file is protected when it is not -- worth saying rather
    than ignoring.
    """
    if wrapping.is_wrapped(text):
        if passphrase is None:
            raise PassphraseError(
                f"this {noun} key is passphrase-protected; "
                "supply the passphrase to open it"
            )
        blob, _ = wrapping.unwrap(text, passphrase, expected_kind=kind)
        return cls.from_bytes(blob)

    if passphrase is not None:
        raise PassphraseError(
            f"a passphrase was supplied, but this {noun} key file is not "
            "passphrase-protected"
        )
    return cls.from_bytes(dearmour(text, prefix, noun))


def _write_private_file(path: PathLike, text: str) -> None:
    """Write a secret file at mode 0600, atomically.

    Two hazards, both of which have bitten this file before or would have:

    * **Permissions.** The mode argument to os.open applies only to files it
      *creates*, so writing over an existing key would inherit whatever
      permissions were already there -- world-readable included. Creating a
      fresh file and renaming it over the target sidesteps that entirely: the
      mode belongs to the new inode. fchmod stays as belt and braces, since
      umask can only clear bits from 0600, never add them.

    * **Losing the key.** `hpqc passwd` rewrites a private key in place. A
      truncating write that fails halfway leaves no key at all and no way back.
      So the new contents are written to a temporary file in the same directory,
      flushed to disk, and then renamed over the target -- os.replace is atomic,
      so a reader sees either the old key or the new one.

    It lives in one function so neither fix can come back undone in a copy of it.
    """
    path = Path(path)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        if hasattr(os, "fchmod"):  # POSIX; Windows has no mode to fix.
            os.fchmod(fd, 0o600)
        os.write(fd, text.encode("ascii"))
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(tmp_name)
        raise
    else:
        os.close(fd)
    os.replace(tmp_name, path)


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
        return armour(
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
        return cls.from_bytes(dearmour(text, PUBLIC_PREFIX, "public"))

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

    def encode(self, passphrase=None, params=None) -> str:
        """Armour the key, passphrase-protected if a passphrase is given."""
        if passphrase is not None:
            return wrapping.wrap(
                self.to_bytes(),
                wrapping.KIND_IDENTITY,
                passphrase,
                params or wrapping.Params(),
            )
        return armour(
            PRIVATE_PREFIX,
            self.to_bytes(),
            [
                "hpqc private key -- KEEP THIS SECRET",
                "algorithms: X25519 + ML-KEM-768 (FIPS 203)",
                f"key id: {self.key_id_hex}",
            ],
        )

    @classmethod
    def decode(cls, text: str, passphrase=None) -> "PrivateKey":
        return _decode_secret(
            cls,
            text,
            passphrase,
            kind=wrapping.KIND_IDENTITY,
            prefix=PRIVATE_PREFIX,
            noun="private",
        )

    def write(self, path: PathLike, passphrase=None, params=None) -> None:
        """Write the key at mode 0600. See _write_private_file."""
        _write_private_file(path, self.encode(passphrase, params))

    @classmethod
    def read(cls, path: PathLike, passphrase=None) -> "PrivateKey":
        return cls.decode(Path(path).read_text(encoding="ascii"), passphrase)


def _sign_key_id(ed25519_public: bytes, mldsa_public: bytes) -> bytes:
    """Short, non-secret fingerprint of a signing identity.

    Printed so a recipient can see *which* key signed a file. Like the
    encryption key id it is a UX affordance: 8 bytes is far too short to pin an
    identity on, so verification always compares full public keys, never this.
    """
    digest = hashlib.sha256(
        _SIGN_KEY_ID_DOMAIN + ed25519_public + mldsa_public
    ).digest()
    return digest[:KEY_ID_LEN]


@dataclass(frozen=True)
class SigningPublicKey:
    """A sender: Ed25519 verifying key + ML-DSA-65 verifying key."""

    ed25519_bytes: bytes
    mldsa_bytes: bytes

    @property
    def key_id(self) -> bytes:
        return _sign_key_id(self.ed25519_bytes, self.mldsa_bytes)

    @property
    def key_id_hex(self) -> str:
        return self.key_id.hex()

    def ed25519(self) -> Ed25519PublicKey:
        try:
            return Ed25519PublicKey.from_public_bytes(self.ed25519_bytes)
        except ValueError as exc:  # pragma: no cover - length is checked upstream
            raise FormatError(f"invalid Ed25519 verifying key: {exc}") from None

    def mldsa(self):
        """Return the live ML-DSA-65 verifying key."""
        backend.require_mldsa()
        try:
            return backend.MLDSA65PublicKey.from_public_bytes(self.mldsa_bytes)
        except UnsupportedAlgorithm as exc:  # pragma: no cover - stack dependent
            raise backend.wrap_unsupported(exc, "ML-DSA-65") from None
        except ValueError as exc:  # pragma: no cover - length is checked upstream
            raise FormatError(f"invalid ML-DSA-65 verifying key: {exc}") from None

    def to_bytes(self) -> bytes:
        return bytes([KEY_FORMAT_VERSION]) + self.ed25519_bytes + self.mldsa_bytes

    @classmethod
    def from_bytes(cls, blob: bytes) -> "SigningPublicKey":
        if len(blob) != _SIGN_PUBLIC_BLOB_LEN:
            raise FormatError(
                f"signing public key must be {_SIGN_PUBLIC_BLOB_LEN} bytes, "
                f"got {len(blob)}"
            )
        if blob[0] != KEY_FORMAT_VERSION:
            raise FormatError(f"unsupported key format version {blob[0]}")
        return cls(
            ed25519_bytes=blob[1 : 1 + ED25519_KEY_LEN],
            mldsa_bytes=blob[1 + ED25519_KEY_LEN :],
        )

    def encode(self) -> str:
        return armour(
            SIGN_PUBLIC_PREFIX,
            self.to_bytes(),
            [
                "hpqc signing public key -- safe to share",
                "algorithms: Ed25519 + ML-DSA-65 (FIPS 204)",
                f"key id: {self.key_id_hex}",
            ],
        )

    @classmethod
    def decode(cls, text: str) -> "SigningPublicKey":
        return cls.from_bytes(dearmour(text, SIGN_PUBLIC_PREFIX, "signing public"))

    def write(self, path: PathLike) -> None:
        Path(path).write_text(self.encode(), encoding="ascii")

    @classmethod
    def read(cls, path: PathLike) -> "SigningPublicKey":
        return cls.decode(Path(path).read_text(encoding="ascii"))


@dataclass(frozen=True)
class SigningPrivateKey:
    """A sender's secrets: Ed25519 private key + ML-DSA-65 seed.

    Like the encryption identity this stores the ML-DSA *seed* (32 bytes) and
    expands it on load, so the file stays small and the expanded key never
    touches disk.
    """

    ed25519_bytes: bytes
    mldsa_seed: bytes

    @classmethod
    def generate(cls) -> "SigningPrivateKey":
        backend.require_mldsa()
        try:
            mldsa_key = backend.MLDSA65PrivateKey.generate()
            seed = mldsa_key.private_bytes_raw()
        except UnsupportedAlgorithm as exc:  # pragma: no cover - stack dependent
            raise backend.wrap_unsupported(exc, "ML-DSA-65") from None
        if len(seed) != MLDSA65_SEED_LEN:  # pragma: no cover - backend contract
            raise FormatError(
                f"backend returned a {len(seed)}-byte ML-DSA key, "
                f"expected the {MLDSA65_SEED_LEN}-byte seed"
            )
        return cls(
            ed25519_bytes=Ed25519PrivateKey.generate().private_bytes_raw(),
            mldsa_seed=seed,
        )

    def ed25519(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(self.ed25519_bytes)

    def mldsa(self):
        """Rebuild the ML-DSA-65 private key from its stored seed."""
        backend.require_mldsa()
        try:
            return backend.MLDSA65PrivateKey.from_seed_bytes(self.mldsa_seed)
        except UnsupportedAlgorithm as exc:  # pragma: no cover - stack dependent
            raise backend.wrap_unsupported(exc, "ML-DSA-65") from None
        except ValueError as exc:  # pragma: no cover - length is checked upstream
            raise FormatError(f"invalid ML-DSA-65 seed: {exc}") from None

    def public_key(self) -> SigningPublicKey:
        return SigningPublicKey(
            ed25519_bytes=self.ed25519().public_key().public_bytes_raw(),
            mldsa_bytes=self.mldsa().public_key().public_bytes_raw(),
        )

    @property
    def key_id_hex(self) -> str:
        return self.public_key().key_id_hex

    def to_bytes(self) -> bytes:
        return bytes([KEY_FORMAT_VERSION]) + self.ed25519_bytes + self.mldsa_seed

    @classmethod
    def from_bytes(cls, blob: bytes) -> "SigningPrivateKey":
        if len(blob) != _SIGN_PRIVATE_BLOB_LEN:
            raise FormatError(
                f"signing private key must be {_SIGN_PRIVATE_BLOB_LEN} bytes, "
                f"got {len(blob)}"
            )
        if blob[0] != KEY_FORMAT_VERSION:
            raise FormatError(f"unsupported key format version {blob[0]}")
        return cls(
            ed25519_bytes=blob[1 : 1 + ED25519_KEY_LEN],
            mldsa_seed=blob[1 + ED25519_KEY_LEN :],
        )

    def encode(self, passphrase=None, params=None) -> str:
        """Armour the key, passphrase-protected if a passphrase is given."""
        if passphrase is not None:
            return wrapping.wrap(
                self.to_bytes(),
                wrapping.KIND_SIGNING_IDENTITY,
                passphrase,
                params or wrapping.Params(),
            )
        return armour(
            SIGN_PRIVATE_PREFIX,
            self.to_bytes(),
            [
                "hpqc signing private key -- KEEP THIS SECRET",
                "algorithms: Ed25519 + ML-DSA-65 (FIPS 204)",
                f"key id: {self.key_id_hex}",
            ],
        )

    @classmethod
    def decode(cls, text: str, passphrase=None) -> "SigningPrivateKey":
        return _decode_secret(
            cls,
            text,
            passphrase,
            kind=wrapping.KIND_SIGNING_IDENTITY,
            prefix=SIGN_PRIVATE_PREFIX,
            noun="signing private",
        )

    def write(self, path: PathLike, passphrase=None, params=None) -> None:
        """Write the key at mode 0600. See _write_private_file."""
        _write_private_file(path, self.encode(passphrase, params))

    @classmethod
    def read(cls, path: PathLike, passphrase=None) -> "SigningPrivateKey":
        return cls.decode(Path(path).read_text(encoding="ascii"), passphrase)
