"""Passphrase-wrapped private keys: scrypt to a key, AEAD around the secret.

Unwrapped private key files are protected only by their file mode, like `age`
identity files. That is a defensible default -- it is also useless the moment
the file leaves the machine, in a backup, a synced folder, or a stolen laptop.
This module adds the other option: derive a key from a passphrase with scrypt
and seal the private key blob under it.

The wrapper is deliberately generic. It takes an opaque secret blob and a byte
saying what kind of key it holds, so encryption identities and signing
identities share one format and one prefix instead of multiplying key file
types. It knows nothing about what it wraps.

    offset  size   field
    0       1      wrapper format version, 1
    1       1      inner key kind (1 = identity, 2 = signing identity)
    2       1      KDF id, 1 = scrypt
    3       1      scrypt log2(N)
    4       1      scrypt r
    5       1      scrypt p
    6       1      AEAD id, 1 = ChaCha20-Poly1305
    7       16     scrypt salt
    23      12     AEAD nonce
    35      2      length of the sealed blob
    37      ...    sealed blob (ciphertext || 16-byte tag)

Four details worth stating:

**The whole header is associated data**, prefixed by a fixed label, so nothing
in it is malleable -- and the label means these bytes can never be reinterpreted
as some other hpqc structure. Note which fields the AAD is actually doing the
work for. The scrypt parameters and the salt are covered twice over: rewriting
`log2(N)` down to 1 changes the derived key, so the tag would fail even without
the AAD. What the AAD alone protects are the fields that do *not* feed the
derivation -- the kind byte, the format version, the algorithm ids, the sealed
length. Relabelling a wrapped identity as a signing key is the case that
isolates it.

**The parameters travel in the file**, so raising the default later does not
strand keys written today. They are also *checked* before scrypt runs, not
trusted: a file claiming N=2^30 asks for 137 GB of memory, and reading a key
file must not be a way to take the machine down. Everything is validated
against a memory ceiling first.

**The kind byte is in the clear.** It costs nothing -- it says "private key",
which the prefix already announced -- and it lets `hpqc info` describe a file,
and a wrong-file-type mistake fail instantly, without a passphrase and without
spending a third of a second in the KDF.

**Passphrases are NFC-normalised** before encoding to UTF-8. The same
characters typed on two systems can arrive as different byte sequences
otherwise, and the key would simply not open.
"""

from __future__ import annotations

import os
import struct
import unicodedata
from dataclasses import dataclass
from typing import Optional, Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .armour import armour, dearmour, payload_line
from .errors import FormatError, PassphraseError
from .wire import U16, Reader

WRAPPED_PREFIX = "hpqc-wsk1"
WRAP_VERSION = 1

# Domain separation: these bytes are never a container header or a signed
# message, so a wrapped blob cannot be reinterpreted as either.
WRAP_LABEL = b"hpqc-v1 wrapped secret key"

KIND_IDENTITY = 1
KIND_SIGNING_IDENTITY = 2
_KIND_NAMES = {
    KIND_IDENTITY: "X25519 + ML-KEM-768 private key",
    KIND_SIGNING_IDENTITY: "Ed25519 + ML-DSA-65 signing private key",
}

KDF_SCRYPT = 1
AEAD_CHACHA20_POLY1305 = 1

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

# ~128 MiB and roughly a third of a second on a 2026 desktop. scrypt's whole
# point is that memory is the expensive part for an attacker with custom
# hardware, so this leans on N rather than on p.
DEFAULT_LOG_N = 17
DEFAULT_R = 8
DEFAULT_P = 1

# Ceilings applied to whatever a *file* claims. Reading a key file must not be
# a way to exhaust the machine's memory.
MAX_MEMORY_BYTES = 1 << 30  # 1 GiB
MIN_LOG_N = 1
# 2^23 is the largest N that can be legal at all: at r=1 it needs exactly the
# 1 GiB ceiling. Anything above is malformed rather than merely expensive, and
# saying so gives a better message than quoting a memory figure. In practice the
# ceiling binds first -- at the default r=8 the highest usable value is 20.
MAX_LOG_N = 23
MAX_P = 16

_HEADER = struct.Struct(">BBBBBBB16s12s")  # through the nonce
HEADER_LEN = _HEADER.size + U16.size


@dataclass(frozen=True)
class Params:
    """scrypt cost parameters."""

    log_n: int = DEFAULT_LOG_N
    r: int = DEFAULT_R
    p: int = DEFAULT_P

    @property
    def n(self) -> int:
        return 1 << self.log_n

    @property
    def memory_bytes(self) -> int:
        """What scrypt will actually allocate: 128 * N * r."""
        return 128 * self.n * self.r

    def validate(self) -> None:
        """Refuse parameters that are malformed or ruinously expensive."""
        if not MIN_LOG_N <= self.log_n <= MAX_LOG_N:
            raise FormatError(
                f"scrypt log2(N) is {self.log_n}; supported range is "
                f"{MIN_LOG_N}..{MAX_LOG_N}"
            )
        if self.r < 1:
            raise FormatError(f"scrypt r must be at least 1, got {self.r}")
        if not 1 <= self.p <= MAX_P:
            raise FormatError(
                f"scrypt p is {self.p}; supported range is 1..{MAX_P}"
            )
        if self.memory_bytes > MAX_MEMORY_BYTES:
            raise FormatError(
                f"this key file asks scrypt for "
                f"{self.memory_bytes // 2**20} MiB of memory (N=2^{self.log_n}, "
                f"r={self.r}), over the {MAX_MEMORY_BYTES // 2**20} MiB limit; "
                "refusing rather than trying to allocate it"
            )

    def describe(self) -> str:
        return (
            f"scrypt N=2^{self.log_n} r={self.r} p={self.p} "
            f"({self.memory_bytes // 2**20} MiB)"
        )


@dataclass(frozen=True)
class Wrapped:
    """A parsed wrapped key. The secret is still sealed."""

    kind: int
    params: Params
    salt: bytes
    nonce: bytes
    sealed: bytes
    version: int = WRAP_VERSION

    def pack_header(self) -> bytes:
        return _HEADER.pack(
            self.version,
            self.kind,
            KDF_SCRYPT,
            self.params.log_n,
            self.params.r,
            self.params.p,
            AEAD_CHACHA20_POLY1305,
            self.salt,
            self.nonce,
        ) + U16.pack(len(self.sealed))

    def to_bytes(self) -> bytes:
        return self.pack_header() + self.sealed

    @property
    def kind_name(self) -> str:
        return _KIND_NAMES.get(self.kind, f"unknown key kind {self.kind}")

    def describe(self) -> str:
        return f"{self.kind_name}, passphrase-protected, {self.params.describe()}"


def _normalise(passphrase: Union[str, bytes]) -> bytes:
    """UTF-8 bytes of an NFC-normalised passphrase.

    Without normalisation the same passphrase typed on two systems can arrive
    as different bytes -- "é" is one code point or two depending on where it
    came from -- and the key would simply refuse to open with no way to tell
    why.
    """
    if isinstance(passphrase, bytes):
        return passphrase
    if not passphrase:
        raise PassphraseError(
            "refusing to wrap a key with an empty passphrase: it would look "
            "protected and would not be"
        )
    return unicodedata.normalize("NFC", passphrase).encode("utf-8")


def _derive(passphrase: Union[str, bytes], salt: bytes, params: Params) -> bytes:
    params.validate()
    # cryptography's Scrypt rather than hashlib.scrypt: the latter inherits
    # OpenSSL's 32 MiB default memory limit and raises "memory limit exceeded"
    # for anything past N=2^14, which is well below a sensible default.
    return Scrypt(
        salt=salt, length=KEY_LEN, n=params.n, r=params.r, p=params.p
    ).derive(_normalise(passphrase))


def wrap(
    blob: bytes,
    kind: int,
    passphrase: Union[str, bytes],
    params: Params = Params(),
) -> str:
    """Seal a secret blob under a passphrase and return the armoured text."""
    if kind not in _KIND_NAMES:
        raise FormatError(f"refusing to wrap an unknown key kind {kind}")
    params.validate()

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive(passphrase, salt, params)

    # The sealed length is not known until the AEAD has run, and the header
    # carries it, so build the header twice: once to authenticate, once to
    # write. Both must agree, which the round trip enforces.
    sealed_len = len(blob) + 16
    header = Wrapped(
        kind=kind,
        params=params,
        salt=salt,
        nonce=nonce,
        sealed=b"\x00" * sealed_len,
    ).pack_header()

    sealed = ChaCha20Poly1305(key).encrypt(nonce, blob, WRAP_LABEL + header)
    assert len(sealed) == sealed_len  # AEAD contract; guards the header above

    wrapped = Wrapped(
        kind=kind, params=params, salt=salt, nonce=nonce, sealed=sealed
    )
    return armour(
        WRAPPED_PREFIX,
        wrapped.to_bytes(),
        [
            "hpqc wrapped private key -- KEEP THIS SECRET",
            f"contents: {wrapped.kind_name}",
            f"protection: {params.describe()}",
        ],
    )


def is_wrapped(text: str) -> bool:
    """True if this key file text is passphrase-protected.

    Answerable without a passphrase, which is the point of a distinct prefix.
    """
    try:
        return payload_line(text).startswith(WRAPPED_PREFIX)
    except FormatError:
        return False


def parse(text: str) -> Wrapped:
    """Parse a wrapped key file without opening it."""
    reader = Reader(dearmour(text, WRAPPED_PREFIX, "wrapped private"),
                    noun="wrapped key")
    fields = _HEADER.unpack(reader.take(_HEADER.size, "wrapped key header"))
    version, kind, kdf_id, log_n, r, p, aead_id, salt, nonce = fields

    if version != WRAP_VERSION:
        raise FormatError(
            f"wrapped key format version {version} is not supported "
            f"(this build reads version {WRAP_VERSION})"
        )
    if kdf_id != KDF_SCRYPT:
        raise FormatError(
            f"unknown key derivation function id {kdf_id}; "
            f"this build only implements scrypt ({KDF_SCRYPT})"
        )
    if aead_id != AEAD_CHACHA20_POLY1305:
        raise FormatError(
            f"unknown AEAD id {aead_id}; this build only implements "
            f"ChaCha20-Poly1305 ({AEAD_CHACHA20_POLY1305})"
        )
    if kind not in _KIND_NAMES:
        raise FormatError(
            f"unknown wrapped key kind {kind}; the file holds something this "
            "build does not understand"
        )

    params = Params(log_n=log_n, r=r, p=p)
    # Before scrypt, not after: an absurd N must be an error rather than an
    # allocation.
    params.validate()

    sealed_len = reader.take_u16("sealed blob length")
    sealed = reader.take(sealed_len, "sealed blob")
    if reader.rest():
        raise FormatError(
            f"{len(reader.rest())} trailing bytes after the sealed blob"
        )

    return Wrapped(
        kind=kind,
        params=params,
        salt=salt,
        nonce=nonce,
        sealed=sealed,
        version=version,
    )


def unwrap(
    text: str,
    passphrase: Union[str, bytes],
    *,
    expected_kind: Optional[int] = None,
) -> Tuple[bytes, int]:
    """Open a wrapped key file. Returns (secret blob, kind).

    `expected_kind` is checked *before* the KDF runs, so handing a signing key
    to something that wanted an encryption identity fails instantly instead of
    after a third of a second of scrypt and a confusing parse error.
    """
    wrapped = parse(text)

    if expected_kind is not None and wrapped.kind != expected_kind:
        raise FormatError(
            f"this file holds an {wrapped.kind_name}, but an "
            f"{_KIND_NAMES[expected_kind]} was expected"
        )

    key = _derive(passphrase, wrapped.salt, wrapped.params)
    try:
        blob = ChaCha20Poly1305(key).decrypt(
            wrapped.nonce, wrapped.sealed, WRAP_LABEL + wrapped.pack_header()
        )
    except InvalidTag:
        # Indistinguishable from a corrupted file, on purpose: the tag says
        # nothing about *which* input was wrong.
        raise PassphraseError(
            "cannot open this key: wrong passphrase, or the file was modified"
        ) from None

    return blob, wrapped.kind
