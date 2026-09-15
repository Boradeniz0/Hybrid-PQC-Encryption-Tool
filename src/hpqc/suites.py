"""Cipher suite registry.

A suite pins down every algorithm choice in one byte that travels in the
container header: which hybrid KEM (kems.py) and which AEAD. Every length the
container parser checks comes from `suite.kem`, so a parameter set is a row in
this table rather than a branch in the parser -- which is what the header's
length prefixes were for.

    id    KEM                  AEAD
    0x01  X25519+ML-KEM-768    ChaCha20-Poly1305
    0x02  X25519+ML-KEM-768    AES-256-GCM
    0x03  X448+ML-KEM-1024     ChaCha20-Poly1305
    0x04  X448+ML-KEM-1024     AES-256-GCM

A container has one suite byte, so it has one KEM: a file cannot be addressed
to an ML-KEM-768 recipient and an ML-KEM-1024 recipient at once. It could have
been -- every stanza length-prefixes its own fields -- but only by letting a
prefix *select* how the rest is read instead of being checked against a value
already known. That is the one thing this parser does not do anywhere else, and
it is not worth trading for the convenience.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Optional, Protocol, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from . import kems
from .errors import UnsupportedSuiteError


class Aead(Protocol):
    """What `Suite.aead(key)` hands back.

    Spelled out rather than annotated `object`, which is what it was and which
    meant every `.encrypt` and `.decrypt` call in this project was unchecked.
    The two implementations are cryptography's ChaCha20Poly1305 and AESGCM;
    this is the part of them hpqc uses, and `associated_data` is Optional
    because a wrapped file key is sealed with none.
    """

    def encrypt(
        self, nonce: bytes, data: bytes, associated_data: Optional[bytes]
    ) -> bytes: ...  # noqa: E704

    def decrypt(
        self, nonce: bytes, data: bytes, associated_data: Optional[bytes]
    ) -> bytes: ...  # noqa: E704


@dataclass(frozen=True)
class Suite:
    """One fully-specified algorithm combination."""

    id: int
    name: str
    kem: kems.Kem
    aead_name: str
    aead: Callable[[bytes], Aead]
    key_len: int
    nonce_len: int

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


CHACHA20_POLY1305 = Suite(
    id=0x01,
    name="X25519+ML-KEM-768/ChaCha20-Poly1305",
    kem=kems.X25519_MLKEM768,
    aead_name="ChaCha20-Poly1305",
    aead=ChaCha20Poly1305,
    key_len=32,
    nonce_len=12,
)

AES_256_GCM = Suite(
    id=0x02,
    name="X25519+ML-KEM-768/AES-256-GCM",
    kem=kems.X25519_MLKEM768,
    aead_name="AES-256-GCM",
    aead=AESGCM,
    key_len=32,
    nonce_len=12,
)

CHACHA20_POLY1305_1024 = Suite(
    id=0x03,
    name="X448+ML-KEM-1024/ChaCha20-Poly1305",
    kem=kems.X448_MLKEM1024,
    aead_name="ChaCha20-Poly1305",
    aead=ChaCha20Poly1305,
    key_len=32,
    nonce_len=12,
)

AES_256_GCM_1024 = Suite(
    id=0x04,
    name="X448+ML-KEM-1024/AES-256-GCM",
    kem=kems.X448_MLKEM1024,
    aead_name="AES-256-GCM",
    aead=AESGCM,
    key_len=32,
    nonce_len=12,
)

DEFAULT_SUITE = CHACHA20_POLY1305

_ALL = (CHACHA20_POLY1305, AES_256_GCM, CHACHA20_POLY1305_1024, AES_256_GCM_1024)
_BY_ID: Dict[int, Suite] = {s.id: s for s in _ALL}

# What the --aead flag accepts on the command line. The KEM half is not chosen
# here: it comes from the recipient's key, which already fixes it.
BY_CLI_NAME: Dict[str, Suite] = {
    "chacha20": CHACHA20_POLY1305,
    "aes": AES_256_GCM,
}

_BY_KEM_AND_AEAD = {(s.kem.id, s.aead_name): s for s in _ALL}


def for_kem(kem: kems.Kem, aead_like: Suite) -> Suite:
    """The suite with this KEM and the AEAD of `aead_like`.

    `--aead` names an AEAD and the recipient's key names a KEM; this is where
    the two meet. Keeping them separate on the command line is deliberate: the
    KEM is not the user's to pick at encryption time -- it is whatever the
    recipient's key already is.
    """
    try:
        return _BY_KEM_AND_AEAD[(kem.id, aead_like.aead_name)]
    except KeyError:  # pragma: no cover - every combination exists today
        raise UnsupportedSuiteError(
            f"no suite combines {kem.name} with {aead_like.aead_name}"
        ) from None


def all_suites() -> Tuple[Suite, ...]:
    """Every suite this build implements, in id order.

    Exposed so that code sizing a buffer can ask "what is the largest any
    registered suite could need" rather than hardcoding today's answer.
    """
    return tuple(_BY_ID[i] for i in sorted(_BY_ID))


def by_id(suite_id: int) -> Suite:
    """Look up a suite by its on-the-wire byte."""
    try:
        return _BY_ID[suite_id]
    except KeyError:
        raise UnsupportedSuiteError(
            f"unknown cipher suite 0x{suite_id:02x}; "
            f"this build supports {', '.join(f'0x{i:02x}' for i in sorted(_BY_ID))}"
        ) from None
