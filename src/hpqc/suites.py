"""Cipher suite registry.

A suite pins down every algorithm choice in one byte that travels in the
container header. The KEM half is fixed for v1 (X25519 + ML-KEM-768); only the
AEAD varies. Adding ML-KEM-1024 later means adding suite bytes here, not
changing the parser -- the header length-prefixes every variable-size field.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .errors import UnsupportedSuiteError


@dataclass(frozen=True)
class Suite:
    """One fully-specified algorithm combination."""

    id: int
    name: str
    kem: str
    aead_name: str
    aead: Callable[[bytes], object]
    key_len: int
    nonce_len: int

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


CHACHA20_POLY1305 = Suite(
    id=0x01,
    name="X25519+ML-KEM-768/ChaCha20-Poly1305",
    kem="X25519+ML-KEM-768",
    aead_name="ChaCha20-Poly1305",
    aead=ChaCha20Poly1305,
    key_len=32,
    nonce_len=12,
)

AES_256_GCM = Suite(
    id=0x02,
    name="X25519+ML-KEM-768/AES-256-GCM",
    kem="X25519+ML-KEM-768",
    aead_name="AES-256-GCM",
    aead=AESGCM,
    key_len=32,
    nonce_len=12,
)

DEFAULT_SUITE = CHACHA20_POLY1305

_BY_ID: Dict[int, Suite] = {s.id: s for s in (CHACHA20_POLY1305, AES_256_GCM)}

# What the --aead flag accepts on the command line.
BY_CLI_NAME: Dict[str, Suite] = {
    "chacha20": CHACHA20_POLY1305,
    "aes": AES_256_GCM,
}


def by_id(suite_id: int) -> Suite:
    """Look up a suite by its on-the-wire byte."""
    try:
        return _BY_ID[suite_id]
    except KeyError:
        raise UnsupportedSuiteError(
            f"unknown cipher suite 0x{suite_id:02x}; "
            f"this build supports {', '.join(f'0x{i:02x}' for i in sorted(_BY_ID))}"
        ) from None
