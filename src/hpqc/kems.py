"""The hybrid KEMs a key can be built from.

A recipient key is a Diffie-Hellman key and an ML-KEM key travelling together
(see keys.py for why they are inseparable). Which *pair* it is has, until now,
been the only possible answer -- X25519 with ML-KEM-768 -- and so was never
written down anywhere except in the constants. A second answer needs it stated.

Two parameter sets:

    id  name                    DH      ML-KEM       NIST category
    1   X25519+ML-KEM-768       X25519  ML-KEM-768   3
    2   X448+ML-KEM-1024        X448    ML-KEM-1024  5

The classical half moves with the post-quantum half on purpose. Pairing
ML-KEM-1024 with X25519 would look like a stronger key and would not be one:
the two halves are combined so that an attacker has to break *both*, so the
strength of the pair is the strength of its stronger half -- and leaving the
classical half at roughly 128 bits while raising the lattice half to category 5
buys nothing against the attacker the upgrade is meant for. X448 is what
matches, and it costs 24 bytes of key and one more multiplication.

What does *not* change between them is the shape of everything else: both ML-KEM
parameter sets produce a 32-byte shared secret and store a 64-byte seed, and
both DH halves are a fixed size their own key type names. Every length in the
wire format is either fixed or length-prefixed and checked against the value
this table gives, so a parameter set is data rather than a code path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Tuple

from cryptography.hazmat.primitives.asymmetric.x448 import (
    X448PrivateKey,
    X448PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from . import backend
from .errors import FormatError

#: Every ML-KEM parameter set hashes down to the same shared secret size, and
#: FIPS 203 stores a private key as the same 64-byte d||z seed for all of them.
KEM_SHARED_SECRET_LEN = 32
KEM_SEED_LEN = 64


@dataclass(frozen=True)
class Kem:
    """One fully-specified hybrid KEM: a DH group and an ML-KEM parameter set.

    Every length a parser needs is here rather than in the parser, so adding a
    parameter set is a row in a table and not an edit to the code that reads
    containers.
    """

    id: int
    name: str
    dh_name: str
    dh_private: Any
    dh_public: Any
    dh_len: int
    dh_shared_len: int
    kem_name: str
    kem_public_len: int
    kem_ciphertext_len: int

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name

    @property
    def ikm_len(self) -> int:
        """How long the combined input keying material is for this KEM."""
        return KEM_SHARED_SECRET_LEN + self.dh_shared_len

    def kem_private_class(self):
        """The ML-KEM private key class, or a clear error if it is missing."""
        backend.require_mlkem(self.kem_name)
        return (
            backend.MLKEM768PrivateKey
            if self.id == X25519_MLKEM768.id
            else backend.MLKEM1024PrivateKey
        )

    def kem_public_class(self):
        backend.require_mlkem(self.kem_name)
        return (
            backend.MLKEM768PublicKey
            if self.id == X25519_MLKEM768.id
            else backend.MLKEM1024PublicKey
        )


X25519_MLKEM768 = Kem(
    id=1,
    name="X25519+ML-KEM-768",
    dh_name="X25519",
    dh_private=X25519PrivateKey,
    dh_public=X25519PublicKey,
    dh_len=32,
    dh_shared_len=32,
    kem_name="ML-KEM-768",
    kem_public_len=1184,
    kem_ciphertext_len=1088,
)

X448_MLKEM1024 = Kem(
    id=2,
    name="X448+ML-KEM-1024",
    dh_name="X448",
    dh_private=X448PrivateKey,
    dh_public=X448PublicKey,
    dh_len=56,
    dh_shared_len=56,
    kem_name="ML-KEM-1024",
    kem_public_len=1568,
    kem_ciphertext_len=1568,
)

#: What `hpqc keygen` produces unless asked otherwise. Category 3 is what the
#: overwhelming majority of deployments want, and it is what X-Wing and the
#: TLS hybrid groups standardised on.
DEFAULT_KEM = X25519_MLKEM768

_BY_ID = {k.id: k for k in (X25519_MLKEM768, X448_MLKEM1024)}

#: What `--kem` accepts on the command line.
BY_CLI_NAME = {
    "mlkem768": X25519_MLKEM768,
    "mlkem1024": X448_MLKEM1024,
}


def all_kems() -> Tuple[Kem, ...]:
    return tuple(_BY_ID[i] for i in sorted(_BY_ID))


def by_id(kem_id: int) -> Kem:
    """Look up a KEM by the byte that identifies it in a key file."""
    try:
        return _BY_ID[kem_id]
    except KeyError:
        raise FormatError(
            f"unknown key type {kem_id}; this build supports "
            f"{', '.join(f'{i} ({_BY_ID[i].name})' for i in sorted(_BY_ID))}"
        ) from None
