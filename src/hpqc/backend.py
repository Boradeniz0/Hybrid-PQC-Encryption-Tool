"""Post-quantum backend probing: ML-KEM-768 and ML-DSA-65.

Both live in `cryptography` 46+ and both need the wheel to have been built
against OpenSSL 3.5 or newer. Either failure is common enough that it deserves
one clear, actionable message instead of an ImportError or a bare
UnsupportedAlgorithm surfacing from deep inside a key operation.

Import failures are captured rather than raised so that `hpqc --version` and
`hpqc info` keep working on a stack that cannot do post-quantum at all -- and
so that a stack with ML-KEM but no ML-DSA can still encrypt without signing.
"""

from __future__ import annotations

from typing import Optional

from cryptography.exceptions import UnsupportedAlgorithm

from .errors import BackendError

_MLKEM_IMPORT_ERROR: Optional[Exception] = None
_MLDSA_IMPORT_ERROR: Optional[Exception] = None

try:
    from cryptography.hazmat.primitives.asymmetric.mlkem import (  # type: ignore[import-not-found]
        MLKEM768PrivateKey,
        MLKEM768PublicKey,
    )
except Exception as exc:  # pragma: no cover - depends on the installed stack
    MLKEM768PrivateKey = None  # type: ignore[assignment,misc]
    MLKEM768PublicKey = None  # type: ignore[assignment,misc]
    _MLKEM_IMPORT_ERROR = exc

try:
    from cryptography.hazmat.primitives.asymmetric.mldsa import (  # type: ignore[import-not-found]
        MLDSA65PrivateKey,
        MLDSA65PublicKey,
    )
except Exception as exc:  # pragma: no cover - depends on the installed stack
    MLDSA65PrivateKey = None  # type: ignore[assignment,misc]
    MLDSA65PublicKey = None  # type: ignore[assignment,misc]
    _MLDSA_IMPORT_ERROR = exc


def _help(algorithm: str) -> str:
    return (
        f"{algorithm} is unavailable in this Python environment.\n"
        "hpqc needs `cryptography` >= 46 built against OpenSSL >= 3.5.\n"
        "Try:  pip install --upgrade 'cryptography>=46'\n"
        "Check: python -c \"from cryptography.hazmat.backends.openssl.backend "
        'import backend; print(backend.openssl_version_text())"'
    )


def require_mlkem() -> None:
    """Raise BackendError unless ML-KEM-768 can be imported."""
    if MLKEM768PrivateKey is None:
        raise BackendError(
            f"{_help('ML-KEM-768')}\n\nUnderlying import error: {_MLKEM_IMPORT_ERROR}"
        )


def require_mldsa() -> None:
    """Raise BackendError unless ML-DSA-65 can be imported.

    Only signing and signature verification need this, so it is deliberately
    separate: an environment that can encrypt should not be refused outright
    because it cannot sign.
    """
    if MLDSA65PrivateKey is None:
        raise BackendError(
            f"{_help('ML-DSA-65')}\n\nUnderlying import error: {_MLDSA_IMPORT_ERROR}"
        )


def mlkem_available() -> bool:
    """True if the ML-KEM classes imported cleanly."""
    return MLKEM768PrivateKey is not None


def mldsa_available() -> bool:
    """True if the ML-DSA classes imported cleanly."""
    return MLDSA65PrivateKey is not None


def wrap_unsupported(
    exc: UnsupportedAlgorithm, algorithm: str = "ML-KEM-768"
) -> BackendError:
    """Turn OpenSSL's 'not supported' into the same actionable message."""
    return BackendError(f"{_help(algorithm)}\n\nOpenSSL rejected the operation: {exc}")
