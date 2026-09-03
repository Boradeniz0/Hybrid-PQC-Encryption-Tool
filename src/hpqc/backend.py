"""ML-KEM backend probing.

ML-KEM only exists in `cryptography` 46+ *and* only works when the wheel was
built against OpenSSL 3.5 or newer. Both failures are common enough that they
deserve one clear message instead of an ImportError or a bare
UnsupportedAlgorithm from deep inside a key operation.

Import failures are captured rather than raised so that `hpqc --version` and
`hpqc info` keep working on a stack that cannot do ML-KEM at all.
"""

from __future__ import annotations

from typing import Optional

from cryptography.exceptions import UnsupportedAlgorithm

from .errors import BackendError

_IMPORT_ERROR: Optional[Exception] = None

try:
    from cryptography.hazmat.primitives.asymmetric.mlkem import (  # type: ignore[import-not-found]
        MLKEM768PrivateKey,
        MLKEM768PublicKey,
    )
except Exception as exc:  # pragma: no cover - depends on the installed stack
    MLKEM768PrivateKey = None  # type: ignore[assignment,misc]
    MLKEM768PublicKey = None  # type: ignore[assignment,misc]
    _IMPORT_ERROR = exc

_HELP = (
    "ML-KEM-768 is unavailable in this Python environment.\n"
    "hpqc needs `cryptography` >= 46 built against OpenSSL >= 3.5.\n"
    "Try:  pip install --upgrade 'cryptography>=46'\n"
    "Check: python -c \"from cryptography.hazmat.backends.openssl.backend import backend;"
    ' print(backend.openssl_version_text())"'
)


def require_mlkem() -> None:
    """Raise BackendError unless ML-KEM-768 can be imported."""
    if MLKEM768PrivateKey is None:
        raise BackendError(f"{_HELP}\n\nUnderlying import error: {_IMPORT_ERROR}")


def available() -> bool:
    """True if the ML-KEM classes imported cleanly."""
    return MLKEM768PrivateKey is not None


def wrap_unsupported(exc: UnsupportedAlgorithm) -> BackendError:
    """Turn OpenSSL's 'not supported' into the same actionable message."""
    return BackendError(f"{_HELP}\n\nOpenSSL rejected the operation: {exc}")
