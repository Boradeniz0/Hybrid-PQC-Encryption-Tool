"""Exception types raised by hpqc.

Everything user-facing derives from HpqcError so the CLI can turn any expected
failure into a clean message instead of a traceback.
"""

from __future__ import annotations


class HpqcError(Exception):
    """Base class for every error hpqc raises on purpose."""


class FormatError(HpqcError):
    """The input is not a well-formed hpqc container or key file."""


class UnsupportedSuiteError(FormatError):
    """The container asks for a cipher suite this build does not implement."""


class WrongRecipientError(HpqcError):
    """The container was encrypted for a different key than the one supplied."""


class DecryptionError(HpqcError):
    """AEAD authentication failed: wrong key, or the file was tampered with."""


class BackendError(HpqcError):
    """The installed cryptography/OpenSSL stack cannot do ML-KEM."""


class SignatureError(HpqcError):
    """Sender authentication failed, or was asked for and is not present."""
