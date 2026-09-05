"""Exception types raised by hpqc.

Everything user-facing derives from HpqcError so the CLI can turn any expected
failure into a clean message instead of a traceback.
"""

from __future__ import annotations


class HpqcError(Exception):
    """Base class for every error hpqc raises on purpose."""


class FormatError(HpqcError):
    """The input is not a well-formed hpqc container or key file."""


class TruncatedError(FormatError):
    """The input ended before a field the parser still needed.

    Carries `needed`: how many more bytes that one field was short by. A
    reader working from a stream uses it to fetch more and try again, which is
    how a header whose length depends on its own contents -- a recipient list
    -- gets read without either a seek or an unbounded buffer.
    """

    def __init__(self, message: str, needed: int) -> None:
        super().__init__(message)
        self.needed = needed


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


class PassphraseError(HpqcError):
    """A wrapped key could not be opened: wrong passphrase, or none supplied."""
