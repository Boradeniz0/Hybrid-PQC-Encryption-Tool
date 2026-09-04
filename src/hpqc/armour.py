"""The on-disk text format for keys: one base64 line with a readable prefix.

Every key file hpqc writes looks like this -- comment lines the parser ignores,
then a single payload line whose prefix says what kind of key follows:

    # hpqc public key -- safe to share
    # key id: 6f1c2a...
    hpqc-pk1<base64>

The prefix is load-bearing. It lets a reader reject a signing key handed to an
encryption parser before decoding anything, and it lets `hpqc info` name a file
without understanding its contents. The prefixes are deliberately chosen so
none is a substring of another, which a test enforces.
"""

from __future__ import annotations

import base64
from typing import List

from .errors import FormatError


def b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64decode(text: str) -> bytes:
    try:
        # validate=True so stray characters are an error, not silently dropped.
        return base64.b64decode(text, validate=True)
    except ValueError as exc:  # binascii.Error subclasses ValueError
        raise FormatError(f"key body is not valid base64: {exc}") from None


def armour(prefix: str, blob: bytes, comments: List[str]) -> str:
    lines = [f"# {c}" for c in comments]
    lines.append(prefix + b64encode(blob))
    return "\n".join(lines) + "\n"


def dearmour(text: str, prefix: str, kind: str) -> bytes:
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
        return b64decode(line[len(prefix) :])
    raise FormatError(f"no hpqc {kind} key found (file has no payload line)")


def payload_line(text: str) -> str:
    """Return the payload line, ignoring comments, without checking a prefix.

    Used when the *kind* of key is what we are trying to work out, rather than
    something already known.
    """
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line
    raise FormatError("no hpqc key found (file has no payload line)")
