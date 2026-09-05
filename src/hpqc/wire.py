"""Bounds-checked forward reading, shared by every parser in hpqc.

Two structures get parsed from attacker-controlled bytes: the container header
and, once decrypted, the signature block. Both need the same discipline -- read
forward, never past the end, and say exactly what was short -- so the cursor
lives in one place rather than being reimplemented per format. A parser that
walks off the end of a buffer is the classic way a "just decode it" bug becomes
a crash on chosen input.
"""

from __future__ import annotations

import struct

from .errors import FormatError, TruncatedError

U16 = struct.Struct(">H")


class Reader:
    """Forward cursor over a byte string, with error messages worth reading."""

    def __init__(self, data: bytes, *, noun: str = "container") -> None:
        self._data = data
        self._pos = 0
        self._noun = noun

    def take(self, n: int, what: str) -> bytes:
        end = self._pos + n
        if end > len(self._data):
            # TruncatedError, not a bare FormatError: the shortfall is the one
            # thing only the parser knows, and a streaming reader needs it to
            # decide how much more to ask for. It is still a FormatError, so
            # callers that only care that parsing failed are unaffected.
            raise TruncatedError(
                f"truncated {self._noun}: need {n} bytes for {what} at offset "
                f"{self._pos}, only {len(self._data) - self._pos} remain",
                needed=end - len(self._data),
            )
        chunk = self._data[self._pos : end]
        self._pos = end
        return chunk

    def take_u16(self, what: str) -> int:
        return U16.unpack(self.take(U16.size, what))[0]

    def take_prefixed(self, what: str, expected: int) -> bytes:
        """Read a u16-prefixed field whose length must be exactly `expected`.

        The prefix is checked rather than trusted: a lying length must be an
        error here, not a short read somewhere downstream.
        """
        length = self.take_u16(f"{what} length")
        if length != expected:
            raise FormatError(
                f"{what} is {length} bytes, expected {expected} here"
            )
        return self.take(length, what)

    @property
    def pos(self) -> int:
        return self._pos

    def rest(self) -> bytes:
        return self._data[self._pos :]
