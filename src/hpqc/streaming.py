"""Chunked AEAD, so a file does not have to fit in memory.

One-shot encryption has a hard ceiling: `AEAD.encrypt` takes a `bytes`, so the
whole plaintext *and* the whole ciphertext are resident at once. That is fine
for a message and useless for a disk image. The fix is to split the plaintext
into fixed-size chunks and seal each one separately -- but doing that naively
breaks three properties the one-shot version had for free, and each of them has
a wrong version that looks like it works.

**1. A nonce per chunk, never repeated.** Encrypting every chunk under the same
key and the same nonce is catastrophic for both of our AEADs: it leaks the
XOR of the plaintexts and, for Poly1305 and GCM alike, hands over the
authentication key. So the nonce has to vary per chunk, and it has to do so in
a way that cannot collide.

**2. Truncation has to be detectable.** Seal each chunk independently and an
attacker can simply delete the last one. Every remaining chunk still verifies,
and the recipient gets a shorter file with no error at all -- "transfer the
first half of the bank statement" is a complete forgery built without touching
a single byte.

**3. Reordering and splicing have to be detectable.** Chunks are individually
valid ciphertexts. Swapping two of them, or pasting a chunk from another file
encrypted to the same recipient, must not verify.

All three are solved by the **STREAM** construction of Hoang, Reyhanitabar,
Rogaway and Vizar (*Online Authenticated-Encryption and its Nonce-Reuse
Misuse-Resistance*, CRYPTO 2015), which is what this module implements. The
12-byte AEAD nonce is built as:

    offset  size   field
    0       7      per-file nonce prefix (the header's nonce field)
    7       4      chunk counter, big-endian, starting at 0
    11      1      0x01 on the last chunk, 0x00 on every other

That single trailing byte is what closes the truncation hole. The final chunk
is sealed under a nonce ending in 0x01; every other chunk under one ending in
0x00. Delete the last chunk and the new last chunk was sealed as "not final"
but must now be opened as "final" -- different nonce, tag check fails. Append a
chunk and the old final chunk fails the same way in reverse. Swap two chunks
and the counters no longer match. And the key is derived per file, so a chunk
lifted from another container fails no matter what its counter says.

Note what is *not* in the nonce: nothing identifying the file. It does not need
to be. The AEAD key here is unique per container -- fresh ephemeral X25519 key,
fresh ML-KEM encapsulation, fresh HKDF salt -- so the counter only has to be
unique within one file. The 7-byte prefix is belt-and-braces; all 12 bytes of
the header's nonce field are authenticated as part of the associated data
regardless, so an attacker cannot retarget the stream by editing it.

The remaining honest limitation is inherent to streaming and cannot be
engineered away: **decryption releases plaintext before the whole file has been
authenticated.** Chunk 3 is written out before chunk 4 is known to verify. A
one-shot container is all-or-nothing; a stream is not. What the caller can do
is make sure the incomplete output is never mistaken for the real thing, which
is why the CLI decrypts to a temporary file and renames it only on success.
"""

from __future__ import annotations

import struct
from typing import Iterator, Optional, Protocol, Tuple

from cryptography.exceptions import InvalidTag

from .errors import DecryptionError, FormatError
from .suites import Suite

class Source(Protocol):
    """Anything with a `read`. Not `BinaryIO`, and the difference is the point.

    Every input this module takes is read forward, a block at a time, and never
    seeked. Annotating that as `BinaryIO` would be claiming a great deal that is
    not used and is not true of what actually gets passed: `PrefixedStream`
    below has one method, and so does the drip-feeding reader the tests use to
    stand in for a pipe. A protocol says what is required, which is also what
    lets a caller supply something small.
    """

    def read(self, n: int = ...) -> bytes: ...  # noqa: E704


class Sink(Protocol):
    """Anything with a `write`.

    Same argument. The signed-stream verifier is a `Sink` and nothing else; it
    exists to sit between the chunk reader and the caller's real sink.

    Named `Source` and `Sink` rather than `Reader` and `Writer` because `wire`
    already has a `Reader` -- a cursor over a byte string, which is a different
    thing entirely -- and two types with one name in a project this size is a
    bug waiting for an import order to change. `source` and `sink` are what the
    parameters have always been called anyway.
    """

    def write(self, data: bytes) -> object: ...  # noqa: E704


#: Plaintext bytes per chunk. 64 KiB is the same figure age uses: large enough
#: that the 16-byte tag is 0.02% overhead, small enough that the working set
#: stays in cache and a truncated stream wastes little work.
CHUNK_SIZE = 64 * 1024

TAG_LEN = 16

#: What one chunk occupies on the wire. Every chunk but the last is exactly
#: this long, which is what lets the reader find the boundaries without a
#: length prefix -- and a length prefix would be attacker-controlled data read
#: before authentication, which is exactly what this format avoids elsewhere.
WIRE_CHUNK_SIZE = CHUNK_SIZE + TAG_LEN

NONCE_PREFIX_LEN = 7
_COUNTER = struct.Struct(">I")
_NOT_FINAL = b"\x00"
_FINAL = b"\x01"

#: A 32-bit counter, so 2**32 chunks of 64 KiB: 256 TiB per file. Reaching it
#: is refused rather than allowed to wrap, because wrapping means nonce reuse.
MAX_CHUNKS = 1 << 32
MAX_STREAM_BYTES = MAX_CHUNKS * CHUNK_SIZE


def chunk_nonce(prefix: bytes, index: int, final: bool) -> bytes:
    """Build the STREAM nonce for chunk `index`."""
    if len(prefix) != NONCE_PREFIX_LEN:
        raise ValueError(
            f"nonce prefix must be {NONCE_PREFIX_LEN} bytes, got {len(prefix)}"
        )
    if index >= MAX_CHUNKS:
        raise FormatError(
            f"stream is longer than {MAX_STREAM_BYTES} bytes, the most a "
            f"{_COUNTER.size * 8}-bit chunk counter can address without reuse"
        )
    return prefix + _COUNTER.pack(index) + (_FINAL if final else _NOT_FINAL)


def read_exactly(source: Source, n: int) -> bytes:
    """Read exactly `n` bytes, or everything left if the source ends first.

    `read(n)` on a pipe is allowed to come back short without being at EOF, so
    a single call cannot tell "the stream ended" from "that is all that has
    arrived so far". Getting this wrong would split a chunk in the middle and
    look exactly like corruption.
    """
    parts = []
    remaining = n
    while remaining > 0:
        block = source.read(remaining)
        if not block:
            break
        parts.append(block)
        remaining -= len(block)
    return b"".join(parts)


class PrefixedStream:
    """A reader that serves `prefix` first and then the underlying stream.

    Deciding whether a stream is chunked, and parsing its header, both mean
    consuming bytes that the next stage still needs. Rather than requiring a
    seekable input -- stdin is not -- the consumed bytes are simply handed
    back in front of the rest.
    """

    def __init__(self, prefix: bytes, source: Optional[Source] = None) -> None:
        self._prefix = prefix
        self._pos = 0
        self._source = source

    def read(self, n: int = -1) -> bytes:
        left = self._prefix[self._pos :]
        if n < 0:
            self._pos = len(self._prefix)
            return left + (self._source.read() if self._source else b"")
        if left:
            take = left[:n]
            self._pos += len(take)
            return take
        return self._source.read(n) if self._source else b""


def _blocks(source: Source, size: int) -> Iterator[Tuple[bytes, bool]]:
    """Yield (block, is_final) with exactly one block of look-ahead.

    Whether a chunk is the last one goes into its nonce, so it has to be known
    *before* the chunk is sealed -- hence reading one block ahead rather than
    discovering the end after the fact.

    An empty input yields a single empty final block. That is deliberate: a
    zero-chunk stream would carry no final marker at all, and truncating a file
    to nothing would then be indistinguishable from encrypting nothing.
    """
    current = read_exactly(source, size)
    while True:
        following = read_exactly(source, size)
        if not following:
            yield current, True
            return
        yield current, False
        current = following


def seal(
    source: Source,
    sink: Sink,
    key: bytes,
    suite: Suite,
    prefix: bytes,
    associated_data: bytes,
) -> int:
    """Chunk-encrypt `source` into `sink`. Returns the number of chunks."""
    aead = suite.aead(key)
    count = 0
    for block, final in _blocks(source, CHUNK_SIZE):
        sink.write(aead.encrypt(chunk_nonce(prefix, count, final), block, associated_data))
        count += 1
    return count


def open_stream(
    source: Source,
    sink: Sink,
    key: bytes,
    suite: Suite,
    prefix: bytes,
    associated_data: bytes,
) -> int:
    """Chunk-decrypt `source` into `sink`. Returns the number of chunks.

    Raises before writing anything for a chunk that does not verify -- but
    chunks already written stay written. See the note on partial output in the
    module docstring.
    """
    aead = suite.aead(key)
    count = 0
    for block, final in _blocks(source, WIRE_CHUNK_SIZE):
        if len(block) < TAG_LEN:
            raise FormatError(
                f"truncated container: chunk {count} is {len(block)} bytes, "
                f"too short to hold a {TAG_LEN}-byte authentication tag"
            )
        try:
            plaintext = aead.decrypt(
                chunk_nonce(prefix, count, final), block, associated_data
            )
        except InvalidTag:
            raise DecryptionError(
                f"authentication failed on chunk {count}: the file was "
                "modified, truncated, or extended, or it was not encrypted "
                "for this key"
            ) from None
        sink.write(plaintext)
        count += 1
    return count


def chunk_count(payload_len: int) -> int:
    """How many wire chunks a payload of this size holds.

    Used by `hpqc info`, which reports on a file it has no key for and so can
    only count boundaries, never verify them.
    """
    if payload_len <= 0:
        return 0
    return -(-payload_len // WIRE_CHUNK_SIZE)
