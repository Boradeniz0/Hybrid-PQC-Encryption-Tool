"""Chunked AEAD: round trips, and the four ways a chunked file can be forged.

Sealing each chunk on its own is the easy half. The half worth testing is that
rearranging, deleting, repeating or importing chunks -- every one of which is a
sequence of individually valid ciphertexts -- is still rejected. Those attacks
need no key and no cryptanalysis, only a text editor, so they are the ones that
actually get tried.
"""

from __future__ import annotations

import io
import os

import pytest

from hpqc import container, streaming
from hpqc.container import FLAG_CHUNKED, FLAG_SIGNED
from hpqc.errors import (
    DecryptionError,
    FormatError,
    SignatureError,
    WrongRecipientError,
)
from hpqc.streaming import CHUNK_SIZE, TAG_LEN, WIRE_CHUNK_SIZE
from hpqc.suites import AES_256_GCM, CHACHA20_POLY1305

SUITES = [CHACHA20_POLY1305, AES_256_GCM]

# Every size where the chunker has to make a decision: nothing at all, inside
# one chunk, exactly on a boundary, and one byte either side of one.
BOUNDARY_SIZES = [
    0,
    1,
    CHUNK_SIZE - 1,
    CHUNK_SIZE,
    CHUNK_SIZE + 1,
    2 * CHUNK_SIZE,
    2 * CHUNK_SIZE + 1,
    3 * CHUNK_SIZE - 1,
]


class Drip:
    """A reader that never returns everything it was asked for.

    `read(n)` on a pipe may come back short without being at EOF. A file object
    hides that, so a test using only BytesIO would pass whether or not the code
    handles it -- and the failure it hides is a chunk split down the middle,
    which looks exactly like corruption.
    """

    def __init__(self, data: bytes, most: int = 7) -> None:
        self._data = data
        self._pos = 0
        self._most = most

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = len(self._data) - self._pos
        block = self._data[self._pos : self._pos + min(n, self._most)]
        self._pos += len(block)
        return block


def seal_stream(data: bytes, recipient, suite=CHACHA20_POLY1305) -> bytes:
    sink = io.BytesIO()
    container.encrypt_stream(io.BytesIO(data), sink, recipient, suite)
    return sink.getvalue()


def open_bytes(blob: bytes, identity, sender=None):
    sink = io.BytesIO()
    opened = container.decrypt_stream(io.BytesIO(blob), sink, identity, sender)
    return sink.getvalue(), opened


def split(blob: bytes):
    """Split a chunked container into (header_bytes, [chunk, ...])."""
    header, header_bytes, _ = container.parse_header(blob)
    body = blob[len(header_bytes) :]
    chunks = [
        body[i : i + WIRE_CHUNK_SIZE] for i in range(0, len(body), WIRE_CHUNK_SIZE)
    ]
    return header_bytes, chunks


class TestRoundTrip:
    @pytest.mark.parametrize("size", BOUNDARY_SIZES)
    def test_a_stream_round_trips(self, size, alice, alice_pub) -> None:
        data = os.urandom(size)
        back, opened = open_bytes(seal_stream(data, alice_pub), alice)
        assert back == data
        assert opened.chunks == max(1, -(-size // CHUNK_SIZE))

    @pytest.mark.parametrize("suite", SUITES, ids=lambda s: s.aead_name)
    def test_both_aeads_stream(self, suite, alice, alice_pub) -> None:
        data = os.urandom(2 * CHUNK_SIZE + 5)
        back, _ = open_bytes(seal_stream(data, alice_pub, suite), alice)
        assert back == data

    def test_a_dripping_source_is_read_correctly(self, alice, alice_pub) -> None:
        """A pipe, not a file: short reads on both the writing and reading side."""
        data = os.urandom(2 * CHUNK_SIZE + 13)
        sink = io.BytesIO()
        container.encrypt_stream(Drip(data), sink, alice_pub)
        blob = sink.getvalue()

        out = io.BytesIO()
        container.decrypt_stream(Drip(blob), out, alice)
        assert out.getvalue() == data

    def test_the_header_says_chunked(self, alice_pub) -> None:
        header, _, _ = container.parse_header(seal_stream(b"x" * 10, alice_pub))
        assert header.chunked
        assert not header.signed
        assert header.flags == FLAG_CHUNKED

    def test_overhead_is_one_tag_per_chunk(self, alice_pub) -> None:
        """No length prefixes, no per-chunk framing: the tags are the whole cost."""
        data = os.urandom(2 * CHUNK_SIZE + 1)
        blob = seal_stream(data, alice_pub)
        header_bytes, chunks = split(blob)
        assert len(chunks) == 3
        assert len(blob) == len(header_bytes) + len(data) + 3 * TAG_LEN

    def test_the_plaintext_is_not_in_the_container(self, alice_pub) -> None:
        marker = b"the-quick-brown-fox" * 16
        blob = seal_stream(marker * 400, alice_pub)
        assert marker not in blob

    def test_two_streams_of_the_same_input_differ(self, alice_pub) -> None:
        """Fresh KEM material per file, so nothing repeats across containers."""
        data = b"identical" * 1000
        assert seal_stream(data, alice_pub) != seal_stream(data, alice_pub)

    def test_info_can_count_chunks_without_the_key(self, alice_pub) -> None:
        data = os.urandom(3 * CHUNK_SIZE + 20)
        blob = seal_stream(data, alice_pub)
        _, header_bytes, _ = container.parse_header(blob)
        payload = len(blob) - len(header_bytes)
        assert streaming.chunk_count(payload) == 4
        assert payload - 4 * TAG_LEN == len(data)


class TestTamperResistance:
    """The attacks that need no key: cut, paste, and reorder valid chunks."""

    @pytest.fixture
    def three_chunks(self, alice_pub):
        data = os.urandom(3 * CHUNK_SIZE)
        blob = seal_stream(data, alice_pub)
        header_bytes, chunks = split(blob)
        assert len(chunks) == 3
        return data, blob, header_bytes, chunks

    def test_truncation_is_refused(self, three_chunks, alice) -> None:
        """The whole reason the final-chunk marker exists.

        Every remaining chunk is a genuine ciphertext sealed by the real
        sender. Nothing but the marker distinguishes "the file ends here" from
        "the file was cut here".
        """
        _, _, header_bytes, chunks = three_chunks
        with pytest.raises(DecryptionError, match="chunk 1"):
            open_bytes(header_bytes + chunks[0] + chunks[1], alice)

    def test_extension_is_refused(self, three_chunks, alice) -> None:
        _, blob, _, chunks = three_chunks
        with pytest.raises(DecryptionError, match="chunk 2"):
            open_bytes(blob + chunks[2], alice)

    def test_reordering_is_refused(self, three_chunks, alice) -> None:
        _, _, header_bytes, chunks = three_chunks
        with pytest.raises(DecryptionError, match="chunk 0"):
            open_bytes(header_bytes + chunks[1] + chunks[0] + chunks[2], alice)

    def test_repeating_a_chunk_is_refused(self, three_chunks, alice) -> None:
        _, _, header_bytes, chunks = three_chunks
        with pytest.raises(DecryptionError, match="chunk 1"):
            open_bytes(header_bytes + chunks[0] + chunks[0] + chunks[2], alice)

    def test_a_chunk_from_another_file_is_refused(
        self, three_chunks, alice, alice_pub
    ) -> None:
        """Same recipient, same size, same position -- and still rejected.

        The AEAD key is derived per container, so a chunk only ever fits the
        file it was written for. This is the case a nonce scheme alone would
        not catch.
        """
        _, _, header_bytes, chunks = three_chunks
        _, others = split(seal_stream(os.urandom(3 * CHUNK_SIZE), alice_pub))
        with pytest.raises(DecryptionError, match="chunk 1"):
            open_bytes(header_bytes + chunks[0] + others[1] + chunks[2], alice)

    def test_a_partial_chunk_is_refused(self, three_chunks, alice) -> None:
        _, blob, _, _ = three_chunks
        with pytest.raises(DecryptionError):
            open_bytes(blob[:-40], alice)

    def test_a_payload_shorter_than_a_tag_is_refused(self, alice, alice_pub) -> None:
        blob = seal_stream(b"", alice_pub)
        _, header_bytes, _ = container.parse_header(blob)
        with pytest.raises(FormatError, match="too short to hold"):
            open_bytes(header_bytes, alice)

    @pytest.mark.parametrize(
        "offset, field",
        [(20, "salt"), (36, "nonce prefix"), (100, "ephemeral key"), (1000, "kem ct")],
    )
    def test_header_tampering_is_caught_on_the_first_chunk(
        self, offset, field, alice, alice_pub
    ) -> None:
        """A flipped header bit fails chunk 0, not the last chunk.

        Note what this does *not* prove. Every field here is also bound into
        the HKDF transcript or the nonce, so it would fail even with no
        associated data at all -- the key would simply be different. The test
        that isolates the associated data is the next one.
        """
        blob = bytearray(seal_stream(os.urandom(2 * CHUNK_SIZE), alice_pub))
        blob[offset] ^= 0x01
        with pytest.raises(DecryptionError, match="chunk 0"):
            open_bytes(bytes(blob), alice)

    @pytest.mark.parametrize("index", range(streaming.NONCE_PREFIX_LEN, 12))
    def test_the_unused_nonce_bytes_are_protected_by_the_associated_data(
        self, index, alice, alice_pub
    ) -> None:
        """The five header bytes whose only protection is the AAD.

        A chunked container feeds seven of the header's twelve nonce bytes into
        the STREAM nonce. The other five reach neither the nonce nor the HKDF
        transcript, so nothing about the derived key depends on them -- and
        without the header as associated data, flipping one would produce a
        different container that still decrypted to the same plaintext.

        That is the whole of what the AAD uniquely buys here, and it is worth
        stating narrowly rather than repeating "the header is authenticated" as
        if it were doing work that HKDF already does.
        """
        blob = bytearray(seal_stream(os.urandom(2 * CHUNK_SIZE), alice_pub))
        blob[32 + index] ^= 0x01
        with pytest.raises(DecryptionError, match="chunk 0"):
            open_bytes(bytes(blob), alice)

    @pytest.mark.parametrize("offset", [4, 5, 6])
    def test_structural_header_fields_are_refused_before_any_chunk(
        self, offset, alice, alice_pub
    ) -> None:
        """Version, suite and flags are checked by the parser, not the tag."""
        blob = bytearray(seal_stream(os.urandom(2 * CHUNK_SIZE), alice_pub))
        blob[offset] ^= 0x01
        with pytest.raises(FormatError):
            open_bytes(bytes(blob), alice)

    def test_a_flipped_bit_inside_a_chunk_is_refused(self, three_chunks, alice) -> None:
        _, blob, header_bytes, _ = three_chunks
        tampered = bytearray(blob)
        tampered[len(header_bytes) + WIRE_CHUNK_SIZE + 100] ^= 0x01
        with pytest.raises(DecryptionError, match="chunk 1"):
            open_bytes(bytes(tampered), alice)

    def test_the_wrong_identity_is_refused(self, alice_pub, bob) -> None:
        with pytest.raises(WrongRecipientError):
            open_bytes(seal_stream(b"secret" * 1000, alice_pub), bob)


def test_without_the_final_marker_truncation_succeeds(
    monkeypatch, alice, alice_pub
) -> None:
    """Proof that the marker is the defence, not an incidental byte.

    Deleting a chunk is caught only because the new last chunk was sealed as
    "not final" and must now be opened as "final". Make every chunk claim to be
    final and the same truncation goes through, handing back a shorter file
    with no error at all -- which is what this asserts. A test that only checks
    the attack fails today cannot tell you *what* is stopping it.
    """
    monkeypatch.setattr(streaming, "_FINAL", b"\x00")

    data = os.urandom(3 * CHUNK_SIZE)
    blob = seal_stream(data, alice_pub)
    header_bytes, chunks = split(blob)

    forged, _ = open_bytes(header_bytes + chunks[0] + chunks[1], alice)
    assert forged == data[: 2 * CHUNK_SIZE]


class TestNonce:
    def test_the_layout_is_prefix_counter_flag(self) -> None:
        prefix = bytes(range(streaming.NONCE_PREFIX_LEN))
        assert streaming.chunk_nonce(prefix, 0, False) == prefix + b"\x00\x00\x00\x00\x00"
        assert streaming.chunk_nonce(prefix, 1, True) == prefix + b"\x00\x00\x00\x01\x01"
        assert streaming.chunk_nonce(prefix, 0x01020304, False) == (
            prefix + b"\x01\x02\x03\x04\x00"
        )

    def test_the_nonce_is_the_length_both_aeads_want(self) -> None:
        nonce = streaming.chunk_nonce(b"x" * streaming.NONCE_PREFIX_LEN, 3, True)
        assert len(nonce) == CHACHA20_POLY1305.nonce_len == AES_256_GCM.nonce_len

    def test_final_and_non_final_nonces_differ(self) -> None:
        prefix = b"y" * streaming.NONCE_PREFIX_LEN
        assert streaming.chunk_nonce(prefix, 7, True) != streaming.chunk_nonce(
            prefix, 7, False
        )

    def test_the_counter_refuses_to_wrap(self) -> None:
        """Wrapping would mean reusing a nonce, which is the one thing to avoid."""
        prefix = b"z" * streaming.NONCE_PREFIX_LEN
        with pytest.raises(FormatError, match="chunk counter"):
            streaming.chunk_nonce(prefix, streaming.MAX_CHUNKS, False)

    def test_a_wrong_length_prefix_is_a_programming_error(self) -> None:
        with pytest.raises(ValueError, match="nonce prefix"):
            streaming.chunk_nonce(b"short", 0, False)

    def test_the_prefix_comes_from_the_header_nonce(self, alice_pub) -> None:
        header, _, _ = container.parse_header(seal_stream(b"hello", alice_pub))
        assert header.nonce_prefix == header.nonce[: streaming.NONCE_PREFIX_LEN]
        assert len(header.nonce) == header.suite.nonce_len


class TestBothShapes:
    """decrypt_stream is the one reader, because the file chooses the shape."""

    def test_it_reads_a_one_shot_container(self, alice, alice_pub) -> None:
        blob = container.encrypt(b"small enough", alice_pub)
        back, opened = open_bytes(blob, alice)
        assert back == b"small enough"
        assert opened.chunks is None
        assert opened.plaintext == b"small enough"

    def test_it_reads_a_signed_one_shot_container(
        self, alice, alice_pub, carol, carol_pub
    ) -> None:
        blob = container.encrypt(b"from carol", alice_pub, sender=carol)
        back, opened = open_bytes(blob, alice, carol_pub)
        assert back == b"from carol"
        assert opened.verified and opened.signer == carol_pub

    def test_a_chunked_container_returns_no_plaintext_in_memory(
        self, alice, alice_pub
    ) -> None:
        data = os.urandom(CHUNK_SIZE + 1)
        _, opened = open_bytes(seal_stream(data, alice_pub), alice)
        assert opened.plaintext == b""
        assert opened.chunks == 2

    def test_asking_to_verify_a_sender_on_a_chunked_file_fails_closed(
        self, alice, alice_pub, carol_pub
    ) -> None:
        """A chunked file is never signed, so the request cannot be satisfied.

        Handing back the plaintext anyway is how "verified" quietly stops
        meaning anything.
        """
        with pytest.raises(SignatureError, match="not signed"):
            open_bytes(seal_stream(b"x" * 100, alice_pub), alice, carol_pub)

    def test_the_one_shot_reader_refuses_a_chunked_container(
        self, alice, alice_pub
    ) -> None:
        blob = seal_stream(b"x" * 100, alice_pub)
        with pytest.raises(FormatError, match="chunked"):
            container.open_container(blob, alice)

    def test_a_header_claiming_both_shapes_is_refused(self, alice_pub) -> None:
        blob = bytearray(seal_stream(b"x" * 100, alice_pub))
        blob[7] = FLAG_SIGNED | FLAG_CHUNKED
        with pytest.raises(FormatError, match="both signed and chunked"):
            container.parse_header(bytes(blob))


class TestReadingPrimitives:
    def test_read_exactly_reassembles_short_reads(self) -> None:
        assert streaming.read_exactly(Drip(b"abcdefghij", most=3), 10) == b"abcdefghij"

    def test_read_exactly_stops_at_the_end(self) -> None:
        assert streaming.read_exactly(io.BytesIO(b"abc"), 10) == b"abc"

    def test_prefixed_stream_serves_the_prefix_first(self) -> None:
        stream = streaming.PrefixedStream(b"head", io.BytesIO(b"tail"))
        assert stream.read(2) == b"he"
        assert stream.read(2) == b"ad"
        assert stream.read(4) == b"tail"
        assert stream.read(1) == b""

    def test_prefixed_stream_does_not_span_the_join(self) -> None:
        """A read never mixes prefix and source bytes; read_exactly does that."""
        stream = streaming.PrefixedStream(b"head", io.BytesIO(b"tail"))
        assert stream.read(8) == b"head"
        assert streaming.read_exactly(stream, 4) == b"tail"

    def test_prefixed_stream_reads_to_the_end(self) -> None:
        stream = streaming.PrefixedStream(b"head", io.BytesIO(b"tail"))
        assert stream.read() == b"headtail"

    def test_prefixed_stream_works_without_a_source(self) -> None:
        stream = streaming.PrefixedStream(b"alone")
        assert stream.read() == b"alone"
        assert stream.read(1) == b""

    def test_chunk_count_matches_what_the_writer_produced(self, alice_pub) -> None:
        for size in BOUNDARY_SIZES:
            blob = seal_stream(os.urandom(size), alice_pub)
            _, header_bytes, _ = container.parse_header(blob)
            payload = len(blob) - len(header_bytes)
            assert streaming.chunk_count(payload) == max(
                1, -(-size // CHUNK_SIZE)
            ), size

    def test_chunk_count_of_nothing_is_nothing(self) -> None:
        assert streaming.chunk_count(0) == 0
