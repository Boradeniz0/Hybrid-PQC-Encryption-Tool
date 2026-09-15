"""Signing a file that is streamed, where the signature covers a digest.

A signature is a statement about a whole message. Streaming means the writer
does not have the whole message when it starts and the reader does not have it
when it finishes, so the two halves of that sentence each need an answer.

*The writer* reads the input twice: once to digest it, once to seal it. That is
the cost, and it is not an implementation shortcut -- the signature has to
exist before the first chunk is written, because it goes in front of the
plaintext where a reader meets it first.

*The reader* gets the claimed signer immediately and the verdict at the end. It
can therefore refuse a `--sender` that does not match before releasing a single
byte, which is the half that can be answered early. Whether the signature is
*valid* is only known once the last chunk has gone out -- and that is the
honest, unavoidable cost, mitigated only by never letting the incomplete output
appear under the name the caller asked for.

The adversary throughout is a *recipient*. They hold the file key, so the AEAD
cannot object to anything they build; the signature is the only thing in their
way, which is why the forgeries below are assembled from the inside.
"""

from __future__ import annotations

import hashlib
import io
import os

import pytest

from hpqc import container, signing, streaming
from hpqc.container import (
    FLAG_CHUNKED,
    FLAG_COMMITTED,
    FLAG_RECIPIENTS,
    FLAG_SIGNED,
)
from hpqc.errors import DecryptionError, FormatError, SignatureError
from hpqc.keys import PrivateKey, SigningPrivateKey
from hpqc.signing import SIGNATURE_BLOCK_LEN, STREAM_DIGEST_LEN
from hpqc.streaming import CHUNK_SIZE
from hpqc.suites import AES_256_GCM, CHACHA20_POLY1305

SUITES = [CHACHA20_POLY1305, AES_256_GCM]

# Sizes where the prologue and the chunker interact: nothing at all, less than
# one chunk once the 5365-byte block is in front of it, exactly on a boundary,
# and either side of one.
SIZES = [
    0,
    1,
    CHUNK_SIZE - SIGNATURE_BLOCK_LEN - 1,
    CHUNK_SIZE - SIGNATURE_BLOCK_LEN,
    CHUNK_SIZE - SIGNATURE_BLOCK_LEN + 1,
    CHUNK_SIZE,
    2 * CHUNK_SIZE + 7,
]


def seal(plaintext, to, sender, suite=CHACHA20_POLY1305, hide=False):
    digest = signing.digest_stream(io.BytesIO(plaintext))
    sink = io.BytesIO()
    chunks = container.encrypt_stream_many(
        io.BytesIO(plaintext), sink, to, suite=suite,
        sender=sender, digest=digest, hide_recipients=hide,
    )
    return sink.getvalue(), chunks


def open_bytes(blob, identity, expected=None):
    sink = io.BytesIO()
    opened = container.decrypt_stream(io.BytesIO(blob), sink, identity, expected)
    return sink.getvalue(), opened


class Drip:
    """A reader that never returns everything it was asked for."""

    def __init__(self, data: bytes, most: int = 7) -> None:
        self._data, self._pos, self._most = data, 0, most

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = len(self._data) - self._pos
        block = self._data[self._pos : self._pos + min(n, self._most)]
        self._pos += len(block)
        return block


class TestRoundTrip:
    @pytest.mark.parametrize("size", SIZES)
    def test_every_size_round_trips(self, alice, alice_pub, carol, carol_pub, size):
        plaintext = os.urandom(size)
        blob, chunks = seal(plaintext, [alice_pub], carol)

        out, opened = open_bytes(blob, alice, carol_pub)
        assert out == plaintext
        assert opened.verified and opened.signer == carol_pub
        assert opened.chunks == chunks
        assert opened.plaintext == b""

    @pytest.mark.parametrize("suite", SUITES, ids=lambda s: s.aead_name)
    def test_both_suites(self, alice, alice_pub, carol, carol_pub, suite):
        plaintext = os.urandom(100_000)
        blob, _ = seal(plaintext, [alice_pub], carol, suite)
        assert open_bytes(blob, alice, carol_pub)[0] == plaintext

    def test_the_header_says_signed_and_chunked(self, alice_pub, carol):
        blob, _ = seal(b"x" * 100_000, [alice_pub], carol)
        header, _, _ = container.parse_header(blob)
        assert header.flags == FLAG_SIGNED | FLAG_CHUNKED
        assert header.signed and header.chunked and not header.multi

    def test_all_three_flags_at_once(self, alice, alice_pub, bob, bob_pub, carol, carol_pub):
        plaintext = os.urandom(150_000)
        blob, _ = seal(plaintext, [alice_pub, bob_pub], carol)

        header, _, _ = container.parse_header(blob)
        assert header.flags == (
            FLAG_SIGNED | FLAG_CHUNKED | FLAG_RECIPIENTS | FLAG_COMMITTED
        )

        for identity in (alice, bob):
            out, opened = open_bytes(blob, identity, carol_pub)
            assert out == plaintext and opened.verified

    def test_it_works_on_a_pipe(self, alice, alice_pub, carol, carol_pub):
        """Seven bytes at a time, through the signature block and out."""
        plaintext = os.urandom(80_000)
        blob, _ = seal(plaintext, [alice_pub], carol)

        sink = io.BytesIO()
        opened = container.decrypt_stream(Drip(blob), sink, alice, carol_pub)
        assert sink.getvalue() == plaintext and opened.verified

    def test_the_signer_is_still_confidential(self, alice_pub, carol):
        """The block is inside the AEAD, so the header gives nothing away."""
        blob, _ = seal(b"x" * 100_000, [alice_pub], carol)
        public = carol.public_key()
        assert public.ed25519_bytes not in blob
        assert public.mldsa_bytes not in blob

    def test_an_unpinned_reader_still_learns_who_signed(
        self, alice, alice_pub, carol, carol_pub
    ):
        blob, _ = seal(b"x" * 70_000, [alice_pub], carol)
        _, opened = open_bytes(blob, alice)
        assert opened.signer == carol_pub
        assert not opened.verified


class TestTheEarlyCheck:
    """What the reader can decide before it writes anything."""

    def test_the_wrong_sender_writes_no_output_at_all(
        self, alice, alice_pub, carol, mallory_pub
    ):
        """The whole point of putting the block at the front.

        With a trailer this could not be done: the mismatch would be found
        after the last chunk had already gone out.
        """
        blob, _ = seal(os.urandom(300_000), [alice_pub], carol)

        sink = io.BytesIO()
        with pytest.raises(SignatureError, match="but verification was requested"):
            container.decrypt_stream(io.BytesIO(blob), sink, alice, mallory_pub)
        assert sink.getvalue() == b""

    def test_an_unsigned_stream_fails_closed(self, alice, alice_pub, carol_pub):
        sink = io.BytesIO()
        container.encrypt_stream_many(
            io.BytesIO(os.urandom(100_000)), sink, [alice_pub]
        )
        out = io.BytesIO()
        with pytest.raises(SignatureError, match="not signed"):
            container.decrypt_stream(io.BytesIO(sink.getvalue()), out, alice, carol_pub)
        assert out.getvalue() == b""

    def test_a_signed_header_over_an_unsigned_payload_is_refused(
        self, alice, alice_pub
    ):
        """Chunk 0 starts with plaintext, and a signature block it is not."""
        sink = io.BytesIO()
        container.encrypt_stream_many(
            io.BytesIO(b"\x00" * 100_000), sink, [alice_pub]
        )
        blob = bytearray(sink.getvalue())
        blob[7] |= FLAG_SIGNED

        out = io.BytesIO()
        with pytest.raises((DecryptionError, FormatError, SignatureError)):
            container.decrypt_stream(io.BytesIO(bytes(blob)), out, alice)


def forge(blob, identity, mutate):
    """Rebuild a container the way a recipient can: with the real file key.

    `mutate(plaintext_stream_bytes) -> bytes` gets everything that was sealed,
    signature block and plaintext together, and returns what to seal instead.
    """
    header, header_bytes, _ = container.parse_header(blob)
    _, key = container._open_setup(header, identity)

    # Unwrap every chunk back to the sealed stream.
    payload = blob[len(header_bytes) :]
    plain = io.BytesIO()
    streaming.open_stream(
        io.BytesIO(payload), plain, key, header.suite,
        header.nonce_prefix, header_bytes,
    )
    sealed = io.BytesIO()
    streaming.seal(
        io.BytesIO(mutate(plain.getvalue())), sealed, key, header.suite,
        header.nonce_prefix, header_bytes,
    )
    return header_bytes + sealed.getvalue()


class TestARecipientCannotForge:
    def test_changing_the_message_is_caught(self, alice, alice_pub, carol, carol_pub):
        """The case the AEAD cannot see, because the forger holds its key."""
        plaintext = b"transfer 100" + b"\x00" * 200_000
        blob, _ = seal(plaintext, [alice_pub], carol)

        forged = forge(
            blob, alice, lambda s: s.replace(b"transfer 100", b"transfer 900", 1)
        )
        # The AEAD is perfectly happy with it.
        sink = io.BytesIO()
        with pytest.raises(SignatureError, match="does not verify"):
            container.decrypt_stream(io.BytesIO(forged), sink, alice, carol_pub)

    def test_truncating_the_plaintext_is_caught_by_the_signature(
        self, alice, alice_pub, carol, carol_pub
    ):
        """Re-chunked properly, so the STREAM marker has nothing to say.

        Cutting bytes off a container is caught by the final-chunk marker. A
        recipient does not have to cut anything: they re-seal a shorter
        plaintext from scratch, and every chunk is genuine. Only the digest
        notices.
        """
        plaintext = os.urandom(200_000)
        blob, _ = seal(plaintext, [alice_pub], carol)

        forged = forge(blob, alice, lambda s: s[: SIGNATURE_BLOCK_LEN + 50_000])
        sink = io.BytesIO()
        with pytest.raises(SignatureError, match="does not verify"):
            container.decrypt_stream(io.BytesIO(forged), sink, alice, carol_pub)

    def test_extending_the_plaintext_is_caught(
        self, alice, alice_pub, carol, carol_pub
    ):
        plaintext = os.urandom(100_000)
        blob, _ = seal(plaintext, [alice_pub], carol)

        forged = forge(blob, alice, lambda s: s + b"and one more thing")
        sink = io.BytesIO()
        with pytest.raises(SignatureError, match="does not verify"):
            container.decrypt_stream(io.BytesIO(forged), sink, alice, carol_pub)

    def test_the_original_still_opens(self, alice, alice_pub, carol, carol_pub):
        """So the three above cannot pass by breaking the container itself."""
        plaintext = os.urandom(100_000)
        blob, _ = seal(plaintext, [alice_pub], carol)
        assert forge(blob, alice, lambda s: s) == blob
        assert open_bytes(blob, alice, carol_pub)[0] == plaintext

    def test_re_addressing_it_is_caught(
        self, alice, alice_pub, bob, bob_pub, carol, carol_pub
    ):
        """Surreptitious forwarding, streamed: the header is bound too."""
        plaintext = os.urandom(100_000)
        blob, _ = seal(plaintext, [alice_pub], carol)

        header, header_bytes, _ = container.parse_header(blob)
        _, key = container._open_setup(header, alice)
        plain = io.BytesIO()
        streaming.open_stream(
            io.BytesIO(blob[len(header_bytes) :]), plain, key, header.suite,
            header.nonce_prefix, header_bytes,
        )

        # A fresh container to bob, around the identical sealed stream.
        header2, header2_bytes, key2 = container._seal_setup(
            [bob_pub], CHACHA20_POLY1305, FLAG_SIGNED | FLAG_CHUNKED
        )
        sealed = io.BytesIO()
        streaming.seal(
            io.BytesIO(plain.getvalue()), sealed, key2, CHACHA20_POLY1305,
            header2.nonce_prefix, header2_bytes,
        )
        forged = header2_bytes + sealed.getvalue()

        sink = io.BytesIO()
        with pytest.raises(SignatureError, match="does not verify"):
            container.decrypt_stream(io.BytesIO(forged), sink, bob, carol_pub)


class TestTheConstruction:
    def test_the_digest_is_sha512_and_domain_separated(self):
        assert STREAM_DIGEST_LEN == 64
        digest = signing.stream_digest()
        digest.update(b"abc")
        assert digest.digest() == hashlib.sha512(
            signing.STREAM_DIGEST_LABEL + b"abc"
        ).digest()
        assert digest.digest() != hashlib.sha512(b"abc").digest()

    def test_digest_stream_matches_the_one_shot_digest(self):
        data = os.urandom(300_000)
        expected = signing.stream_digest()
        expected.update(data)
        assert signing.digest_stream(io.BytesIO(data)) == expected.digest()
        assert signing.digest_stream(Drip(data)) == expected.digest()

    def test_the_three_labels_are_distinct(self):
        labels = {
            signing.SIG_LABEL,
            signing.SIG_CONTAINER_LABEL,
            signing.SIG_STREAM_LABEL,
        }
        assert len(labels) == 3

    def test_the_signed_message_binds_the_header(self, alice_pub, carol_pub):
        digest = b"\x11" * STREAM_DIGEST_LEN
        one = signing.stream_signed_message(
            digest, carol_pub, b"header-one", CHACHA20_POLY1305
        )
        two = signing.stream_signed_message(
            digest, carol_pub, b"header-two", CHACHA20_POLY1305
        )
        assert one != two

    def test_the_header_length_prefix_keeps_it_unambiguous(self, carol_pub):
        """The header and the digest are the only two fields that could slide.

        The digest is fixed-length and last, and the header is length-prefixed,
        so no byte can move between them.
        """
        digest = b"\x22" * STREAM_DIGEST_LEN
        one = signing.stream_signed_message(
            digest, carol_pub, b"AB", CHACHA20_POLY1305
        )
        two = signing.stream_signed_message(
            digest, carol_pub, b"A", CHACHA20_POLY1305
        )
        assert one != two

    def test_a_digest_of_the_wrong_length_is_refused(self, carol_pub):
        with pytest.raises(ValueError, match="must be 64 bytes"):
            signing.stream_signed_message(
                b"short", carol_pub, b"header", CHACHA20_POLY1305
            )

    def test_sender_and_digest_go_together(self, alice_pub, carol):
        with pytest.raises(ValueError, match="sender and digest go together"):
            container.encrypt_stream_many(
                io.BytesIO(b"x"), io.BytesIO(), [alice_pub], sender=carol
            )
        with pytest.raises(ValueError, match="sender and digest go together"):
            container.encrypt_stream_many(
                io.BytesIO(b"x"), io.BytesIO(), [alice_pub],
                digest=b"\x00" * STREAM_DIGEST_LEN,
            )

    def test_a_stream_signature_cannot_be_replayed_into_a_one_shot_file(
        self, alice, alice_pub, carol, carol_pub
    ):
        """Different labels, and the flags are inside the bound header anyway."""
        blob, _ = seal(b"x" * 100, [alice_pub], carol)
        header, header_bytes, _ = container.parse_header(blob)
        _, key = container._open_setup(header, alice)
        plain = io.BytesIO()
        streaming.open_stream(
            io.BytesIO(blob[len(header_bytes) :]), plain, key, header.suite,
            header.nonce_prefix, header_bytes,
        )

        one_shot_header, one_shot_bytes, one_shot_key = container._seal_setup(
            [alice_pub], CHACHA20_POLY1305, FLAG_SIGNED
        )
        forged = one_shot_bytes + CHACHA20_POLY1305.aead(one_shot_key).encrypt(
            one_shot_header.nonce, plain.getvalue(), one_shot_bytes
        )
        with pytest.raises(SignatureError, match="does not verify"):
            container.open_container(forged, alice, carol_pub)


class TestTruncatedSignatureBlocks:
    def test_a_stream_that_ends_inside_the_block(self, alice, alice_pub, carol):
        """Fewer than 5365 bytes were sealed, so there is no block to check."""
        header, header_bytes, key = container._seal_setup(
            [alice_pub], CHACHA20_POLY1305, FLAG_SIGNED | FLAG_CHUNKED
        )
        sealed = io.BytesIO()
        streaming.seal(
            io.BytesIO(b"\x00" * 100), sealed, key, CHACHA20_POLY1305,
            header.nonce_prefix, header_bytes,
        )
        blob = header_bytes + sealed.getvalue()

        sink = io.BytesIO()
        with pytest.raises(SignatureError, match="before the .* block was complete"):
            container.decrypt_stream(io.BytesIO(blob), sink, alice)
        assert sink.getvalue() == b""

    def test_an_empty_signed_stream(self, alice, alice_pub):
        header, header_bytes, key = container._seal_setup(
            [alice_pub], CHACHA20_POLY1305, FLAG_SIGNED | FLAG_CHUNKED
        )
        sealed = io.BytesIO()
        streaming.seal(
            io.BytesIO(b""), sealed, key, CHACHA20_POLY1305,
            header.nonce_prefix, header_bytes,
        )
        sink = io.BytesIO()
        with pytest.raises(SignatureError):
            container.decrypt_stream(
                io.BytesIO(header_bytes + sealed.getvalue()), sink, alice
            )
