"""Several recipients per file: the stanza list, and what it does and does not hide.

Two properties carry most of these tests.

*Every recipient reads the file and nobody else does.* That is the feature, and
the interesting half is the "nobody else": the stanzas carry no key ids, so a
wrong identity is discovered by failing to open any of them rather than by
comparing names.

*The file names nobody.* A recipient list in the clear proves that a particular
set of people were talking, which is often worth more than the message. So the
tests below assert the absence of every recipient's key id in the bytes -- and,
because an absence test passes just as happily when it is looking for the wrong
thing, they also assert its presence in the single-recipient shape that does
publish it.
"""

from __future__ import annotations

import io
import os

import pytest

from hpqc import container, hybrid, recipients, suites
from hpqc.container import (
    FLAG_CHUNKED,
    FLAG_RECIPIENTS,
    FLAG_SIGNED,
    NO_KEY_ID,
)
from hpqc.errors import (
    DecryptionError,
    FormatError,
    SignatureError,
    WrongRecipientError,
)
from hpqc.keys import PrivateKey
from hpqc.recipients import MAX_RECIPIENTS
from hpqc.suites import AES_256_GCM, CHACHA20_POLY1305
from hpqc.wire import U16

SUITES = [CHACHA20_POLY1305, AES_256_GCM]

OFF_FLAGS = 6
OFF_KEY_ID = 8
OFF_SALT = 16
#: Where the recipient count sits: preamble (32) + a 12-byte nonce.
OFF_COUNT = 44
OFF_FIRST_STANZA = 46


@pytest.fixture(scope="module")
def crowd():
    """Five identities, generated once: key generation is the slow part here."""
    return [PrivateKey.generate() for _ in range(5)]


@pytest.fixture(scope="module")
def crowd_pub(crowd):
    return [k.public_key() for k in crowd]


class Counted(io.BytesIO):
    """A BytesIO that counts how many times it was read from."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.reads = 0

    def read(self, n: int = -1) -> bytes:
        self.reads += 1
        return super().read(n)


class Drip:
    """A reader that never returns everything it was asked for.

    The header is no longer a fixed size, so reading it is a loop, and a loop
    over `read` is exactly where a short read on a pipe goes wrong.
    """

    def __init__(self, data: bytes, most: int = 7) -> None:
        self._data = data
        self._pos = 0
        self._most = most
        self.reads = 0

    def read(self, n: int = -1) -> bytes:
        self.reads += 1
        if n < 0:
            n = len(self._data) - self._pos
        block = self._data[self._pos : self._pos + min(n, self._most)]
        self._pos += len(block)
        return block


def stanzas_of(blob: bytes):
    header, _, _ = container.parse_header(blob)
    return header.stanzas


class TestRoundTrip:
    @pytest.mark.parametrize("suite", SUITES, ids=lambda s: s.aead_name)
    @pytest.mark.parametrize("count", [2, 3, 5])
    def test_every_recipient_opens_the_file(self, crowd, crowd_pub, count, suite):
        blob = container.encrypt_many(
            b"attack at dawn", crowd_pub[:count], suite=suite
        )
        for identity in crowd[:count]:
            assert container.decrypt(blob, identity) == b"attack at dawn"

    @pytest.mark.parametrize("slot", [0, 1, 2, 3, 4])
    def test_the_slot_can_be_anywhere_in_the_list(self, crowd, crowd_pub, slot):
        """Trial decryption has to find the right stanza wherever it sits.

        Opening the first one by luck would pass a test that only ever put the
        reader at the front of the queue.
        """
        blob = container.encrypt_many(b"somewhere in here", crowd_pub)
        assert container.decrypt(blob, crowd[slot]) == b"somewhere in here"

    @pytest.mark.parametrize(
        "plaintext", [b"", b"x", b"\x00" * 1024, os.urandom(5000)]
    )
    def test_payload_shapes(self, crowd, crowd_pub, plaintext):
        blob = container.encrypt_many(plaintext, crowd_pub[:2])
        assert container.decrypt(blob, crowd[1]) == plaintext

    def test_one_recipient_still_writes_the_container_it_always_wrote(
        self, alice, alice_pub
    ):
        """The list shape is an addition, not a replacement.

        A single recipient keeps the older header exactly -- same length, same
        key id in the same place -- so every file and every frozen vector that
        predates this feature still describes what the tool writes today.
        """
        blob = container.encrypt_many(b"solo", [alice_pub])
        header, header_bytes, _ = container.parse_header(blob)

        assert header.flags == 0
        assert not header.multi
        assert header.recipient_count == 1
        assert header.key_id == alice_pub.key_id
        assert len(header_bytes) == 1168
        assert container.decrypt(blob, alice) == b"solo"

    def test_hiding_a_single_recipient_uses_the_list_shape(self, alice, alice_pub):
        blob = container.encrypt_many(b"solo", [alice_pub], hide_recipients=True)
        header, _, _ = container.parse_header(blob)

        assert header.multi
        assert header.recipient_count == 1
        assert header.key_id == NO_KEY_ID
        assert container.decrypt(blob, alice) == b"solo"

    def test_the_header_grows_by_exactly_one_stanza_per_recipient(self, crowd_pub):
        sizes = []
        for count in (1, 2, 3, 4):
            _, header_bytes, _ = container.parse_header(
                container.encrypt_many(
                    b"x", crowd_pub[:count], hide_recipients=True
                )
            )
            sizes.append(len(header_bytes))

        stanza = recipients.stanza_len(CHACHA20_POLY1305)
        assert [b - a for a, b in zip(sizes, sizes[1:])] == [stanza] * 3
        assert sizes[0] == OFF_FIRST_STANZA + stanza


class TestPrivacy:
    def test_no_recipient_is_named_anywhere_in_the_file(self, crowd_pub):
        blob = container.encrypt_many(b"who is this for", crowd_pub)
        for public in crowd_pub:
            assert public.key_id not in blob
            assert public.x25519_bytes not in blob
            assert public.mlkem_bytes not in blob

    def test_the_single_recipient_shape_does_name_its_recipient(self, alice_pub):
        """The other half of the test above, and the reason it is not vacuous.

        Searching a container for eight bytes that are not there passes just as
        readily when the search itself is broken. This is the same search
        against the shape that is supposed to contain them.
        """
        blob = container.encrypt_many(b"who is this for", [alice_pub])
        assert alice_pub.key_id in blob

    def test_the_key_id_field_is_zero_and_is_enforced(self, alice, crowd_pub):
        """A fixed field nothing reads is a place to smuggle bytes."""
        blob = bytearray(container.encrypt_many(b"x", crowd_pub[:2]))
        assert bytes(blob[OFF_KEY_ID : OFF_KEY_ID + 8]) == NO_KEY_ID

        blob[OFF_KEY_ID] = 0x41
        with pytest.raises(FormatError, match="key id field is not empty"):
            container.parse_header(bytes(blob))

    def test_the_same_recipient_gets_different_stanzas_every_time(self, alice_pub):
        """Why a fixed all-zero nonce is safe for a wrapped file key.

        The nonce may repeat only because the key never does: each stanza has
        its own ephemeral X25519 key and its own ML-KEM encapsulation behind
        it, so no two wrapping keys are ever the same.
        """
        first = stanzas_of(
            container.encrypt_many(b"x", [alice_pub], hide_recipients=True)
        )[0]
        second = stanzas_of(
            container.encrypt_many(b"x", [alice_pub], hide_recipients=True)
        )[0]

        assert first.ephemeral_public != second.ephemeral_public
        assert first.kem_ciphertext != second.kem_ciphertext
        assert first.wrapped_key != second.wrapped_key

    def test_two_recipients_of_one_file_get_different_stanzas(self, crowd_pub):
        one, two = stanzas_of(container.encrypt_many(b"x", crowd_pub[:2]))
        assert one.ephemeral_public != two.ephemeral_public
        assert one.kem_ciphertext != two.kem_ciphertext
        assert one.wrapped_key != two.wrapped_key


class TestRefusals:
    def test_a_stranger_cannot_open_it(self, crowd, crowd_pub, alice):
        blob = container.encrypt_many(b"not for you", crowd_pub[:3])
        with pytest.raises(WrongRecipientError, match="3 recipient slot"):
            container.decrypt(blob, alice)

    def test_the_refusal_names_no_recipient(self, crowd_pub, alice):
        """Even the error message keeps the promise the format makes."""
        blob = container.encrypt_many(b"not for you", crowd_pub[:3])
        with pytest.raises(WrongRecipientError) as caught:
            container.decrypt(blob, alice)
        for public in crowd_pub[:3]:
            assert public.key_id_hex not in str(caught.value)

    def test_an_empty_recipient_list_is_refused(self):
        with pytest.raises(ValueError, match="at least one recipient"):
            container.encrypt_many(b"x", [])

    def test_a_repeated_recipient_is_refused(self, alice_pub, bob_pub):
        with pytest.raises(ValueError, match="was given twice"):
            container.encrypt_many(b"x", [alice_pub, bob_pub, alice_pub])

    def test_too_many_recipients_is_refused(self, alice_pub):
        """Checked before the duplicate scan, so this costs one key, not 1025."""
        with pytest.raises(ValueError, match=f"than the {MAX_RECIPIENTS}"):
            container.encrypt_many(b"x", [alice_pub] * (MAX_RECIPIENTS + 1))

    def test_claiming_the_signed_flag_on_an_unsigned_list_fails(
        self, crowd, crowd_pub
    ):
        """Both bits are known, so only the tag stops this."""
        blob = bytearray(container.encrypt_many(b"x", crowd_pub[:2]))
        blob[OFF_FLAGS + 1] = FLAG_SIGNED | FLAG_RECIPIENTS

        with pytest.raises(DecryptionError, match="authentication failed"):
            container.decrypt(bytes(blob), crowd[0])

    def test_signing_a_chunked_list_is_still_refused(self, crowd_pub):
        blob = bytearray(container.encrypt_many(b"x", crowd_pub[:2]))
        blob[OFF_FLAGS + 1] = FLAG_SIGNED | FLAG_RECIPIENTS | FLAG_CHUNKED

        with pytest.raises(FormatError, match="both signed and chunked"):
            container.parse_header(bytes(blob))

    @pytest.mark.parametrize("count", [0, MAX_RECIPIENTS + 1, 0xFFFF])
    def test_an_out_of_range_recipient_count_is_refused(self, crowd_pub, count):
        """Bounded before it can ask the parser to do any work."""
        blob = bytearray(container.encrypt_many(b"x", crowd_pub[:2]))
        blob[OFF_COUNT : OFF_COUNT + 2] = U16.pack(count)

        with pytest.raises(FormatError, match="the supported range is"):
            container.parse_header(bytes(blob))


class TestTamperResistance:
    """The whole header is the AEAD's associated data, stanzas included.

    That is what makes the recipient list unforgeable rather than merely
    private: an attacker cannot quietly drop a recipient, because doing so
    breaks the file for everybody who is left.
    """

    @pytest.mark.parametrize("offset", [0, 40, 1200, 2000])
    def test_editing_any_stanza_byte_breaks_the_file_for_everyone(
        self, crowd, crowd_pub, offset
    ):
        """Which error depends on which field was hit, and that is the point.

        Offset 0 is a length prefix, so the parser rejects it before any key is
        touched; the rest land in key material the tag covers. What matters is
        that neither recipient gets a plaintext out of any of them.
        """
        blob = bytearray(container.encrypt_many(b"x", crowd_pub[:2]))
        blob[OFF_FIRST_STANZA + offset] ^= 0x01

        for identity in crowd[:2]:
            with pytest.raises(
                (DecryptionError, FormatError, WrongRecipientError)
            ):
                container.decrypt(bytes(blob), identity)

    def test_removing_a_recipient_cannot_be_done_quietly(self, crowd, crowd_pub):
        """Strip Bob's stanza and Alice notices, even though it was not hers.

        Without the stanzas in the associated data this would succeed silently:
        Alice would read the file exactly as before and never learn that Bob
        had been cut out of a conversation he was meant to be in.
        """
        blob = container.encrypt_many(b"x", crowd_pub[:2])
        _, header_bytes, payload = container.parse_header(blob)
        stanza = recipients.stanza_len(CHACHA20_POLY1305)

        shortened = bytearray(header_bytes[: len(header_bytes) - stanza])
        shortened[OFF_COUNT : OFF_COUNT + 2] = U16.pack(1)
        forged = bytes(shortened) + payload

        # The header is well-formed: it parses, and it claims one recipient.
        header, _, _ = container.parse_header(forged)
        assert header.recipient_count == 1

        # And it is useless, because the payload was sealed over the other one.
        with pytest.raises(DecryptionError, match="authentication failed"):
            container.decrypt(forged, crowd[0])

    def test_a_stanza_from_another_file_does_not_open(self, alice, alice_pub):
        """Every stanza is bound to its file's salt as well as to its recipient."""
        first = container.encrypt_many(b"one", [alice_pub], hide_recipients=True)
        second = container.encrypt_many(b"two", [alice_pub], hide_recipients=True)

        head_a, _, _ = container.parse_header(first)
        head_b, _, _ = container.parse_header(second)

        # Under its own salt it opens; under the other file's it does not.
        assert recipients.unwrap(
            head_a.stanzas, alice, head_a.salt, head_a.suite
        )
        with pytest.raises(WrongRecipientError):
            recipients.unwrap(head_a.stanzas, alice, head_b.salt, head_b.suite)

    def test_a_stanza_cannot_be_moved_to_another_recipient(self, alice, bob, bob_pub):
        blob = container.encrypt_many(b"for bob", [bob_pub], hide_recipients=True)
        header, _, _ = container.parse_header(blob)

        assert recipients.unwrap(header.stanzas, bob, header.salt, header.suite)
        with pytest.raises(WrongRecipientError):
            recipients.unwrap(header.stanzas, alice, header.salt, header.suite)

    @pytest.mark.parametrize("offset", [OFF_SALT, OFF_COUNT - 4, OFF_FLAGS])
    def test_editing_the_preamble_breaks_it(self, crowd, crowd_pub, offset):
        blob = bytearray(container.encrypt_many(b"x", crowd_pub[:2]))
        blob[offset] ^= 0x01
        with pytest.raises((DecryptionError, FormatError, WrongRecipientError)):
            container.decrypt(bytes(blob), crowd[0])


class TestWrappingKeys:
    def test_the_wrap_label_is_distinct_from_the_payload_label(self, alice_pub):
        """Same inputs, different purpose, different key -- by the label alone."""
        ephemeral_public, kem_ciphertext, ikm = hybrid.encapsulate(alice_pub)
        args = dict(
            ikm=ikm,
            salt=b"\x00" * 16,
            suite=CHACHA20_POLY1305,
            ephemeral_public=ephemeral_public,
            kem_ciphertext=kem_ciphertext,
            recipient=alice_pub,
        )
        payload_key = hybrid.derive_key(**args, label=hybrid.HKDF_LABEL)
        wrapping_key = hybrid.derive_key(**args, label=hybrid.WRAP_LABEL)

        assert payload_key != wrapping_key
        assert hybrid.derive_key(**args) == payload_key

    def test_a_stanza_is_actually_sealed_under_the_wrap_label(
        self, alice, alice_pub
    ):
        """Recompute a stanza's key from the outside, and open it by hand.

        The test above only says the two labels differ, which stays true no
        matter which one the wrapping code reaches for -- it passed unchanged
        when both derivations were switched to the payload label. This one
        pins the derivation itself: every input is spelled out here, so the
        stanza opens only if recipients.wrap used exactly these.
        """
        blob = container.encrypt_many(b"x", [alice_pub], hide_recipients=True)
        header, _, _ = container.parse_header(blob)
        stanza = header.stanzas[0]

        ikm = hybrid.decapsulate(
            alice, stanza.ephemeral_public, stanza.kem_ciphertext
        )
        wrapping_key = hybrid.derive_key(
            ikm=ikm,
            salt=header.salt,
            suite=header.suite,
            ephemeral_public=stanza.ephemeral_public,
            kem_ciphertext=stanza.kem_ciphertext,
            recipient=alice_pub,
            label=hybrid.WRAP_LABEL,
        )
        file_key = header.suite.aead(wrapping_key).decrypt(
            b"\x00" * header.suite.nonce_len, stanza.wrapped_key, None
        )
        assert file_key == recipients.unwrap(
            header.stanzas, alice, header.salt, header.suite
        )

    def test_the_wrapped_key_is_the_file_key_and_nothing_else(self, alice, alice_pub):
        blob = container.encrypt_many(b"payload", [alice_pub], hide_recipients=True)
        header, header_bytes, ciphertext = container.parse_header(blob)

        file_key = recipients.unwrap(
            header.stanzas, alice, header.salt, header.suite
        )
        assert len(file_key) == header.suite.key_len
        assert (
            header.suite.aead(file_key).decrypt(
                header.nonce, ciphertext, header_bytes
            )
            == b"payload"
        )

    def test_the_stanza_nonce_is_all_zeros(self):
        assert recipients._zero_nonce(CHACHA20_POLY1305) == b"\x00" * 12
        assert recipients._zero_nonce(AES_256_GCM) == b"\x00" * 12


class TestChunked:
    """Chunking and the recipient list are independent, and compose."""

    @pytest.mark.parametrize("suite", SUITES, ids=lambda s: s.aead_name)
    def test_a_chunked_file_with_several_recipients(self, crowd, crowd_pub, suite):
        plaintext = os.urandom(200_000)
        sink = io.BytesIO()
        chunks = container.encrypt_stream_many(
            io.BytesIO(plaintext), sink, crowd_pub[:3], suite=suite
        )
        assert chunks == 4

        header, _, _ = container.parse_header(sink.getvalue())
        assert header.multi and header.chunked
        assert header.flags == FLAG_RECIPIENTS | FLAG_CHUNKED

        for identity in crowd[:3]:
            got = io.BytesIO()
            opened = container.decrypt_stream(
                io.BytesIO(sink.getvalue()), got, identity
            )
            assert got.getvalue() == plaintext
            assert opened.chunks == 4

    def test_truncation_is_still_caught(self, crowd, crowd_pub):
        plaintext = os.urandom(200_000)
        sink = io.BytesIO()
        container.encrypt_stream_many(io.BytesIO(plaintext), sink, crowd_pub[:2])

        cut = sink.getvalue()[: -(65536 + 16)]
        with pytest.raises(DecryptionError, match="authentication failed on chunk"):
            container.decrypt_stream(io.BytesIO(cut), io.BytesIO(), crowd[0])

    def test_a_stranger_is_refused_before_a_byte_is_written(self, crowd_pub, alice):
        sink = io.BytesIO()
        container.encrypt_stream_many(
            io.BytesIO(os.urandom(200_000)), sink, crowd_pub[:2]
        )
        out = io.BytesIO()
        with pytest.raises(WrongRecipientError):
            container.decrypt_stream(io.BytesIO(sink.getvalue()), out, alice)
        assert out.getvalue() == b""


class TestReadingTheHeader:
    """A header whose length depends on its own contents, read off a pipe."""

    def test_a_header_larger_than_the_read_ahead(self, crowd, crowd_pub):
        many = crowd_pub + [PrivateKey.generate().public_key() for _ in range(10)]
        blob = container.encrypt_many(b"crowded", many)
        _, header_bytes, _ = container.parse_header(blob)
        assert len(header_bytes) > container.HEADER_READ_AHEAD

        got = io.BytesIO()
        container.decrypt_stream(Drip(blob), got, crowd[0])
        assert got.getvalue() == b"crowded"

    def test_the_read_loop_does_not_grow_with_the_recipient_count(self, crowd_pub):
        """Each round asks for at least as much again as it already holds.

        Fetching only the shortfall would be correct and quadratic: one reparse
        per stanza, over a count the writer of the file chooses. Doubling turns
        forty stanzas into a handful of reads instead of a hundred and twenty.
        """
        many = crowd_pub + [PrivateKey.generate().public_key() for _ in range(35)]
        blob = container.encrypt_many(b"x", many)
        _, header_bytes, _ = container.parse_header(blob)
        assert len(header_bytes) > 45_000

        source = Counted(blob)
        header, _, _ = container.read_header(source)
        assert header.recipient_count == len(many)
        assert source.reads <= 12

    def test_a_truncated_header_reports_the_field_that_ran_out(self, crowd_pub):
        blob = container.encrypt_many(b"x", crowd_pub[:2])
        _, header_bytes, _ = container.parse_header(blob)

        with pytest.raises(FormatError, match="truncated container"):
            container.read_header(io.BytesIO(header_bytes[:-40]))

    def test_a_header_promising_stanzas_that_never_arrive_is_refused(
        self, crowd_pub
    ):
        """The loop has to end when the bytes stop coming, not keep asking."""
        blob = container.encrypt_many(b"x", crowd_pub[:2])
        _, header_bytes, _ = container.parse_header(blob)
        front = bytearray(header_bytes[:OFF_FIRST_STANZA])
        front[OFF_COUNT : OFF_COUNT + 2] = U16.pack(MAX_RECIPIENTS)

        with pytest.raises(FormatError, match="truncated container"):
            container.read_header(io.BytesIO(bytes(front)))

    def test_the_cap_covers_the_biggest_header_the_count_check_allows(self):
        """Why the clamp in read_header can never cut a legal header short.

        MAX_RECIPIENTS is the real bound; MAX_HEADER_LEN is that bound measured
        in bytes. If a suite were ever added with a larger stanza and this were
        not updated, the reader would stop mid-header on a perfectly valid file.
        """
        stanza = max(recipients.stanza_len(s) for s in suites.all_suites())
        nonce = max(s.nonce_len for s in suites.all_suites())
        biggest = 32 + nonce + U16.size + MAX_RECIPIENTS * stanza
        assert container.MAX_HEADER_LEN == biggest


def reseal(header_bytes: bytes, payload: bytes, key: bytes, suite, nonce) -> bytes:
    """Rebuild a container around arbitrary payload bytes.

    The adversary for a signature on a shared file is a *recipient*: they hold
    the file key, so they can seal whatever they like under the header they
    received and the AEAD will be perfectly happy. Only the signature is in
    their way, which is why these tests forge from the inside rather than by
    flipping bits from the outside.
    """
    return header_bytes + suite.aead(key).encrypt(nonce, payload, header_bytes)


def payload_of(blob: bytes, identity):
    """(header, header_bytes, file key, decrypted payload) for a container."""
    header, header_bytes, ciphertext = container.parse_header(blob)
    _, key = container._open_setup(header, identity)
    payload = header.suite.aead(key).decrypt(
        header.nonce, ciphertext, header_bytes
    )
    return header, header_bytes, key, payload


class TestSignedRecipientLists:
    """A signature over a file that names none of its recipients.

    The usual construction binds the recipient's public keys into the signed
    message; here there are none to bind, so the header is bound instead --
    every stanza of it. See signing.py.
    """

    @pytest.mark.parametrize("count", [1, 2, 3])
    def test_every_recipient_verifies_the_same_signature(
        self, crowd, crowd_pub, carol, carol_pub, count
    ):
        blob = container.encrypt_many(
            b"minutes", crowd_pub[:count], sender=carol, hide_recipients=True
        )
        header, _, _ = container.parse_header(blob)
        assert header.multi and header.signed

        for identity in crowd[:count]:
            opened = container.open_container(blob, identity, carol_pub)
            assert opened.plaintext == b"minutes"
            assert opened.verified
            assert opened.signer == carol_pub

    def test_it_is_still_confidential_who_signed(self, crowd_pub, carol):
        """`info` reads the header; the signer is inside the AEAD."""
        blob = container.encrypt_many(b"x", crowd_pub[:2], sender=carol)
        assert carol.public_key().ed25519_bytes not in blob
        assert carol.public_key().mldsa_bytes not in blob

    def test_a_recipient_cannot_re_address_it(
        self, crowd, crowd_pub, alice, alice_pub, carol, carol_pub
    ):
        """Surreptitious forwarding, run by somebody who really is a recipient.

        crowd[0] opens the file, keeps the signature block byte for byte, and
        seals it into a fresh container for alice. Alice's AEAD check passes --
        the container is genuinely well-formed -- and the signature does not,
        because it was computed over a header that no longer exists.
        """
        blob = container.encrypt_many(
            b"for the committee", crowd_pub[:3], sender=carol
        )
        _, _, _, payload = payload_of(blob, crowd[0])

        forged = container.encrypt_many(b"placeholder", [alice_pub])
        header2, header2_bytes, key2 = container._seal_setup(
            [alice_pub], CHACHA20_POLY1305, FLAG_RECIPIENTS | FLAG_SIGNED
        )
        forged = reseal(
            header2_bytes, payload, key2, CHACHA20_POLY1305, header2.nonce
        )

        with pytest.raises(SignatureError, match="does not verify"):
            container.open_container(forged, alice, carol_pub)
        # And without a pinned sender either: the signature is checked anyway.
        with pytest.raises(SignatureError, match="does not verify"):
            container.open_container(forged, alice)

    def test_a_recipient_cannot_change_the_message(
        self, crowd, crowd_pub, carol, carol_pub
    ):
        """The case the AEAD cannot touch, because the forger has the key."""
        blob = container.encrypt_many(b"transfer 100", crowd_pub[:2], sender=carol)
        header, header_bytes, key, payload = payload_of(blob, crowd[0])

        block = payload[: len(payload) - len(b"transfer 100")]
        forged = reseal(
            header_bytes,
            block + b"transfer 900",
            key,
            header.suite,
            header.nonce,
        )
        # The AEAD is content: the forger sealed it with the real file key.
        assert container.parse_header(forged)[0].signed
        with pytest.raises(SignatureError, match="does not verify"):
            container.open_container(forged, crowd[1], carol_pub)

    def test_the_original_recipients_can_still_read_it(
        self, crowd, crowd_pub, carol, carol_pub
    ):
        """The pair to the two tests above, so they cannot pass by being broken."""
        blob = container.encrypt_many(b"transfer 100", crowd_pub[:2], sender=carol)
        for identity in crowd[:2]:
            assert (
                container.open_container(blob, identity, carol_pub).plaintext
                == b"transfer 100"
            )

    def test_a_classic_signature_cannot_be_replayed_into_a_list(
        self, alice, alice_pub, carol, carol_pub
    ):
        """The two constructions have different labels, and it shows.

        Without distinct labels a signature made for a named recipient could be
        presented as one made over a container, and the other way round.
        """
        classic = container.encrypt(b"one to one", alice_pub, sender=carol)
        _, _, _, payload = payload_of(classic, alice)

        header, header_bytes, key = container._seal_setup(
            [alice_pub], CHACHA20_POLY1305, FLAG_RECIPIENTS | FLAG_SIGNED
        )
        forged = reseal(
            header_bytes, payload, key, CHACHA20_POLY1305, header.nonce
        )
        with pytest.raises(SignatureError, match="does not verify"):
            container.open_container(forged, alice, carol_pub)

    def test_a_list_signature_cannot_be_replayed_into_a_classic_container(
        self, alice, alice_pub, carol, carol_pub
    ):
        listed = container.encrypt_many(
            b"one to one", [alice_pub], sender=carol, hide_recipients=True
        )
        _, _, _, payload = payload_of(listed, alice)

        header, header_bytes, key = container._seal_setup(
            [alice_pub], CHACHA20_POLY1305, FLAG_SIGNED
        )
        forged = reseal(
            header_bytes, payload, key, CHACHA20_POLY1305, header.nonce
        )
        with pytest.raises(SignatureError, match="does not verify"):
            container.open_container(forged, alice, carol_pub)

    def test_the_wrong_sender_is_named_rather_than_failing_cryptographically(
        self, crowd, crowd_pub, carol, mallory_pub
    ):
        blob = container.encrypt_many(b"x", crowd_pub[:2], sender=carol)
        with pytest.raises(SignatureError, match="but verification was requested"):
            container.open_container(blob, crowd[0], mallory_pub)

    def test_verification_of_an_unsigned_list_fails_closed(self, crowd, crowd_pub, carol_pub):
        blob = container.encrypt_many(b"x", crowd_pub[:2])
        with pytest.raises(SignatureError, match="not signed"):
            container.open_container(blob, crowd[0], carol_pub)

    def test_an_unpinned_signature_is_returned_but_not_verified(
        self, crowd, crowd_pub, carol_pub, carol
    ):
        blob = container.encrypt_many(b"x", crowd_pub[:2], sender=carol)
        opened = container.open_container(blob, crowd[0])
        assert opened.signer == carol_pub
        assert not opened.verified

    @pytest.mark.parametrize("offset", [OFF_FLAGS + 1, OFF_SALT, OFF_FIRST_STANZA + 5])
    def test_editing_the_header_breaks_it(self, crowd, crowd_pub, carol, offset):
        blob = bytearray(container.encrypt_many(b"x", crowd_pub[:2], sender=carol))
        blob[offset] ^= 0x01
        with pytest.raises(
            (DecryptionError, FormatError, WrongRecipientError, SignatureError)
        ):
            container.decrypt(bytes(blob), crowd[0])

    def test_the_signed_message_is_length_prefixed(self, alice_pub, carol_pub):
        """A byte cannot move between the header and the plaintext.

        They are the only two variable-length fields in the message, and
        without the length prefix `header || plaintext` would be the same
        string for a header one byte shorter and a plaintext one byte longer.
        """
        from hpqc import signing

        first = signing.container_signed_message(
            b"BC", carol_pub, b"A", CHACHA20_POLY1305
        )
        second = signing.container_signed_message(
            b"C", carol_pub, b"AB", CHACHA20_POLY1305
        )
        assert first != second


def test_the_two_signing_constructions_use_different_labels() -> None:
    """A direct assertion, and it has to be, which is worth saying out loud.

    Everywhere else in this suite a domain-separation label is pinned by
    something behavioural: break it and a forgery goes through. Not here.
    Sharing one label between the two constructions passes all 557 other
    tests, because the messages already differ structurally -- the classic one
    carries 1216 bytes of recipient public keys where the container one carries
    a 4-byte length and a header, and no legal header is 1212 bytes long, so
    the two can never line up.

    That is an accident of two constants, not a property anyone should rely on.
    Add a suite with a larger ML-KEM public key, or a field to the header, and
    the accident can stop holding while every test still passes. So the label
    is pinned here directly, and the frozen vectors record it too.
    """
    from hpqc import signing
    from hpqc.keys import MLKEM768_PUBLIC_LEN, X25519_KEY_LEN

    assert signing.SIG_CONTAINER_LABEL != signing.SIG_LABEL
    # The coincidence this test exists to outlive: 4 + header == 32 + 1184.
    assert X25519_KEY_LEN + MLKEM768_PUBLIC_LEN - 4 == 1212
