"""Two hybrid KEMs, and what has to be true when a format grows a second one.

The .hpqc header has claimed since v1 that a new KEM would "drop in without a
parser change", on the strength of length-prefixing every variable-size field.
This module is where that claim gets tested rather than repeated. X448 +
ML-KEM-1024 is the second parameter set, and it changes four lengths at once --
the DH public key, the DH shared secret, the ML-KEM public key and the ML-KEM
ciphertext -- so it is a real test of the idea and not a cosmetic one.

The property that matters most is the negative one. A suite byte says which
KEM a container uses, and it arrives unauthenticated: nothing has verified a
tag when the parser reads it. Changing it must therefore be caught by the
lengths rather than by the tag, before a single key operation runs.
"""

from __future__ import annotations

import io
import os

import pytest

from hpqc import container, hybrid, kems, recipients, suites
from hpqc.errors import FormatError, HpqcError, WrongRecipientError
from hpqc.keys import PrivateKey, PublicKey, SigningPrivateKey

SMALL = kems.X25519_MLKEM768
BIG = kems.X448_MLKEM1024

ALL_SUITES = [
    suites.CHACHA20_POLY1305,
    suites.AES_256_GCM,
    suites.CHACHA20_POLY1305_1024,
    suites.AES_256_GCM_1024,
]

OFF_SUITE = 5
OFF_EPK_LEN = 44
#: preamble + a 12-byte nonce + the 32-byte commitment + the u16 count.
LIST_HEADER_BASE = 32 + 12 + recipients.COMMITMENT_LEN + 2


@pytest.fixture(scope="module")
def big_identities():
    """Three X448 + ML-KEM-1024 identities. Generated once; they are not cheap."""
    return [PrivateKey.generate(BIG) for _ in range(3)]


@pytest.fixture(scope="module")
def big_pubs(big_identities):
    return [k.public_key() for k in big_identities]


class TestTheTable:
    def test_every_suite_names_a_kem_this_build_implements(self):
        for suite in suites.all_suites():
            assert suite.kem in kems.all_kems()

    def test_the_kem_ids_and_lengths_are_what_the_standards_say(self):
        assert (SMALL.dh_len, SMALL.dh_shared_len) == (32, 32)
        assert (SMALL.kem_public_len, SMALL.kem_ciphertext_len) == (1184, 1088)
        assert (BIG.dh_len, BIG.dh_shared_len) == (56, 56)
        assert (BIG.kem_public_len, BIG.kem_ciphertext_len) == (1568, 1568)
        assert SMALL.id == 1 and BIG.id == 2

    def test_the_lengths_the_table_gives_are_the_lengths_the_backend_uses(self):
        """The table is copied from FIPS 203; this checks the copy.

        Every parser length comes from here, so a typo would be a format that
        agrees with itself and with nothing else.
        """
        for kem in kems.all_kems():
            identity = PrivateKey.generate(kem)
            public = identity.public_key()
            assert len(public.dh_bytes) == kem.dh_len
            assert len(public.kem_bytes) == kem.kem_public_len

            _, ciphertext, ikm = hybrid.encapsulate(public)
            assert len(ciphertext) == kem.kem_ciphertext_len
            assert len(ikm) == kem.ikm_len

    def test_the_two_kems_produce_different_sized_containers(self, big_pubs, alice_pub):
        small = container.encrypt(b"x", alice_pub)
        big = container.encrypt(b"x", big_pubs[0], suites.CHACHA20_POLY1305_1024)
        assert len(container.parse_header(small)[1]) == 1168
        assert len(container.parse_header(big)[1]) == 1672


class TestRoundTrips:
    @pytest.mark.parametrize("suite", ALL_SUITES, ids=lambda s: f"0x{s.id:02x}")
    def test_one_recipient(self, suite, alice, alice_pub, big_identities, big_pubs):
        identity, public = (
            (alice, alice_pub) if suite.kem is SMALL else (big_identities[0], big_pubs[0])
        )
        blob = container.encrypt(b"attack at dawn", public, suite)
        assert container.decrypt(blob, identity) == b"attack at dawn"

    def test_several_recipients_at_1024(self, big_identities, big_pubs):
        blob = container.encrypt_many(
            b"group", big_pubs, suite=suites.CHACHA20_POLY1305_1024
        )
        header, header_bytes, _ = container.parse_header(blob)
        assert header.multi and header.recipient_count == 3
        assert len(header_bytes) == LIST_HEADER_BASE + 3 * recipients.stanza_len(
            suites.CHACHA20_POLY1305_1024
        )
        for identity in big_identities:
            assert container.decrypt(blob, identity) == b"group"

    def test_signed_and_listed_at_1024(self, big_identities, big_pubs, carol, carol_pub):
        blob = container.encrypt_many(
            b"signed group",
            big_pubs[:2],
            suite=suites.AES_256_GCM_1024,
            sender=carol,
        )
        for identity in big_identities[:2]:
            opened = container.open_container(blob, identity, carol_pub)
            assert opened.plaintext == b"signed group" and opened.verified

    def test_chunked_at_1024(self, big_identities, big_pubs):
        plaintext = os.urandom(200_000)
        sink = io.BytesIO()
        chunks = container.encrypt_stream_many(
            io.BytesIO(plaintext),
            sink,
            big_pubs[:2],
            suite=suites.CHACHA20_POLY1305_1024,
        )
        got = io.BytesIO()
        opened = container.decrypt_stream(
            io.BytesIO(sink.getvalue()), got, big_identities[1]
        )
        assert got.getvalue() == plaintext and opened.chunks == chunks

    def test_a_1024_key_file_round_trips_and_says_what_it_is(self, big_identities):
        identity = big_identities[0]
        assert PrivateKey.decode(identity.encode()) == identity
        assert "X448 + ML-KEM-1024" in identity.encode()
        public = identity.public_key()
        assert PublicKey.decode(public.encode()) == public
        assert "X448 + ML-KEM-1024" in public.encode()


class TestTheSuiteByteCannotReinterpretAContainer:
    """The unauthenticated byte that says how to read everything after it.

    A parser that used the suite byte to *select* field lengths and then
    believed whatever prefix it found would let an attacker steer the reader.
    Here the prefix is checked against the value the suite fixes, so a
    relabelled container fails on arithmetic before any key is touched.
    """

    def test_a_1024_container_relabelled_as_768(self, big_identities, big_pubs):
        blob = bytearray(
            container.encrypt(b"x", big_pubs[0], suites.CHACHA20_POLY1305_1024)
        )
        blob[OFF_SUITE] = suites.CHACHA20_POLY1305.id

        with pytest.raises(FormatError, match="is 56 bytes, expected 32 here"):
            container.parse_header(bytes(blob))

    def test_a_768_container_relabelled_as_1024(self, alice, alice_pub):
        blob = bytearray(container.encrypt(b"x", alice_pub))
        blob[OFF_SUITE] = suites.CHACHA20_POLY1305_1024.id

        with pytest.raises(FormatError, match="is 32 bytes, expected 56 here"):
            container.parse_header(bytes(blob))

    def test_relabelling_a_recipient_list_too(self, big_pubs):
        blob = bytearray(
            container.encrypt_many(
                b"x", big_pubs[:2], suite=suites.AES_256_GCM_1024
            )
        )
        blob[OFF_SUITE] = suites.AES_256_GCM.id
        with pytest.raises(FormatError, match="expected 32 here"):
            container.parse_header(bytes(blob))

    def test_it_fails_before_any_key_operation(self, alice, alice_pub, monkeypatch):
        """Arithmetic, not cryptography, and that is the point.

        If the length check were downstream of decapsulation the same attack
        would still be refused, but only after handing attacker-chosen bytes to
        the KEM. This asserts nothing gets that far.
        """
        real = hybrid.decapsulate
        calls = []

        def watched(*args, **kwargs):
            calls.append(args)
            return real(*args, **kwargs)

        monkeypatch.setattr(hybrid, "decapsulate", watched)

        blob = bytearray(container.encrypt(b"x", alice_pub))
        # Untouched, the same call path does reach decapsulation -- otherwise
        # this test would pass for a decrypt that never got anywhere near it.
        assert container.decrypt(bytes(blob), alice) == b"x"
        assert len(calls) == 1

        blob[OFF_SUITE] = suites.CHACHA20_POLY1305_1024.id
        with pytest.raises(FormatError):
            container.decrypt(bytes(blob), alice)
        assert len(calls) == 1

    def test_a_lying_length_prefix_is_refused(self, alice, alice_pub):
        """The prefix is checked, not believed, even when it agrees with nothing."""
        blob = bytearray(container.encrypt(b"x", alice_pub))
        blob[OFF_EPK_LEN : OFF_EPK_LEN + 2] = (56).to_bytes(2, "big")
        with pytest.raises(FormatError, match="is 56 bytes, expected 32 here"):
            container.parse_header(bytes(blob))


class TestKeyTypesDoNotMix:
    def test_a_768_key_cannot_be_used_with_a_1024_suite(self, alice_pub):
        with pytest.raises(ValueError, match="needs X448\\+ML-KEM-1024 recipients"):
            container.encrypt(b"x", alice_pub, suites.CHACHA20_POLY1305_1024)

    def test_a_1024_key_cannot_be_used_with_a_768_suite(self, big_pubs):
        with pytest.raises(ValueError, match="needs X25519\\+ML-KEM-768 recipients"):
            container.encrypt(b"x", big_pubs[0], suites.CHACHA20_POLY1305)

    def test_a_mixed_recipient_list_is_refused(self, alice_pub, big_pubs):
        with pytest.raises(ValueError, match="needs X448"):
            container.encrypt_many(
                b"x", [big_pubs[0], alice_pub], suite=suites.AES_256_GCM_1024
            )

    def test_the_wrong_kind_of_identity_says_so(self, alice, big_pubs):
        blob = container.encrypt(b"x", big_pubs[0], suites.CHACHA20_POLY1305_1024)
        with pytest.raises(WrongRecipientError, match="but the supplied identity is"):
            container.decrypt(blob, alice)

    def test_it_says_so_for_a_recipient_list_too(self, alice, big_pubs):
        """Without the check this would be a trial-unwrap that could not work.

        Every stanza is the wrong length for a 768 identity's KEM, so the loop
        would burn three decapsulations to reach "none of them opened" -- a
        true answer arrived at by accident.
        """
        blob = container.encrypt_many(
            b"x", big_pubs, suite=suites.CHACHA20_POLY1305_1024
        )
        with pytest.raises(WrongRecipientError, match="but the supplied identity is"):
            container.decrypt(blob, alice)


class TestTheDerivationSeparatesThem:
    def test_the_suite_byte_is_in_the_transcript(self, big_pubs):
        """So a key derived under one suite is worthless under the other."""
        public = big_pubs[0]
        ephemeral_public, kem_ciphertext, ikm = hybrid.encapsulate(public)
        args = dict(
            ikm=ikm,
            salt=b"\x00" * 16,
            ephemeral_public=ephemeral_public,
            kem_ciphertext=kem_ciphertext,
            recipient=public,
        )
        chacha = hybrid.derive_key(suite=suites.CHACHA20_POLY1305_1024, **args)
        aes = hybrid.derive_key(suite=suites.AES_256_GCM_1024, **args)
        small = hybrid.derive_key(suite=suites.CHACHA20_POLY1305, **args)
        assert len({chacha, aes, small}) == 3

    def test_the_ikm_is_longer_for_x448(self, alice_pub, big_pubs):
        _, _, small = hybrid.encapsulate(alice_pub)
        _, _, big = hybrid.encapsulate(big_pubs[0])
        assert len(small) == 64
        assert len(big) == 88


LOW_ORDER_X448 = [b"\x00" * 56, b"\x01" + b"\x00" * 55]


@pytest.mark.parametrize("point", LOW_ORDER_X448, ids=["zero", "one"])
def test_a_low_order_x448_recipient_key_is_rejected_cleanly(big_pubs, point):
    """X448 rejects these with a bare ValueError, exactly as X25519 does.

    The handling was written once for X25519; this is the test that says it
    still applies when the group changes underneath it.
    """
    hostile = PublicKey(dh_bytes=point, kem_bytes=big_pubs[0].kem_bytes, kem=BIG)
    with pytest.raises(FormatError, match="recipient X448 public key"):
        container.encrypt(b"secret", hostile, suites.CHACHA20_POLY1305_1024)


@pytest.mark.parametrize("point", LOW_ORDER_X448, ids=["zero", "one"])
def test_a_low_order_x448_ephemeral_key_is_rejected_cleanly(
    big_identities, big_pubs, point
):
    blob = bytearray(
        container.encrypt(b"secret", big_pubs[0], suites.CHACHA20_POLY1305_1024)
    )
    blob[46 : 46 + 56] = point
    with pytest.raises(FormatError, match="ephemeral X448 public key"):
        container.decrypt(bytes(blob), big_identities[0])
