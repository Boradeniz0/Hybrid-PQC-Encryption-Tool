"""Sender authentication: Ed25519 + ML-DSA-65, signed then encrypted.

The interesting tests here are not the round trips. They are:

  * a payload with one valid and one invalid signature must be rejected, in
    both directions -- otherwise the scheme is not hybrid, it just looks it;
  * a signed file addressed to Bob must not verify for Carol, even though the
    plaintext and the signature are byte-identical (surreptitious forwarding).

Because the signature lives *inside* the AEAD, an attacker who only flips bytes
in the container is stopped by the tag long before any signature check runs. So
the adversary that matters here is the sender: whoever encrypts chooses the
payload. `seal` below models exactly that, letting the tests put an arbitrary
signature block inside an otherwise perfectly valid container.
"""

from __future__ import annotations

import os

import pytest

from hpqc import container, hybrid, signing
from hpqc.container import FLAG_SIGNED, encrypt, open_container
from hpqc.errors import FormatError, SignatureError
from hpqc.keys import (
    ED25519_KEY_LEN,
    MLDSA65_PUBLIC_LEN,
    MLDSA65_SEED_LEN,
    PRIVATE_PREFIX,
    PUBLIC_PREFIX,
    SIGN_PRIVATE_PREFIX,
    SIGN_PUBLIC_PREFIX,
    SigningPrivateKey,
    SigningPublicKey,
)
from hpqc.suites import AES_256_GCM, CHACHA20_POLY1305, DEFAULT_SUITE
from helpers import seal

SUITES = [CHACHA20_POLY1305, AES_256_GCM]

# Offsets into the signature block, mirroring the table in signing.py so a
# silent layout change breaks these tests loudly.
OFF_ED_PK_LEN = 0
OFF_ED_PK = 2
OFF_MLDSA_PK_LEN = 34
OFF_MLDSA_PK = 36
OFF_ED_SIG_LEN = 1988
OFF_ED_SIG = 1990
OFF_MLDSA_SIG_LEN = 2054
OFF_MLDSA_SIG = 2056
BLOCK_LEN = 5365

HEADER_LEN = 1168
TAG_LEN = 16


# --------------------------------------------------------------------------
# Signing key files
# --------------------------------------------------------------------------


class TestSigningKeys:
    def test_sizes_are_what_the_algorithms_specify(self, carol, carol_pub) -> None:
        assert len(carol.ed25519_bytes) == ED25519_KEY_LEN
        assert len(carol.mldsa_seed) == MLDSA65_SEED_LEN
        assert len(carol_pub.ed25519_bytes) == ED25519_KEY_LEN
        assert len(carol_pub.mldsa_bytes) == MLDSA65_PUBLIC_LEN

    def test_armour_round_trips(self, carol, carol_pub) -> None:
        assert SigningPrivateKey.decode(carol.encode()) == carol
        assert SigningPublicKey.decode(carol_pub.encode()) == carol_pub

    def test_the_seed_expands_deterministically(self, carol, carol_pub) -> None:
        """The file holds 32 bytes; the 1952-byte key is rebuilt on load."""
        assert SigningPrivateKey.decode(carol.encode()).public_key() == carol_pub

    def test_key_ids_are_stable_and_distinct(self, carol_pub, mallory_pub) -> None:
        assert carol_pub.key_id == carol_pub.key_id
        assert carol_pub.key_id != mallory_pub.key_id

    def test_the_key_id_covers_both_algorithms(self, carol_pub, mallory_pub) -> None:
        """Swapping either half must change the fingerprint."""
        half_swapped = SigningPublicKey(
            ed25519_bytes=carol_pub.ed25519_bytes,
            mldsa_bytes=mallory_pub.mldsa_bytes,
        )
        other_half = SigningPublicKey(
            ed25519_bytes=mallory_pub.ed25519_bytes,
            mldsa_bytes=carol_pub.mldsa_bytes,
        )
        assert half_swapped.key_id != carol_pub.key_id
        assert other_half.key_id != carol_pub.key_id

    def test_armour_prefixes_cannot_be_confused(self) -> None:
        """"hpqc-sk1" must not match inside "hpqc-ssk1", and so on.

        The four prefixes are close enough that a substring test in the wrong
        place would silently route a signing key into the encryption parser.
        """
        prefixes = [
            PUBLIC_PREFIX,
            PRIVATE_PREFIX,
            SIGN_PUBLIC_PREFIX,
            SIGN_PRIVATE_PREFIX,
        ]
        assert len(set(prefixes)) == 4
        for outer in prefixes:
            for inner in prefixes:
                if outer is not inner:
                    assert inner not in outer, f"{inner!r} hides inside {outer!r}"

    def test_the_private_key_file_is_not_world_readable(self, carol, tmp_path) -> None:
        path = tmp_path / "sign.key"
        carol.write(path)
        assert oct(path.stat().st_mode)[-3:] == "600"

    def test_writing_over_a_world_readable_file_still_ends_up_private(
        self, carol, tmp_path
    ) -> None:
        """The same bug the encryption key had; both go through one helper now."""
        path = tmp_path / "sign.key"
        path.write_text("placeholder")
        path.chmod(0o644)

        carol.write(path)
        assert oct(path.stat().st_mode)[-3:] == "600"

    def test_an_encryption_key_is_not_accepted_as_a_signing_key(
        self, alice_pub
    ) -> None:
        with pytest.raises(FormatError, match="signing public"):
            SigningPublicKey.decode(alice_pub.encode())

    def test_a_signing_key_is_not_accepted_as_an_encryption_key(
        self, carol_pub
    ) -> None:
        from hpqc.keys import PublicKey

        with pytest.raises(FormatError, match="hpqc public key"):
            PublicKey.decode(carol_pub.encode())

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "# only a comment\n",
            "not-a-key\n",
            SIGN_PUBLIC_PREFIX + "!!!!not base64!!!!\n",
            SIGN_PUBLIC_PREFIX + "AAAA\n",
        ],
        ids=["empty", "comment-only", "wrong-prefix", "bad-base64", "too-short"],
    )
    def test_malformed_signing_keys_are_refused(self, text) -> None:
        with pytest.raises(FormatError):
            SigningPublicKey.decode(text)


# --------------------------------------------------------------------------
# The signed message
# --------------------------------------------------------------------------


class TestSignedMessage:
    def test_it_starts_with_the_domain_label(self, carol_pub, alice_pub) -> None:
        message = signing.signed_message(
            b"x", carol_pub, alice_pub, DEFAULT_SUITE
        )
        assert message.startswith(signing.SIG_LABEL)

    def test_the_recipient_is_part_of_it(self, carol_pub, alice_pub, bob_pub) -> None:
        """This is what stops surreptitious forwarding."""
        for_alice = signing.signed_message(b"x", carol_pub, alice_pub, DEFAULT_SUITE)
        for_bob = signing.signed_message(b"x", carol_pub, bob_pub, DEFAULT_SUITE)
        assert for_alice != for_bob

    def test_the_sender_is_part_of_it(self, carol_pub, mallory_pub, alice_pub) -> None:
        """A signature cannot be lifted onto a different claimed identity."""
        from_carol = signing.signed_message(
            b"x", carol_pub, alice_pub, DEFAULT_SUITE
        )
        from_mallory = signing.signed_message(
            b"x", mallory_pub, alice_pub, DEFAULT_SUITE
        )
        assert from_carol != from_mallory

    def test_the_suite_is_part_of_it(self, carol_pub, alice_pub) -> None:
        chacha = signing.signed_message(
            b"x", carol_pub, alice_pub, CHACHA20_POLY1305
        )
        aes = signing.signed_message(b"x", carol_pub, alice_pub, AES_256_GCM)
        assert chacha != aes

    def test_the_plaintext_is_part_of_it(self, carol_pub, alice_pub) -> None:
        first = signing.signed_message(b"pay 100", carol_pub, alice_pub, DEFAULT_SUITE)
        second = signing.signed_message(b"pay 900", carol_pub, alice_pub, DEFAULT_SUITE)
        assert first != second

    def test_it_is_domain_separated_from_the_hkdf_label(self) -> None:
        """A signature and a derived key must never cover the same bytes."""
        assert signing.SIG_LABEL != hybrid.HKDF_LABEL
        assert not signing.SIG_LABEL.startswith(hybrid.HKDF_LABEL)
        assert not hybrid.HKDF_LABEL.startswith(signing.SIG_LABEL)


# --------------------------------------------------------------------------
# Round trips
# --------------------------------------------------------------------------


class TestRoundTrip:
    @pytest.mark.parametrize("suite", SUITES, ids=lambda s: s.aead_name)
    @pytest.mark.parametrize(
        "plaintext",
        [b"", b"x", b"attack at dawn", bytes(range(256)) * 100],
        ids=["empty", "one-byte", "short", "large"],
    )
    def test_sign_encrypt_decrypt_verify(
        self, alice, alice_pub, carol, carol_pub, suite, plaintext
    ) -> None:
        blob = encrypt(plaintext, alice_pub, suite, sender=carol)
        opened = open_container(blob, alice, carol_pub)

        assert opened.plaintext == plaintext
        assert opened.signer == carol_pub
        assert opened.verified is True

    def test_the_header_advertises_that_it_is_signed(
        self, alice_pub, carol
    ) -> None:
        header, _, _ = container.parse_header(
            encrypt(b"x", alice_pub, sender=carol)
        )
        assert header.signed is True
        assert header.flags == FLAG_SIGNED

    def test_an_unsigned_file_says_so(self, alice, alice_pub) -> None:
        blob = encrypt(b"x", alice_pub)
        header, _, _ = container.parse_header(blob)
        opened = open_container(blob, alice)

        assert header.signed is False
        assert opened.signer is None
        assert opened.verified is False

    def test_the_overhead_is_the_documented_constant(self, alice_pub, carol) -> None:
        for size in (0, 1, 10_000):
            blob = encrypt(b"\x00" * size, alice_pub, sender=carol)
            assert len(blob) - size == HEADER_LEN + BLOCK_LEN + TAG_LEN

    def test_signing_is_randomised_but_still_verifies(
        self, alice, alice_pub, carol, carol_pub
    ) -> None:
        """ML-DSA signing is hedged, so two signatures over one message differ."""
        first = encrypt(b"same", alice_pub, sender=carol)
        second = encrypt(b"same", alice_pub, sender=carol)

        assert first != second
        assert open_container(first, alice, carol_pub).plaintext == b"same"
        assert open_container(second, alice, carol_pub).plaintext == b"same"

    def test_opening_without_a_sender_key_reports_but_does_not_claim(
        self, alice, alice_pub, carol, carol_pub
    ) -> None:
        """No pinned key means no identity claim -- verified stays False."""
        opened = open_container(encrypt(b"x", alice_pub, sender=carol), alice)

        assert opened.signer == carol_pub
        assert opened.verified is False

    def test_decrypt_still_returns_just_the_plaintext(
        self, alice, alice_pub, carol
    ) -> None:
        """The signature block must not leak into the plaintext."""
        blob = encrypt(b"just the message", alice_pub, sender=carol)
        assert container.decrypt(blob, alice) == b"just the message"


# --------------------------------------------------------------------------
# The signer stays confidential
# --------------------------------------------------------------------------


class TestSignerConfidentiality:
    def test_the_signers_keys_do_not_appear_in_the_container(
        self, alice_pub, carol, carol_pub
    ) -> None:
        """Signing before encrypting is what buys this."""
        blob = encrypt(b"x", alice_pub, sender=carol)

        assert carol_pub.ed25519_bytes not in blob
        assert carol_pub.mldsa_bytes not in blob
        assert carol_pub.key_id not in blob


# --------------------------------------------------------------------------
# Negative cases
# --------------------------------------------------------------------------


class TestVerificationFailures:
    def test_a_file_signed_by_someone_else_is_refused(
        self, alice, alice_pub, mallory, carol_pub
    ) -> None:
        blob = encrypt(b"x", alice_pub, sender=mallory)

        with pytest.raises(SignatureError, match="was signed by key id"):
            open_container(blob, alice, carol_pub)

    def test_requesting_verification_of_an_unsigned_file_fails_closed(
        self, alice, alice_pub, carol_pub
    ) -> None:
        """Asking for authentication and getting none must be an error."""
        blob = encrypt(b"x", alice_pub)

        with pytest.raises(SignatureError, match="not signed"):
            open_container(blob, alice, carol_pub)

    def test_a_signature_over_a_different_plaintext_is_refused(
        self, alice, alice_pub, carol, carol_pub
    ) -> None:
        """The sender is the adversary: they can sign one thing and send another."""
        honest = signing.sign_payload(b"pay 100", carol, alice_pub, DEFAULT_SUITE)
        swapped = honest[:BLOCK_LEN] + b"pay 900"

        with pytest.raises(SignatureError, match="does not verify"):
            open_container(seal(swapped, alice_pub), alice, carol_pub)

    def test_the_ed25519_signature_alone_is_not_enough(
        self, alice, alice_pub, carol, carol_pub
    ) -> None:
        """Break the ML-DSA half and the file must still be refused.

        Together with its mirror below, this is what makes the scheme hybrid
        rather than merely hybrid-shaped: neither signature can be dropped.
        """
        payload = bytearray(
            signing.sign_payload(b"x", carol, alice_pub, DEFAULT_SUITE)
        )
        payload[OFF_MLDSA_SIG : OFF_MLDSA_SIG + signing.MLDSA65_SIGNATURE_LEN] = (
            os.urandom(signing.MLDSA65_SIGNATURE_LEN)
        )

        with pytest.raises(SignatureError, match="ML-DSA-65 signature does not verify"):
            open_container(seal(bytes(payload), alice_pub), alice, carol_pub)

    def test_the_mldsa_signature_alone_is_not_enough(
        self, alice, alice_pub, carol, carol_pub
    ) -> None:
        payload = bytearray(
            signing.sign_payload(b"x", carol, alice_pub, DEFAULT_SUITE)
        )
        payload[OFF_ED_SIG : OFF_ED_SIG + signing.ED25519_SIGNATURE_LEN] = os.urandom(
            signing.ED25519_SIGNATURE_LEN
        )

        with pytest.raises(SignatureError, match="Ed25519 signature does not verify"):
            open_container(seal(bytes(payload), alice_pub), alice, carol_pub)

    def test_substituting_the_senders_public_key_is_refused(
        self, alice, alice_pub, carol, mallory_pub
    ) -> None:
        """Claim to be Mallory while holding Carol's signature."""
        payload = bytearray(
            signing.sign_payload(b"x", carol, alice_pub, DEFAULT_SUITE)
        )
        payload[OFF_ED_PK : OFF_ED_PK + ED25519_KEY_LEN] = mallory_pub.ed25519_bytes
        payload[OFF_MLDSA_PK : OFF_MLDSA_PK + MLDSA65_PUBLIC_LEN] = (
            mallory_pub.mldsa_bytes
        )

        with pytest.raises(SignatureError, match="does not verify"):
            open_container(seal(bytes(payload), alice_pub), alice, mallory_pub)


class TestSurreptitiousForwarding:
    """Davis (2001): sign-then-encrypt without binding the recipient.

    Bob receives a signed file from Carol, decrypts it, and re-encrypts the
    *same* plaintext and the *same* signature to Alice. If the signature covers
    only the plaintext, Alice sees "Carol wrote this to me" -- and Carol never
    wrote to Alice at all. The AEAD cannot help: Bob builds a fresh, perfectly
    valid one. Only binding the recipient into the signed message stops it.
    """

    def test_the_original_recipient_can_verify(
        self, bob, bob_pub, carol, carol_pub
    ) -> None:
        payload = signing.sign_payload(b"pay 100", carol, bob_pub, DEFAULT_SUITE)
        opened = open_container(seal(payload, bob_pub), bob, carol_pub)

        assert opened.plaintext == b"pay 100"
        assert opened.verified is True

    def test_forwarding_it_to_someone_else_does_not_verify(
        self, alice, alice_pub, bob_pub, carol, carol_pub
    ) -> None:
        """The same bytes, re-addressed. This must fail."""
        payload = signing.sign_payload(b"pay 100", carol, bob_pub, DEFAULT_SUITE)
        forwarded = seal(payload, alice_pub)

        with pytest.raises(SignatureError, match="does not verify"):
            open_container(forwarded, alice, carol_pub)

    def test_it_does_not_verify_even_without_a_pinned_sender(
        self, alice, alice_pub, bob_pub, carol
    ) -> None:
        """Alice is protected whether or not she knows Carol's key."""
        payload = signing.sign_payload(b"pay 100", carol, bob_pub, DEFAULT_SUITE)

        with pytest.raises(SignatureError, match="does not verify"):
            open_container(seal(payload, alice_pub), alice)


class TestMalformedSignatureBlocks:
    @pytest.mark.parametrize(
        "keep",
        [0, 1, OFF_MLDSA_PK, OFF_ED_SIG, OFF_MLDSA_SIG, BLOCK_LEN - 1],
        ids=lambda n: f"{n}-bytes",
    )
    def test_a_truncated_block_never_reads_past_the_end(
        self, alice, alice_pub, carol, keep
    ) -> None:
        payload = signing.sign_payload(b"x", carol, alice_pub, DEFAULT_SUITE)

        with pytest.raises(FormatError, match="truncated signature block"):
            open_container(seal(payload[:keep], alice_pub), alice)

    @pytest.mark.parametrize(
        "offset, field",
        [
            (OFF_ED_PK_LEN, "Ed25519 verifying key"),
            (OFF_MLDSA_PK_LEN, "ML-DSA-65 verifying key"),
            (OFF_ED_SIG_LEN, "Ed25519 signature"),
            (OFF_MLDSA_SIG_LEN, "ML-DSA-65 signature"),
        ],
    )
    def test_a_lying_length_prefix_is_refused(
        self, alice, alice_pub, carol, offset, field
    ) -> None:
        """Every prefix is checked against what the algorithm specifies."""
        payload = bytearray(
            signing.sign_payload(b"x", carol, alice_pub, DEFAULT_SUITE)
        )
        payload[offset] ^= 0x01

        with pytest.raises(FormatError, match=field):
            open_container(seal(bytes(payload), alice_pub), alice)

    def test_an_empty_payload_claiming_to_be_signed_is_refused(
        self, alice, alice_pub
    ) -> None:
        with pytest.raises(FormatError, match="truncated signature block"):
            open_container(seal(b"", alice_pub), alice)
