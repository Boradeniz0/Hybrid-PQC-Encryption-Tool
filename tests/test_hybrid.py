"""The hybrid KEM and the HKDF combiner.

These tests are the ones that would catch a "hybrid" that is secretly running
on one algorithm -- the failure mode where the post-quantum half is computed,
stored in the header, and then quietly left out of the key derivation.
"""

from __future__ import annotations

import pytest

from hpqc import hybrid
from hpqc.hybrid import (
    MLKEM768_CIPHERTEXT_LEN,
    SALT_LEN,
    SHARED_SECRET_LEN,
    decapsulate,
    derive_key,
    encapsulate,
)
from hpqc.keys import X25519_KEY_LEN, PrivateKey
from hpqc.suites import CHACHA20_POLY1305


def test_encapsulate_produces_the_expected_wire_sizes(alice_pub) -> None:
    ephemeral_public, kem_ciphertext, ikm = encapsulate(alice_pub)

    assert len(ephemeral_public) == X25519_KEY_LEN
    assert len(kem_ciphertext) == MLKEM768_CIPHERTEXT_LEN
    # Two 32-byte shared secrets concatenated.
    assert len(ikm) == 2 * SHARED_SECRET_LEN


def test_the_recipient_recovers_the_same_keying_material(alice) -> None:
    ephemeral_public, kem_ciphertext, ikm = encapsulate(alice.public_key())
    assert decapsulate(alice, ephemeral_public, kem_ciphertext) == ikm


def test_a_different_identity_derives_different_keying_material(alice, bob) -> None:
    ephemeral_public, kem_ciphertext, ikm = encapsulate(alice.public_key())

    # ML-KEM uses implicit rejection, so this does not raise -- it just yields
    # a different secret. The AEAD tag is what turns that into a hard failure.
    assert decapsulate(bob, ephemeral_public, kem_ciphertext) != ikm


def test_every_encapsulation_is_fresh(alice_pub) -> None:
    first = encapsulate(alice_pub)
    second = encapsulate(alice_pub)

    assert first[0] != second[0]  # ephemeral public key
    assert first[1] != second[1]  # ML-KEM ciphertext
    assert first[2] != second[2]  # keying material


def _derive(ikm: bytes, alice_pub, **overrides) -> bytes:
    args = {
        "ikm": ikm,
        "salt": b"\x00" * SALT_LEN,
        "suite": CHACHA20_POLY1305,
        "ephemeral_public": b"\x01" * X25519_KEY_LEN,
        "kem_ciphertext": b"\x02" * MLKEM768_CIPHERTEXT_LEN,
        "recipient": alice_pub,
    }
    args.update(overrides)
    return derive_key(**args)


@pytest.mark.parametrize(
    "flipped_byte, half",
    [(0, "ML-KEM"), (31, "ML-KEM"), (32, "X25519"), (63, "X25519")],
)
def test_both_shared_secrets_actually_reach_the_derived_key(
    alice_pub, flipped_byte, half
) -> None:
    """Flipping a bit in either half must change the AEAD key.

    If the derivation ever dropped one KEM, half of these would pass silently
    while the tool advertised itself as hybrid.
    """
    ikm = bytes(2 * SHARED_SECRET_LEN)
    tweaked = bytearray(ikm)
    tweaked[flipped_byte] ^= 0x01

    assert _derive(ikm, alice_pub) != _derive(bytes(tweaked), alice_pub), half


def test_the_transcript_is_bound_into_the_derivation(alice_pub, bob_pub) -> None:
    """Changing any public input must change the key, even with the same ikm."""
    ikm = bytes(2 * SHARED_SECRET_LEN)
    baseline = _derive(ikm, alice_pub)

    assert _derive(ikm, alice_pub, salt=b"\xff" * SALT_LEN) != baseline
    assert _derive(ikm, alice_pub, ephemeral_public=bytes(X25519_KEY_LEN)) != baseline
    assert (
        _derive(ikm, alice_pub, kem_ciphertext=bytes(MLKEM768_CIPHERTEXT_LEN))
        != baseline
    )
    assert _derive(ikm, bob_pub) != baseline


def test_the_suite_id_is_bound_into_the_derivation(alice_pub) -> None:
    """A downgrade attempt must not land on a usable key."""
    from hpqc.suites import AES_256_GCM

    ikm = bytes(2 * SHARED_SECRET_LEN)
    assert _derive(ikm, alice_pub) != _derive(ikm, alice_pub, suite=AES_256_GCM)


def test_derivation_is_deterministic(alice_pub) -> None:
    ikm = bytes(2 * SHARED_SECRET_LEN)
    assert _derive(ikm, alice_pub) == _derive(ikm, alice_pub)


def test_derived_key_matches_the_suite_key_length(alice_pub) -> None:
    ikm = bytes(2 * SHARED_SECRET_LEN)
    assert len(_derive(ikm, alice_pub)) == CHACHA20_POLY1305.key_len


def test_the_label_is_domain_separated() -> None:
    """A version marker in the label keeps future formats from colliding."""
    assert b"hpqc-v1" in hybrid.HKDF_LABEL


def test_end_to_end_key_agreement(alice) -> None:
    """What container.encrypt/decrypt rely on, in one place."""
    public = alice.public_key()
    ephemeral_public, kem_ciphertext, sender_ikm = encapsulate(public)
    receiver_ikm = decapsulate(alice, ephemeral_public, kem_ciphertext)

    sender_key = derive_key(
        sender_ikm,
        b"salt" * 4,
        CHACHA20_POLY1305,
        ephemeral_public,
        kem_ciphertext,
        public,
    )
    receiver_key = derive_key(
        receiver_ikm,
        b"salt" * 4,
        CHACHA20_POLY1305,
        ephemeral_public,
        kem_ciphertext,
        public,
    )
    assert sender_key == receiver_key


def test_decapsulation_needs_the_matching_private_key(alice) -> None:
    other = PrivateKey.generate()
    ephemeral_public, kem_ciphertext, ikm = encapsulate(alice.public_key())
    assert decapsulate(other, ephemeral_public, kem_ciphertext) != ikm
