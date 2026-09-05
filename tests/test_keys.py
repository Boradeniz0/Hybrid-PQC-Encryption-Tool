"""Key generation, serialisation, and identification."""

from __future__ import annotations

import stat

import pytest

from hpqc.errors import FormatError
from hpqc import kems
from hpqc.keys import (
    KEY_ID_LEN,
    MLKEM768_PUBLIC_LEN,
    MLKEM768_SEED_LEN,
    PRIVATE_PREFIX,
    PUBLIC_PREFIX,
    X25519_KEY_LEN,
    PrivateKey,
    PublicKey,
)


def test_generated_key_has_the_sizes_fips_203_specifies(alice: PrivateKey) -> None:
    assert len(alice.dh_bytes) == X25519_KEY_LEN
    assert len(alice.kem_seed) == MLKEM768_SEED_LEN

    public = alice.public_key()
    assert len(public.dh_bytes) == X25519_KEY_LEN
    assert len(public.kem_bytes) == MLKEM768_PUBLIC_LEN


def test_public_key_is_deterministic_from_the_private_seed(alice: PrivateKey) -> None:
    """The 64-byte seed must expand to the same ML-KEM key every time."""
    assert alice.public_key() == alice.public_key()

    reloaded = PrivateKey.from_bytes(alice.to_bytes())
    assert reloaded.public_key() == alice.public_key()


def test_private_key_survives_an_armour_round_trip(alice: PrivateKey) -> None:
    restored = PrivateKey.decode(alice.encode())
    assert restored == alice


def test_public_key_survives_an_armour_round_trip(alice_pub: PublicKey) -> None:
    restored = PublicKey.decode(alice_pub.encode())
    assert restored == alice_pub


def test_armour_carries_a_readable_prefix(alice: PrivateKey) -> None:
    assert PRIVATE_PREFIX in alice.encode()
    assert PUBLIC_PREFIX in alice.public_key().encode()


def test_comment_lines_are_ignored_by_the_parser(alice_pub: PublicKey) -> None:
    noisy = "# generated on some laptop\n\n" + alice_pub.encode() + "\n"
    assert PublicKey.decode(noisy) == alice_pub


def test_key_id_is_short_stable_and_distinct(
    alice_pub: PublicKey, bob_pub: PublicKey
) -> None:
    assert len(alice_pub.key_id) == KEY_ID_LEN
    assert alice_pub.key_id == PublicKey.decode(alice_pub.encode()).key_id
    assert alice_pub.key_id != bob_pub.key_id


def test_key_id_covers_both_halves(alice_pub: PublicKey, bob_pub: PublicKey) -> None:
    """A key id must change if either algorithm's public key changes.

    Otherwise two identities sharing one half would collide, and swapping in a
    foreign ML-KEM key would go unnoticed by the fingerprint.
    """
    swapped_mlkem = PublicKey(alice_pub.dh_bytes, bob_pub.kem_bytes)
    swapped_dh = PublicKey(bob_pub.dh_bytes, alice_pub.kem_bytes)

    assert swapped_mlkem.key_id != alice_pub.key_id
    assert swapped_dh.key_id != alice_pub.key_id


def test_private_key_file_is_not_readable_by_others(tmp_path, alice) -> None:
    path = tmp_path / "id.key"
    alice.write(path)

    mode = path.stat().st_mode
    assert not mode & stat.S_IRGRP
    assert not mode & stat.S_IROTH
    assert PrivateKey.read(path) == alice


def test_writing_over_a_world_readable_file_still_ends_up_private(
    tmp_path, alice
) -> None:
    path = tmp_path / "id.key"
    path.write_text("stale")
    path.chmod(0o644)

    alice.write(path)

    assert not path.stat().st_mode & stat.S_IROTH


def test_public_key_round_trips_through_a_file(tmp_path, alice_pub) -> None:
    path = tmp_path / "id.pub"
    alice_pub.write(path)
    assert PublicKey.read(path) == alice_pub


@pytest.mark.parametrize(
    "text, expected",
    [
        ("", "no hpqc"),
        ("# only a comment\n", "no hpqc"),
        ("ssh-ed25519 AAAA\n", "expected an hpqc"),
        (PUBLIC_PREFIX + "not base64!!\n", "not valid base64"),
    ],
)
def test_malformed_key_files_are_rejected_with_a_reason(text, expected) -> None:
    with pytest.raises(FormatError, match=expected):
        PublicKey.decode(text)


def test_a_public_key_is_not_accepted_as_a_private_key(alice_pub: PublicKey) -> None:
    with pytest.raises(FormatError, match="expected an hpqc private key"):
        PrivateKey.decode(alice_pub.encode())


def test_wrong_blob_length_is_rejected() -> None:
    with pytest.raises(FormatError, match="public key must be"):
        PublicKey.from_bytes(b"\x01" + b"\x00" * 10)


def test_an_unknown_key_type_is_rejected(alice_pub: PublicKey) -> None:
    blob = bytearray(alice_pub.to_bytes())
    blob[0] = 0xFE
    with pytest.raises(FormatError, match="unknown key type 254"):
        PublicKey.from_bytes(bytes(blob))


def test_a_known_key_type_with_the_wrong_length_is_rejected(
    alice_pub: PublicKey,
) -> None:
    """The type byte says how long the blob is; both have to agree.

    An X448+ML-KEM-1024 key is 1625 bytes and an X25519+ML-KEM-768 one is
    1217. Relabelling the shorter as the longer must not get a parser reading
    408 bytes past the end of it.
    """
    blob = bytearray(alice_pub.to_bytes())
    blob[0] = kems.X448_MLKEM1024.id
    with pytest.raises(FormatError, match="must be 1625 bytes, got 1217"):
        PublicKey.from_bytes(bytes(blob))


def test_an_empty_key_blob_is_rejected() -> None:
    with pytest.raises(FormatError, match="empty"):
        PublicKey.from_bytes(b"")
    with pytest.raises(FormatError, match="empty"):
        PrivateKey.from_bytes(b"")
