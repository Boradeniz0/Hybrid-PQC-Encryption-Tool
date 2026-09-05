"""The .hpqc container: header layout, round trips, and tamper resistance."""

from __future__ import annotations

import pytest

from hpqc import container, hybrid
from hpqc.container import MAGIC, decrypt, encrypt, parse_header
from hpqc.errors import (
    DecryptionError,
    FormatError,
    UnsupportedSuiteError,
    WrongRecipientError,
)
from hpqc.suites import AES_256_GCM, CHACHA20_POLY1305

# Offsets into the header, mirroring the table in container.py. Spelling them
# out here means a silent layout change breaks these tests loudly.
OFF_VERSION = 4
OFF_SUITE = 5
OFF_FLAGS = 6
OFF_KEY_ID = 8
OFF_SALT = 16
OFF_NONCE = 32
OFF_EPK_LEN = 44
OFF_EPK = 46
OFF_KEM_LEN = 78
OFF_KEM_CT = 80
HEADER_LEN = 1168
TAG_LEN = 16

SUITES = [CHACHA20_POLY1305, AES_256_GCM]


def flip(blob: bytes, offset: int) -> bytes:
    """Return blob with one bit flipped at offset."""
    tampered = bytearray(blob)
    tampered[offset] ^= 0x01
    return bytes(tampered)


@pytest.mark.parametrize("suite", SUITES, ids=lambda s: s.aead_name)
@pytest.mark.parametrize(
    "plaintext",
    [b"", b"x", b"attack at dawn", b"\x00" * 1024, bytes(range(256)) * 400],
    ids=["empty", "one-byte", "short", "zeros", "large"],
)
def test_round_trip(alice, alice_pub, suite, plaintext) -> None:
    assert decrypt(encrypt(plaintext, alice_pub, suite), alice) == plaintext


def test_header_is_exactly_the_documented_length(alice_pub) -> None:
    blob = encrypt(b"", alice_pub)
    assert len(blob) == HEADER_LEN + TAG_LEN

    _, header_bytes, ciphertext = parse_header(blob)
    assert len(header_bytes) == HEADER_LEN
    assert len(ciphertext) == TAG_LEN


def test_overhead_is_constant_regardless_of_plaintext_size(alice_pub) -> None:
    for size in (0, 1, 10_000):
        blob = encrypt(b"\x00" * size, alice_pub)
        assert len(blob) - size == HEADER_LEN + TAG_LEN


def test_parsed_header_reports_what_was_written(alice_pub) -> None:
    blob = encrypt(b"data", alice_pub, AES_256_GCM)
    header, _, _ = parse_header(blob)

    assert header.version == container.FORMAT_VERSION
    assert header.suite == AES_256_GCM
    assert header.flags == container.FLAGS_NONE
    assert header.key_id == alice_pub.key_id
    assert len(header.salt) == hybrid.SALT_LEN
    assert len(header.nonce) == AES_256_GCM.nonce_len
    assert len(header.kem_ciphertext) == hybrid.MLKEM768_CIPHERTEXT_LEN


def test_the_same_plaintext_encrypts_differently_every_time(alice_pub) -> None:
    """Fresh ephemeral key, fresh encapsulation, fresh salt and nonce."""
    first = encrypt(b"same message", alice_pub)
    second = encrypt(b"same message", alice_pub)

    assert first != second
    assert first[OFF_EPK:OFF_KEM_LEN] != second[OFF_EPK:OFF_KEM_LEN]
    assert first[OFF_KEM_CT:HEADER_LEN] != second[OFF_KEM_CT:HEADER_LEN]
    assert first[OFF_SALT:OFF_NONCE] != second[OFF_SALT:OFF_NONCE]
    assert first[HEADER_LEN:] != second[HEADER_LEN:]


def test_plaintext_does_not_appear_in_the_container(alice_pub) -> None:
    needle = b"TOP-SECRET-CANARY-VALUE"
    assert needle not in encrypt(needle * 50, alice_pub)


def test_the_wrong_identity_is_rejected_before_any_crypto(alice_pub, bob) -> None:
    with pytest.raises(WrongRecipientError, match="encrypted for key id"):
        decrypt(encrypt(b"secret", alice_pub), bob)


@pytest.mark.parametrize(
    "offset, field",
    [
        (OFF_SALT, "HKDF salt"),
        (OFF_NONCE, "AEAD nonce"),
        (OFF_EPK, "ephemeral public key"),
        (OFF_KEM_CT, "ML-KEM ciphertext"),
        (HEADER_LEN, "payload"),
        (HEADER_LEN + TAG_LEN - 1, "authentication tag"),
    ],
)
def test_flipping_one_bit_anywhere_is_caught(alice, alice_pub, offset, field) -> None:
    """The whole header is associated data, so nothing here is malleable."""
    blob = encrypt(b"attack at dawn", alice_pub)

    with pytest.raises(DecryptionError, match="authentication failed"):
        decrypt(flip(blob, offset), alice)


def test_retargeting_the_key_id_is_caught(alice, alice_pub) -> None:
    blob = encrypt(b"secret", alice_pub)

    with pytest.raises(WrongRecipientError):
        decrypt(flip(blob, OFF_KEY_ID), alice)


def test_downgrading_the_suite_is_caught(alice, alice_pub) -> None:
    """Rewriting the suite byte must not yield a decryptable file.

    The byte is both inside the AEAD's associated data and inside the HKDF
    transcript, so an attacker cannot steer the recipient onto a different
    cipher.
    """
    blob = bytearray(encrypt(b"secret", alice_pub, CHACHA20_POLY1305))
    blob[OFF_SUITE] = AES_256_GCM.id

    with pytest.raises(DecryptionError):
        decrypt(bytes(blob), alice)


def test_a_valid_foreign_kem_ciphertext_cannot_be_spliced_in(alice, alice_pub) -> None:
    """Swap the ML-KEM ciphertext for another *valid* one for the same key.

    This is the sharpest test of the hybrid construction: the substitute
    decapsulates cleanly, so nothing upstream complains. Only because the
    ML-KEM secret feeds the derivation -- and the ciphertext is bound as
    associated data -- does the file fail to open.
    """
    blob = bytearray(encrypt(b"secret", alice_pub))
    _, foreign_kem_ct, _ = hybrid.encapsulate(alice_pub)
    blob[OFF_KEM_CT:HEADER_LEN] = foreign_kem_ct

    with pytest.raises(DecryptionError):
        decrypt(bytes(blob), alice)


def test_a_foreign_ephemeral_key_cannot_be_spliced_in(alice, alice_pub) -> None:
    """The X25519 half is bound just as tightly as the ML-KEM half."""
    blob = bytearray(encrypt(b"secret", alice_pub))
    foreign_epk, _, _ = hybrid.encapsulate(alice_pub)
    blob[OFF_EPK:OFF_KEM_LEN] = foreign_epk

    with pytest.raises(DecryptionError):
        decrypt(bytes(blob), alice)


def test_headers_cannot_be_swapped_between_files(alice, alice_pub) -> None:
    first = encrypt(b"message one", alice_pub)
    second = encrypt(b"message two", alice_pub)

    with pytest.raises(DecryptionError):
        decrypt(first[:HEADER_LEN] + second[HEADER_LEN:], alice)


def test_truncating_the_payload_is_caught(alice, alice_pub) -> None:
    blob = encrypt(b"a longer message that survives truncation", alice_pub)

    with pytest.raises(DecryptionError):
        decrypt(blob[:-1], alice)


def test_appending_garbage_is_caught(alice, alice_pub) -> None:
    with pytest.raises(DecryptionError):
        decrypt(encrypt(b"secret", alice_pub) + b"\x00", alice)


def test_a_non_hpqc_file_is_reported_as_such(alice) -> None:
    with pytest.raises(FormatError, match="not an hpqc file"):
        decrypt(b"\x89PNG\r\n\x1a\n" + b"\x00" * 2000, alice)


def test_an_empty_file_is_reported_as_truncated(alice) -> None:
    with pytest.raises(FormatError, match="truncated container"):
        decrypt(b"", alice)


@pytest.mark.parametrize("keep", [4, 32, 100, 1167], ids=lambda n: f"{n}-bytes")
def test_a_truncated_header_never_reads_past_the_end(alice, alice_pub, keep) -> None:
    blob = encrypt(b"secret", alice_pub)

    with pytest.raises(FormatError):
        decrypt(blob[:keep], alice)


def test_an_unknown_format_version_is_refused(alice, alice_pub) -> None:
    blob = bytearray(encrypt(b"secret", alice_pub))
    blob[OFF_VERSION] = 99

    with pytest.raises(FormatError, match="version 99 is not supported"):
        decrypt(bytes(blob), alice)


def test_an_unknown_suite_is_refused(alice, alice_pub) -> None:
    blob = bytearray(encrypt(b"secret", alice_pub))
    blob[OFF_SUITE] = 0xEE

    with pytest.raises(UnsupportedSuiteError, match="unknown cipher suite 0xee"):
        decrypt(bytes(blob), alice)


@pytest.mark.parametrize("value", [0x08, 0x10, 0x80, 0xF8])
def test_unknown_flag_bits_are_refused(value, alice, alice_pub) -> None:
    """Reserved bits are a forward-compatibility hook, not something to ignore.

    Bits 0, 1 and 2 are taken (FLAG_SIGNED, FLAG_CHUNKED, FLAG_RECIPIENTS);
    every other bit still has to be refused by name, so a file written by a
    newer build fails loudly here instead of being half understood.
    """
    blob = bytearray(encrypt(b"secret", alice_pub))
    blob[OFF_FLAGS + 1] = value

    with pytest.raises(FormatError, match="unknown header flags"):
        decrypt(bytes(blob), alice)


def test_high_byte_flag_bits_are_refused(alice, alice_pub) -> None:
    """The flags field is 16 bits; the top half must be checked too."""
    blob = bytearray(encrypt(b"secret", alice_pub))
    blob[OFF_FLAGS] = 0x01

    with pytest.raises(FormatError, match="unknown header flags"):
        decrypt(bytes(blob), alice)


def test_claiming_the_signed_flag_on_an_unsigned_file_fails(alice, alice_pub) -> None:
    """A known flag bit is not a free pass -- the AAD still covers it.

    Setting FLAG_SIGNED gets past the flag check, so this is the case that
    proves the header's integrity protection is what stops it rather than the
    parser's allow-list.
    """
    blob = bytearray(encrypt(b"secret", alice_pub))
    blob[OFF_FLAGS + 1] = container.FLAG_SIGNED

    with pytest.raises(DecryptionError, match="authentication failed"):
        decrypt(bytes(blob), alice)


def test_claiming_both_signed_and_chunked_is_refused(alice, alice_pub) -> None:
    """The one flag combination this build never writes.

    Both bits are individually known, so the allow-list lets the pair through;
    it takes a rule of its own to stop a header that would send a signature
    parser walking into chunk framing.
    """
    blob = bytearray(encrypt(b"secret", alice_pub))
    blob[OFF_FLAGS + 1] = container.FLAG_SIGNED | container.FLAG_CHUNKED

    with pytest.raises(FormatError, match="both signed and chunked"):
        decrypt(bytes(blob), alice)


@pytest.mark.parametrize(
    "offset, field",
    [(OFF_EPK_LEN + 1, "ephemeral X25519 public key"), (OFF_KEM_LEN + 1, "ML-KEM-768")],
)
def test_a_lying_length_prefix_is_refused(alice, alice_pub, offset, field) -> None:
    blob = bytearray(encrypt(b"secret", alice_pub))
    blob[offset] ^= 0x01

    with pytest.raises(FormatError, match=field):
        decrypt(bytes(blob), alice)


def test_magic_is_the_first_thing_on_the_wire(alice_pub) -> None:
    assert encrypt(b"", alice_pub).startswith(MAGIC)


# The canonical X25519 points of small order. Each one forces an all-zero
# shared secret, and OpenSSL refuses them with a bare ValueError -- which must
# not reach the user as a traceback.
LOW_ORDER_POINTS = [
    bytes(32),
    b"\x01" + bytes(31),
    bytes.fromhex(
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
    ),
]


@pytest.mark.parametrize(
    "point", LOW_ORDER_POINTS, ids=["zero", "one", "order-8"]
)
def test_a_low_order_ephemeral_key_is_rejected_cleanly(alice, alice_pub, point) -> None:
    """A crafted header must produce an hpqc error, never a raw ValueError."""
    blob = bytearray(encrypt(b"secret", alice_pub))
    blob[OFF_EPK:OFF_KEM_LEN] = point

    with pytest.raises(FormatError, match="ephemeral X25519 public key"):
        decrypt(bytes(blob), alice)


@pytest.mark.parametrize(
    "point", LOW_ORDER_POINTS, ids=["zero", "one", "order-8"]
)
def test_a_low_order_recipient_key_is_rejected_cleanly(alice_pub, point) -> None:
    """A malicious .pub file must not crash the sender either."""
    from hpqc.keys import PublicKey

    hostile = PublicKey(x25519_bytes=point, mlkem_bytes=alice_pub.mlkem_bytes)

    with pytest.raises(FormatError, match="recipient X25519 public key"):
        encrypt(b"secret", hostile)
