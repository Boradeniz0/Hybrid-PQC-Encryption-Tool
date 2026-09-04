"""Mutation fuzzing over the container parser.

Every byte of a .hpqc file is attacker-controlled in the threat model that
matters, so two properties have to hold for *any* input:

  * decryption never succeeds on a corrupted file (no forgeries), and
  * failure always arrives as an HpqcError, never as a stray ValueError,
    struct.error, or IndexError escaping the parser.

The second is the one that rots quietly: a new header field parsed without a
bounds check still passes every hand-written test while turning a malformed
file into a traceback. The seed is fixed so a failure is reproducible.

The signature block gets its own pass. Corrupting a finished signed container
almost always trips the AEAD tag first, so those mutations never reach
signing.py's parser at all. To actually fuzz it the payload has to be mutated
*before* it is sealed -- which is also the realistic threat, since the sender
is who chooses the payload.
"""

from __future__ import annotations

import random

import pytest

from hpqc.container import decrypt, encrypt, open_container
from hpqc.errors import HpqcError
from hpqc.signing import sign_payload
from hpqc.suites import DEFAULT_SUITE

from helpers import seal

SEED = 1337
ITERATIONS = 400


def _mutate(rng: random.Random, blob: bytes) -> bytes:
    mutated = bytearray(blob)
    for _ in range(rng.randint(1, 6)):
        mutated[rng.randrange(len(mutated))] = rng.randrange(256)
    if rng.random() < 0.2:  # sometimes truncate as well
        mutated = mutated[: rng.randrange(len(mutated) + 1)]
    return bytes(mutated)


def test_random_corruption_never_escapes_as_an_unexpected_exception(
    alice, alice_pub
) -> None:
    container = encrypt(b"the quick brown fox jumps over the lazy dog" * 10, alice_pub)
    rng = random.Random(SEED)

    for _ in range(ITERATIONS):
        corrupted = _mutate(rng, container)
        if corrupted == container:
            continue
        try:
            decrypt(corrupted, alice)
        except HpqcError:
            pass
        except Exception as exc:  # noqa: BLE001 - that is the point of the test
            pytest.fail(
                f"{type(exc).__name__} escaped the parser: {exc}\n"
                f"input prefix: {corrupted[:48].hex()}"
            )
        else:
            pytest.fail("a corrupted container decrypted successfully")


def test_random_garbage_is_never_mistaken_for_a_container(alice) -> None:
    rng = random.Random(SEED + 1)

    for _ in range(ITERATIONS):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 2500)))
        with pytest.raises(HpqcError):
            decrypt(blob, alice)


def test_garbage_carrying_a_valid_magic_is_still_rejected(alice) -> None:
    """Get past the cheapest check and the rest still has to hold."""
    from hpqc.container import MAGIC

    rng = random.Random(SEED + 2)

    for _ in range(ITERATIONS):
        body = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 2500)))
        with pytest.raises(HpqcError):
            decrypt(MAGIC + body, alice)


def test_random_corruption_of_a_signed_container_never_escapes(
    alice, alice_pub, carol
) -> None:
    container = encrypt(b"signed and sealed" * 20, alice_pub, sender=carol)
    rng = random.Random(SEED + 3)

    for _ in range(ITERATIONS):
        corrupted = _mutate(rng, container)
        if corrupted == container:
            continue
        try:
            decrypt(corrupted, alice)
        except HpqcError:
            pass
        except Exception as exc:  # noqa: BLE001 - that is the point of the test
            pytest.fail(
                f"{type(exc).__name__} escaped: {exc}\n"
                f"input prefix: {corrupted[:48].hex()}"
            )
        else:
            pytest.fail("a corrupted signed container decrypted successfully")


def test_a_mutated_signature_block_never_escapes_and_never_verifies(
    alice, alice_pub, carol, carol_pub
) -> None:
    """Fuzz signing.py's parser, sealing each mutation so the AEAD passes.

    This is the test that catches a signature field parsed without a bounds
    check, and a verification path that accepts a block it should not.
    """
    payload = sign_payload(b"pay 100", carol, alice_pub, DEFAULT_SUITE)
    rng = random.Random(SEED + 4)

    for _ in range(ITERATIONS):
        mutated = _mutate(rng, payload)
        if mutated == payload:
            continue
        blob = seal(mutated, alice_pub)
        try:
            open_container(blob, alice, carol_pub)
        except HpqcError:
            pass
        except Exception as exc:  # noqa: BLE001
            pytest.fail(
                f"{type(exc).__name__} escaped the signature parser: {exc}\n"
                f"payload prefix: {mutated[:48].hex()}"
            )
        else:
            pytest.fail("a mutated signature block verified successfully")
