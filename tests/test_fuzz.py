"""Mutation fuzzing over the container parser.

Every byte of a .hpqc file is attacker-controlled in the threat model that
matters, so two properties have to hold for *any* input:

  * decryption never succeeds on a corrupted file (no forgeries), and
  * failure always arrives as an HpqcError, never as a stray ValueError,
    struct.error, or IndexError escaping the parser.

The second is the one that rots quietly: a new header field parsed without a
bounds check still passes every hand-written test while turning a malformed
file into a traceback. The seed is fixed so a failure is reproducible.
"""

from __future__ import annotations

import random

import pytest

from hpqc.container import decrypt, encrypt
from hpqc.errors import HpqcError

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
