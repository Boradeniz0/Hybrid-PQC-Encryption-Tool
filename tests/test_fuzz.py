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

Chunked containers get their own pass, because their failure mode is
different in kind: a chunked file is decrypted incrementally, so a corrupted
one can produce output *before* it fails. What must hold is that whatever came
out is a genuine prefix of the real plaintext -- a partial answer, never an
invented one.

Wrapped key files get a pass too. A key file is untrusted input like any other,
and its header carries scrypt cost parameters -- so on top of the usual two
properties, a mutation must never make the parser attempt an enormous
allocation. That is why every mutation here uses a low recorded cost and the
whole test still finishes in well under a second: any mutation that produced a
real derivation at a mutated cost would show up as the suite hanging.
"""

from __future__ import annotations

import io
import random

import pytest

from hpqc import container as container_module
from hpqc import streaming, wrapping
from hpqc.armour import armour
from hpqc.container import decrypt, encrypt, open_container
from hpqc.errors import HpqcError
from hpqc.keys import PrivateKey
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


def test_random_corruption_of_a_chunked_container_never_escapes(
    alice, alice_pub
) -> None:
    """Same two properties as the one-shot pass, plus one only streams have.

    Because chunks are released as they verify, a corrupted file can write real
    plaintext and only then fail. That is allowed. What is not allowed is a
    single byte of output that the sender did not write, so every failed
    attempt is checked against the true plaintext: the output must be a prefix
    of it, and it must never be all of it.
    """
    plaintext = bytes(random.Random(SEED).randrange(256) for _ in range(3 * streaming.CHUNK_SIZE))
    sink = io.BytesIO()
    container_module.encrypt_stream(io.BytesIO(plaintext), sink, alice_pub)
    blob = sink.getvalue()
    rng = random.Random(SEED + 7)

    for _ in range(ITERATIONS):
        corrupted = _mutate(rng, blob)
        if corrupted == blob:
            continue
        out = io.BytesIO()
        try:
            container_module.decrypt_stream(io.BytesIO(corrupted), out, alice)
        except HpqcError:
            pass
        except Exception as exc:  # noqa: BLE001 - that is the point of the test
            pytest.fail(
                f"{type(exc).__name__} escaped the chunked reader: {exc}\n"
                f"input prefix: {corrupted[:48].hex()}"
            )
        else:
            pytest.fail("a corrupted chunked container decrypted successfully")

        released = out.getvalue()
        assert plaintext.startswith(released), (
            "a failed chunked decrypt released bytes the sender never wrote"
        )
        assert released != plaintext, (
            "a corrupted container yielded the whole plaintext before failing"
        )


def test_a_mutated_wrapped_key_never_escapes_and_never_opens(monkeypatch) -> None:
    """Fuzz the wrapped-key parser, including its cost parameters.

    Two ways this could go wrong beyond a stray exception: a mutation that makes
    the file open anyway, and a mutated log2(N) or r that the parser accepts and
    hands to scrypt, turning a corrupt key file into a multi-gigabyte
    allocation.

    The memory ceiling is lowered to exactly what the recorded key needs for the
    duration. The real ceiling is 1 GiB, which a mutation can legitimately land
    under -- N=2^20 at r=8 is a valid, expensive key -- and then this test would
    spend seconds and a gigabyte on it, at the mercy of the seed. With the
    ceiling at the recorded cost, every mutation that raises it is refused
    outright, so each iteration is either cheap or instant while the parser is
    still fuzzed over every byte.
    """
    passphrase = "correct horse battery staple"
    params = wrapping.Params(log_n=10)
    text = PrivateKey.generate().encode(passphrase, params)
    blob = wrapping.parse(text).to_bytes()
    monkeypatch.setattr(wrapping, "MAX_MEMORY_BYTES", params.memory_bytes)
    rng = random.Random(SEED + 5)

    for _ in range(ITERATIONS):
        mutated = _mutate(rng, blob)
        if mutated == blob:
            continue
        candidate = armour(wrapping.WRAPPED_PREFIX, mutated, [])
        try:
            wrapping.unwrap(candidate, passphrase)
        except HpqcError:
            pass
        except Exception as exc:  # noqa: BLE001
            pytest.fail(
                f"{type(exc).__name__} escaped the wrapped-key parser: {exc}\n"
                f"blob prefix: {mutated[:40].hex()}"
            )
        else:
            pytest.fail("a mutated wrapped key opened successfully")


def test_random_garbage_is_never_mistaken_for_a_wrapped_key() -> None:
    rng = random.Random(SEED + 6)

    for _ in range(ITERATIONS):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
        candidate = armour(wrapping.WRAPPED_PREFIX, blob, [])
        with pytest.raises(HpqcError):
            wrapping.unwrap(candidate, "anything")
