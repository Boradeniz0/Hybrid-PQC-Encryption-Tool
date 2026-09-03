"""Frozen known-answer vectors: the wire format must not drift.

Every other test in this suite checks that hpqc agrees with *itself* -- encrypt
then decrypt, derive twice and compare. That catches a lot, but it cannot catch
the one change that matters most to anyone who has already encrypted a file: a
refactor that alters the header layout or the key derivation in a way both
sides agree on. Yesterday's containers would stop opening and every test would
still pass.

tests/vectors/v1.json pins that down. It holds containers produced by an
earlier build, together with the identity that opens them, so the current code
has to reproduce yesterday's answers. Encryption is not reproducible (fresh
ephemeral key, fresh encapsulation, fresh salt and nonce, none of them
injectable), so the vectors are verified on the decryption side, which is
deterministic.

Regenerate with `python tools/make_vectors.py --force` -- and only when the
format has changed on purpose, which also means bumping FORMAT_VERSION and
hybrid.HKDF_LABEL.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hpqc import hybrid, suites
from hpqc.container import FORMAT_VERSION, decrypt, parse_header
from hpqc.errors import HpqcError
from hpqc.keys import PrivateKey, PublicKey

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "v1.json").read_text(encoding="ascii")
)


@pytest.fixture(scope="module")
def identity() -> PrivateKey:
    return PrivateKey.decode(VECTORS["identity"])


def _ids(entries):
    return [f"{e['suite']}-{len(e['plaintext']) // 2}B" for e in entries]


def test_the_vector_file_targets_this_format_version() -> None:
    assert VECTORS["format_version"] == FORMAT_VERSION


def test_the_hkdf_label_has_not_changed() -> None:
    """A changed label changes every derived key, so it must be deliberate.

    If this fails because the derivation genuinely changed shape, the label
    bump is correct -- but the format version has to move with it and these
    vectors have to be regenerated under a new name, not overwritten.
    """
    assert hybrid.HKDF_LABEL.decode("ascii") == VECTORS["hkdf_label"]


class TestKeyEncoding:
    """The armour is part of the format: old key files must still load."""

    def test_the_recorded_private_key_still_decodes(self, identity) -> None:
        assert identity.to_bytes().hex() == VECTORS["private_blob"]

    def test_the_recorded_public_key_still_decodes(self) -> None:
        public = PublicKey.decode(VECTORS["public"])
        assert public.to_bytes().hex() == VECTORS["public_blob"]

    def test_the_key_id_is_unchanged(self, identity) -> None:
        """Key ids are printed to users and stored in every header."""
        assert identity.public_key().key_id_hex == VECTORS["key_id"]

    def test_the_private_key_still_yields_the_recorded_public_key(
        self, identity
    ) -> None:
        """Catches a change in how the ML-KEM seed is expanded on load."""
        assert identity.public_key() == PublicKey.decode(VECTORS["public"])


@pytest.mark.parametrize(
    "vector", VECTORS["containers"], ids=_ids(VECTORS["containers"])
)
class TestContainers:
    def test_it_decrypts_to_the_recorded_plaintext(self, vector, identity) -> None:
        container = bytes.fromhex(vector["container"])
        assert decrypt(container, identity) == bytes.fromhex(vector["plaintext"])

    def test_its_header_still_parses_as_recorded(self, vector) -> None:
        header, header_bytes, ciphertext = parse_header(
            bytes.fromhex(vector["container"])
        )
        assert header.version == FORMAT_VERSION
        assert header.suite.id == vector["suite_id"]
        assert header.suite.name == vector["suite_name"]
        assert header.key_id.hex() == VECTORS["key_id"]
        # The header is the AAD, so its length is load-bearing, not cosmetic.
        assert len(header_bytes) == 1168
        assert len(ciphertext) == len(bytes.fromhex(vector["plaintext"])) + 16

    def test_a_recorded_container_is_still_rejected_when_corrupted(
        self, vector, identity
    ) -> None:
        """Guards against a change that makes the vectors decode unconditionally."""
        corrupted = bytearray(bytes.fromhex(vector["container"]))
        corrupted[-1] ^= 0x01
        with pytest.raises(HpqcError):
            decrypt(bytes(corrupted), identity)


@pytest.mark.parametrize(
    "vector", VECTORS["derivations"], ids=[v["suite"] for v in VECTORS["derivations"]]
)
def test_the_derivation_reproduces_the_recorded_key(vector) -> None:
    """Pins HKDF: the label, the salt, and every field of the transcript.

    The inputs here are fixed filler rather than a real exchange, so this
    isolates the derivation from the KEMs: reorder the transcript, drop a
    field, or change the label and this is the test that notices.
    """
    key = hybrid.derive_key(
        ikm=bytes.fromhex(vector["ikm"]),
        salt=bytes.fromhex(vector["salt"]),
        suite=suites.by_id(vector["suite_id"]),
        ephemeral_public=bytes.fromhex(vector["ephemeral_public"]),
        kem_ciphertext=bytes.fromhex(vector["kem_ciphertext"]),
        recipient=PublicKey.decode(VECTORS["public"]),
    )
    assert key.hex() == vector["key"]
