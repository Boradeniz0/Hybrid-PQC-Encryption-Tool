"""Frozen known-answer vectors: the wire format must not drift.

Every other test in this suite checks that hpqc agrees with *itself* -- encrypt
then decrypt, derive twice and compare. That catches a lot, but it cannot catch
the one change that matters most to anyone who has already encrypted a file: a
refactor that alters the header layout or the key derivation in a way both
sides agree on. Yesterday's containers would stop opening and every test would
still pass.

tests/vectors/v1.json pins that down. It holds containers produced by an
earlier build, together with the identity that opens them, so the current code
has to reproduce yesterday's answers. tests/vectors/v1-signed.json does the same
for sender authentication, and records two extra things: the digest of the exact
byte string the signatures cover, which pins the construction, and one container
that must never verify -- a signature made for a different recipient, re-sealed.

The digests matter because a recorded *signature* cannot pin a construction. Drop
the recipient from the signed message and the recorded signature stops verifying
-- but it would have stopped verifying under any change, so the failure says
nothing about which one. The digest names it exactly. Encryption is not reproducible (fresh
ephemeral key, fresh encapsulation, fresh salt and nonce, none of them
injectable), so the vectors are verified on the decryption side, which is
deterministic.

Regenerate with `python tools/make_vectors.py --force` -- and only when the
format has changed on purpose, which also means bumping FORMAT_VERSION and
hybrid.HKDF_LABEL.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hpqc import hybrid, signing, suites
from hpqc.container import (
    FLAG_SIGNED,
    FORMAT_VERSION,
    decrypt,
    open_container,
    parse_header,
)
from hpqc.errors import HpqcError, SignatureError
from hpqc.keys import PrivateKey, PublicKey, SigningPublicKey


def _load(name: str) -> dict:
    path = Path(__file__).parent / "vectors" / name
    return json.loads(path.read_text(encoding="ascii"))


VECTORS = _load("v1.json")
SIGNED = _load("v1-signed.json")


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


# --------------------------------------------------------------------------
# Sender authentication
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def signed_identity() -> PrivateKey:
    return PrivateKey.decode(SIGNED["identity"])


@pytest.fixture(scope="module")
def recorded_signer() -> SigningPublicKey:
    return SigningPublicKey.decode(SIGNED["signer"])


def test_the_signed_vectors_target_this_format(recorded_signer) -> None:
    assert SIGNED["format_version"] == FORMAT_VERSION
    assert SIGNED["flag_signed"] == FLAG_SIGNED
    assert SIGNED["signature_block_len"] == signing.SIGNATURE_BLOCK_LEN
    assert recorded_signer.key_id_hex == SIGNED["signer_key_id"]
    assert recorded_signer.to_bytes().hex() == SIGNED["signer_blob"]


def test_the_signature_label_has_not_changed() -> None:
    """A changed label invalidates every signature ever produced."""
    assert signing.SIG_LABEL.decode("ascii") == SIGNED["sig_label"]


@pytest.mark.parametrize(
    "vector", SIGNED["containers"], ids=_ids(SIGNED["containers"])
)
class TestSignedContainers:
    def test_it_verifies_against_the_recorded_signer(
        self, vector, signed_identity, recorded_signer
    ) -> None:
        opened = open_container(
            bytes.fromhex(vector["container"]), signed_identity, recorded_signer
        )
        assert opened.plaintext == bytes.fromhex(vector["plaintext"])
        assert opened.signer == recorded_signer
        assert opened.verified is True

    def test_its_header_still_advertises_the_signed_flag(self, vector) -> None:
        header, header_bytes, _ = parse_header(bytes.fromhex(vector["container"]))
        assert header.signed is True
        assert header.flags == FLAG_SIGNED
        assert header.suite.id == vector["suite_id"]
        # The flag lives in the header, which is the AAD; its length must not
        # have moved just because the payload grew.
        assert len(header_bytes) == 1168

    def test_the_overhead_is_still_the_documented_constant(self, vector) -> None:
        plaintext_len = len(bytes.fromhex(vector["plaintext"]))
        container_len = len(bytes.fromhex(vector["container"]))
        assert container_len - plaintext_len == 1168 + signing.SIGNATURE_BLOCK_LEN + 16

    def test_it_reports_the_signer_without_a_pinned_key(
        self, vector, signed_identity
    ) -> None:
        """Reporting who signed is fine; claiming it was verified is not."""
        opened = open_container(bytes.fromhex(vector["container"]), signed_identity)
        assert opened.signer.key_id_hex == SIGNED["signer_key_id"]
        assert opened.verified is False


@pytest.mark.parametrize(
    "vector",
    SIGNED["signed_messages"],
    ids=[f"{v['suite']}-{len(v['plaintext']) // 2}B" for v in SIGNED["signed_messages"]],
)
def test_the_signed_message_construction_is_unchanged(vector, recorded_signer) -> None:
    """Pins every field of what gets signed, and their order.

    This is the signature counterpart to the HKDF derivation vectors: drop the
    recipient (and surreptitious forwarding works again), reorder two fields,
    change the label, or slip in a length prefix, and this digest moves. None of
    those changes can be caught by a recorded signature, which fails under any
    modification and so cannot say which one happened.
    """
    message = signing.signed_message(
        bytes.fromhex(vector["plaintext"]),
        recorded_signer,
        PublicKey.decode(SIGNED["public"]),
        suites.by_id(vector["suite_id"]),
    )

    assert len(message) == vector["length"]
    assert hashlib.sha256(message).hexdigest() == vector["sha256"]


class TestFrozenForwardingRejection:
    """A signature made for one recipient, re-sealed to another.

    What this guards is a build that accepts forwarded containers outright --
    verification skipped, or the sender-supplied key inside the file trusted
    without checking what it was bound to. It does *not* by itself catch a
    change to the signed-message construction: a signature recorded under the
    old construction fails under a new one too, so the rejection would be
    right for the wrong reason. That job belongs to the digest vectors above.
    """

    def test_it_never_verifies_with_a_pinned_signer(
        self, signed_identity, recorded_signer
    ) -> None:
        with pytest.raises(SignatureError, match="does not verify"):
            open_container(
                bytes.fromhex(SIGNED["forwarded"]["container"]),
                signed_identity,
                recorded_signer,
            )

    def test_it_never_verifies_without_one_either(self, signed_identity) -> None:
        with pytest.raises(SignatureError, match="does not verify"):
            open_container(
                bytes.fromhex(SIGNED["forwarded"]["container"]), signed_identity
            )

    def test_it_fails_for_the_right_reason(self, signed_identity) -> None:
        """The rejection must come from the binding, not from a broken file.

        SignatureError rather than DecryptionError is itself the proof that the
        AEAD verified: the tag check runs first and would have raised the other
        error. These assertions add the rest of it -- the container really is
        addressed to this identity and really is marked signed, so the tests
        above are not passing because the vector is merely corrupt.
        """
        from hpqc.errors import DecryptionError

        blob = bytes.fromhex(SIGNED["forwarded"]["container"])
        header, _, _ = parse_header(blob)

        assert header.signed is True
        assert header.key_id == signed_identity.public_key().key_id

        with pytest.raises(SignatureError) as caught:
            open_container(blob, signed_identity)
        assert not isinstance(caught.value, DecryptionError)
