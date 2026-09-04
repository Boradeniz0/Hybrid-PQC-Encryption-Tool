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
tests/vectors/v1-chunked.json covers the streamed payload shape, and records the
STREAM nonce table for the same reason the signed file records digests.

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
import io
import json
import unicodedata
from pathlib import Path

import pytest

from hpqc import hybrid, signing, streaming, suites, wrapping
from hpqc.container import (
    FLAG_CHUNKED,
    FLAG_SIGNED,
    FORMAT_VERSION,
    decrypt,
    decrypt_stream,
    open_container,
    parse_header,
)
from hpqc.errors import HpqcError, PassphraseError, SignatureError
from hpqc.keys import PrivateKey, PublicKey, SigningPrivateKey, SigningPublicKey


def _load(name: str) -> dict:
    path = Path(__file__).parent / "vectors" / name
    return json.loads(path.read_text(encoding="ascii"))


VECTORS = _load("v1.json")
SIGNED = _load("v1-signed.json")
WRAPPED = _load("v1-wrapped.json")
CHUNKED = _load("v1-chunked.json")


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


# --------------------------------------------------------------------------
# Passphrase-wrapped private keys
# --------------------------------------------------------------------------

_WRAPPED_CLASSES = {
    wrapping.KIND_IDENTITY: PrivateKey,
    wrapping.KIND_SIGNING_IDENTITY: SigningPrivateKey,
}


def test_the_wrapped_vectors_target_this_format() -> None:
    assert WRAPPED["format_version"] == wrapping.WRAP_VERSION


def test_the_wrap_label_has_not_changed() -> None:
    """It is associated data, so changing it makes every wrapped key unopenable."""
    assert wrapping.WRAP_LABEL.decode("ascii") == WRAPPED["wrap_label"]


@pytest.mark.parametrize(
    "vector", WRAPPED["keys"], ids=[k["kind_name"] for k in WRAPPED["keys"]]
)
class TestWrappedKeys:
    def test_it_still_opens_with_the_recorded_passphrase(self, vector) -> None:
        """Pins the layout, the scrypt call, and the associated data at once."""
        blob, kind = wrapping.unwrap(vector["wrapped"], WRAPPED["passphrase_nfd"])

        assert blob.hex() == vector["blob"]
        assert kind == vector["kind"]

    def test_the_normalised_passphrase_opens_it_too(self, vector) -> None:
        """The recorded passphrase is NFD; a user typing NFC must still get in.

        This is the test that would have caught shipping without normalisation:
        a key wrapped on one system simply would not open on another, and
        nothing in the error would say why.
        """
        composed = unicodedata.normalize("NFC", WRAPPED["passphrase_nfd"])
        assert composed != WRAPPED["passphrase_nfd"]  # genuinely different bytes

        blob, _ = wrapping.unwrap(vector["wrapped"], composed)
        assert blob.hex() == vector["blob"]

    def test_the_recorded_parameters_are_what_the_file_carries(self, vector) -> None:
        params = wrapping.parse(vector["wrapped"]).params

        assert params.log_n == WRAPPED["scrypt"]["log_n"]
        assert params.r == WRAPPED["scrypt"]["r"]
        assert params.p == WRAPPED["scrypt"]["p"]

    def test_it_loads_through_the_key_class_to_the_recorded_identity(
        self, vector
    ) -> None:
        cls = _WRAPPED_CLASSES[vector["kind"]]
        key = cls.decode(vector["wrapped"], WRAPPED["passphrase_nfd"])

        assert key.public_key().key_id_hex == vector["key_id"]
        assert key.public_key().encode() == vector["public"]

    def test_the_wrong_passphrase_still_fails(self, vector) -> None:
        with pytest.raises(PassphraseError):
            wrapping.unwrap(vector["wrapped"], "not the passphrase")

    def test_the_secret_is_not_sitting_in_the_file(self, vector) -> None:
        assert bytes.fromhex(vector["blob"]) not in vector["wrapped"].encode("ascii")


# --------------------------------------------------------------------------
# Chunked containers
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def chunked_identity() -> PrivateKey:
    return PrivateKey.decode(CHUNKED["identity"])


def test_the_chunked_vectors_target_this_format() -> None:
    assert CHUNKED["format_version"] == FORMAT_VERSION
    assert CHUNKED["flag_chunked"] == FLAG_CHUNKED


def test_the_chunking_constants_have_not_changed() -> None:
    """Every one of these is on the wire, implicitly.

    Nothing in a container states its chunk size: the reader assumes it, and
    finds the boundaries by counting. Change the constant and every file
    written before the change becomes unreadable, without a single test
    failing anywhere else.
    """
    assert CHUNKED["chunk_size"] == streaming.CHUNK_SIZE
    assert CHUNKED["tag_len"] == streaming.TAG_LEN
    assert CHUNKED["wire_chunk_size"] == streaming.WIRE_CHUNK_SIZE
    assert CHUNKED["nonce_prefix_len"] == streaming.NONCE_PREFIX_LEN
    assert CHUNKED["max_chunks"] == streaming.MAX_CHUNKS


@pytest.mark.parametrize(
    "vector",
    CHUNKED["nonces"],
    ids=[f"{v['index']}{'-final' if v['final'] else ''}" for v in CHUNKED["nonces"]],
)
def test_the_stream_nonce_construction_is_unchanged(vector) -> None:
    """The vector that actually pins the layout.

    A recorded container cannot do this job. Widen the counter, move the final
    -chunk byte to the front, swap 0x00 and 0x01 -- the writer and the reader
    change together, so the recorded container stops opening either way, and
    the failure says nothing about which change caused it. These triples name
    it exactly: the byte string, for a fixed prefix, index and final flag.
    """
    nonce = streaming.chunk_nonce(
        bytes.fromhex(vector["prefix"]), vector["index"], vector["final"]
    )
    assert nonce.hex() == vector["nonce"]


def _open_chunked(blob: bytes, identity: PrivateKey):
    sink = io.BytesIO()
    opened = decrypt_stream(io.BytesIO(blob), sink, identity)
    return sink.getvalue(), opened


@pytest.mark.parametrize(
    "vector",
    CHUNKED["containers"],
    ids=[f"{v['suite']}-{v['chunks']}chunk" for v in CHUNKED["containers"]],
)
class TestChunkedContainers:
    def test_it_decrypts_to_the_recorded_digest(
        self, vector, chunked_identity
    ) -> None:
        plaintext, opened = _open_chunked(
            bytes.fromhex(vector["container"]), chunked_identity
        )
        assert len(plaintext) == vector["plaintext_len"]
        assert hashlib.sha256(plaintext).hexdigest() == vector["plaintext_sha256"]
        assert opened.chunks == vector["chunks"]
        if "plaintext" in vector:
            assert plaintext == bytes.fromhex(vector["plaintext"])

    def test_its_header_still_parses_as_recorded(self, vector) -> None:
        header, header_bytes, payload = parse_header(
            bytes.fromhex(vector["container"])
        )
        assert header.version == FORMAT_VERSION
        assert header.chunked and not header.signed
        assert header.suite.id == vector["suite_id"]
        assert header.key_id.hex() == CHUNKED["key_id"]
        assert len(header_bytes) == 1168
        # Tags are the only per-chunk overhead; nothing else is framed.
        assert len(payload) == vector["plaintext_len"] + vector["chunks"] * 16

    def test_truncating_a_recorded_container_is_still_refused(
        self, vector, chunked_identity
    ) -> None:
        """The frozen half of the truncation defence.

        The live tests build a container and cut it; this one cuts a container
        built by an earlier version of the code, so a change that made the
        final-chunk marker stop mattering fails here too.
        """
        blob = bytes.fromhex(vector["container"])
        with pytest.raises(HpqcError):
            _open_chunked(blob[: -streaming.TAG_LEN - 1], chunked_identity)

    def test_a_recorded_container_is_still_rejected_when_corrupted(
        self, vector, chunked_identity
    ) -> None:
        corrupted = bytearray(bytes.fromhex(vector["container"]))
        corrupted[-1] ^= 0x01
        with pytest.raises(HpqcError):
            _open_chunked(bytes(corrupted), chunked_identity)


def test_a_recorded_multi_chunk_container_loses_its_last_chunk_and_fails(
    chunked_identity,
) -> None:
    """Cut on a chunk boundary, so every remaining chunk is untouched.

    Corrupting bytes proves the AEAD works. Removing a whole valid chunk is the
    attack the marker exists for, and this runs it against a frozen file.
    """
    vector = next(v for v in CHUNKED["containers"] if v["chunks"] > 1)
    blob = bytes.fromhex(vector["container"])
    cut = blob[: -streaming.WIRE_CHUNK_SIZE]

    with pytest.raises(HpqcError):
        _open_chunked(cut, chunked_identity)
