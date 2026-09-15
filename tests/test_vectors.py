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
tests/vectors/v1-recipients.json covers files written to a list of recipients,
and records the derived wrapping key and the sealed file key for fixed inputs --
because a recorded container would still round-trip after the wrapping label,
the salt, or the recipient binding had been dropped from the derivation.

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

from hpqc import container as container_module
from hpqc import hybrid, kems, recipients, signing, streaming, suites, wrapping
from hpqc.container import (
    FLAG_CHUNKED,
    FLAG_COMMITTED,
    FLAG_RECIPIENTS,
    FLAG_SIGNED,
    FORMAT_VERSION,
    decrypt,
    decrypt_stream,
    open_container,
    parse_header,
)
from hpqc.errors import (
    FormatError,
    HpqcError,
    PassphraseError,
    SignatureError,
    WrongRecipientError,
)
from hpqc.keys import PrivateKey, PublicKey, SigningPrivateKey, SigningPublicKey


def _load(name: str) -> dict:
    path = Path(__file__).parent / "vectors" / name
    return json.loads(path.read_text(encoding="ascii"))


VECTORS = _load("v1.json")
SIGNED = _load("v1-signed.json")
WRAPPED = _load("v1-wrapped.json")
CHUNKED = _load("v1-chunked.json")
RECIPIENTS = _load("v1-recipients.json")
SIGNED_RECIPIENTS = _load("v1-signed-recipients.json")
MLKEM1024 = _load("v1-mlkem1024.json")
COMMITTED = _load("v1-committed.json")
SIGNED_STREAM = _load("v1-signed-stream.json")


@pytest.fixture(scope="module")
def identity() -> PrivateKey:
    return PrivateKey.decode(VECTORS["identity"])


def is_listed(container_hex: str) -> bool:
    """Whether a recorded container uses the recipient list, from its flags.

    Read straight out of the bytes rather than by parsing, because parsing is
    exactly what these containers no longer survive.
    """
    flags = int.from_bytes(bytes.fromhex(container_hex)[6:8], "big")
    return bool(flags & FLAG_RECIPIENTS)


def named(entries):
    """The recorded containers with a single named recipient."""
    return [e for e in entries if not is_listed(e["container"])]


def listed(entries):
    """The recorded containers whose recipients are a list."""
    return [e for e in entries if is_listed(e["container"])]


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


# --------------------------------------------------------------------------
# Recipient lists
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def listed_identities():
    return [PrivateKey.decode(text) for text in RECIPIENTS["identities"]]


@pytest.fixture(scope="module")
def listed_stranger() -> PrivateKey:
    return PrivateKey.decode(RECIPIENTS["stranger"])


def test_the_recipient_vectors_target_this_format() -> None:
    assert RECIPIENTS["format_version"] == FORMAT_VERSION
    assert RECIPIENTS["flag_recipients"] == FLAG_RECIPIENTS


def test_the_file_key_wrap_label_has_not_changed() -> None:
    """A different label from the payload's, and the same one as yesterday's.

    Change it and every stanza ever written becomes unopenable -- while every
    round-trip test keeps passing, because both halves would move together.
    """
    assert hybrid.WRAP_LABEL.decode("ascii") == RECIPIENTS["wrap_label"]
    assert hybrid.WRAP_LABEL != hybrid.HKDF_LABEL


def test_the_stanza_layout_constants_have_not_changed() -> None:
    """Nothing in a container states these; the reader counts on them.

    The offsets this file recorded moved when the commitment was added, and
    that is the point of it being a separate 32-byte field rather than a
    reinterpretation of one already there. They are checked against a real
    header in the committed vectors instead.
    """
    layout = RECIPIENTS["layout"]
    assert layout["max_recipients"] == recipients.MAX_RECIPIENTS
    assert layout["wrap_tag_len"] == recipients.WRAP_TAG_LEN
    assert layout["no_key_id"] == container_module.NO_KEY_ID.hex()
    for name, expected in layout["stanza_len"].items():
        assert recipients.stanza_len(suites.BY_CLI_NAME[name]) == expected

    assert layout["count_offset"] + recipients.COMMITMENT_LEN == COMMITTED[
        "count_offset"
    ]


@pytest.mark.parametrize(
    "vector",
    RECIPIENTS["wrappings"],
    ids=[v["suite"] for v in RECIPIENTS["wrappings"]],
)
def test_the_wrapping_derivation_is_unchanged(vector) -> None:
    """The vector that actually pins the scheme.

    Drop the salt, reuse the payload label, stop binding the recipient's public
    keys -- a recorded container survives every one of those, because the
    writer and the reader move together and the file still opens. Recording the
    derived key and the sealed blob for fixed inputs is what notices.
    """
    suite = suites.BY_CLI_NAME[vector["suite"]]
    recipient = PublicKey.decode(RECIPIENTS["publics"][vector["recipient_index"]])

    wrapping_key = hybrid.derive_key(
        ikm=bytes.fromhex(vector["ikm"]),
        salt=bytes.fromhex(vector["salt"]),
        suite=suite,
        ephemeral_public=bytes.fromhex(vector["ephemeral_public"]),
        kem_ciphertext=bytes.fromhex(vector["kem_ciphertext"]),
        recipient=recipient,
        label=hybrid.WRAP_LABEL,
    )
    assert wrapping_key.hex() == vector["wrapping_key"]

    # And the sealing on top of it: the nonce is all zeros, deliberately.
    nonce = bytes.fromhex(vector["nonce"])
    assert nonce == b"\x00" * suite.nonce_len
    sealed = suite.aead(wrapping_key).encrypt(
        nonce, bytes.fromhex(vector["file_key"]), None
    )
    assert sealed.hex() == vector["wrapped_key"]
    assert suite.aead(wrapping_key).decrypt(
        nonce, bytes.fromhex(vector["wrapped_key"]), None
    ) == bytes.fromhex(vector["file_key"])


@pytest.fixture(scope="module")
def signed_list_identities():
    return [PrivateKey.decode(t) for t in SIGNED_RECIPIENTS["identities"]]


@pytest.fixture(scope="module")
def signed_list_signer() -> SigningPublicKey:
    return SigningPublicKey.decode(SIGNED_RECIPIENTS["signer_public"])


def test_the_signed_recipient_vectors_target_this_format() -> None:
    assert SIGNED_RECIPIENTS["format_version"] == FORMAT_VERSION
    assert SIGNED_RECIPIENTS["flags"] == FLAG_SIGNED | FLAG_RECIPIENTS


def test_the_container_signature_label_has_not_changed() -> None:
    """Distinct from the classic one, and the same as yesterday's.

    Nothing behavioural pins the separation today -- the two messages already
    differ structurally -- so it is pinned here and in test_recipients.py.
    """
    assert signing.SIG_CONTAINER_LABEL.decode("ascii") == SIGNED_RECIPIENTS[
        "sig_container_label"
    ]
    assert signing.SIG_LABEL.decode("ascii") == SIGNED_RECIPIENTS["sig_label"]
    assert signing.SIG_CONTAINER_LABEL != signing.SIG_LABEL


@pytest.mark.parametrize(
    "vector",
    SIGNED_RECIPIENTS["signed_messages"],
    ids=[v["suite"] for v in SIGNED_RECIPIENTS["signed_messages"]],
)
def test_the_container_signed_message_construction_is_unchanged(
    vector, signed_list_signer
) -> None:
    """The vector that pins the construction rather than one run of it.

    Drop the header from the signed message and surreptitious forwarding works
    again. Drop its length prefix and a byte can move between the header and
    the plaintext. Either way every round trip still passes and every recorded
    signature stops verifying for a reason nobody can name. The digest names it.
    """
    message = signing.container_signed_message(
        bytes.fromhex(vector["plaintext"]),
        signed_list_signer,
        bytes.fromhex(vector["header_bytes"]),
        suites.BY_CLI_NAME[vector["suite"]],
    )
    assert len(message) == vector["message_len"]
    assert hashlib.sha256(message).hexdigest() == vector["message_sha256"]


@pytest.fixture(scope="module")
def big_identities():
    return [PrivateKey.decode(t) for t in MLKEM1024["identities"]]


def test_the_1024_vectors_target_this_format() -> None:
    assert MLKEM1024["format_version"] == FORMAT_VERSION


def test_the_kem_table_has_not_changed() -> None:
    """The numbers every parser looks up, frozen against a self-consistent typo.

    Get one of these wrong and hpqc still encrypts and decrypts perfectly --
    with itself, and with nothing else that implements FIPS 203.
    """
    recorded = MLKEM1024["kem"]
    kem = kems.by_id(recorded["id"])

    assert kem.name == recorded["name"]
    assert kem.dh_name == recorded["dh_name"]
    assert kem.dh_len == recorded["dh_len"]
    assert kem.dh_shared_len == recorded["dh_shared_len"]
    assert kem.kem_name == recorded["kem_name"]
    assert kem.kem_public_len == recorded["kem_public_len"]
    assert kem.kem_ciphertext_len == recorded["kem_ciphertext_len"]
    assert kems.KEM_SEED_LEN == recorded["kem_seed_len"]
    assert kem.ikm_len == recorded["ikm_len"]

    for name, suite_id in recorded["suite_ids"].items():
        assert suites.by_id(suite_id).kem is kem
        assert suites.by_id(suite_id).aead_name == suites.BY_CLI_NAME[name].aead_name

    assert recipients.stanza_len(suites.by_id(3)) == recorded["stanza_len"]


def test_a_recorded_1024_key_still_decodes() -> None:
    """The blob layout: one type byte, then two halves of recorded length.

    The private blob is the reason the type byte exists. Its ML-KEM seed is 64
    bytes for every parameter set, so a 768 and a 1024 private key differ only
    by their DH half -- length alone cannot tell them apart.
    """
    recorded = MLKEM1024["keys"]
    identity = PrivateKey.decode(recorded["identity"])
    public = PublicKey.decode(recorded["public"])

    assert identity.public_key() == public
    assert public.key_id_hex == recorded["key_id"]
    assert public.to_bytes().hex() == recorded["public_blob"]
    assert identity.to_bytes().hex() == recorded["private_blob"]
    assert identity.kem is kems.X448_MLKEM1024

    other = PrivateKey.decode(recorded["other_kem_identity"])
    assert other.kem is kems.X25519_MLKEM768
    assert other.to_bytes()[0] != identity.to_bytes()[0]
    assert len(other.to_bytes()) != len(identity.to_bytes())


@pytest.mark.parametrize(
    "vector", MLKEM1024["derivations"], ids=[v["suite"] for v in MLKEM1024["derivations"]]
)
def test_the_1024_derivations_are_unchanged(vector) -> None:
    suite = suites.by_id(vector["suite_id"])
    public = PublicKey.decode(MLKEM1024["publics"][0])
    args = dict(
        ikm=bytes.fromhex(vector["ikm"]),
        salt=bytes.fromhex(vector["salt"]),
        suite=suite,
        ephemeral_public=bytes.fromhex(vector["ephemeral_public"]),
        kem_ciphertext=bytes.fromhex(vector["kem_ciphertext"]),
        recipient=public,
    )
    assert hybrid.derive_key(**args, label=hybrid.HKDF_LABEL).hex() == vector[
        "payload_key"
    ]
    assert hybrid.derive_key(**args, label=hybrid.WRAP_LABEL).hex() == vector[
        "wrap_key"
    ]


@pytest.mark.parametrize(
    "vector",
    named(MLKEM1024["containers"]),
    ids=[
        f"{v['suite']}-{v['shape'].replace(' ', '-')}"
        for v in named(MLKEM1024["containers"])
    ],
)
class TestRecorded1024Containers:
    def test_it_still_decrypts(self, vector, big_identities) -> None:
        blob = bytes.fromhex(vector["container"])
        for identity in big_identities[: vector["recipients"]]:
            assert decrypt(blob, identity) == bytes.fromhex(vector["plaintext"])

    def test_its_header_still_parses_as_recorded(self, vector) -> None:
        header, header_bytes, _ = parse_header(bytes.fromhex(vector["container"]))
        assert header.suite.id == vector["suite_id"]
        assert header.suite.kem is kems.X448_MLKEM1024
        assert header.recipient_count == vector["recipients"]
        assert header.signed == vector.get("signed", False)
        if vector["recipients"] == 1 and not header.multi:
            assert len(header_bytes) == MLKEM1024["kem"]["header_len"]

    def test_a_stranger_still_cannot(self, vector) -> None:
        stranger = PrivateKey.decode(MLKEM1024["stranger"])
        with pytest.raises(HpqcError):
            decrypt(bytes.fromhex(vector["container"]), stranger)

    def test_a_768_identity_still_cannot(self, vector) -> None:
        small = PrivateKey.decode(MLKEM1024["keys"]["other_kem_identity"])
        with pytest.raises(WrongRecipientError, match="but the supplied identity is"):
            decrypt(bytes.fromhex(vector["container"]), small)

    def test_relabelling_it_as_the_smaller_kem_still_fails(self, vector) -> None:
        """The suite byte cannot reinterpret a recorded container's fields."""
        blob = bytearray(bytes.fromhex(vector["container"]))
        blob[5] = vector["suite_id"] - 2  # 0x03 -> 0x01, 0x04 -> 0x02
        with pytest.raises(HpqcError, match="expected 32 here"):
            parse_header(bytes(blob))


@pytest.fixture(scope="module")
def stream_identities():
    return [PrivateKey.decode(t) for t in SIGNED_STREAM["identities"]]


@pytest.fixture(scope="module")
def stream_signer() -> SigningPublicKey:
    return SigningPublicKey.decode(SIGNED_STREAM["signer_public"])


def test_the_signed_stream_vectors_target_this_format() -> None:
    assert SIGNED_STREAM["format_version"] == FORMAT_VERSION
    assert SIGNED_STREAM["flags"] == FLAG_SIGNED | FLAG_CHUNKED
    assert SIGNED_STREAM["signature_block_len"] == signing.SIGNATURE_BLOCK_LEN


def test_the_stream_signature_labels_have_not_changed() -> None:
    assert signing.SIG_STREAM_LABEL.decode("ascii") == SIGNED_STREAM[
        "sig_stream_label"
    ]
    assert signing.STREAM_DIGEST_LABEL.decode("ascii") == SIGNED_STREAM[
        "stream_digest_label"
    ]
    assert signing.STREAM_DIGEST_LEN == SIGNED_STREAM["stream_digest_len"]
    assert len({
        signing.SIG_LABEL,
        signing.SIG_CONTAINER_LABEL,
        signing.SIG_STREAM_LABEL,
    }) == 3


@pytest.mark.parametrize(
    "vector", SIGNED_STREAM["digests"], ids=[v["name"] for v in SIGNED_STREAM["digests"]]
)
def test_the_stream_digest_construction_is_unchanged(vector) -> None:
    """What the signature is actually a statement about.

    Change the hash, change its label, or start feeding it the signature block
    along with the plaintext, and every signature ever made over a stream stops
    verifying -- while every round trip in the suite keeps passing, because the
    writer and the reader would move together.
    """
    if "plaintext" in vector:
        plaintext = bytes.fromhex(vector["plaintext"])
    else:
        plaintext = None

    if plaintext is not None:
        assert signing.digest_stream(io.BytesIO(plaintext)).hex() == vector["digest"]
        assert len(bytes.fromhex(vector["digest"])) == signing.STREAM_DIGEST_LEN
    else:
        # The long one is recorded by length and hash rather than inline.
        assert vector["plaintext_len"] > streaming.CHUNK_SIZE
        assert len(bytes.fromhex(vector["digest"])) == signing.STREAM_DIGEST_LEN


@pytest.mark.parametrize(
    "vector",
    SIGNED_STREAM["signed_messages"],
    ids=[v["suite"] for v in SIGNED_STREAM["signed_messages"]],
)
def test_the_stream_signed_message_construction_is_unchanged(
    vector, stream_signer
) -> None:
    message = signing.stream_signed_message(
        bytes.fromhex(vector["digest"]),
        stream_signer,
        bytes.fromhex(vector["header_bytes"]),
        suites.BY_CLI_NAME[vector["suite"]],
    )
    assert len(message) == vector["message_len"]
    assert hashlib.sha256(message).hexdigest() == vector["message_sha256"]


@pytest.mark.parametrize(
    "vector",
    named(SIGNED_STREAM["containers"]),
    ids=[
        f"{v['suite']}-{v['shape'].replace(' ', '-')}"
        for v in named(SIGNED_STREAM["containers"])
    ],
)
class TestRecordedSignedStreams:
    def test_every_recipient_still_verifies_it(
        self, vector, stream_identities, stream_signer
    ) -> None:
        blob = bytes.fromhex(vector["container"])
        for identity in stream_identities[: vector["recipients"]]:
            sink = io.BytesIO()
            opened = decrypt_stream(io.BytesIO(blob), sink, identity, stream_signer)
            assert opened.verified and opened.signer == stream_signer
            assert opened.chunks == vector["chunks"]
            assert len(sink.getvalue()) == vector["plaintext_len"]
            assert (
                hashlib.sha256(sink.getvalue()).hexdigest()
                == vector["plaintext_sha256"]
            )

    def test_its_header_still_says_signed_and_chunked(self, vector) -> None:
        header, _, _ = parse_header(bytes.fromhex(vector["container"]))
        assert header.signed and header.chunked
        assert header.suite.id == vector["suite_id"]
        assert header.recipient_count == vector["recipients"]

    def test_it_still_hides_who_signed(self, vector, stream_signer) -> None:
        blob = bytes.fromhex(vector["container"])
        assert stream_signer.ed25519_bytes not in blob
        assert stream_signer.mldsa_bytes not in blob

    def test_a_stranger_still_cannot_open_it(self, vector) -> None:
        stranger = PrivateKey.decode(SIGNED_STREAM["stranger"])
        with pytest.raises(HpqcError):
            decrypt_stream(
                io.BytesIO(bytes.fromhex(vector["container"])),
                io.BytesIO(),
                stranger,
            )

    def test_truncating_it_is_still_refused(self, vector, stream_identities) -> None:
        blob = bytes.fromhex(vector["container"])
        with pytest.raises(HpqcError):
            decrypt_stream(
                io.BytesIO(blob[: -streaming.WIRE_CHUNK_SIZE]),
                io.BytesIO(),
                stream_identities[0],
            )


def test_a_recorded_forwarded_stream_still_does_not_verify(
    stream_identities, stream_signer
) -> None:
    """Surreptitious forwarding over a stream, frozen.

    The block was signed over one container's header and the stream re-sealed
    under another. The AEAD is content -- whoever built it held the file key --
    so only the header binding is between this and a file that verifies as
    "the signer wrote this to me".
    """
    vector = SIGNED_STREAM["forwarded"]
    blob = bytes.fromhex(vector["container"])
    identity = stream_identities[vector["opens_for"]]

    with pytest.raises(SignatureError):
        decrypt_stream(io.BytesIO(blob), io.BytesIO(), identity, stream_signer)
    with pytest.raises(SignatureError):
        decrypt_stream(io.BytesIO(blob), io.BytesIO(), identity)


def test_the_forwarded_stream_vector_is_a_real_container(stream_identities) -> None:
    """Otherwise the test above could pass because the file is simply broken."""
    vector = SIGNED_STREAM["forwarded"]
    blob = bytes.fromhex(vector["container"])
    identity = stream_identities[vector["opens_for"]]

    header, header_bytes, _ = parse_header(blob)
    assert header.signed and header.chunked
    _, key = container_module._open_setup(header, identity)

    # Every chunk opens; it is the signature over them that does not.
    plain = io.BytesIO()
    streaming.open_stream(
        io.BytesIO(blob[len(header_bytes) :]), plain, key, header.suite,
        header.nonce_prefix, header_bytes,
    )
    assert plain.getvalue().endswith(bytes.fromhex(vector["plaintext"]))
    assert len(plain.getvalue()) == (
        signing.SIGNATURE_BLOCK_LEN + len(bytes.fromhex(vector["plaintext"]))
    )


# --------------------------------------------------------------------------
# Recipient lists that commit to their file key
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def committed_identities():
    return [PrivateKey.decode(t) for t in COMMITTED["identities"]]


@pytest.fixture(scope="module")
def committed_big_identities():
    return [PrivateKey.decode(t) for t in COMMITTED["big_identities"]]


@pytest.fixture(scope="module")
def committed_signer() -> SigningPublicKey:
    return SigningPublicKey.decode(COMMITTED["signer_public"])


def test_the_committed_vectors_target_this_format() -> None:
    assert COMMITTED["format_version"] == FORMAT_VERSION
    assert COMMITTED["flag_committed"] == FLAG_COMMITTED
    assert COMMITTED["flag_recipients"] == FLAG_RECIPIENTS
    assert COMMITTED["commitment_len"] == recipients.COMMITMENT_LEN


def test_the_commitment_label_has_not_changed() -> None:
    assert recipients.COMMIT_LABEL.decode("ascii") == COMMITTED["commit_label"]


@pytest.mark.parametrize(
    "vector", COMMITTED["commitments"], ids=[v["suite"] for v in COMMITTED["commitments"]]
)
def test_the_commitment_derivation_is_unchanged(vector) -> None:
    """The vector that pins the scheme rather than one run of it.

    Change the label, drop the salt, swap the hash -- a recorded container
    survives every one of those, because the writer computes the commitment and
    the reader checks it and the two move together. Only the known answer
    notices, and what it protects is the property that a sender cannot hand two
    recipients two different file keys.
    """
    suite = suites.BY_CLI_NAME[vector["suite"]]
    assert recipients.commitment(
        bytes.fromhex(vector["file_key"]),
        bytes.fromhex(vector["salt"]),
        suite,
    ).hex() == vector["commitment"]


@pytest.mark.parametrize(
    "vector",
    COMMITTED["containers"],
    ids=[
        f"{v['suite']}-{v['shape'].replace(' ', '-')}-{v['recipients']}to"
        for v in COMMITTED["containers"]
    ],
)
class TestRecordedCommittedLists:
    @staticmethod
    def _identities(vector, small, big):
        return (big if vector.get("big") else small)[: vector["recipients"]]

    def test_every_recipient_still_opens_it(
        self, vector, committed_identities, committed_big_identities, committed_signer
    ) -> None:
        blob = bytes.fromhex(vector["container"])
        sender = committed_signer if vector.get("signed") else None

        for identity in self._identities(
            vector, committed_identities, committed_big_identities
        ):
            if vector.get("chunked"):
                sink = io.BytesIO()
                opened = decrypt_stream(io.BytesIO(blob), sink, identity, sender)
                assert opened.chunks == vector["chunks"]
                assert (
                    hashlib.sha256(sink.getvalue()).hexdigest()
                    == vector["plaintext_sha256"]
                )
            else:
                opened = open_container(blob, identity, sender)
                assert opened.plaintext == bytes.fromhex(vector["plaintext"])
            assert opened.verified == bool(sender)

    def test_its_header_still_parses_as_recorded(self, vector) -> None:
        blob = bytes.fromhex(vector["container"])
        header, header_bytes, _ = parse_header(blob)

        assert header.multi and header.committed
        assert header.suite.id == vector["suite_id"]
        assert header.recipient_count == vector["recipients"]
        assert header.signed == bool(vector.get("signed"))
        assert header.chunked == bool(vector.get("chunked"))
        assert len(header.commitment) == recipients.COMMITMENT_LEN

        offset = COMMITTED["commitment_offset"]
        assert blob[offset : offset + recipients.COMMITMENT_LEN] == header.commitment
        count_offset = COMMITTED["count_offset"]
        assert int.from_bytes(
            blob[count_offset : count_offset + 2], "big"
        ) == header.recipient_count

    def test_it_still_names_nobody(self, vector) -> None:
        blob = bytes.fromhex(vector["container"])
        publics = COMMITTED["big_publics"] if vector.get("big") else COMMITTED["publics"]
        for text in publics:
            assert PublicKey.decode(text).key_id not in blob

    def test_a_stranger_still_cannot_open_it(self, vector) -> None:
        stranger = PrivateKey.decode(COMMITTED["stranger"])
        with pytest.raises(HpqcError):
            if vector.get("chunked"):
                decrypt_stream(
                    io.BytesIO(bytes.fromhex(vector["container"])),
                    io.BytesIO(),
                    stranger,
                )
            else:
                decrypt(bytes.fromhex(vector["container"]), stranger)

    def test_editing_the_recorded_commitment_is_refused(
        self, vector, committed_identities, committed_big_identities
    ) -> None:
        """It is inside the associated data, so it cannot be quietly replaced."""
        blob = bytearray(bytes.fromhex(vector["container"]))
        blob[COMMITTED["commitment_offset"]] ^= 0x01
        identity = self._identities(
            vector, committed_identities, committed_big_identities
        )[0]

        with pytest.raises(HpqcError):
            if vector.get("chunked"):
                decrypt_stream(io.BytesIO(bytes(blob)), io.BytesIO(), identity)
            else:
                decrypt(bytes(blob), identity)


def test_a_recorded_uncommitted_list_is_refused(committed_identities) -> None:
    """The shape a sender who wants to cheat would write, frozen.

    Everything about it is well-formed: real stanzas, a real payload, a tag
    that verifies. What it does not have is anything tying the two stanzas to
    one file key -- so it is refused on the flags, before any of that is
    reached. The library cannot produce this container at all; it was built
    by hand for the vector.
    """
    vector = COMMITTED["uncommitted"]
    blob = bytes.fromhex(vector["container"])

    assert int.from_bytes(blob[6:8], "big") == FLAG_RECIPIENTS
    with pytest.raises(FormatError, match="commitment and a recipient list go together"):
        parse_header(blob)
    for identity in committed_identities[: vector["recipients"]]:
        with pytest.raises(FormatError):
            decrypt(blob, identity)


def test_a_recorded_forwarded_committed_list_still_does_not_verify(
    committed_identities, committed_signer
) -> None:
    vector = COMMITTED["forwarded"]
    blob = bytes.fromhex(vector["container"])
    identity = committed_identities[vector["opens_for"]]

    with pytest.raises(SignatureError):
        open_container(blob, identity, committed_signer)
    with pytest.raises(SignatureError):
        open_container(blob, identity)


def test_the_forwarded_committed_vector_is_a_real_container(
    committed_identities,
) -> None:
    """So the test above cannot pass because the file is merely broken."""
    vector = COMMITTED["forwarded"]
    blob = bytes.fromhex(vector["container"])
    identity = committed_identities[vector["opens_for"]]

    header, header_bytes, ciphertext = parse_header(blob)
    assert header.multi and header.committed and header.signed
    _, key = container_module._open_setup(header, identity)
    payload = header.suite.aead(key).decrypt(header.nonce, ciphertext, header_bytes)
    assert payload.endswith(bytes.fromhex(vector["plaintext"]))


# --------------------------------------------------------------------------
# Recipient lists written before the commitment was required
# --------------------------------------------------------------------------

#: Every recorded container from before flag bit 3 existed. They keep their
#: bytes; what they prove is now the refusal.
BEFORE_COMMITMENTS = [
    (name, entry)
    for name, data in (
        ("v1-recipients", RECIPIENTS),
        ("v1-signed-recipients", SIGNED_RECIPIENTS),
        ("v1-mlkem1024", MLKEM1024),
        ("v1-signed-stream", SIGNED_STREAM),
    )
    for entry in (
        listed(data["containers"])
        + [data[k] for k in ("chunked_container", "forwarded") if k in data]
    )
    if is_listed(entry["container"])
]


def test_the_old_vectors_really_do_contain_recipient_lists() -> None:
    """Guard against the list above silently becoming empty.

    A refusal test over nothing passes forever, and the classification is done
    by reading a flags field out of hex -- exactly the kind of thing that turns
    into `[]` after an unrelated edit.
    """
    assert len(BEFORE_COMMITMENTS) == 21
    assert len({name for name, _ in BEFORE_COMMITMENTS}) == 4


@pytest.mark.parametrize(
    "name,entry",
    BEFORE_COMMITMENTS,
    ids=[f"{name}-{i}" for i, (name, _) in enumerate(BEFORE_COMMITMENTS)],
)
def test_a_recipient_list_without_a_commitment_is_refused(name, entry) -> None:
    """These opened when they were recorded, and must not open now.

    Three commits' worth of frozen containers stopped being readable when the
    file key commitment became mandatory, and that is the correct outcome:
    nothing in them stops the sender who wrote them handing two recipients two
    different messages. They are kept exactly as they are rather than
    regenerated, because a frozen vector that gets edited when the format
    changes is not freezing anything. What they pin now is that the refusal
    happens, and that it says why.
    """
    blob = bytes.fromhex(entry["container"])
    with pytest.raises(FormatError, match="cannot be opened"):
        parse_header(blob)
