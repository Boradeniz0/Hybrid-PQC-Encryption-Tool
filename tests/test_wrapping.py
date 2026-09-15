"""Passphrase-wrapped private keys: scrypt to a key, AEAD around the secret.

The tests that matter here are not the round trips:

  * a key file may claim any scrypt parameters it likes, so reading one must not
    be a way to make the machine allocate 137 GB;
  * every KDF parameter is inside the associated data, so none of them can be
    rewritten downwards by someone who has the file;
  * the same passphrase typed on two systems can arrive as different bytes
    unless it is normalised.

Every test uses a low cost setting. The defaults are ~128 MiB and a third of a
second by design; running that a few dozen times would make the suite slow for
no coverage, and the parameters travelling in the file is exactly what makes
turning them down safe.
"""

from __future__ import annotations

import unicodedata

import pytest

from hpqc import wrapping
from hpqc.armour import armour
from hpqc.errors import FormatError, PassphraseError
from hpqc.keys import PrivateKey, SigningPrivateKey
from hpqc.wrapping import (
    AEAD_CHACHA20_POLY1305,
    KDF_SCRYPT,
    KIND_IDENTITY,
    KIND_SIGNING_IDENTITY,
    WRAP_VERSION,
    WRAPPED_PREFIX,
    Params,
    Wrapped,
)

FAST = Params(log_n=12)
PASSPHRASE = "correct horse battery staple"

# Offsets into the wrapped-key header, mirroring the table in wrapping.py.
OFF_VERSION = 0
OFF_KIND = 1
OFF_KDF = 2
OFF_LOG_N = 3
OFF_R = 4
OFF_P = 5
OFF_AEAD = 6
OFF_SALT = 7
OFF_NONCE = 23
OFF_SEALED_LEN = 35
OFF_SEALED = 37


def rewrap(blob: bytes) -> str:
    """Armour a hand-built wrapped-key blob, bypassing wrap()'s checks."""
    return armour(WRAPPED_PREFIX, blob, ["hand-built for a test"])


def wrapped_blob(**overrides) -> bytes:
    """A structurally valid wrapped blob whose fields can be overridden."""
    fields = dict(
        kind=KIND_IDENTITY,
        params=FAST,
        salt=bytes(wrapping.SALT_LEN),
        nonce=bytes(wrapping.NONCE_LEN),
        sealed=bytes(97 + 16),
    )
    fields.update(overrides)
    return Wrapped(**fields).to_bytes()


class TestParams:
    def test_n_and_memory_follow_log_n(self) -> None:
        params = Params(log_n=15, r=8, p=1)
        assert params.n == 32768
        assert params.memory_bytes == 128 * 32768 * 8  # 32 MiB

    def test_the_defaults_are_accepted(self) -> None:
        Params().validate()

    def test_the_default_is_a_deliberate_cost(self) -> None:
        """Guards against someone lowering it without meaning to."""
        assert Params().memory_bytes == 128 * 2**20  # 128 MiB
        assert wrapping.DEFAULT_LOG_N == 17

    @pytest.mark.parametrize(
        "params, expected",
        [
            (Params(log_n=0), "log2\\(N\\)"),
            (Params(log_n=99), "log2\\(N\\)"),
            (Params(r=0), "r must be at least 1"),
            (Params(p=0), "p is 0"),
            (Params(p=17), "p is 17"),
            (Params(log_n=24), "log2\\(N\\)"),
            (Params(log_n=23), "over the"),
            (Params(log_n=20, r=64), "over the"),
        ],
    )
    def test_bad_parameters_are_refused(self, params, expected) -> None:
        with pytest.raises(FormatError, match=expected):
            params.validate()

    def test_the_memory_ceiling_is_below_what_a_machine_would_notice(self) -> None:
        assert wrapping.MAX_MEMORY_BYTES <= 1 << 30


class TestHostileParameters:
    """A key file is untrusted input; its cost parameters especially so."""

    def test_an_expensive_n_is_refused_rather_than_allocated(self) -> None:
        """N=2^23 at r=8 asks for 8 GiB. This must be an error, not an attempt.

        If this test ever hangs or gets OOM-killed instead of failing, the
        validation moved to after the KDF call.
        """
        text = rewrap(wrapped_blob(params=Params(log_n=23)))

        with pytest.raises(FormatError, match="refusing rather than trying"):
            wrapping.unwrap(text, PASSPHRASE)

    def test_an_out_of_range_n_is_refused_as_malformed(self) -> None:
        """Above what could ever be legal, so the message names the range."""
        text = rewrap(wrapped_blob(params=Params(log_n=200)))

        with pytest.raises(FormatError, match="supported range"):
            wrapping.unwrap(text, PASSPHRASE)

    def test_an_absurd_r_is_refused_too(self) -> None:
        text = rewrap(wrapped_blob(params=Params(log_n=20, r=255)))

        with pytest.raises(FormatError, match="of memory"):
            wrapping.unwrap(text, PASSPHRASE)

    def test_parsing_alone_refuses_them(self) -> None:
        """`hpqc info` parses without a passphrase; it must be safe too."""
        text = rewrap(wrapped_blob(params=Params(log_n=23)))

        with pytest.raises(FormatError):
            wrapping.parse(text)


class TestRoundTrip:
    @pytest.mark.parametrize(
        "kind", [KIND_IDENTITY, KIND_SIGNING_IDENTITY], ids=["identity", "signing"]
    )
    def test_wrap_then_unwrap(self, kind) -> None:
        secret = bytes(range(64))
        text = wrapping.wrap(secret, kind, PASSPHRASE, FAST)
        blob, recovered_kind = wrapping.unwrap(text, PASSPHRASE)

        assert blob == secret
        assert recovered_kind == kind

    def test_the_secret_is_not_in_the_file(self) -> None:
        secret = b"CANARY" * 8
        text = wrapping.wrap(secret, KIND_IDENTITY, PASSPHRASE, FAST)

        assert secret not in text.encode("ascii")
        assert "CANARY" not in text

    def test_two_wraps_of_one_secret_differ(self) -> None:
        """Fresh salt and nonce every time."""
        secret = bytes(32)
        first = wrapping.wrap(secret, KIND_IDENTITY, PASSPHRASE, FAST)
        second = wrapping.wrap(secret, KIND_IDENTITY, PASSPHRASE, FAST)

        assert first != second
        assert wrapping.unwrap(first, PASSPHRASE)[0] == secret
        assert wrapping.unwrap(second, PASSPHRASE)[0] == secret

    def test_the_parameters_survive_the_round_trip(self) -> None:
        params = Params(log_n=13, r=4, p=2)
        text = wrapping.wrap(bytes(32), KIND_IDENTITY, PASSPHRASE, params)

        assert wrapping.parse(text).params == params

    def test_a_low_cost_key_still_opens(self) -> None:
        """The parameters are in the file, so any valid setting is readable."""
        text = wrapping.wrap(bytes(32), KIND_IDENTITY, PASSPHRASE, Params(log_n=1))
        assert wrapping.unwrap(text, PASSPHRASE)[0] == bytes(32)


class TestPassphrases:
    def test_the_wrong_passphrase_is_refused(self) -> None:
        text = wrapping.wrap(bytes(32), KIND_IDENTITY, PASSPHRASE, FAST)

        with pytest.raises(PassphraseError, match="wrong passphrase"):
            wrapping.unwrap(text, "not the passphrase")

    def test_an_empty_passphrase_is_refused_at_wrap_time(self) -> None:
        """A file that looks protected and is not is worse than an error."""
        with pytest.raises(PassphraseError, match="empty passphrase"):
            wrapping.wrap(bytes(32), KIND_IDENTITY, "", FAST)

    def test_normalisation_makes_the_same_passphrase_work(self) -> None:
        """"é" is one code point or two depending on where it was typed.

        Without NFC normalisation a key wrapped on one system simply would not
        open on another, with nothing to suggest why.
        """
        composed = unicodedata.normalize("NFC", "café passphrase")
        decomposed = unicodedata.normalize("NFD", "café passphrase")
        assert composed != decomposed  # different bytes, same passphrase

        text = wrapping.wrap(bytes(32), KIND_IDENTITY, decomposed, FAST)
        assert wrapping.unwrap(text, composed)[0] == bytes(32)

    def test_a_genuinely_different_passphrase_still_fails(self) -> None:
        """Normalisation must not make everything equal."""
        text = wrapping.wrap(bytes(32), KIND_IDENTITY, "café", FAST)

        with pytest.raises(PassphraseError):
            wrapping.unwrap(text, "cafe")

    def test_bytes_passphrases_are_taken_as_given(self) -> None:
        text = wrapping.wrap(bytes(32), KIND_IDENTITY, b"\xff\xfe raw", FAST)
        assert wrapping.unwrap(text, b"\xff\xfe raw")[0] == bytes(32)


class TestHeaderIsAssociatedData:
    """Nothing in the header is malleable.

    Two mechanisms, worth keeping straight. The scrypt parameters and the salt
    also feed the derivation, so changing them yields a different key and the tag
    fails whether or not they are authenticated. The fields the AAD alone
    protects are the ones that do not -- the kind byte, the version, the
    algorithm ids, the sealed length -- and relabelling the kind is the case
    that isolates it.
    """

    @pytest.mark.parametrize(
        "offset, field",
        [
            (OFF_LOG_N, "scrypt log2(N)"),
            (OFF_R, "scrypt r"),
            (OFF_SALT, "salt"),
            (OFF_SALT + 15, "end of the salt"),
            (OFF_NONCE, "nonce"),
            (OFF_SEALED, "sealed blob"),
            (OFF_SEALED + 96, "last plaintext byte"),
        ],
    )
    def test_flipping_a_bit_makes_the_key_unopenable(self, offset, field) -> None:
        text = wrapping.wrap(bytes(97), KIND_IDENTITY, PASSPHRASE, FAST)
        blob = bytearray(wrapping.parse(text).to_bytes())
        blob[offset] ^= 0x01

        with pytest.raises(PassphraseError):
            wrapping.unwrap(rewrap(bytes(blob)), PASSPHRASE)

    def test_downgrading_the_cost_does_not_yield_a_readable_key(self) -> None:
        """The interesting case: rewrite log2(N) to 1 and hand the file back.

        The parameters are authenticated, so this cannot be used to make a
        victim's own tooling re-derive under weaker settings.
        """
        text = wrapping.wrap(bytes(97), KIND_IDENTITY, PASSPHRASE, Params(log_n=13))
        wrapped = wrapping.parse(text)
        weakened = Wrapped(
            kind=wrapped.kind,
            params=Params(log_n=1),
            salt=wrapped.salt,
            nonce=wrapped.nonce,
            sealed=wrapped.sealed,
        )

        with pytest.raises(PassphraseError):
            wrapping.unwrap(rewrap(weakened.to_bytes()), PASSPHRASE)

    def test_changing_the_kind_byte_is_caught(self) -> None:
        """The field that only the AAD protects: it never reaches the KDF."""
        text = wrapping.wrap(bytes(97), KIND_IDENTITY, PASSPHRASE, FAST)
        wrapped = wrapping.parse(text)
        relabelled = Wrapped(
            kind=KIND_SIGNING_IDENTITY,
            params=wrapped.params,
            salt=wrapped.salt,
            nonce=wrapped.nonce,
            sealed=wrapped.sealed,
        )

        with pytest.raises(PassphraseError):
            wrapping.unwrap(rewrap(relabelled.to_bytes()), PASSPHRASE)


class TestMalformedFiles:
    @pytest.mark.parametrize(
        "keep", [0, 1, OFF_SALT, OFF_NONCE, OFF_SEALED_LEN, OFF_SEALED, OFF_SEALED + 50]
    )
    def test_a_truncated_file_never_reads_past_the_end(self, keep) -> None:
        text = wrapping.wrap(bytes(97), KIND_IDENTITY, PASSPHRASE, FAST)
        blob = wrapping.parse(text).to_bytes()[:keep]

        with pytest.raises(FormatError, match="truncated wrapped key|sealed blob"):
            wrapping.unwrap(rewrap(blob), PASSPHRASE)

    def test_trailing_bytes_are_refused(self) -> None:
        """Silently ignoring them would leave a place to hide data."""
        text = wrapping.wrap(bytes(97), KIND_IDENTITY, PASSPHRASE, FAST)
        blob = wrapping.parse(text).to_bytes() + b"\x00"

        with pytest.raises(FormatError, match="trailing bytes"):
            wrapping.unwrap(rewrap(blob), PASSPHRASE)

    def test_a_lying_sealed_length_is_refused(self) -> None:
        text = wrapping.wrap(bytes(97), KIND_IDENTITY, PASSPHRASE, FAST)
        blob = bytearray(wrapping.parse(text).to_bytes())
        blob[OFF_SEALED_LEN + 1] = 0xFF

        with pytest.raises(FormatError, match="sealed blob"):
            wrapping.unwrap(rewrap(bytes(blob)), PASSPHRASE)

    @pytest.mark.parametrize(
        "offset, value, expected",
        [
            (OFF_VERSION, 99, "version 99 is not supported"),
            (OFF_KDF, 7, "key derivation function id 7"),
            (OFF_AEAD, 7, "AEAD id 7"),
            (OFF_KIND, 99, "unknown wrapped key kind 99"),
        ],
    )
    def test_unknown_identifiers_are_refused_by_name(
        self, offset, value, expected
    ) -> None:
        blob = bytearray(wrapped_blob())
        blob[offset] = value

        with pytest.raises(FormatError, match=expected):
            wrapping.parse(rewrap(bytes(blob)))

    def test_the_recorded_identifiers_are_the_ones_we_write(self) -> None:
        """Catches a renumbering that would strand every existing key file."""
        blob = wrapped_blob()
        assert blob[OFF_VERSION] == WRAP_VERSION == 1
        assert blob[OFF_KDF] == KDF_SCRYPT == 1
        assert blob[OFF_AEAD] == AEAD_CHACHA20_POLY1305 == 1

    def test_wrapping_an_unknown_kind_is_refused(self) -> None:
        with pytest.raises(FormatError, match="unknown key kind"):
            wrapping.wrap(bytes(32), 99, PASSPHRASE, FAST)


class TestDetection:
    def test_a_wrapped_file_is_recognised(self) -> None:
        text = wrapping.wrap(bytes(32), KIND_IDENTITY, PASSPHRASE, FAST)
        assert wrapping.is_wrapped(text) is True

    @pytest.mark.parametrize(
        "text",
        ["", "# comment only\n", "garbage\n", "hpqc-sk1AAAA\n", "hpqc-pk1AAAA\n"],
        ids=["empty", "comment-only", "garbage", "plain-private", "public"],
    )
    def test_other_files_are_not(self, text) -> None:
        assert wrapping.is_wrapped(text) is False

    def test_the_prefix_is_not_confusable_with_the_others(self) -> None:
        from hpqc.keys import (
            PRIVATE_PREFIX,
            PUBLIC_PREFIX,
            SIGN_PRIVATE_PREFIX,
            SIGN_PUBLIC_PREFIX,
        )

        others = [
            PUBLIC_PREFIX,
            PRIVATE_PREFIX,
            SIGN_PUBLIC_PREFIX,
            SIGN_PRIVATE_PREFIX,
        ]
        for other in others:
            assert other not in WRAPPED_PREFIX
            assert WRAPPED_PREFIX not in other

    def test_describe_needs_no_passphrase(self) -> None:
        text = wrapping.wrap(bytes(32), KIND_SIGNING_IDENTITY, PASSPHRASE, FAST)
        described = wrapping.parse(text).describe()

        assert "signing private key" in described
        assert "scrypt N=2^12" in described

    def test_it_does_not_name_algorithms_it_cannot_see(self) -> None:
        """The kind byte says encryption or signing, and that is all it says.

        An encryption identity is X25519+ML-KEM-768 or X448+ML-KEM-1024, and
        which one is the first byte *inside* the sealed blob. Naming one of
        them here labelled every passphrase-protected ML-KEM-1024 key as
        ML-KEM-768 -- a confident wrong answer, where this file already knows
        how to say "unavailable without the passphrase".
        """
        described = wrapping.parse(
            wrapping.wrap(bytes(32), KIND_IDENTITY, PASSPHRASE, FAST)
        ).describe()

        assert "encryption private key" in described
        for guess in ("X25519", "X448", "ML-KEM-768", "ML-KEM-1024"):
            assert guess not in described


class TestKeyIntegration:
    """The same behaviour through PrivateKey / SigningPrivateKey."""

    @pytest.mark.parametrize(
        "cls", [PrivateKey, SigningPrivateKey], ids=["identity", "signing"]
    )
    def test_round_trip_through_the_key_classes(self, cls) -> None:
        key = cls.generate()
        text = key.encode(PASSPHRASE, FAST)

        assert cls.decode(text, PASSPHRASE) == key

    @pytest.mark.parametrize(
        "cls", [PrivateKey, SigningPrivateKey], ids=["identity", "signing"]
    )
    def test_wrapping_does_not_change_the_key_id(self, cls) -> None:
        """The whole point of `hpqc passwd`: storage changes, identity does not."""
        key = cls.generate()
        reopened = cls.decode(key.encode(PASSPHRASE, FAST), PASSPHRASE)

        assert reopened.public_key() == key.public_key()

    def test_a_wrapped_key_without_a_passphrase_says_so(self) -> None:
        text = PrivateKey.generate().encode(PASSPHRASE, FAST)

        with pytest.raises(PassphraseError, match="passphrase-protected"):
            PrivateKey.decode(text)

    def test_a_passphrase_for_an_unwrapped_key_is_an_error(self) -> None:
        """Not a no-op: the caller believes the file is protected and it is not."""
        text = PrivateKey.generate().encode()

        with pytest.raises(PassphraseError, match="not passphrase-protected"):
            PrivateKey.decode(text, PASSPHRASE)

    def test_an_identity_is_not_accepted_as_a_signing_key(self) -> None:
        text = PrivateKey.generate().encode(PASSPHRASE, FAST)

        with pytest.raises(FormatError, match="signing private key was expected"):
            SigningPrivateKey.decode(text, PASSPHRASE)

    def test_the_kind_check_happens_before_the_kdf(self, monkeypatch) -> None:
        """A wrong-file mistake should be instant, not a third of a second.

        Asserted by making the KDF fail loudly if it is reached at all, rather
        than by timing it: the point is that the answer does not depend on the
        derivation, and a stopwatch would only say it was fast today.
        """
        text = PrivateKey.generate().encode(PASSPHRASE, FAST)

        def explode(*args, **kwargs):
            raise AssertionError("the KDF ran before the key kind was checked")

        monkeypatch.setattr(wrapping, "_derive", explode)

        with pytest.raises(FormatError, match="signing private key was expected"):
            SigningPrivateKey.decode(text, PASSPHRASE)

    def test_a_wrapped_key_file_is_not_world_readable(self, tmp_path) -> None:
        path = tmp_path / "wrapped.key"
        PrivateKey.generate().write(path, PASSPHRASE, FAST)

        assert oct(path.stat().st_mode)[-3:] == "600"

    def test_writing_over_a_world_readable_file_still_ends_up_private(
        self, tmp_path
    ) -> None:
        path = tmp_path / "wrapped.key"
        path.write_text("placeholder")
        path.chmod(0o644)

        PrivateKey.generate().write(path, PASSPHRASE, FAST)
        assert oct(path.stat().st_mode)[-3:] == "600"

    def test_writing_leaves_no_temporary_file_behind(self, tmp_path) -> None:
        """Key writes go through a temp file and a rename; it must be cleaned up."""
        path = tmp_path / "wrapped.key"
        PrivateKey.generate().write(path, PASSPHRASE, FAST)

        assert [entry.name for entry in tmp_path.iterdir()] == ["wrapped.key"]
