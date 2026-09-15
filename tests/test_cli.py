"""End-to-end CLI behaviour, driven through click's test runner."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from hpqc.cli import ONE_SHOT_LIMIT, cli
from hpqc import streaming, wrapping
from hpqc.container import parse_header
from hpqc.errors import HpqcError
from hpqc.keys import PrivateKey, PublicKey, SigningPrivateKey, SigningPublicKey


def separated_runner() -> CliRunner:
    """A runner that keeps stderr out of stdout, on every click version.

    click 8.2 always separates the two. Before that -- and Python 3.9 pins
    click to 8.1, so this is not hypothetical -- the default folded stderr into
    stdout and `result.stderr` raised outright. Separating everywhere means the
    pipe tests check what they claim to check: that a status line never lands
    in the plaintext.
    """
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:  # click >= 8.2, where it is the only behaviour
        return CliRunner()


def shown(result) -> str:
    """Everything the user would see, from both streams.

    `result.output` is not portable: on click 8.1 with the streams separated it
    is stdout alone, and on 8.2+ it is the two interleaved. Assertions that
    only care whether a message appeared use this instead.
    """
    return result.stdout + result.stderr


@pytest.fixture
def runner() -> CliRunner:
    return separated_runner()


def run(runner: CliRunner, *args: str, stdin: bytes = b"") -> "object":
    return runner.invoke(cli, list(args), input=stdin, catch_exceptions=False)




@pytest.fixture
def workspace(runner: CliRunner, tmp_path: Path, monkeypatch):
    """A temp cwd with alice's key pair already generated."""
    monkeypatch.chdir(tmp_path)
    result = run(runner, "keygen", "-o", "alice")
    assert result.exit_code == 0, shown(result)
    return tmp_path


def test_keygen_writes_both_files_and_prints_the_key_id(workspace, runner) -> None:
    private_path = workspace / "alice.key"
    public_path = workspace / "alice.pub"

    assert private_path.exists() and public_path.exists()

    identity = PrivateKey.read(private_path)
    public = PublicKey.read(public_path)
    assert identity.public_key() == public

    result = run(runner, "info", str(public_path))
    assert public.key_id_hex in shown(result)


def test_keygen_refuses_to_clobber_an_existing_key(workspace, runner) -> None:
    result = runner.invoke(cli, ["keygen", "-o", "alice"])

    assert result.exit_code != 0
    assert "already exists" in shown(result)
    assert "--force" in shown(result)


def test_keygen_force_overwrites(workspace, runner) -> None:
    before = (workspace / "alice.key").read_text()
    result = run(runner, "keygen", "-o", "alice", "--force")

    assert result.exit_code == 0
    assert (workspace / "alice.key").read_text() != before


def test_encrypt_then_decrypt_restores_the_file(workspace, runner) -> None:
    plaintext = b"\x00\x01\x02 binary \xff\xfe payload"
    (workspace / "secret.bin").write_bytes(plaintext)

    assert run(runner, "encrypt", "-r", "alice.pub", "secret.bin", "-o", "secret.hpqc").exit_code == 0
    assert run(runner, "decrypt", "-k", "alice.key", "secret.hpqc", "-o", "out.bin").exit_code == 0

    assert (workspace / "out.bin").read_bytes() == plaintext
    assert (workspace / "secret.hpqc").read_bytes() != plaintext


@pytest.mark.parametrize("aead", ["chacha20", "aes"])
def test_both_aead_choices_round_trip(workspace, runner, aead) -> None:
    (workspace / "in.txt").write_bytes(b"hello")

    run(runner, "encrypt", "--aead", aead, "-r", "alice.pub", "in.txt", "-o", "c.hpqc")
    run(runner, "decrypt", "-k", "alice.key", "c.hpqc", "-o", "out.txt")

    assert (workspace / "out.txt").read_bytes() == b"hello"


def test_stdin_and_stdout_are_the_defaults(workspace, runner) -> None:
    encrypted = run(runner, "encrypt", "-r", "alice.pub", stdin=b"piped secret")
    assert encrypted.exit_code == 0

    decrypted = run(
        runner, "decrypt", "-k", "alice.key", stdin=encrypted.stdout_bytes
    )
    assert decrypted.stdout_bytes == b"piped secret"


def test_decrypting_with_the_wrong_key_fails_clearly(workspace, runner) -> None:
    run(runner, "keygen", "-o", "bob")
    (workspace / "in.txt").write_bytes(b"for alice only")
    run(runner, "encrypt", "-r", "alice.pub", "in.txt", "-o", "c.hpqc")

    result = runner.invoke(cli, ["decrypt", "-k", "bob.key", "c.hpqc", "-o", "out.txt"])

    assert result.exit_code != 0
    assert "encrypted for key id" in str(result.exception)
    assert not (workspace / "out.txt").exists()


def test_a_tampered_file_fails_and_writes_nothing(workspace, runner) -> None:
    (workspace / "in.txt").write_bytes(b"important")
    run(runner, "encrypt", "-r", "alice.pub", "in.txt", "-o", "c.hpqc")

    blob = bytearray((workspace / "c.hpqc").read_bytes())
    blob[-1] ^= 0x01
    (workspace / "c.hpqc").write_bytes(bytes(blob))

    result = runner.invoke(cli, ["decrypt", "-k", "alice.key", "c.hpqc", "-o", "out.txt"])

    assert result.exit_code != 0
    assert "authentication failed" in str(result.exception)
    assert not (workspace / "out.txt").exists()


def test_info_describes_a_container_without_the_private_key(workspace, runner) -> None:
    (workspace / "in.txt").write_bytes(b"x" * 100)
    run(runner, "encrypt", "-r", "alice.pub", "in.txt", "-o", "c.hpqc")

    result = run(runner, "info", "c.hpqc")

    assert result.exit_code == 0
    assert "hpqc container" in shown(result)
    assert "ML-KEM-768" in shown(result)
    assert PublicKey.read(workspace / "alice.pub").key_id_hex in shown(result)


def test_info_recognises_key_files(workspace, runner) -> None:
    assert "public key" in shown(run(runner, "info", "alice.pub"))
    assert "private key" in shown(run(runner, "info", "alice.key"))


def test_info_rejects_unrelated_input(workspace, runner) -> None:
    (workspace / "junk.bin").write_bytes(b"\x7fELF\x02\x01\x01\x00")

    result = runner.invoke(cli, ["info", "junk.bin"])

    assert result.exit_code != 0
    assert "unrecognised input" in shown(result)


def test_a_missing_recipient_file_is_reported_by_click(workspace, runner) -> None:
    result = runner.invoke(cli, ["encrypt", "-r", "nope.pub", "-o", "c.hpqc"], input=b"x")

    assert result.exit_code != 0
    assert "nope.pub" in shown(result)


def test_encrypting_to_a_private_key_file_is_refused(workspace, runner) -> None:
    """A slipped -r alice.key must not silently produce an unopenable file."""
    result = runner.invoke(cli, ["encrypt", "-r", "alice.key", "-o", "c.hpqc"], input=b"x")

    assert result.exit_code != 0
    assert not (workspace / "c.hpqc").exists()


def test_help_lists_every_command(runner) -> None:
    output = shown(run(runner, "--help"))

    for command in ("keygen", "signgen", "encrypt", "decrypt", "info"):
        assert command in output


# --------------------------------------------------------------------------
# Sender authentication
# --------------------------------------------------------------------------


@pytest.fixture
def signed_workspace(workspace, runner):
    """alice's identity plus two signing identities, carol's and eve's."""
    for name in ("carol", "eve"):
        result = run(runner, "signgen", "-o", f"{name}-sign")
        assert result.exit_code == 0, shown(result)
    return workspace


def test_signgen_writes_both_files(signed_workspace, runner) -> None:
    private_path = signed_workspace / "carol-sign.key"
    public_path = signed_workspace / "carol-sign.pub"

    assert private_path.exists() and public_path.exists()
    assert oct(private_path.stat().st_mode)[-3:] == "600"

    sender = SigningPrivateKey.read(private_path)
    assert sender.public_key() == SigningPublicKey.read(public_path)


def test_signgen_refuses_to_clobber_an_existing_key(signed_workspace, runner) -> None:
    result = run(runner, "signgen", "-o", "carol-sign")

    assert result.exit_code != 0
    assert "already exists" in shown(result)


def test_sign_then_verify_round_trip(signed_workspace, runner) -> None:
    (signed_workspace / "m.txt").write_bytes(b"pay 100")

    result = run(
        runner, "encrypt", "-r", "alice.pub", "m.txt",
        "-o", "m.hpqc", "-s", "carol-sign.key",
    )
    assert result.exit_code == 0, shown(result)

    result = run(
        runner, "decrypt", "-k", "alice.key", "m.hpqc",
        "-o", "out.txt", "--sender", "carol-sign.pub",
    )
    assert result.exit_code == 0, shown(result)
    assert (signed_workspace / "out.txt").read_bytes() == b"pay 100"
    assert "signature ok" in result.stderr


def test_decrypting_a_signed_file_without_a_sender_key_warns(
    signed_workspace, runner
) -> None:
    run(
        runner, "encrypt", "-r", "alice.pub", "-o", "m.hpqc",
        "-s", "carol-sign.key", stdin=b"hello",
    )
    result = run(runner, "decrypt", "-k", "alice.key", "m.hpqc", "-o", "out.txt")

    assert result.exit_code == 0, shown(result)
    assert (signed_workspace / "out.txt").read_bytes() == b"hello"
    assert "warning" in result.stderr
    assert "pass --sender" in result.stderr


def test_the_signature_notice_never_lands_on_stdout(signed_workspace, runner) -> None:
    """`hpqc decrypt file > out` must not have a status line mixed into it.

    stdout is the plaintext. Anything chatty belongs on stderr, or piping the
    tool silently corrupts what it writes.
    """
    run(
        runner, "encrypt", "-r", "alice.pub", "-o", "m.hpqc",
        "-s", "carol-sign.key", stdin=b"exact bytes",
    )
    result = run(
        runner, "decrypt", "-k", "alice.key", "m.hpqc",
        "--sender", "carol-sign.pub",
    )

    assert result.exit_code == 0, shown(result)
    assert result.stdout_bytes == b"exact bytes"


def test_verifying_against_the_wrong_sender_fails_and_writes_nothing(
    signed_workspace, runner
) -> None:
    run(
        runner, "encrypt", "-r", "alice.pub", "-o", "m.hpqc",
        "-s", "carol-sign.key", stdin=b"hello",
    )
    result = runner.invoke(
        cli,
        ["decrypt", "-k", "alice.key", "m.hpqc", "-o", "out.txt",
         "--sender", "eve-sign.pub"],
    )

    assert result.exit_code != 0
    assert "was signed by key id" in str(result.exception)
    assert not (signed_workspace / "out.txt").exists()


def test_verifying_an_unsigned_file_fails_closed(signed_workspace, runner) -> None:
    run(runner, "encrypt", "-r", "alice.pub", "-o", "m.hpqc", stdin=b"hello")
    result = runner.invoke(
        cli,
        ["decrypt", "-k", "alice.key", "m.hpqc", "-o", "out.txt",
         "--sender", "carol-sign.pub"],
    )

    assert result.exit_code != 0
    assert "not signed" in str(result.exception)
    assert not (signed_workspace / "out.txt").exists()


def test_info_reports_whether_a_file_is_signed(signed_workspace, runner) -> None:
    run(
        runner, "encrypt", "-r", "alice.pub", "-o", "signed.hpqc",
        "-s", "carol-sign.key", stdin=b"x",
    )
    run(runner, "encrypt", "-r", "alice.pub", "-o", "plain.hpqc", stdin=b"x")

    assert "signed:      yes" in shown(run(runner, "info", "signed.hpqc"))
    assert "signed:      no" in shown(run(runner, "info", "plain.hpqc"))


def test_info_recognises_signing_key_files(signed_workspace, runner) -> None:
    public = shown(run(runner, "info", "carol-sign.pub"))
    private = shown(run(runner, "info", "carol-sign.key"))

    assert "signing public key" in public
    assert "signing private key" in private
    assert "Ed25519 + ML-DSA-65" in public


def test_signing_with_an_encryption_key_is_refused(signed_workspace, runner) -> None:
    """The four key kinds have distinct prefixes; the error must say so."""
    result = runner.invoke(
        cli,
        ["encrypt", "-r", "alice.pub", "-o", "m.hpqc", "-s", "alice.key"],
        input=b"x",
    )

    assert result.exit_code != 0
    assert "signing private" in str(result.exception)
    assert not (signed_workspace / "m.hpqc").exists()


# --------------------------------------------------------------------------
# Passphrase-protected private keys
# --------------------------------------------------------------------------

# Every keygen below passes a low scrypt cost. The default is ~128 MiB and a
# third of a second on purpose; paying that a few dozen times would make the
# suite slow without testing anything the parameters do not already cover.
FAST = ["--scrypt-log-n", "12"]
PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def pwfile(tmp_path: Path):
    """Write a passphrase to a file and return its name, cwd-relative."""

    def write(text: str, name: str = "pw.txt") -> str:
        (tmp_path / name).write_text(text, encoding="utf-8")
        return name

    return write


@pytest.fixture
def faketty(monkeypatch):
    """Pretend there is a terminal, so the passphrase prompt is allowed.

    `_prompt_passphrase` refuses to prompt without a tty -- reading a passphrase
    from stdin would swallow the data being encrypted. Under CliRunner stdin is
    never a tty, so exercising the prompt at all means saying otherwise. The
    check lives behind `_have_terminal` for exactly this reason: CliRunner
    substitutes its own stdin, so patching the real one has no effect.
    """
    monkeypatch.setattr("hpqc.cli._have_terminal", lambda: True)


@pytest.fixture
def protected(workspace, runner, pwfile):
    """A workspace whose `secret` identity is passphrase-protected."""
    pw = pwfile(PASSPHRASE)
    result = run(runner, "keygen", "-o", "secret", "--passphrase-file", pw, *FAST)
    assert result.exit_code == 0, shown(result)
    return workspace


def test_keygen_can_protect_the_private_key(protected, runner) -> None:
    text = (protected / "secret.key").read_text()

    assert wrapping.is_wrapped(text)
    assert oct((protected / "secret.key").stat().st_mode)[-3:] == "600"
    # The public half is not a secret and is never wrapped.
    assert not wrapping.is_wrapped((protected / "secret.pub").read_text())


def test_info_describes_a_wrapped_key_without_the_passphrase(protected, runner) -> None:
    output = shown(run(runner, "info", "secret.key"))

    assert "wrapped private key" in output
    assert "X25519 + ML-KEM-768" in output
    assert "scrypt N=2^12" in output
    assert "unavailable without the passphrase" in output


def test_a_protected_key_round_trips(protected, runner, pwfile) -> None:
    (protected / "m.txt").write_bytes(b"under a passphrase")
    run(runner, "encrypt", "-r", "secret.pub", "m.txt", "-o", "m.hpqc")
    result = run(
        runner, "decrypt", "-k", "secret.key", "m.hpqc", "-o", "out.txt",
        "--passphrase-file", pwfile(PASSPHRASE),
    )

    assert result.exit_code == 0, shown(result)
    assert (protected / "out.txt").read_bytes() == b"under a passphrase"


def test_the_wrong_passphrase_fails_and_writes_nothing(
    protected, runner, pwfile
) -> None:
    run(runner, "encrypt", "-r", "secret.pub", "-o", "m.hpqc", stdin=b"x")
    result = runner.invoke(
        cli,
        ["decrypt", "-k", "secret.key", "m.hpqc", "-o", "out.txt",
         "--passphrase-file", pwfile("not it", "bad.txt")],
    )

    assert result.exit_code != 0
    assert "wrong passphrase" in str(result.exception)
    assert not (protected / "out.txt").exists()


def test_without_a_terminal_the_missing_passphrase_is_explained(
    protected, runner
) -> None:
    """The alternative is reading it from stdin and eating the ciphertext."""
    run(runner, "encrypt", "-r", "secret.pub", "-o", "m.hpqc", stdin=b"x")
    result = run(runner, "decrypt", "-k", "secret.key", "m.hpqc", "-o", "out.txt")

    assert result.exit_code != 0
    assert "no terminal" in shown(result)
    assert "--passphrase-file" in shown(result)


def test_the_passphrase_can_be_typed_at_a_prompt(
    workspace, runner, faketty
) -> None:
    result = run(
        runner, "keygen", "-o", "typed", "-p", *FAST,
        stdin=f"{PASSPHRASE}\n{PASSPHRASE}\n".encode(),
    )
    assert result.exit_code == 0, shown(result)
    assert wrapping.is_wrapped((workspace / "typed.key").read_text())

    run(runner, "encrypt", "-r", "typed.pub", "-o", "m.hpqc", stdin=b"typed")
    result = run(
        runner, "decrypt", "-k", "typed.key", "m.hpqc", "-o", "out.txt",
        stdin=f"{PASSPHRASE}\n".encode(),
    )
    assert result.exit_code == 0, shown(result)
    assert (workspace / "out.txt").read_bytes() == b"typed"


def test_a_mistyped_confirmation_is_not_accepted(workspace, runner, faketty) -> None:
    """A mismatch is reported and re-asked; the first value is never taken.

    The retry is supplied rather than letting the input run out, and that is
    deliberate. click 8.2 turns exhausted input into an abort, but click 8.1 --
    which is what Python 3.9 resolves, so this is not hypothetical -- hands the
    prompt an empty string instead, and an empty value does not end its retry
    loop. The version that asserted "input runs out, so the command fails" hung
    forever there, writing prompts until the process was killed. What both
    versions agree on is the part actually worth testing: the mismatch is
    refused out loud, and the key that gets written is the retyped one.
    """
    result = runner.invoke(
        cli,
        ["keygen", "-o", "typed", "-p", *FAST],
        input=f"one\ntwo\n{PASSPHRASE}\n{PASSPHRASE}\n".encode(),
    )

    assert result.exit_code == 0, shown(result)
    assert "do not match" in shown(result)

    text = (workspace / "typed.key").read_text()
    assert wrapping.is_wrapped(text)
    PrivateKey.decode(text, PASSPHRASE)  # the retyped one, not "one"
    for rejected in ("one", "two"):
        with pytest.raises(HpqcError):
            PrivateKey.decode(text, rejected)


def test_the_two_passphrase_sources_cannot_be_combined(
    workspace, runner, pwfile
) -> None:
    result = run(
        runner, "keygen", "-o", "k", "-p",
        "--passphrase-file", pwfile(PASSPHRASE), *FAST,
    )

    assert result.exit_code != 0
    assert "pick one" in shown(result)


def test_an_empty_passphrase_file_is_refused(workspace, runner, pwfile) -> None:
    result = run(
        runner, "keygen", "-o", "k", "--passphrase-file", pwfile(""), *FAST
    )

    assert result.exit_code != 0
    assert "empty" in shown(result)
    assert not (workspace / "k.key").exists()


def test_exactly_one_trailing_newline_is_stripped(workspace, runner, pwfile) -> None:
    """A passphrase may end in a space; only the line ending is removed."""
    run(
        runner, "keygen", "-o", "k",
        "--passphrase-file", pwfile("pass phrase \n", "with-space.txt"), *FAST,
    )
    run(runner, "encrypt", "-r", "k.pub", "-o", "m.hpqc", stdin=b"x")

    kept = run(
        runner, "decrypt", "-k", "k.key", "m.hpqc", "-o", "ok.txt",
        "--passphrase-file", pwfile("pass phrase ", "kept.txt"),
    )
    assert kept.exit_code == 0, shown(kept)

    trimmed = runner.invoke(
        cli,
        ["decrypt", "-k", "k.key", "m.hpqc", "-o", "no.txt",
         "--passphrase-file", pwfile("pass phrase", "trimmed.txt")],
    )
    assert trimmed.exit_code != 0


def test_a_passphrase_for_an_unprotected_key_is_an_error(
    workspace, runner, pwfile
) -> None:
    run(runner, "encrypt", "-r", "alice.pub", "-o", "m.hpqc", stdin=b"x")
    result = runner.invoke(
        cli,
        ["decrypt", "-k", "alice.key", "m.hpqc", "-o", "out.txt",
         "--passphrase-file", pwfile(PASSPHRASE)],
    )

    assert result.exit_code != 0
    assert "not passphrase-protected" in str(result.exception)


def test_a_protected_signing_key_can_still_sign(workspace, runner, pwfile) -> None:
    pw = pwfile(PASSPHRASE)
    run(runner, "signgen", "-o", "signer", "--passphrase-file", pw, *FAST)
    (workspace / "m.txt").write_bytes(b"signed under a passphrase")

    result = run(
        runner, "encrypt", "-r", "alice.pub", "m.txt", "-o", "m.hpqc",
        "-s", "signer.key", "--passphrase-file", pw,
    )
    assert result.exit_code == 0, shown(result)

    result = run(
        runner, "decrypt", "-k", "alice.key", "m.hpqc", "-o", "out.txt",
        "--sender", "signer.pub",
    )
    assert result.exit_code == 0, shown(result)
    assert (workspace / "out.txt").read_bytes() == b"signed under a passphrase"


def test_a_passphrase_file_without_a_key_to_open_is_refused(
    workspace, runner, pwfile
) -> None:
    result = run(
        runner, "encrypt", "-r", "alice.pub", "-o", "m.hpqc",
        "--passphrase-file", pwfile(PASSPHRASE), stdin=b"x",
    )

    assert result.exit_code != 0
    assert "only makes sense with --sign" in shown(result)


# --------------------------------------------------------------------------
# hpqc passwd
# --------------------------------------------------------------------------


def _key_id(output: str) -> str:
    for line in output.splitlines():
        if line.startswith("key id"):
            return line.split(":", 1)[1].strip().split()[0]
    raise AssertionError(f"no key id in {output!r}")


def test_passwd_changes_the_passphrase_without_changing_the_key(
    protected, runner, pwfile
) -> None:
    """The identity must survive: otherwise every holder of the public key
    would have to fetch a new one just because a passphrase changed."""
    before = PublicKey.read(protected / "secret.pub")
    old = pwfile(PASSPHRASE)
    new = pwfile("a different passphrase", "new.txt")

    result = run(
        runner, "passwd", "secret.key",
        "--passphrase-file", old, "--new-passphrase-file", new, *FAST,
    )
    assert result.exit_code == 0, shown(result)
    assert "passphrase changed" in shown(result)
    assert _key_id(shown(result)) == before.key_id_hex

    assert PrivateKey.read(protected / "secret.key",
                           "a different passphrase").public_key() == before

    with pytest.raises(Exception):
        PrivateKey.read(protected / "secret.key", PASSPHRASE)


def test_passwd_can_remove_the_passphrase(protected, runner, pwfile) -> None:
    result = run(
        runner, "passwd", "secret.key", "--remove",
        "--passphrase-file", pwfile(PASSPHRASE),
    )

    assert result.exit_code == 0, shown(result)
    assert "passphrase removed" in shown(result)
    assert not wrapping.is_wrapped((protected / "secret.key").read_text())
    assert PrivateKey.read(protected / "secret.key")
    assert oct((protected / "secret.key").stat().st_mode)[-3:] == "600"


def test_passwd_can_add_a_passphrase_to_an_unprotected_key(
    workspace, runner, pwfile
) -> None:
    before = PublicKey.read(workspace / "alice.pub")
    result = run(
        runner, "passwd", "alice.key",
        "--new-passphrase-file", pwfile(PASSPHRASE), *FAST,
    )

    assert result.exit_code == 0, shown(result)
    assert "passphrase added" in shown(result)
    assert wrapping.is_wrapped((workspace / "alice.key").read_text())
    assert PrivateKey.read(workspace / "alice.key", PASSPHRASE).public_key() == before


def test_passwd_works_on_signing_keys_too(workspace, runner, pwfile) -> None:
    run(runner, "signgen", "-o", "signer")
    before = SigningPublicKey.read(workspace / "signer.pub")

    result = run(
        runner, "passwd", "signer.key",
        "--new-passphrase-file", pwfile(PASSPHRASE), *FAST,
    )

    assert result.exit_code == 0, shown(result)
    assert SigningPrivateKey.read(
        workspace / "signer.key", PASSPHRASE
    ).public_key() == before


def test_passwd_refuses_to_remove_a_passphrase_that_is_not_there(
    workspace, runner
) -> None:
    result = run(runner, "passwd", "alice.key", "--remove")

    assert result.exit_code != 0
    assert "no passphrase to remove" in shown(result)


def test_passwd_rejects_contradictory_options(protected, runner, pwfile) -> None:
    result = run(
        runner, "passwd", "secret.key", "--remove",
        "--passphrase-file", pwfile(PASSPHRASE),
        "--new-passphrase-file", pwfile("x", "new.txt"),
    )

    assert result.exit_code != 0
    assert "contradict" in shown(result)


def test_passwd_refuses_a_public_key_file(workspace, runner) -> None:
    result = run(runner, "passwd", "alice.pub")

    assert result.exit_code != 0
    assert "not an hpqc private key" in shown(result)


def test_passwd_leaves_the_key_intact_when_it_fails(protected, runner, pwfile) -> None:
    """The rewrite is a temp file and a rename, so a failure loses nothing."""
    before = (protected / "secret.key").read_text()
    result = runner.invoke(
        cli,
        ["passwd", "secret.key", "--passphrase-file", pwfile("wrong", "bad.txt"),
         "--new-passphrase-file", pwfile("new", "new.txt")],
    )

    assert result.exit_code != 0
    assert (protected / "secret.key").read_text() == before
    assert [p.name for p in protected.iterdir() if p.name.startswith(".")] == []


class TestStreaming:
    """Large inputs: the format switch, and what a failed stream leaves behind."""

    def _big(self, workspace: Path, extra: int = 1) -> bytes:
        data = os.urandom(ONE_SHOT_LIMIT + extra)
        (workspace / "big.bin").write_bytes(data)
        return data

    def test_a_large_file_is_chunked_and_round_trips(self, workspace, runner) -> None:
        data = self._big(workspace)
        assert run(runner, "encrypt", "-r", "alice.pub", "big.bin", "-o", "big.hpqc").exit_code == 0
        assert run(runner, "decrypt", "-k", "alice.key", "big.hpqc", "-o", "out.bin").exit_code == 0

        assert (workspace / "out.bin").read_bytes() == data
        header, _, _ = parse_header((workspace / "big.hpqc").read_bytes())
        assert header.chunked

    def test_a_small_file_stays_one_shot(self, workspace, runner) -> None:
        """The default has to leave ordinary messages exactly as they were."""
        (workspace / "small.bin").write_bytes(b"x" * 100)
        run(runner, "encrypt", "-r", "alice.pub", "small.bin", "-o", "small.hpqc")

        header, _, _ = parse_header((workspace / "small.hpqc").read_bytes())
        assert not header.chunked

    def test_chunked_can_be_forced_on_a_small_file(self, workspace, runner) -> None:
        (workspace / "small.bin").write_bytes(b"x" * 100)
        run(runner, "encrypt", "-r", "alice.pub", "small.bin", "-o", "c.hpqc", "--chunked")

        header, _, _ = parse_header((workspace / "c.hpqc").read_bytes())
        assert header.chunked
        assert run(runner, "decrypt", "-k", "alice.key", "c.hpqc", "-o", "o.bin").exit_code == 0
        assert (workspace / "o.bin").read_bytes() == b"x" * 100

    def test_one_shot_can_be_forced_on_a_large_file(self, workspace, runner) -> None:
        data = self._big(workspace)
        run(runner, "encrypt", "-r", "alice.pub", "big.bin", "-o", "big.hpqc", "--one-shot")

        header, _, _ = parse_header((workspace / "big.hpqc").read_bytes())
        assert not header.chunked
        run(runner, "decrypt", "-k", "alice.key", "big.hpqc", "-o", "out.bin")
        assert (workspace / "out.bin").read_bytes() == data

    def test_a_large_input_streams_through_a_pipe(self, workspace, runner) -> None:
        """Both status lines go to stderr, so the pipeline carries only data."""
        data = os.urandom(ONE_SHOT_LIMIT + 1)

        sealed = run(runner, "encrypt", "-r", "alice.pub", stdin=data)
        assert sealed.exit_code == 0
        assert "streamed in" in sealed.stderr
        opened = run(runner, "decrypt", "-k", "alice.key", stdin=sealed.stdout_bytes)

        assert opened.stdout_bytes == data
        assert parse_header(sealed.stdout_bytes)[0].chunked

    def test_info_reports_the_chunking_without_the_key(self, workspace, runner) -> None:
        data = self._big(workspace)
        run(runner, "encrypt", "-r", "alice.pub", "big.bin", "-o", "big.hpqc")

        output = shown(run(runner, "info", "big.hpqc"))
        assert "chunked:     yes" in output
        assert "17 chunk(s)" in output
        assert f"plaintext:   {len(data)} bytes" in output

    def test_info_says_so_when_a_file_is_not_chunked(self, workspace, runner) -> None:
        (workspace / "small.bin").write_bytes(b"x" * 100)
        run(runner, "encrypt", "-r", "alice.pub", "small.bin", "-o", "small.hpqc")
        assert "chunked:     no" in shown(run(runner, "info", "small.hpqc"))

    def test_chunked_and_sign_work_together_on_a_file(self, workspace, runner) -> None:
        run(runner, "signgen", "-o", "signer")
        (workspace / "small.bin").write_bytes(b"x" * 100)

        result = run(
            runner, "encrypt", "-r", "alice.pub", "small.bin", "-o", "x.hpqc",
            "--chunked", "-s", "signer.key",
        )
        assert result.exit_code == 0, shown(result)

        header, _, _ = parse_header((workspace / "x.hpqc").read_bytes())
        assert header.signed and header.chunked

        result = run(runner, "decrypt", "-k", "alice.key", "x.hpqc",
                     "-o", "back.bin", "--sender", "signer.pub")
        assert result.exit_code == 0, shown(result)
        assert "signature ok" in shown(result)
        assert (workspace / "back.bin").read_bytes() == b"x" * 100

    def test_chunked_and_sign_are_refused_on_stdin(self, workspace, runner) -> None:
        """Two passes over the plaintext, and stdin only arrives once."""
        run(runner, "signgen", "-o", "signer")

        result = runner.invoke(
            cli,
            ["encrypt", "-r", "alice.pub", "-o", "x.hpqc",
             "--chunked", "-s", "signer.key"],
            input=b"x" * 100,
        )
        assert result.exit_code != 0
        assert "read twice" in shown(result)
        assert not (workspace / "x.hpqc").exists()

    def test_signing_a_large_file_now_streams(self, workspace, runner) -> None:
        """It used to fall back to one shot, because a signature needs it all.

        It still needs it all -- it just reads the file twice to get it, rather
        than holding it. The plaintext never exists as one object on either
        side, which for a signed disk image is the whole difference.
        """
        run(runner, "signgen", "-o", "signer")
        self._big(workspace)

        result = run(
            runner, "encrypt", "-r", "alice.pub", "big.bin", "-o", "big.hpqc",
            "-s", "signer.key",
        )
        assert result.exit_code == 0
        assert "streamed in" in shown(result)
        assert "signed by key id" in shown(result)

        header, _, _ = parse_header((workspace / "big.hpqc").read_bytes())
        assert header.signed and header.chunked

        result = run(runner, "decrypt", "-k", "alice.key", "big.hpqc",
                     "-o", "back.bin", "--sender", "signer.pub")
        assert result.exit_code == 0, shown(result)
        assert (workspace / "back.bin").read_bytes() == (workspace / "big.bin").read_bytes()

    def test_signing_a_large_pipe_still_falls_back(self, workspace, runner) -> None:
        """The one case that cannot stream, and it says why rather than failing."""
        run(runner, "signgen", "-o", "signer")
        big = b"\xa5" * (ONE_SHOT_LIMIT + 4096)

        result = runner.invoke(
            cli, ["encrypt", "-r", "alice.pub", "-o", "big.hpqc", "-s", "signer.key"],
            input=big,
        )
        assert result.exit_code == 0, shown(result)
        assert "stdin arrives once" in shown(result)

        header, _, _ = parse_header((workspace / "big.hpqc").read_bytes())
        assert header.signed and not header.chunked

    def test_a_truncated_stream_leaves_no_output_file(self, workspace, runner) -> None:
        """The reason decryption goes through a temporary file and a rename.

        A chunked decrypt writes chunk 3 before it knows chunk 4 verifies, so
        without the rename a truncated file would leave a plausible, silently
        incomplete plaintext sitting under the name the user asked for.
        """
        self._big(workspace)
        run(runner, "encrypt", "-r", "alice.pub", "big.bin", "-o", "big.hpqc")
        blob = (workspace / "big.hpqc").read_bytes()
        (workspace / "cut.hpqc").write_bytes(blob[: -streaming.WIRE_CHUNK_SIZE])

        result = runner.invoke(cli, ["decrypt", "-k", "alice.key", "cut.hpqc", "-o", "out.bin"])
        assert result.exit_code != 0
        assert not (workspace / "out.bin").exists()
        assert not list(workspace.glob(".*.tmp"))

    def test_decrypted_output_is_not_world_readable(self, workspace, runner) -> None:
        """The plaintext is the secret; the ciphertext is meant to be passed around."""
        (workspace / "small.bin").write_bytes(b"x" * 100)
        run(runner, "encrypt", "-r", "alice.pub", "small.bin", "-o", "small.hpqc")
        run(runner, "decrypt", "-k", "alice.key", "small.hpqc", "-o", "out.bin")

        assert (workspace / "out.bin").stat().st_mode & 0o777 == 0o600

    def test_an_interrupted_encrypt_leaves_no_half_written_container(
        self, workspace, runner, monkeypatch
    ) -> None:
        """A rename is either done or not; a partial .hpqc would look decryptable."""
        self._big(workspace)

        def explode(*args, **kwargs):
            raise RuntimeError("disk went away")

        monkeypatch.setattr(streaming, "seal", explode)
        with pytest.raises(RuntimeError):
            run(runner, "encrypt", "-r", "alice.pub", "big.bin", "-o", "big.hpqc")

        assert not (workspace / "big.hpqc").exists()
        assert not list(workspace.glob(".*.tmp"))


def test_output_can_be_a_character_device(workspace, runner) -> None:
    """`-o /dev/null` has to keep working, and for the right reason.

    Atomic output writes a temporary file beside the target and renames it,
    which cannot be done inside /dev. Getting this wrong is quiet rather than
    loud: every negative check written as `decrypt ... -o /dev/null` still
    "fails", just at the wrong step, and stops testing what it says it tests.
    """
    (workspace / "m.bin").write_bytes(b"discard me")
    run(runner, "encrypt", "-r", "alice.pub", "m.bin", "-o", "m.hpqc")

    result = run(runner, "decrypt", "-k", "alice.key", "m.hpqc", "-o", "/dev/null")
    assert result.exit_code == 0, shown(result)


def test_the_wrong_identity_is_refused_when_writing_to_dev_null(
    workspace, runner
) -> None:
    """The negative case the one above exists to protect."""
    (workspace / "m.bin").write_bytes(b"secret")
    run(runner, "encrypt", "-r", "alice.pub", "m.bin", "-o", "m.hpqc")
    run(runner, "keygen", "-o", "stranger")

    result = runner.invoke(
        cli, ["decrypt", "-k", "stranger.key", "m.hpqc", "-o", "/dev/null"]
    )
    assert result.exit_code != 0
    assert "encrypted for key id" in str(result.exception)


# --------------------------------------------------------------------------
# Several recipients
# --------------------------------------------------------------------------


@pytest.fixture
def group(workspace, runner):
    """alice (from `workspace`) plus bob and carol, all with key pairs."""
    for name in ("bob", "carol"):
        result = run(runner, "keygen", "-o", name)
        assert result.exit_code == 0, shown(result)
    (workspace / "msg.txt").write_bytes(b"minutes of the meeting\n")
    return workspace


class TestSeveralRecipients:
    def test_every_recipient_can_decrypt(self, group, runner) -> None:
        result = run(
            runner, "encrypt", "-r", "alice.pub", "-r", "bob.pub",
            "-r", "carol.pub", "msg.txt", "-o", "g.hpqc",
        )
        assert result.exit_code == 0, shown(result)
        assert "encrypted to 3 recipients" in shown(result)

        for name in ("alice", "bob", "carol"):
            out = f"{name}.txt"
            result = run(runner, "decrypt", "-k", f"{name}.key", "g.hpqc", "-o", out)
            assert result.exit_code == 0, shown(result)
            assert (group / out).read_bytes() == b"minutes of the meeting\n"

    def test_info_reports_the_count_and_not_the_names(self, group, runner) -> None:
        run(runner, "encrypt", "-r", "alice.pub", "-r", "bob.pub",
            "msg.txt", "-o", "g.hpqc")
        result = run(runner, "info", "g.hpqc")

        assert "recipients:  2 (the file does not name them)" in shown(result)
        for name in ("alice", "bob"):
            key_id = PublicKey.read(group / f"{name}.pub").key_id_hex
            assert key_id not in shown(result)

    def test_one_recipient_still_names_its_recipient(self, group, runner) -> None:
        """The older shape is not gone, and `info` still says who a file is for."""
        run(runner, "encrypt", "-r", "alice.pub", "msg.txt", "-o", "one.hpqc")
        result = run(runner, "info", "one.hpqc")

        key_id = PublicKey.read(group / "alice.pub").key_id_hex
        assert f"recipient:   key id {key_id}" in shown(result)

    def test_hide_recipients_works_with_one(self, group, runner) -> None:
        run(runner, "encrypt", "-r", "alice.pub", "--hide-recipients",
            "msg.txt", "-o", "h.hpqc")
        result = run(runner, "info", "h.hpqc")

        assert "recipients:  1" in shown(result)
        key_id = PublicKey.read(group / "alice.pub").key_id_hex
        assert key_id not in shown(result)

        result = run(runner, "decrypt", "-k", "alice.key", "h.hpqc", "-o", "back.txt")
        assert result.exit_code == 0, shown(result)
        assert (group / "back.txt").read_bytes() == b"minutes of the meeting\n"

    def test_an_outsider_is_refused_and_nothing_is_written(
        self, group, runner
    ) -> None:
        run(runner, "keygen", "-o", "dave")
        run(runner, "encrypt", "-r", "alice.pub", "-r", "bob.pub",
            "msg.txt", "-o", "g.hpqc")

        result = runner.invoke(
            cli, ["decrypt", "-k", "dave.key", "g.hpqc", "-o", "no.txt"]
        )

        assert result.exit_code != 0
        assert "2 recipient slot" in str(result.exception)
        assert not (group / "no.txt").exists()

    def test_the_same_recipient_twice_is_refused(self, group, runner) -> None:
        result = run(runner, "encrypt", "-r", "alice.pub", "-r", "alice.pub",
                     "msg.txt", "-o", "x.hpqc")

        assert result.exit_code != 0
        assert "same key" in shown(result)
        assert not (group / "x.hpqc").exists()

    def test_a_copy_of_a_key_under_another_name_is_still_a_duplicate(
        self, group, runner
    ) -> None:
        """The check is on the key, not the filename."""
        (group / "alias.pub").write_text((group / "alice.pub").read_text())
        result = run(runner, "encrypt", "-r", "alice.pub", "-r", "alias.pub",
                     "msg.txt", "-o", "x.hpqc")

        assert result.exit_code != 0
        assert "same key" in shown(result)

    def test_signing_to_several_recipients_round_trips(self, group, runner) -> None:
        run(runner, "signgen", "-o", "signer")
        result = run(runner, "encrypt", "-r", "alice.pub", "-r", "bob.pub",
                     "-r", "carol.pub", "msg.txt", "-o", "s.hpqc", "-s", "signer.key")
        assert result.exit_code == 0, shown(result)
        assert "encrypted to 3 recipients" in shown(result)
        assert "signed by key id" in shown(result)

        info = shown(run(runner, "info", "s.hpqc"))
        assert "recipients:  3" in info
        assert "signed:      yes (signer is encrypted; decrypt to see who)" in info

        for name in ("alice", "bob", "carol"):
            result = run(runner, "decrypt", "-k", f"{name}.key", "s.hpqc",
                         "-o", f"{name}-s.txt", "--sender", "signer.pub")
            assert result.exit_code == 0, shown(result)
            assert "signature ok" in shown(result)
            assert (group / f"{name}-s.txt").read_bytes() == b"minutes of the meeting\n"

    def test_signing_a_hidden_single_recipient_round_trips(
        self, group, runner
    ) -> None:
        run(runner, "signgen", "-o", "signer")
        result = run(runner, "encrypt", "-r", "alice.pub", "--hide-recipients",
                     "msg.txt", "-o", "hs.hpqc", "-s", "signer.key")
        assert result.exit_code == 0, shown(result)

        result = run(runner, "decrypt", "-k", "alice.key", "hs.hpqc",
                     "-o", "hs.txt", "--sender", "signer.pub")
        assert result.exit_code == 0, shown(result)
        assert (group / "hs.txt").read_bytes() == b"minutes of the meeting\n"

    def test_verifying_a_group_file_against_the_wrong_sender_fails(
        self, group, runner
    ) -> None:
        run(runner, "signgen", "-o", "signer")
        run(runner, "signgen", "-o", "impostor")
        run(runner, "encrypt", "-r", "alice.pub", "-r", "bob.pub",
            "msg.txt", "-o", "s.hpqc", "-s", "signer.key")

        result = runner.invoke(cli, ["decrypt", "-k", "bob.key", "s.hpqc",
                                     "-o", "no.txt", "--sender", "impostor.pub"])
        assert result.exit_code != 0
        assert "but verification was requested against" in str(result.exception)
        assert not (group / "no.txt").exists()

    def test_a_large_file_to_a_group_streams_and_is_signed(
        self, group, runner
    ) -> None:
        """All three flags at once, from the command line."""
        run(runner, "signgen", "-o", "signer")
        big = b"\xa5" * (ONE_SHOT_LIMIT + 4096)
        (group / "big.bin").write_bytes(big)

        result = run(runner, "encrypt", "-r", "alice.pub", "-r", "bob.pub",
                     "big.bin", "-o", "bs.hpqc", "-s", "signer.key")
        assert result.exit_code == 0, shown(result)
        assert "streamed in" in shown(result)

        info = shown(run(runner, "info", "bs.hpqc"))
        assert "chunked:     yes" in info
        assert "recipients:  2" in info
        assert "signed:      yes" in info

        for name in ("alice", "bob", "carol"):
            expected = name in ("alice", "bob")
            result = runner.invoke(
                cli, ["decrypt", "-k", f"{name}.key", "bs.hpqc",
                      "-o", f"{name}.bin", "--sender", "signer.pub"]
            )
            assert (result.exit_code == 0) is expected, shown(result)
            if expected:
                assert (group / f"{name}.bin").read_bytes() == big

    def test_a_large_file_streams_to_several_recipients(self, group, runner) -> None:
        big = b"\xa5" * (ONE_SHOT_LIMIT + 4096)
        (group / "big.bin").write_bytes(big)

        result = run(runner, "encrypt", "-r", "alice.pub", "-r", "bob.pub",
                     "big.bin", "-o", "big.hpqc")
        assert result.exit_code == 0, shown(result)
        assert "streamed in" in shown(result)

        info = shown(run(runner, "info", "big.hpqc"))
        assert "chunked:     yes" in info
        assert "recipients:  2" in info

        result = run(runner, "decrypt", "-k", "bob.key", "big.hpqc", "-o", "back.bin")
        assert result.exit_code == 0, shown(result)
        assert (group / "back.bin").read_bytes() == big

    def test_it_pipes(self, group, runner) -> None:
        result = run(runner, "encrypt", "-r", "alice.pub", "-r", "bob.pub",
                     stdin=b"piped to a group")
        assert result.exit_code == 0, result.stderr
        blob = result.stdout_bytes

        (group / "p.hpqc").write_bytes(blob)
        result = runner.invoke(cli, ["decrypt", "-k", "carol.key", "p.hpqc", "-o", "-"])
        assert result.exit_code != 0
        assert "recipient slot" in str(result.exception)

        result = run(runner, "decrypt", "-k", "bob.key", "p.hpqc", "-o", "-")
        assert result.stdout_bytes == b"piped to a group"

    def test_the_recipient_notice_never_lands_on_stdout(self, group, runner) -> None:
        """Same rule as the signature notice: stdout may be the ciphertext."""
        result = run(runner, "encrypt", "-r", "alice.pub", "-r", "bob.pub",
                     stdin=b"x")
        assert "recipients" not in result.stdout_bytes.decode("latin-1")
        assert "encrypted to 2 recipients" in result.stderr

    def test_a_header_past_the_read_ahead_still_describes(
        self, group, runner
    ) -> None:
        """`info` reads a header it cannot size in advance."""
        names = [f"r{i}" for i in range(6)]
        for name in names:
            run(runner, "keygen", "-o", name)
        args = []
        for name in names:
            args += ["-r", f"{name}.pub"]

        result = run(runner, "encrypt", *args, "msg.txt", "-o", "many.hpqc")
        assert result.exit_code == 0, shown(result)

        header_len = len(parse_header((group / "many.hpqc").read_bytes())[1])
        assert header_len > 4096

        result = run(runner, "info", "many.hpqc")
        assert f"header:      {header_len} bytes" in shown(result)
        assert "recipients:  6" in shown(result)


# --------------------------------------------------------------------------
# The second hybrid KEM
# --------------------------------------------------------------------------


class TestKemChoice:
    def test_keygen_makes_a_1024_key_and_says_so(self, workspace, runner) -> None:
        result = run(runner, "keygen", "-o", "big", "--kem", "mlkem1024")
        assert result.exit_code == 0, shown(result)
        assert "algorithms:  X448+ML-KEM-1024" in shown(result)

        result = run(runner, "info", "big.pub")
        assert "algorithms: X448 + ML-KEM-1024" in shown(result)
        result = run(runner, "info", "big.key")
        assert "algorithms: X448 + ML-KEM-1024" in shown(result)

    def test_the_default_is_unchanged(self, workspace, runner) -> None:
        """Every key written before --kem existed is what --kem's default writes."""
        result = run(runner, "info", "alice.pub")
        assert "algorithms: X25519 + ML-KEM-768" in shown(result)
        assert (workspace / "alice.pub").read_text().count("hpqc-pk1") == 1

    def test_the_kem_comes_from_the_key_not_the_command_line(
        self, workspace, runner
    ) -> None:
        """`encrypt` has no --kem: the recipient's key already decided."""
        run(runner, "keygen", "-o", "big", "--kem", "mlkem1024")
        (workspace / "m.txt").write_bytes(b"category five")

        result = run(runner, "encrypt", "-r", "big.pub", "m.txt", "-o", "b.hpqc")
        assert result.exit_code == 0, shown(result)
        assert "suite:       X448+ML-KEM-1024/ChaCha20-Poly1305 (0x03)" in shown(
            run(runner, "info", "b.hpqc")
        )

        result = run(runner, "encrypt", "-r", "alice.pub", "m.txt", "-o", "a.hpqc")
        assert "suite:       X25519+ML-KEM-768/ChaCha20-Poly1305 (0x01)" in shown(
            run(runner, "info", "a.hpqc")
        )

    @pytest.mark.parametrize("aead,suite_id", [("chacha20", "0x03"), ("aes", "0x04")])
    def test_both_aeads_pair_with_the_bigger_kem(
        self, workspace, runner, aead, suite_id
    ) -> None:
        run(runner, "keygen", "-o", "big", "--kem", "mlkem1024")
        (workspace / "m.txt").write_bytes(b"category five")

        run(runner, "encrypt", "-r", "big.pub", "m.txt", "-o", "b.hpqc", "--aead", aead)
        assert f"({suite_id})" in shown(run(runner, "info", "b.hpqc"))

        result = run(runner, "decrypt", "-k", "big.key", "b.hpqc", "-o", "back.txt")
        assert result.exit_code == 0, shown(result)
        assert (workspace / "back.txt").read_bytes() == b"category five"

    def test_a_group_of_1024_recipients(self, workspace, runner) -> None:
        for name in ("big1", "big2"):
            run(runner, "keygen", "-o", name, "--kem", "mlkem1024")
        (workspace / "m.txt").write_bytes(b"category five")

        result = run(runner, "encrypt", "-r", "big1.pub", "-r", "big2.pub",
                     "m.txt", "-o", "g.hpqc")
        assert result.exit_code == 0, shown(result)
        info = shown(run(runner, "info", "g.hpqc"))
        assert "recipients:  2" in info
        assert "kem ct:      1568 bytes x 2" in info

        for name in ("big1", "big2"):
            result = run(runner, "decrypt", "-k", f"{name}.key", "g.hpqc",
                         "-o", f"{name}.txt")
            assert (workspace / f"{name}.txt").read_bytes() == b"category five"

    def test_mixing_key_types_in_one_file_is_refused(self, workspace, runner) -> None:
        run(runner, "keygen", "-o", "big", "--kem", "mlkem1024")
        (workspace / "m.txt").write_bytes(b"x")

        result = run(runner, "encrypt", "-r", "big.pub", "-r", "alice.pub",
                     "m.txt", "-o", "x.hpqc")
        assert result.exit_code != 0
        assert "one file has one KEM" in shown(result)
        assert not (workspace / "x.hpqc").exists()

    def test_the_wrong_kind_of_identity_is_refused(self, workspace, runner) -> None:
        run(runner, "keygen", "-o", "big", "--kem", "mlkem1024")
        (workspace / "m.txt").write_bytes(b"x")
        run(runner, "encrypt", "-r", "big.pub", "m.txt", "-o", "b.hpqc")

        result = runner.invoke(
            cli, ["decrypt", "-k", "alice.key", "b.hpqc", "-o", "no.txt"]
        )
        assert result.exit_code != 0
        assert "but the supplied identity is" in str(result.exception)
        assert not (workspace / "no.txt").exists()

    def test_a_1024_key_can_be_passphrase_protected(
        self, workspace, runner, pwfile
    ) -> None:
        pw = pwfile("open sesame")
        result = run(runner, "keygen", "-o", "big", "--kem", "mlkem1024",
                     "--passphrase-file", pw, "--scrypt-log-n", "14")
        assert result.exit_code == 0, shown(result)
        (workspace / "m.txt").write_bytes(b"x")
        run(runner, "encrypt", "-r", "big.pub", "m.txt", "-o", "b.hpqc")

        result = run(runner, "decrypt", "-k", "big.key", "b.hpqc", "-o", "out.txt",
                     "--passphrase-file", pw)
        assert result.exit_code == 0, shown(result)
        assert (workspace / "out.txt").read_bytes() == b"x"

    def test_an_unknown_kem_name_is_refused_by_click(self, workspace, runner) -> None:
        result = runner.invoke(cli, ["keygen", "-o", "x", "--kem", "mlkem512"])
        assert result.exit_code != 0
        assert "mlkem512" in shown(result)


def test_info_on_a_missing_file_is_a_message_not_a_traceback(
    workspace, runner
) -> None:
    """`info` stats the file for its size, and stat() on nothing is a crash.

    It was one, briefly: the size was taken before the open, so a path that did
    not exist reached os.stat instead of the error handling. Every other
    command routes a bad path through click's `exists=True`; `info` accepts
    anything so it can also read stdin, so this is where it has to be caught.
    """
    result = runner.invoke(cli, ["info", "nope.hpqc"])

    assert result.exit_code != 0
    assert "nope.hpqc" in shown(result)
    assert "Traceback" not in shown(result)
    assert not isinstance(result.exception, FileNotFoundError)


def test_info_on_a_directory_is_a_message_too(workspace, runner) -> None:
    result = runner.invoke(cli, ["info", "."])

    assert result.exit_code != 0
    assert "Traceback" not in shown(result)


# --------------------------------------------------------------------------
# Behaving like a filter
# --------------------------------------------------------------------------


def test_a_reader_that_stops_early_is_not_an_error(workspace, runner) -> None:
    """`hpqc decrypt big.hpqc | head` must not fail, and must say nothing.

    This one needs a real process and a real pipe: click's test runner has no
    pipe to break. What it protects against is a silent failure -- click
    intercepts EPIPE itself and exits 1 with nothing on stderr, so under
    `set -o pipefail` a perfectly ordinary command fails a script for no
    visible reason. Restoring SIGPIPE's default makes hpqc die the way `cat`
    does instead.
    """
    import signal
    import subprocess
    import sys

    plaintext = b"first line\n" + b"a" * (ONE_SHOT_LIMIT + 4096)
    (workspace / "big.txt").write_bytes(plaintext)
    result = run(runner, "encrypt", "-r", "alice.pub", "big.txt", "-o", "big.hpqc")
    assert result.exit_code == 0, shown(result)

    proc = subprocess.run(
        [sys.executable, "-m", "hpqc", "decrypt", "-k", "alice.key", "big.hpqc"],
        cwd=workspace,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.returncode == 0 and proc.stdout == plaintext

    # Now with a reader that leaves after one line. The pipe is wired by hand
    # rather than with communicate(): after handing head's stdin to the writer
    # and closing our copy, communicate() tries to flush a closed file, which
    # is a ValueError before Python 3.12. Reading head's stdout directly works
    # everywhere -- and this test exists to check a portability fix, so it had
    # better be portable itself.
    head = subprocess.Popen(["head", "-1"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    writer = subprocess.Popen(
        [sys.executable, "-m", "hpqc", "decrypt", "-k", "alice.key", "big.hpqc"],
        cwd=workspace,
        stdout=head.stdin,
        stderr=subprocess.PIPE,
    )
    head.stdin.close()  # only the writer holds the write end now
    try:
        assert head.stdout.read() == b"first line\n"
    finally:
        head.stdout.close()
        head.wait()
    stderr = writer.communicate()[1]

    # Killed by SIGPIPE, exactly as `cat big | head` is -- not a silent exit 1.
    assert writer.returncode == -signal.SIGPIPE, writer.returncode
    assert stderr == b"", stderr


def test_a_group_file_from_before_commitments_is_refused_clearly(
    workspace, runner
) -> None:
    """The message a user meets if they still have an older group file.

    Those files stopped being readable when the file key commitment became
    mandatory, and the error has to say why rather than looking like
    corruption -- because it is not corruption, it is a shape that could not be
    trusted.
    """
    import json
    from pathlib import Path as _Path

    vectors = json.loads(
        (_Path(__file__).parent / "vectors" / "v1-recipients.json").read_text()
    )
    blob = bytes.fromhex(vectors["containers"][-1]["container"])
    (workspace / "old.hpqc").write_bytes(blob)
    (workspace / "old.key").write_text(vectors["identities"][0])

    result = runner.invoke(cli, ["info", "old.hpqc"])
    assert result.exit_code != 0
    assert "commitment and a recipient list go together" in str(result.exception)

    result = runner.invoke(
        cli, ["decrypt", "-k", "old.key", "old.hpqc", "-o", "out.bin"]
    )
    assert result.exit_code != 0
    assert "cannot be opened" in str(result.exception)
    assert not (workspace / "out.bin").exists()


def test_info_does_not_count_the_signature_block_as_plaintext(
    workspace, runner
) -> None:
    """A signed stream seals `signature block || plaintext` as one stream.

    Subtracting the tags alone leaves the block in the figure, so `info` used
    to report a signed file as 5365 bytes larger than it is -- a number that
    looks right until you compare it with `ls`.
    """
    from hpqc.signing import SIGNATURE_BLOCK_LEN

    run(runner, "signgen", "-o", "signer")
    plaintext = b"\xc3" * (ONE_SHOT_LIMIT + 4096)
    (workspace / "big.bin").write_bytes(plaintext)

    for name, args in (
        ("plain.hpqc", []),
        ("signed.hpqc", ["-s", "signer.key"]),
    ):
        result = run(
            runner, "encrypt", "-r", "alice.pub", "big.bin", "-o", name, *args
        )
        assert result.exit_code == 0, shown(result)
        assert "streamed in" in shown(result)

        info = shown(run(runner, "info", name))
        assert f"plaintext:   {len(plaintext)} bytes" in info, info

    # And the two containers really do differ by the block, so the test is not
    # passing because the subtraction is a no-op. The block can also push the
    # stream over a chunk boundary, which costs one more tag, so that is
    # accounted for rather than assumed away.
    def shape(name):
        blob = (workspace / name).read_bytes()
        _, header_bytes, _ = parse_header(blob)
        payload = len(blob) - len(header_bytes)
        return len(blob), streaming.chunk_count(payload)

    signed_size, signed_chunks = shape("signed.hpqc")
    plain_size, plain_chunks = shape("plain.hpqc")
    assert signed_size - plain_size == (
        SIGNATURE_BLOCK_LEN + streaming.TAG_LEN * (signed_chunks - plain_chunks)
    )
