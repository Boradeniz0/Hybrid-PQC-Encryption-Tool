"""End-to-end CLI behaviour, driven through click's test runner."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from hpqc.cli import cli
from hpqc import wrapping
from hpqc.errors import HpqcError
from hpqc.keys import PrivateKey, PublicKey, SigningPrivateKey, SigningPublicKey


def separated_runner() -> CliRunner:
    """A runner that keeps stderr out of stdout, on every click version.

    click 8.2 always separates the two. Before that -- and Python 3.9 pins click
    to 8.1, because 8.2 requires 3.10 -- the default folded stderr into stdout
    and `result.stderr` raised `ValueError: stderr not separately captured`
    outright. Three assertions here used it, so the 3.9 job could not have been
    passing.
    """
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:  # click >= 8.2, where it is the only behaviour
        return CliRunner()


def shown(result) -> str:
    """Everything the user would see, from both streams.

    `shown(result)` is not portable: on click 8.1 with the streams separated it
    is stdout alone, and on 8.2+ it is the two interleaved. Assertions that only
    care whether a message appeared use this instead.
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
    loop. The version that asserted "the input runs out, so the command fails"
    looped forever there, writing prompts, at 100% CPU and four gigabytes of
    resident memory. What both versions agree on is the part actually worth
    testing: the mismatch is refused out loud, and the key that gets written is
    the retyped one.
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
