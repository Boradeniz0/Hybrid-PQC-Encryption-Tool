"""End-to-end CLI behaviour, driven through click's test runner."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from hpqc.cli import cli
from hpqc.keys import PrivateKey, PublicKey


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def run(runner: CliRunner, *args: str, stdin: bytes = b"") -> "object":
    return runner.invoke(cli, list(args), input=stdin, catch_exceptions=False)


@pytest.fixture
def workspace(runner: CliRunner, tmp_path: Path, monkeypatch):
    """A temp cwd with alice's key pair already generated."""
    monkeypatch.chdir(tmp_path)
    result = run(runner, "keygen", "-o", "alice")
    assert result.exit_code == 0, result.output
    return tmp_path


def test_keygen_writes_both_files_and_prints_the_key_id(workspace, runner) -> None:
    private_path = workspace / "alice.key"
    public_path = workspace / "alice.pub"

    assert private_path.exists() and public_path.exists()

    identity = PrivateKey.read(private_path)
    public = PublicKey.read(public_path)
    assert identity.public_key() == public

    result = run(runner, "info", str(public_path))
    assert public.key_id_hex in result.output


def test_keygen_refuses_to_clobber_an_existing_key(workspace, runner) -> None:
    result = runner.invoke(cli, ["keygen", "-o", "alice"])

    assert result.exit_code != 0
    assert "already exists" in result.output
    assert "--force" in result.output


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
    assert "hpqc container" in result.output
    assert "ML-KEM-768" in result.output
    assert PublicKey.read(workspace / "alice.pub").key_id_hex in result.output


def test_info_recognises_key_files(workspace, runner) -> None:
    assert "public key" in run(runner, "info", "alice.pub").output
    assert "private key" in run(runner, "info", "alice.key").output


def test_info_rejects_unrelated_input(workspace, runner) -> None:
    (workspace / "junk.bin").write_bytes(b"\x7fELF\x02\x01\x01\x00")

    result = runner.invoke(cli, ["info", "junk.bin"])

    assert result.exit_code != 0
    assert "unrecognised input" in result.output


def test_a_missing_recipient_file_is_reported_by_click(workspace, runner) -> None:
    result = runner.invoke(cli, ["encrypt", "-r", "nope.pub", "-o", "c.hpqc"], input=b"x")

    assert result.exit_code != 0
    assert "nope.pub" in result.output


def test_encrypting_to_a_private_key_file_is_refused(workspace, runner) -> None:
    """A slipped -r alice.key must not silently produce an unopenable file."""
    result = runner.invoke(cli, ["encrypt", "-r", "alice.key", "-o", "c.hpqc"], input=b"x")

    assert result.exit_code != 0
    assert not (workspace / "c.hpqc").exists()


def test_help_lists_every_command(runner) -> None:
    output = run(runner, "--help").output

    for command in ("keygen", "encrypt", "decrypt", "info"):
        assert command in output
