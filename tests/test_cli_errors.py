"""The messages a user actually sees when something goes wrong.

This tool's loudest promise is that a bad input produces a sentence and an exit
code, never a traceback. Every other test file checks what happens when things
work, or when a *container* is hostile. These are the ordinary mistakes: a path
that is a directory, a key file that is a JPEG, a terminal where binary output
was going to go.

They were the last untested lines in `cli.py`, and the gap was not theoretical.
A `stat()` moved one line above its `open()` during a refactor in this project's
history and turned `hpqc info nope.hpqc` into a `FileNotFoundError`; six hundred
tests had nothing to say about it, because none of them had ever handed `info` a
path that was not there.

`run()` gets its own section. Everywhere else the tests drive click in-process
through `CliRunner`, which bypasses `run()` entirely -- so the function that
turns every expected error into its message was itself the least exercised code
in the package.
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import click
import pytest

from hpqc import backend, cli
from hpqc.cli import cli as cli_group
from hpqc.cli import run
from hpqc.errors import HpqcError

from test_cli import run as invoke  # noqa: F401  (shared helper)
from test_cli import separated_runner, shown


@pytest.fixture
def runner():
    return separated_runner()


@pytest.fixture
def workspace(runner, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli_group, ["keygen", "-o", "alice"])
    assert result.exit_code == 0, shown(result)
    yield tmp_path
    # Some tests below chmod a file to 0000 to make it unreadable. Put the
    # mode back: pytest keeps the last few tmp directories and prunes the
    # older ones on a later run, and a tree it cannot walk is a failure that
    # surfaces in some unrelated run days later.
    for child in tmp_path.rglob("*"):
        try:
            child.chmod(0o600 if child.is_file() else 0o700)
        except OSError:  # pragma: no cover - nothing to do about it here
            pass


# --------------------------------------------------------------------------
# Inputs that cannot be read
# --------------------------------------------------------------------------


def test_a_directory_given_as_input_is_a_message(workspace, runner) -> None:
    result = runner.invoke(
        cli_group, ["encrypt", "-r", "alice.pub", ".", "-o", "out.hpqc"]
    )
    assert result.exit_code != 0
    assert "Is a directory" in shown(result)
    assert not (workspace / "out.hpqc").exists()


def test_a_directory_given_to_info_is_a_message(workspace, runner) -> None:
    result = runner.invoke(cli_group, ["info", "."])
    assert result.exit_code != 0
    assert "cannot read ." in shown(result)


def test_an_unreadable_input_is_a_message(workspace, runner) -> None:
    """Skipped for root, which is not stopped by a mode."""
    secret = workspace / "locked.bin"
    secret.write_bytes(b"x")
    secret.chmod(0o000)
    if os.access(secret, os.R_OK):
        pytest.skip("running as a user that ignores file modes")

    try:
        result = runner.invoke(
            cli_group, ["encrypt", "-r", "alice.pub", "locked.bin", "-o", "out.hpqc"]
        )
        assert result.exit_code != 0
        assert "Permission denied" in shown(result)
    finally:
        secret.chmod(0o600)


def test_a_passphrase_file_that_is_a_directory_is_a_message(
    workspace, runner
) -> None:
    result = runner.invoke(
        cli_group,
        ["keygen", "-o", "locked", "--passphrase-file", ".", "--scrypt-log-n", "14"],
    )
    assert result.exit_code != 0
    assert "Is a directory" in shown(result) or "directory" in shown(result)


def test_an_empty_passphrase_file_is_refused(workspace, runner) -> None:
    (workspace / "empty").write_text("")
    result = runner.invoke(
        cli_group,
        ["keygen", "-o", "locked", "--passphrase-file", "empty",
         "--scrypt-log-n", "14"],
    )
    assert result.exit_code != 0
    assert "refusing to use an empty passphrase" in shown(result)


def test_a_binary_file_where_a_key_was_expected(workspace, runner) -> None:
    """A .key that is not text at all -- a JPEG renamed, say."""
    (workspace / "not.key").write_bytes(bytes(range(256)))

    result = runner.invoke(
        cli_group, ["passwd", "not.key", "--remove"]
    )
    assert result.exit_code != 0
    assert "is not an hpqc key file (it is not text)" in shown(result)


def test_a_container_that_is_not_text_and_not_a_container(workspace, runner) -> None:
    """`info` has to say something about arbitrary binary rubbish."""
    (workspace / "rubbish") .write_bytes(os.urandom(64))
    result = runner.invoke(cli_group, ["info", "rubbish"])

    assert result.exit_code != 0
    assert "unrecognised input" in shown(result)


# --------------------------------------------------------------------------
# Outputs that cannot be written
# --------------------------------------------------------------------------


def test_writing_into_a_missing_directory_is_a_message(workspace, runner) -> None:
    (workspace / "in.txt").write_bytes(b"x")
    result = runner.invoke(
        cli_group,
        ["encrypt", "-r", "alice.pub", "in.txt", "-o", "nowhere/out.hpqc"],
    )
    assert result.exit_code != 0
    assert "cannot write nowhere/out.hpqc" in shown(result)


def test_writing_to_an_unwritable_device_is_a_message(workspace, runner) -> None:
    """The straight-through branch, for a path that is not a regular file."""
    if not Path("/dev/full").exists():
        pytest.skip("no /dev/full here")
    (workspace / "in.txt").write_bytes(b"x" * 100)

    result = runner.invoke(
        cli_group, ["encrypt", "-r", "alice.pub", "in.txt", "-o", "/dev/full"]
    )
    # /dev/full accepts the open and fails the write: either way it must be a
    # message rather than a traceback.
    assert result.exit_code != 0
    assert "Traceback" not in shown(result)


class Terminal:
    """A stdout that says it is a tty, with a buffer to write into."""

    def __init__(self) -> None:
        self.buffer = io.BytesIO()

    def isatty(self) -> bool:
        return True


def test_refusing_to_write_a_container_to_a_terminal(monkeypatch) -> None:
    """A .hpqc file is binary whatever was encrypted, so this one is refused.

    Driven against `_output_stream` rather than through the runner, because the
    runner replaces sys.stdout with something of its own and the check is about
    the real one.
    """
    monkeypatch.setattr(cli.sys, "stdout", Terminal())
    with pytest.raises(click.ClickException, match="refusing to write a container"):
        with cli._output_stream("-", container=True):
            pass  # pragma: no cover - the context manager raises on entry


def test_plaintext_is_written_to_a_terminal(monkeypatch) -> None:
    """And decryption is not refused, which it was.

    `hpqc decrypt -k k.key f.hpqc` is the most ordinary command the tool has,
    and it failed on every real terminal -- as did the pipeline in the README,
    whose last stage writes to one. What comes out of a decrypt is the caller's
    own file; refusing to hand it over in case it is untidy is a guess about a
    file they already know. gpg, age and openssl all just write it.
    """
    terminal = Terminal()
    monkeypatch.setattr(cli.sys, "stdout", terminal)
    with cli._output_stream("-") as sink:
        sink.write(b"attack at dawn\n")
    assert terminal.buffer.getvalue() == b"attack at dawn\n"


# --------------------------------------------------------------------------
# Paths through info that nothing else reaches
# --------------------------------------------------------------------------


def test_info_describes_a_container_on_stdin(workspace, runner) -> None:
    (workspace / "in.txt").write_bytes(b"x" * 50)
    assert runner.invoke(
        cli_group, ["encrypt", "-r", "alice.pub", "in.txt", "-o", "c.hpqc"]
    ).exit_code == 0

    result = runner.invoke(
        cli_group, ["info"], input=(workspace / "c.hpqc").read_bytes()
    )
    assert result.exit_code == 0, shown(result)
    assert "type:        hpqc container" in shown(result)
    assert "payload:     66 bytes" in shown(result)


def test_info_says_so_when_the_backend_cannot_decrypt(
    workspace, runner, monkeypatch
) -> None:
    """A stack without ML-KEM can still describe a file, and says it cannot open it."""
    (workspace / "in.txt").write_bytes(b"x")
    assert runner.invoke(
        cli_group, ["encrypt", "-r", "alice.pub", "in.txt", "-o", "c.hpqc"]
    ).exit_code == 0

    monkeypatch.setattr(backend, "mlkem_available", lambda: False)
    result = runner.invoke(cli_group, ["info", "c.hpqc"])

    assert result.exit_code == 0, shown(result)
    assert "ML-KEM unavailable here" in shown(result)


# --------------------------------------------------------------------------
# run(), the real entry point
# --------------------------------------------------------------------------


def encrypted_to_a_stranger(workspace, runner) -> None:
    runner.invoke(cli_group, ["keygen", "-o", "stranger"])
    (workspace / "in.txt").write_bytes(b"for alice only")
    assert runner.invoke(
        cli_group,
        ["encrypt", "-r", "alice.pub", "in.txt", "-o", "c.hpqc"],
    ).exit_code == 0


def test_run_turns_an_hpqc_error_into_one_line(
    workspace, runner, monkeypatch, capsys
) -> None:
    """`error: ...` on stderr and exit 1, with no traceback.

    Reached through run() rather than CliRunner, because run() is what the
    installed `hpqc` binary calls and CliRunner never touches it.
    """
    encrypted_to_a_stranger(workspace, runner)
    monkeypatch.setattr(
        sys, "argv",
        ["hpqc", "decrypt", "-k", "stranger.key", "c.hpqc", "-o", "out.txt"],
    )

    assert run() == 1
    captured = capsys.readouterr()
    assert captured.err.startswith("error: ")
    assert "encrypted for key id" in captured.err
    assert "Traceback" not in captured.err
    assert not (workspace / "out.txt").exists()


def test_run_turns_a_click_exception_into_its_own_message(
    workspace, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(sys, "argv", ["hpqc", "info", "nope.hpqc"])

    assert run() == 1
    captured = capsys.readouterr()
    assert "cannot read nope.hpqc" in captured.err
    assert "Traceback" not in captured.err


def test_run_reports_an_abort_as_aborted(monkeypatch, capsys) -> None:
    """Ctrl-C at a passphrase prompt comes out of click as Abort."""
    def abort(*_args, **_kwargs):
        raise click.Abort()

    monkeypatch.setattr(cli.cli, "main", abort)
    assert run() == 130
    assert capsys.readouterr().err.strip() == "aborted"


def test_run_passes_a_successful_exit_code_through(workspace, monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["hpqc", "info", "alice.pub"])
    assert run() == 0


def test_run_handles_version(monkeypatch, capsys) -> None:
    """`--version` becomes an Exit inside click, and must come back as 0.

    Which mechanism click uses has moved between versions -- it either returns
    or raises SystemExit -- so both are accepted here. What is not negotiable
    is that the code is 0 and the version reaches stdout.
    """
    monkeypatch.setattr(sys, "argv", ["hpqc", "--version"])
    try:
        assert run() == 0
    except SystemExit as exit_info:  # pragma: no cover - click version dependent
        assert exit_info.code in (0, None)
    assert "hpqc" in capsys.readouterr().out


def test_the_module_entry_point_works(workspace) -> None:
    """`python -m hpqc`, which is what the SIGPIPE test drives."""
    import subprocess

    proc = subprocess.run(
        [sys.executable, "-m", "hpqc", "info", "alice.pub"],
        cwd=workspace, capture_output=True,
    )
    assert proc.returncode == 0
    assert b"hpqc public key" in proc.stdout


def test_the_module_entry_point_reports_failure(workspace) -> None:
    import subprocess

    proc = subprocess.run(
        [sys.executable, "-m", "hpqc", "info", "nope.hpqc"],
        cwd=workspace, capture_output=True,
    )
    assert proc.returncode == 1
    assert b"cannot read nope.hpqc" in proc.stderr
    assert b"Traceback" not in proc.stderr


@pytest.mark.parametrize(
    "args,path",
    [
        (["keygen", "-o", "locked", "--scrypt-log-n", "14",
          "--passphrase-file", "pw"], "pw"),
        (["passwd", "alice.key", "--remove"], "alice.key"),
    ],
    ids=["passphrase-file", "key-file"],
)
def test_an_unreadable_file_is_refused_by_click_before_it_is_opened(
    workspace, runner, args, path
) -> None:
    """Which is a finding, not the test I set out to write.

    hpqc has `cannot read X: <reason>` handlers on both of these reads, and
    neither can be reached from the command line: `click.Path(exists=True)`
    checks that the path exists, is not a directory *and* is readable, so click
    has already refused the file. The handlers stay -- a read with no error
    handling is how a traceback gets shipped, and the check-then-open gap is
    real however narrow -- but they are marked for what they are, and what this
    pins is the message the user actually gets.
    """
    (workspace / "pw").write_text("secret")
    (workspace / path).chmod(0o000)
    if os.access(workspace / path, os.R_OK):
        pytest.skip("running as a user that ignores file modes")

    try:
        result = runner.invoke(cli_group, args)
        assert result.exit_code != 0
        assert "is not readable" in shown(result)
        assert "Traceback" not in shown(result)
    finally:
        (workspace / path).chmod(0o600)


def test_a_directory_as_the_output_is_a_message(workspace, runner) -> None:
    """It exists and is not a regular file, so it takes the straight-through
    branch -- where opening it is what fails."""
    (workspace / "in.txt").write_bytes(b"x")
    (workspace / "outdir").mkdir()

    result = runner.invoke(
        cli_group, ["encrypt", "-r", "alice.pub", "in.txt", "-o", "outdir"]
    )
    assert result.exit_code != 0
    assert "cannot write outdir" in shown(result)
    assert "Traceback" not in shown(result)


def test_passwd_prompts_for_the_new_passphrase(workspace, runner, monkeypatch) -> None:
    """The interactive branch, which every other passphrase test bypasses."""
    monkeypatch.setattr(cli, "_have_terminal", lambda: True)

    result = runner.invoke(
        cli_group,
        ["passwd", "alice.key", "--scrypt-log-n", "14"],
        input="hunter2\nhunter2\n",
    )
    assert result.exit_code == 0, shown(result)
    assert "passphrase added" in shown(result)

    (workspace / "in.txt").write_bytes(b"x")
    (workspace / "pw").write_text("hunter2")
    assert runner.invoke(
        cli_group, ["encrypt", "-r", "alice.pub", "in.txt", "-o", "c.hpqc"]
    ).exit_code == 0
    result = runner.invoke(
        cli_group,
        ["decrypt", "-k", "alice.key", "c.hpqc", "-o", "out.txt",
         "--passphrase-file", "pw"],
    )
    assert result.exit_code == 0, shown(result)
    assert (workspace / "out.txt").read_bytes() == b"x"


def test_the_main_module_imports_cleanly() -> None:
    """`python -m hpqc` needs this module to import before it runs anything."""
    import hpqc.__main__

    assert hpqc.__main__.run is run


@pytest.mark.parametrize(
    "written,ending",
    [(b"open sesame", "none"), (b"open sesame\n", "lf"), (b"open sesame\r\n", "crlf")],
)
def test_a_passphrase_file_means_the_same_thing_however_it_ends(
    workspace, runner, written, ending
) -> None:
    """One trailing newline is stripped, and CRLF counts as one.

    A passphrase may legitimately contain spaces, including at its ends, so
    nothing else is trimmed -- which means a file saved on Windows has to be
    handled deliberately rather than left to produce a passphrase with a
    stray carriage return in it that no prompt will ever reproduce.
    """
    (workspace / "pw").write_bytes(written)
    (workspace / "in.txt").write_bytes(b"x")

    result = runner.invoke(
        cli_group,
        ["keygen", "-o", f"locked-{ending}", "--force", "--passphrase-file", "pw",
         "--scrypt-log-n", "14"],
    )
    assert result.exit_code == 0, shown(result)

    # The same passphrase, typed without any line ending at all, opens it.
    (workspace / "typed").write_bytes(b"open sesame")
    assert runner.invoke(
        cli_group,
        ["encrypt", "-r", f"locked-{ending}.pub", "in.txt", "-o", "c.hpqc"],
    ).exit_code == 0
    result = runner.invoke(
        cli_group,
        ["decrypt", "-k", f"locked-{ending}.key", "c.hpqc", "-o", "out.txt",
         "--passphrase-file", "typed"],
    )
    assert result.exit_code == 0, shown(result)
    assert (workspace / "out.txt").read_bytes() == b"x"


def test_info_recognises_a_key_file_on_stdin(workspace, runner) -> None:
    """stdin does not have to be a container; `info` falls through to the keys."""
    result = runner.invoke(
        cli_group, ["info"], input=(workspace / "alice.pub").read_bytes()
    )
    assert result.exit_code == 0, shown(result)
    assert "type:       hpqc public key" in shown(result)
    assert "X25519 + ML-KEM-768" in shown(result)


# --------------------------------------------------------------------------
# On a real terminal
# --------------------------------------------------------------------------


def on_a_terminal(args, cwd):
    """Run `python -m hpqc ...` with stdout attached to a real pty.

    The reason this exists: `CliRunner` gives the command a StringIO, which is
    not a tty, so `sys.stdout.isatty()` was False in every test ever written
    and the terminal guard never once ran. It was in the wrong place for
    months -- it refused *decryption*, so the most ordinary command the tool
    has, and the pipeline printed in the README, both failed on any real
    terminal while 789 tests said everything was fine.

    The pty is read to EOF and only then is stderr collected, and `wait` is
    used rather than `communicate`. That is not fussiness: `communicate` on a
    process whose stdin has already been closed raises `ValueError: flush of
    closed file` before Python 3.12, which is the second time in this file's
    history that exact call has broken the two oldest jobs in the matrix. The
    child here needs no stdin at all, so it gets none.
    """
    import os
    import pty
    import subprocess
    import sys

    primary, secondary = pty.openpty()
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "hpqc", *args],
            cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=secondary, stderr=subprocess.PIPE,
        )
        os.close(secondary)
        secondary = -1

        seen = b""
        while True:
            try:
                block = os.read(primary, 4096)
            except OSError:  # the pty reports EIO once the child is gone
                break
            if not block:
                break
            seen += block

        # The child has exited, so its stderr is complete and this cannot block.
        stderr = proc.stderr.read()
        proc.stderr.close()
        proc.wait()
        return proc.returncode, seen, stderr
    finally:
        os.close(primary)
        if secondary != -1:  # pragma: no cover - only on an early failure
            os.close(secondary)


@pytest.fixture
def a_container(workspace, runner):
    (workspace / "msg.txt").write_bytes(b"attack at dawn\n")
    result = runner.invoke(
        cli_group, ["encrypt", "-r", "alice.pub", "msg.txt", "-o", "msg.hpqc"]
    )
    assert result.exit_code == 0, shown(result)
    return workspace


def test_decrypting_to_a_terminal_prints_the_plaintext(a_container) -> None:
    """`hpqc decrypt -k k.key f.hpqc`, with nowhere else for it to go."""
    code, out, err = on_a_terminal(
        ["decrypt", "-k", "alice.key", "msg.hpqc"], a_container
    )
    assert code == 0, err
    assert b"attack at dawn" in out


def test_encrypting_to_a_terminal_is_refused(a_container) -> None:
    """A container is binary whatever was encrypted, so this one is refused."""
    code, out, err = on_a_terminal(
        ["encrypt", "-r", "alice.pub", "msg.txt"], a_container
    )
    assert code != 0
    assert b"refusing to write a container to a terminal" in err
    assert b"HPQC" not in out


def test_the_readme_pipeline_ends_on_a_terminal(a_container) -> None:
    """The example the README leads with, run the way a reader would run it.

    Its last stage writes to the terminal, so the guard in the wrong place
    broke it -- and no test noticed, because no test had a terminal.
    """
    import subprocess
    import sys

    encrypted = subprocess.run(
        [sys.executable, "-m", "hpqc", "encrypt", "-r", "alice.pub"],
        cwd=a_container, input=b"meet me at dawn\n", capture_output=True,
    )
    assert encrypted.returncode == 0, encrypted.stderr
    (a_container / "piped.hpqc").write_bytes(encrypted.stdout)

    code, out, err = on_a_terminal(
        ["decrypt", "-k", "alice.key", "piped.hpqc"], a_container
    )
    assert code == 0, err
    assert b"meet me at dawn" in out
