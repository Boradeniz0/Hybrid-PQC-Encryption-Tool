"""Command line interface.

    hpqc keygen  -o alice
    hpqc signgen -o alice-sign
    hpqc encrypt -r bob.pub secret.pdf -o secret.pdf.hpqc -s alice-sign.key
    hpqc decrypt -k bob.key secret.pdf.hpqc -o secret.pdf --sender alice-sign.pub
    hpqc info    secret.pdf.hpqc

Input defaults to stdin and output to stdout, so the tool pipes:

    echo "hi" | hpqc encrypt -r alice.pub | hpqc decrypt -k alice.key

Everything about a signature goes to stderr, never stdout: stdout may be the
plaintext itself, and mixing a status line into it would corrupt the output of
`hpqc decrypt ... > file`.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from . import __version__, armour, backend, container, suites, wrapping
from .errors import HpqcError
from .keys import (
    PRIVATE_PREFIX,
    PUBLIC_PREFIX,
    SIGN_PRIVATE_PREFIX,
    SIGN_PUBLIC_PREFIX,
    PrivateKey,
    PublicKey,
    SigningPrivateKey,
    SigningPublicKey,
)

STDIO = "-"

# Note the absence of a --passphrase VALUE option anywhere below. Command lines
# are visible to every user on the machine through ps, so a passphrase passed
# that way is not a secret. Prompting or a file are the two ways in.
PASSPHRASE_FILE_HELP = (
    "Read the passphrase from FILE instead of prompting. "
    "(There is deliberately no --passphrase VALUE: command lines are "
    "visible to other users via ps.)"
)


def _read_passphrase_file(path: str) -> str:
    """Read a passphrase from a file, stripping one trailing newline.

    Exactly one, and no other whitespace: a passphrase may legitimately contain
    spaces, including at its ends, and quietly trimming them would make the same
    passphrase from a file and from a prompt disagree.
    """
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise click.ClickException(f"cannot read {path}: {exc.strerror}") from None
    if raw.endswith("\r\n"):
        raw = raw[:-2]
    elif raw.endswith("\n"):
        raw = raw[:-1]
    if not raw:
        raise click.ClickException(
            f"{path} is empty; refusing to use an empty passphrase"
        )
    return raw


def _have_terminal() -> bool:
    """Whether there is a terminal to ask a passphrase on."""
    return sys.stdin.isatty()


def _prompt_passphrase(prompt: str, *, confirm: bool) -> str:
    """Ask for a passphrase on the terminal.

    The prompt goes to stderr because stdout may be the plaintext. Without a
    terminal there is nothing to prompt on, and reading it from stdin would
    swallow the data being encrypted, so that case is refused with a pointer to
    --passphrase-file rather than left to misbehave.
    """
    if not _have_terminal():
        raise click.ClickException(
            "a passphrase is needed but there is no terminal to ask on; "
            "use --passphrase-file"
        )
    return click.prompt(
        prompt, hide_input=True, confirmation_prompt=confirm, err=True
    )


def _scrypt_option(f):
    """--scrypt-log-n, shared by every command that writes a protected key.

    Exposed rather than hardcoded for two reasons: the parameters travel inside
    the key file, so a lower or higher setting stays readable everywhere, and
    128 MiB is a lot to ask of a small machine. Only N is adjustable; r and p
    stay at 8 and 1, because N is the dial that buys resistance.
    """
    return click.option(
        "--scrypt-log-n",
        type=click.IntRange(wrapping.MIN_LOG_N, wrapping.MAX_LOG_N),
        default=wrapping.DEFAULT_LOG_N,
        show_default=True,
        metavar="INT",
        help="scrypt cost as log2(N); each step up doubles time and memory.",
    )(f)


def _params(scrypt_log_n: int) -> "wrapping.Params":
    params = wrapping.Params(log_n=scrypt_log_n)
    params.validate()  # catches a memory ceiling the range check cannot express
    return params


def _passphrase_for_new_key(
    ask: bool, passphrase_file: Optional[str], *, what: str
) -> Optional[str]:
    """Resolve the passphrase to protect a *new* key with, or None for none."""
    if ask and passphrase_file is not None:
        raise click.ClickException(
            "--passphrase and --passphrase-file do both the same job; pick one"
        )
    if passphrase_file is not None:
        return _read_passphrase_file(passphrase_file)
    if ask:
        return _prompt_passphrase(f"passphrase for the new {what}", confirm=True)
    return None


def _read_key_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="ascii")
    except OSError as exc:
        raise click.ClickException(f"cannot read {path}: {exc.strerror}") from None
    except UnicodeDecodeError:
        raise click.ClickException(
            f"{path} is not an hpqc key file (it is not text)"
        ) from None


def _open_private(path: str, passphrase_file: Optional[str], cls):
    """Load a private key file, prompting for a passphrase if it needs one."""
    text = _read_key_text(path)
    passphrase = None
    if wrapping.is_wrapped(text):
        passphrase = (
            _read_passphrase_file(passphrase_file)
            if passphrase_file is not None
            else _prompt_passphrase(f"passphrase for {path}", confirm=False)
        )
    elif passphrase_file is not None:
        # Pass it through rather than ignoring it: the key layer explains that
        # this file is not protected, which is what the user needs to hear.
        passphrase = _read_passphrase_file(passphrase_file)
    return cls.decode(text, passphrase)


def _read_input(path: str) -> bytes:
    if path == STDIO:
        return sys.stdin.buffer.read()
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise click.ClickException(f"cannot read {path}: {exc.strerror}") from None


def _write_output(path: str, data: bytes, *, binary: bool) -> None:
    if path == STDIO:
        if binary and sys.stdout.isatty():
            raise click.ClickException(
                "refusing to write binary data to a terminal; "
                "use -o FILE or pipe the output"
            )
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return
    try:
        Path(path).write_bytes(data)
    except OSError as exc:
        raise click.ClickException(f"cannot write {path}: {exc.strerror}") from None


def _fail_if_exists(path: Path, force: bool) -> None:
    if path.exists() and not force:
        raise click.ClickException(
            f"{path} already exists; pass --force to overwrite it"
        )


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="hpqc")
def cli() -> None:
    """Hybrid post-quantum encryption: X25519 + ML-KEM-768 -> HKDF -> AEAD.

    Optional sender authentication uses Ed25519 + ML-DSA-65 and needs a
    separate signing key pair from `hpqc signgen`.
    """


@cli.command()
@click.option(
    "-o",
    "--out",
    "basename",
    default="hpqc-key",
    show_default=True,
    help="Base name; writes BASENAME.key (private, 0600) and BASENAME.pub.",
)
@click.option("--force", is_flag=True, help="Overwrite existing key files.")
@click.option(
    "-p",
    "--passphrase",
    "ask_passphrase",
    is_flag=True,
    help="Protect the private key with a passphrase (prompts twice).",
)
@click.option(
    "--passphrase-file",
    type=click.Path(exists=True, dir_okay=False),
    help=PASSPHRASE_FILE_HELP,
)
@_scrypt_option
def keygen(
    basename: str,
    force: bool,
    ask_passphrase: bool,
    passphrase_file: Optional[str],
    scrypt_log_n: int,
) -> None:
    """Generate a hybrid X25519 + ML-KEM-768 key pair."""
    private_path = Path(f"{basename}.key")
    public_path = Path(f"{basename}.pub")
    _fail_if_exists(private_path, force)
    _fail_if_exists(public_path, force)

    passphrase = _passphrase_for_new_key(
        ask_passphrase, passphrase_file, what="private key"
    )

    identity = PrivateKey.generate()
    public = identity.public_key()

    identity.write(private_path, passphrase, _params(scrypt_log_n))
    public.write(public_path)

    protection = (
        "passphrase-protected" if passphrase is not None else "mode 0600 only"
    )
    click.echo(f"private key: {private_path}  ({protection} -- keep it secret)")
    click.echo(f"public key:  {public_path}   (share this)")
    click.echo(f"key id:      {public.key_id_hex}")


@cli.command()
@click.option(
    "-o",
    "--out",
    "basename",
    default="hpqc-signing-key",
    show_default=True,
    help="Base name; writes BASENAME.key (private, 0600) and BASENAME.pub.",
)
@click.option("--force", is_flag=True, help="Overwrite existing key files.")
@click.option(
    "-p",
    "--passphrase",
    "ask_passphrase",
    is_flag=True,
    help="Protect the private key with a passphrase (prompts twice).",
)
@click.option(
    "--passphrase-file",
    type=click.Path(exists=True, dir_okay=False),
    help=PASSPHRASE_FILE_HELP,
)
@_scrypt_option
def signgen(
    basename: str,
    force: bool,
    ask_passphrase: bool,
    passphrase_file: Optional[str],
    scrypt_log_n: int,
) -> None:
    """Generate a hybrid Ed25519 + ML-DSA-65 signing key pair.

    Kept separate from `keygen` on purpose: a key should do one job, and files
    stay readable by builds that predate signing.
    """
    private_path = Path(f"{basename}.key")
    public_path = Path(f"{basename}.pub")
    _fail_if_exists(private_path, force)
    _fail_if_exists(public_path, force)

    passphrase = _passphrase_for_new_key(
        ask_passphrase, passphrase_file, what="signing private key"
    )

    sender = SigningPrivateKey.generate()
    public = sender.public_key()

    sender.write(private_path, passphrase, _params(scrypt_log_n))
    public.write(public_path)

    protection = (
        "passphrase-protected" if passphrase is not None else "mode 0600 only"
    )
    click.echo(f"signing private key: {private_path}  ({protection})")
    click.echo(f"signing public key:  {public_path}   (give this to recipients)")
    click.echo(f"key id:              {public.key_id_hex}")


@cli.command()
@click.argument("input_path", metavar="[INPUT]", default=STDIO)
@click.option(
    "-r",
    "--recipient",
    "recipient_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Recipient's .pub file.",
)
@click.option("-o", "--out", "output_path", default=STDIO, help="Output file.")
@click.option(
    "--aead",
    type=click.Choice(sorted(suites.BY_CLI_NAME)),
    default="chacha20",
    show_default=True,
    help="AEAD to encrypt the payload with.",
)
@click.option(
    "-s",
    "--sign",
    "signing_key_path",
    type=click.Path(exists=True, dir_okay=False),
    help="Your signing .key file; adds sender authentication.",
)
@click.option(
    "--passphrase-file",
    type=click.Path(exists=True, dir_okay=False),
    help=f"For a protected signing key. {PASSPHRASE_FILE_HELP}",
)
def encrypt(
    input_path: str,
    recipient_path: str,
    output_path: str,
    aead: str,
    signing_key_path: Optional[str],
    passphrase_file: Optional[str],
) -> None:
    """Encrypt INPUT (default stdin) to a recipient's public key."""
    if signing_key_path is None and passphrase_file is not None:
        raise click.ClickException(
            "--passphrase-file only makes sense with --sign; there is no "
            "private key to open otherwise"
        )
    recipient = PublicKey.read(recipient_path)
    sender = (
        _open_private(signing_key_path, passphrase_file, SigningPrivateKey)
        if signing_key_path is not None
        else None
    )
    suite = suites.BY_CLI_NAME[aead]
    plaintext = _read_input(input_path)
    blob = container.encrypt(plaintext, recipient, suite, sender=sender)
    _write_output(output_path, blob, binary=True)
    if sender is not None:
        click.echo(
            f"signed by key id {sender.public_key().key_id_hex}", err=True
        )


@cli.command()
@click.argument("input_path", metavar="[INPUT]", default=STDIO)
@click.option(
    "-k",
    "--key",
    "key_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Your .key identity file.",
)
@click.option("-o", "--out", "output_path", default=STDIO, help="Output file.")
@click.option(
    "--sender",
    "sender_path",
    type=click.Path(exists=True, dir_okay=False),
    help="Sender's signing .pub file; requires and verifies a signature.",
)
@click.option(
    "--passphrase-file",
    type=click.Path(exists=True, dir_okay=False),
    help=f"For a protected identity. {PASSPHRASE_FILE_HELP}",
)
def decrypt(
    input_path: str,
    key_path: str,
    output_path: str,
    sender_path: Optional[str],
    passphrase_file: Optional[str],
) -> None:
    """Decrypt INPUT (default stdin) with your private key."""
    identity = _open_private(key_path, passphrase_file, PrivateKey)
    sender = (
        SigningPublicKey.read(sender_path) if sender_path is not None else None
    )
    blob = _read_input(input_path)
    opened = container.open_container(blob, identity, sender)
    _write_output(output_path, opened.plaintext, binary=True)

    if opened.signer is None:
        return
    if opened.verified:
        click.echo(
            f"signature ok: signed by key id {opened.signer.key_id_hex}", err=True
        )
    else:
        # The signature checks out against the key inside the file, which
        # proves the file is self-consistent and nothing about who wrote it --
        # that key could have been generated for this one message.
        click.echo(
            f"warning: signed by key id {opened.signer.key_id_hex}; "
            "pass --sender to verify the signer's identity",
            err=True,
        )


def _private_key_kind(text: str) -> int:
    """Work out which kind of private key a file holds, without opening it."""
    if wrapping.is_wrapped(text):
        return wrapping.parse(text).kind
    line = armour.payload_line(text)
    # Signing first for clarity; the prefixes are chosen so that neither is a
    # prefix of the other, which a test enforces.
    if line.startswith(SIGN_PRIVATE_PREFIX):
        return wrapping.KIND_SIGNING_IDENTITY
    if line.startswith(PRIVATE_PREFIX):
        return wrapping.KIND_IDENTITY
    raise click.ClickException(
        f"{line[:16]!r}... is not an hpqc private key; "
        "passwd only works on private keys"
    )


@cli.command()
@click.argument(
    "key_path", metavar="KEYFILE", type=click.Path(exists=True, dir_okay=False)
)
@click.option(
    "--remove",
    is_flag=True,
    help="Strip the passphrase, leaving the key protected by file mode only.",
)
@click.option(
    "--passphrase-file",
    type=click.Path(exists=True, dir_okay=False),
    help=f"The key's *current* passphrase. {PASSPHRASE_FILE_HELP}",
)
@click.option(
    "--new-passphrase-file",
    type=click.Path(exists=True, dir_okay=False),
    help="Read the new passphrase from FILE instead of prompting.",
)
@_scrypt_option
def passwd(
    key_path: str,
    remove: bool,
    passphrase_file: Optional[str],
    new_passphrase_file: Optional[str],
    scrypt_log_n: int,
) -> None:
    """Add, change, or remove the passphrase on a private KEYFILE.

    The key itself is untouched -- only how it is stored changes -- so the
    public key and key id stay exactly as they were. That is the point: without
    this, changing a passphrase would mean generating a new identity, and
    everyone holding your public key would have to fetch a new one.
    """
    if remove and new_passphrase_file is not None:
        raise click.ClickException(
            "--remove and --new-passphrase-file contradict each other"
        )

    text = _read_key_text(key_path)
    kind = _private_key_kind(text)
    cls = (
        SigningPrivateKey
        if kind == wrapping.KIND_SIGNING_IDENTITY
        else PrivateKey
    )
    was_wrapped = wrapping.is_wrapped(text)

    if remove and not was_wrapped:
        raise click.ClickException(f"{key_path} has no passphrase to remove")

    key = _open_private(key_path, passphrase_file, cls)

    if remove:
        new_passphrase = None
    elif new_passphrase_file is not None:
        new_passphrase = _read_passphrase_file(new_passphrase_file)
    else:
        new_passphrase = _prompt_passphrase(
            f"new passphrase for {key_path}", confirm=True
        )

    # Written to a temporary file and renamed over the original, so an
    # interrupted rewrite cannot leave the key half-written or gone.
    key.write(key_path, new_passphrase, _params(scrypt_log_n))

    if remove:
        what = "passphrase removed; the key is now protected by file mode only"
    elif was_wrapped:
        what = "passphrase changed"
    else:
        what = "passphrase added"
    click.echo(f"{key_path}: {what}")
    click.echo(f"key id: {key.public_key().key_id_hex} (unchanged)")


@cli.command()
@click.argument("input_path", metavar="[INPUT]", default=STDIO)
def info(input_path: str) -> None:
    """Describe a .hpqc container or a key file without decrypting it."""
    data = _read_input(input_path)

    if data.startswith(container.MAGIC):
        _describe_container(data)
        return

    text = _as_text(data)
    if text and wrapping.is_wrapped(text):
        wrapped = wrapping.parse(text)
        click.echo("type:       hpqc wrapped private key")
        click.echo(f"contents:   {wrapped.kind_name}")
        click.echo(f"protection: {wrapped.params.describe()}")
        # The key id is derived from the key itself, which is sealed.
        click.echo("key id:     unavailable without the passphrase")
        return
    if text and SIGN_PUBLIC_PREFIX in text:
        public = SigningPublicKey.decode(text)
        click.echo("type:       hpqc signing public key")
        click.echo("algorithms: Ed25519 + ML-DSA-65")
        click.echo(f"key id:     {public.key_id_hex}")
        return
    if text and SIGN_PRIVATE_PREFIX in text:
        sender = SigningPrivateKey.decode(text)
        click.echo("type:       hpqc signing private key")
        click.echo("algorithms: Ed25519 + ML-DSA-65")
        click.echo(f"key id:     {sender.key_id_hex}")
        return
    if text and PUBLIC_PREFIX in text:
        public = PublicKey.decode(text)
        click.echo("type:       hpqc public key")
        click.echo("algorithms: X25519 + ML-KEM-768")
        click.echo(f"key id:     {public.key_id_hex}")
        return
    if text and PRIVATE_PREFIX in text:
        identity = PrivateKey.decode(text)
        click.echo("type:       hpqc private key")
        click.echo("algorithms: X25519 + ML-KEM-768")
        click.echo(f"key id:     {identity.key_id_hex}")
        return

    raise click.ClickException(
        "unrecognised input: not an hpqc container and not an hpqc key file"
    )


def _as_text(data: bytes) -> Optional[str]:
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        return None


def _describe_container(data: bytes) -> None:
    header, header_bytes, ciphertext = container.parse_header(data)
    click.echo("type:        hpqc container")
    click.echo(f"version:     {header.version}")
    click.echo(f"suite:       {header.suite.name} (0x{header.suite.id:02x})")
    click.echo(f"recipient:   key id {header.key_id_hex}")
    click.echo(f"header:      {len(header_bytes)} bytes (authenticated as AAD)")
    click.echo(f"kem ct:      {len(header.kem_ciphertext)} bytes")
    click.echo(f"payload:     {len(ciphertext)} bytes (ciphertext + 16-byte tag)")
    if header.signed:
        # The signature block is inside the AEAD, so info genuinely cannot say
        # who signed -- that is the point of signing before encrypting.
        click.echo(
            "signed:      yes (signer is encrypted; decrypt to see who)"
        )
    else:
        click.echo("signed:      no")
    if not backend.mlkem_available():
        click.echo("note:        ML-KEM unavailable here; this file cannot be decrypted")


def run() -> int:
    """Entry point that turns expected errors into clean messages."""
    try:
        # standalone_mode=False lets our own error handling run; click still
        # converts --help/--version into an Exit and hands back its code.
        result = cli.main(standalone_mode=False)
    except HpqcError as exc:
        click.echo(f"error: {exc}", err=True)
        return 1
    except click.ClickException as exc:
        exc.show()
        return exc.exit_code
    except click.Abort:
        click.echo("aborted", err=True)
        return 130
    except BrokenPipeError:  # pragma: no cover - `hpqc info big.hpqc | head`
        return 0
    return result if isinstance(result, int) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run())
