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

from . import __version__, backend, container, suites
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
def keygen(basename: str, force: bool) -> None:
    """Generate a hybrid X25519 + ML-KEM-768 key pair."""
    private_path = Path(f"{basename}.key")
    public_path = Path(f"{basename}.pub")
    _fail_if_exists(private_path, force)
    _fail_if_exists(public_path, force)

    identity = PrivateKey.generate()
    public = identity.public_key()

    identity.write(private_path)
    public.write(public_path)

    click.echo(f"private key: {private_path}  (mode 0600 -- keep it secret)")
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
def signgen(basename: str, force: bool) -> None:
    """Generate a hybrid Ed25519 + ML-DSA-65 signing key pair.

    Kept separate from `keygen` on purpose: a key should do one job, and files
    stay readable by builds that predate signing.
    """
    private_path = Path(f"{basename}.key")
    public_path = Path(f"{basename}.pub")
    _fail_if_exists(private_path, force)
    _fail_if_exists(public_path, force)

    sender = SigningPrivateKey.generate()
    public = sender.public_key()

    sender.write(private_path)
    public.write(public_path)

    click.echo(f"signing private key: {private_path}  (mode 0600 -- keep it secret)")
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
def encrypt(
    input_path: str,
    recipient_path: str,
    output_path: str,
    aead: str,
    signing_key_path: Optional[str],
) -> None:
    """Encrypt INPUT (default stdin) to a recipient's public key."""
    recipient = PublicKey.read(recipient_path)
    sender = (
        SigningPrivateKey.read(signing_key_path)
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
def decrypt(
    input_path: str, key_path: str, output_path: str, sender_path: Optional[str]
) -> None:
    """Decrypt INPUT (default stdin) with your private key."""
    identity = PrivateKey.read(key_path)
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


@cli.command()
@click.argument("input_path", metavar="[INPUT]", default=STDIO)
def info(input_path: str) -> None:
    """Describe a .hpqc container or a key file without decrypting it."""
    data = _read_input(input_path)

    if data.startswith(container.MAGIC):
        _describe_container(data)
        return

    text = _as_text(data)
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
