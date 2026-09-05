"""Command line interface.

    hpqc keygen  -o alice
    hpqc signgen -o alice-sign
    hpqc encrypt -r bob.pub secret.pdf -o secret.pdf.hpqc -s alice-sign.key
    hpqc encrypt -r bob.pub -r carol.pub notes.txt -o notes.hpqc
    hpqc decrypt -k bob.key secret.pdf.hpqc -o secret.pdf --sender alice-sign.pub
    hpqc info    secret.pdf.hpqc

Input defaults to stdin and output to stdout, so the tool pipes:

    echo "hi" | hpqc encrypt -r alice.pub | hpqc decrypt -k alice.key

Everything about a signature goes to stderr, never stdout: stdout may be the
plaintext itself, and mixing a status line into it would corrupt the output of
`hpqc decrypt ... > file`.
"""

from __future__ import annotations

import os
import signal
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator, Optional

import click

from . import (
    __version__,
    armour,
    backend,
    container,
    kems,
    streaming,
    suites,
    wrapping,
)
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


def _read_recipients(paths) -> "list":
    """Load every -r file, refusing a list that repeats someone.

    A duplicate is harmless to the format -- two stanzas that both open for the
    same person -- but it is far more likely to be a shell mistake than a plan,
    and the case worth catching is the one where a *different* recipient was
    meant and is now missing.
    """
    loaded = []
    seen = {}
    for path in paths:
        public = PublicKey.read(path)
        if public.key_id in seen:
            raise click.ClickException(
                f"{path} and {seen[public.key_id]} are the same key "
                f"(key id {public.key_id_hex}); listing a recipient twice is "
                "more often a mistake than a plan"
            )
        if loaded and public.kem.id != loaded[0].kem.id:
            # One suite byte per container means one KEM per container. Saying
            # so here is better than a length mismatch four layers down.
            raise click.ClickException(
                f"{path} is {public.kem.name} but {paths[0]} is "
                f"{loaded[0].kem.name}; one file has one KEM, so these "
                "recipients need separate files"
            )
        seen[public.key_id] = path
        loaded.append(public)
    return loaded


def _read_input(path: str) -> bytes:
    if path == STDIO:
        return sys.stdin.buffer.read()
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise click.ClickException(f"cannot read {path}: {exc.strerror}") from None


#: Inputs at or below this go through the one-shot format; larger ones are
#: chunked. The threshold exists so that ordinary messages keep producing
#: exactly the containers they always have -- including the ones frozen in
#: tests/vectors -- while a file nobody can hold in memory still works.
ONE_SHOT_LIMIT = 1 << 20


@contextmanager
def _input_stream(path: str) -> Iterator[BinaryIO]:
    """Open an input for reading, or hand back stdin."""
    if path == STDIO:
        yield sys.stdin.buffer
        return
    try:
        handle = open(path, "rb")
    except OSError as exc:
        raise click.ClickException(f"cannot read {path}: {exc.strerror}") from None
    try:
        yield handle
    finally:
        handle.close()


def _default_file_mode() -> int:
    """The mode a normally-created file would get under the current umask."""
    mask = os.umask(0)
    os.umask(mask)
    return 0o666 & ~mask


@contextmanager
def _output_stream(path: str, *, private: bool = False) -> Iterator[BinaryIO]:
    """Open an output for writing, replacing it atomically on success.

    Streaming makes atomicity matter in a way it did not before. A one-shot
    decrypt verifies the whole payload before a byte is written, so a failure
    leaves nothing behind. A chunked decrypt writes chunk 3 before it knows
    chunk 4 verifies, so a truncated file would otherwise leave a plausible,
    silently incomplete plaintext sitting under the name the user expects.
    Writing to a temporary file and renaming only on success means the result
    either appeared whole or never appeared.

    `private` asks for mode 0600: it is set for decrypted plaintext, which is
    the secret, and not for ciphertext, which is meant to be handed around.
    """
    if path == STDIO:
        if sys.stdout.isatty():
            raise click.ClickException(
                "refusing to write binary data to a terminal; "
                "use -o FILE or pipe the output"
            )
        yield sys.stdout.buffer
        sys.stdout.buffer.flush()
        return

    target = Path(path)
    if target.exists() and not target.is_file():
        # /dev/null, a fifo, a device. There is no temporary file to rename
        # over one of these, and replacing it with a regular file would be the
        # wrong answer -- so write straight through. (A symlink to a regular
        # file does go through the atomic path, and is replaced by one, which
        # is the usual behaviour of anything that writes-then-renames.)
        try:
            handle = open(target, "wb")
        except OSError as exc:
            raise click.ClickException(
                f"cannot write {path}: {exc.strerror}"
            ) from None
        try:
            yield handle
        finally:
            handle.close()
        return

    directory = target.parent if str(target.parent) else Path(".")
    try:
        fd, temporary = tempfile.mkstemp(
            dir=str(directory), prefix=f".{target.name}.", suffix=".tmp"
        )
    except OSError as exc:
        raise click.ClickException(
            f"cannot write {path}: {exc.strerror}"
        ) from None
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600 if private else _default_file_mode())
        with os.fdopen(fd, "wb") as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        os.unlink(temporary)
        raise
    os.replace(temporary, target)


def _fail_if_exists(path: Path, force: bool) -> None:
    if path.exists() and not force:
        raise click.ClickException(
            f"{path} already exists; pass --force to overwrite it"
        )


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="hpqc")
def cli() -> None:
    """Hybrid post-quantum encryption: Diffie-Hellman + ML-KEM -> HKDF -> AEAD.

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
    "--kem",
    "kem_name",
    type=click.Choice(sorted(kems.BY_CLI_NAME)),
    default="mlkem768",
    show_default=True,
    help=(
        "Which hybrid KEM. mlkem768 is X25519 + ML-KEM-768 (NIST category 3); "
        "mlkem1024 is X448 + ML-KEM-1024 (category 5). The classical half "
        "moves with the post-quantum one, because raising only one of them "
        "raises nothing."
    ),
)
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
    kem_name: str,
    ask_passphrase: bool,
    passphrase_file: Optional[str],
    scrypt_log_n: int,
) -> None:
    """Generate a hybrid key pair: Diffie-Hellman + ML-KEM."""
    private_path = Path(f"{basename}.key")
    public_path = Path(f"{basename}.pub")
    _fail_if_exists(private_path, force)
    _fail_if_exists(public_path, force)

    passphrase = _passphrase_for_new_key(
        ask_passphrase, passphrase_file, what="private key"
    )

    kem = kems.BY_CLI_NAME[kem_name]
    identity = PrivateKey.generate(kem)
    public = identity.public_key()

    identity.write(private_path, passphrase, _params(scrypt_log_n))
    public.write(public_path)

    protection = (
        "passphrase-protected" if passphrase is not None else "mode 0600 only"
    )
    click.echo(f"private key: {private_path}  ({protection} -- keep it secret)")
    click.echo(f"public key:  {public_path}   (share this)")
    click.echo(f"algorithms:  {kem.name}")
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
    "recipient_paths",
    required=True,
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Recipient's .pub file. Repeat it to encrypt to several people.",
)
@click.option(
    "--hide-recipients",
    is_flag=True,
    help=(
        "Leave the recipient unnamed in the header. This is automatic with "
        "more than one recipient -- there is no single name to write -- and "
        "the flag asks for the same treatment with exactly one."
    ),
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
    "--chunked/--one-shot",
    "chunked",
    default=None,
    help=(
        "Force the payload shape. The default picks it from the input size: "
        f"up to {ONE_SHOT_LIMIT // 1024} KiB is sealed in one piece, anything "
        "larger is streamed in chunks so it never has to fit in memory."
    ),
)
@click.option(
    "--passphrase-file",
    type=click.Path(exists=True, dir_okay=False),
    help=f"For a protected signing key. {PASSPHRASE_FILE_HELP}",
)
def encrypt(
    input_path: str,
    recipient_paths: tuple,
    hide_recipients: bool,
    output_path: str,
    aead: str,
    signing_key_path: Optional[str],
    chunked: Optional[bool],
    passphrase_file: Optional[str],
) -> None:
    """Encrypt INPUT (default stdin) to one or more public keys."""
    if signing_key_path is None and passphrase_file is not None:
        raise click.ClickException(
            "--passphrase-file only makes sense with --sign; there is no "
            "private key to open otherwise"
        )
    if chunked and signing_key_path is not None:
        raise click.ClickException(
            "--chunked and --sign cannot be combined: a signature is a "
            "statement about a whole message, so it cannot be produced until "
            "the whole message has been read"
        )
    to = _read_recipients(recipient_paths)
    sender = (
        _open_private(signing_key_path, passphrase_file, SigningPrivateKey)
        if signing_key_path is not None
        else None
    )
    # --aead names an AEAD; the KEM is not the sender's to pick, it is whatever
    # the recipients' keys already are. This is where the two meet.
    suite = suites.for_kem(to[0].kem, suites.BY_CLI_NAME[aead])

    with _input_stream(input_path) as source:
        # One byte past the limit is enough to tell "this fits" from "this does
        # not", without reading a gigabyte to find out.
        head = streaming.read_exactly(source, ONE_SHOT_LIMIT + 1)
        stream_it = len(head) > ONE_SHOT_LIMIT if chunked is None else chunked

        if stream_it and sender is not None:
            # Reached only on the automatic path -- the explicit combination is
            # refused above. Signing wins, because dropping the signature
            # silently would be worse than using more memory than we would like.
            stream_it = False
            click.echo(
                "note: signing needs the whole file at once; writing a "
                "one-shot container instead of streaming",
                err=True,
            )

        if stream_it:
            with _output_stream(output_path) as sink:
                chunks = container.encrypt_stream_many(
                    streaming.PrefixedStream(head, source),
                    sink,
                    to,
                    suite=suite,
                    hide_recipients=hide_recipients,
                )
            click.echo(
                f"streamed in {chunks} chunks of "
                f"{streaming.CHUNK_SIZE // 1024} KiB",
                err=True,
            )
        else:
            blob = container.encrypt_many(
                head + source.read(),
                to,
                suite=suite,
                sender=sender,
                hide_recipients=hide_recipients,
            )
            with _output_stream(output_path) as sink:
                sink.write(blob)

    if len(to) > 1:
        click.echo(
            f"encrypted to {len(to)} recipients; the file does not name them",
            err=True,
        )
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

    # decrypt_stream handles both payload shapes, because which one a file uses
    # is its own business: the flag is in the header, and the reader only finds
    # out after parsing it.
    with _input_stream(input_path) as source:
        with _output_stream(output_path, private=True) as sink:
            opened = container.decrypt_stream(source, sink, identity, sender)

    if opened.chunks is not None:
        click.echo(f"streamed {opened.chunks} chunks", err=True)
        if output_path == STDIO:
            # Writing to a file goes through a temporary and a rename, so a
            # failure leaves nothing. A pipe cannot be taken back: each chunk
            # is already gone downstream before the next one is checked.
            click.echo(
                "note: chunks are released as they verify, so a truncated "
                "file will have written partial output before failing",
                err=True,
            )

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
    if input_path == STDIO:
        data = _read_input(input_path)
        front, total = data, len(data)
        if front.startswith(container.MAGIC):
            _describe_container(streaming.PrefixedStream(front), total)
            return
    else:
        # Everything reported about a container lives in its header, and a
        # container can now be larger than memory, so read the front and take
        # the size from the filesystem rather than pulling it all in to print
        # nine lines.
        with _input_stream(input_path) as source:
            # The size is taken after the open, not before it: a missing or
            # unreadable path has to come back as one clean message from
            # _input_stream, not as a stat() traceback a few lines earlier.
            total = Path(input_path).stat().st_size
            front = streaming.read_exactly(source, container.HEADER_READ_AHEAD)
            if front.startswith(container.MAGIC):
                # Handed the still-open stream, not just the bytes: a long
                # recipient list can push the header past the read-ahead, and
                # read_header goes back for the rest itself.
                _describe_container(
                    streaming.PrefixedStream(front, source), total
                )
                return

    data = front if input_path == STDIO else _read_input(input_path)
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
        click.echo(f"algorithms: {public.kem.dh_name} + {public.kem.kem_name}")
        click.echo(f"key id:     {public.key_id_hex}")
        return
    if text and PRIVATE_PREFIX in text:
        identity = PrivateKey.decode(text)
        click.echo("type:       hpqc private key")
        click.echo(
            f"algorithms: {identity.kem.dh_name} + {identity.kem.kem_name}"
        )
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


def _describe_container(source: BinaryIO, total: int) -> None:
    """Report on a container from its header plus the file's total size.

    Only the header is read; the payload length is arithmetic, not something
    that has to be pulled off disk.
    """
    header, header_bytes, _ = container.read_header(source)
    payload = total - len(header_bytes)
    click.echo("type:        hpqc container")
    click.echo(f"version:     {header.version}")
    click.echo(f"suite:       {header.suite.name} (0x{header.suite.id:02x})")
    if header.multi:
        # The count is all there is to report. Naming the recipients is what
        # the list shape exists to avoid, so `info` on someone else's file
        # reveals how many people can read it and not one of them.
        click.echo(
            f"recipients:  {header.recipient_count} (the file does not "
            "name them)"
        )
    else:
        click.echo(f"recipient:   key id {header.key_id_hex}")
    click.echo(f"header:      {len(header_bytes)} bytes (authenticated as AAD)")
    if header.multi:
        kem_len = len(header.stanzas[0].kem_ciphertext)
        click.echo(f"kem ct:      {kem_len} bytes x {header.recipient_count}")
    else:
        click.echo(f"kem ct:      {len(header.kem_ciphertext)} bytes")
    if header.chunked:
        chunks = streaming.chunk_count(payload)
        click.echo(f"payload:     {payload} bytes")
        click.echo(
            f"chunked:     yes, {chunks} chunk(s) of up to "
            f"{streaming.CHUNK_SIZE // 1024} KiB "
            f"(+{streaming.TAG_LEN}-byte tag each)"
        )
        # Exact, because every chunk but the last is full: the tags are the
        # only overhead, and there are exactly as many as there are chunks.
        click.echo(f"plaintext:   {payload - chunks * streaming.TAG_LEN} bytes")
    else:
        click.echo(
            f"payload:     {payload} bytes (ciphertext + 16-byte tag)"
        )
        click.echo("chunked:     no")
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


def _restore_sigpipe() -> None:
    """Die on a closed pipe the way every other filter does.

    Python ignores SIGPIPE and turns the failed write into BrokenPipeError,
    which is right for a server and wrong for a filter. `hpqc decrypt big.hpqc
    | head` then ends with click intercepting EPIPE and exiting 1 with nothing
    on stderr -- a silent failure for a completely ordinary command, and one
    `set -o pipefail` turns into a failed script.

    Restoring the default disposition makes hpqc behave like `cat`: the write
    that has nowhere to go kills the process, the shell sees SIGPIPE, and
    nothing is printed. The BrokenPipeError handler below stays for platforms
    that have no SIGPIPE at all.
    """
    if hasattr(signal, "SIGPIPE"):  # POSIX; Windows has no such signal
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def run() -> int:
    """Entry point that turns expected errors into clean messages."""
    _restore_sigpipe()
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
    except BrokenPipeError:  # pragma: no cover - only where SIGPIPE is absent
        return 0
    return result if isinstance(result, int) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run())
