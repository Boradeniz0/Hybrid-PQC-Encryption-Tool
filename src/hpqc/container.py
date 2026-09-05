"""The .hpqc container format: header layout, encryption, decryption.

Byte layout (all integers big-endian):

    offset  size   field
    0       4      magic, b"HPQC"
    4       1      format version, 1
    5       1      cipher suite id  -> suites.by_id()
    6       2      flags; bit 0 = signed, bit 1 = chunked,
                       bit 2 = recipient list, rest reserved
    8       8      recipient key id (truncated SHA-256, a UX hint only)
    16      16     HKDF salt
    32      12     AEAD nonce  (suite.nonce_len); in chunked mode the
                       first 7 bytes are the STREAM nonce prefix
    44      2      length of the ephemeral X25519 public key (32)
    46      32     ephemeral X25519 public key
    78      2      length of the ML-KEM-768 ciphertext (1088)
    80      1088   ML-KEM-768 ciphertext
    1168    ...    AEAD ciphertext || 16-byte tag

With bit 2 set the file has more than one recipient (or one it declines to
name), and everything from offset 44 is replaced by a list:

    44      2      recipient count, 1..MAX_RECIPIENTS
    46      ...    that many stanzas, each 2+32 ephemeral X25519 public key,
                       2+1088 ML-KEM-768 ciphertext, 2+48 wrapped file key
    ...     ...    AEAD ciphertext || 16-byte tag

and the key id at offset 8 is all zeros, because there is no one recipient to
name and naming one of several would be worse than naming none. See
recipients.py for what a stanza holds and why it identifies nobody.

Two properties matter more than the exact offsets:

* **The whole header is the AEAD's associated data.** Every byte above is
  authenticated. Flip the suite id to downgrade the file, swap in a different
  ML-KEM ciphertext, retarget the key id -- the tag check fails. Nothing in the
  header is trusted before the tag is verified.

* **Variable-size fields are length-prefixed.** v1 only ever emits 32 and 1088,
  but a future ML-KEM-1024 suite drops in without a parser change.

* **The header's length can depend on its own contents, and is still bounded.**
  A recipient list makes the header variable-length for the first time. The
  reader does not seek and does not trust a length it has not checked: it reads
  a fixed amount, parses, and if the parser says how many more bytes one field
  was short by, fetches at least that much and parses again -- up to a hard cap
  of MAX_HEADER_LEN. See `read_header`.

* **Unknown flag bits are refused, known ones are not.** Sender authentication
  was added by claiming bit 0 of the reserved `flags` field, which is what it
  was there for. An older build meets a signed file, sees a flag bit it does
  not implement, and refuses it by name instead of decrypting something it only
  half understands -- while this build still reads every unsigned file written
  before signing existed. The format version did not have to move.

* **The payload comes in two shapes.** With bit 1 clear it is a single AEAD
  ciphertext, and both plaintext and ciphertext are held in memory at once.
  With bit 1 set it is a sequence of fixed-size chunks, each sealed under its
  own nonce, and neither side has to hold more than one chunk. See streaming.py
  for why the chunked shape needs an explicit final-chunk marker.

The chunked shape is mutually exclusive with signing, and that is a property of
signatures rather than an implementation shortcut: a signature is a statement
about a whole message, so it cannot be produced until the whole message has
been read, and it cannot be checked until the whole message has been received.
Signing therefore uses the one-shot payload, and a container claiming to be
both signed and chunked is refused as malformed.

Signing is also, for now, mutually exclusive with a recipient list -- but for a
reason that is an implementation gap rather than a law of nature. The signature
binds the recipient's public keys into the signed message, which is what stops
surreptitious forwarding (see signing.py); with several recipients it has to
bind the whole set instead, and the set has to travel inside the AEAD so that
an eavesdropper still cannot read it. Until that exists, the combination is
refused rather than approximated: binding just one of the recipients would
verify for that person and fail for everybody else, and binding none of them
would quietly reopen the forwarding hole.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidTag

from . import hybrid, recipients, signing, streaming, suites
from .errors import (
    DecryptionError,
    FormatError,
    SignatureError,
    TruncatedError,
    WrongRecipientError,
)
from .hybrid import MLKEM768_CIPHERTEXT_LEN, SALT_LEN
from .keys import (
    KEY_ID_LEN,
    X25519_KEY_LEN,
    PrivateKey,
    PublicKey,
    SigningPrivateKey,
    SigningPublicKey,
)
from .suites import DEFAULT_SUITE, Suite
from .wire import U16, Reader

MAGIC = b"HPQC"
FORMAT_VERSION = 1

FLAGS_NONE = 0
FLAG_SIGNED = 0x0001  # the AEAD payload starts with a signature block
FLAG_CHUNKED = 0x0002  # the payload is a STREAM of fixed-size sealed chunks
FLAG_RECIPIENTS = 0x0004  # the header carries a list of anonymous stanzas
_KNOWN_FLAGS = FLAG_SIGNED | FLAG_CHUNKED | FLAG_RECIPIENTS

#: What the fixed key id field holds when the recipient list is in use. It is
#: checked on parse rather than skipped: a fixed field that nothing reads is a
#: place to smuggle bytes past everyone who looks at the file with `info`.
NO_KEY_ID = b"\x00" * KEY_ID_LEN

#: How much of a container to read before trying to parse its header. A
#: single-recipient header is 1168 bytes and this covers it in one read; a
#: recipient list may need more, which `read_header` fetches on demand.
HEADER_READ_AHEAD = 4096

_MAX_STANZA_LEN = max(recipients.stanza_len(s) for s in suites.all_suites())
_MAX_NONCE_LEN = max(s.nonce_len for s in suites.all_suites())

_PREAMBLE = struct.Struct(">4sBBH8s16s")  # magic, version, suite, flags, key id, salt

#: The hard ceiling on a header, so that a hostile count field cannot make the
#: reader buffer without limit before a single byte has been authenticated.
MAX_HEADER_LEN = (
    _PREAMBLE.size
    + _MAX_NONCE_LEN
    + U16.size
    + recipients.MAX_RECIPIENTS * _MAX_STANZA_LEN
)


@dataclass(frozen=True)
class Header:
    """Parsed container header. Untrusted until the AEAD tag verifies."""

    suite: Suite
    flags: int
    key_id: bytes
    salt: bytes
    nonce: bytes
    #: Set on a single-recipient header, empty when `stanzas` is in use.
    ephemeral_public: bytes = b""
    kem_ciphertext: bytes = b""
    #: Set when the recipient list is in use, empty otherwise. The two are
    #: alternatives, never both: which one a file uses is flag bit 2.
    stanzas: Tuple[recipients.Stanza, ...] = ()
    version: int = FORMAT_VERSION

    def pack(self) -> bytes:
        preamble = _PREAMBLE.pack(
            MAGIC,
            self.version,
            self.suite.id,
            self.flags,
            self.key_id,
            self.salt,
        )
        if self.multi:
            return b"".join(
                (preamble, self.nonce, U16.pack(len(self.stanzas)))
                + tuple(stanza.pack() for stanza in self.stanzas)
            )
        return b"".join(
            (
                preamble,
                self.nonce,
                U16.pack(len(self.ephemeral_public)),
                self.ephemeral_public,
                U16.pack(len(self.kem_ciphertext)),
                self.kem_ciphertext,
            )
        )

    @property
    def key_id_hex(self) -> str:
        return self.key_id.hex()

    @property
    def signed(self) -> bool:
        """True if the payload begins with a signature block.

        Whether the signature *verifies* -- and who signed -- cannot be known
        from the header: the signature lives inside the AEAD, so it takes the
        recipient's private key to find out. That is deliberate; see signing.py.
        """
        return bool(self.flags & FLAG_SIGNED)

    @property
    def chunked(self) -> bool:
        """True if the payload is a STREAM of sealed chunks, not one ciphertext."""
        return bool(self.flags & FLAG_CHUNKED)

    @property
    def multi(self) -> bool:
        """True if the recipients are a list of anonymous stanzas."""
        return bool(self.flags & FLAG_RECIPIENTS)

    @property
    def recipient_count(self) -> int:
        """How many recipients this file has -- all a stranger can learn.

        Which recipients they are is not in the file; see recipients.py.
        """
        return len(self.stanzas) if self.multi else 1

    @property
    def nonce_prefix(self) -> bytes:
        """The STREAM per-file nonce prefix: the first 7 bytes of the nonce.

        The other five are not fed to the nonce, but they are still random and
        still covered by the associated data, so nothing about the header can
        be edited without breaking every chunk.
        """
        return self.nonce[: streaming.NONCE_PREFIX_LEN]


def parse_header(data: bytes) -> Tuple[Header, bytes, bytes]:
    """Split a container into (header, header_bytes, aead_ciphertext).

    `header_bytes` is returned verbatim rather than re-packed: it is the AEAD's
    associated data, and re-serialising could paper over a byte we did not
    round-trip faithfully.
    """
    reader = Reader(data)
    preamble = reader.take(_PREAMBLE.size, "header preamble")
    magic, version, suite_id, flags, key_id, salt = _PREAMBLE.unpack(preamble)

    if magic != MAGIC:
        raise FormatError(
            f"not an hpqc file: expected magic {MAGIC!r}, got {magic!r}"
        )
    if version != FORMAT_VERSION:
        raise FormatError(
            f"container format version {version} is not supported "
            f"(this build writes and reads version {FORMAT_VERSION})"
        )

    suite = suites.by_id(suite_id)

    unknown = flags & ~_KNOWN_FLAGS
    if unknown:
        # Refuse by name rather than ignoring the bit: an unknown flag means
        # the writer used a feature this build does not implement, and
        # decrypting half of what the file says would be worse than failing.
        raise FormatError(
            f"unknown header flags 0x{unknown:04x}; the file uses a feature "
            f"this build does not implement (known flags: 0x{_KNOWN_FLAGS:04x})"
        )

    if flags & FLAG_SIGNED and flags & FLAG_RECIPIENTS:
        # Never written by this build. Refusing is the fail-closed answer: the
        # alternative is verifying a signature whose recipient binding cannot
        # be reconstructed, which is a check that looks like it passed.
        raise FormatError(
            "header claims the payload is both signed and encrypted to a "
            "recipient list; this build does not sign to several recipients"
        )

    if flags & FLAG_SIGNED and flags & FLAG_CHUNKED:
        # Never written, so this can only be a doctored header. Refuse it here
        # rather than let a signature parser loose on chunk framing: the
        # signature block would be read out of what is really a sealed chunk.
        raise FormatError(
            "header claims the payload is both signed and chunked; a signature "
            "covers a whole message, so signed containers are never chunked"
        )

    nonce = reader.take(suite.nonce_len, "AEAD nonce")

    ephemeral_public = kem_ciphertext = b""
    stanzas: Tuple[recipients.Stanza, ...] = ()

    if flags & FLAG_RECIPIENTS:
        if key_id != NO_KEY_ID:
            raise FormatError(
                "header uses a recipient list, which names nobody, but its "
                f"key id field is not empty (0x{key_id.hex()})"
            )
        count = reader.take_u16("recipient count")
        if not 1 <= count <= recipients.MAX_RECIPIENTS:
            # Bounded before anything is allocated for it. The count is the
            # one field in the header that decides how much work the parser
            # does, so it is checked before it can ask for any.
            raise FormatError(
                f"header claims {count} recipients; the supported range is "
                f"1 to {recipients.MAX_RECIPIENTS}"
            )
        stanzas = tuple(
            recipients.read_stanza(reader, suite) for _ in range(count)
        )
    else:
        ephemeral_public = reader.take_prefixed(
            "ephemeral X25519 public key", X25519_KEY_LEN
        )
        kem_ciphertext = reader.take_prefixed(
            "ML-KEM-768 ciphertext", MLKEM768_CIPHERTEXT_LEN
        )

    header = Header(
        suite=suite,
        flags=flags,
        key_id=key_id,
        salt=salt,
        nonce=nonce,
        ephemeral_public=ephemeral_public,
        kem_ciphertext=kem_ciphertext,
        stanzas=stanzas,
        version=version,
    )
    return header, data[: reader.pos], reader.rest()


def read_header(source: BinaryIO) -> Tuple[Header, bytes, bytes]:
    """Read a header off a stream. Returns (header, header_bytes, leftover).

    A header used to be a fixed 1168 bytes; a recipient list makes it depend on
    a count that is itself inside the header. The obvious fixes are both bad on
    a pipe: seeking is not available, and reading "enough" would mean trusting
    a length before anything is authenticated.

    So the parser does the deciding. It is handed a fixed read-ahead, and if it
    runs out it says exactly how many bytes the field it was reading is short
    by. That much (at least) is fetched and the parse is retried, up to
    MAX_HEADER_LEN. Retrying re-parses from the start, so each round asks for at
    least as much again as it already holds -- otherwise a thousand stanzas
    would mean a thousand re-parses, and the reader would be quadratic in a
    number an attacker chooses.

    Whatever was read past the end of the header is returned as `leftover`; it
    is the front of the payload and the caller has to put it back.
    """
    buf = streaming.read_exactly(source, HEADER_READ_AHEAD)
    while True:
        try:
            return parse_header(buf)
        except TruncatedError as exc:
            # What actually bounds this is the recipient count: a count outside
            # 1..MAX_RECIPIENTS is refused before a single stanza is read, and
            # MAX_HEADER_LEN is what that bound comes to in bytes. Clamping to
            # it as well is the belt to those braces -- `want` reaches zero and
            # the loop ends, whatever some future field decides it needs.
            want = min(max(exc.needed, len(buf)), MAX_HEADER_LEN - len(buf))
            more = streaming.read_exactly(source, want) if want else b""
            if not more:
                # Nothing more to be had: the file really is short, and the
                # parser's own message says which field ran out.
                raise
            buf += more


def encrypt(
    plaintext: bytes,
    recipient: PublicKey,
    suite: Suite = DEFAULT_SUITE,
    sender: Optional[SigningPrivateKey] = None,
) -> bytes:
    """Encrypt to a recipient, optionally signing as `sender`.

    Signing happens *before* encryption: the signature block is prepended to
    the plaintext and the whole thing is sealed, so the signer's identity is
    confidential and the signature covers what was actually written rather
    than the ciphertext. See signing.py for why that ordering matters.
    """
    return encrypt_many(plaintext, [recipient], suite=suite, sender=sender)


def encrypt_many(
    plaintext: bytes,
    to: Sequence[PublicKey],
    *,
    suite: Suite = DEFAULT_SUITE,
    sender: Optional[SigningPrivateKey] = None,
    hide_recipients: bool = False,
) -> bytes:
    """Encrypt to one or more recipients.

    With a single recipient and `hide_recipients` false this writes exactly the
    container `encrypt` always wrote, key id and all -- the older shape is not
    deprecated, it is what one recipient costs least. Anything else uses the
    recipient list, which names nobody and adds one stanza per recipient.
    """
    flags = _recipient_flags(to, hide_recipients)

    if sender is not None and flags & FLAG_RECIPIENTS:
        raise ValueError(
            "signing to a recipient list is not implemented: the signature "
            "binds the recipient, and binding one of several would verify for "
            "that recipient and fail for the rest"
        )

    payload = plaintext
    if sender is not None:
        payload = signing.sign_payload(plaintext, sender, to[0], suite)
        flags |= FLAG_SIGNED

    header, header_bytes, key = _seal_setup(to, suite, flags)
    ciphertext = suite.aead(key).encrypt(header.nonce, payload, header_bytes)
    return header_bytes + ciphertext


def _recipient_flags(to: Sequence[PublicKey], hide_recipients: bool) -> int:
    """Decide whether this file needs the recipient list.

    More than one recipient leaves no choice. One recipient does, and the
    choice is the caller's: the classic shape prints its recipient's key id to
    anyone who runs `info` on the file, and the list shape does not.
    """
    recipients.check_recipients(to)
    return FLAG_RECIPIENTS if len(to) > 1 or hide_recipients else FLAGS_NONE


def _seal_setup(
    to: Sequence[PublicKey], suite: Suite, flags: int
) -> Tuple[Header, bytes, bytes]:
    """Run the KEM(s) and build the header for a new container.

    Shared by the one-shot and chunked writers so that neither can drift from
    the other on the part that matters: which values go into the header, and
    which of them are bound into the key derivation.

    The two recipient shapes differ in where the payload key comes from, and
    the difference is forced. With one named recipient the key *is* the KEM
    output, run through HKDF -- nothing extra to store, nothing extra to get
    wrong. With several, no single key can come out of several independent
    encapsulations, so the payload key is random and each recipient gets a
    sealed copy of it. See recipients.py.
    """
    salt = os.urandom(SALT_LEN)
    # The payload key is unique per file (fresh ephemeral X25519 key, fresh
    # ML-KEM encapsulation, fresh salt -- or, in the list shape, 32 fresh
    # random bytes), so this nonce is never reused under it. A random nonce is
    # belt-and-braces; the freshness of the key is what actually rules out the
    # catastrophic nonce-reuse case. In chunked mode only the first 7 bytes
    # reach the nonce -- the chunk counter supplies the rest -- and the same
    # argument still applies.
    nonce = os.urandom(suite.nonce_len)

    if flags & FLAG_RECIPIENTS:
        file_key = os.urandom(suite.key_len)
        header = Header(
            suite=suite,
            flags=flags,
            key_id=NO_KEY_ID,
            salt=salt,
            nonce=nonce,
            stanzas=recipients.wrap_for_all(file_key, to, salt, suite),
        )
        return header, header.pack(), file_key

    (recipient,) = to
    ephemeral_public, kem_ciphertext, ikm = hybrid.encapsulate(recipient)
    header = Header(
        suite=suite,
        flags=flags,
        key_id=recipient.key_id,
        salt=salt,
        nonce=nonce,
        ephemeral_public=ephemeral_public,
        kem_ciphertext=kem_ciphertext,
    )
    key = hybrid.derive_key(
        ikm=ikm,
        salt=salt,
        suite=suite,
        ephemeral_public=ephemeral_public,
        kem_ciphertext=kem_ciphertext,
        recipient=recipient,
    )
    return header, header.pack(), key


def encrypt_stream(
    source: BinaryIO,
    sink: BinaryIO,
    recipient: PublicKey,
    suite: Suite = DEFAULT_SUITE,
) -> int:
    """Chunk-encrypt `source` into `sink`. Returns the number of chunks.

    Neither the plaintext nor the ciphertext is ever fully resident, so this is
    the path for files that do not fit in memory. There is no `sender`
    parameter: a signature covers a whole message and this writer never has one
    in hand. See streaming.py.
    """
    return encrypt_stream_many(source, sink, [recipient], suite=suite)


def encrypt_stream_many(
    source: BinaryIO,
    sink: BinaryIO,
    to: Sequence[PublicKey],
    *,
    suite: Suite = DEFAULT_SUITE,
    hide_recipients: bool = False,
) -> int:
    """Chunk-encrypt to one or more recipients. Returns the number of chunks.

    Chunking and the recipient list are independent: one is about the payload,
    the other about the header, and they compose without either knowing about
    the other. That they do is the payoff of putting both in the flags field
    rather than in the format version.
    """
    flags = _recipient_flags(to, hide_recipients) | FLAG_CHUNKED
    header, header_bytes, key = _seal_setup(to, suite, flags)
    sink.write(header_bytes)
    return streaming.seal(
        source, sink, key, suite, header.nonce_prefix, header_bytes
    )


@dataclass(frozen=True)
class Opened:
    """The result of opening a container.

    `signer` is the signing key the file carries, or None if it is unsigned.
    `verified` says whether that key was checked against one the caller
    supplied: a signature that verifies against the key embedded in the file
    proves the file is internally consistent, not who wrote it. Only a caller
    who pinned the sender's public key gets `verified=True`, and only that
    caller has learned an identity.

    `chunks` is None when the one-shot path ran and `plaintext` holds the whole
    message. It is a count when `decrypt_stream` streamed the file, and then
    `plaintext` is empty -- the point of streaming is that the plaintext never
    exists as one object.
    """

    plaintext: bytes
    signer: Optional[SigningPublicKey] = None
    verified: bool = False
    chunks: Optional[int] = None


def _open_setup(
    header: Header, identity: PrivateKey
) -> Tuple[PublicKey, bytes]:
    """Check the key id and re-derive the AEAD key from a parsed header.

    The mirror of _seal_setup, and shared for the same reason: the reader and
    the writer have to agree byte for byte on what the key is derived from, and
    two copies of that would only agree until one of them was edited.
    """
    recipient = identity.public_key()

    if header.multi:
        # No key id to check against: the stanzas name nobody, so the only way
        # to find out whether this file is ours is to try to open one.
        return recipient, recipients.unwrap(
            header.stanzas, identity, header.salt, header.suite
        )

    if header.key_id != recipient.key_id:
        raise WrongRecipientError(
            f"this file was encrypted for key id {header.key_id_hex}, "
            f"but the supplied identity is {recipient.key_id_hex}"
        )

    ikm = hybrid.decapsulate(
        identity, header.ephemeral_public, header.kem_ciphertext
    )
    key = hybrid.derive_key(
        ikm=ikm,
        salt=header.salt,
        suite=header.suite,
        ephemeral_public=header.ephemeral_public,
        kem_ciphertext=header.kem_ciphertext,
        recipient=recipient,
    )
    return recipient, key


def open_container(
    container: bytes,
    identity: PrivateKey,
    sender: Optional[SigningPublicKey] = None,
) -> Opened:
    """Decrypt a container and, if it is signed, check the signatures.

    Passing `sender` demands authentication: an unsigned file, a file signed by
    a different key, or a signature that does not verify all raise
    SignatureError rather than returning plaintext.
    """
    header, header_bytes, ciphertext = parse_header(container)
    if header.chunked:
        raise FormatError(
            "this container is chunked; open it with decrypt_stream, which "
            "does not need the whole file in memory"
        )

    recipient, key = _open_setup(header, identity)

    try:
        payload = header.suite.aead(key).decrypt(
            header.nonce, ciphertext, header_bytes
        )
    except InvalidTag:
        raise DecryptionError(
            "authentication failed: the file was modified, or it was not "
            "encrypted for this key"
        ) from None

    if not header.signed:
        if sender is not None:
            # Fail closed: the caller asked for authentication and this file
            # cannot provide it. Returning the plaintext with a shrug is how
            # "verified" quietly comes to mean nothing.
            raise SignatureError(
                "sender verification was requested, but this file is not signed"
            )
        return Opened(plaintext=payload)

    plaintext, signer = signing.open_payload(
        payload, recipient, header.suite, expected_sender=sender
    )
    return Opened(
        plaintext=plaintext, signer=signer, verified=sender is not None
    )


def decrypt(
    container: bytes,
    identity: PrivateKey,
    sender: Optional[SigningPublicKey] = None,
) -> bytes:
    """Decrypt a container and return just the plaintext.

    A thin wrapper over open_container for callers that do not care who signed.
    Note that it still *checks* a signature if one is present -- it only
    discards the answer about who produced it.
    """
    return open_container(container, identity, sender).plaintext


def decrypt_stream(
    source: BinaryIO,
    sink: BinaryIO,
    identity: PrivateKey,
    sender: Optional[SigningPublicKey] = None,
) -> Opened:
    """Decrypt a container from a stream, writing the plaintext to `sink`.

    Handles both payload shapes, because the reader does not get to choose:
    which one a file uses is a flag in its header, and the caller learns it
    only after parsing. A chunked container streams and comes back with
    `Opened.chunks` set and `Opened.plaintext` empty. A one-shot container
    cannot stream -- its AEAD tag covers the whole payload, so nothing can be
    released before all of it is in hand -- and is read whole and returned in
    full, exactly as `open_container` would.

    The header is taken from a bounded read off the front, so this works on a
    pipe: no seeking, and a hostile file cannot make the reader buffer more
    than MAX_HEADER_LEN bytes before the format is known.
    """
    header, header_bytes, leftover = read_header(source)

    if not header.chunked:
        opened = open_container(
            header_bytes + leftover + source.read(), identity, sender
        )
        sink.write(opened.plaintext)
        return opened

    if sender is not None:
        # Same fail-closed rule as the one-shot path: a chunked file is never
        # signed, so an authentication request it cannot satisfy is an error
        # rather than a plaintext with a caveat.
        raise SignatureError(
            "sender verification was requested, but this file is not signed"
        )

    _, key = _open_setup(header, identity)
    chunks = streaming.open_stream(
        streaming.PrefixedStream(leftover, source),
        sink,
        key,
        header.suite,
        header.nonce_prefix,
        header_bytes,
    )
    return Opened(plaintext=b"", chunks=chunks)
