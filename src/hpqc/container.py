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
    44      2      length of the ephemeral DH public key (32, or 56)
    46      32     ephemeral DH public key
    78      2      length of the ML-KEM ciphertext (1088, or 1568)
    80      1088   ML-KEM ciphertext
    1168    ...    AEAD ciphertext || 16-byte tag

    (offsets past 44 are those of suite 0x01; the two lengths come from the
     suite byte, and a suite using X448 + ML-KEM-1024 makes them 56 and 1568)

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

* **Variable-size fields are length-prefixed, and the prefix is checked rather
  than believed.** Every length is looked up from the suite byte and the
  prefix must match it. That is what let ML-KEM-1024 arrive as two rows in
  suites.py rather than as a branch here -- and it is also why a container has
  exactly one KEM: a prefix that *selected* the parse instead of confirming it
  would be a length trusted before anything is authenticated.

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

All three flags are independent, and every combination of them is a shape this
build writes. Signed-and-chunked took some doing, because a signature is a
statement about a whole message and a chunked writer never holds one: it is
reconciled by signing a *digest*, computed in a first pass over the input, with
the signature block written in front of the plaintext so that a reader meets it
before anything is released. See signing.py.

Signing composes with a recipient list, but not by the obvious route. The
signature normally binds the recipient's public keys into the signed message,
which is what stops surreptitious forwarding (see signing.py) -- and a file
with a recipient list names no recipients, so there is nothing there to bind.
What gets bound instead is the header itself, stanzas and all: the delivery
rather than a description of it. Which of the two constructions a file uses is
decided by flag bit 2, and the reader knows it before it opens anything.
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
from .hybrid import SALT_LEN
from .keys import (
    KEY_ID_LEN,
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
            f"ephemeral {suite.kem.dh_name} public key", suite.kem.dh_len
        )
        kem_ciphertext = reader.take_prefixed(
            f"{suite.kem.kem_name} ciphertext", suite.kem.kem_ciphertext_len
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
    """Encrypt to a single named recipient, optionally signing as `sender`.

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
    if sender is not None:
        flags |= FLAG_SIGNED

    # The header is built first, because with a recipient list the signature is
    # computed over it. Nothing circular in that: the stanzas depend on the
    # file key, the header on the stanzas, and only then is the payload sealed.
    header, header_bytes, key = _seal_setup(to, suite, flags)

    payload = plaintext
    if sender is not None:
        payload = (
            signing.sign_payload_to_container(
                plaintext, sender, header_bytes, suite
            )
            if header.multi
            else signing.sign_payload(plaintext, sender, to[0], suite)
        )

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


def _check_suite(to: Sequence[PublicKey], suite: Suite) -> None:
    """Every recipient's key must be the KEM the suite names.

    A container carries one suite byte, so it carries one KEM. Mixing key types
    in one file is refused here rather than half-supported: see suites.py.
    """
    wrong = [r for r in to if r.kem.id != suite.kem.id]
    if wrong:
        raise ValueError(
            f"suite {suite.name} needs {suite.kem.name} recipients, but "
            f"{len(wrong)} of {len(to)} " + ("is", "are")[len(wrong) > 1] + " "
            + ", ".join(sorted({r.kem.name for r in wrong}))
        )


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
    _check_suite(to, suite)
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
    sender: Optional[SigningPrivateKey] = None,
    digest: Optional[bytes] = None,
) -> int:
    """Chunk-encrypt to one or more recipients. Returns the number of chunks.

    All three flags are independent and compose: one is about the payload
    shape, one about the header's recipients, one about authentication. That
    they do is the payoff of putting each in the flags field rather than in the
    format version, which has still never moved.

    Signing needs `digest`, which is `signing.digest_stream` over the same
    plaintext this call is about to seal. The caller supplies it rather than
    this function computing it, because computing it means reading the input a
    second time and only the caller knows how to get another reader for it.
    """
    if (sender is None) != (digest is None):
        raise ValueError(
            "sender and digest go together: signing a stream needs the digest "
            "of the plaintext, taken before the first chunk is written"
        )

    flags = _recipient_flags(to, hide_recipients) | FLAG_CHUNKED
    if sender is not None:
        flags |= FLAG_SIGNED

    header, header_bytes, key = _seal_setup(to, suite, flags)

    if sender is not None:
        # The block goes in front of the plaintext, inside the AEAD, exactly as
        # it does in a one-shot container -- so the framing does not change at
        # all, and neither does the signer's confidentiality.
        source = streaming.PrefixedStream(
            signing.sign_stream_prologue(digest, sender, header_bytes, suite),
            source,
        )

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

    if recipient.kem.id != header.suite.kem.id:
        raise WrongRecipientError(
            f"this file uses {header.suite.kem.name}, but the supplied "
            f"identity is {recipient.kem.name}"
        )

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

    if header.multi:
        # No recipient to bind, so the container was bound instead -- and the
        # header handed over here is the one this reader parsed, never one the
        # payload got to name. See signing.py.
        plaintext, signer = signing.open_container_payload(
            payload, header_bytes, header.suite, expected_sender=sender
        )
    else:
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

    if sender is not None and not header.signed:
        # Same fail-closed rule as the one-shot path: an authentication request
        # this file cannot satisfy is an error, not a plaintext with a caveat.
        raise SignatureError(
            "sender verification was requested, but this file is not signed"
        )

    _, key = _open_setup(header, identity)
    payload = streaming.PrefixedStream(leftover, source)

    if not header.signed:
        chunks = streaming.open_stream(
            payload, sink, key, header.suite, header.nonce_prefix, header_bytes
        )
        return Opened(plaintext=b"", chunks=chunks)

    # The verifier sits between the chunk reader and the caller's sink: it
    # takes the signature block off the front, holds everything back until the
    # claimed signer has been checked, and digests what it passes on.
    verifier = signing.StreamVerifier(sink, expected_sender=sender)
    chunks = streaming.open_stream(
        payload, verifier, key, header.suite, header.nonce_prefix, header_bytes
    )
    signer = verifier.finish(header_bytes, header.suite)
    return Opened(
        plaintext=b"",
        signer=signer,
        verified=sender is not None,
        chunks=chunks,
    )
