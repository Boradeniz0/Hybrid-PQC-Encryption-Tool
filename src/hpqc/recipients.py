"""Encrypting one file to several recipients, without naming any of them.

The v1 container derives its AEAD key straight from the KEM: encapsulate to
the recipient, run the shared secrets through HKDF, seal the payload under the
result. That is the smallest thing that works, and it works for exactly one
recipient -- there is no way to make two independent encapsulations, to two
different public keys, arrive at the same key. So a second recipient needs a
level of indirection, and it is the same one PGP, CMS and age all reach for:

  1. Pick a random **file key**. This is what actually seals the payload.
  2. For each recipient, run the hybrid KEM against *their* public key and
     derive a **wrapping key** from it.
  3. Seal the file key under each wrapping key. Each sealed copy is a
     **stanza**, and the header carries one per recipient.

Any recipient recovers the file key from their own stanza and reads the file.

Three things about this are easy to get wrong.

**The stanzas do not say who they are for.** There is no key id in a stanza, on
purpose. A recipient list in the clear tells anyone holding the file who the
other recipients are -- and for a group message that is often worth more than
the contents, because it proves those people were talking. So the reader
instead *tries* each stanza in turn and keeps the one that opens; the AEAD tag
is the test. What the file still leaks is how many recipients there are, which
is why `hpqc info` reports a count and nothing else.

The cost is paid twice. Opening a file is O(recipients) decapsulations rather
than O(1), which is microseconds and does not matter. And "wrong key" can no
longer name the key the file was for, because the file does not know: it
becomes "none of these stanzas opened", which is less helpful and is the
honest answer.

**A wrapping key is used exactly once, so its nonce is all zeros.** A nonce
exists to stop two messages being encrypted under one key. Every stanza has a
fresh ephemeral X25519 key and a fresh ML-KEM encapsulation behind it, so its
wrapping key is unique to that stanza and seals exactly one thing. A random
nonce here would add twelve bytes an attacker could fiddle with and buy
nothing. (`hybrid.derive_key` is still salted, and the salt is shared by every
stanza in the file -- differing input keying material is what separates them.)

**The wrapping key is bound to the recipient it was derived for.** The HKDF
info covers the stanza's ephemeral public key, its ML-KEM ciphertext, and the
recipient's own two public keys, under a label distinct from the payload's. A
stanza therefore cannot be moved to another file or another recipient, and a
wrapping key can never collide with the key that seals a payload.

What this does *not* defend against is inherent to multi-recipient encryption
rather than a gap here: every recipient learns the file key, so any one of them
can decrypt the file, re-wrap the same file key to somebody else, and produce
a container indistinguishable from one the original sender wrote. Sender
authentication is the only answer to that, and it is a separate flag.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence, Tuple

from cryptography.exceptions import InvalidTag

from . import hybrid
from .errors import WrongRecipientError
from .hybrid import MLKEM768_CIPHERTEXT_LEN
from .keys import X25519_KEY_LEN, PrivateKey, PublicKey
from .suites import Suite
from .wire import U16, Reader

#: The AEAD tag on a wrapped file key. Both suites use 16 bytes.
WRAP_TAG_LEN = 16

#: An upper bound on the recipient list, so a hostile header cannot make the
#: reader buffer without limit before anything has been authenticated. It is
#: far past any plausible use: 1024 recipients is a 1.2 MB header.
MAX_RECIPIENTS = 1024


@dataclass(frozen=True)
class Stanza:
    """One recipient's sealed copy of the file key.

    Deliberately anonymous: an ephemeral public key, a KEM ciphertext and a
    sealed blob, none of which identifies the recipient to anyone who cannot
    already decapsulate.
    """

    ephemeral_public: bytes
    kem_ciphertext: bytes
    wrapped_key: bytes

    def pack(self) -> bytes:
        return b"".join(
            (
                U16.pack(len(self.ephemeral_public)),
                self.ephemeral_public,
                U16.pack(len(self.kem_ciphertext)),
                self.kem_ciphertext,
                U16.pack(len(self.wrapped_key)),
                self.wrapped_key,
            )
        )


def wrapped_key_len(suite: Suite) -> int:
    """How long a sealed file key is for this suite."""
    return suite.key_len + WRAP_TAG_LEN


def stanza_len(suite: Suite) -> int:
    """The exact size of one stanza on the wire, for header-size arithmetic."""
    return (
        U16.size + X25519_KEY_LEN
        + U16.size + MLKEM768_CIPHERTEXT_LEN
        + U16.size + wrapped_key_len(suite)
    )


def read_stanza(reader: Reader, suite: Suite) -> Stanza:
    """Parse one stanza, checking every length against what the suite fixes."""
    return Stanza(
        ephemeral_public=reader.take_prefixed(
            "ephemeral X25519 public key", X25519_KEY_LEN
        ),
        kem_ciphertext=reader.take_prefixed(
            "ML-KEM-768 ciphertext", MLKEM768_CIPHERTEXT_LEN
        ),
        wrapped_key=reader.take_prefixed(
            "wrapped file key", wrapped_key_len(suite)
        ),
    )


def check_recipients(recipients: Sequence[PublicKey]) -> None:
    """Refuse a recipient list that cannot mean what the caller intended.

    An empty list would produce a file nobody can open. A repeated recipient
    would produce two stanzas that both open for the same person -- harmless,
    but it is far more likely to be `-r bob.pub -r bob.pub` by mistake than a
    deliberate choice, and silently doing something the caller did not mean is
    how a *missing* recipient goes unnoticed.
    """
    if not recipients:
        raise ValueError("a container needs at least one recipient")
    if len(recipients) > MAX_RECIPIENTS:
        raise ValueError(
            f"{len(recipients)} recipients is more than the {MAX_RECIPIENTS} "
            "this format allows"
        )
    seen = set()
    for recipient in recipients:
        if recipient.key_id in seen:
            raise ValueError(
                f"recipient key id {recipient.key_id_hex} was given twice"
            )
        seen.add(recipient.key_id)


def wrap(
    file_key: bytes, recipient: PublicKey, salt: bytes, suite: Suite
) -> Stanza:
    """Seal `file_key` for one recipient."""
    ephemeral_public, kem_ciphertext, ikm = hybrid.encapsulate(recipient)
    wrapping_key = hybrid.derive_key(
        ikm=ikm,
        salt=salt,
        suite=suite,
        ephemeral_public=ephemeral_public,
        kem_ciphertext=kem_ciphertext,
        recipient=recipient,
        label=hybrid.WRAP_LABEL,
    )
    return Stanza(
        ephemeral_public=ephemeral_public,
        kem_ciphertext=kem_ciphertext,
        wrapped_key=suite.aead(wrapping_key).encrypt(
            _zero_nonce(suite), file_key, None
        ),
    )


def wrap_for_all(
    file_key: bytes,
    recipients: Sequence[PublicKey],
    salt: bytes,
    suite: Suite,
) -> Tuple[Stanza, ...]:
    """Seal `file_key` once per recipient, in the order they were given.

    The order carries no information -- a stanza cannot be attributed to a
    recipient without their private key -- so there is nothing to shuffle.
    """
    check_recipients(recipients)
    return tuple(wrap(file_key, r, salt, suite) for r in recipients)


def unwrap(
    stanzas: Iterable[Stanza], identity: PrivateKey, salt: bytes, suite: Suite
) -> bytes:
    """Recover the file key from whichever stanza belongs to `identity`.

    Every stanza is tried in order and the first one whose tag verifies wins.
    The loop stops there, so how long this takes reveals *which* slot is the
    caller's to anyone able to measure it -- an observer holding only the file
    still learns nothing but the count. Constant-time trial decryption would
    mean always running every decapsulation, and that is a trade this tool does
    not currently make; see the scope notes in the README.
    """
    recipient = identity.public_key()
    count = 0
    for count, stanza in enumerate(stanzas, start=1):
        ikm = hybrid.decapsulate(
            identity, stanza.ephemeral_public, stanza.kem_ciphertext
        )
        wrapping_key = hybrid.derive_key(
            ikm=ikm,
            salt=salt,
            suite=suite,
            ephemeral_public=stanza.ephemeral_public,
            kem_ciphertext=stanza.kem_ciphertext,
            recipient=recipient,
            label=hybrid.WRAP_LABEL,
        )
        try:
            return suite.aead(wrapping_key).decrypt(
                _zero_nonce(suite), stanza.wrapped_key, None
            )
        except InvalidTag:
            continue

    # No key id to quote: the stanzas do not carry one, which is the point.
    raise WrongRecipientError(
        f"none of this file's {count} recipient slot(s) could be opened with "
        f"key id {recipient.key_id_hex}; it was encrypted for someone else"
    )


def _zero_nonce(suite: Suite) -> bytes:
    """The nonce every stanza uses. See the module docstring."""
    return b"\x00" * suite.nonce_len
