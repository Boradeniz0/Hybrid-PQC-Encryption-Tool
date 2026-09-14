#!/usr/bin/env python3
"""Generate the frozen known-answer vectors under tests/vectors/.

Run it and it writes any vector file that does not exist yet; existing files are
left alone, because their whole purpose is to be frozen. `--force` overwrites,
and is only correct when the format has deliberately changed -- which also means
bumping the format version and regenerating under a new name rather than
quietly replacing history.

    python tools/make_vectors.py [--force]

Encryption cannot be made deterministic: the ephemeral X25519 key, the ML-KEM
encapsulation randomness, the salt, the nonce and (for ML-DSA) the signature
hedging are all fresh, and the backend exposes no way to inject them. So the
vectors are recorded from one run and verified on the *decryption* side, which
is fully deterministic.

Every key in these files is a test key. They are published on purpose and must
never be used for anything real.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
# seal() lives with the tests because it models a malicious sender; the
# forwarding vector below needs exactly that, so reuse it rather than copy it.
sys.path.insert(0, str(ROOT / "tests"))

from helpers import seal  # noqa: E402

from hpqc import (  # noqa: E402
    hybrid,
    kems,
    recipients,
    signing,
    streaming,
    suites,
    wrapping,
)
from hpqc.container import (  # noqa: E402
    FLAG_CHUNKED,
    FLAG_RECIPIENTS,
    FLAG_SIGNED,
    _seal_setup,
    encrypt,
    encrypt_many,
    encrypt_stream,
    encrypt_stream_many,
)
from hpqc.keys import PrivateKey, SigningPrivateKey  # noqa: E402

import unicodedata  # noqa: E402

VECTORS = ROOT / "tests" / "vectors"

PLAINTEXTS = [
    b"",
    b"hpqc test vector v1\n",
    bytes(range(256)),
]

TEST_KEY_WARNING = (
    "Every key in this file is a TEST KEY, published deliberately; never use "
    "one for anything real."
)


def _filler(label: bytes, length: int) -> bytes:
    """Deterministic non-secret bytes, so the derivation vectors are stable."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(label + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def build_v1() -> dict:
    """Unsigned containers: the v1 wire format and the key derivation."""
    identity = PrivateKey.generate()
    public = identity.public_key()

    data = {
        "note": (
            "Frozen known-answer vectors for the hpqc v1 wire format. "
            + TEST_KEY_WARNING
        ),
        "format_version": 1,
        "hkdf_label": hybrid.HKDF_LABEL.decode("ascii"),
        "identity": identity.encode(),
        "public": public.encode(),
        "key_id": public.key_id_hex,
        "public_blob": public.to_bytes().hex(),
        "private_blob": identity.to_bytes().hex(),
        "containers": [],
        "derivations": [],
    }

    for cli_name, suite in sorted(suites.BY_CLI_NAME.items()):
        for plaintext in PLAINTEXTS:
            data["containers"].append({
                "suite": cli_name,
                "suite_id": suite.id,
                "suite_name": suite.name,
                "plaintext": plaintext.hex(),
                "container": encrypt(plaintext, public, suite).hex(),
            })

        ikm = _filler(b"hpqc-vector-ikm", 2 * hybrid.SHARED_SECRET_LEN)
        salt = _filler(b"hpqc-vector-salt", hybrid.SALT_LEN)
        epk = _filler(b"hpqc-vector-epk", 32)
        kem_ct = _filler(b"hpqc-vector-kemct", hybrid.MLKEM768_CIPHERTEXT_LEN)
        data["derivations"].append({
            "suite": cli_name,
            "suite_id": suite.id,
            "ikm": ikm.hex(),
            "salt": salt.hex(),
            "ephemeral_public": epk.hex(),
            "kem_ciphertext": kem_ct.hex(),
            "key": hybrid.derive_key(
                ikm=ikm, salt=salt, suite=suite,
                ephemeral_public=epk, kem_ciphertext=kem_ct,
                recipient=public,
            ).hex(),
        })

    return data


def build_v1_signed() -> dict:
    """Signed containers, plus one that must never verify.

    Two things are recorded beyond the round trips:

    * `signed_messages` -- the SHA-256 of the exact byte string the signatures
      are computed over, for fixed inputs. This is what pins the construction:
      drop the recipient from it, reorder a field, change the label, and the
      digest moves. A recorded *signature* cannot do this job, because a
      signature made under the old construction fails under a new one too, just
      for the wrong reason.

    * `forwarded` -- a container addressed to `identity` whose signature was
      made for a different recipient. It must keep failing. This guards a build
      that starts accepting forwarded containers outright -- verification
      skipped, or the sender-supplied key trusted without checking the binding.
    """
    identity = PrivateKey.generate()
    public = identity.public_key()
    signer = SigningPrivateKey.generate()
    signer_public = signer.public_key()

    other = PrivateKey.generate().public_key()

    data = {
        "note": (
            "Frozen known-answer vectors for hpqc sender authentication "
            "(Ed25519 + ML-DSA-65, signed then encrypted). " + TEST_KEY_WARNING
        ),
        "format_version": 1,
        "flag_signed": FLAG_SIGNED,
        "sig_label": signing.SIG_LABEL.decode("ascii"),
        "signature_block_len": signing.SIGNATURE_BLOCK_LEN,
        "identity": identity.encode(),
        "public": public.encode(),
        "key_id": public.key_id_hex,
        "signer_private": signer.encode(),
        "signer": signer_public.encode(),
        "signer_key_id": signer_public.key_id_hex,
        "signer_blob": signer_public.to_bytes().hex(),
        "containers": [],
        "signed_messages": [],
    }

    # Digests rather than the messages themselves: signed_message embeds two
    # public keys, so the full byte string is ~3 KB of already-recorded data.
    for cli_name, suite in sorted(suites.BY_CLI_NAME.items()):
        for plaintext in (b"", b"pay the bearer 100\n"):
            message = signing.signed_message(
                plaintext, signer_public, public, suite
            )
            data["signed_messages"].append({
                "suite": cli_name,
                "suite_id": suite.id,
                "plaintext": plaintext.hex(),
                "length": len(message),
                "sha256": hashlib.sha256(message).hexdigest(),
            })

    # A signed container carries a fixed 5365-byte block whatever the payload
    # size, so the plaintext-length dimension adds bytes to this file without
    # adding coverage. Both suites still matter: the suite id is inside the
    # signed message.
    for cli_name, suite in sorted(suites.BY_CLI_NAME.items()):
        for plaintext in PLAINTEXTS[:2]:
            data["containers"].append({
                "suite": cli_name,
                "suite_id": suite.id,
                "suite_name": suite.name,
                "plaintext": plaintext.hex(),
                "container": encrypt(
                    plaintext, public, suite, sender=signer
                ).hex(),
            })

    forwarded_plaintext = b"pay the bearer 100\n"
    data["forwarded"] = {
        "note": (
            "Signed for a different recipient and re-sealed to `identity`: "
            "opening it must always raise SignatureError. If this ever "
            "verifies, the recipient has stopped being bound into the signed "
            "message and surreptitious forwarding works again."
        ),
        "plaintext": forwarded_plaintext.hex(),
        "intended_recipient_public": other.encode(),
        "container": seal(
            signing.sign_payload(
                forwarded_plaintext, signer, other, suites.DEFAULT_SUITE
            ),
            public,
        ).hex(),
    }

    return data


def build_v1_wrapped() -> dict:
    """Passphrase-wrapped private keys.

    Opening a wrapped key is deterministic given the file and the passphrase, so
    one recorded file pins the whole construction: the byte layout, how scrypt is
    called, what goes into the associated data, and the NFC normalisation of the
    passphrase. Change any of those and this file stops opening.

    The cost is deliberately low so the tests stay quick. The parameters live
    inside the file, which is exactly what makes that safe -- the *default* cost
    is asserted separately, in tests/test_wrapping.py.
    """
    # NFD: the same characters as "cafe\u0301 passphrase" typed on a system that
    # decomposes accents. Recording this form and opening with the composed one
    # is what pins the normalisation.
    passphrase = unicodedata.normalize("NFD", "caf\u00e9 passphrase \u00fczerine")
    params = wrapping.Params(log_n=12)

    identity = PrivateKey.generate()
    signer = SigningPrivateKey.generate()

    return {
        "note": (
            "Frozen known-answer vectors for hpqc passphrase-wrapped private "
            "keys (scrypt + ChaCha20-Poly1305). " + TEST_KEY_WARNING + " The "
            "passphrase is recorded in NFD form on purpose; opening with its "
            "NFC form must work, which is what pins the normalisation."
        ),
        "format_version": wrapping.WRAP_VERSION,
        "wrap_label": wrapping.WRAP_LABEL.decode("ascii"),
        "passphrase_nfd": passphrase,
        "scrypt": {"log_n": params.log_n, "r": params.r, "p": params.p},
        "keys": [
            {
                "kind": wrapping.KIND_IDENTITY,
                "kind_name": "identity",
                "wrapped": identity.encode(passphrase, params),
                "blob": identity.to_bytes().hex(),
                "key_id": identity.public_key().key_id_hex,
                "public": identity.public_key().encode(),
            },
            {
                "kind": wrapping.KIND_SIGNING_IDENTITY,
                "kind_name": "signing identity",
                "wrapped": signer.encode(passphrase, params),
                "blob": signer.to_bytes().hex(),
                "key_id": signer.public_key().key_id_hex,
                "public": signer.public_key().encode(),
            },
        ],
    }


def build_v1_chunked() -> dict:
    """Chunked containers, and the nonce construction that holds them together.

    Two things are recorded, for the same reason the signed vectors record two:

    * `nonces` -- the STREAM nonce for fixed (prefix, index, final) triples.
      This is what pins the construction. A recorded *container* cannot: move
      the counter, widen it, swap the final-chunk byte, and the writer and the
      reader move together, so the recorded container fails -- but it fails
      because the key no longer matches, not because the layout changed. The
      vector would go on "passing" while the property it guarded was gone.

    * `containers` -- recorded chunked containers, checked by the digest of
      what they decrypt to. These prove the whole path end to end, including
      that a file written before a change is still readable after it.

    The multi-chunk plaintext is recorded as a length and a SHA-256 rather than
    inline: it is 64 KiB of filler whose only job is to cross a chunk boundary,
    and a known-answer test does not need it spelled out.
    """
    identity = PrivateKey.generate()
    public = identity.public_key()

    def sealed(plaintext: bytes, suite) -> bytes:
        sink = io.BytesIO()
        encrypt_stream(io.BytesIO(plaintext), sink, public, suite)
        return sink.getvalue()

    data = {
        "note": (
            "Frozen known-answer vectors for hpqc chunked (streamed) "
            "containers. " + TEST_KEY_WARNING
        ),
        "format_version": 1,
        "flag_chunked": FLAG_CHUNKED,
        "chunk_size": streaming.CHUNK_SIZE,
        "tag_len": streaming.TAG_LEN,
        "wire_chunk_size": streaming.WIRE_CHUNK_SIZE,
        "nonce_prefix_len": streaming.NONCE_PREFIX_LEN,
        "max_chunks": streaming.MAX_CHUNKS,
        "identity": identity.encode(),
        "public": public.encode(),
        "key_id": public.key_id_hex,
        "nonces": [],
        "containers": [],
    }

    prefix = _filler(b"hpqc-vector-prefix", streaming.NONCE_PREFIX_LEN)
    for index in (0, 1, 2, 255, 256, 0x01020304, streaming.MAX_CHUNKS - 1):
        for final in (False, True):
            data["nonces"].append({
                "prefix": prefix.hex(),
                "index": index,
                "final": final,
                "nonce": streaming.chunk_nonce(prefix, index, final).hex(),
            })

    # Small enough to record inline, and one of each suite.
    for cli_name, suite in sorted(suites.BY_CLI_NAME.items()):
        plaintext = b"hpqc chunked test vector v1\n"
        data["containers"].append({
            "suite": cli_name,
            "suite_id": suite.id,
            "chunks": 1,
            "plaintext": plaintext.hex(),
            "plaintext_len": len(plaintext),
            "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
            "container": sealed(plaintext, suite).hex(),
        })

    # One byte past a chunk boundary: the smallest input that needs a
    # non-final chunk, and therefore the smallest one that exercises the
    # final-chunk marker at all.
    big = _filler(b"hpqc-vector-chunked", streaming.CHUNK_SIZE + 1)
    data["containers"].append({
        "suite": "chacha20",
        "suite_id": suites.DEFAULT_SUITE.id,
        "chunks": 2,
        "plaintext_len": len(big),
        "plaintext_sha256": hashlib.sha256(big).hexdigest(),
        "container": sealed(big, suites.DEFAULT_SUITE).hex(),
    })

    return data


def build_v1_recipients() -> dict:
    """Containers with a recipient list, and the wrapping-key derivation.

    Three things are recorded, and only the second of them pins the scheme.

    * `containers` -- files with two and three recipients, each with every
      recipient's private key, so the test can check that *each* of them opens
      it and that a fourth identity does not. This is the end-to-end proof that
      a file written today is still readable after a change.

    * `wrappings` -- for fixed inputs, the derived wrapping key and the exact
      sealed file key it produces. This is what a recorded container cannot do:
      change the HKDF label, drop the salt, stop binding the recipient's own
      public keys, and the writer and reader move together, so a recorded
      container still round-trips. Only a recorded derivation notices. The
      zero nonce is spelled out here for the same reason.

    * `layout` -- the constants a reader has to agree on before it can find a
      stanza at all.
    """
    identities = [PrivateKey.generate() for _ in range(3)]
    publics = [k.public_key() for k in identities]
    stranger = PrivateKey.generate()

    data = {
        "note": (
            "Frozen known-answer vectors for hpqc containers with a recipient "
            "list. " + TEST_KEY_WARNING
        ),
        "format_version": 1,
        "flag_recipients": FLAG_RECIPIENTS,
        "wrap_label": hybrid.WRAP_LABEL.decode("ascii"),
        "layout": {
            "max_recipients": recipients.MAX_RECIPIENTS,
            "wrap_tag_len": recipients.WRAP_TAG_LEN,
            "count_offset": 44,
            "first_stanza_offset": 46,
            "stanza_len": {
                name: recipients.stanza_len(suite)
                for name, suite in sorted(suites.BY_CLI_NAME.items())
            },
            "no_key_id": "00" * 8,
        },
        "identities": [k.encode() for k in identities],
        "publics": [p.encode() for p in publics],
        "key_ids": [p.key_id_hex for p in publics],
        "stranger": stranger.encode(),
        "containers": [],
        "wrappings": [],
    }

    plaintext = b"hpqc recipient-list test vector v1\n"
    for cli_name, suite in sorted(suites.BY_CLI_NAME.items()):
        for count in (1, 2, 3):
            data["containers"].append({
                "suite": cli_name,
                "suite_id": suite.id,
                "recipients": count,
                "hidden_single": count == 1,
                "plaintext": plaintext.hex(),
                "container": encrypt_many(
                    plaintext,
                    publics[:count],
                    suite=suite,
                    hide_recipients=count == 1,
                ).hex(),
            })

    # One chunked file with a recipient list: the two flags are independent and
    # a vector is the cheapest way to say so and keep saying so.
    chunked_plaintext = _filler(b"hpqc-vector-recipients-chunked", streaming.CHUNK_SIZE + 1)
    sink = io.BytesIO()
    encrypt_stream_many(io.BytesIO(chunked_plaintext), sink, publics[:2])
    data["chunked_container"] = {
        "suite": "chacha20",
        "recipients": 2,
        "chunks": 2,
        "flags": FLAG_RECIPIENTS | FLAG_CHUNKED,
        "plaintext_len": len(chunked_plaintext),
        "plaintext_sha256": hashlib.sha256(chunked_plaintext).hexdigest(),
        "container": sink.getvalue().hex(),
    }

    for cli_name, suite in sorted(suites.BY_CLI_NAME.items()):
        ikm = _filler(b"hpqc-vector-wrap-ikm", 2 * hybrid.SHARED_SECRET_LEN)
        salt = _filler(b"hpqc-vector-wrap-salt", hybrid.SALT_LEN)
        epk = _filler(b"hpqc-vector-wrap-epk", 32)
        kem_ct = _filler(b"hpqc-vector-wrap-kemct", hybrid.MLKEM768_CIPHERTEXT_LEN)
        file_key = _filler(b"hpqc-vector-file-key", suite.key_len)
        wrapping_key = hybrid.derive_key(
            ikm=ikm, salt=salt, suite=suite,
            ephemeral_public=epk, kem_ciphertext=kem_ct,
            recipient=publics[0], label=hybrid.WRAP_LABEL,
        )
        data["wrappings"].append({
            "suite": cli_name,
            "suite_id": suite.id,
            "ikm": ikm.hex(),
            "salt": salt.hex(),
            "ephemeral_public": epk.hex(),
            "kem_ciphertext": kem_ct.hex(),
            "recipient_index": 0,
            "file_key": file_key.hex(),
            "nonce": ("00" * suite.nonce_len),
            "wrapping_key": wrapping_key.hex(),
            "wrapped_key": suite.aead(wrapping_key)
            .encrypt(b"\x00" * suite.nonce_len, file_key, None)
            .hex(),
        })

    return data


def build_v1_signed_recipients() -> dict:
    """Signed containers with a recipient list, where the header is what is bound.

    A file with a recipient list names no recipients, so the usual construction
    -- put the recipient's public keys inside the signed message -- has nothing
    to work with. The header is bound instead, every stanza of it. Three things
    are recorded:

    * `signed_messages` -- the SHA-256 of the exact byte string the signatures
      cover, for fixed inputs. This is what pins the construction: drop the
      header, drop its length prefix, change the label, and the digest moves.
      A recorded signature cannot do that job, because it stops verifying under
      any change at all and so names none of them.

    * `containers` -- signed files to one, two and three recipients. Every
      recipient must verify the same signature, and a fourth identity must not
      be able to open the file at all.

    * `forwarded` -- a signature made over one header, re-sealed into a
      different container addressed to the same identity. It must keep failing.
      This is surreptitious forwarding as a recipient would actually run it,
      frozen, so a build that stopped binding the header fails here.
    """
    identities = [PrivateKey.generate() for _ in range(3)]
    publics = [k.public_key() for k in identities]
    stranger = PrivateKey.generate()
    signer = SigningPrivateKey.generate()
    signer_public = signer.public_key()

    data = {
        "note": (
            "Frozen known-answer vectors for hpqc containers that are both "
            "signed and written to a recipient list. " + TEST_KEY_WARNING
        ),
        "format_version": 1,
        "flags": FLAG_SIGNED | FLAG_RECIPIENTS,
        "sig_container_label": signing.SIG_CONTAINER_LABEL.decode("ascii"),
        "sig_label": signing.SIG_LABEL.decode("ascii"),
        "identities": [k.encode() for k in identities],
        "publics": [p.encode() for p in publics],
        "stranger": stranger.encode(),
        "signer": signer.encode(),
        "signer_public": signer_public.encode(),
        "signer_key_id": signer_public.key_id_hex,
        "signed_messages": [],
        "containers": [],
    }

    plaintext = b"hpqc signed recipient-list test vector v1\n"

    for cli_name, suite in sorted(suites.BY_CLI_NAME.items()):
        for count in (1, 2, 3):
            data["containers"].append({
                "suite": cli_name,
                "suite_id": suite.id,
                "recipients": count,
                "plaintext": plaintext.hex(),
                "container": encrypt_many(
                    plaintext,
                    publics[:count],
                    suite=suite,
                    sender=signer,
                    hide_recipients=count == 1,
                ).hex(),
            })

        # Fixed header bytes, so the digest is a known answer rather than a
        # record of one random run. They never have to parse: the signed
        # message is a byte string, and this pins the byte string.
        header_bytes = _filler(b"hpqc-vector-signed-header", 1220)
        message = signing.container_signed_message(
            plaintext, signer_public, header_bytes, suite
        )
        data["signed_messages"].append({
            "suite": cli_name,
            "suite_id": suite.id,
            "header_bytes": header_bytes.hex(),
            "header_len": len(header_bytes),
            "plaintext": plaintext.hex(),
            "message_len": len(message),
            "message_sha256": hashlib.sha256(message).hexdigest(),
        })

    # Surreptitious forwarding, frozen. The signature is made over one header
    # and the payload is then sealed into a different container -- exactly what
    # a recipient can build, since they hold the file key.
    victim = identities[0]
    suite = suites.DEFAULT_SUITE
    elsewhere, elsewhere_bytes, _ = _seal_setup(
        [publics[1]], suite, FLAG_RECIPIENTS | FLAG_SIGNED
    )
    payload = signing.sign_payload_to_container(
        plaintext, signer, elsewhere_bytes, suite
    )
    header, header_bytes, key = _seal_setup(
        [victim.public_key()], suite, FLAG_RECIPIENTS | FLAG_SIGNED
    )
    data["forwarded"] = {
        "note": (
            "signed for one container, re-sealed into another addressed to "
            "identities[0]; opening it must raise SignatureError"
        ),
        "suite": "chacha20",
        "container": (
            header_bytes
            + suite.aead(key).encrypt(header.nonce, payload, header_bytes)
        ).hex(),
        "opens_for": 0,
    }

    return data


def build_v1_mlkem1024() -> dict:
    """The second hybrid KEM: X448 + ML-KEM-1024, suites 0x03 and 0x04.

    Four things are recorded, and the first two are the ones a container cannot
    stand in for.

    * `kem` -- the parameter set table itself. Every length the container
      parser checks is looked up from it, so a typo there would produce a
      format that agrees with itself and with nothing else. Freezing the
      numbers is the only way a self-consistent mistake gets caught.

    * `derivations` -- the derived key for fixed inputs under each suite. The
      transcript now covers two variable-length fields whose sizes come from
      the suite byte; drop the suite byte from it, or reorder the fields, and
      a recorded container still round-trips.

    * `keys` -- one identity and its public key. This pins the blob layout:
      one type byte, a 56-byte X448 key, a 1568-byte ML-KEM key, and a private
      blob whose 64-byte seed is exactly as long as ML-KEM-768's -- which is
      why the type byte has to exist at all.

    * `containers` -- every shape at this parameter set: one recipient, a
      recipient list, a signed list, and a chunked file.
    """
    kem = kems.X448_MLKEM1024
    identities = [PrivateKey.generate(kem) for _ in range(2)]
    publics = [k.public_key() for k in identities]
    stranger = PrivateKey.generate(kem)
    small = PrivateKey.generate()
    signer = SigningPrivateKey.generate()

    suite_ids = {
        "chacha20": suites.CHACHA20_POLY1305_1024,
        "aes": suites.AES_256_GCM_1024,
    }

    data = {
        "note": (
            "Frozen known-answer vectors for hpqc's X448 + ML-KEM-1024 hybrid "
            "KEM. " + TEST_KEY_WARNING
        ),
        "format_version": 1,
        "kem": {
            "id": kem.id,
            "name": kem.name,
            "dh_name": kem.dh_name,
            "dh_len": kem.dh_len,
            "dh_shared_len": kem.dh_shared_len,
            "kem_name": kem.kem_name,
            "kem_public_len": kem.kem_public_len,
            "kem_ciphertext_len": kem.kem_ciphertext_len,
            "kem_seed_len": kems.KEM_SEED_LEN,
            "ikm_len": kem.ikm_len,
            "suite_ids": {n: s.id for n, s in sorted(suite_ids.items())},
            "header_len": 32 + 12 + 2 + kem.dh_len + 2 + kem.kem_ciphertext_len,
            "stanza_len": recipients.stanza_len(suites.CHACHA20_POLY1305_1024),
        },
        "keys": {
            "identity": identities[0].encode(),
            "public": publics[0].encode(),
            "key_id": publics[0].key_id_hex,
            "public_blob": publics[0].to_bytes().hex(),
            "private_blob": identities[0].to_bytes().hex(),
            # A 768 identity, to prove the two cannot be confused for each other.
            "other_kem_identity": small.encode(),
        },
        "identities": [k.encode() for k in identities],
        "publics": [p.encode() for p in publics],
        "stranger": stranger.encode(),
        "signer": signer.encode(),
        "signer_public": signer.public_key().encode(),
        "derivations": [],
        "containers": [],
    }

    plaintext = b"hpqc ML-KEM-1024 test vector v1\n"

    for cli_name, suite in sorted(suite_ids.items()):
        data["containers"].append({
            "suite": cli_name,
            "suite_id": suite.id,
            "shape": "one recipient",
            "recipients": 1,
            "plaintext": plaintext.hex(),
            "container": encrypt(plaintext, publics[0], suite).hex(),
        })
        data["containers"].append({
            "suite": cli_name,
            "suite_id": suite.id,
            "shape": "recipient list",
            "recipients": 2,
            "plaintext": plaintext.hex(),
            "container": encrypt_many(
                plaintext, publics, suite=suite
            ).hex(),
        })
        data["containers"].append({
            "suite": cli_name,
            "suite_id": suite.id,
            "shape": "signed recipient list",
            "recipients": 2,
            "signed": True,
            "plaintext": plaintext.hex(),
            "container": encrypt_many(
                plaintext, publics, suite=suite, sender=signer
            ).hex(),
        })

        ikm = _filler(b"hpqc-vector-1024-ikm", kem.ikm_len)
        salt = _filler(b"hpqc-vector-1024-salt", hybrid.SALT_LEN)
        epk = _filler(b"hpqc-vector-1024-epk", kem.dh_len)
        kem_ct = _filler(b"hpqc-vector-1024-kemct", kem.kem_ciphertext_len)
        row = {
            "suite": cli_name,
            "suite_id": suite.id,
            "ikm": ikm.hex(),
            "salt": salt.hex(),
            "ephemeral_public": epk.hex(),
            "kem_ciphertext": kem_ct.hex(),
        }
        for label_name, label in (
            ("payload", hybrid.HKDF_LABEL),
            ("wrap", hybrid.WRAP_LABEL),
        ):
            row[f"{label_name}_key"] = hybrid.derive_key(
                ikm=ikm, salt=salt, suite=suite,
                ephemeral_public=epk, kem_ciphertext=kem_ct,
                recipient=publics[0], label=label,
            ).hex()
        data["derivations"].append(row)

    chunked = _filler(b"hpqc-vector-1024-chunked", streaming.CHUNK_SIZE + 1)
    sink = io.BytesIO()
    encrypt_stream_many(
        io.BytesIO(chunked), sink, publics, suite=suites.CHACHA20_POLY1305_1024
    )
    data["chunked_container"] = {
        "suite": "chacha20",
        "recipients": 2,
        "chunks": 2,
        "plaintext_len": len(chunked),
        "plaintext_sha256": hashlib.sha256(chunked).hexdigest(),
        "container": sink.getvalue().hex(),
    }

    return data


def build_v1_signed_stream() -> dict:
    """Signed containers whose payload is streamed, where a digest is signed.

    The signer never holds the whole plaintext, so the signed message carries a
    digest of it instead of the message itself. That makes three things worth
    freezing, and only the first two are things a container cannot stand in for.

    * `digests` -- the domain-separated SHA-512 of fixed plaintexts. Change the
      label, change the algorithm, or start hashing the signature block along
      with the plaintext, and every signature ever made stops verifying while
      every round trip keeps working.

    * `signed_messages` -- the SHA-256 of the exact byte string the signatures
      cover, for fixed inputs. Drop the header from it and surreptitious
      forwarding comes back; drop the digest and the plaintext stops being
      covered at all.

    * `containers` -- streamed signed files, one recipient and a list, both
      suites. Each must still verify, and a fourth identity must not open it.

    * `forwarded` -- a signature made over one header, re-sealed into another
      addressed to the same identity. It must keep failing.
    """
    identities = [PrivateKey.generate() for _ in range(2)]
    publics = [k.public_key() for k in identities]
    stranger = PrivateKey.generate()
    signer = SigningPrivateKey.generate()
    signer_public = signer.public_key()

    data = {
        "note": (
            "Frozen known-answer vectors for hpqc containers that are both "
            "signed and chunked. " + TEST_KEY_WARNING
        ),
        "format_version": 1,
        "flags": FLAG_SIGNED | FLAG_CHUNKED,
        "sig_stream_label": signing.SIG_STREAM_LABEL.decode("ascii"),
        "stream_digest_label": signing.STREAM_DIGEST_LABEL.decode("ascii"),
        "stream_digest_len": signing.STREAM_DIGEST_LEN,
        "signature_block_len": signing.SIGNATURE_BLOCK_LEN,
        "identities": [k.encode() for k in identities],
        "publics": [p.encode() for p in publics],
        "stranger": stranger.encode(),
        "signer": signer.encode(),
        "signer_public": signer_public.encode(),
        "digests": [],
        "signed_messages": [],
        "containers": [],
    }

    # The digest construction, over inputs small enough to spell out.
    for label, plaintext in (
        ("empty", b""),
        ("short", b"hpqc streamed signature test vector v1\n"),
        ("binary", bytes(range(256))),
    ):
        data["digests"].append({
            "name": label,
            "plaintext": plaintext.hex(),
            "digest": signing.digest_stream(io.BytesIO(plaintext)).hex(),
        })

    # And one that crosses a chunk boundary, recorded by length and hash.
    crossing = _filler(b"hpqc-vector-stream-signed", streaming.CHUNK_SIZE + 1)
    data["digests"].append({
        "name": "crosses a chunk boundary",
        "plaintext_len": len(crossing),
        "plaintext_sha256": hashlib.sha256(crossing).hexdigest(),
        "digest": signing.digest_stream(io.BytesIO(crossing)).hex(),
    })

    def sealed(plaintext, to, suite):
        sink = io.BytesIO()
        encrypt_stream_many(
            io.BytesIO(plaintext), sink, to, suite=suite, sender=signer,
            digest=signing.digest_stream(io.BytesIO(plaintext)),
        )
        return sink.getvalue()

    for cli_name, suite in sorted(suites.BY_CLI_NAME.items()):
        for count, shape in ((1, "one recipient"), (2, "recipient list")):
            data["containers"].append({
                "suite": cli_name,
                "suite_id": suite.id,
                "shape": shape,
                "recipients": count,
                "plaintext_len": len(crossing),
                "plaintext_sha256": hashlib.sha256(crossing).hexdigest(),
                "chunks": 2,
                "container": sealed(crossing, publics[:count], suite).hex(),
            })

        header_bytes = _filler(b"hpqc-vector-stream-header", 1168)
        digest = signing.digest_stream(io.BytesIO(crossing))
        message = signing.stream_signed_message(
            digest, signer_public, header_bytes, suite
        )
        data["signed_messages"].append({
            "suite": cli_name,
            "suite_id": suite.id,
            "header_bytes": header_bytes.hex(),
            "digest": digest.hex(),
            "message_len": len(message),
            "message_sha256": hashlib.sha256(message).hexdigest(),
        })

    # Surreptitious forwarding, streamed and frozen: the block is signed over
    # one header and the stream re-sealed under another.
    suite = suites.DEFAULT_SUITE
    plaintext = b"hpqc streamed forwarding vector v1\n"
    digest = signing.digest_stream(io.BytesIO(plaintext))
    _, elsewhere_bytes, _ = _seal_setup(
        [publics[1]], suite, FLAG_SIGNED | FLAG_CHUNKED
    )
    prologue = signing.sign_stream_prologue(
        digest, signer, elsewhere_bytes, suite
    )
    header, header_bytes, key = _seal_setup(
        [publics[0]], suite, FLAG_SIGNED | FLAG_CHUNKED
    )
    sink = io.BytesIO()
    streaming.seal(
        streaming.PrefixedStream(prologue, io.BytesIO(plaintext)),
        sink, key, suite, header.nonce_prefix, header_bytes,
    )
    data["forwarded"] = {
        "note": (
            "signed over one container's header, re-sealed into another "
            "addressed to identities[0]; opening it must raise SignatureError"
        ),
        "suite": "chacha20",
        "opens_for": 0,
        "plaintext": plaintext.hex(),
        "container": (header_bytes + sink.getvalue()).hex(),
    }

    return data


BUILDERS = {
    "v1.json": build_v1,
    "v1-signed.json": build_v1_signed,
    "v1-wrapped.json": build_v1_wrapped,
    "v1-chunked.json": build_v1_chunked,
    "v1-recipients.json": build_v1_recipients,
    "v1-signed-recipients.json": build_v1_signed_recipients,
    "v1-mlkem1024.json": build_v1_mlkem1024,
    "v1-signed-stream.json": build_v1_signed_stream,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing vector files (invalidates them)",
    )
    args = parser.parse_args()

    wrote = 0
    for name, build in BUILDERS.items():
        path = VECTORS / name
        if path.exists() and not args.force:
            print(f"{name}: already exists, left alone")
            continue
        path.write_text(json.dumps(build(), indent=2) + "\n", encoding="ascii")
        print(f"{name}: wrote {path.stat().st_size} bytes")
        wrote += 1

    if not wrote:
        print(
            "\nNothing written. These vectors are frozen on purpose; pass "
            "--force only if the format changed deliberately.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
