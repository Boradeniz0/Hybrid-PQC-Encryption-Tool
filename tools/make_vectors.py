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
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
# seal() lives with the tests because it models a malicious sender; the
# forwarding vector below needs exactly that, so reuse it rather than copy it.
sys.path.insert(0, str(ROOT / "tests"))

from helpers import seal  # noqa: E402

from hpqc import hybrid, signing, suites  # noqa: E402
from hpqc.container import FLAG_SIGNED, encrypt  # noqa: E402
from hpqc.keys import PrivateKey, SigningPrivateKey  # noqa: E402

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


BUILDERS = {
    "v1.json": build_v1,
    "v1-signed.json": build_v1_signed,
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
