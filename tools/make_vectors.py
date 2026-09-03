#!/usr/bin/env python3
"""Generate tests/vectors/v1.json -- the frozen known-answer vectors.

Run once; the output is checked in and must not change. Its purpose is to pin
the *wire format and the key derivation* so a future refactor cannot silently
alter either: tests/test_vectors.py decrypts these exact bytes with this exact
identity and compares against the recorded plaintexts and keys.

Encryption cannot be made deterministic (the ephemeral X25519 key, the ML-KEM
encapsulation randomness, the salt and the nonce are all freshly random, and
the backend gives no way to inject them), so the vectors are recorded from one
run and verified on the *decryption* side, which is fully deterministic.

    python tools/make_vectors.py [--force]

The identity in this file is a test key. It is published on purpose and must
never be used for anything real.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hpqc import hybrid, suites  # noqa: E402
from hpqc.container import encrypt  # noqa: E402
from hpqc.keys import PrivateKey  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "tests" / "vectors" / "v1.json"

PLAINTEXTS = [
    b"",
    b"hpqc test vector v1\n",
    bytes(range(256)),
]


def _filler(label: bytes, length: int) -> bytes:
    """Deterministic non-secret bytes, so the derivation vectors are stable."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(label + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true",
                        help="overwrite existing vectors (invalidates them)")
    args = parser.parse_args()

    if OUT.exists() and not args.force:
        print(f"{OUT} already exists; refusing to overwrite.", file=sys.stderr)
        print("These vectors are frozen on purpose. Pass --force only if the "
              "format has intentionally changed.", file=sys.stderr)
        return 1

    identity = PrivateKey.generate()
    public = identity.public_key()

    data = {
        "note": (
            "Frozen known-answer vectors for the hpqc v1 wire format. The "
            "identity below is a TEST KEY, published deliberately; never use "
            "it for anything real. Regenerate only with "
            "tools/make_vectors.py --force, and only if the format changed "
            "on purpose."
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

    OUT.write_text(json.dumps(data, indent=2) + "\n", encoding="ascii")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
    print(f"key id: {public.key_id_hex}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
