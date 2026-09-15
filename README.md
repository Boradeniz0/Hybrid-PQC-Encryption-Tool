# hpqc

[![CI](https://github.com/Boradeniz0/Hybrid-PQC-Encryption-Tool/actions/workflows/ci.yml/badge.svg)](https://github.com/Boradeniz0/Hybrid-PQC-Encryption-Tool/actions/workflows/ci.yml)

A command line tool that encrypts files to a public key using an elliptic curve
and ML-KEM together. Both key exchanges run, both shared secrets feed one
HKDF-SHA256 extraction, and the result drives an AEAD. An attacker has to break
both to read the file.

This is a learning and portfolio project. It has not been audited. See
[THREAT-MODEL.md](THREAT-MODEL.md) before trusting it with anything real.

## Install

Needs Python 3.9.2 or newer and `cryptography` 46 or newer, built against
OpenSSL 3.5 or newer. That is where ML-KEM and ML-DSA live. No `liboqs` build is
required.

```console
pipx install git+https://github.com/Boradeniz0/Hybrid-PQC-Encryption-Tool
hpqc --help
```

To work on it:

```console
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

## Quickstart

```console
$ hpqc keygen -o alice
private key: alice.key  (mode 0600 only -- keep it secret)
public key:  alice.pub   (share this)
algorithms:  X25519+ML-KEM-768
key id:      dc367bffcdf81019

$ hpqc encrypt -r alice.pub report.pdf -o report.pdf.hpqc
$ hpqc decrypt -k alice.key report.pdf.hpqc -o report.pdf
```

To also answer "who sent this":

```console
$ hpqc signgen -o bob-sign
signing private key: bob-sign.key  (mode 0600 only)
signing public key:  bob-sign.pub   (give this to recipients)
key id:              1322446e7dc517ec

$ hpqc encrypt -r alice.pub report.pdf -o report.hpqc -s bob-sign.key
signed by key id 1322446e7dc517ec

$ hpqc decrypt -k alice.key report.hpqc -o report.pdf --sender bob-sign.pub
signature ok: signed by key id 1322446e7dc517ec
```

To send one file to several people, without naming any of them in it:

```console
$ hpqc encrypt -r alice.pub -r bob.pub -r carol.pub minutes.txt -o minutes.hpqc
encrypted to 3 recipients; the file does not name them

$ hpqc decrypt -k bob.key minutes.hpqc -o minutes.txt
```

To keep a private key under a passphrase rather than file permissions alone:

```console
$ hpqc keygen -o alice --passphrase
passphrase for the new private key:
Repeat for confirmation:
private key: alice.key  (passphrase-protected -- keep it secret)
```

## What it does

- **Hybrid key exchange.** X25519 with ML-KEM-768 by default, X448 with
  ML-KEM-1024 on request. Both halves move together, because raising only one
  of them raises nothing.
- **Hybrid sender authentication.** Ed25519 with ML-DSA-65, both required,
  signed before encryption so who signed a file is itself confidential.
- **Large files.** Past a megabyte the payload is sealed in 64 KiB chunks. A
  200 MB file costs 36 MB of memory instead of 621 MB, and stays there when it
  is signed, where holding it whole would cost 817 MB.
- **Several recipients per file.** One file key, wrapped once per recipient,
  and the header names none of them. It also commits to that key, so a sender
  cannot hand two recipients two different messages.
- **Passphrase-protected private keys.** scrypt to a key, ChaCha20-Poly1305
  around the secret, parameters stored in the file.
- **A format that has not moved.** Four features so far, four flag bits, and
  the version byte is still 1. Every file written by any earlier build still
  opens, with one deliberate exception noted in [DESIGN.md](DESIGN.md).

## Why hybrid

Someone recording your traffic today can store it until a quantum computer
exists and decrypt it then. This is called harvest-now-decrypt-later, and it
makes X25519-only encryption a problem for anything that has to stay secret for
a decade. Using ML-KEM alone trades one risk for another: lattice cryptography
is much younger than elliptic curves, and the implementations are younger still.

Hybrid takes neither bet.

| Attacker | X25519 alone | ML-KEM alone | hpqc |
| --- | --- | --- | --- |
| Classical, today | safe | safe | safe |
| Breaks ML-KEM by cryptanalysis | safe | **broken** | safe |
| Has a quantum computer | **broken** | safe | safe |
| Breaks both | broken | broken | broken |

## Usage

```
hpqc keygen  [-o BASENAME] [--force] [--kem mlkem768|mlkem1024]
                                     [-p | --passphrase-file F] [--scrypt-log-n N]
hpqc signgen [-o BASENAME] [--force] [-p | --passphrase-file F] [--scrypt-log-n N]
hpqc encrypt -r RECIPIENT.pub [-r ...] [INPUT] [-o OUT]
                                     [--aead chacha20|aes] [-s SIGNING.key]
                                     [--chunked | --one-shot]
                                     [--hide-recipients] [--passphrase-file F]
hpqc decrypt -k IDENTITY.key [INPUT] [-o OUT] [--sender SIGNER.pub]
                                     [--passphrase-file F]
hpqc passwd  KEYFILE [--remove] [--scrypt-log-n N]
                                     [--passphrase-file F] [--new-passphrase-file F]
hpqc info    [INPUT]                 describe a container or a key file
```

`INPUT` defaults to stdin and `-o` to stdout, so everything pipes:

```console
$ echo "meet me at dawn" | hpqc encrypt -r alice.pub | hpqc decrypt -k alice.key
meet me at dawn
```

`hpqc info` reads a container's header without the private key:

```console
$ hpqc info report.hpqc
type:        hpqc container
version:     1
suite:       X25519+ML-KEM-768/ChaCha20-Poly1305 (0x01)
recipient:   key id dc367bffcdf81019
header:      1168 bytes (authenticated as AAD)
kem ct:      1088 bytes
payload:     100016 bytes (ciphertext + 16-byte tag)
plaintext:   100000 bytes
chunked:     no
signed:      no
```

## Testing

```console
$ pytest --cov
801 passed
TOTAL   1419 statements, 282 branches, 100% coverage
$ mypy
Success: no issues found in 16 source files
```

Line and branch coverage of the package, enforced in CI at 97%. CI type-checks
and runs the suite on Python 3.9, 3.11, 3.13 and 3.14, then drives the installed
binary through 44 checks against the real command line. `tools/ci-local.sh` runs
all of that, on every Python in the matrix, in docker.

Nine files of frozen known-answer vectors are checked into the repository. They
record derivations, digests and nonce tables, not just containers, because a
recorded container cannot pin a construction: change it and the writer and
reader move together, so the file stops opening either way and the failure names
no cause.

[TESTING.md](TESTING.md) has the manual walkthrough and what the suite actually
checks.

## Documentation

| | |
| --- | --- |
| [DESIGN.md](DESIGN.md) | How it works, and why each decision went the way it did |
| [FORMAT.md](FORMAT.md) | The `.hpqc` wire format and the key file format |
| [THREAT-MODEL.md](THREAT-MODEL.md) | What it defends against, and what it does not |
| [TESTING.md](TESTING.md) | Running it by hand, and what the test suite checks |
| [NOTES.md](NOTES.md) | What I got wrong while building it, and how each one surfaced |

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), Module-Lattice-Based Digital Signature Standard (ML-DSA)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748), Elliptic Curves for Security (X25519, X448)
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), EdDSA (Ed25519)
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), HKDF
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439), ChaCha20 and Poly1305
- [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914), the scrypt password-based KDF
- Hoang, Reyhanitabar, Rogaway and Vizar, *Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance* (CRYPTO 2015), the STREAM construction used for chunked files
- Dodis, Grubbs, Ristenpart and Woodage, *Fast Message Franking: From Invisible Salamanders to Encryptment* (CRYPTO 2018)
- Len, Grubbs and Ristenpart, *Partitioning Oracle Attacks* (USENIX Security 2021)
- Davis, *Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP, and XML* (USENIX ATC 2001), where surreptitious forwarding comes from
- [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/), a hybrid KEM combiner; hpqc uses the same `ss_m || ss_x` ordering
- [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/), hybrid key exchange in TLS 1.3

## License

MIT, see [LICENSE](LICENSE).
