# Architecture

A map of the code: what each file is for, and what actually happens when you
run a command.

This answers "where does this live" and "what calls what". The other documents
answer different questions, and this one deliberately does not repeat them:
[DESIGN.md](DESIGN.md) is why each cryptographic decision went the way it did,
[FORMAT.md](FORMAT.md) is the bytes on disk, [THREAT-MODEL.md](THREAT-MODEL.md)
is what is defended and what is not.

## The shape of it

Sixteen modules in `src/hpqc/`, layered strictly. Every module imports only
from layers below it, so there are no cycles and any module can be read with
only the ones under it in mind.

```
  cli.py                 the commands, argument parsing, all user-facing text
     |
  container.py           the .hpqc file: header, payload, encrypt, decrypt
     |
  recipients.py          one file key, wrapped once per recipient
     |
  hybrid.py  signing.py  the hybrid KEM;  Ed25519 + ML-DSA-65
     |
  keys.py  wrapping.py   key pairs and their files; passphrase protection
     |
  kems.py  suites.py  streaming.py
     |                   algorithm tables; chunked AEAD
  wire.py  armour.py  backend.py
     |                   bounds-checked reads; base64 text format; probing
  errors.py              the exception types, and nothing else
```

The direction matters. `errors.py` imports nothing from the package, and
`cli.py` is the only module that knows a terminal exists. Nothing below `cli.py`
prints, exits, or reads a command line argument, which is why the library is
usable without the CLI and why the CLI holds every message a user sees.

## What happens on `hpqc encrypt`

Take `hpqc encrypt -r alice.pub report.pdf -o report.hpqc`.

1. **`cli.py`** parses the arguments, reads `alice.pub` through
   `keys.PublicKey.read`, and picks a suite with `suites.for_kem`: the recipient's
   key fixes the KEM half, `--aead` picks only the cipher. It then chooses the
   payload shape from the input size, one piece up to 1024 KiB and chunked above
   that, and calls `container.encrypt_many` or `container.encrypt_stream_many`.

2. **`container.py`** does the setup both shapes share. It calls
   `hybrid.encapsulate(recipient)`, which is where both key exchanges happen.

3. **`hybrid.py`** generates a fresh ephemeral Diffie-Hellman key, does the
   exchange against the recipient's DH half, encapsulates to their ML-KEM half,
   and returns the two public values plus `ikm = ss_mlkem || ss_dh`. Both
   secrets are in there, concatenated, so a key derived from it needs both.

4. **`container.py`** fills in a `Header`: magic, version, suite id, flags, key
   id, a random salt, a random nonce, and the two public values from step 3. It
   calls `hybrid.derive_key`, which runs HKDF-SHA256 over `ikm` with the salt,
   and with an `info` transcript that binds the suite byte, both public values,
   the recipient's public keys and a label. Binding the transcript is what stops
   a valid foreign KEM ciphertext being spliced in: the bytes would decapsulate
   fine and derive a different key.

5. The packed header becomes the AEAD's associated data, so every field in it is
   authenticated even though none of it is secret. Editing any byte of the header
   turns into a tag failure rather than a silent reinterpretation.

6. **The payload**, in one of two shapes:
   - one piece: `suite.aead(key).encrypt(nonce, plaintext, header_bytes)`.
   - chunked: `streaming.seal` cuts the input into 64 KiB pieces and seals each
     under its own nonce from `streaming.chunk_nonce`, built from a 7-byte
     per-file prefix, a 4-byte counter, and a last byte that is 1 on the final
     chunk and 0 everywhere else. That one byte is what makes truncation fail.

With `-s signing.key` the payload gains a signature block in front of the
plaintext, built by **`signing.py`** before any encryption happens. For a
streamed file the signature covers a SHA-512 digest rather than the plaintext,
because the signer never holds the whole file; `cli.py` calls
`signing.digest_stream` for a first pass over the input, which is why signing a
stream needs a file and not stdin.

With several `-r` flags, **`recipients.py`** takes over the key handling: one
random file key seals the payload, and that key is wrapped once per recipient
under a per-recipient key derived with a different HKDF label. The header
carries a 32-byte commitment to the file key, so a sender cannot wrap two
different keys to two people. No recipient is named anywhere in the file.

## What happens on `hpqc decrypt`

Take `hpqc decrypt -k alice.key report.hpqc -o report.pdf`.

1. **`cli.py`** reads the key file. `wrapping.is_wrapped` checks whether it is
   passphrase-protected, and if so `wrapping.parse` plus a prompt and
   `wrapping.unwrap` get the real key blob out: scrypt turns the passphrase into
   a key, and ChaCha20-Poly1305 opens the sealed secret with the whole wrap
   header as associated data, so the cost parameters cannot be edited.

2. **`container.py`** reads the header. This is the one field in the format whose
   length depends on its own contents, because a recipient list can hold up to
   1024 stanzas, so `read_header` reads 4 KiB, parses, and when the parser runs
   short it asks for at least as much again and retries, up to a hard cap.
   Every read goes through **`wire.Reader`**, which refuses to hand out bytes it
   does not have and names the field it was reading when it runs out.

3. Everything the header claims is checked before anything is trusted. An
   unknown flag bit, a suite id that does not exist, a field length that does not
   match what the suite fixes: each is refused here, with a message naming the
   field.

4. **`hybrid.decapsulate`** does both halves in reverse and rebuilds `ikm`, and
   `hybrid.derive_key` rebuilds the key from the same transcript. For a file with
   a recipient list, `recipients.unwrap` tries each stanza in turn until one
   opens, then `recipients.check_commitment` confirms the file key is the one the
   header committed to.

5. **The payload** is opened with the header as associated data. If the tag
   fails, that is the end: wrong key, wrong file, or an edited byte, and the
   error does not distinguish them because the AEAD cannot.

6. **Output** goes through a temporary file that is renamed into place only once
   everything verifies, so a failed decryption leaves no half-written plaintext.
   For a signed file `signing.open_payload` or `signing.StreamVerifier` checks
   both signatures, and with `--sender` the signer's public key is compared in
   full against the one in the file before any plaintext is released.

## Every file

### `src/hpqc/`

| File | Lines | What it is for |
| --- | ---: | --- |
| `errors.py` | 53 | The nine exception types. `HpqcError` is the base, and `cli.py` turns anything deriving from it into one readable line. A failure that is not one of these is a bug. |
| `wire.py` | 67 | `Reader`: forward-only, bounds-checked reads. Every parser in the project goes through it, so no parser has its own length arithmetic to get wrong. |
| `armour.py` | 67 | The key file text format: a prefix such as `hpqc-pk1`, one base64 line, and comment lines the parser ignores. |
| `backend.py` | 98 | Probes the installed `cryptography` for ML-KEM and ML-DSA, and turns a missing backend into a message naming the algorithm and the requirement instead of an import error. |
| `kems.py` | 189 | The two hybrid KEMs as data: X25519 with ML-KEM-768 (id 1) and X448 with ML-KEM-1024 (id 2), each carrying its key and ciphertext lengths. Adding a third means adding a row. |
| `suites.py` | 157 | The four cipher suites, each a KEM from `kems.py` plus an AEAD. The suite byte in a file indexes this table. |
| `streaming.py` | 265 | Chunked AEAD: `seal` and `open_stream` over 64 KiB pieces, and `chunk_nonce`, the STREAM construction that makes truncation, extension, reordering and repetition all fail. |
| `wrapping.py` | 367 | Passphrase-protected private keys. scrypt to a key, ChaCha20-Poly1305 around the secret, cost parameters stored in the file and bounded before scrypt is allowed to allocate. |
| `keys.py` | 601 | The four key types: encryption and signing, public and private. Generation, the on-disk blob layout, key ids, and writing a private key at mode 0600 through a temporary file. |
| `hybrid.py` | 186 | The hybrid KEM. `encapsulate` and `decapsulate` run both exchanges, and `derive_key` is the HKDF with the transcript that binds everything the file claims. |
| `signing.py` | 556 | Ed25519 and ML-DSA-65, both required, signed before encryption. Three signed-message constructions with distinct labels, and `StreamVerifier` for the digest-signing path. |
| `recipients.py` | 320 | Several recipients per file. Stanza packing, trial decryption, and the file key commitment. Also the bound of 1024 recipients and the refusal of a repeated one. |
| `container.py` | 808 | The `.hpqc` file itself. Header layout and parsing, the adaptive `read_header`, and the four write paths and two read paths for signed or unsigned, chunked or one piece. |
| `cli.py` | 995 | The six commands, and every string a user ever sees. Also `run()`, which catches `HpqcError` and `OSError` so neither reaches a terminal as a traceback. |
| `__init__.py` | 38 | The version number and the package docstring. |
| `__main__.py` | 10 | Lets `python -m hpqc` work alongside the installed `hpqc` script. |

### `tests/`

530 test functions, which collect as 818 tests because many are parametrized
over both KEMs, both AEADs and both payload shapes. Mostly negative tests: the
interesting question for a crypto tool is what it refuses.

| File | Tests | What it covers |
| --- | ---: | --- |
| `conftest.py` | fixtures | Session-scoped keys, so key generation is not paid for per test. |
| `helpers.py` | helpers | `seal`, which builds a valid container around an arbitrary payload. Needed because the adversary for a signature is the sender, so forgeries have to be built from the inside rather than by flipping bits. |
| `test_cli.py` | 92 | End-to-end behaviour through click's test runner. |
| `test_vectors.py` | 76 | The frozen known-answer vectors. These record derivations, digests and nonce tables, not just containers, because a recorded container cannot pin a construction: change it and the writer and reader move together. |
| `test_recipients.py` | 59 | The stanza list, anonymity, and the commitment. |
| `test_wrapping.py` | 42 | scrypt parameters, bounds, and the sealed blob. |
| `test_streaming.py` | 41 | Round trips plus the four ways to forge a chunked file. |
| `test_signing.py` | 37 | Both signatures, and surreptitious forwarding in all three constructions. |
| `test_cli_errors.py` | 31 | The messages a user actually sees, including `run()` itself, which every other CLI test bypasses. |
| `test_container.py` | 28 | Header layout, round trips, tamper resistance. |
| `test_kems.py` | 23 | Both parameter sets, and what has to hold once a format has two of anything. |
| `test_keys.py` | 21 | Generation, serialisation, identification. |
| `test_stream_signing.py` | 25 | A recipient forging a signed stream from the inside. |
| `test_fuzz.py` | 17 | Mutation fuzzing: a corrupted container must always fail as an `HpqcError` and never decrypt. |
| `test_format_doc.py` | 17 | Parses the tables out of FORMAT.md and holds them to the code, so the format document cannot drift. |
| `test_hybrid.py` | 12 | The combiner, and that both secrets reach the derived key. |
| `test_backend.py` | 9 | The messages a machine without post-quantum support gets. |
| `tests/vectors/*.json` | 9 files | The frozen vectors themselves. Every key in them is generated fresh by `tools/make_vectors.py` and exists only to be published. |

### Everything else

| Path | What it is for |
| --- | --- |
| `pyproject.toml` | Packaging, the `hpqc` entry point, and the pytest and coverage configuration including the 97% gate. |
| `tools/make_vectors.py` | Regenerates the frozen vectors. Encryption cannot be made deterministic, so it records one random run; opening a recorded file is fully deterministic. |
| `tools/ci-local.sh` | Runs the CI workflow locally across every Python in the matrix, in docker. It extracts the steps from `.github/workflows/ci.yml` rather than restating them, and refuses to run if a step comes out empty. |
| `.github/workflows/ci.yml` | Type-checks and tests on Python 3.9, 3.11, 3.13 and 3.14, then drives the installed binary through 44 checks against a real command line. |
| `README.md` | What it is, how to install it, and what the commands do. |
| `DESIGN.md` | How each feature works and why the decision went that way. |
| `FORMAT.md` | The wire format and the key file format, byte by byte. |
| `THREAT-MODEL.md` | What is defended, against whom, and what is not defended. |
| `TESTING.md` | The manual walkthrough, and what the suite checks. |
| `NOTES.md` | Every real bug and gap found while building this, and how each one surfaced. |

## Where to start reading

If you want to understand the cryptography, read `hybrid.py` first. It is 186
lines and it is the whole idea: two key exchanges, one HKDF, a transcript that
binds what the file claims.

If you want to understand the file format, read `container.py`'s `Header` and
`parse_header`, with [FORMAT.md](FORMAT.md) open beside them.

If you want to understand what the project is actually careful about, read
[NOTES.md](NOTES.md). It is the list of things that were wrong, and most of the
tests exist because of something on it.
