"""Hold FORMAT.md to what the code actually writes.

A specification document is the one part of a project that nothing checks. The
tests check the code against itself, the frozen vectors check it against
yesterday, and the format document sits beside both describing a layout that
was true when someone typed it.

This is not hypothetical here. TESTING.md opened by claiming every command in
it had been run and its output checked, and by the time anyone looked again
four of its numbers were stale: two file sizes that had each grown by the
32-byte file key commitment, a line the tool prints that the transcript did not
show, and a memory figure that disagreed with DESIGN.md about the same
measurement. Every one of them was true when written.

So these tests *parse the tables out of FORMAT.md* rather than restating their
contents. Copying the numbers into a test would only move the drift: the copy
and the document would agree with each other while both drifted away from the
code. Reading the document means a wrong row in it fails the suite.

What is checked is the arithmetic a reader does with the tables: that offsets
are contiguous and cumulative, that the sizes sum to the real thing, and that
every constant named in a row matches the constant in the module.
"""

from __future__ import annotations

import pathlib
import re
import struct
from typing import Dict, List, Tuple

import pytest

from hpqc import armour, container, kems, keys, recipients, streaming, suites, wrapping
from hpqc.keys import PrivateKey, PublicKey, SigningPrivateKey

FORMAT_MD = pathlib.Path(__file__).resolve().parent.parent / "FORMAT.md"

#: Rows of an offset/size table look like "| 44 | 2 | length of the ... |".
#: The size column is allowed to be "..." for a trailing variable-length field,
#: which is the one row whose arithmetic cannot continue.
_ROW = re.compile(r"^\|\s*(\d+)\s*\|\s*(\d+|\.\.\.)\s*\|\s*(.+?)\s*\|$")


def _tables() -> Dict[str, List[Tuple[int, str, str]]]:
    """Every offset/size table in FORMAT.md, keyed by the heading above it.

    The key is the nearest preceding heading of any level, which is what a
    reader would call the table. A section with two tables keeps only the
    second; FORMAT.md has none, and the assertion below says so rather than
    letting a future one vanish silently.
    """
    found: Dict[str, List[Tuple[int, str, str]]] = {}
    heading = ""
    rows: List[Tuple[int, str, str]] = []
    for line in FORMAT_MD.read_text().splitlines():
        if line.startswith("#"):
            if rows:
                assert heading not in found, f"two offset tables under {heading!r}"
                found[heading] = rows
            heading = line.lstrip("#").strip()
            rows = []
            continue
        match = _ROW.match(line)
        if match:
            rows.append((int(match.group(1)), match.group(2), match.group(3)))
        elif rows and not line.startswith("|"):
            assert heading not in found, f"two offset tables under {heading!r}"
            found[heading] = rows
            rows = []
    if rows:  # pragma: no cover - FORMAT.md does not end inside a table
        found[heading] = rows
    return found


@pytest.fixture(scope="module")
def tables() -> Dict[str, List[Tuple[int, str, str]]]:
    return _tables()


def _is_contiguous(rows: List[Tuple[int, str, str]]) -> None:
    """Each row starts where the previous one ended, so a reader can add up."""
    at = 0
    for offset, size, field in rows:
        assert offset == at, f"{field!r} starts at {offset}, expected {at}"
        if size == "...":
            return
        at += int(size)


def test_the_document_still_has_the_tables_these_tests_read() -> None:
    """A renamed heading must fail loudly, not silently check nothing.

    Every test below looks its table up by heading. Without this, deleting a
    section or retitling it would turn its test into a no-op that passes, which
    is the exact failure mode the frozen vectors exist to prevent elsewhere.
    """
    assert set(_tables()) == {
        "Container",
        "Recipient lists",
        "Signature block",
        "STREAM nonce",
        "Wrapped private keys",
    }


def test_the_container_table_describes_a_real_header(
    tables: Dict[str, List[Tuple[int, str, str]]], alice_pub: PublicKey
) -> None:
    """The header table, against a container built by the library.

    Suite 0x01 is the one the table is written for, which it says. Every offset
    up to the payload is fixed, so the whole table is checkable by addition.
    """
    rows = tables["Container"]
    _is_contiguous(rows)
    by_offset = {offset: (size, field) for offset, size, field in rows}

    blob = container.encrypt(b"x" * 100, alice_pub)
    assert by_offset[0][0] == "4" and blob[0:4] == container.MAGIC
    assert by_offset[4][0] == "1" and blob[4] == container.FORMAT_VERSION
    assert by_offset[5][0] == "1" and blob[5] == suites.DEFAULT_SUITE.id
    assert by_offset[6][0] == "2" and struct.unpack(">H", blob[6:8])[0] == 0
    assert by_offset[8][0] == "8" and blob[8:16] == alice_pub.key_id
    assert by_offset[16][0] == "16" and len(blob[16:32]) == 16
    assert by_offset[32][0] == "12" and len(blob[32:44]) == suites.DEFAULT_SUITE.nonce_len
    assert struct.unpack(">H", blob[44:46])[0] == int(by_offset[46][0])
    assert struct.unpack(">H", blob[78:80])[0] == int(by_offset[80][0])

    payload_at = max(by_offset)
    assert by_offset[payload_at][1] == "payload"
    assert payload_at == len(blob) - (100 + 16)


def test_the_flag_bits_the_container_table_names_are_the_flags_in_the_code(
    tables: Dict[str, List[Tuple[int, str, str]]]
) -> None:
    """The flags row names four bits in words. Those words are the four flags."""
    flags_row = [f for offset, _, f in tables["Container"] if offset == 6]
    assert len(flags_row) == 1
    described = dict(
        (name.strip(), int(bit))
        for bit, name in re.findall(r"bit (\d) (\w+(?: \w+)?)", flags_row[0])
    )
    assert described == {"signed": 0, "chunked": 1, "recipient list": 2, "commitment": 3}
    assert container.FLAG_SIGNED == 1 << described["signed"]
    assert container.FLAG_CHUNKED == 1 << described["chunked"]
    assert container.FLAG_RECIPIENTS == 1 << described["recipient list"]
    assert container.FLAG_COMMITTED == 1 << described["commitment"]


def test_the_suite_table_lists_every_suite_and_nothing_else() -> None:
    """A suite added to the code and not to the document fails here.

    The reverse matters more: a document listing a suite the code does not have
    tells a reader to write a byte that will be refused.
    """
    rows = re.findall(
        r"^\| `0x0(\d)` \| (.+?) \| (.+?) \|$", FORMAT_MD.read_text(), re.M
    )
    documented = {int(i): (kem.strip(), aead.strip()) for i, kem, aead in rows}
    real = {
        s.id: (s.kem.name.replace("+", " + "), s.aead_name) for s in suites.all_suites()
    }
    assert documented == real


def test_the_alternative_suite_sizes_in_the_prose_are_right() -> None:
    """The sentence under the table, which is where suite 0x03's sizes live.

    "a suite using X448 with ML-KEM-1024 makes them 56 and 1568, for a
    1672-byte header" is three numbers no table holds.
    """
    text = FORMAT_MD.read_text()
    match = re.search(
        r"makes them (\d+) and (\d+), for a\s*\n?(\d+)-byte header", text
    )
    assert match, "the sentence describing suite 0x03's header has changed"
    dh_len, kem_len, header_len = (int(g) for g in match.groups())

    suite = suites.by_id(0x03)
    assert suite.kem.dh_len == dh_len
    assert suite.kem.kem_ciphertext_len == kem_len

    recipient = PrivateKey.generate(kems.X448_MLKEM1024).public_key()
    blob = container.encrypt(b"x" * 100, recipient, suite)
    assert len(blob) - (100 + 16) == header_len


def test_the_recipient_table_describes_a_real_group_header(
    tables: Dict[str, List[Tuple[int, str, str]]],
    alice_pub: PublicKey,
    bob_pub: PublicKey,
) -> None:
    """Everything from offset 44 on, for a file with a recipient list."""
    rows = tables["Recipient lists"]
    assert rows[0][0] == 44, "the table no longer starts where the prose says"
    by_offset = {offset: (size, field) for offset, size, field in rows}
    assert int(by_offset[44][0]) == recipients.COMMITMENT_LEN

    blob = container.encrypt_many(b"x" * 100, [alice_pub, bob_pub])
    assert blob[8:16] == container.NO_KEY_ID
    assert struct.unpack(">H", blob[6:8])[0] == (
        container.FLAG_RECIPIENTS | container.FLAG_COMMITTED
    )
    assert struct.unpack(">H", blob[76:78])[0] == 2
    assert int(by_offset[76][0]) == 2

    stanzas_at = 78
    assert by_offset[stanzas_at][1].endswith("stanzas")
    assert (len(blob) - stanzas_at - (100 + 16)) // 2 == recipients.stanza_len(
        suites.DEFAULT_SUITE
    )


def test_the_stanza_sizes_in_the_prose_are_right() -> None:
    """"1174 bytes for suite `0x01`, 1678 for suite `0x03`"."""
    match = re.search(
        r"(\d+) bytes for suite `0x01`, (\d+) for suite `0x03`", FORMAT_MD.read_text()
    )
    assert match, "the sentence giving the stanza sizes has changed"
    assert int(match.group(1)) == recipients.stanza_len(suites.by_id(0x01))
    assert int(match.group(2)) == recipients.stanza_len(suites.by_id(0x03))


def test_the_recipient_count_bound_in_the_table_is_the_bound_in_the_code(
    tables: Dict[str, List[Tuple[int, str, str]]]
) -> None:
    """The count row says "1 to 1024". 1024 is a constant, not a round number."""
    count_row = [f for offset, _, f in tables["Recipient lists"] if offset == 76]
    match = re.search(r"(\d+) to (\d+)", count_row[0])
    assert match
    assert int(match.group(1)) == 1
    assert int(match.group(2)) == recipients.MAX_RECIPIENTS


def test_the_signature_block_table_describes_a_real_signature_block(
    tables: Dict[str, List[Tuple[int, str, str]]],
    alice_pub: PublicKey,
    carol: SigningPrivateKey,
) -> None:
    """Offsets inside the decrypted payload, which no container exposes.

    So this one is checked by arithmetic against the fixed overhead instead:
    the final row's offset is where the plaintext starts, and a signed
    container is exactly that much larger than an unsigned one.
    """
    rows = tables["Signature block"]
    _is_contiguous(rows)
    plaintext_at = max(offset for offset, _, _ in rows)
    assert [f for o, _, f in rows if o == plaintext_at] == ["plaintext"]

    plain = container.encrypt(b"x" * 100, alice_pub)
    signed = container.encrypt(b"x" * 100, alice_pub, sender=carol)
    assert len(signed) - len(plain) == plaintext_at


def test_the_overheads_in_the_payload_prose_are_right(alice_pub: PublicKey,
                                                     carol: SigningPrivateKey) -> None:
    """"1184 bytes per file whatever its size, or 6549 if it is signed", and
    "1168 plus 16 per chunk"."""
    text = FORMAT_MD.read_text()
    match = re.search(r"(\d+) bytes per file whatever its size, or (\d+) if", text)
    assert match, "the sentence giving the fixed overhead has changed"
    one_shot, signed_overhead = (int(g) for g in match.groups())

    for size in (0, 1, 1000, 100000):
        assert len(container.encrypt(b"x" * size, alice_pub)) - size == one_shot
    assert len(container.encrypt(b"x", alice_pub, sender=carol)) - 1 == signed_overhead

    match = re.search(r"Overhead is (\d+) plus (\d+) per chunk", text)
    assert match, "the sentence giving the chunked overhead has changed"
    header_len, per_chunk = (int(g) for g in match.groups())
    assert header_len == len(container.encrypt(b"", alice_pub)) - streaming.TAG_LEN
    assert per_chunk == streaming.TAG_LEN


def test_the_stream_nonce_table_describes_a_real_nonce(
    tables: Dict[str, List[Tuple[int, str, str]]]
) -> None:
    """Seven bytes of prefix, four of counter, one of final marker."""
    rows = tables["STREAM nonce"]
    _is_contiguous(rows)
    assert sum(int(size) for _, size, _ in rows) == suites.DEFAULT_SUITE.nonce_len

    prefix = bytes(range(int(rows[0][1])))
    final = streaming.chunk_nonce(prefix, 0, True)
    assert final[: len(prefix)] == prefix
    assert struct.unpack(">I", streaming.chunk_nonce(prefix, 5, False)[7:11])[0] == 5

    # The marker row names both byte values in hex, and those two bytes are the
    # whole difference between a stream and a truncation that verifies. Reading
    # them out of the row is the point: asserting b"\x01" here would check the
    # code against itself and leave the document free to say anything.
    marker_row = [f for offset, _, f in rows if offset == 11]
    assert len(marker_row) == 1
    markers = re.findall(r"`0x([0-9a-f]{2})`", marker_row[0])
    assert len(markers) == 2, f"expected two byte values in {marker_row[0]!r}"
    last, other = (bytes([int(value, 16)]) for value in markers)
    assert final[11:] == last
    assert streaming.chunk_nonce(prefix, 0, False)[11:] == other


def test_the_stream_ceiling_in_the_prose_is_the_ceiling_in_the_code() -> None:
    """"the counter is refused at 2^32 ... 256 TiB per file"."""
    match = re.search(r"refused at 2\^(\d+).+?(\d+) TiB per file",
                      FORMAT_MD.read_text(), re.S)
    assert match, "the sentence giving the stream ceiling has changed"
    bits, tib = int(match.group(1)), int(match.group(2))
    assert 2 ** bits == streaming.MAX_CHUNKS
    assert streaming.MAX_CHUNKS * streaming.CHUNK_SIZE == streaming.MAX_STREAM_BYTES
    assert streaming.MAX_STREAM_BYTES // (1024 ** 4) == tib


def test_the_key_prefix_table_is_the_armour_the_code_writes() -> None:
    """Five prefixes, and each one has to be the constant the writer uses."""
    rows = re.findall(r"^\| `(hpqc-[a-z0-9]+)` \| (.+?) \|$", FORMAT_MD.read_text(), re.M)
    documented = {prefix: what.strip() for prefix, what in rows}
    assert documented == {
        "hpqc-pk1": "encryption public key",
        "hpqc-sk1": "encryption private key",
        "hpqc-spk1": "signing public key",
        "hpqc-ssk1": "signing private key",
        "hpqc-wsk1": "any private key, passphrase-wrapped",
    }
    assert set(documented) == {
        armour_prefix
        for armour_prefix in (
            keys.PUBLIC_PREFIX,
            keys.PRIVATE_PREFIX,
            keys.SIGN_PUBLIC_PREFIX,
            keys.SIGN_PRIVATE_PREFIX,
            wrapping.WRAPPED_PREFIX,
        )
    }


def test_the_key_blob_table_gives_the_real_blob_sizes() -> None:
    """Six rows of "type, this (n), that (m)" and a total. Both are checked.

    The sizes in the parentheses have to add up to the total in the last
    column, and the total has to be the length of a blob the code writes.
    """
    rows = re.findall(
        r"^\| (Encryption \w+, type \d|Signing \w+) \| (.+?) \| (\d+) \|$",
        FORMAT_MD.read_text(),
        re.M,
    )
    assert len(rows) == 6

    real = {}
    for kem in kems.all_kems():
        private = PrivateKey.generate(kem)
        real[f"Encryption public, type {kem.id}"] = len(
            private.public_key().to_bytes()
        )
        real[f"Encryption private, type {kem.id}"] = len(private.to_bytes())
        assert private.to_bytes()[0] == kem.id
    signing = SigningPrivateKey.generate()
    real["Signing public"] = len(signing.public_key().to_bytes())
    real["Signing private"] = len(signing.to_bytes())

    for name, layout, total in rows:
        parts = [int(n) for n in re.findall(r"\((\d+)\)", layout)]
        assert len(parts) == 2, f"{name}: expected two sized fields in {layout!r}"
        assert 1 + sum(parts) == int(total), f"{name}: the row does not add up"
        assert real[name] == int(total), f"{name}: the code writes a different size"


def test_the_wrapped_key_table_describes_a_real_wrapped_key(
    tables: Dict[str, List[Tuple[int, str, str]]]
) -> None:
    """The 39-byte header, field by field, against a key wrapped right here."""
    rows = tables["Wrapped private keys"]
    _is_contiguous(rows)
    by_offset = {offset: (size, field) for offset, size, field in rows}
    blob_at = max(by_offset)
    assert by_offset[blob_at][0] == "..."
    assert blob_at == wrapping.HEADER_LEN

    match = re.search(r"plus a (\d+)-byte header", FORMAT_MD.read_text())
    assert match and int(match.group(1)) == wrapping.HEADER_LEN

    private = PrivateKey.generate(suites.DEFAULT_SUITE.kem)
    armoured = wrapping.wrap(private.to_bytes(), wrapping.KIND_IDENTITY, b"hunter2")
    raw = armour.dearmour(armoured, wrapping.WRAPPED_PREFIX, "wrapped private key")

    assert raw[0] == wrapping.WRAP_VERSION
    assert raw[1] == wrapping.KIND_IDENTITY
    assert raw[2] == wrapping.KDF_SCRYPT
    assert raw[6] == wrapping.AEAD_CHACHA20_POLY1305
    assert len(raw[7:23]) == int(by_offset[7][0])
    assert len(raw[23:35]) == int(by_offset[23][0])
    assert struct.unpack(">H", raw[35:37])[0] == len(raw) - wrapping.HEADER_LEN

    signing = wrapping.wrap(
        SigningPrivateKey.generate().to_bytes(),
        wrapping.KIND_SIGNING_IDENTITY,
        b"hunter2",
    )
    raw_signing = armour.dearmour(
        signing, wrapping.WRAPPED_PREFIX, "wrapped private key"
    )
    assert raw_signing[1] == wrapping.KIND_SIGNING_IDENTITY


def test_the_kind_bytes_the_table_names_are_the_kinds_in_the_code(
    tables: Dict[str, List[Tuple[int, str, str]]]
) -> None:
    """"kind: 1 encryption identity, 2 signing identity"."""
    kind_row = [f for offset, _, f in tables["Wrapped private keys"] if offset == 1]
    described = {
        name: int(value)
        for value, name in re.findall(r"(\d) (\w+) identity", kind_row[0])
    }
    assert described == {"encryption": wrapping.KIND_IDENTITY,
                         "signing": wrapping.KIND_SIGNING_IDENTITY}


def test_the_scrypt_bound_in_the_prose_is_the_bound_in_the_code() -> None:
    """"a file asking for more than 1 GiB is refused rather than allocated"."""
    match = re.search(r"asking for more than (\d+) GiB is refused", FORMAT_MD.read_text())
    assert match, "the sentence giving the scrypt memory bound has changed"
    assert int(match.group(1)) * 1024 ** 3 == wrapping.MAX_MEMORY_BYTES
