# Trying hpqc by hand

The automated suite covers all of this and more (`pytest`, 788 tests). This is
the manual pass: what to run, and what each result is actually telling you.

Every command here has been run and its output checked.

```console
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
mkdir -p /tmp/hpqc-demo && cd /tmp/hpqc-demo
```

## 1. Encrypt and decrypt

```console
hpqc keygen -o alice
head -c 100000 /dev/urandom > secret.bin

hpqc encrypt -r alice.pub secret.bin -o secret.hpqc
hpqc info secret.hpqc
hpqc decrypt -k alice.key secret.hpqc -o back.bin
cmp secret.bin back.bin && echo OK
```

`info` reads the header without the private key. Note
`header: 1168 bytes (authenticated as AAD)` and `signed: no`.

Overhead is constant, whatever the file size:

```console
for n in 0 1 1000 100000; do
  head -c $n /dev/zero > t.bin
  hpqc encrypt -r alice.pub t.bin -o t.hpqc
  echo "$n bytes -> overhead $(( $(stat -c%s t.hpqc) - n ))"
done
```

All four print **1184**: 1168 of header plus a 16-byte tag. Everything pipes,
so it works as a filter:

```console
echo "attack at dawn" | hpqc encrypt -r alice.pub | hpqc decrypt -k alice.key
```

And the same plaintext never produces the same file twice — fresh ephemeral key,
fresh encapsulation, fresh salt and nonce:

```console
hpqc encrypt -r alice.pub t.bin -o a.hpqc
hpqc encrypt -r alice.pub t.bin -o b.hpqc
cmp -s a.hpqc b.hpqc && echo "IDENTICAL -- bug" || echo "different, as expected"
```

## 2. Sender authentication

```console
hpqc signgen -o bob-sign
echo "pay 100 EUR" > order.txt

hpqc encrypt -r alice.pub order.txt -o order.hpqc -s bob-sign.key
hpqc info order.hpqc | tail -1
```

That prints `signed: yes (signer is encrypted; decrypt to see who)`. It does not
say *who* signed, and it cannot: the signature sits inside the AEAD, so the
signer's identity is confidential. Only the recipient can find out.

```console
# verify against a pinned sender key
hpqc decrypt -k alice.key order.hpqc -o v1.txt --sender bob-sign.pub

# without one: it opens, and warns
hpqc decrypt -k alice.key order.hpqc -o v2.txt
```

Read that warning. A signature that verifies against the key *inside the file*
proves the file is self-consistent and nothing about who wrote it — whoever
encrypted it could have generated that signing key a second earlier. Only
`--sender` turns it into a claim about identity.

## 3. Passphrase-protected keys

```console
hpqc keygen -o locked --passphrase     # asks twice
hpqc info locked.key
```

`key id: unavailable without the passphrase` — the wrapper's parameters and the
kind of key it holds are readable, the key itself is not.

```console
echo vault > v.txt
hpqc encrypt -r locked.pub v.txt -o v.hpqc
hpqc decrypt -k locked.key v.hpqc -o v-back.txt      # prompts
cmp v.txt v-back.txt && echo OK
```

Changing the passphrase must not change the identity — otherwise everyone
holding the public key would need a new one:

```console
hpqc info locked.pub          # note the key id
hpqc passwd locked.key
hpqc info locked.pub          # same key id
```

```console
hpqc passwd locked.key --remove
hpqc info locked.key          # no longer wrapped
```

The default cost is ~128 MiB and about a third of a second. `--scrypt-log-n 14`
turns it down; the parameters live in the file, so keys written at different
costs all keep working.

## 4. Large files

Nothing to turn on: past a megabyte the format switches on its own, and
decryption is told by a flag bit in the header.

```console
head -c 5000000 /dev/urandom > big.bin
hpqc encrypt -r alice.pub big.bin -o big.hpqc
hpqc info big.hpqc
hpqc decrypt -k alice.key big.hpqc -o big-out.bin
cmp big.bin big-out.bin && echo "round trip ok"
```

`info` should report `chunked:     yes, 77 chunk(s)` and a `plaintext:` line
that matches `big.bin` exactly. A small file still says `chunked:     no` — the
containers you made in section 1 are byte-for-byte the shape they always were.

Watch the memory, which is the whole point:

```console
/usr/bin/time -f 'streamed:  %M KB' hpqc encrypt -r alice.pub big.bin -o s.hpqc
/usr/bin/time -f 'one-shot:  %M KB' hpqc encrypt -r alice.pub big.bin -o o.hpqc --one-shot
```

On a 200 MB file the difference is roughly 35 MB against 620 MB. On 5 MB it is
35 MB against about 50 MB — the streamed figure does not move with the input,
which is what "streaming" is supposed to buy.

### Cut one chunk off the end

The attack the format exists to stop, and it needs no key:

```console
size=$(stat -c '%s' big.hpqc)
head -c $((size - 65552)) big.hpqc > cut.hpqc     # exactly one 64 KiB chunk
hpqc decrypt -k alice.key cut.hpqc -o cut.bin; echo "exit=$?"
ls cut.bin
```

Every chunk left in `cut.hpqc` is a genuine ciphertext sealed by the real
sender — nothing in it has been altered. It fails anyway, because the chunk
that is now last was sealed with the "not final" marker and has to be opened
with the "final" one. And `ls` should say `cut.bin` does not exist: decryption
writes to a temporary file and renames it only once the last chunk verifies, so
a truncated stream leaves no plausible-looking partial plaintext behind.

Try the same with a chunk *added* (`cat big.hpqc <(tail -c 65552 big.hpqc) >
grown.hpqc`), and with two chunks swapped. All refused.

### Signing a large file

```console
hpqc signgen -o bob-sign
hpqc signgen -o impostor
hpqc encrypt -r alice.pub big.bin -o big-signed.hpqc -s bob-sign.key
hpqc info big-signed.hpqc | grep -E 'chunked|signed'
hpqc decrypt -k alice.key big-signed.hpqc -o back.bin --sender bob-sign.pub
```

```
streamed in 77 chunks of 64 KiB
signed by key id 62e867ac623c8929
chunked:     yes, 77 chunk(s) of up to 64 KiB (+16-byte tag each)
signed:      yes (signer is encrypted; decrypt to see who)
signature ok: signed by key id 62e867ac623c8929
```

It streams *and* it is signed. A signature is still a statement about the whole
message, so hpqc reads the file twice: once to digest it, once to seal it. The
cost moved from memory to I/O.

The signature block goes in front of the plaintext, so a wrong `--sender` is
caught before a single byte is released:

```console
rm -f out.bin
hpqc decrypt -k alice.key big-signed.hpqc -o out.bin --sender impostor.pub
echo "exit=$?"; ls out.bin
```

```
error: this file was signed by key id 62e867ac623c8929, but verification was
requested against b5cabaa4fc81de22
exit=1
ls: cannot access 'out.bin': No such file or directory
```

With the signature in a trailer that file would already have been written. What
*cannot* be caught early is whether the signature is valid, and the temporary
file plus rename is what keeps that from mattering.

One input cannot be read twice, and it says so rather than guessing:

```console
cat big.bin | hpqc encrypt -r alice.pub -s bob-sign.key -o piped.hpqc
cat big.bin | hpqc encrypt -r alice.pub -s bob-sign.key -o x.hpqc --chunked
```

```
note: signing a stream reads the input twice and stdin arrives once;
writing a one-shot container instead
Error: --chunked and --sign need an input that can be read twice: the
signature covers a digest of the whole plaintext and has to exist before
the first chunk is written. Give INPUT as a file rather than on stdin
```

## 5. Several recipients

```console
hpqc keygen -o bob
hpqc keygen -o carol
hpqc keygen -o dave
printf 'minutes of the meeting\n' > minutes.txt

hpqc encrypt -r alice.pub -r bob.pub -r carol.pub minutes.txt -o minutes.hpqc
hpqc info minutes.hpqc
```

```
encrypted to 3 recipients; the file does not name them
recipients:  3 (the file does not name them)
header:      3600 bytes (authenticated as AAD)
kem ct:      1088 bytes x 3
```

All three open it, and dave does not:

```console
for who in alice bob carol; do hpqc decrypt -k $who.key minutes.hpqc; done
hpqc decrypt -k dave.key minutes.hpqc -o /dev/null; echo "exit=$?"
```

```
minutes of the meeting
minutes of the meeting
minutes of the meeting
error: none of this file's 3 recipient slot(s) could be opened with key id
cfd18e698231d3b9; it was encrypted for someone else
exit=1
```

Note what the error cannot say: which key the file *was* for. The stanzas carry
no key ids, so the file genuinely does not know.

### The file names nobody

Search the container for each recipient's key id. It is binary, so hex, not
`grep` on the raw file:

```console
for who in alice bob carol; do
  id=$(hpqc info $who.pub | sed -n 's/^key id: *//p')
  od -An -v -tx1 minutes.hpqc | tr -d ' \n' | grep -q "$id" \
    && echo "$who: FOUND" || echo "$who: not present"
done
```

```
alice: not present
bob: not present
carol: not present
```

An absence is only worth something if the search works, so run the same search
against a single-recipient file, which *does* publish its recipient:

```console
hpqc encrypt -r alice.pub minutes.txt -o one.hpqc
id=$(hpqc info alice.pub | sed -n 's/^key id: *//p')
od -An -v -tx1 one.hpqc | tr -d ' \n' | grep -q "$id" && echo FOUND
```

That prints `FOUND`. `--hide-recipients` gets the same anonymity for one
recipient, and the sizes show what it costs:

```console
hpqc encrypt -r alice.pub --hide-recipients minutes.txt -o hidden.hpqc
stat -c '%n %s' one.hpqc hidden.hpqc minutes.hpqc
```

```
one.hpqc 1207
hidden.hpqc 1291
minutes.hpqc 3639
```

84 bytes to stop naming one recipient — 32 of them the file key commitment,
which the next section is about — and 1174 for each extra one.

### Removing a recipient

```console
hpqc encrypt -r alice.pub -r bob.pub minutes.txt -o pair.hpqc
# drop the last stanza (1174 bytes) and rewrite the count from 2 to 1.
# The count sits at 76 now: 44, plus the 32-byte file key commitment.
head -c $(( $(stat -c%s pair.hpqc) - 1174 )) pair.hpqc > cut.hpqc
printf '\x00\x01' | dd of=cut.hpqc bs=1 seek=76 count=2 conv=notrunc status=none

hpqc info cut.hpqc | grep recipients
hpqc decrypt -k alice.key cut.hpqc -o /dev/null; echo "exit=$?"
```

The header parses and claims one recipient; alice's stanza is untouched and
still hers. It fails anyway, because the whole header is the payload's
associated data — so cutting bob out of the conversation is a denial of
service, not a silent edit.

### Signing to a group

There is no recipient named in the file, so the signature binds the header
instead — the delivery rather than a description of it.

```console
hpqc signgen -o dave-sign
hpqc signgen -o impostor

hpqc encrypt -r alice.pub -r bob.pub -r carol.pub minutes.txt \
  -o signed.hpqc -s dave-sign.key
hpqc info signed.hpqc | grep -E 'recipients|signed'
for who in alice bob carol; do
  hpqc decrypt -k $who.key signed.hpqc -o /dev/null --sender dave-sign.pub
done
```

```
recipients:  3 (the file does not name them)
signed:      yes (signer is encrypted; decrypt to see who)
signature ok: signed by key id f8705c71fad8bb04
signature ok: signed by key id f8705c71fad8bb04
signature ok: signed by key id f8705c71fad8bb04
```

One signature, three recipients, and none of them learns who the others are.
`info` still cannot see who signed, because the signature block is inside the
AEAD.

```console
hpqc decrypt -k bob.key signed.hpqc -o /dev/null --sender impostor.pub
echo "exit=$?"
```

That fails, naming both key ids rather than reporting a cryptographic error for
what is really a key mix-up.

The signature block costs the same as it does anywhere else — post-quantum
signatures are simply large:

```console
hpqc encrypt -r alice.pub -r bob.pub -r carol.pub minutes.txt -o plain.hpqc
stat -c '%n %s' plain.hpqc signed.hpqc
```

```
plain.hpqc 3607
signed.hpqc 8972
```

5365 bytes of it, of which ML-DSA-65's signature alone is 3309.

### The file key commitment

The header commits to the one file key every stanza wraps, so a sender cannot
give Bob one key and Carol another and write them different messages. It sits
at offset 44 and it is 32 bytes:

```console
python -c "
from hpqc.container import parse_header
import pathlib
blob = pathlib.Path('pair.hpqc').read_bytes()
header, _, _ = parse_header(blob)
print('committed:', header.committed)
print('at 44:    ', blob[44:76] == header.commitment)
"
```

```
committed: True
at 44:     True
```

It is not optional. A recipient list without it is refused rather than read as
an older file, because the sender is who chooses — and the sender is who this
defends against. Group containers written before this existed therefore stopped
opening, which is what the frozen vectors in `tests/vectors/v1-recipients.json`
now prove:

```console
python -c "
import json, pathlib
v = json.loads(pathlib.Path('$OLDPWD/tests/vectors/v1-recipients.json').read_text())
pathlib.Path('old.hpqc').write_bytes(bytes.fromhex(v['containers'][-1]['container']))
"
hpqc info old.hpqc; echo "exit=$?"
```

```
error: a file key commitment and a recipient list go together: this header has
flags 0x0004 and exactly one of them; a recipient list written before
commitments were required cannot be opened, because nothing in it stops the
sender giving two recipients two different messages
exit=1
```

## 6. The second hybrid KEM

```console
hpqc keygen -o big --kem mlkem1024
hpqc info big.pub
hpqc encrypt -r big.pub minutes.txt -o big.hpqc
hpqc info big.hpqc | head -6
```

```
algorithms:  X448+ML-KEM-1024
algorithms: X448 + ML-KEM-1024
suite:       X448+ML-KEM-1024/ChaCha20-Poly1305 (0x03)
header:      1672 bytes (authenticated as AAD)
kem ct:      1568 bytes
```

There is no `--kem` on `encrypt`: the recipient's key already decided, and
`--aead` picks only the AEAD. The two meet at the suite byte.

### The suite byte cannot reinterpret a file

It says how every field after it is read, and it arrives unauthenticated. So
relabelling a 1024 container as a 768 one has to fail on arithmetic, long
before any key is touched:

```console
cp big.hpqc relabelled.hpqc
printf '\x01' | dd of=relabelled.hpqc bs=1 seek=5 count=1 conv=notrunc status=none
hpqc info relabelled.hpqc; echo "exit=$?"
```

```
error: ephemeral X25519 public key is 56 bytes, expected 32 here
exit=1
```

The field is named after the suite the file *claims*: byte 5 now says X25519,
so the parser expected 32 bytes and found 56. That is all it has to go on, and
it is enough.

Compare that with the suite downgrade in the next section, which gets all the
way to a tag failure: there the two suites have identical field sizes, so only
the AEAD notices. Here the lengths disagree and the parser stops first.

### One file, one KEM

```console
hpqc encrypt -r big.pub -r alice.pub minutes.txt -o x.hpqc; echo "exit=$?"
hpqc decrypt -k alice.key big.hpqc -o /dev/null; echo "exit=$?"
```

```
Error: alice.pub is X25519+ML-KEM-768 but big.pub is X448+ML-KEM-1024;
one file has one KEM, so these recipients need separate files
exit=1
error: this file uses X448+ML-KEM-1024, but the supplied identity is
X25519+ML-KEM-768
exit=1
```

## 7. What has to fail

This is the interesting part. Each of these must exit non-zero with a readable
message — never a traceback.

```console
# the wrong identity
hpqc keygen -o stranger
hpqc decrypt -k stranger.key secret.hpqc -o /dev/null; echo "exit=$?"

# one flipped byte
cp secret.hpqc tampered.hpqc
dd if=/dev/urandom of=tampered.hpqc bs=1 \
   seek=$(( $(stat -c%s tampered.hpqc) - 1 )) count=1 conv=notrunc status=none
hpqc decrypt -k alice.key tampered.hpqc -o /dev/null; echo "exit=$?"

# signed by someone else
hpqc signgen -o impostor
hpqc decrypt -k alice.key order.hpqc -o /dev/null --sender impostor.pub; echo "exit=$?"

# asking to verify a file that is not signed: fails closed
hpqc decrypt -k alice.key secret.hpqc -o /dev/null --sender bob-sign.pub; echo "exit=$?"

# not an hpqc file at all
hpqc decrypt -k alice.key /bin/ls -o /dev/null; echo "exit=$?"
```

### The suite downgrade

The clearest demonstration of what the associated data is for. Rewrite the
suite byte at offset 5 from ChaCha20-Poly1305 to AES-256-GCM:

```console
cp secret.hpqc downgraded.hpqc
printf '\x02' | dd of=downgraded.hpqc bs=1 seek=5 count=1 conv=notrunc status=none

hpqc info downgraded.hpqc | grep suite
hpqc decrypt -k alice.key downgraded.hpqc -o /dev/null; echo "exit=$?"
```

`info` cheerfully reports **AES-256-GCM**, and decryption fails. The header is
what the file *claims*; nothing in it is trusted until the tag verifies. The
suite byte is covered twice over — by the AEAD's associated data and by the HKDF
transcript — so it cannot be used to steer a recipient onto a different cipher.

## 8. The test suite

```console
pytest -q                 # 788 passed
pytest -q -W error        # clean with warnings escalated to errors
pytest --cov              # 100% of lines and branches, gated at 97% in CI
mypy                      # clean on every matrix Python
tools/ci-local.sh         # the same, on all four Pythons CI uses, in docker
```

The last one exists because one Python is not a matrix. A test written to check
that hpqc survives a reader closing a pipe was itself unportable — it called
`subprocess.communicate()` on a child whose stdin it had already handed away
and closed, which raises before Python 3.12 — and it passed locally, went out,
and turned CI red. `tools/ci-local.sh` reads the version list and the smoke
test straight out of `.github/workflows/ci.yml`, so it cannot drift from what
actually runs.

The most instructive thing you can do with it is break something on purpose and
watch which test notices. Reverse the hybrid combiner in `src/hpqc/hybrid.py`:

```python
def _combine(ss_mlkem: bytes, ss_x25519: bytes) -> bytes:
    return ss_x25519 + ss_mlkem      # was: ss_mlkem + ss_x25519
```

`pytest -q` then fails **20 tests, every one of them in
`tests/test_vectors.py`**. The other 412 pass, because both sides of every round
trip agree with each other — only the frozen vectors know what yesterday's
answer was. Undo it with `git checkout src/hpqc/hybrid.py`.

Now the streaming one. In `src/hpqc/streaming.py`, make the final-chunk marker
stop meaning anything:

```python
_FINAL = b"\x00"      # was: b"\x01"
```

That fails **15 tests** — four in `tests/test_streaming.py` and eleven in
`tests/test_vectors.py`, including every recorded chunked container. One test
does *not* fail, and it is the interesting one:
`test_without_the_final_marker_truncation_succeeds` passes, because it asserts
that with the marker gone a truncated file decrypts cleanly. Run it on its own
to watch a 3-chunk file quietly turn into a 2-chunk one:

```console
pytest -q -k without_the_final_marker
```

Then the streamed signature. In `src/hpqc/signing.py`, stop feeding the digest
into the signed message:

```python
def stream_signed_message(digest, sender, header_bytes, suite):
    return b"".join((
        SIG_STREAM_LABEL, bytes([suite.id]),
        sender.ed25519_bytes, sender.mldsa_bytes,
        U32.pack(len(header_bytes)), header_bytes,
        # digest,          <- removed
    ))
```

That fails **3 tests in `tests/test_stream_signing.py` and 6 in
`tests/test_vectors.py`**, and the three are the ones that matter: a recipient
re-sealing a changed, a shorter, or a longer plaintext. Every chunk in those
forgeries is genuine and properly framed, so nothing else in the tool has a
word to say about them.

Now the one that breaks every file ever written and changes no behaviour at
all. In `src/hpqc/hybrid.py`, edit the label the wrapping key is derived under:

```python
WRAP_LABEL = b"hpqc-v1 file key wrap x25519+ml-kem-768 CHANGED"
```

`pytest -q` fails **10 tests, every one of them in `tests/test_vectors.py`**.
The other 533 pass — every round trip still works, because the writer and the
reader moved together. What actually happened is that every file anyone had
already encrypted to a recipient list became permanently unopenable. Reordering
the stanza fields in `Stanza.pack` and `read_stanza` does the same thing and
fails 28, all of them vectors. This is the argument for recording a
*derivation* rather than a container: a recorded container that stops opening
tells you something changed and never which thing.

Two more worth trying the same way, both in `src/hpqc/signing.py`:

- Delete `recipient.x25519_bytes` and `recipient.mlkem_bytes` from
  `signed_message` and surreptitious forwarding starts working again.
  `test_the_signed_message_construction_is_unchanged` names it.
- Skip the `signer.mldsa().verify(...)` call and the scheme quietly stops being
  hybrid. `test_the_ed25519_signature_alone_is_not_enough` catches it.
