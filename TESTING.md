# Trying hpqc by hand

The automated suite covers all of this and more (`pytest`, 432 tests). This is
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
hpqc encrypt -r alice.pub big.bin -o big-signed.hpqc -s bob-sign.key
hpqc info big-signed.hpqc | grep chunked
```

It prints a note on stderr and writes a one-shot container. A signature is a
statement about a whole message, so it cannot be made until the whole message
has been read; hpqc keeps the signature and gives up the streaming rather than
the other way round. Asking for both explicitly is refused outright:

```console
hpqc encrypt -r alice.pub big.bin -o x.hpqc -s bob-sign.key --chunked
```

## 5. What has to fail

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

## 6. The test suite

```console
pytest -q                 # 432 passed
pytest -q -W error        # clean with warnings escalated to errors
```

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

Two more worth trying the same way, both in `src/hpqc/signing.py`:

- Delete `recipient.x25519_bytes` and `recipient.mlkem_bytes` from
  `signed_message` and surreptitious forwarding starts working again.
  `test_the_signed_message_construction_is_unchanged` names it.
- Skip the `signer.mldsa().verify(...)` call and the scheme quietly stops being
  hybrid. `test_the_ed25519_signature_alone_is_not_enough` catches it.
