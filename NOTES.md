# What I got wrong

Every one of these was a real bug or a real gap in this repository, and each one
is here because of *how* it surfaced. The method is the point: a test suite that
agrees with itself, a coverage number, and a green CI badge can all be true
while something is broken.

## A guard sat on the wrong command for months, and no test could see it

hpqc refused to write binary data to a terminal. A good rule, applied to the
wrong command. It fired on *decryption*, so `hpqc decrypt -k k.key f.hpqc`, the
most ordinary command the tool has, failed on every real terminal. So did the
pipeline the README leads with, whose last stage writes to one.

789 tests said everything was fine. They could not see it: the test runner hands
the command a StringIO, so `isatty()` was False in every test ever written here
and the guard never once ran. The manual guide had the same blind spot for the
same reason, because its expected output was captured from a non-tty shell.

It took someone working through that guide on a real terminal and hitting the
error seven times in one sitting.

The guard now applies to containers, which are binary by construction. A
decrypted plaintext is the caller's own file, and refusing to hand it over in
case it is untidy is a guess about a file they already know. `gpg -d`, `age -d`
and `openssl enc -d` all simply write it.

There are now three tests that drive the real binary against a real pty, because
that is the only way to have a terminal to be wrong about.

## I shipped a group encryption feature with a hole in it

Three commits after adding multiple recipients I went looking for remaining work
and reread the threat model instead of the code. Every recipient unwraps a file
key from their own stanza, and nothing made those keys *the same* key.

ChaCha20-Poly1305 and AES-GCM are not key-committing, so a sender could wrap one
key to Bob and another to Carol, seal one crafted payload, and have them read
different messages under a tag that verifies for both. Signing does not help:
the signature block is inside the payload, so each view carries its own.

I had written, in that very section, that any recipient can re-send the file as
if it came from you, and answered it with signing. I had not asked the mirrored
question: what can the *sender* do to a group that it cannot do to one person.

The fix is 32 bytes and a comparison. Finding it was rereading my own threat
model with the feature in front of me, which is not something a test suite can
do for you.

## Only the frozen vectors noticed a change that broke every file

Changing the HKDF label that the wrapping key is derived under leaves the tool
perfectly self-consistent. The writer and the reader move together, every round
trip still works, and every file anyone had already encrypted becomes
permanently unopenable.

I ran it: 410 tests passed and not one of them was the vectors. Reordering the
stanza fields on the wire does the same thing, and fails 28, all of them
vectors.

That is the whole argument for recording a *derivation* rather than a container.
A recorded container that stops opening tells you something changed and never
which thing, because a self-consistent change breaks it in exactly the same way
a corrupt file would.

## One byte is the whole difference between a stream and a forgery

To check that the final-chunk marker actually does anything, I removed it, re-ran
the truncation attack against a 3-chunk file, and got 128 KiB of correct
plaintext with no error at all. Not a crash, not a warning: a shorter file that
verifies.

A test asserting only "the attack fails today" would have passed under both
versions of the code and told me nothing about which byte was stopping it. There
is now a test that disables the marker and asserts the truncation *succeeds*, so
the defence is named rather than assumed.

## A domain separation label that nothing behavioural pins

hpqc gives its two one-shot signing constructions different labels, which is the
standard hygiene. I went to check that the tests caught a shared label, and they
did not. All 557 other tests passed with the two set equal.

The reason is that the messages already differ structurally: one carries 1216
bytes of recipient public keys where the other carries a 4-byte length and a
header, and no legal header is 1212 bytes long, so the two can never line up.

That is an accident of two constants, not a property to rely on. Add a suite
with a larger ML-KEM key and it can stop holding while every test still passes.
So the label is pinned by direct assertion, next to a comment saying why it has
to be. The honest version of "the tests catch it" is sometimes "they cannot, and
here is what I did instead".

## hpqc info told you the wrong algorithms about a key it could not read

A passphrase-protected X448 + ML-KEM-1024 key was described as "X25519 +
ML-KEM-768 private key". Flatly, confidently wrong.

The wrapper records whether the sealed blob is an encryption identity or a
signing one. Which KEM an encryption identity uses is the first byte *inside*
the blob, which is exactly what the passphrase protects. The label had been
written when there was only one answer, and stayed when there were two.

It now says "encryption private key" and names nothing it cannot see, which is
what the same output already did two lines below for the key id. The fix is
smaller than the lesson: a field that was true when it was written is not the
same thing as a field that is true.

## The annotations were decoration in two places

`Suite.aead` was `Callable[[bytes], object]`, so every `.encrypt` and `.decrypt`
call in the project was unchecked. A typo in either would have been caught by a
test rather than by a tool. And half the signatures said `BinaryIO` where what
actually gets passed has exactly one method: the prefixing reader, the
drip-feeding stand-in for a pipe, the verifier that sits between the chunk
reader and the real sink.

Naming the contracts made mypy mean something and the code honest at the same
time. It also immediately found a name collision I had just introduced between
the new stream `Reader` and `wire.Reader`, which is two types with one name in
one file.

## Three pieces of code turned out to be unreachable

Writing the last of the error-path tests found:

- a `cannot read X` handler that click's own `Path(exists=True)` gets to first,
  because it checks readability too;
- a CRLF branch in the passphrase reader that could never run, because
  `read_text` opens in text mode and normalises CRLF to LF before the
  comparison;
- an accessor on `PublicKey` that nothing called, because a recipient's
  Diffie-Hellman half is only ever the peer of an exchange and that path takes
  raw bytes.

The dead branch and the dead accessor are gone. The handler stays, marked for
what it is, because a read with no error handling is how a traceback gets
shipped.

Chasing coverage for its own sake is busywork. Chasing it until every line has a
reason to exist is a different activity.

## A shell check that failed about one run in ten

The CI smoke test was full of lines like
`hpqc info f.hpqc | grep -q '^recipients:  3'`. `grep -q` exits at its first
match, so if the writer still has a line to go it is killed by SIGPIPE, and
under `set -o pipefail` that turns a check which *passed* into a failed script.

It is a race, so it fails sometimes, which is exactly the shape of thing that
gets rerun and forgotten. Worse is the same pattern inside an `if`: the status
goes non-zero, the else branch runs, and a check for a leaked key id reports it
as absent.

Every one of them now runs the command, then greps the file it wrote.

## hpqc decrypt big.hpqc | head exited 1 and said nothing

Chasing the above found the real bug underneath it. Python ignores SIGPIPE and
turns the failed write into `BrokenPipeError`. `run()` had a handler for exactly
that, and it never ran, because click catches EPIPE first and calls
`sys.exit(1)` after silencing the flush.

So the most ordinary pipeline in the world failed, with an empty stderr and no
explanation. Restoring SIGPIPE's default disposition makes hpqc behave like
`cat`: the write that has nowhere to go kills the process, the shell sees 141,
and nothing is printed.

## The test for a portability fix was itself unportable

The test written to check that SIGPIPE fix called `subprocess.communicate()` on a
child whose stdin it had already handed away and closed, which raises
`ValueError: flush of closed file` before Python 3.12. It passed on the
development machine, went out, and turned CI red on the two oldest Pythons in
the matrix, which is exactly the version-specific behaviour the fix underneath
it was about.

What the episode actually produced is `tools/ci-local.sh`. The repository was
private, so the CI logs were not readable from a terminal, and a matrix you
cannot run is a matrix you find out about afterwards.

That script then made the same class of mistake twice more. Its first version
hardcoded `pytest -q` and knew nothing about the type-check step or the coverage
gate the workflow had gained, which is the exact drift it was written to
prevent. Then the first version of its workflow parser handled only `run: |` and
not `run: mypy`, so two steps ran as empty scripts and reported success. It now
refuses to run if a step comes out empty.

## A full disk was eight frames of Python

`hpqc keygen -o k` on a filesystem with no room left printed a traceback ending
in `OSError: [Errno 122] Disk quota exceeded`. The tool has a careful error path
for every way a *file* can be wrong, and none at all for the machine underneath
it being full, read-only, or gone.

That is the same mistake in both directions. `HpqcError` covers what the input
says; `OSError` covers what the disk says; only the first had a handler, so the
second reached the user as a stack trace with the one useful line buried at the
bottom. It surfaced when the user's disk filled up, which is to say by accident,
on a machine that happened to be out of space that afternoon.

`run()` now catches `OSError` too and prints `error: <strerror> while writing
<path>`, which is the same information the last line of the traceback had. The
two tests make the write fail from inside, because a test cannot fill a disk;
what confirms the real thing is `bash -c 'ulimit -f 0; hpqc keygen -o k'`, which
produces a genuine `OSError` from the kernel and now prints one line.

## A stat() one line too early

While tidying `hpqc info` to read headers from a stream, I moved the `stat()`
for the file size one line above the `open()` instead of one line below. `hpqc
info nope.hpqc` then raised `FileNotFoundError` instead of saying "cannot read
nope.hpqc".

Six hundred tests did not catch it, because `info` is the one command whose path
click cannot check with `exists=True`, since it also reads stdin, and no test
had ever given it a path that was not there. The CI smoke script found it within
a minute of being run.

## The declared Python floor was wrong

`requires-python = ">=3.9"` looked fine and was not. `cryptography>=46` declares
`!=3.9.0,!=3.9.1`, so on those two releases `pip install` fails in the resolver
rather than with a useful message. Setting up the CI matrix is what surfaced it.
