"""Shared fixtures.

Key generation is cheap but not free, and most tests only need *a* valid
identity, so the two stock identities are generated once per session.
"""

from __future__ import annotations

import pytest

from hpqc.keys import PrivateKey, SigningPrivateKey


@pytest.fixture(scope="session")
def alice() -> PrivateKey:
    return PrivateKey.generate()


@pytest.fixture(scope="session")
def bob() -> PrivateKey:
    return PrivateKey.generate()


@pytest.fixture(scope="session")
def alice_pub(alice: PrivateKey):
    return alice.public_key()


@pytest.fixture(scope="session")
def bob_pub(bob: PrivateKey):
    return bob.public_key()


@pytest.fixture(scope="session")
def carol() -> SigningPrivateKey:
    """A sender: the signing identity used throughout the signature tests."""
    return SigningPrivateKey.generate()


@pytest.fixture(scope="session")
def carol_pub(carol: SigningPrivateKey):
    return carol.public_key()


@pytest.fixture(scope="session")
def mallory() -> SigningPrivateKey:
    """A second, unrelated signing identity, for "signed by someone else"."""
    return SigningPrivateKey.generate()


@pytest.fixture(scope="session")
def mallory_pub(mallory: SigningPrivateKey):
    return mallory.public_key()
