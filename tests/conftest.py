"""Shared fixtures.

Key generation is cheap but not free, and most tests only need *a* valid
identity, so the two stock identities are generated once per session.
"""

from __future__ import annotations

import pytest

from hpqc.keys import PrivateKey


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
