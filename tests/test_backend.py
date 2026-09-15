"""The messages a machine without post-quantum support gets.

hpqc needs `cryptography` >= 46 built against OpenSSL >= 3.5, and on a machine
without it the failure arrives from deep inside a key operation as an
ImportError or a bare `UnsupportedAlgorithm`. backend.py exists to turn that
into one paragraph that says what is missing and what to install.

None of it runs on a machine that *has* the support -- which is every machine
the test suite has ever run on -- so the unavailable state is simulated by
setting the module's captured classes to None, exactly as the import failure
would have. What is checked is that the message names the algorithm, explains
the requirement, and carries the underlying error rather than swallowing it.
"""

from __future__ import annotations

import pytest

from hpqc import backend
from hpqc.errors import BackendError
from cryptography.exceptions import UnsupportedAlgorithm


@pytest.fixture
def without_mlkem(monkeypatch):
    monkeypatch.setattr(backend, "MLKEM768PrivateKey", None)
    monkeypatch.setattr(backend, "MLKEM1024PrivateKey", None)
    monkeypatch.setattr(
        backend, "_MLKEM_IMPORT_ERROR", ImportError("no module named mlkem")
    )


@pytest.fixture
def without_mldsa(monkeypatch):
    monkeypatch.setattr(backend, "MLDSA65PrivateKey", None)
    monkeypatch.setattr(
        backend, "_MLDSA_IMPORT_ERROR", ImportError("no module named mldsa")
    )


def test_it_reports_what_is_available_here() -> None:
    """The suite cannot run at all without these, so this is the honest baseline."""
    assert backend.mlkem_available()
    assert backend.mldsa_available()


def test_require_mlkem_explains_itself(without_mlkem) -> None:
    with pytest.raises(BackendError) as caught:
        backend.require_mlkem()

    message = str(caught.value)
    assert "ML-KEM-768 is unavailable" in message
    assert "cryptography" in message and "OpenSSL >= 3.5" in message
    assert "no module named mlkem" in message


def test_require_mlkem_names_the_parameter_set_that_was_wanted(without_mlkem) -> None:
    """One import decides both, so the name comes from the caller."""
    with pytest.raises(BackendError, match="ML-KEM-1024 is unavailable"):
        backend.require_mlkem("ML-KEM-1024")


def test_require_mldsa_is_separate(without_mldsa) -> None:
    """A machine that can encrypt is not refused because it cannot sign."""
    backend.require_mlkem()  # still fine

    with pytest.raises(BackendError, match="ML-DSA-65 is unavailable"):
        backend.require_mldsa()
    assert not backend.mldsa_available()
    assert backend.mlkem_available()


def test_mlkem_unavailable_is_reported_by_the_flag(without_mlkem) -> None:
    assert not backend.mlkem_available()


def test_wrap_unsupported_keeps_the_underlying_error() -> None:
    """OpenSSL's own words matter: they say which build is installed."""
    wrapped = backend.wrap_unsupported(
        UnsupportedAlgorithm("ML-KEM is not supported by this backend")
    )
    assert isinstance(wrapped, BackendError)
    assert "ML-KEM-768 is unavailable" in str(wrapped)
    assert "not supported by this backend" in str(wrapped)


def test_wrap_unsupported_can_name_another_algorithm() -> None:
    wrapped = backend.wrap_unsupported(
        UnsupportedAlgorithm("nope"), "ML-DSA-65"
    )
    assert "ML-DSA-65 is unavailable" in str(wrapped)


def test_a_missing_backend_stops_key_generation_with_that_message(
    without_mlkem,
) -> None:
    """The path a user on an old OpenSSL actually takes."""
    from hpqc.keys import PrivateKey

    with pytest.raises(BackendError, match="is unavailable"):
        PrivateKey.generate()


def test_a_missing_signing_backend_stops_signing_only(
    without_mldsa, alice, alice_pub
) -> None:
    """Which is the whole reason the two checks are separate functions."""
    from hpqc import container
    from hpqc.keys import SigningPrivateKey

    blob = container.encrypt(b"still works", alice_pub)
    assert container.decrypt(blob, alice) == b"still works"

    with pytest.raises(BackendError, match="ML-DSA-65 is unavailable"):
        SigningPrivateKey.generate()
