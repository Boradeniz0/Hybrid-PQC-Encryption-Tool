"""Support `python -m hpqc` alongside the installed `hpqc` script."""

import sys

from .cli import run

if __name__ == "__main__":  # pragma: no cover - only true in a subprocess
    # Exercised by the tests that run `python -m hpqc` for real, which is the
    # only way to run it; coverage does not follow a subprocess.
    sys.exit(run())
