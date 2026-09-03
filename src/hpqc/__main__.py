"""Support `python -m hpqc` alongside the installed `hpqc` script."""

import sys

from .cli import run

if __name__ == "__main__":
    sys.exit(run())
