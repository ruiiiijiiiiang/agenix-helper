#!/usr/bin/env python3
"""Worker entry point for a self-contained staged agenix-toolkit bundle."""

import sys
from pathlib import Path

sys.dont_write_bytecode = True

from agenix_toolkit.crypto import worker_main  # noqa: E402
from agenix_toolkit.process import entrypoint  # noqa: E402

if __name__ == "__main__":
    sys.exit(entrypoint(lambda: worker_main(Path(__file__).resolve().parent)))
