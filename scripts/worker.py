#!/usr/bin/env python3
"""Worker entry point for a self-contained staged agenix-helper bundle."""

import sys
from pathlib import Path

sys.dont_write_bytecode = True

from agenix_helper.crypto import worker_main  # noqa: E402
from agenix_helper.process import entrypoint  # noqa: E402

if __name__ == "__main__":
    sys.exit(entrypoint(lambda: worker_main(Path(__file__).resolve().parent)))
