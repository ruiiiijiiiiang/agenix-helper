#!/usr/bin/env python3
"""Controller entry point for agenix-helper."""

import sys

sys.dont_write_bytecode = True

from agenix_helper.cli import main  # noqa: E402
from agenix_helper.process import entrypoint  # noqa: E402

if __name__ == "__main__":
    sys.exit(entrypoint(main))
