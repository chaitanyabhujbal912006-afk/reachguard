"""CLI entry point wrapper for PyPI / package distribution."""

import sys
from pathlib import Path

# Ensure project root is in sys.path when invoked as installed package
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from main import app

if __name__ == "__main__":
    app()
