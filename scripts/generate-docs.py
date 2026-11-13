#!/usr/bin/env python3
"""Generate documentation from checked-in contracts, never from a review run."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from scripts.documentation import main

if __name__ == "__main__":
    raise SystemExit(main())
