#!/usr/bin/env python3
"""Score a completed smoke run: structural checks, and keyed scoring when the user supplies the answer key.

Writes runs/<run-id>/data/verification/smoke-score.json and smoke-score.txt; changes nothing else in the run.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]

from appsec_review.reporting.smoke_score import main

if __name__ == "__main__":
    raise SystemExit(main())
