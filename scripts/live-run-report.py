#!/usr/bin/env python3
"""Serve or export a read-only nested dossier-style live HTML report for a review run.

Displays run status, nested wave/job progress, # findings, model/performance metrics, and the top-N
ranked findings (or a slanted diagonal N/A watermark when # findings == 0), auto-refreshing every
5 minutes (300 seconds) by default. Never modifies runs/<run-id>/.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]

from appsec_review.reporting.live_report import main

if __name__ == "__main__":
    raise SystemExit(main())
