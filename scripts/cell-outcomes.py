#!/usr/bin/env python3
"""Report where an inference review run spent its cells: per-role attempt outcomes and reasons, retrieval tool
errors, per-package attempt counts and model-call wall time by outcome (T-5028, step one).

Reads the run's ledgers, cell attempt receipts and model execution receipts; writes only
data/verification/cell-outcomes.{json,txt} when --write is given. A lane that has not sealed yet reports its
cells as ``unattributed``.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]

from appsec_review.reporting.cell_outcomes import main

if __name__ == "__main__":
    raise SystemExit(main())
