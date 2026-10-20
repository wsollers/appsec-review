"""Live system acceptance (SAT/SIT) of a complete ``wave1_review`` run through Dagster.

Operator-run, skipped unless ``APPSEC_REVIEW_SYSTEM_ACCEPTANCE`` is set. It needs the Dagster stack
from ``deploy/dagster`` running on the pinned images, reviewing the corpus the baselines were
accepted on, with the model backend configured, and it uses the Docker daemon and the real model.

    APPSEC_REVIEW_SYSTEM_ACCEPTANCE=cpp-multivuln-v1 \\
        python -m pytest tests/live/test_wave1_system_live.py --basetemp=test/tmp/system

Set ``APPSEC_REVIEW_SYSTEM_RUN`` to an application run id to evaluate a finished run instead of
starting one. The check is ``stepwise.py system`` (docs/processes/local-dagster-parity.md): every
job accepted, every handoff intact, the final review packages and document-issue ledger valid, the
output equal to the accepted baselines, and no seeded defect missed.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
TAG = os.environ.get("APPSEC_REVIEW_SYSTEM_ACCEPTANCE", "")

pytestmark = [
    pytest.mark.skipif(not TAG, reason="set APPSEC_REVIEW_SYSTEM_ACCEPTANCE=<corpus tag> to run the live system test"),
]


def _stepwise():
    bin_dir = ROOT / "deploy" / "dagster" / "bin"
    import sys

    sys.path.insert(0, str(bin_dir))
    spec = importlib.util.spec_from_file_location("stepwise_system", bin_dir / "stepwise.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_complete_wave1_review_runs_in_dagster_and_meets_the_accepted_corpus(capsys) -> None:
    arguments = ["--interval-seconds", "30", "system", "--tag", TAG]
    run = os.environ.get("APPSEC_REVIEW_SYSTEM_RUN")
    if run:
        arguments += ["--app-run", run]
    status = _stepwise().main(arguments)
    output = capsys.readouterr().out
    print(output)
    assert status == 0, "\n".join(line for line in output.splitlines() if "answer-key MISSED" in line
                                  or line.startswith(("system", "== SYSTEM", "compare", "   integrity")))[-4000:]
