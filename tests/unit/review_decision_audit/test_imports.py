"""Cold import order must not depend on other tests priming the job package."""
import subprocess
import sys

import pytest


@pytest.mark.parametrize("module", [
    "appsec_review.review.decision_audit.contracts",
    "appsec_review.review.decision_audit.metadata",
    "appsec_review.review.decision_audit.reader",
    "appsec_review.reporting.dossiers",
    "appsec_review.reporting.telemetry_finalize",
    "appsec_review.observability.findings.cli",
    "appsec_review.jobs.job_inference_security_review",
    "appsec_review.jobs.job_final_publication_gate",
], ids=lambda module: module.rsplit(".", 1)[-1])
def test_cold_import_preserves_real_contract_validation(module):
    result = subprocess.run(
        [sys.executable, "-I", "-c", """
import importlib
import sys
importlib.import_module(sys.argv[1])
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.models import IntegrityError
assert c.Link("original-id", None).to_dict() == {"value": "original-id", "absence_reason": None}
try:
    c.Link("original-id", c.AbsenceReason.NOT_PRODUCED)
except IntegrityError:
    pass
else:
    raise AssertionError("cold import bypassed closed contract validation")
""", module],
        capture_output=True, text=True, timeout=8, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
