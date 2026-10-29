"""Exhaustive-only vectors over independently materialized, driver-owned consumers."""
from __future__ import annotations

import hashlib
import json

import pytest

from appsec_review.acceptance.answer_key import Defect, evaluate_current_report
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.storage import file_sha256
from appsec_review.storage.validation import current_validation, validation_scope
from tests.acceptance_review_stages import consumer_chain
from tests.final_report_support import REPORT
from tests.integration.test_current_report_acceptance import (
    ROOT, _assert_identity_matrix, _orphan_scanner_hit,
)


VECTORS = (
    "identity-state-bucket",
    "missing-current",
    "orphan-hit",
    "report-tamper",
    "manifest-tamper",
    "finding-tamper",
    "handoff-tamper",
    "same-length-report-tamper",
)


@pytest.fixture
def current_report():
    staged = consumer_chain("ci-positive")
    if staged is None:
        raise ValueError("exhaustive integrity cases require a supervised private consumer tree")
    lane, chain = staged
    reference = chain.handoff(REPORT)["outputs"]["report.assemble"]["artifact"]
    # This bounded read only locates mutations; the oracle revalidates after mutation.
    report = read_bound_json(chain.run_root, reference)
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    defect = Defect(
        "untrusted-ci", "CWE-829", ".github/workflows/ci.yml", 1, "", (),
        claim_id=finding["claim_id"], finding_package_id=finding["finding_package_id"])
    return lane, chain, defect, report


@pytest.mark.parametrize("vector", VECTORS, ids=VECTORS)
def test_current_report_integrity_vector(vector, current_report):
    lane, chain, defect, report = current_report
    assert current_validation(chain.run_root) is None
    if vector == "identity-state-bucket":
        _assert_identity_matrix(current_report)
    elif vector == "orphan-hit":
        orphan = _orphan_scanner_hit(chain)
        _assert_identity_matrix(current_report, additional=(orphan,))
        path = chain.run_root / "data" / "indices" / "observations" / "superseded" / "stale.sqlite"
        lane.emit(
            "ACCEPTANCE_MUTATION_VALIDATED", vector=vector, run_root=str(chain.run_root),
            path=path.relative_to(chain.run_root).as_posix(), after_sha256=file_sha256(path),
            mutation="orphan-scanner-hit", validator="evaluate_current_report", outcome="missed-not-gap")
    else:
        if vector == "missing-current":
            path = chain.run_root / "data" / "jobs" / REPORT / "latest.json"
        elif vector in {"report-tamper", "same-length-report-tamper"}:
            path = chain.run_root / chain.handoff(REPORT)["outputs"]["report.assemble"]["artifact"]["path"]
        elif vector == "manifest-tamper":
            pointer = json.loads((chain.run_root / "data" / "indices" / "accepted.json").read_text(
                encoding="utf-8"))
            path = chain.run_root / pointer["manifest_path"]
        elif vector == "finding-tamper":
            path = chain.run_root / report["findings"][0]["path"]
        elif vector == "handoff-tamper":
            pointer = json.loads((chain.run_root / "data" / "jobs" / REPORT / "latest.json").read_text(
                encoding="utf-8"))
            path = chain.run_root / pointer["handoff_path"]
        else:
            raise ValueError("undeclared exhaustive integrity vector")
        original = path.read_bytes()
        if vector == "missing-current":
            path.unlink()
            changed = None
        else:
            changed = b"[" + original[1:] if vector == "same-length-report-tamper" else original + b" "
            assert changed != original
            if vector == "same-length-report-tamper":
                assert len(changed) == len(original)
            path.write_bytes(changed)
        with lane.span(vector), validation_scope(chain.run_root):
            result = evaluate_current_report([defect], chain.run_root, schema_root=ROOT)
        assert result.failed and result.missed == [defect.id] and result.gaps and not result.found
        lane.emit(
            "ACCEPTANCE_MUTATION_VALIDATED", vector=vector, run_root=str(chain.run_root),
            path=path.relative_to(chain.run_root).as_posix(),
            before_sha256=hashlib.sha256(original).hexdigest(),
            after_sha256=hashlib.sha256(changed).hexdigest() if changed is not None else None,
            same_size=changed is not None and len(original) == len(changed),
            validator="evaluate_current_report", outcome="rejected", gaps=list(result.gaps))
    assert current_validation(chain.run_root) is None
    lane.emit("ACCEPTANCE_CASE_FINISHED", case=vector)
