"""Manual read-only acceptance of an explicitly supplied completed strict review.

APPSEC_F01_ACCEPTANCE_RUN must name an isolated run with an admitted repair, actual internal
build iterations and a subsequent accepted indexing publication. This check launches nothing.
"""

import json
import os
from pathlib import Path

import pytest

from appsec_review.indexing.store import accepted_handoff
from appsec_review.runtime.repair import current_binding, verify_publication
from appsec_review.storage.shared import verify_reference


@pytest.mark.time_budget(30, reason="Read and verify the supplied run's accepted inventory artifact")
def test_repaired_review_inventory_preserves_internal_attempt_accounting():
    selected = os.environ.get("APPSEC_F01_ACCEPTANCE_RUN")
    assert selected, "manual prerequisite: APPSEC_F01_ACCEPTANCE_RUN is not set"
    root = Path(selected).resolve(strict=True)
    assert (root / "data/recovery/repairs").is_dir(), "fixture must contain an admitted repair"
    indexing = accepted_handoff(root, "job_review_data_indexing")
    assert indexing is not None, "fixture has no accepted indexing publication after repair"
    verify_publication(root, indexing.handoff, indexing.sha256)
    claim_path = indexing.handoff["resolving_paths"]["attempt"] + "/claim.json"
    claim_ref = next(ref for ref in indexing.handoff["artifacts"] if ref["path"] == claim_path)
    claim = json.loads(verify_reference(root, claim_ref).read_bytes())
    binding = current_binding(root)
    assert binding is not None and binding["repair"] is not None
    assert claim["repair_admission_sha256"] == binding["repair"]["sha256"], (
        "accepted indexing must follow the current admitted repair")
    reference = indexing.handoff["outputs"]["audit.inventory"]["artifact"]
    report = json.loads(verify_reference(root, reference).read_bytes())
    assert report["audit"]["status"] == "PASSED", report["audit"]["violations"]
    assert report["run_tree"]["audit_scope"] == "full_customer_evidence"
    assert report["run_tree"]["scratch_audited"]
    assert report["run_tree"]["unaccounted_count"] == 0
    internal = [row for row in report["file_ownership"] if row["job_id"] == "job_build_iteration"]
    assert any(row["attempt_id"] for row in internal), "fixture must contain actual internal attempts"
    assert all(row["accounting_only"] and not row["in_publication_stage"] for row in internal)
    assert not any(row["job_id"] == "job_build_iteration" for row in report["rows"])
    recovery = next(row for row in report["rows"] if row["output_kind"] == "recovery_records")
    assert recovery["disposition"] == "protected"
