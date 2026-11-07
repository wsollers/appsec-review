"""Manual, read-only acceptance of an operator-supplied F02 review publication."""
import json
import os
from pathlib import Path

import pytest

from appsec_review.indexing.store import accepted_handoff
from appsec_review.runtime.contracts import read_job_contract
from appsec_review.runtime.inputs import read_input_observations
from appsec_review.storage.shared import verify_reference


@pytest.mark.time_budget(60, reason="Verify accepted input contracts and read receipts in a supplied review")
def test_published_review_preserves_admitted_input_and_read_identities():
    selected = os.environ.get("APPSEC_F02_ACCEPTANCE_RUN")
    assert selected, "manual prerequisite: APPSEC_F02_ACCEPTANCE_RUN is not set"
    root = Path(selected).resolve(strict=True)
    for job_id in ("job_review_data_indexing", "job_review_package_assembly", "job_final_publication_gate"):
        accepted = accepted_handoff(root, job_id)
        assert accepted is not None, f"manual prerequisite: no accepted {job_id}"
        handoff = accepted.handoff
        claim_path = handoff["resolving_paths"]["attempt"] + "/claim.json"
        ref = next(item for item in handoff["artifacts"] if item["path"] == claim_path)
        claim = json.loads(verify_reference(root, ref).read_bytes())
        assert claim["dataset_contract"]["schema"] == "appsec-review/attempt-datasets/3"
        contract = read_job_contract(claim["dataset_contract"]["job_contract"])
        observations = read_input_observations(root, handoff)
        assert observations is not None
        assert observations["citation_observation"] == "not_observed"
        declared = {item.key: item for item in contract.inputs}
        for observed in observations["reads"]:
            key = observed["channel"], observed["producer"], observed["output_kind"]
            requirement = declared[key]
            assert observed["schema"] == requirement.schema
            assert observed["authority"] == requirement.authority
            assert observed["read"] is True and observed["cited"] is None
            if observed["channel"] == "handoff":
                assert observed["handoff_sha256"] == claim["upstream_handoffs"][observed["producer"]]
