from copy import deepcopy
from dataclasses import replace

import pytest

from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.publication import AuditUnavailable
from appsec_review.review.models import IntegrityError

from .helpers import RED, VERIFIER, digest, document, fixture, reference


@pytest.mark.parametrize("change", [
    {"schema": "unsupported/1"}, {"cell_id": "foreign"}, {"attempt": 2}, {"attempt_id": "foreign"},
    {"status": "failed"}, {"result_sha256": "0" * 64}, {"result": None}, {"unexpected": True},
    {"reused_from": {}},
], ids=["schema", "cell", "attempt", "attempt-id", "status", "result-hash", "result", "closed-keys", "reuse"])
def test_hash_bound_but_malformed_receipt_is_integrity_failure(tmp_path, change):
    f = fixture(tmp_path, receipt_change=change)
    with pytest.raises(IntegrityError):
        f.publish()


@pytest.mark.parametrize("change", ["schema", "keys", "duplicate", "omitted", "foreign-cell", "foreign-claim",
                                   "foreign-package", "hash", "round", "decision"])
def test_capture_membership_is_verified_not_trusted(tmp_path, change):
    f = fixture(tmp_path)
    lane = deepcopy(f.inputs.lanes[0].value)
    capture = lane["proposal_audit"]
    row = capture["items"][0]
    if change == "schema":
        capture["schema"] = "unknown"
    elif change == "keys":
        row["arbitrary"] = "not accepted"
    elif change == "duplicate":
        capture["items"].append(dict(row))
    elif change == "omitted":
        capture["items"] = []
    else:
        field, value = {"foreign-cell": ("cell_id", "foreign"), "foreign-claim": ("claim_id", "foreign"),
                        "foreign-package": ("package_id", "foreign"), "hash": ("receipt_sha256", digest("wrong")),
                        "round": ("round", 8), "decision": ("decision", "unsupported")}[change]
        row[field] = value
    f.inputs = replace(f.inputs, lanes=(replace(f.inputs.lanes[0], value=lane),))
    with pytest.raises(IntegrityError):
        f.project()


@pytest.mark.parametrize("change", ["population", "lead-source", "duplicate-adjudication", "absent-adjudication",
                                   "absent-producer", "absent-relation", "state", "structure"])
def test_real_projection_crosschecks(tmp_path, change):
    f = fixture(tmp_path)
    error = IntegrityError
    if change == "population":
        f.inputs = replace(f.inputs, collection=replace(f.inputs.collection, leads=f.inputs.collection.leads[:1]))
    elif change == "lead-source":
        f.inputs = replace(f.inputs, lead_sources={})
    elif change in ("duplicate-adjudication", "absent-adjudication", "absent-relation", "state"):
        doc = deepcopy(f.inputs.adjudications.value)
        if change == "duplicate-adjudication":
            doc["adjudications"].append(dict(doc["adjudications"][0]))
        elif change == "absent-adjudication":
            doc["adjudications"] = []
            error = AuditUnavailable
        elif change == "absent-relation":
            doc["adjudications"][0]["counted_relation_ids"].append("foreign")
        else:
            doc["adjudications"][0]["state"] = "contradicted"
        f.inputs = replace(f.inputs, adjudications=replace(f.inputs.adjudications, value=doc))
    elif change == "absent-producer":
        projection = f.inputs.projection
        cells = {key: value for key, value in projection.cells.items() if key != RED}
        projection = replace(projection, cells=cells)
        f.inputs = replace(f.inputs, projection=projection,
                           origin=replace(f.inputs.origin, projection_sha256=projection.sha256()),
                           projection_document=replace(f.inputs.projection_document, value=projection.to_json()))
    else:
        lane = deepcopy(f.inputs.lanes[0].value)
        next(iter(lane["independence"].values()))[0]["audit"]["arbitrary"] = "forbidden"
        f.inputs = replace(f.inputs, lanes=(replace(f.inputs.lanes[0], value=lane),))
    with pytest.raises(error):
        f.project()


@pytest.mark.parametrize("kind", ["noncanonical", "chain"])
def test_rehashed_bad_ledger_still_fails(tmp_path, kind):
    f = fixture(tmp_path)
    path = f.root / f.refs.ledger["path"]
    if kind == "noncanonical":
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        path.write_bytes(path.read_bytes().replace(b'"sequence":0', b'"sequence":9', 1))
    import hashlib
    f.refs = replace(f.refs, ledger={**f.refs.ledger, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    with pytest.raises(IntegrityError):
        f.publish()


@pytest.mark.parametrize("field", ["run_id", "ledger_head_sha256", "projection_sha256", "package_manifest_sha256"])
def test_rehashed_foreign_inner_handoff_rejected(tmp_path, field):
    f = fixture(tmp_path)
    import json
    value = json.loads((f.root / f.refs.handoff["path"]).read_bytes())
    value[field] = "foreign" if field == "run_id" else digest("wrong")
    changed = document(f.root, f.refs.handoff["path"], value)
    f.refs = replace(f.refs, handoff=reference(changed))
    f.inputs = replace(f.inputs, origin=replace(f.inputs.origin, review_handoff_sha256=changed.source.sha256))
    with pytest.raises(IntegrityError, match="inner review"):
        f.publish()


@pytest.mark.parametrize("entry", ["L2", {"lead": "L2"}, {"lead": "L2", "why": "guard was inspected"}],
                         ids=["bare", "unstated", "stated"])
def test_original_compact_reason_not_expander_fallback(tmp_path, entry):
    f = fixture(tmp_path)
    receipt = f.inputs.receipts[RED]
    receipt = replace(receipt, value={**receipt.value, "compact_result": {"no_claim": [entry]}})
    f.inputs = replace(f.inputs, receipts={**f.inputs.receipts, RED: receipt})
    rows = [row for row in f.project().records if isinstance(row, c.DecisionRecord)
            and row.outcome == "explicit_no_claim"]
    assert len(rows) == 1
    row = rows[0]
    if isinstance(entry, dict) and "why" in entry:
        assert row.context.explanation.text == entry["why"]
        assert row.basis_status == c.BasisStatus.NARRATIVE_ONLY
    else:
        assert row.context.explanation.text is None
        assert row.basis_status == c.BasisStatus.UNSTATED


def test_memo_reuse_does_not_invent_new_verifier_reads(tmp_path):
    f = fixture(tmp_path)
    receipt = f.inputs.receipts[VERIFIER]
    receipt = replace(receipt, value={**receipt.value, "reused_from": {
        "cell_id": RED, "attempt": 1, "receipt_sha256": f.inputs.receipts[RED].source.sha256, "memo_key": digest("memo")}})
    f.inputs = replace(f.inputs, receipts={**f.inputs.receipts, VERIFIER: receipt})
    verifier = next(row for row in f.project().records if isinstance(row, c.VerificationRecord))
    assert verifier.existing_r6_passed.value is True
    assert verifier.confirmation_eligible.value is False
    assert all(not row.own_read_refs for row in verifier.predicates)
    assert "audit:verifier_memo_reuse_without_own_reads" in verifier.context.gap_ids


def test_legacy_sibling_never_excuses_missing_fresh_membership(tmp_path):
    f = fixture(tmp_path)
    fresh = deepcopy(f.inputs.lanes[0].value)
    fresh["proposal_audit"]["items"] = []
    historical = {"lane": "hunt", "expected_cells": {}, "independence": {}, "capabilities": []}
    f.inputs = replace(f.inputs, lanes=(replace(f.inputs.lanes[0], value=fresh),
                                       replace(f.inputs.lanes[0], value=historical)))
    with pytest.raises(IntegrityError, match="fresh membership"):
        f.project()


def test_reused_request_sidecar_does_not_invent_full_marker_inspection(tmp_path):
    f = fixture(tmp_path)
    lane = deepcopy(f.inputs.lanes[0].value)
    next(iter(lane["independence"].values()))[0]["audit"]["request_markers_absent"] = None
    f.inputs = replace(f.inputs, lanes=(replace(f.inputs.lanes[0], value=lane),))
    row = next(row for row in f.project().records if isinstance(row, c.VerificationRecord))
    assert row.existing_r6_passed.value is True
    assert row.blindness.passed.value is None
    assert row.confirmation_eligible.value is None
    assert "audit:verifier_request_bytes_not_observed" in row.context.gap_ids
