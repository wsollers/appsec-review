from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_inference_security_review.audit import publish_decision_audit
from appsec_review.jobs.job_inference_security_review.datasets import DATASETS
from appsec_review.indexing.inventory import compile_glob
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import CellStatus, IntegrityError, Role
from appsec_review.runtime.contracts import JobContract, accepted_inputs
from appsec_review.runtime.handoff import collect_artifacts
from appsec_review.runtime.inputs import input_read_scope, observe_output

from .helpers import ATTEMPT, CELLS, RED, digest, document, fixture, reference


JOB = "job_inference_security_review"


@pytest.mark.parametrize("kind", ["package", "finding"])
@pytest.mark.parametrize("pin", ["correct", "omitted", "wrong-hash", "changed-bytes"])
def test_real_source_closure_is_collectable_and_observable(tmp_path, kind, pin):
    f = fixture(tmp_path)
    if kind == "package":
        original = document(f.root, ATTEMPT + "/steps/packages/tasks/assemble_lead_packages/assembly/packages/package-1.json",
                            f.inputs.packages[0].value)
        package_set = deepcopy(f.inputs.package_sets[0].value)
        package_set["packages"][0].update(reference(original))
        changed = document(f.root, f.refs.package_sets[0]["path"], package_set)
        f.refs = replace(f.refs, package_sets=(reference(changed), *f.refs.package_sets[1:]))
    else:
        directory = ATTEMPT + "/steps/publication/tasks/publish_handoff/"
        original = document(f.root, directory + "findings/" + f.inputs.findings[0].source.path.split("/")[-1],
                            f.inputs.findings[0].value)
        handoff = document(f.root, directory + "inference-review-handoff.json",
                           json.loads((f.root / f.refs.handoff["path"]).read_bytes()))
        f.refs = replace(f.refs, handoff=reference(handoff))
    published = publish_decision_audit(
        run_root=f.root, attempt_root=f.attempt, origin=f.inputs.origin, scope=f.scope,
        collection=f.inputs.collection, inputs=f.refs, settings=f.settings)
    # These are nested in accepted JSON inputs, not direct unit-output references.
    output_kind = "review_packages" if kind == "package" else "scores_and_findings"
    declaration = next(row for row in DATASETS if row.output_kind == output_kind)
    assert any(compile_glob(pattern).fullmatch(original.source.path) for pattern in declaration.artifacts)
    payload = published.unit_output()
    artifacts = collect_artifacts(f.root, payload)
    ref = next(row for row in artifacts if row["path"] == original.source.path)
    assert ref["sha256"] == original.source.sha256
    sources = payload["audit_source_artifacts"]
    assert all(row["path"].startswith(ATTEMPT + "/") for row in sources)
    assert not any(row["path"].startswith(("data/indices/", CELLS + "/")) for row in sources)
    if pin == "omitted":
        artifacts = [row for row in artifacts if row["path"] != ref["path"]]
    elif pin == "wrong-hash":
        artifacts = [{**row, "sha256": digest("wrong")} if row["path"] == ref["path"] else row for row in artifacts]
    elif pin == "changed-bytes":
        (f.root / ref["path"]).write_bytes(b"changed after collection")
    handoff = {"artifacts": artifacts, "attempt_id": f.inputs.origin.review_attempt_id,
               "target_snapshot": f.inputs.origin.target_snapshot}
    context = SimpleNamespace(
        run_root=f.root, config=SimpleNamespace(job_id="job_dossier_publication"),
        upstream_handoffs={JOB: digest("accepted-wrapper")},
        contract=JobContract(inputs=accepted_inputs(JOB, DATASETS, output_kinds=(output_kind,))))
    # Seed only the already-accepted producer boundary; use the actual typed read observer.
    if pin == "correct":
        with input_read_scope(context) as reads:
            reads.producers[JOB] = handoff, DATASETS
            observe_output(f.root, JOB, output_kind, ref)
            actual = reads.document()["reads"]
            assert len(actual) == 1
            assert actual[0]["path"] == ref["path"] and actual[0]["read"] is True
            assert actual[0]["cited"] is None
    else:
        with pytest.raises(ValueError):
            with input_read_scope(context) as reads:
                reads.producers[JOB] = handoff, DATASETS
                observe_output(f.root, JOB, output_kind, ref)
        assert reads.document()["reads"] == []


def test_collect_artifacts_rejects_wrong_source_pin_before_acceptance(tmp_path):
    f = fixture(tmp_path)
    result = publish_decision_audit(run_root=f.root, attempt_root=f.attempt, origin=f.inputs.origin, scope=f.scope,
                                    collection=f.inputs.collection, inputs=f.refs, settings=f.settings)
    payload = result.unit_output()
    payload["audit_source_artifacts"][0]["sha256"] = digest("wrong")
    with pytest.raises(ValueError):
        collect_artifacts(f.root, payload)


@pytest.mark.parametrize("changed", ["collection-empty", "admission-empty", "duplicate-collection", "duplicate-admission"])
def test_supplied_collection_population_never_turns_into_legacy_absence(tmp_path, changed):
    f = fixture(tmp_path)
    if changed in ("collection-empty", "duplicate-collection"):
        leads = () if changed == "collection-empty" else (*f.inputs.collection.leads, f.inputs.collection.leads[0])
        f.inputs = replace(f.inputs, collection=replace(f.inputs.collection, leads=leads))
    else:
        lead_set = f.inputs.package_sets[0]
        body = deepcopy(lead_set.value)
        body["admission"] = [] if changed == "admission-empty" else [*body["admission"], body["admission"][0]]
        f.inputs = replace(f.inputs, package_sets=(replace(lead_set, value=body), *f.inputs.package_sets[1:]))
    with pytest.raises(IntegrityError, match="lead"):
        f.project()


def test_explicit_none_retains_legacy_population_uncertainty(tmp_path):
    f = fixture(tmp_path)
    f.inputs = replace(f.inputs, collection=None)
    result = f.project()
    population = next(row for row in result.coverage if row.population == c.Population.LEADS)
    assert population.expected is None and population.unavailable is None
    assert population.emitted == 3 and population.reason == c.CoverageReason.LEGACY_UNAVAILABLE
    assert all(row.context.gap_ids == ("audit:lead_provenance_legacy_unrecorded",)
               for row in result.records if isinstance(row, c.DecisionRecord) and row.stage == c.Stage.COLLECTION)


def test_supplied_empty_population_can_be_complete_zero(tmp_path):
    f = fixture(tmp_path)
    package_set = f.inputs.package_sets[0]
    f.inputs = replace(f.inputs, collection=replace(f.inputs.collection, leads=()),
        package_sets=(replace(package_set, value={**package_set.value, "admission": []}), *f.inputs.package_sets[1:]))
    population = next(row for row in f.project().coverage if row.population == c.Population.LEADS)
    assert (population.expected, population.emitted, population.unavailable, population.reason) == (0, 0, 0, None)


@pytest.mark.parametrize("bad", [["missing"], ["p1", "p1"], "p1", [1]], ids=["foreign", "duplicate", "not-list", "not-id"])
def test_lead_membership_must_resolve_inside_its_original_receipt(tmp_path, bad):
    f = fixture(tmp_path)
    receipt = f.inputs.receipts[RED]
    value = deepcopy(receipt.value)
    value["result"]["lead_accounting"][0]["proposal_ids"] = bad
    f.inputs = replace(f.inputs, receipts={**f.inputs.receipts, RED: replace(receipt, value=value)})
    with pytest.raises(IntegrityError, match="receipt-local"):
        f.project()


def test_exact_many_to_many_lead_proposal_claim_membership(tmp_path):
    f = fixture(tmp_path)
    claim = next(iter(f.inputs.projection.claims))
    receipt = f.inputs.receipts[RED]
    body = deepcopy(receipt.value)
    body["result"]["proposals"] = [
        {"local_id": local, "source_lead_ids": leads}
        for local, leads in (("p1", ["lead-1"]), ("p2", ["lead-1", "lead-3"]),
                             ("p3", ["lead-3"]), ("p4", ["lead-3"]))]
    body["result"]["lead_accounting"] = [
        {"observation_id": "lead-1", "outcome": "proposal", "proposal_ids": ["p1", "p2"], "gap_ids": [], "reason": "first"},
        {"observation_id": "lead-3", "outcome": "proposal", "proposal_ids": ["p2", "p3", "p4"], "gap_ids": [], "reason": "second"},
    ]
    body["result_sha256"] = sha256_hex(body["result"])
    changed = document(f.root, receipt.source.path, body)
    other = "cell-" + digest("another-red")
    other_body = deepcopy(body)
    other_body.update(cell_id=other, attempt_id=f"{other}/attempt-1")
    other_body["result"]["proposals"] = [{"local_id": "p1", "source_lead_ids": ["lead-3"]}]
    other_body["result"]["lead_accounting"] = [
        {"observation_id": "lead-3", "outcome": "proposal", "proposal_ids": ["p1"], "gap_ids": [], "reason": "third"}]
    other_body["result_sha256"] = sha256_hex(other_body["result"])
    other_doc = document(f.root, f"{CELLS}/{other}/attempt-1.json", other_body)
    projection = f.inputs.projection
    red = replace(projection.cells[RED][0], receipt_sha256=changed.source.sha256)
    projection = replace(projection, cells={**projection.cells, RED: (red,),
        other: (replace(red, cell_id=other, receipt_sha256=other_doc.source.sha256),)})
    lane = deepcopy(f.inputs.lanes[0].value)
    base = lane["proposal_audit"]["items"][0]
    lane["proposal_audit"]["items"] = [
        {**base, "proposal_ref": local, "claim_id": claim_id, "decision": decision, "reason": reason,
         "receipt_sha256": changed.source.sha256}
        for local, claim_id, decision, reason in (
            ("p1", claim, "admitted", None), ("p2", claim, "over_cap", "claims_per_package_cap"),
            ("p3", None, "over_cap", "max_active_claims"), ("p4", None, "rejected", "closed_vocabulary"))]
    lane["proposal_audit"]["items"].append({**base, "cell_id": other, "receipt_sha256": other_doc.source.sha256})
    lane["expected_cells"][other] = "lead"
    lane["capabilities"].append({"cell_id": other, "round": 0})
    f.inputs = replace(f.inputs, projection=projection,
        projection_document=replace(f.inputs.projection_document, value=projection.to_json()),
        origin=replace(f.inputs.origin, projection_sha256=projection.sha256()),
        lanes=(replace(f.inputs.lanes[0], value=lane),),
        receipts={**f.inputs.receipts, RED: changed, other: other_doc})
    result = f.project()
    leads = [row for row in result.records if isinstance(row, c.DecisionRecord)
             and row.stage == c.Stage.RED_DISCOVERY and row.context.subject.lead_id.value is not None]
    joins = {(row.context.subject.cell_id.value, row.context.subject.lead_id.value):
             {(ref.path, ref.record_id.value) for ref in row.context.origin_proposals} for row in leads}
    assert joins[(RED, "lead-1")] == {(changed.source.path, "p1"), (changed.source.path, "p2")}
    assert joins[(RED, "lead-3")] == {(changed.source.path, local) for local in ("p2", "p3", "p4")}
    assert joins[(other, "lead-3")] == {(other_doc.source.path, "p1")}
    mapping = {(row.context.subject.cell_id.value, row.context.subject.proposal_ref.value):
               row.context.subject.claim_id.value for row in result.records if isinstance(row, c.DecisionRecord)
               and row.context.subject.proposal_ref.value is not None}
    assert mapping == {(RED, "p1"): claim, (RED, "p2"): claim, (RED, "p3"): None, (RED, "p4"): None, (other, "p1"): claim}
    for row in result.records:
        if isinstance(row, c.DecisionRecord) and row.context.subject.proposal_ref.value:
            assert len(row.context.origin_proposals) == 1
            assert row.context.origin_proposals[0].record_id == row.context.subject.proposal_ref
    basis = next(row for row in result.records if isinstance(row, c.DecisionBasisRecord))
    assert {(ref.path, ref.record_id.value) for ref in basis.context.origin_proposals} == {
        (changed.source.path, "p1"), (changed.source.path, "p2"), (other_doc.source.path, "p1")}


@pytest.mark.parametrize("state,expected", [
    ("out_of_scope", ()),
    ("unresolved", ()),
    ("conflicted", (Role.RED_TEAM_ANALYST, Role.BLUE_TEAM_REFUTER)),
    ("contradicted", (Role.BLUE_TEAM_REFUTER,)),
    ("confirmed", (Role.RED_TEAM_ANALYST, Role.INDEPENDENT_VERIFIER)),
    ("supported", (Role.RED_TEAM_ANALYST, Role.INDEPENDENT_VERIFIER)),
])
def test_deciding_roles_follow_original_row_not_all_counted_relations(tmp_path, state, expected):
    f = fixture(tmp_path, state=state, unrelated_support=True)
    original = deepcopy(f.inputs.projection.to_json())
    row = next(item for item in f.project().records if isinstance(item, c.DecisionRecord)
               and item.stage == c.Stage.ADJUDICATION)
    assert set(row.deciding_actor_roles) == set(expected)
    counted_roles = {relation.actor_role for relation in row.context.relations if relation.counted}
    assert counted_roles - set(expected)
    assert f.inputs.projection.to_json() == original
    assert {relation.relation_id for relation in row.context.relations if relation.counted} == set(
        f.inputs.adjudications.value["adjudications"][0]["counted_relation_ids"])


@pytest.mark.parametrize("kind", ["foreign", "omitted", "duplicate", "not-list", "not-id", "duplicate-accounting"])
def test_original_bidirectional_lead_membership_is_required(tmp_path, kind):
    f = fixture(tmp_path)
    receipt = f.inputs.receipts[RED]
    body = deepcopy(receipt.value)
    if kind == "duplicate-accounting":
        body["result"]["lead_accounting"].append(deepcopy(body["result"]["lead_accounting"][0]))
    else:
        body["result"]["proposals"][0]["source_lead_ids"] = {
            "foreign": ["lead-3"], "omitted": [], "duplicate": ["lead-1", "lead-1"],
            "not-list": "lead-1", "not-id": [1]}[kind]
    f.inputs = replace(f.inputs, receipts={**f.inputs.receipts, RED: replace(receipt, value=body)})
    with pytest.raises(IntegrityError):
        f.project()
